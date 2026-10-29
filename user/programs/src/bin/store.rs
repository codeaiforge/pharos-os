//! The storage service (#77, storage.md part 8): the driver of the
//! writable virtio-blk disk, running the `pharos-store` format on it and
//! serving files and streams to clients in their namespaces.
//!
//! - Argument 0, the service. Handles: 1 the console, 2 the device (`MAP |
//!   CONFIG | IRQ`), 3 its endpoint (`RECEIVE`), 4 the report endpoint
//!   (`SEND`). Mounts the store, sends `ready`, and serves requests
//!   ([`pharos_programs::store_proto`]). Exits 1 if the store does not
//!   mount, 2 if the device cannot be set up.
//! - Argument 1, the crash writer (handles 1 and 2): checks the `crash/`
//!   objects an earlier, killed run left (a counter file and a log stream
//!   that must agree), prints `store check: ok <counter> <records>` or
//!   `store check: FAIL ...`, then `store: writing`, then takes
//!   [`CRASH_STEPS`] steps, checks again, and exits 0. `cargo xtask test`
//!   kills it at random moments while it writes.

#![no_std]
#![no_main]

use pharos_programs::store_proto::{MAX_CLIENT_PATH, Request, Status, full_path, namespace, parse};
use pharos_programs::virtio::{Blk, SECTOR};
use pharos_store::{BLOCK, Block, Device, Error, IoError, Kind, Store};
use pharos_user::{
    Handle, Mapped, Received, debug_write, delete, irq_create, mem_map_cap, mem_unmap, receive,
    send, try_send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
const SERVICE: Handle = 3;
const REPORT: Handle = 4;
const BASE: u64 = 0x1000_0000;
/// Steps the crash writer takes.
pub const CRASH_STEPS: u64 = 100;
/// Most clients with an attached buffer.
const MAX_CLIENTS: usize = 16;
const SECTORS: u64 = (BLOCK / SECTOR) as u64;

/// The writable disk as a store device: one 4 KiB block per request.
struct Disk {
    blk: Blk,
    irq: Handle,
}

impl Device for Disk {
    fn blocks(&self) -> u64 {
        self.blk.capacity / SECTORS
    }
    fn read(&mut self, block: u64, buf: &mut Block) -> Result<(), IoError> {
        self.blk
            .read(self.irq, block * SECTORS, buf)
            .map_err(|_| IoError)
    }
    fn write(&mut self, block: u64, buf: &Block) -> Result<(), IoError> {
        self.blk
            .write(self.irq, block * SECTORS, buf)
            .map_err(|_| IoError)
    }
    fn flush(&mut self) -> Result<(), IoError> {
        self.blk.flush(self.irq).map_err(|_| IoError)
    }
}

fn say(parts: &[&[u8]]) {
    let mut line = [0u8; 128];
    let mut n = 0;
    for p in parts {
        let take = p.len().min(line.len() - n);
        line[n..n + take].copy_from_slice(&p[..take]);
        n += take;
    }
    let _ = debug_write(CONSOLE, &line[..n]);
}

fn decimal(mut v: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &out[i..];
        }
    }
}

fn status(e: Error) -> Status {
    match e {
        Error::Io => Status::IoError,
        Error::NotFound => Status::NotFound,
        Error::NoSpace => Status::NoSpace,
        Error::Corrupt => Status::Corrupt,
        _ => Status::BadRequest,
    }
}

/// One client's attached buffer, by badge.
struct Client {
    badge: u32,
    buffer: Mapped,
}

struct Service {
    store: Store<Disk>,
    clients: [Option<Client>; MAX_CLIENTS],
    /// Set after a device error on a write: writes are refused until the
    /// service restarts (reads continue).
    broken: bool,
}

/// `buffer[at..at + len]`, if it lies inside the buffer.
fn range_ok(buffer: &Mapped, at: u64, len: u64) -> bool {
    at.checked_add(len)
        .is_some_and(|end| end <= buffer.len() as u64)
}

impl Service {
    /// `ATTACH`: maps the client's buffer writable (replacing an earlier
    /// one) and drops the capability; the mapping keeps it alive.
    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let mapped = match namespace(badge) {
            Some(_) => mem_map_cap(memory, true, len).ok(),
            None => None,
        };
        let _ = delete(memory);
        let Some(buffer) = mapped else {
            return;
        };
        let slot = match self
            .clients
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.badge == badge))
        {
            Some(i) => i,
            None => match self.clients.iter().position(Option::is_none) {
                Some(i) => i,
                None => {
                    let _ = mem_unmap(buffer.addr(), buffer.len() as u64);
                    return;
                }
            },
        };
        if let Some(old) = self.clients[slot].replace(Client { badge, buffer }) {
            let _ = mem_unmap(old.buffer.addr(), old.buffer.len() as u64);
        }
    }

    /// Handles one request; writes the reply (status first) into `out` and
    /// returns its length.
    fn handle(&mut self, req: Option<Request<'_>>, badge: u32, out: &mut [u8; 256]) -> usize {
        match self.answer(req, badge, out) {
            Ok(n) => {
                out[0] = Status::Ok as u8;
                n
            }
            Err(s) => {
                out[0] = s as u8;
                1
            }
        }
    }

    fn answer(
        &mut self,
        req: Option<Request<'_>>,
        badge: u32,
        out: &mut [u8; 256],
    ) -> Result<usize, Status> {
        let req = req.ok_or(Status::BadRequest)?;
        let (prefix, read_only) = namespace(badge).ok_or(Status::NoAccess)?;
        let mut path = [0u8; 104];
        let full =
            |p: &[u8], path: &mut [u8; 104]| full_path(prefix, p, path).ok_or(Status::BadRequest);
        let writing = matches!(
            req,
            Request::Write { .. } | Request::Append { .. } | Request::Delete { .. }
        );
        if writing && read_only {
            return Err(Status::ReadOnly);
        }
        if writing && self.broken {
            return Err(Status::IoError);
        }
        let buffer = self
            .clients
            .iter()
            .flatten()
            .find(|c| c.badge == badge)
            .map(|c| c.buffer);
        let result = match req {
            Request::Stat { path: p } => {
                let n = full(p, &mut path)?;
                let info = self.store.stat(&path[..n]).map_err(status)?;
                out[1] = info.kind as u8;
                out[2..10].copy_from_slice(&info.len.to_le_bytes());
                out[10..18].copy_from_slice(&info.records.to_le_bytes());
                return Ok(18);
            }
            Request::Read {
                path: p,
                offset,
                len,
                at,
            } => {
                let n = full(p, &mut path)?;
                let buffer = buffer
                    .filter(|b| range_ok(b, at, len))
                    .ok_or(Status::NoBuffer)?;
                let mut done = 0u64;
                let got = self
                    .store
                    .read_with(&path[..n], offset, len, |bytes| {
                        buffer.write_bytes((at + done) as usize, bytes);
                        done += bytes.len() as u64;
                    })
                    .map_err(status)?;
                out[1..9].copy_from_slice(&got.to_le_bytes());
                return Ok(9);
            }
            Request::Write { path: p, len, at } => {
                let n = full(p, &mut path)?;
                let buffer = buffer
                    .filter(|b| range_ok(b, at, len))
                    .ok_or(Status::NoBuffer)?;
                self.store.write_with(&path[..n], len, |offset, block| {
                    let k = (len - offset).min(BLOCK as u64) as usize;
                    buffer.read_bytes((at + offset) as usize, &mut block[..k]);
                })
            }
            Request::Append { path: p, record } => {
                let n = full(p, &mut path)?;
                match self.store.append(&path[..n], record) {
                    Ok((number, head)) => {
                        out[1..9].copy_from_slice(&number.to_le_bytes());
                        out[9..41].copy_from_slice(&head);
                        return Ok(41);
                    }
                    Err(e) => Err(e),
                }
            }
            Request::List { prefix: p, start } => {
                // `<namespace>/<p>`, matched as a byte prefix.
                let n = prefix.len() + 1 + p.len();
                path[..prefix.len()].copy_from_slice(prefix);
                path[prefix.len()] = b'/';
                path[prefix.len() + 1..n].copy_from_slice(p);
                let (mut at, mut count, mut more) = (3, 0u8, 0u8);
                for name in self.store.list(&path[..n]).skip(start as usize) {
                    let name = &name[prefix.len() + 1..];
                    if at + 1 + name.len() > out.len() || name.len() > MAX_CLIENT_PATH {
                        more = 1;
                        break;
                    }
                    out[at] = name.len() as u8;
                    out[at + 1..at + 1 + name.len()].copy_from_slice(name);
                    at += 1 + name.len();
                    count += 1;
                }
                out[1] = count;
                out[2] = more;
                return Ok(at);
            }
            Request::Delete { path: p } => {
                let n = full(p, &mut path)?;
                self.store.delete(&path[..n])
            }
            Request::Buffer => {
                let size = buffer.map_or(0, |b| b.len() as u64);
                out[1..9].copy_from_slice(&size.to_le_bytes());
                return Ok(9);
            }
            Request::Attach { .. } => return Err(Status::BadRequest),
        };
        match result {
            Ok(()) => Ok(1),
            Err(Error::Io) => {
                self.broken = true;
                Err(Status::IoError)
            }
            Err(e) => Err(status(e)),
        }
    }
}

fn serve(store: Store<Disk>) -> u64 {
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 3;
    }
    let mut s = Service {
        store,
        clients: Default::default(),
        broken: false,
    };
    let mut msg = [0u8; 256];
    loop {
        let Ok(Received::Message { len, cap, badge }) = receive(SERVICE, &mut msg) else {
            continue;
        };
        let req = parse(&msg[..len.min(msg.len())]);
        if let Some(Request::Attach { len }) = req {
            if cap != 0 {
                s.attach(badge, cap, len);
            }
            continue;
        }
        // A call: the capability is the one-shot reply capability.
        let mut reply = [0u8; 256];
        let n = s.handle(req, badge, &mut reply);
        if cap != 0 {
            let _ = try_send(cap, &reply[..n]);
            let _ = delete(cap);
        }
    }
}

// ---- The crash writer -------------------------------------------------

const COUNTER: &[u8] = b"crash/counter";
const LOG: &[u8] = b"crash/log";
const COUNTER_LEN: u64 = 3 * BLOCK as u64;

/// Byte `i` of the counter file holding `k`.
fn counter_byte(k: u64, i: u64) -> u8 {
    if i < 8 {
        k.to_le_bytes()[i as usize]
    } else {
        (i.wrapping_mul(7).wrapping_add(k)) as u8
    }
}

/// The counter value and record count, if every check passes: the file's
/// CRC and pattern, each record's CRC and chain, record `i` holding `i`.
fn check(store: &mut Store<Disk>) -> Option<(u64, u64)> {
    let k = match store.stat(COUNTER) {
        Err(Error::NotFound) => 0,
        Ok(info) if info.kind == Kind::File && info.len == COUNTER_LEN => {
            let mut head = [0u8; 8];
            let mut at = 0u64;
            let mut first = true;
            let mut k = 0;
            let mut good = true;
            store
                .read_with(COUNTER, 0, COUNTER_LEN, |bytes| {
                    if first {
                        head.copy_from_slice(&bytes[..8]);
                        k = u64::from_le_bytes(head);
                        first = false;
                    }
                    for &b in bytes {
                        good &= b == counter_byte(k, at);
                        at += 1;
                    }
                })
                .ok()?;
            if !good {
                return None;
            }
            k
        }
        _ => return None,
    };
    let mut m = 0u64;
    let mut good = true;
    match store.records(LOG, |r| {
        good &= r == m.to_le_bytes();
        m += 1;
    }) {
        Ok(()) | Err(Error::NotFound) => {}
        Err(_) => return None,
    }
    (good && (m == k || m == k + 1)).then_some((k, m))
}

fn crash_writer(mut store: Store<Disk>) -> u64 {
    let mut a = [0u8; 20];
    let mut b = [0u8; 20];
    let Some((mut k, mut m)) = check(&mut store) else {
        say(&[b"store check: FAIL"]);
        return 1;
    };
    say(&[
        b"store check: ok ",
        decimal(k, &mut a),
        b" ",
        decimal(m, &mut b),
    ]);
    say(&[b"store: writing"]);
    for _ in 0..CRASH_STEPS {
        let done = if k == m {
            store.append(LOG, &m.to_le_bytes()).map(|_| m += 1)
        } else {
            let next = m;
            store
                .write_with(COUNTER, COUNTER_LEN, |offset, block| {
                    for (i, byte) in block.iter_mut().enumerate() {
                        *byte = counter_byte(next, offset + i as u64);
                    }
                })
                .map(|()| k = next)
        };
        if done.is_err() {
            say(&[b"store: write failed"]);
            return 1;
        }
    }
    match check(&mut store) {
        Some((k, m)) => say(&[
            b"store crash: done ",
            decimal(k, &mut a),
            b" ",
            decimal(m, &mut b),
        ]),
        None => {
            say(&[b"store check: FAIL after writing"]);
            return 1;
        }
    }
    0
}

fn main(arg: u64) -> u64 {
    let Ok(blk) = Blk::init_flushing(DEVICE, 0, BASE) else {
        say(&[b"store: device setup failed"]);
        return 2;
    };
    let Ok(irq) = irq_create(DEVICE, 0) else {
        say(&[b"store: no interrupt"]);
        return 2;
    };
    let store = match Store::mount(Disk { blk, irq }) {
        Ok(store) => store,
        Err(_) => {
            say(&[b"store: no valid store on the disk"]);
            return 1;
        }
    };
    if arg == 1 {
        return crash_writer(store);
    }
    serve(store)
}
