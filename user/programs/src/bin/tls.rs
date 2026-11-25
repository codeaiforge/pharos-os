//! The TLS service (tls.md, D-034, #271): TLS 1.3 client connections to
//! the destinations `init` lists, over the network service's TCP, with
//! rustls and `pharos-tls`. A client opens a connection by destination
//! index; the service checks the certificate against the pinned roots and
//! the destination's name, and refuses anything else.
//!
//! Capabilities, in handle order: 1 the debug console, 2 the virtio-rng
//! device, 3 `RECEIVE` on its endpoint (a client's badge is its number,
//! 1 to 8; badge 0 is `init`'s), 4 `init`'s report endpoint, 5 `READ` on
//! the root filesystem (for `system/tls/roots`), 6 `SEND` on the network
//! service with the TCP destinations, 7 `SEND` on the audit service as
//! client 4 (without it every `OPEN` is `NO_AUDIT`).
//!
//! Before each handshake it seeds its HMAC-DRBG from 48 bytes of
//! virtio-rng and 32 of RDSEED where the CPU has it, needs the wall clock,
//! and stores an `INTENT`; any of these missing fails the `OPEN`
//! (`NO_RANDOM`, `NO_CLOCK`, `NO_AUDIT`) before a byte is sent. The
//! network service is polled (`TCP_POLL`, `TCP_CONNECT`): a deferred call
//! would stop this single-threaded service from answering anyone else.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_programs::output::Limit;
use pharos_programs::virtio_rng::Rng;
use pharos_proto::audit::{self, Entry, Kind, action, outcome};
use pharos_proto::net::{self, Request as NetRequest};
use pharos_proto::tls::{
    self, CLOSED, Destination, HANDSHAKE, MAX_BUFFER, MAX_CLIENTS, MAX_DESTINATIONS, NAME,
    NO_ACCESS, NO_AUDIT, NO_BUFFER, NO_CLOCK, NO_RANDOM, OK, OVER_LIMIT, Request, VERSION,
    encode_opened, reason,
};
use pharos_proto::{Info, refusal, status};
use pharos_tls::drbg::SharedDrbg;
use pharos_tls::rustls::ClientConfig;
use pharos_tls::rustls::pki_types::UnixTime;
use pharos_tls::rustls::time_provider::TimeProvider;
use pharos_tls::{Refusal, Session};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, clock_real, debug_write, delete, endpoint_create,
    entropy, mem_map, mem_map_cap, mem_share, mem_unmap, open, read, receive_timeout, send,
    try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const RNG_DEVICE: Handle = 2;
const SERVICE: Handle = 3;
const REPORT: Handle = 4;
const ROOT: Handle = 5;
const NET: Handle = 6;
const AUDIT: Handle = 7;
const BASE: u64 = 0x1000_0000;

/// The pinned roots in the image (tls.md).
const ROOTS: &[u8] = b"system/tls/roots";
/// Connections in all, and per client (tls.md).
const MAX_CONNS: usize = 4;
const PER_CLIENT: usize = 2;
/// `OPEN`s a client may make at once that reach the audit trail, then one
/// a second (#275): each writes 2 or 3 records, so one client cannot fill
/// the trail faster than that. A refused one writes nothing.
const OPEN_BURST: u64 = 16;
const OPEN_EVERY_US: u64 = 1_000_000;
/// How long a handshake may take.
const HANDSHAKE_US: u64 = 10_000_000;
/// A connection with no client request and no data from the server for
/// this long is closed (tls.md, budgets; review F3, #274).
const IDLE_US: u64 = 60_000_000;
/// How often open connections are polled.
const TICK_US: u64 = 10_000;
/// How long the network and audit services may take to answer.
const CALL_US: u64 = 1_000_000;
/// How long virtio-rng may take to give a seed.
const SEED_US: u64 = 1_000_000;
/// The network buffer: per connection, 8 KiB to receive, then 8 to send.
const WINDOW: usize = 8 * 1024;
const NET_BUFFER: usize = MAX_CONNS * 2 * WINDOW;
/// Plaintext a connection may hold for its client, and TLS bytes it may
/// queue to send.
const MAX_PLAIN: usize = 32 * 1024;
const MAX_QUEUED: usize = 32 * 1024;

static RANDOM: SharedDrbg = SharedDrbg::new();

/// The wall clock, `clock_real` (tls.md, time): none means no handshake.
#[derive(Debug)]
struct Clock;

impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        clock_real().map(|s| UnixTime::since_unix_epoch(Duration::from_secs(s)))
    }
}

struct Dest {
    ip: [u8; 4],
    port: u16,
    name: Vec<u8>,
}

struct Client {
    dests: [Option<Dest>; MAX_DESTINATIONS as usize],
    buffer: Option<Mapped>,
    /// The `OPEN`s that write an intent (#275).
    opens: Limit,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            dests: Default::default(),
            buffer: None,
            opens: Limit::rate(OPEN_BURST, OPEN_EVERY_US),
        }
    }
}

enum Phase {
    /// The client's deferred `OPEN`, and when the handshake must end.
    Handshake {
        reply: Handle,
        deadline: u64,
    },
    Open,
    /// The server reset it, a record failed, or it ended: only `CLOSE`.
    Dead,
}

struct Conn {
    client: u8,
    /// The network service's connection.
    net: u8,
    session: Session,
    phase: Phase,
    /// The client's deferred `READ`: reply, offset, and most bytes.
    read: Option<(Handle, u32, u32)>,
    /// The intent's sequence number.
    intent: u64,
    /// TCP's end of stream was seen.
    eof: bool,
    /// The last client request on it, or data from the server.
    active: u64,
}

struct Service {
    config: Option<Arc<ClientConfig>>,
    rng: Option<Rng>,
    clients: [Client; MAX_CLIENTS as usize],
    conns: [Option<Conn>; MAX_CONNS],
    net_buffer: Option<Mapped>,
    reply: Handle,
}

fn say(msg: &[u8]) {
    let _ = debug_write(CONSOLE, msg);
}

/// Sends `bytes` on the reply capability without blocking, then lets go.
fn answer(reply: Handle, bytes: &[u8]) {
    let _ = try_send(reply, bytes);
    let _ = delete(reply);
}

fn count(status: u8, n: u32) -> [u8; 6] {
    net::encode_count(status, n)
}

/// The root file, or no roots (every handshake an unknown issuer).
fn read_roots() -> pharos_tls::rustls::RootCertStore {
    let empty = pharos_tls::rustls::RootCertStore::empty;
    let Ok(file) = open(ROOT, ROOTS) else {
        say(b"tls: no root file; every OPEN is an unknown issuer");
        return empty();
    };
    let mut bytes = vec![0u8; pharos_tls::MAX_ROOTS_FILE + 1];
    let mut len = 0;
    while len < bytes.len() {
        let end = bytes.len().min(len + 4096);
        match read(file, len as u64, &mut bytes[len..end]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(_) => break,
        }
    }
    let _ = delete(file);
    match pharos_tls::roots(&bytes[..len]) {
        Some(store) => {
            let mut line = *b"tls: roots: 00";
            let n = store.roots.len().min(99);
            line[12] = b'0' + (n / 10) as u8;
            line[13] = b'0' + (n % 10) as u8;
            say(&line);
            store
        }
        None => {
            say(b"tls: the root file is malformed; no roots");
            empty()
        }
    }
}

impl Service {
    /// `call_timeout` to `to`; the reply's bytes, if one came.
    fn call(&self, to: Handle, msg: &[u8], out: &mut [u8; 256]) -> Option<usize> {
        match call_timeout(to, msg, self.reply, out, CALL_US) {
            Ok(Received::Message { len, cap, .. }) => {
                if cap != 0 {
                    let _ = delete(cap);
                }
                Some(len)
            }
            _ => None,
        }
    }

    fn net(&self, req: &NetRequest<'_>) -> Option<([u8; 256], usize)> {
        let mut msg = [0u8; 64];
        let n = net::encode(req, &mut msg)?;
        let mut out = [0u8; 256];
        let len = self.call(NET, &msg[..n], &mut out)?;
        Some((out, len))
    }

    /// Appends an audit record; its sequence number.
    fn audit(&self, kind: Kind, refers: u64, ok: u8, detail: &[u8]) -> Option<u64> {
        let e = Entry {
            kind,
            refers,
            actor: b"",
            task: 0,
            attempt: 0,
            action: action::TLS,
            permission: None,
            service: b"tls",
            outcome: ok,
            detail,
        };
        let mut msg = [0u8; 256];
        let n = audit::encode(&audit::Request::Append(e), &mut msg)?;
        let mut out = [0u8; 256];
        match self.call(AUDIT, &msg[..n], &mut out) {
            Some(9) if out[0] == status::OK => Some(u64::from_le_bytes(out[1..9].try_into().ok()?)),
            _ => None,
        }
    }

    /// Seeds the generator: 48 bytes of virtio-rng, and 32 of RDSEED where
    /// the CPU has it. False without virtio-rng's bytes.
    fn seed(&mut self) -> bool {
        let Some(rng) = self.rng.as_mut() else {
            return false;
        };
        let mut seed = [0u8; 80];
        if rng.fill(&mut seed[..48], SEED_US).is_err() {
            say(b"tls: virtio-rng gave no seed");
            self.rng = None;
            return false;
        }
        for chunk in seed[48..].chunks_mut(8) {
            if let Some(v) = entropy::rdseed64() {
                chunk.copy_from_slice(&v.to_le_bytes());
            }
        }
        let ok = RANDOM.seed(&seed) && RANDOM.ready();
        seed.fill(0);
        ok
    }

    fn handle(&mut self, msg: &[u8], badge: u32, cap: Handle, out: &mut [u8; 256]) {
        let req = match tls::parse(msg) {
            Ok(r) => r,
            Err(why) => {
                if cap != 0 {
                    let n = refusal(why, VERSION, out);
                    answer(cap, &out[..n]);
                }
                return;
            }
        };
        if let Request::Attach { len } = req {
            // A `send`: the capability is the buffer, there is no reply.
            return self.attach(badge, cap, len);
        }
        if cap == 0 {
            return;
        }
        let client = u8::try_from(badge)
            .ok()
            .filter(|c| (1..=MAX_CLIENTS).contains(c));
        match (req, client) {
            (Request::Info, _) => {
                let info = Info {
                    name: NAME,
                    low: VERSION,
                    high: VERSION,
                    details: &[],
                };
                let n = info.encode(out).unwrap_or(0);
                answer(cap, &out[..n]);
            }
            (
                Request::Allow {
                    client,
                    destination,
                    dest,
                },
                None,
            ) if badge == 0 => {
                self.allow(client, destination, dest);
                answer(cap, &[OK]);
            }
            (_, None) => answer(cap, &[NO_ACCESS]),
            (Request::Allow { .. }, Some(_)) => answer(cap, &[NO_ACCESS]),
            (Request::Open { destination }, Some(c)) => self.open(c, destination, cap),
            (Request::Write { conn, offset, len }, Some(c)) => {
                let r = self.write(c, conn, offset, len);
                answer(cap, &r);
            }
            (Request::Read { conn, offset, max }, Some(c)) => self.read(c, conn, offset, max, cap),
            (Request::Close { conn }, Some(c)) => {
                let s = self.close(c, conn);
                answer(cap, &[s]);
            }
            (Request::Attach { .. }, Some(_)) => {}
        }
    }

    fn allow(&mut self, client: u8, destination: u8, d: Destination<'_>) {
        // `parse` checked both ranges.
        let c = &mut self.clients[usize::from(client - 1)];
        c.dests[usize::from(destination)] = Some(Dest {
            ip: d.ip,
            port: d.port,
            name: d.name.to_vec(),
        });
    }

    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let client = u8::try_from(badge)
            .ok()
            .filter(|c| (1..=MAX_CLIENTS).contains(c));
        let mapped = match client {
            Some(_) if memory != 0 && len <= MAX_BUFFER => mem_map_cap(memory, true, len).ok(),
            _ => None,
        };
        if memory != 0 {
            let _ = delete(memory);
        }
        if let (Some(c), Some(m)) = (client, mapped)
            && let Some(old) = self.clients[usize::from(c - 1)].buffer.replace(m)
        {
            let _ = mem_unmap(old);
        }
    }

    /// `OPEN`: every check that can fail without the network first, then
    /// the intent, then TCP; the reply waits for the handshake's end.
    fn open(&mut self, client: u8, destination: u8, reply: Handle) {
        let refuse = |s: u8, r: u8| answer(reply, &encode_opened(s, 0, r));
        let Some((ip, port, name)) = self.clients[usize::from(client - 1)]
            .dests
            .get(usize::from(destination))
            .and_then(Option::as_ref)
            .map(|d| (d.ip, d.port, d.name.clone()))
        else {
            return refuse(NO_ACCESS, 0);
        };
        if clock_real().is_none() {
            return refuse(NO_CLOCK, 0);
        }
        if !self.seed() {
            return refuse(NO_RANDOM, 0);
        }
        let held = self
            .conns
            .iter()
            .flatten()
            .filter(|c| c.client == client)
            .count();
        let Some(slot) = self
            .conns
            .iter()
            .position(Option::is_none)
            .filter(|_| held < PER_CLIENT)
        else {
            return refuse(OVER_LIMIT, 0);
        };
        let Some(config) = self.config.clone() else {
            return refuse(status::INTERNAL, 0);
        };
        if !self.clients[usize::from(client - 1)].opens.admit(uptime()) {
            return refuse(OVER_LIMIT, 0);
        }
        let mut detail = Vec::with_capacity(64);
        detail.extend_from_slice(b"open client ");
        detail.push(b'0' + client);
        detail.extend_from_slice(b" dest ");
        detail.push(b'0' + destination);
        detail.push(b' ');
        detail.extend_from_slice(&name[..name.len().min(64 - detail.len())]);
        let Some(intent) = self.audit(Kind::Intent, 0, outcome::NONE, &detail) else {
            return refuse(NO_AUDIT, 0);
        };
        let fail = |s: &Self, why: u8, detail: &[u8]| {
            let _ = s.audit(Kind::Outcome, intent, outcome::FAILED, detail);
            refuse(HANDSHAKE, why);
        };
        let net = match self.net(&NetRequest::TcpConnect { ip, port }) {
            Some((out, 2)) if out[0] == net::OK => out[1],
            _ => return fail(self, reason::TCP, b"tcp refused"),
        };
        let name = core::str::from_utf8(&name).unwrap_or("");
        match Session::new(config, name) {
            Ok(session) => {
                self.conns[slot] = Some(Conn {
                    client,
                    net,
                    session,
                    phase: Phase::Handshake {
                        reply,
                        deadline: uptime() + HANDSHAKE_US,
                    },
                    read: None,
                    intent,
                    eof: false,
                    active: uptime(),
                });
            }
            Err(e) => {
                let _ = self.net(&NetRequest::TcpClose { conn: net });
                fail(self, refusal_reason(&e), b"handshake refused");
            }
        }
    }

    fn conn(&mut self, client: u8, conn: u8) -> Option<&mut Conn> {
        let c = self
            .conns
            .get_mut(usize::from(conn))?
            .as_mut()
            .filter(|c| c.client == client)?;
        c.active = uptime();
        Some(c)
    }

    fn write(&mut self, client: u8, conn: u8, offset: u32, len: u32) -> [u8; 6] {
        let mut data = vec![0u8; len.min(16 * 1024) as usize];
        let ok = (self.clients[usize::from(client - 1)].buffer.as_ref())
            .filter(|b| u64::from(offset) + u64::from(len) <= b.len() as u64)
            .map(|b| b.read_bytes(offset as usize, &mut data));
        let Some(c) = self.conn(client, conn) else {
            return count(CLOSED, 0);
        };
        if !matches!(c.phase, Phase::Open) {
            return count(CLOSED, 0);
        }
        if ok.is_none() {
            return count(NO_BUFFER, 0);
        }
        if c.session.outgoing().len() > MAX_QUEUED {
            return count(status::BUSY, 0);
        }
        match c.session.write(&data) {
            Ok(()) => count(OK, data.len() as u32),
            Err(_) => {
                c.phase = Phase::Dead;
                count(CLOSED, 0)
            }
        }
    }

    fn read(&mut self, client: u8, conn: u8, offset: u32, max: u32, reply: Handle) {
        let fits = (self.clients[usize::from(client - 1)].buffer.as_ref())
            .is_some_and(|b| max > 0 && u64::from(offset) + u64::from(max) <= b.len() as u64);
        let Some(c) = self.conn(client, conn) else {
            return answer(reply, &count(CLOSED, 0));
        };
        if !fits {
            return answer(reply, &count(NO_BUFFER, 0));
        }
        if !matches!(c.phase, Phase::Open) {
            return answer(reply, &count(CLOSED, 0));
        }
        if c.read.is_some() {
            return answer(reply, &count(status::BUSY, 0));
        }
        c.read = Some((reply, offset, max));
        self.deliver(usize::from(conn));
    }

    fn close(&mut self, client: u8, conn: u8) -> u8 {
        if self.conn(client, conn).is_none() {
            return CLOSED;
        }
        self.finish(usize::from(conn), true);
        OK
    }

    /// Ends connection `i`: `close_notify` if asked (best effort), the
    /// network connection closed, waiting calls answered, the close
    /// recorded.
    fn finish(&mut self, i: usize, notify: bool) {
        let Some(mut c) = self.conns[i].take() else {
            return;
        };
        if notify && matches!(c.phase, Phase::Open) && c.session.close().is_ok() {
            self.push(i, &mut c);
        }
        let _ = self.net(&NetRequest::TcpClose { conn: c.net });
        if let Some((reply, ..)) = c.read.take() {
            answer(reply, &count(CLOSED, 0));
        }
        if let Phase::Handshake { reply, .. } = c.phase {
            // Its client closed it first (review F4, #274).
            let _ = self.audit(Kind::Outcome, c.intent, outcome::FAILED, b"closed");
            answer(reply, &encode_opened(CLOSED, 0, 0));
        }
        let mut detail = Vec::with_capacity(48);
        detail.extend_from_slice(b"close out ");
        push_number(&mut detail, c.session.bytes_out);
        detail.extend_from_slice(b" in ");
        push_number(&mut detail, c.session.bytes_in);
        let _ = self.audit(Kind::Event, 0, outcome::OK, &detail);
    }

    /// Sends what TLS has queued, as far as TCP takes it.
    fn push(&self, i: usize, c: &mut Conn) -> bool {
        let Some(buf) = &self.net_buffer else {
            return false;
        };
        let at = i * 2 * WINDOW + WINDOW;
        while !c.session.outgoing().is_empty() {
            let n = c.session.outgoing().len().min(WINDOW);
            buf.write_bytes(at, &c.session.outgoing()[..n]);
            let req = NetRequest::TcpWrite {
                conn: c.net,
                offset: at as u32,
                len: n as u32,
            };
            match self
                .net(&req)
                .and_then(|(out, len)| net::parse_count(&out[..len]))
            {
                Some((net::OK, 0)) => break,
                Some((net::OK, sent)) if sent as usize > n => return false,
                Some((net::OK, sent)) => c.session.sent(sent as usize),
                _ => return false,
            }
        }
        true
    }

    /// Moves TCP bytes into TLS for connection `i`; false if TCP ended
    /// badly. Sets `eof` at the end of the stream.
    fn pull(&self, i: usize, c: &mut Conn) -> Result<(), u8> {
        let Some(buf) = &self.net_buffer else {
            return Err(reason::TCP);
        };
        let at = i * 2 * WINDOW;
        while !c.eof && c.session.readable() < MAX_PLAIN {
            let req = NetRequest::TcpPoll {
                conn: c.net,
                offset: at as u32,
                max: WINDOW as u32,
            };
            match self
                .net(&req)
                .and_then(|(out, len)| net::parse_count(&out[..len]))
            {
                Some((net::OK, 0)) => c.eof = true,
                // More than was asked for: never trusted (review F1, #274).
                Some((net::OK, n)) if n as usize > WINDOW => return Err(reason::TCP),
                Some((net::OK, n)) => {
                    c.active = uptime();
                    let mut data = vec![0u8; n as usize];
                    buf.read_bytes(at, &mut data);
                    if c.session.receive(&data).is_err() {
                        return Err(reason::PROTOCOL);
                    }
                }
                Some((net::NOT_FOUND, _)) => break,
                _ => return Err(reason::TCP),
            }
        }
        Ok(())
    }

    /// Answers connection `i`'s waiting `READ` if it can be.
    fn deliver(&mut self, i: usize) {
        let Some(c) = self.conns[i].as_mut() else {
            return;
        };
        let Some((reply, offset, max)) = c.read else {
            return;
        };
        let dead = matches!(c.phase, Phase::Dead);
        let ended = c.session.peer_closed() || c.eof;
        if c.session.readable() == 0 && !ended && !dead {
            return;
        }
        c.read = None;
        if c.session.readable() == 0 {
            // `close_notify`: 0 bytes, the end. Anything else: gone.
            let s = if c.session.peer_closed() { OK } else { CLOSED };
            return answer(reply, &count(s, 0));
        }
        let mut data = vec![0u8; c.session.readable().min(max as usize)];
        let n = c.session.read(&mut data);
        let client = &self.clients[usize::from(c.client - 1)];
        match client.buffer.as_ref() {
            Some(b) if u64::from(offset) + n as u64 <= b.len() as u64 => {
                b.write_bytes(offset as usize, &data[..n]);
                answer(reply, &count(OK, n as u32));
            }
            _ => answer(reply, &count(NO_BUFFER, 0)),
        }
    }

    /// One round over the connections: send, receive, and move each on.
    fn poll(&mut self) {
        let now = uptime();
        for i in 0..MAX_CONNS {
            let Some(mut c) = self.conns[i].take() else {
                continue;
            };
            if !matches!(c.phase, Phase::Handshake { .. }) && now > c.active + IDLE_US {
                self.conns[i] = Some(c);
                self.finish(i, true);
                continue;
            }
            if matches!(c.phase, Phase::Dead) {
                // Only its client's `CLOSE` is left; answer a waiting read.
                self.conns[i] = Some(c);
                self.deliver(i);
                continue;
            }
            let pushed = self.push(i, &mut c);
            let pulled = self.pull(i, &mut c);
            // The handshake may have queued more (its Finished).
            let pushed = pushed && self.push(i, &mut c);
            let mut done = None;
            match c.phase {
                Phase::Handshake { reply, deadline } => {
                    let why = match (c.session.error(), &pulled) {
                        (Some(e), _) => Some(refusal_reason(e)),
                        (None, Err(r)) => Some(*r),
                        _ if !pushed => Some(reason::TCP),
                        _ if c.session.is_open() => None,
                        _ if c.eof => Some(reason::PROTOCOL),
                        _ if now > deadline => Some(reason::TIMEOUT),
                        _ => {
                            self.conns[i] = Some(c);
                            continue;
                        }
                    };
                    match why {
                        // No record of the success, no connection (review
                        // F5, #274).
                        None if self
                            .audit(Kind::Outcome, c.intent, outcome::OK, b"ok")
                            .is_none() =>
                        {
                            answer(reply, &encode_opened(NO_AUDIT, 0, 0));
                            c.phase = Phase::Dead;
                            done = Some(true);
                        }
                        None => {
                            c.phase = Phase::Open;
                            answer(reply, &encode_opened(OK, i as u8, 0));
                        }
                        Some(r) => {
                            let mut d = *b"handshake 0";
                            d[10] = b'0' + r;
                            let _ = self.audit(Kind::Outcome, c.intent, outcome::FAILED, &d);
                            answer(reply, &encode_opened(HANDSHAKE, 0, r));
                            c.phase = Phase::Dead;
                            done = Some(false);
                        }
                    }
                }
                Phase::Open => {
                    if c.session.error().is_some() || pulled.is_err() || !pushed {
                        c.phase = Phase::Dead;
                    }
                }
                Phase::Dead => {}
            }
            self.conns[i] = Some(c);
            if let Some(notify) = done {
                self.finish(i, notify);
            } else {
                self.deliver(i);
            }
        }
    }
}

fn refusal_reason(e: &pharos_tls::rustls::Error) -> u8 {
    match pharos_tls::refusal(e) {
        Refusal::UnknownIssuer => reason::UNKNOWN_ISSUER,
        Refusal::Expired => reason::EXPIRED,
        Refusal::Name => reason::NAME,
        Refusal::Certificate => reason::CERTIFICATE,
        Refusal::Protocol => reason::PROTOCOL,
    }
}

fn push_number(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

fn main(_: u64) -> u64 {
    let rng = match Rng::init(RNG_DEVICE, BASE) {
        Ok(r) => Some(r),
        Err(why) => {
            say(b"tls: no virtio-rng; every OPEN is NO_RANDOM");
            say(why.as_bytes());
            None
        }
    };
    let roots = read_roots();
    let config = pharos_tls::config(roots, &RANDOM, Arc::new(Clock)).ok();
    let Ok(reply) = endpoint_create() else {
        say(b"tls: cannot create an endpoint");
        return 1;
    };
    // One buffer at the network service for every connection's TCP data.
    let net_buffer = mem_map(NET_BUFFER as u64).ok().filter(|b| {
        let mut msg = [0u8; 16];
        let n = net::encode(
            &NetRequest::Attach {
                len: NET_BUFFER as u64,
            },
            &mut msg,
        )
        .unwrap_or(0);
        mem_share(b).is_ok_and(|m| send(NET, &msg[..n], m, READ_WRITE, 0).is_ok())
    });
    if net_buffer.is_none() {
        say(b"tls: no buffer at the network service");
    }
    let mut s = Service {
        config,
        rng,
        clients: Default::default(),
        conns: Default::default(),
        net_buffer,
        reply,
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let mut buf = [0u8; 256];
    let mut out = [0u8; 256];
    loop {
        let live = (s.conns.iter().flatten()).any(|c| !matches!(c.phase, Phase::Dead));
        let wait = if live { TICK_US } else { pharos_user::FOREVER };
        match receive_timeout(SERVICE, &mut buf, wait) {
            Ok(Received::Message { len, cap, badge }) => {
                let n = len.min(buf.len());
                let msg = buf;
                s.handle(&msg[..n], badge, cap, &mut out);
            }
            Ok(Received::Notification(_)) | Err(_) => {}
        }
        s.poll();
    }
}

const READ_WRITE: u32 = pharos_user::rights::READ | pharos_user::rights::WRITE;
