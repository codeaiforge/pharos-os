//! The knowledge service (#143, knowledge.md, D-025): shared entries as
//! immutable versions with provenance, in the store's `knowledge`
//! namespace. The logic is `pharos_programs::knowledge::Service`; this
//! program receives requests, keeps each client's buffer, and replies.
//!
//! Handles: 1 the console, 2 its endpoint (`RECEIVE`), 3 `init`'s report
//! endpoint, 4 the storage service, badged for namespace `knowledge`
//! (read-write). Clients are told apart by badge
//! (`pharos_proto::knowledge::client`). A client's buffer is copied out
//! before anything in it is read, so a client changing it meanwhile
//! changes nothing.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use pharos_programs::knowledge::{MAX_RECORD, Service};
use pharos_programs::tasks::{Files, StoreFailed};
use pharos_proto::knowledge::{self, MIN_BUFFER, Request};
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{refusal, status};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map,
    mem_map_cap, mem_share, receive, send, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const STORE: Handle = 4;
const STORE_US: u64 = 10_000_000;
/// Its own buffer at the store: one version record at a time.
const STORE_BUFFER: u64 = 8 << 10;
/// The largest buffer a client may attach, and how many clients keep one.
const MAX_CLIENT_BUFFER: u64 = 64 << 10;
const MAX_CLIENTS: usize = 4;

fn decimal(mut v: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    loop {
        at -= 1;
        out[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &out[at..];
        }
    }
}

fn say(parts: &[&[u8]]) {
    let line: Vec<u8> = parts.concat();
    let _ = debug_write(CONSOLE, &line);
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// The storage service as [`Files`], through this service's buffer there.
// ponytail: the runtime's `Store` without its health checks; one copy
// each until a third program needs it, then a shared module.
struct Store {
    buffer: Mapped,
    reply: Handle,
}

impl Store {
    fn call(
        &self,
        req: &StoreRequest<'_>,
        out: &mut [u8; 256],
    ) -> Result<StoreStatus, StoreFailed> {
        let mut msg = [0u8; 256];
        let n = store::encode(req, &mut msg).ok_or(StoreFailed)?;
        match call_timeout(STORE, &msg[..n], self.reply, out, STORE_US) {
            Ok(Received::Message { len, .. }) if len >= 1 => Ok(StoreStatus::from_code(out[0])),
            _ => Err(StoreFailed),
        }
    }

    /// Attaches the buffer at the storage service: at start, and again
    /// after it restarted and lost it.
    fn attach(&self) -> bool {
        let len = self.buffer.len() as u64;
        let attached = mem_share(&self.buffer).is_ok_and(|memory| {
            let mut msg = [0u8; 16];
            let sent = store::encode(&StoreRequest::Attach { len }, &mut msg)
                .is_some_and(|n| send(STORE, &msg[..n], memory, READ | WRITE, 0).is_ok());
            let _ = delete(memory);
            sent
        });
        let mut out = [0u8; 256];
        attached
            && self.call(&StoreRequest::Buffer, &mut out) == Ok(StoreStatus::Ok)
            && u64_at(&out, 1) == len
    }

    fn call_buffered(
        &self,
        req: &StoreRequest<'_>,
        out: &mut [u8; 256],
    ) -> Result<StoreStatus, StoreFailed> {
        match self.call(req, out)? {
            StoreStatus::NoBuffer if self.attach() => self.call(req, out),
            s => Ok(s),
        }
    }
}

impl Files for Store {
    fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
        if bytes.len() > self.buffer.len() {
            return Err(StoreFailed);
        }
        self.buffer.write_bytes(0, bytes);
        let req = StoreRequest::Write {
            path,
            len: bytes.len() as u64,
            at: 0,
        };
        match self.call_buffered(&req, &mut [0; 256])? {
            StoreStatus::Ok => Ok(()),
            _ => Err(StoreFailed),
        }
    }

    fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed> {
        let mut out = [0u8; 256];
        match self.call(&StoreRequest::Stat { path }, &mut out)? {
            StoreStatus::NotFound => return Ok(None),
            StoreStatus::Ok => {}
            _ => return Err(StoreFailed),
        }
        let len = u64_at(&out, 2);
        if len > self.buffer.len() as u64 {
            return Err(StoreFailed);
        }
        let req = StoreRequest::Read {
            path,
            offset: 0,
            len,
            at: 0,
        };
        if self.call_buffered(&req, &mut out)? != StoreStatus::Ok || u64_at(&out, 1) != len {
            return Err(StoreFailed);
        }
        let mut bytes = alloc::vec![0u8; len as usize];
        self.buffer.read_bytes(0, &mut bytes);
        Ok(Some(bytes))
    }

    // ponytail: never called; versions and marks are never deleted.
    fn delete(&mut self, _: &[u8]) -> Result<(), StoreFailed> {
        Err(StoreFailed)
    }

    fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed> {
        let mut names = Vec::new();
        loop {
            let mut out = [0u8; 256];
            let start = names.len() as u32;
            if self.call(&StoreRequest::List { prefix, start }, &mut out)? != StoreStatus::Ok {
                return Err(StoreFailed);
            }
            let (count, more) = (out[1], out[2]);
            let mut at = 3;
            for _ in 0..count {
                let n = usize::from(*out.get(at).ok_or(StoreFailed)?);
                names.push(out.get(at + 1..at + 1 + n).ok_or(StoreFailed)?.to_vec());
                at += 1 + n;
            }
            if more == 0 || count == 0 {
                return Ok(names);
            }
        }
    }
}

/// Each client's buffer, by badge.
struct Buffers([Option<(u32, Mapped)>; MAX_CLIENTS]);

impl Buffers {
    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let mapped = (MIN_BUFFER..=MAX_CLIENT_BUFFER)
            .contains(&len)
            .then(|| mem_map_cap(memory, true, len).ok())
            .flatten();
        let _ = delete(memory);
        let Some(m) = mapped else { return };
        let at = self
            .0
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.0 == badge))
            .or_else(|| self.0.iter().position(Option::is_none));
        match at {
            Some(at) => {
                if let Some((_, old)) = self.0[at].replace((badge, m)) {
                    let _ = pharos_user::mem_unmap(old);
                }
            }
            None => {
                let _ = pharos_user::mem_unmap(m);
            }
        }
    }

    fn of(&self, badge: u32) -> Option<&Mapped> {
        self.0
            .iter()
            .flatten()
            .find(|(b, _)| *b == badge)
            .map(|(_, m)| m)
    }
}

/// One request from `badge`; the reply in `out`.
fn handle(
    s: &mut Service,
    f: &mut Store,
    buffers: &Buffers,
    msg: &[u8],
    badge: u32,
    out: &mut [u8; 256],
) -> usize {
    let req = match knowledge::parse(msg) {
        Ok(req) => req,
        Err(refused) => return refusal(refused, knowledge::VERSION, out),
    };
    if !Service::allowed(badge, &req) {
        out[0] = status::NO_ACCESS;
        return 1;
    }
    let buffer = buffers.of(badge);
    let needs = !matches!(req, Request::Info | Request::Verify { .. });
    if needs && buffer.is_none() {
        out[0] = status::NO_BUFFER;
        return 1;
    }
    // Copied out first: the client may change its buffer meanwhile.
    let mut input = Vec::new();
    if let (Request::Put { len }, Some(b)) = (req, buffer) {
        if usize::from(len) > MAX_RECORD {
            out[0] = status::TOO_LARGE;
            return 1;
        }
        input = alloc::vec![0u8; usize::from(len)];
        b.read_bytes(0, &mut input);
    }
    let a = s.handle(f, badge, req, &input, uptime());
    if !a.buffer.is_empty() {
        match buffer {
            Some(b) if a.buffer.len() <= b.len() => b.write_bytes(0, &a.buffer),
            _ => {
                out[0] = status::NO_BUFFER;
                return 1;
            }
        }
    }
    let n = a.reply.len().min(out.len());
    out[..n].copy_from_slice(&a.reply[..n]);
    n
}

fn main(_: u64) -> u64 {
    let (Ok(reply), Ok(buffer)) = (endpoint_create(), mem_map(STORE_BUFFER)) else {
        return 1;
    };
    let mut f = Store { buffer, reply };
    if !f.attach() {
        say(&[b"knowledge: the store does not answer"]);
        return 2;
    }
    let Ok((mut s, loaded)) = Service::start(&mut f) else {
        say(&[b"knowledge: the store refused the start"]);
        return 3;
    };
    let (mut a, mut b, mut c, mut d) = ([0u8; 20], [0u8; 20], [0u8; 20], [0u8; 20]);
    say(&[
        b"knowledge: start ",
        decimal(u64::from(s.starts), &mut a),
        b", ",
        decimal(loaded.versions as u64, &mut b),
        b" versions, ",
        decimal(loaded.marks as u64, &mut c),
        b" marks, ",
        decimal(loaded.unreadable as u64, &mut d),
        b" unreadable",
    ]);
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 4;
    }
    let mut buffers = Buffers([const { None }; MAX_CLIENTS]);
    let mut msg = [0u8; 256];
    loop {
        let Ok(Received::Message { len, cap, badge }) = receive(SERVICE, &mut msg) else {
            continue;
        };
        let msg = &msg[..len.min(256)];
        if let Ok(Request::Attach { len }) = knowledge::parse(msg) {
            if cap != 0 {
                buffers.attach(badge, cap, len);
            }
            continue;
        }
        let mut out = [0u8; 256];
        let n = handle(&mut s, &mut f, &buffers, msg, badge, &mut out);
        if cap != 0 {
            let _ = try_send(cap, &out[..n]);
            let _ = delete(cap);
        }
    }
}
