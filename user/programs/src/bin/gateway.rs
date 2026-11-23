//! The egress gateway (gateway.md, D-035, #282): sends an HTTPS request a
//! compiled route describes, with the route's secret, released by the
//! vault, in the route's header, and hands the answer back with the
//! secret stripped. A client names a route, a path the route's pattern
//! allows, and a body; never a host, a header, or a secret.
//!
//! Capabilities, in handle order: 1 the debug console, 2 `RECEIVE` on its
//! endpoint (client 1 the agent runtime, 2 test programs), 3 `init`'s
//! report endpoint, 4 `SEND` on the vault (badge 1), 5 `SEND` on the TLS
//! service as a TLS client, whose destinations are its entry's `tls`
//! list, 6 `SEND` on the audit service as client 6. Its argument is the
//! table's number, whose routes and destinations it reads.
//!
//! A request, in order (gateway.md): the client's checks, the intent
//! recorded, the secret released, the connection opened, the request
//! written, the secret erased, the answer read to the server's close and
//! parsed with no secret in memory, the secret released again to strip
//! it, the outcome recorded, the answer. Every refusal is recorded too.
//! Any failure closes the connection and erases what was released.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use pharos_programs::gateway as logic;
use pharos_proto::audit::{self, Entry, Kind, action, outcome};
use pharos_proto::gateway::{
    self, ANSWER, Answered, MAX_BUFFER, NAME, NO_ACCESS, NO_AUDIT, NO_BUFFER, OK, Request, TIMEOUT,
    TIMEOUT_US, TLS as TLS_FAILED, VERSION,
};
use pharos_proto::http::reason;
use pharos_proto::net::parse_count;
use pharos_proto::tls::{self, Request as Tls};
use pharos_proto::vault::{self, Request as Vault};
use pharos_proto::{Info, refusal, status};
use pharos_services::Route;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map,
    mem_map_cap, mem_share, mem_unmap, receive, send, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const VAULT: Handle = 4;
const TLS: Handle = 5;
const AUDIT: Handle = 6;
/// Its clients' badges: 1 the runtime, 2 test programs.
const CLIENTS: usize = pharos_services::GATEWAY_CLIENTS as usize;
/// Its buffers at the vault (a prefix and a value) and the TLS service.
const VAULT_BUFFER: u64 = vault::MAX_BUFFER;
const TLS_BUFFER: u64 = tls::MAX_BUFFER;
/// How long the vault and the audit service may take to answer.
const CALL_US: u64 = 1_000_000;

fn say(msg: &[u8]) {
    let _ = debug_write(CONSOLE, msg);
}

/// Sends `bytes` on the reply capability without blocking, then lets go.
fn answer(reply: Handle, bytes: &[u8]) {
    let _ = try_send(reply, bytes);
    let _ = delete(reply);
}

fn failed(status: u8, detail: u8, http: u16) -> Answered {
    Answered {
        status,
        detail,
        http,
        ..Answered::default()
    }
}

struct Gateway {
    routes: &'static [Route],
    /// Each destination's server name, for `Host` (the TLS service checks
    /// the certificate against the same name).
    hosts: Vec<&'static [u8]>,
    clients: [Option<Mapped>; CLIENTS],
    vault: Mapped,
    tls: Mapped,
    reply: Handle,
}

impl Gateway {
    fn handle(&mut self, msg: &[u8], badge: u32, cap: Handle, out: &mut [u8; 256]) {
        let req = match gateway::parse(msg) {
            Ok(r) => r,
            Err(why) => {
                if cap != 0 {
                    let n = refusal(why, VERSION, out);
                    answer(cap, &out[..n]);
                }
                return;
            }
        };
        let client = (1..=CLIENTS as u32).contains(&badge).then_some(badge as u8);
        if let Request::Attach { len } = req {
            return self.attach(client, cap, len);
        }
        if cap == 0 {
            return;
        }
        match req {
            Request::Info => {
                let info = Info {
                    name: NAME,
                    low: VERSION,
                    high: VERSION,
                    details: &[],
                };
                let n = info.encode(out).unwrap_or(0);
                answer(cap, &out[..n]);
            }
            Request::Request {
                route,
                path_len,
                body_len,
            } => {
                let a = match client {
                    Some(c) => self.request(c, route, path_len.into(), body_len as usize),
                    None => self.refused(NO_ACCESS, &logic::refusal_detail(0, route, NO_ACCESS)),
                };
                answer(cap, &a.encode());
            }
            Request::Attach { .. } => {}
        }
    }

    fn attach(&mut self, client: Option<u8>, memory: Handle, len: u64) {
        let mapped = match client {
            Some(_) if memory != 0 && len <= MAX_BUFFER => mem_map_cap(memory, true, len).ok(),
            _ => None,
        };
        if memory != 0 {
            let _ = delete(memory);
        }
        if let (Some(c), Some(m)) = (client, mapped)
            && let Some(old) = self.clients[usize::from(c) - 1].replace(m)
        {
            let _ = mem_unmap(old);
        }
    }

    /// One request from `client`; what to answer.
    fn request(&mut self, client: u8, name: &[u8], path_len: usize, body_len: usize) -> Answered {
        let found = self.routes.iter().position(|r| r.name.as_bytes() == name);
        let route = found.map(|i| &self.routes[i]);
        // A route is a byte at the vault (at most 32 per table).
        let index = found.unwrap_or(0) as u8;
        let buffer = self.clients[usize::from(client) - 1].as_ref();
        let Some(b) = buffer.filter(|b| path_len + body_len <= b.len()) else {
            let d = logic::refusal_detail(client, name, NO_BUFFER);
            return self.refused(NO_BUFFER, &d);
        };
        let mut target = vec![0u8; path_len];
        let mut body = vec![0u8; body_len];
        b.read_bytes(0, &mut target);
        b.read_bytes(path_len, &mut body);
        let room = b.len();
        let r = match logic::check(route, client, &target, body_len) {
            Ok(r) => r,
            Err(s) => {
                let d = logic::refusal_detail(client, name, s);
                return self.refused(s, &d);
            }
        };
        let detail = logic::intent_detail(client, r, &target, &body);
        let Some(seq) = self.audit(Kind::Intent, 0, outcome::NONE, &detail) else {
            return failed(NO_AUDIT, 0, 0);
        };
        let deadline = uptime() + TIMEOUT_US;
        let (a, bytes) = match self.exchange(index, r, &target, &body, room, deadline) {
            Ok((bytes, a)) => (a, Some(bytes)),
            Err(a) => (a, None),
        };
        let ok = if a.status == OK {
            outcome::OK
        } else {
            outcome::FAILED
        };
        if self
            .audit(Kind::Outcome, seq, ok, &logic::outcome_detail(&a))
            .is_none()
        {
            return failed(NO_AUDIT, 0, 0);
        }
        // Written only once the outcome is recorded: else nothing reaches
        // the client.
        if let (Some(bytes), Some(b)) = (bytes, self.clients[usize::from(client) - 1].as_ref()) {
            b.write_bytes(0, &bytes);
        }
        a
    }

    /// Records a refusal; what to answer (`NO_AUDIT` if it was not stored).
    fn refused(&self, s: u8, detail: &[u8]) -> Answered {
        match self.audit(Kind::Event, 0, outcome::REFUSED, detail) {
            Some(_) => failed(s, 0, 0),
            None => failed(NO_AUDIT, 0, 0),
        }
    }

    /// Everything between the intent and the outcome.
    fn exchange(
        &mut self,
        index: u8,
        r: &Route,
        target: &[u8],
        body: &[u8],
        room: usize,
        deadline: u64,
    ) -> Result<(Vec<u8>, Answered), Answered> {
        let host = self.hosts.get(usize::from(r.dest)).copied();
        let host = host.ok_or(failed(TLS_FAILED, tls::NO_ACCESS, 0))?;
        let mut secret = self.release(index, r)?;
        let opened = self.call_tls(
            &Tls::Open {
                destination: r.dest,
            },
            deadline,
        );
        let conn = match opened
            .as_ref()
            .and_then(|(m, n)| tls::parse_opened(&m[..*n]))
        {
            Some((tls::OK, conn, _)) => conn,
            Some((s, _, why)) => {
                logic::erase(&mut secret);
                return Err(failed(TLS_FAILED, s, why.into()));
            }
            None => {
                logic::erase(&mut secret);
                return Err(failed(TIMEOUT, 0, 0));
            }
        };
        let request = logic::request(r, host, target, &secret, body);
        logic::erase(&mut secret);
        let result = match request {
            Some(mut bytes) => {
                let sent = self.write(conn, &bytes, deadline);
                logic::erase(&mut bytes);
                // The TLS buffer held the head too.
                self.tls
                    .write_bytes(0, &vec![0u8; bytes.len().min(self.tls.len())]);
                sent.and_then(|()| self.read(conn, r, deadline))
            }
            None => Err(failed(ANSWER, reason::TOO_LARGE, 0)),
        };
        let _ = self.call_tls(&Tls::Close { conn }, deadline.max(uptime() + CALL_US));
        let (raw, complete) = result?;
        let parsed = logic::parse(&raw, complete, r).map_err(|why| failed(ANSWER, why, 0))?;
        // The secret again, only to strip it from what was parsed.
        let mut secret = self.release(index, r)?;
        let prefix = r.header.1.as_bytes();
        let value = secret.get(prefix.len()..).unwrap_or(&[]);
        let stripped = logic::strip(&parsed, prefix, value, room);
        logic::erase(&mut secret);
        stripped.ok_or(failed(ANSWER, reason::TOO_LARGE, parsed.http))
    }

    /// `prefix ‖ value` from the vault, or nothing for a route without a
    /// secret; the vault's buffer is cleared at once.
    fn release(&mut self, index: u8, r: &Route) -> Result<Vec<u8>, Answered> {
        if r.secret.is_none() {
            return Ok(Vec::new());
        }
        let mut msg = [0u8; 8];
        let n = vault::encode(&Vault::Release { route: index }, &mut msg).unwrap_or(0);
        let mut out = [0u8; 16];
        let got = match call_timeout(VAULT, &msg[..n], self.reply, &mut out, CALL_US) {
            Ok(Received::Message { len, cap, .. }) => {
                if cap != 0 {
                    let _ = delete(cap);
                }
                vault::parse_released(&out[..len.min(out.len())])
            }
            _ => None,
        };
        match got {
            Some((vault::OK, len)) if usize::from(len) <= self.vault.len() => {
                let mut secret = vec![0u8; len.into()];
                self.vault.read_bytes(0, &mut secret);
                self.vault.write_bytes(0, &vec![0u8; len.into()]);
                Ok(secret)
            }
            Some((s, _)) if s != vault::OK => Err(failed(s, 0, 0)),
            _ => Err(failed(status::INTERNAL, 0, 0)),
        }
    }

    /// One call to the TLS service within the deadline.
    fn call_tls(&self, req: &Tls<'_>, deadline: u64) -> Option<([u8; 256], usize)> {
        let mut msg = [0u8; 256];
        let n = tls::encode(req, &mut msg)?;
        let left = deadline.checked_sub(uptime()).filter(|t| *t > 0)?;
        let mut out = [0u8; 256];
        match call_timeout(TLS, &msg[..n], self.reply, &mut out, left) {
            Ok(Received::Message { len, cap, .. }) => {
                if cap != 0 {
                    let _ = delete(cap);
                }
                Some((out, len.min(256)))
            }
            _ => None,
        }
    }

    /// Writes `bytes` through the TLS buffer, a buffer's worth at a time.
    fn write(&self, conn: u8, bytes: &[u8], deadline: u64) -> Result<(), Answered> {
        for chunk in bytes.chunks(self.tls.len()) {
            self.tls.write_bytes(0, chunk);
            let req = Tls::Write {
                conn,
                offset: 0,
                len: chunk.len() as u32,
            };
            let reply = self.call_tls(&req, deadline).ok_or(failed(TIMEOUT, 0, 0))?;
            match parse_count(&reply.0[..reply.1]) {
                Some((tls::OK, n)) if n as usize == chunk.len() => {}
                Some((s, _)) => return Err(failed(TLS_FAILED, s, 0)),
                None => return Err(failed(TLS_FAILED, status::INTERNAL, 0)),
            }
        }
        Ok(())
    }

    /// The answer, to the server's close; whether it sent `close_notify`.
    fn read(&self, conn: u8, r: &Route, deadline: u64) -> Result<(Vec<u8>, bool), Answered> {
        // ponytail: room for the head, the body, and chunk sizes; a
        // chunked answer of many tiny chunks may be refused as too large.
        let limit = pharos_proto::http::MAX_HEAD + r.max_answer as usize + 4096;
        let mut raw = Vec::new();
        loop {
            let req = Tls::Read {
                conn,
                offset: 0,
                max: self.tls.len() as u32,
            };
            let reply = self.call_tls(&req, deadline).ok_or(failed(TIMEOUT, 0, 0))?;
            match parse_count(&reply.0[..reply.1]) {
                Some((tls::OK, 0)) => return Ok((raw, true)),
                Some((tls::CLOSED, _)) => return Ok((raw, false)),
                Some((tls::OK, n)) if n as usize <= self.tls.len() => {
                    let at = raw.len();
                    if at + n as usize > limit {
                        return Err(failed(ANSWER, reason::TOO_LARGE, 0));
                    }
                    raw.resize(at + n as usize, 0);
                    self.tls.read_bytes(0, &mut raw[at..]);
                }
                Some((s, _)) => return Err(failed(TLS_FAILED, s, 0)),
                None => return Err(failed(TLS_FAILED, status::INTERNAL, 0)),
            }
        }
    }

    /// Appends a record; its sequence number, or `None` if not stored.
    fn audit(&self, kind: Kind, refers: u64, ok: u8, detail: &[u8]) -> Option<u64> {
        let e = Entry {
            kind,
            refers,
            actor: b"",
            task: 0,
            attempt: 0,
            action: action::HTTPS,
            permission: None,
            service: b"gateway",
            outcome: ok,
            detail,
        };
        let mut msg = [0u8; 256];
        let n = audit::encode(&audit::Request::Append(e), &mut msg)?;
        let mut out = [0u8; 256];
        match call_timeout(AUDIT, &msg[..n], self.reply, &mut out, CALL_US) {
            Ok(Received::Message { len, cap, .. }) => {
                if cap != 0 {
                    let _ = delete(cap);
                }
                (len == 9 && out[0] == status::OK)
                    .then(|| u64::from_le_bytes(out[1..9].try_into().unwrap_or([0; 8])))
            }
            _ => None,
        }
    }
}

/// Maps a buffer of `len` and attaches it at `service` with `msg`.
fn attach(service: Handle, msg: &[u8], len: u64) -> Option<Mapped> {
    let b = mem_map(len).ok()?;
    let m = mem_share(&b).ok()?;
    send(service, msg, m, READ | WRITE, 0).ok()?;
    Some(b)
}

fn main(arg: u64) -> u64 {
    let entry = pharos_services::table(arg)
        .iter()
        .find(|s| s.name == "gateway");
    let hosts = entry.map_or(Vec::new(), |g| g.tls.iter().map(|d| d.2).collect());
    let mut msg = [0u8; 16];
    let n = vault::encode(&Vault::Attach { len: VAULT_BUFFER }, &mut msg).unwrap_or(0);
    let vault = attach(VAULT, &msg[..n], VAULT_BUFFER);
    let n = tls::encode(&Tls::Attach { len: TLS_BUFFER }, &mut msg).unwrap_or(0);
    let tls = attach(TLS, &msg[..n], TLS_BUFFER);
    let (Some(vault), Some(tls), Ok(reply)) = (vault, tls, endpoint_create()) else {
        say(b"gateway: cannot attach its buffers");
        return 1;
    };
    let mut g = Gateway {
        routes: pharos_services::routes(arg),
        hosts,
        clients: [const { None }; CLIENTS],
        vault,
        tls,
        reply,
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    // ponytail: one request at a time, each up to 30 s; per-client
    // deferred replies if two clients' requests must overlap.
    let mut buf = [0u8; 256];
    let mut out = [0u8; 256];
    loop {
        if let Ok(Received::Message { len, cap, badge }) = receive(SERVICE, &mut buf) {
            let n = len.min(buf.len());
            let msg = buf;
            g.handle(&msg[..n], badge, cap, &mut out);
        }
    }
}
