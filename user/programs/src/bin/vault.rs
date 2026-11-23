//! The vault (gateway.md, D-035, #281): holds the host's secrets in
//! memory and releases one, for a route, to the gateway only. Nothing is
//! written to disk; the secrets come from the kernel's copy of the host's
//! `fw_cfg` file at each start.
//!
//! Capabilities, in handle order: 1 the debug console, 2 `RECEIVE` on its
//! endpoint (the gateway's badge is 1; any other is refused), 3 `init`'s
//! report endpoint, 4 the secrets file (`READ`), 5 `SEND` on the audit
//! service as client 5 (without it every `RELEASE` is `NO_AUDIT`). Its
//! argument is the table's number, whose routes it reads
//! (`pharos_services::routes`).
//!
//! Every `RELEASE`, released or refused, is recorded before it is
//! answered, by the route's and the secret's names; a value is never
//! recorded, logged, or sent anywhere but the gateway's buffer.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use pharos_proto::audit::{self, Entry, Kind, action, outcome};
use pharos_proto::vault::{
    self, MAX_BUFFER, MAX_FILE, NAME, NO_ACCESS, NO_AUDIT, NO_BUFFER, NO_SECRET, NOT_FOUND, OK,
    Request, Secrets, VERSION, encode_released,
};
use pharos_proto::{Info, refusal, status};
use pharos_services::Route;
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map_cap,
    mem_unmap, receive, secrets_read, send, try_send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const SECRETS: Handle = 4;
const AUDIT: Handle = 5;
/// The gateway's badge, the vault's only client.
const GATEWAY: u32 = 1;
/// How long the audit service may take to answer.
const CALL_US: u64 = 1_000_000;

fn say(msg: &[u8]) {
    let _ = debug_write(CONSOLE, msg);
}

/// Sends `bytes` on the reply capability without blocking, then lets go.
fn answer(reply: Handle, bytes: &[u8]) {
    let _ = try_send(reply, bytes);
    let _ = delete(reply);
}

struct Vault<'a> {
    secrets: Secrets<'a>,
    routes: &'static [Route],
    buffer: Option<Mapped>,
    reply: Handle,
}

impl Vault<'_> {
    fn handle(&mut self, msg: &[u8], badge: u32, cap: Handle, out: &mut [u8; 256]) {
        let req = match vault::parse(msg) {
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
            Request::Release { route } => {
                let (s, len) = self.release(badge, route);
                answer(cap, &encode_released(s, len));
            }
            Request::Attach { .. } => {}
        }
    }

    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let mapped = match badge {
            GATEWAY if memory != 0 && len <= MAX_BUFFER => mem_map_cap(memory, true, len).ok(),
            _ => None,
        };
        if memory != 0 {
            let _ = delete(memory);
        }
        if let Some(m) = mapped
            && let Some(old) = self.buffer.replace(m)
        {
            let _ = mem_unmap(old);
        }
    }

    /// `RELEASE`: the route's prefix and secret into the gateway's buffer,
    /// once the release is recorded. Every refusal is recorded too.
    fn release(&mut self, badge: u32, index: u8) -> (u8, u16) {
        let route = self.routes.get(usize::from(index));
        let secret = route.and_then(|r| r.secret);
        let value = secret.and_then(|s| self.secrets.get(s.as_bytes()));
        let prefix = route.map_or("", |r| r.header.1).as_bytes();
        let fits = |m: &Mapped| value.is_some_and(|v| prefix.len() + v.len() <= m.len());
        let s = match () {
            _ if badge != GATEWAY => NO_ACCESS,
            _ if route.is_none() => NOT_FOUND,
            _ if value.is_none() => NO_SECRET,
            _ if !self.buffer.as_ref().is_some_and(fits) => NO_BUFFER,
            _ => OK,
        };
        let mut detail = Vec::with_capacity(80);
        detail.extend_from_slice(b"release ");
        match route {
            Some(r) => detail.extend_from_slice(r.name.as_bytes()),
            None => push_number(&mut detail, u64::from(index)),
        }
        if let Some(name) = secret {
            detail.extend_from_slice(b" secret ");
            detail.extend_from_slice(name.as_bytes());
        }
        if s != OK {
            detail.extend_from_slice(b" status ");
            push_number(&mut detail, u64::from(s));
        }
        let ok = if s == OK {
            outcome::OK
        } else {
            outcome::REFUSED
        };
        if !self.audit(ok, &detail) {
            return (NO_AUDIT, 0);
        }
        match (s, value, &self.buffer) {
            (OK, Some(v), Some(m)) => {
                m.write_bytes(0, prefix);
                m.write_bytes(prefix.len(), v);
                (OK, (prefix.len() + v.len()) as u16)
            }
            _ => (s, 0),
        }
    }

    /// Appends an event; false if the audit service did not store it.
    fn audit(&self, ok: u8, detail: &[u8]) -> bool {
        let e = Entry {
            kind: Kind::Event,
            refers: 0,
            actor: b"",
            task: 0,
            attempt: 0,
            action: action::VAULT,
            permission: None,
            service: b"vault",
            outcome: ok,
            detail,
        };
        let mut msg = [0u8; 256];
        let Some(n) = audit::encode(&audit::Request::Append(e), &mut msg) else {
            return false;
        };
        let mut out = [0u8; 256];
        match call_timeout(AUDIT, &msg[..n], self.reply, &mut out, CALL_US) {
            Ok(Received::Message { len, cap, .. }) => {
                if cap != 0 {
                    let _ = delete(cap);
                }
                len == 9 && out[0] == status::OK
            }
            _ => false,
        }
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

fn main(arg: u64) -> u64 {
    // The file stays in this buffer for the vault's life; `Secrets`
    // borrows it.
    let mut file = vec![0u8; MAX_FILE];
    let len = match secrets_read(SECRETS, &mut file) {
        Ok(n) if n <= MAX_FILE => n,
        _ => {
            say(b"vault: no secrets file; every RELEASE is NO_SECRET");
            0
        }
    };
    let secrets = match vault::parse_secrets(&file[..len]) {
        Ok(s) => s,
        Err(line) => {
            let mut msg = Vec::from(&b"vault: the secrets file is refused at line "[..]);
            push_number(&mut msg, line as u64);
            say(&msg);
            Secrets::default()
        }
    };
    let mut msg = Vec::from(&b"vault: secrets: "[..]);
    push_number(&mut msg, secrets.len() as u64);
    say(&msg);
    let Ok(reply) = endpoint_create() else {
        say(b"vault: cannot create an endpoint");
        return 1;
    };
    let mut v = Vault {
        secrets,
        routes: pharos_services::routes(arg),
        buffer: None,
        reply,
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let mut buf = [0u8; 256];
    let mut out = [0u8; 256];
    loop {
        if let Ok(Received::Message { len, cap, badge }) = receive(SERVICE, &mut buf) {
            let n = len.min(buf.len());
            let msg = buf;
            v.handle(&msg[..n], badge, cap, &mut out);
        }
    }
}
