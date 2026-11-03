//! The audit service (#107, capabilities.md): the only writer of the audit
//! trail. Clients (`init`, `trust`, the agent runtime) send entries with
//! `APPEND`; the service adds the sequence number, the time, and the
//! client's badge, and appends the record to this boot's stream,
//! `log/<boot>`, in the store's `audit` namespace, where the store chains
//! every record with SHA-256 (D-017). `HEAD` reports the stream, its
//! record count, and its chain head, which `trust` shows as the anchor.
//!
//! Handles: 1 the console, 2 its endpoint (`RECEIVE`), 3 `init`'s report
//! endpoint, 4 the storage service, badged for namespace `audit`
//! (read-write). A boot is the next number after the highest `log/<n>`;
//! its first record is a `boot` event. An entry the store does not take
//! (full, failing, or not answering within 10 s) answers `UNWRITABLE`, and
//! the caller refuses the action. A restarted service starts a new stream.

#![no_std]
#![no_main]

use pharos_proto::audit::{
    self, Entry, Head, Kind, MAX_RECORD, Record, Request, UNWRITABLE, action, client, outcome,
};
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{refusal, status};
use pharos_user::{
    Handle, Received, call_timeout, debug_write, endpoint_create, receive, send, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const STORE: Handle = 4;
const STORE_US: u64 = 10_000_000;

struct Audit {
    reply: Handle,
    /// `log/<boot>`.
    path: [u8; 16],
    path_len: usize,
    boot: u32,
    records: u64,
    head: [u8; 32],
}

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
    let mut line = [0u8; 128];
    let mut n = 0;
    for p in parts {
        let k = p.len().min(line.len() - n);
        line[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    let _ = debug_write(CONSOLE, &line[..n]);
}

/// A `log/<n>` name's number.
fn boot_of(name: &[u8]) -> Option<u32> {
    let digits = name.strip_prefix(b"log/")?;
    if digits.is_empty() || digits.len() > 9 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(digits.iter().fold(0, |n, d| n * 10 + u32::from(d - b'0')))
}

impl Audit {
    fn store(&self, req: &StoreRequest<'_>, out: &mut [u8; 256]) -> Option<(StoreStatus, usize)> {
        let mut msg = [0u8; 256];
        let n = store::encode(req, &mut msg)?;
        match call_timeout(STORE, &msg[..n], self.reply, out, STORE_US) {
            Ok(Received::Message { len, .. }) if len >= 1 => {
                Some((StoreStatus::from_code(out[0]), len.min(256)))
            }
            _ => None,
        }
    }

    /// The highest boot number already in the store (0: none).
    fn last_boot(&self) -> Option<u32> {
        let mut out = [0u8; 256];
        let mut last = 0;
        let mut start = 0u32;
        loop {
            let req = StoreRequest::List {
                prefix: b"log/",
                start,
            };
            let (s, n) = self.store(&req, &mut out)?;
            if s != StoreStatus::Ok || n < 3 {
                return None;
            }
            let (count, more) = (out[1], out[2]);
            let mut at = 3;
            for _ in 0..count {
                let len = usize::from(*out.get(at)?);
                let name = out.get(at + 1..at + 1 + len)?;
                last = last.max(boot_of(name).unwrap_or(0));
                at += 1 + len;
            }
            start += u32::from(count);
            if more == 0 || count == 0 {
                return Some(last);
            }
        }
    }

    /// Stores `entry` from `client`; its sequence number, or `None` if the
    /// store did not take it.
    fn append(&mut self, client: u8, entry: Entry<'_>) -> Option<u64> {
        let rec = Record {
            sequence: self.records,
            time: uptime(),
            client,
            entry,
        };
        let mut bytes = [0u8; MAX_RECORD];
        let n = rec.encode(&mut bytes)?;
        let req = StoreRequest::Append {
            path: &self.path[..self.path_len],
            record: &bytes[..n],
        };
        let mut out = [0u8; 256];
        match self.store(&req, &mut out)? {
            (StoreStatus::Ok, 41) => {
                let mut number = [0u8; 8];
                number.copy_from_slice(&out[1..9]);
                self.records = u64::from_le_bytes(number) + 1;
                self.head.copy_from_slice(&out[9..41]);
                Some(rec.sequence)
            }
            _ => None,
        }
    }

    /// One `call` from `badge`; writes the reply into `out`.
    fn handle(&mut self, msg: &[u8], badge: u32, out: &mut [u8; 256]) -> usize {
        let req = match audit::parse(msg) {
            Ok(req) => req,
            Err(refused) => return refusal(refused, audit::VERSION, out),
        };
        let Some(client) = u8::try_from(badge).ok().filter(|c| *c != 0) else {
            out[0] = status::NO_ACCESS;
            return 1;
        };
        match req {
            Request::Append(entry) => match self.append(client, entry) {
                Some(seq) => {
                    out[0] = status::OK;
                    out[1..9].copy_from_slice(&seq.to_le_bytes());
                    9
                }
                None => {
                    out[0] = UNWRITABLE;
                    1
                }
            },
            Request::Head => Head {
                boot: self.boot,
                records: self.records,
                head: self.head,
            }
            .encode(out)
            .unwrap_or(0),
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(reply) = endpoint_create() else {
        return 1;
    };
    let mut a = Audit {
        reply,
        path: [0; 16],
        path_len: 0,
        boot: 0,
        records: 0,
        head: [0; 32],
    };
    // With no store, the service still runs and answers `UNWRITABLE`.
    let boot = a.last_boot().map_or(1, |b| b + 1);
    a.boot = boot;
    let mut d = [0u8; 20];
    let digits = decimal(u64::from(boot), &mut d);
    a.path[..4].copy_from_slice(b"log/");
    a.path[4..4 + digits.len()].copy_from_slice(digits);
    a.path_len = 4 + digits.len();
    let first = Entry {
        kind: Kind::Event,
        refers: 0,
        actor: b"",
        task: 0,
        attempt: 0,
        action: action::BOOT,
        permission: None,
        service: b"",
        outcome: outcome::OK,
        detail: b"",
    };
    let stored = a.append(client::AUDIT, first).is_some();
    let mut d = [0u8; 20];
    let digits = decimal(u64::from(boot), &mut d);
    if stored {
        say(&[b"audit: boot ", digits, b", log/", digits]);
    } else {
        say(&[
            b"audit: boot ",
            digits,
            b": the store does not take records",
        ]);
    }
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 2;
    }
    let mut msg = [0u8; 256];
    loop {
        if let Ok(Received::Message { len, cap, badge }) = receive(SERVICE, &mut msg) {
            let mut out = [0u8; 256];
            let n = a.handle(&msg[..len.min(256)], badge, &mut out);
            if cap != 0 {
                let _ = try_send(cap, &out[..n]);
                let _ = pharos_user::delete(cap);
            }
        }
    }
}
