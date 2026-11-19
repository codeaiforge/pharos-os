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
//! (read-write), 5 the `AuditAnchor` key (D-047, #256). After each record
//! it stores, the service appends a signed head (`pharos_image::head`:
//! the stream's count and chain head, and the boot measurement, signed
//! with Ed25519 under the key) to `head/<boot>`; `cargo xtask store audit
//! --key` checks a trail against the last one. Without the key it signs
//! nothing, and the verifier rejects the trail. A boot is the next number after the highest `log/<n>`;
//! its first record is a `boot` event. An entry the store does not take
//! (full, failing, or not answering within 10 s) answers `UNWRITABLE`, and
//! the caller refuses the action. A restarted service starts a new stream;
//! until the store says which (#214), every entry is `UNWRITABLE`.
//!
//! After each record it asks the store how full the trail is (`SPACE`,
//! D-048, #217) and, once per boot for each level of `WARN_AT` it crosses,
//! reports `full <level>` to `init`, which tells `trust`. The report is
//! offered with `try_send`, never a blocking send, since `init` calls this
//! service too; it is offered again every 100 ms until `init` takes it.
//!
//! `ROTATE`, from `trust` only, frees every stream before this boot's
//! (`log/<n>` and `head/<n>`) if they give the code `cargo xtask store
//! export` printed for them (`pharos_image::head::export_code`, D-048). It
//! frees them first and then stores a `rotate` record naming the code:
//! the trail is usually full by then, and the record needs the room.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_programs::sequence::Sequence;
use pharos_proto::audit::{
    self, Entry, Head, Kind, MAX_RECORD, NO_EXPORT, Record, Request, UNWRITABLE, WARN_AT, action,
    client, full_report, outcome,
};
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{refusal, status};
use pharos_user::{
    Handle, Received, call_timeout, debug_write, endpoint_create, key_measurement, key_read,
    receive, receive_timeout, send, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const STORE: Handle = 4;
const ANCHOR: Handle = 5;
const STORE_US: u64 = 10_000_000;

struct Audit {
    reply: Handle,
    /// `log/<boot>`.
    path: [u8; 16],
    path_len: usize,
    boot: u32,
    /// The next sequence number (#216).
    sequence: Sequence,
    head: [u8; 32],
    /// The `AuditAnchor` key, the Ed25519 seed; `None` without one.
    seed: Option<[u8; 32]>,
    /// The boot measurement the kernel took (zeros if it took none).
    measurement: [u8; 32],
    /// The seed's public key, for `HEAD` (zeros without a seed, #262).
    public: [u8; 32],
    /// Records under the last signed head the store took.
    signed: u64,
    /// The highest `WARN_AT` level the trail has crossed, and the highest
    /// `init` has taken (D-048).
    warn_due: u8,
    warn_sent: u8,
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

/// `<prefix><boot>` in `out`; its length.
fn named(prefix: &[u8], boot: u32, out: &mut [u8; 16]) -> usize {
    let mut d = [0u8; 20];
    let digits = decimal(u64::from(boot), &mut d);
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..prefix.len() + digits.len()].copy_from_slice(digits);
    prefix.len() + digits.len()
}

/// 8 bytes as 16 lowercase hexadecimal digits.
fn hex8(bytes: &[u8; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = b"0123456789abcdef"[usize::from(b >> 4)];
        out[2 * i + 1] = b"0123456789abcdef"[usize::from(b & 15)];
    }
    out
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
        Some(self.boots()?.into_iter().max().unwrap_or(0))
    }

    /// The boot number of every `log/<n>` in the store.
    fn boots(&self) -> Option<Vec<u32>> {
        let mut out = [0u8; 256];
        let mut boots = Vec::new();
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
                boots.extend(boot_of(name));
                at += 1 + len;
            }
            start += u32::from(count);
            if more == 0 || count == 0 {
                return Some(boots);
            }
        }
    }

    /// Opens this boot's stream: the next number after the highest
    /// `log/<n>`, with its `boot` record first. False if the store cannot
    /// say which that is or does not take the record: nothing is appended
    /// until then (#214), so no record lands in an earlier boot's stream.
    fn open(&mut self) -> bool {
        let Some(boot) = self.last_boot().and_then(|b| b.checked_add(1)) else {
            return false;
        };
        let mut d = [0u8; 20];
        let digits = decimal(u64::from(boot), &mut d);
        self.path[..4].copy_from_slice(b"log/");
        self.path[4..4 + digits.len()].copy_from_slice(digits);
        self.path_len = 4 + digits.len();
        self.boot = boot;
        self.sequence = Sequence::default();
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
        if self.write(client::AUDIT, first).is_none() {
            self.boot = 0;
            return false;
        }
        let mut d = [0u8; 20];
        let digits = decimal(u64::from(boot), &mut d);
        say(&[b"audit: boot ", digits, b", log/", digits]);
        true
    }

    /// Stores `entry` from `client` in this boot's stream, opened first if
    /// it is not yet; its sequence number, or `None` if not stored.
    fn append(&mut self, client: u8, entry: Entry<'_>) -> Option<u64> {
        if self.boot == 0 && !self.open() {
            return None;
        }
        self.write(client, entry)
    }

    /// The stream's record count, from the store.
    fn count(&self) -> Option<u64> {
        Some(self.stat(&self.path[..self.path_len])?.0)
    }

    /// A stream's record count and chain head, from the store.
    fn stat(&self, path: &[u8]) -> Option<(u64, [u8; 32])> {
        let mut out = [0u8; 256];
        match self.store(&StoreRequest::Stat { path }, &mut out)? {
            (StoreStatus::Ok, 50) => Some((
                u64::from_le_bytes(out[10..18].try_into().ok()?),
                out[18..50].try_into().ok()?,
            )),
            _ => None,
        }
    }

    /// `ROTATE` (D-048): the status, and how many streams were freed.
    fn rotate(&mut self, code: [u8; 8]) -> (u8, u32) {
        if self.boot == 0 && !self.open() {
            return (UNWRITABLE, 0);
        }
        let Some(mut boots) = self.boots() else {
            return (UNWRITABLE, 0);
        };
        boots.retain(|b| *b < self.boot);
        boots.sort_unstable();
        let (Some(&first), Some(&last)) = (boots.first(), boots.last()) else {
            return (status::NOT_FOUND, 0);
        };
        let mut streams = Vec::new();
        for &boot in &boots {
            let mut path = [0u8; 16];
            let n = named(b"log/", boot, &mut path);
            let Some((records, head)) = self.stat(&path[..n]) else {
                return (UNWRITABLE, 0);
            };
            streams.push((boot, records, head));
        }
        if pharos_image::head::export_code(streams) != code {
            return (NO_EXPORT, 0);
        }
        // ponytail: a store failure part-way leaves the rest, whose code
        // then differs; the user exports again.
        for &boot in &boots {
            for prefix in [&b"log/"[..], b"head/"] {
                let mut path = [0u8; 16];
                let n = named(prefix, boot, &mut path);
                let mut out = [0u8; 256];
                match self.store(&StoreRequest::Delete { path: &path[..n] }, &mut out) {
                    Some((StoreStatus::Ok | StoreStatus::NotFound, _)) => {}
                    _ => return (UNWRITABLE, 0),
                }
            }
        }
        let mut detail = [0u8; 64];
        let mut n = 0;
        let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
        let parts: [&[u8]; 6] = [
            b"export ",
            &hex8(&code),
            b" boots ",
            decimal(first.into(), &mut a),
            b"-",
            decimal(last.into(), &mut b),
        ];
        for p in parts {
            detail[n..n + p.len()].copy_from_slice(p);
            n += p.len();
        }
        // Warned again as the new trail fills.
        (self.warn_due, self.warn_sent) = (0, 0);
        let entry = Entry {
            kind: Kind::Event,
            refers: 0,
            actor: b"user",
            task: 0,
            attempt: 0,
            action: action::ROTATE,
            permission: None,
            service: b"audit",
            outcome: outcome::OK,
            detail: &detail[..n],
        };
        say(&[b"audit: rotated: ", &detail[..n]]);
        if self.write(client::AUDIT, entry).is_none() {
            return (UNWRITABLE, boots.len() as u32);
        }
        (status::OK, boots.len() as u32)
    }

    /// Stores `entry` from `client`; its sequence number, or `None` if the
    /// store did not take it.
    fn write(&mut self, client: u8, entry: Entry<'_>) -> Option<u64> {
        let mut sequence = self.sequence;
        let next = sequence.next(|| self.count());
        self.sequence = sequence;
        let rec = Record {
            sequence: next?,
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
        match self.store(&req, &mut out) {
            Some((StoreStatus::Ok, 41)) => {
                let mut number = [0u8; 8];
                number.copy_from_slice(&out[1..9]);
                self.sequence.stored(u64::from_le_bytes(number));
                self.head.copy_from_slice(&out[9..41]);
                self.sign();
                self.check_space();
                Some(rec.sequence)
            }
            // Perhaps taken, its answer lost: counted before the next.
            _ => {
                self.sequence.failed();
                None
            }
        }
    }

    /// Appends the signed head of the stream as it is now to `head/<boot>`
    /// (D-047). A head the store does not take leaves the records after the
    /// last one unsigned, which the verifier reports; the record itself is
    /// stored, so its caller is not refused.
    fn sign(&mut self) {
        let Some(seed) = self.seed else { return };
        let signed = pharos_image::head::Head {
            boot: self.boot,
            records: self.sequence.records(),
            chain: self.head,
            measurement: self.measurement,
            uptime_us: uptime(),
        }
        .sign(&seed);
        let mut path = [0u8; 16];
        path[..5].copy_from_slice(b"head/");
        let digits = &self.path[4..self.path_len];
        path[5..5 + digits.len()].copy_from_slice(digits);
        let req = StoreRequest::Append {
            path: &path[..5 + digits.len()],
            record: &signed,
        };
        let mut out = [0u8; 256];
        if matches!(self.store(&req, &mut out), Some((StoreStatus::Ok, _))) {
            self.signed = self.sequence.records();
        } else {
            say(&[b"audit: signed head not stored"]);
        }
    }

    /// Asks the store how full the trail is, and notes each `WARN_AT`
    /// level crossed (D-048, #217).
    fn check_space(&mut self) {
        let mut out = [0u8; 256];
        if let Some((StoreStatus::Ok, 2)) = self.store(&StoreRequest::Space, &mut out) {
            for level in WARN_AT {
                if out[1] >= level && self.warn_due < level {
                    self.warn_due = level;
                    let mut d = [0u8; 20];
                    say(&[
                        b"audit: the trail is ",
                        decimal(level.into(), &mut d),
                        b"% full",
                    ]);
                }
            }
        }
    }

    /// Offers `init` each crossed level it has not taken, lowest first;
    /// true while one is still waiting.
    fn report_space(&mut self) -> bool {
        for level in WARN_AT {
            if level <= self.warn_due && level > self.warn_sent {
                if try_send(REPORT, &full_report(level)).is_err() {
                    return true;
                }
                self.warn_sent = level;
            }
        }
        false
    }

    /// One `call` from `badge`; writes the reply into `out`.
    fn handle(&mut self, msg: &[u8], badge: u32, out: &mut [u8; 256]) -> usize {
        let req = match audit::parse(msg) {
            Ok(req) => req,
            Err(refused) => return refusal(refused, audit::VERSION, out),
        };
        // No badge: `init`, the only holder of an unbadged capability
        // (it cannot badge a copy of its own; #108).
        let client = match badge {
            0 => client::INIT,
            b => match u8::try_from(b) {
                Ok(c) if c != client::AUDIT && c != client::INIT => c,
                _ => {
                    out[0] = status::NO_ACCESS;
                    return 1;
                }
            },
        };
        match req {
            Request::Rotate(code) if client == client::TRUST => {
                let (code, freed) = self.rotate(code);
                out[0] = code;
                out[1..5].copy_from_slice(&freed.to_le_bytes());
                5
            }
            Request::Rotate(_) => {
                out[0] = status::NO_ACCESS;
                1
            }
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
            // Opened first if it is not yet (#214): boot 0 means none.
            Request::Head if self.boot == 0 && !self.open() => Head {
                boot: 0,
                records: 0,
                head: [0; 32],
                signed: 0,
                key: self.public,
                measurement: self.measurement,
            }
            .encode(out)
            .unwrap_or(0),
            Request::Head => Head {
                boot: self.boot,
                records: self.sequence.records(),
                head: self.head,
                signed: self.signed,
                key: self.public,
                measurement: self.measurement,
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
        sequence: Sequence::default(),
        head: [0; 32],
        seed: key_read(ANCHOR).ok(),
        measurement: key_measurement(ANCHOR).unwrap_or([0; 32]),
        public: [0; 32],
        signed: 0,
        warn_due: 0,
        warn_sent: 0,
    };
    if let Some(seed) = &a.seed {
        a.public = pharos_image::public_key(seed);
    }
    if a.seed.is_none() {
        say(&[b"audit: no signing key; heads are not signed"]);
    }
    // With no store, the service still runs and answers `UNWRITABLE`
    // until it can open its stream (#214).
    if !a.open() {
        say(&[b"audit: the store does not take records; not yet a stream"]);
    }
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 2;
    }
    let mut msg = [0u8; 256];
    loop {
        let got = if a.report_space() {
            receive_timeout(SERVICE, &mut msg, 100_000)
        } else {
            receive(SERVICE, &mut msg)
        };
        if let Ok(Received::Message { len, cap, badge }) = got {
            let mut out = [0u8; 256];
            let n = a.handle(&msg[..len.min(256)], badge, &mut out);
            if cap != 0 {
                let _ = try_send(cap, &out[..n]);
                let _ = pharos_user::delete(cap);
            }
        }
    }
}
