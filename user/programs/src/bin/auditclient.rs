//! The `audit` test kernel's client (#107). Handles: 1 the console, 2 and
//! 3 `SEND` on the audit service badged as clients 4 and 5, 4 the kernel's
//! step endpoint (`SEND`). Each passed step is sent as `ok <step>`, a
//! failed one printed; then `done`. Exits with the number of failures.
//!
//! Argument 0, the first boot of the service: `HEAD` shows the boot record,
//! entries from both clients get consecutive sequence numbers, an intent
//! and its outcome, malformed entries are refused. Argument 1, after the
//! kernel killed and restarted the service: a new stream; then the tiny
//! store fills and `APPEND` answers `UNWRITABLE`, while `HEAD` still works.

#![no_std]
#![no_main]

use pharos_proto::audit::{
    self, Entry, Head, Kind, Request, UNWRITABLE, VERSION, action, op, outcome,
};
use pharos_proto::status;
use pharos_user::{Handle, Received, call_timeout, debug_write, endpoint_create, send};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const A: Handle = 2;
const B: Handle = 3;
const STEPS: Handle = 4;

struct Client {
    reply: Handle,
    failed: u64,
}

fn entry(detail: &'static [u8]) -> Entry<'static> {
    Entry {
        kind: Kind::Event,
        refers: 0,
        actor: b"tester",
        task: 1,
        attempt: 1,
        action: action::SUBMIT,
        permission: None,
        service: b"audit",
        outcome: outcome::OK,
        detail,
    }
}

impl Client {
    fn raw(&self, to: Handle, msg: &[u8]) -> (u8, [u8; 256], usize) {
        let mut out = [0u8; 256];
        match call_timeout(to, msg, self.reply, &mut out, 20_000_000) {
            Ok(Received::Message { len, .. }) if len >= 1 => (out[0], out, len.min(256)),
            _ => (status::INTERNAL, out, 0),
        }
    }

    /// `APPEND`: the status and, if stored, the sequence number.
    fn append(&self, to: Handle, e: Entry<'_>) -> (u8, Option<u64>) {
        let mut msg = [0u8; 256];
        let Some(n) = audit::encode(&Request::Append(e), &mut msg) else {
            return (status::BAD_REQUEST, None);
        };
        let (code, out, len) = self.raw(to, &msg[..n]);
        let seq = (code == status::OK && len == 9).then(|| {
            let mut s = [0u8; 8];
            s.copy_from_slice(&out[1..9]);
            u64::from_le_bytes(s)
        });
        (code, seq)
    }

    fn head(&self) -> Option<Head> {
        let (_, out, len) = self.raw(A, &[VERSION, op::HEAD]);
        Head::parse(&out[..len])
    }

    fn step(&mut self, name: &str, ok: bool) {
        let mut line = [0u8; 128];
        let (word, to): (&[u8], Handle) = if ok {
            (b"ok ", STEPS)
        } else {
            self.failed += 1;
            (b"FAILED ", CONSOLE)
        };
        let n = (word.len() + name.len()).min(line.len());
        line[..word.len()].copy_from_slice(word);
        line[word.len()..n].copy_from_slice(&name.as_bytes()[..n - word.len()]);
        if to == STEPS {
            let _ = send(STEPS, &line[..n], 0, 0, 0);
        } else {
            let _ = debug_write(CONSOLE, &line[..n]);
        }
    }
}

fn first(c: &mut Client) {
    let h = c.head();
    c.step(
        "HEAD: boot 1, its boot record only",
        h.is_some_and(|h| h.boot == 1 && h.records == 1),
    );
    let seqs = [
        c.append(A, entry(b"one")).1,
        c.append(B, entry(b"two")).1,
        c.append(A, entry(b"three")).1,
    ];
    c.step(
        "entries from two clients get consecutive sequence numbers",
        seqs == [Some(1), Some(2), Some(3)],
    );
    let intent = Entry {
        kind: Kind::Intent,
        action: action::INFER,
        outcome: outcome::NONE,
        ..entry(b"")
    };
    let (_, i) = c.append(A, intent);
    let done = i.map(|i| {
        c.append(
            A,
            Entry {
                kind: Kind::Outcome,
                refers: i,
                ..intent
            },
        )
    });
    c.step(
        "an intent, then its outcome referring to it",
        i == Some(4) && done == Some((status::OK, Some(5))),
    );
    // A valid entry, then its actor's first byte made a space.
    let mut msg = [0u8; 256];
    let n = audit::encode(&Request::Append(entry(b"x")), &mut msg).unwrap_or(0);
    let actor_at = 2 + 1 + 8 + 1;
    msg[actor_at] = b' ';
    let bad_name = c.raw(A, &msg[..n]).0;
    let outcome_without = Entry {
        kind: Kind::Outcome,
        ..entry(b"")
    };
    let mut raw = [0u8; 256];
    let k = audit::encode(&Request::Append(outcome_without), &mut raw);
    c.step(
        "malformed entries are refused and not stored",
        bad_name == status::BAD_REQUEST && k.is_none() && c.head().is_some_and(|h| h.records == 6),
    );
    let h = c.head();
    c.step(
        "HEAD: 6 records and a chain head",
        h.is_some_and(|h| h.records == 6 && h.head != [0; 32]),
    );
}

fn second(c: &mut Client) {
    c.step(
        "after the restart: boot 2, a new stream",
        c.head().is_some_and(|h| h.boot == 2 && h.records == 1),
    );
    let mut stored = 0u64;
    let mut last = status::OK;
    for _ in 0..5_000 {
        let e = entry(b"filling the tiny store with records until it is full");
        match c.append(A, e) {
            (status::OK, Some(_)) => stored += 1,
            (code, _) => {
                last = code;
                break;
            }
        }
    }
    c.step(
        "the store fills: APPEND answers UNWRITABLE",
        stored > 10 && last == UNWRITABLE,
    );
    c.step(
        "and keeps answering it",
        c.append(B, entry(b"after")).0 == UNWRITABLE,
    );
    c.step(
        "HEAD still answers, counting only stored records",
        c.head()
            .is_some_and(|h| h.boot == 2 && h.records == stored + 1),
    );
    let mut d = [0u8; 20];
    let mut at = d.len();
    let mut v = stored;
    loop {
        at -= 1;
        d[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut line = [0u8; 40];
    let prefix = b"auditclient: stored ";
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..prefix.len() + d.len() - at].copy_from_slice(&d[at..]);
    let _ = debug_write(CONSOLE, &line[..prefix.len() + d.len() - at]);
}

fn main(arg: u64) -> u64 {
    let Ok(reply) = endpoint_create() else {
        return 100;
    };
    let mut c = Client { reply, failed: 0 };
    if arg == 0 {
        first(&mut c);
    } else {
        second(&mut c);
    }
    let _ = send(STEPS, b"done", 0, 0, 0);
    c.failed
}
