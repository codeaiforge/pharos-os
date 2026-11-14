//! The `knowledge` test kernel's client (#143). Handles: 1 the console,
//! 2, 3, and 4 `SEND` on the knowledge service badged as the runtime, as
//! `trust`, and as an unknown client (3), 5 the kernel's step endpoint
//! (`SEND`). Each passed step is sent as `ok <step>`, a failed one printed;
//! then `done`. Exits with the number of failures.
//!
//! Argument 0, the service's first start: versions put, corrected, in
//! conflict, and retracted; evidence in a scope the reader cannot read;
//! a query and a history; a version verified; refusals by badge. Argument
//! 1, after the kernel killed and restarted the service: every version,
//! status, and mark is still there, and the next version is numbered on.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use pharos_proto::knowledge::{
    self, Author, Kind, List, MIN_BUFFER, Put, Request, Source, Summary, code, flag, parse_version,
};
use pharos_proto::{Info, Reader, status};
use pharos_store::sha256;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map,
    mem_share, send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const RUNTIME: Handle = 2;
const TRUST: Handle = 3;
const OTHER: Handle = 4;
const STEPS: Handle = 5;

const NOTES: u8 = 0;
const HR: u8 = 2;
const ALL: u8 = 0xff;

struct Client {
    reply: Handle,
    buffer: Mapped,
    failed: u64,
}

fn author() -> Author<'static> {
    Author::Agent {
        name: b"writer",
        task: 9,
    }
}

fn put<'a>(scope: u8, key: &'a [u8], kind: Kind, replaces: u32, content: &'a [u8]) -> Put<'a> {
    Put {
        scope,
        key,
        kind,
        replaces,
        author: author(),
        source: Source::Written,
        readable: ALL,
        tags: List::new(&[&b"plan"[..]]).unwrap_or_default(),
        evidence: List::default(),
        content,
    }
}

impl Client {
    fn raw(&self, to: Handle, msg: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 256];
        match call_timeout(to, msg, self.reply, &mut out, 20_000_000) {
            Ok(Received::Message { len, .. }) if len >= 1 => out[..len.min(256)].to_vec(),
            _ => alloc::vec![status::INTERNAL],
        }
    }

    fn call(&self, to: Handle, req: &Request<'_>) -> Vec<u8> {
        let mut msg = [0u8; 256];
        match knowledge::encode(req, &mut msg) {
            Some(n) => self.raw(to, &msg[..n]),
            None => alloc::vec![status::BAD_REQUEST],
        }
    }

    fn attach(&self, to: Handle) -> bool {
        let len = self.buffer.len() as u64;
        mem_share(&self.buffer).is_ok_and(|memory| {
            let mut msg = [0u8; 16];
            let sent = knowledge::encode(&Request::Attach { len }, &mut msg)
                .is_some_and(|n| send(to, &msg[..n], memory, READ | WRITE, 0).is_ok());
            let _ = delete(memory);
            sent
        })
    }

    /// `PUT` on `to`: the new version, or the status.
    fn put(&self, to: Handle, p: &Put<'_>) -> Result<u32, u8> {
        let mut body = alloc::vec![0u8; knowledge::MAX_RECORD];
        let n = p.encode(&mut body).ok_or(status::BAD_REQUEST)?;
        self.buffer.write_bytes(0, &body[..n]);
        let r = self.call(to, &Request::Put { len: n as u16 });
        match r[..] {
            [status::OK, a, b, c, d] => Ok(u32::from_le_bytes([a, b, c, d])),
            [code, ..] => Err(code),
            [] => Err(status::INTERNAL),
        }
    }

    /// `GET`: each (status, version, content), or the status.
    fn get(
        &self,
        scope: u8,
        key: &[u8],
        version: u32,
        readable: u8,
    ) -> Result<Vec<(u8, u32, Vec<u8>)>, u8> {
        let req = Request::Get {
            scope,
            key,
            version,
            readable,
        };
        let r = self.call(RUNTIME, &req);
        let [status::OK, count, a, b, c, d] = r[..] else {
            return Err(r.first().copied().unwrap_or(status::INTERNAL));
        };
        let len = u32::from_le_bytes([a, b, c, d]) as usize;
        let mut bytes = alloc::vec![0u8; len];
        self.buffer.read_bytes(0, &mut bytes);
        let mut out = Vec::new();
        let mut rest = &bytes[..];
        for _ in 0..count {
            let [st, l0, l1, tail @ ..] = rest else {
                return Err(status::INTERNAL);
            };
            let n = usize::from(u16::from_le_bytes([*l0, *l1]));
            let v = tail
                .get(..n)
                .and_then(parse_version)
                .ok_or(status::INTERNAL)?;
            out.push((*st, v.version, v.content.to_vec()));
            rest = &tail[n..];
        }
        Ok(out)
    }

    fn statuses(&self, scope: u8, key: &[u8], version: u32) -> Vec<(u32, u8)> {
        self.get(scope, key, version, ALL)
            .map(|v| v.into_iter().map(|(s, n, _)| (n, s)).collect())
            .unwrap_or_default()
    }

    fn history(&self, key: &[u8]) -> Vec<(u32, u32, u8)> {
        let req = Request::History {
            scope: NOTES,
            key,
            from: 1,
            readable: ALL,
        };
        let r = self.call(RUNTIME, &req);
        let [status::OK, count, _] = r[..] else {
            return Vec::new();
        };
        let mut bytes = alloc::vec![0u8; 16 * 64];
        self.buffer.read_bytes(0, &mut bytes);
        let mut rd = Reader::new(&bytes);
        (0..count)
            .filter_map(|_| Summary::read(&mut rd))
            .map(|s| (s.version, s.replaces, s.status))
            .collect()
    }

    fn verify(&self, to: Handle, key: &[u8], version: u32, content: &[u8], right: bool) -> Vec<u8> {
        let h = sha256(&[content]);
        let mut prefix = [h[0], h[1], h[2], h[3]];
        if !right {
            prefix[0] ^= 1;
        }
        let req = Request::Verify {
            scope: NOTES,
            key,
            version,
            prefix,
        };
        self.call(to, &req)
    }

    fn step(&mut self, name: &str, ok: bool) {
        let (word, to): (&[u8], Handle) = if ok {
            (b"ok ", STEPS)
        } else {
            self.failed += 1;
            (b"FAILED ", CONSOLE)
        };
        let line = [word, name.as_bytes()].concat();
        if to == STEPS {
            let _ = send(STEPS, &line, 0, 0, 0);
        } else {
            let _ = debug_write(CONSOLE, &line);
        }
    }
}

const RELEASE: &[u8] = b"release";
const MONDAY: &[u8] = b"ship monday";

fn first(c: &mut Client) {
    let info = c.raw(RUNTIME, &[knowledge::VERSION, pharos_proto::op::INFO]);
    let named = Info::parse(&info).is_some_and(|i| i.name == knowledge::NAME);
    let before = c.call(
        RUNTIME,
        &Request::Get {
            scope: NOTES,
            key: RELEASE,
            version: 0,
            readable: ALL,
        },
    );
    c.step(
        "INFO answers; a request before ATTACH is NO_BUFFER",
        named && before == [status::NO_BUFFER],
    );
    let attached = c.attach(RUNTIME) && c.attach(OTHER);
    let numbers = [
        c.put(
            RUNTIME,
            &put(NOTES, RELEASE, Kind::Claim, 0, b"ship friday"),
        ),
        c.put(RUNTIME, &put(NOTES, RELEASE, Kind::Claim, 1, MONDAY)),
        // A second writer corrects version 1 too: a conflict.
        c.put(
            RUNTIME,
            &put(NOTES, RELEASE, Kind::Claim, 1, b"ship sunday"),
        ),
    ];
    c.step(
        "versions put and corrected, numbered by the service",
        attached && numbers == [Ok(1), Ok(2), Ok(3)],
    );
    let conflict =
        c.statuses(NOTES, RELEASE, 0) == [(2, flag::CONFLICTING), (3, flag::CONFLICTING)];
    let retracted = c.put(RUNTIME, &put(NOTES, RELEASE, Kind::Retraction, 3, b""));
    let s = flag::SUPERSEDED | flag::STALE;
    c.step(
        "a conflict, then a retraction; every version kept with its status",
        conflict
            && retracted == Ok(4)
            && c.statuses(NOTES, RELEASE, 0) == [(2, 0), (4, 0)]
            && c.statuses(NOTES, RELEASE, 1) == [(1, s)]
            && c.statuses(NOTES, RELEASE, 3) == [(3, s | flag::RETRACTED)],
    );
    let refused = [
        c.put(RUNTIME, &put(NOTES, RELEASE, Kind::Claim, 0, b"again")),
        c.put(RUNTIME, &put(NOTES, RELEASE, Kind::Claim, 9, b"x")),
        c.put(
            RUNTIME,
            &Put {
                author: Author::User,
                ..put(NOTES, b"forged", Kind::Claim, 0, b"x")
            },
        ),
        c.put(TRUST, &put(NOTES, b"other", Kind::Claim, 0, b"x")),
        c.put(OTHER, &put(NOTES, b"other", Kind::Claim, 0, b"x")),
    ];
    c.step(
        "a wrong replaces, the user as author, and other badges are refused",
        refused
            == [
                Err(code::REPLACES),
                Err(code::REPLACES),
                Err(status::NO_ACCESS),
                Err(status::NO_ACCESS),
                Err(status::NO_ACCESS),
            ],
    );
    let salary = c.put(RUNTIME, &put(HR, b"salary", Kind::Claim, 0, b"secret"));
    let budget = c.put(
        RUNTIME,
        &Put {
            evidence: List::new(&[(HR, &b"salary"[..], 1)]).unwrap_or_default(),
            ..put(NOTES, b"budget", Kind::Claim, 0, b"derived")
        },
    );
    let notes_only = 1 << NOTES;
    let hidden = c.get(NOTES, b"budget", 0, notes_only) == Err(status::NOT_FOUND)
        && c.get(HR, b"salary", 1, notes_only) == Err(status::NOT_FOUND)
        && c.get(NOTES, b"nothing", 0, notes_only) == Err(status::NOT_FOUND);
    let seen = c.get(NOTES, b"budget", 0, ALL).is_ok_and(|v| v.len() == 1);
    c.step(
        "what cites an unreadable scope is as missing as nothing",
        salary == Ok(1) && budget == Ok(1) && hidden && seen,
    );
    let query = c.call(
        RUNTIME,
        &Request::Query {
            scope: NOTES,
            tag: b"plan",
            start: 0,
            readable: notes_only,
        },
    );
    let mut keys = [0u8; 8];
    c.buffer.read_bytes(0, &mut keys);
    let history = c.history(RELEASE);
    c.step(
        "a query leaves out budget; the history has every version",
        query == [status::OK, 1, 0]
            && &keys == b"\x07release"
            && history == [(1, 0, s), (2, 1, 0), (3, 1, s | flag::RETRACTED), (4, 3, 0)],
    );
    let marks = [
        c.verify(RUNTIME, RELEASE, 2, MONDAY, true),
        c.verify(TRUST, RELEASE, 2, MONDAY, false),
        c.verify(TRUST, RELEASE, 9, MONDAY, true),
    ];
    let mut by = [0u8; 32];
    let n = knowledge::encode_author(author(), &mut by).unwrap_or(0);
    let ok = [&[status::OK][..], &by[..n]].concat();
    let marked = c.verify(TRUST, RELEASE, 2, MONDAY, true);
    c.step(
        "only trust verifies, with the right hash prefix",
        marks
            == [
                alloc::vec![status::NO_ACCESS],
                alloc::vec![code::HASH_DIFFERS],
                alloc::vec![status::NOT_FOUND],
            ]
            && marked == ok
            && c.statuses(NOTES, RELEASE, 2) == [(2, flag::VERIFIED)],
    );
}

fn second(c: &mut Client) {
    // The restarted service has no buffer from us.
    let lost = c.get(NOTES, RELEASE, 0, ALL) == Err(status::NO_BUFFER);
    let attached = c.attach(RUNTIME);
    let s = flag::SUPERSEDED | flag::STALE;
    c.step(
        "after the restart: every version and status is still there",
        lost && attached
            && c.statuses(NOTES, RELEASE, 0) == [(2, flag::VERIFIED), (4, 0)]
            && c.statuses(NOTES, RELEASE, 3) == [(3, s | flag::RETRACTED)]
            && c.get(NOTES, RELEASE, 2, ALL)
                .is_ok_and(|v| v[0].2 == MONDAY)
            && c.get(NOTES, b"budget", 0, 1 << NOTES) == Err(status::NOT_FOUND)
            && c.history(RELEASE).len() == 4,
    );
    let next = c.put(
        RUNTIME,
        &put(NOTES, RELEASE, Kind::Claim, 2, b"ship tuesday"),
    );
    c.step(
        "the next version is numbered on, and the old head is stale",
        next == Ok(5)
            && c.statuses(NOTES, RELEASE, 2) == [(2, s | flag::VERIFIED)]
            && c.statuses(NOTES, RELEASE, 0) == [(4, 0), (5, 0)],
    );
}

fn main(arg: u64) -> u64 {
    let (Ok(reply), Ok(buffer)) = (endpoint_create(), mem_map(MIN_BUFFER)) else {
        return 100;
    };
    let mut c = Client {
        reply,
        buffer,
        failed: 0,
    };
    match arg {
        0 => first(&mut c),
        _ => second(&mut c),
    }
    let _ = send(STEPS, b"done", 0, 0, 0);
    c.failed
}
