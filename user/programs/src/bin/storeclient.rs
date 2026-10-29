//! A storage-service client for the `store` test kernel (#77). Handles: 1
//! the console, 2 `SEND` on the service (badged by the kernel with a
//! namespace), and for argument 4 also 3 (another badge). Each step prints
//! `ok <step>` or `FAIL <step>`; the exit code is the number of failures.
//!
//! - 1: namespace 1, read-write: files through a shared buffer, streams,
//!   listing, deletion, bad paths and ranges, and `NO_SPACE`.
//! - 2: namespace 1, read-only: reads what 1 left, every write refused.
//! - 3: namespace 2: sees nothing of namespace 1.
//! - 4: badge 0 (handle 2) and an unknown namespace (handle 3): refused.

#![no_std]
#![no_main]

use pharos_programs::store_proto::{Request, Status, encode};
use pharos_store::sha256;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_reply, debug_write, endpoint_create, mem_map_buffer, mem_share,
    send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
/// Bigger than the 16 MiB test store.
const HUGE: u64 = 17 << 20;

fn report(failures: &mut u64, step: &str, ok: bool) {
    let mut line = [0u8; 96];
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let n = (prefix.len() + step.len()).min(line.len());
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..n].copy_from_slice(&step.as_bytes()[..n - prefix.len()]);
    let _ = debug_write(CONSOLE, &line[..n]);
    if !ok {
        *failures += 1;
    }
}

/// A client: the service handle and a reply endpoint.
struct Client {
    service: Handle,
    reply: Handle,
}

impl Client {
    fn new(service: Handle) -> Self {
        Self {
            service,
            reply: endpoint_create().unwrap_or(0),
        }
    }

    /// Sends `req` by `call`; returns the status and the whole reply.
    fn call(&self, req: Request<'_>) -> (Status, [u8; 256]) {
        let mut msg = [0u8; 256];
        let Some(n) = encode(&req, &mut msg) else {
            return (Status::BadRequest, msg);
        };
        let mut buf = [0u8; 256];
        match call_reply(self.service, &msg[..n], self.reply, &mut buf) {
            Ok(Received::Message { len, .. }) if len >= 1 => (Status::from_code(buf[0]), buf),
            _ => (Status::IoError, buf),
        }
    }

    fn status(&self, req: Request<'_>) -> Status {
        self.call(req).0
    }

    /// Maps a buffer of `len` bytes and attaches it; returns it if the
    /// service reports that size.
    fn attach(&self, len: u64) -> Option<Mapped> {
        let buf = mem_map_buffer(len).ok()?;
        let memory = mem_share(buf.addr(), len).ok()?;
        let mut msg = [0u8; 16];
        let n = encode(&Request::Attach { len }, &mut msg)?;
        send(self.service, &msg[..n], memory, READ | WRITE, 0).ok()?;
        let (s, reply) = self.call(Request::Buffer);
        let size = u64::from_le_bytes(reply[1..9].try_into().ok()?);
        (s == Status::Ok && size == len).then_some(buf)
    }
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

fn byte(i: usize) -> u8 {
    (i * 13 + 5) as u8
}

fn writer(f: &mut u64) {
    let c = Client::new(SERVICE);
    let Some(buf) = c.attach(65536) else {
        report(f, "attach a 64 KiB buffer", false);
        return;
    };
    report(f, "attach a 64 KiB buffer", true);
    for i in 0..10_000 {
        buf.write8(i, byte(i));
    }
    report(
        f,
        "write a file from the buffer",
        c.status(Request::Write {
            path: b"dir/a.txt",
            len: 10_000,
            at: 0,
        }) == Status::Ok,
    );
    let (s, r) = c.call(Request::Stat { path: b"dir/a.txt" });
    report(
        f,
        "stat it",
        s == Status::Ok && r[1] == 1 && u64_at(&r, 2) == 10_000,
    );
    let (s, r) = c.call(Request::Read {
        path: b"dir/a.txt",
        offset: 0,
        len: 10_000,
        at: 32_768,
    });
    let same = (0..10_000).all(|i| buf.read8(32_768 + i) == byte(i));
    report(
        f,
        "read it back into the buffer",
        s == Status::Ok && u64_at(&r, 1) == 10_000 && same,
    );
    let (s, r) = c.call(Request::Read {
        path: b"dir/a.txt",
        offset: 9_990,
        len: 100,
        at: 0,
    });
    report(
        f,
        "a read past the end stops there",
        s == Status::Ok && u64_at(&r, 1) == 10,
    );
    buf.write_bytes(0, b"hello");
    let replaced = c.status(Request::Write {
        path: b"dir/a.txt",
        len: 5,
        at: 0,
    }) == Status::Ok;
    let (_, r) = c.call(Request::Stat { path: b"dir/a.txt" });
    report(f, "replace it", replaced && u64_at(&r, 2) == 5);
    let (s1, r1) = c.call(Request::Append {
        path: b"log",
        record: b"one",
    });
    let (s2, r2) = c.call(Request::Append {
        path: b"log",
        record: b"two",
    });
    let h1 = sha256(&[&[0; 32], b"one"]);
    let h2 = sha256(&[&h1, b"two"]);
    report(
        f,
        "append records; numbers and chain head match",
        s1 == Status::Ok
            && s2 == Status::Ok
            && u64_at(&r1, 1) == 0
            && u64_at(&r2, 1) == 1
            && r2[9..41] == h2,
    );
    buf.write_bytes(0, b"kept");
    let kept = c.status(Request::Write {
        path: b"keep.txt",
        len: 4,
        at: 0,
    }) == Status::Ok;
    let (s, r) = c.call(Request::List {
        prefix: b"",
        start: 0,
    });
    let names: &[&[u8]] = &[b"dir/a.txt", b"keep.txt", b"log"];
    let mut at = 3;
    let mut listed = s == Status::Ok && r[1] == 3;
    for name in names {
        listed &= usize::from(r[at]) == name.len() && &r[at + 1..at + 1 + name.len()] == *name;
        at += 1 + name.len();
    }
    report(f, "list the namespace", kept && listed);
    report(
        f,
        "delete; then NOT_FOUND",
        c.status(Request::Delete { path: b"dir/a.txt" }) == Status::Ok
            && c.status(Request::Stat { path: b"dir/a.txt" }) == Status::NotFound,
    );
    report(
        f,
        "a path escaping the namespace: BAD_REQUEST",
        c.status(Request::Stat { path: b"../x" }) == Status::BadRequest,
    );
    report(
        f,
        "a range outside the buffer: NO_BUFFER",
        c.status(Request::Read {
            path: b"keep.txt",
            offset: 0,
            len: 10_000,
            at: 60_000,
        }) == Status::NoBuffer,
    );
    report(
        f,
        "a file as a stream: BAD_REQUEST",
        c.status(Request::Append {
            path: b"keep.txt",
            record: b"x",
        }) == Status::BadRequest,
    );
    // A bigger buffer replaces the first; the write cannot fit.
    let big = c.attach(HUGE);
    report(f, "attach a 17 MiB buffer", big.is_some());
    report(
        f,
        "a write larger than the store: NO_SPACE, nothing written",
        c.status(Request::Write {
            path: b"big",
            len: HUGE,
            at: 0,
        }) == Status::NoSpace
            && c.status(Request::Stat { path: b"big" }) == Status::NotFound,
    );
}

fn reader(f: &mut u64) {
    let c = Client::new(SERVICE);
    let buf = c.attach(4096);
    let (s, r) = c.call(Request::Read {
        path: b"keep.txt",
        offset: 0,
        len: 4,
        at: 0,
    });
    let kept = buf.is_some_and(|b| (0..4).all(|i| b.read8(i) == b"kept"[i]));
    report(
        f,
        "read-only: reads what the writer left",
        s == Status::Ok && u64_at(&r, 1) == 4 && kept,
    );
    report(
        f,
        "read-only: write, append, and delete refused",
        c.status(Request::Write {
            path: b"keep.txt",
            len: 1,
            at: 0,
        }) == Status::ReadOnly
            && c.status(Request::Append {
                path: b"log",
                record: b"x",
            }) == Status::ReadOnly
            && c.status(Request::Delete { path: b"keep.txt" }) == Status::ReadOnly,
    );
}

fn other(f: &mut u64) {
    let c = Client::new(SERVICE);
    let (s, r) = c.call(Request::List {
        prefix: b"",
        start: 0,
    });
    report(
        f,
        "another namespace sees nothing of the first",
        c.status(Request::Stat { path: b"keep.txt" }) == Status::NotFound
            && s == Status::Ok
            && r[1] == 0,
    );
}

fn strangers(f: &mut u64) {
    let unbadged = Client::new(SERVICE);
    let unknown = Client::new(3);
    report(
        f,
        "badge 0 and an unknown namespace: NO_ACCESS",
        unbadged.status(Request::Stat { path: b"keep.txt" }) == Status::NoAccess
            && unknown.status(Request::Stat { path: b"keep.txt" }) == Status::NoAccess,
    );
}

fn main(arg: u64) -> u64 {
    let mut f = 0;
    match arg {
        1 => writer(&mut f),
        2 => reader(&mut f),
        3 => other(&mut f),
        4 => strangers(&mut f),
        _ => f = 0xbad,
    }
    f
}
