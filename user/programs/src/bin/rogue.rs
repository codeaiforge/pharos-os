//! A stand-in for a failed or compromised AI service (M4.6, D-031,
//! services.md "AI services"). `init` starts it from a test table in
//! place of `infer` or the agent runtime, with exactly that service's
//! manifest, so it holds only what the shipped service holds. Handle 3 is
//! `init`'s report endpoint in both manifests.
//!
//! - Argument 1 (as `infer`, #183) and 2 (as the agent runtime): reports
//!   `ready`, then tries everything its manifest does not grant: every
//!   handle for what it does not hold, kernel addresses in system calls,
//!   memory past its limit, and forged requests to `init`, the store, and
//!   (as the runtime) `trust`. It prints each attempt that succeeds
//!   (`rogue: ALLOWED <what>`) and then `rogue: as <service>: <n> refused,
//!   <m> allowed`, and waits.
//! - Argument 3 (as `infer`, #182): reports `ready` and never receives on
//!   the inference endpoint, a hung service. It creates one endpoint of
//!   its own (handle 5, after the manifest's 4) and waits there; when the
//!   test kernel sends it `exhaust`, it maps memory until refused (1 MiB
//!   pieces down to single pages), says how much it holds, and keeps
//!   asking every millisecond, so it takes any frame another process
//!   frees: a runaway service.

#![no_std]
#![no_main]

use pharos_proto::{service, status, store, trust};
use pharos_user::probe::{KERNEL_HALF, debug_write_from, read_into};
use pharos_user::rights::{READ, SEND};
use pharos_user::{
    Handle, Received, call_timeout, config_read, debug_write, dma_alloc, endpoint_create,
    irq_create, mem_map, mem_share, mem_unmap, mmio_map, open, process_stop, receive,
    receive_timeout, send, sleep, spawn, try_send, try_send_cap,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const REPORT: Handle = 3;
/// The store: `models` read-only as `infer` (handle 4), `agents` as the
/// runtime (handle 7).
const INFER_STORE: Handle = 4;
const ROOT: Handle = 4;
const TRUST: Handle = 6;
const RUNTIME_STORE: Handle = 7;
/// Pages each manifest allows (`pharos_services::{INFER_LIMIT, AGENTS_LIMIT}`).
const INFER_PAGES: u64 = 1 << 18;
const RUNTIME_PAGES: u64 = 1 << 14;
/// A forged call gets this long for an answer.
const FORGED_US: u64 = 200_000;

/// `n` in decimal.
fn decimal(mut n: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &out[i..];
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

/// Waits forever.
fn idle(endpoint: Handle) -> ! {
    let mut buf = [0u8; 8];
    loop {
        let _ = receive(endpoint, &mut buf);
    }
}

/// Counts attempts, printing any that succeeded.
struct Probes {
    refused: u64,
    allowed: u64,
    reply: Handle,
}

impl Probes {
    fn expect_refused(&mut self, what: &[u8], refused: bool) {
        if refused {
            self.refused += 1;
        } else {
            self.allowed += 1;
            say(&[b"rogue: ALLOWED ", what]);
        }
    }

    /// A call that must not be answered `OK` (no answer, or a refusal).
    fn forged(&mut self, what: &[u8], endpoint: Handle, msg: &[u8]) {
        let mut out = [0u8; 256];
        let ok = matches!(
            call_timeout(endpoint, msg, self.reply, &mut out, FORGED_US),
            Ok(Received::Message { len, .. }) if len >= 1 && out[0] == status::OK
        );
        self.expect_refused(what, !ok);
    }

    /// `init`'s management and listing operations, which answer only
    /// `trust`'s badge (D-029).
    fn forge_init(&mut self) {
        use service::op;
        for (what, o, name) in [
            (&b"init START net"[..], op::START, &b"net"[..]),
            (b"init STOP audit", op::STOP, b"audit"),
            (b"init RESTART store", op::RESTART, b"store"),
            (b"init SERVICES", op::SERVICES, b""),
            (b"init CONFIG", op::CONFIG, b""),
            (b"init RUNTIME", op::RUNTIME, b""),
            (b"init ROLLBACK", op::ROLLBACK, b""),
            (b"init NEXT", op::NEXT, b""),
        ] {
            let mut msg = [0u8; 16];
            msg[..3].copy_from_slice(&[service::VERSION, o, name.len() as u8]);
            msg[3..3 + name.len()].copy_from_slice(name);
            self.forged(what, REPORT, &msg[..3 + name.len()]);
        }
    }

    /// The store, on `handle`: dropping another client's buffer, and a
    /// path out of its namespace.
    fn forge_store(&mut self, handle: Handle) {
        let mut msg = [0u8; 64];
        for (what, req) in [
            (&b"store RELEASE"[..], store::Request::Release { client: 1 }),
            (
                b"store STAT ../audit",
                store::Request::Stat {
                    path: b"../audit/log",
                },
            ),
        ] {
            if let Some(n) = store::encode(&req, &mut msg) {
                self.forged(what, handle, &msg[..n]);
            }
        }
    }

    /// Every handle from `first` to 64 is empty.
    fn empty_handles(&mut self, first: Handle) {
        for h in first..=64 {
            if h == self.reply {
                continue;
            }
            let any = try_send(h, b"x").is_ok()
                || open(h, b"bin/init").is_ok()
                || config_read(h, 0, 4).is_ok()
                || process_stop(h).is_ok()
                || irq_create(h, 0).is_ok()
                || receive_timeout(h, &mut [0; 8], 0).is_ok();
            self.expect_refused(b"an empty handle", !any);
        }
    }

    /// Handles `1..=last` hold no device and no process, and none may be
    /// passed on (no `GRANT`) except `own` if given.
    fn no_devices(&mut self, last: Handle, own: Option<Handle>) {
        for h in 1..=last {
            let any = config_read(h, 0, 4).is_ok()
                || mmio_map(h, 0, 0, 4096, 0x5000_0000).is_ok()
                || dma_alloc(h, 1, 0x5100_0000).is_ok()
                || irq_create(h, 0).is_ok()
                || process_stop(h).is_ok();
            self.expect_refused(b"a device or process operation", !any);
            if Some(h) != own {
                // Passed to `init`, which keeps nothing from a service. A
                // blocking send: only a refusal fails at once.
                let passed = send(REPORT, b"x", h, READ | SEND, 0).is_ok();
                self.expect_refused(b"passing on a capability", !passed);
            }
        }
    }

    /// System calls given kernel addresses, and memory past `pages`.
    fn memory(&mut self, pages: u64, file: Option<Handle>) {
        let k = KERNEL_HALF + 0x10_0000;
        self.expect_refused(
            b"debug_write from the kernel",
            debug_write_from(CONSOLE, k, 16).is_err(),
        );
        if let Some(f) = file {
            self.expect_refused(b"read into the kernel", read_into(f, k, 16).is_err());
        }
        self.expect_refused(b"mem_share of the kernel", mem_share(k, 4096).is_err());
        self.expect_refused(b"mem_unmap of the kernel", mem_unmap(k, 4096).is_err());
        self.expect_refused(
            b"memory past its limit",
            mem_map((pages + 1) * 4096).is_err(),
        );
    }
}

fn hostile(arg: u64) -> u64 {
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let Ok(reply) = endpoint_create() else {
        return 2;
    };
    let mut p = Probes {
        refused: 0,
        allowed: 0,
        reply,
    };
    let name: &[u8] = if arg == 1 {
        // As `infer`: 1 console, 2 its endpoint, 3 report, 4 `models`.
        p.empty_handles(5);
        p.no_devices(4, None);
        // Its own endpoint holds only `RECEIVE`; `models` is read-only.
        // Blocking: allowed, it would wait forever, and the kernel's wait
        // for the tally fails.
        p.expect_refused(b"send on its own endpoint", send(2, b"x", 0, 0, 0).is_err());
        let mut msg = [0u8; 64];
        if let Some(n) = store::encode(
            &store::Request::Append {
                path: b"x",
                record: b"x",
            },
            &mut msg,
        ) {
            p.forged(b"store APPEND to models", INFER_STORE, &msg[..n]);
        }
        p.forge_store(INFER_STORE);
        p.memory(INFER_PAGES, None);
        b"infer"
    } else {
        // As the runtime: 1 console, 2 its endpoint (may be passed on),
        // 3 report, 4 root, 5 infer, 6 trust, 7 `agents`, 8 audit.
        p.empty_handles(9);
        p.no_devices(8, Some(2));
        let file = open(ROOT, b"bin/init").ok();
        p.memory(RUNTIME_PAGES, file);
        p.forge_store(RUNTIME_STORE);
        // `trust`: a registration with a capability that is not a process,
        // and a resolution of an approval never asked. Neither is answered;
        // the runner checks `trust` showed neither.
        let mut msg = [0u8; 64];
        if let Some(n) = trust::encode(
            &trust::Request::Register {
                slot: 0,
                name: b"rogue",
                group: b"",
            },
            &mut msg,
        ) {
            let _ = try_send_cap(TRUST, &msg[..n], reply, SEND, 0);
        }
        if let Some(n) = trust::encode(
            &trust::Request::Resolved {
                number: 77,
                resolution: trust::Resolution::Granted,
            },
            &mut msg,
        ) {
            let _ = try_send(TRUST, &msg[..n]);
        }
        let spawned = spawn(ROOT, 0, &[], None).is_ok();
        p.expect_refused(b"spawn from the filesystem itself", !spawned);
        b"agents"
    };
    p.forge_init();
    let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
    say(&[
        b"rogue: as ",
        name,
        b": ",
        decimal(p.refused, &mut a),
        b" refused, ",
        decimal(p.allowed, &mut b),
        b" allowed",
    ]);
    idle(reply)
}

/// Maps as much as it may, in pieces from 1 MiB down to one page, so
/// few of its 1024 mappings are used; returns the bytes mapped.
fn grab() -> u64 {
    let mut bytes = 0;
    for size in [1 << 20, 1 << 18, 1 << 16, 1 << 14, 1 << 12] {
        while mem_map(size).is_ok() {
            bytes += size;
        }
    }
    bytes
}

/// Takes all it may, says how much, then keeps taking every freed frame.
fn exhaust() -> ! {
    let mut d = [0u8; 20];
    say(&[b"rogue: holding ", decimal(grab() >> 20, &mut d), b" MiB"]);
    loop {
        grab();
        sleep(1_000);
    }
}

fn runaway() -> u64 {
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let Ok(own) = endpoint_create() else {
        return 2;
    };
    say(&[b"rogue: ready, never receiving"]);
    let mut buf = [0u8; 16];
    loop {
        if let Ok(Received::Message { len, .. }) = receive(own, &mut buf) {
            if buf[..len.min(16)] == *b"exhaust" {
                exhaust();
            }
        }
    }
}

fn main(arg: u64) -> u64 {
    match arg {
        1 | 2 => hostile(arg),
        3 => runaway(),
        _ => 9,
    }
}
