//! Test kernel: waits with timeouts (issue #76, user-environment.md). The
//! `timeprobe` program runs one case per process; the kernel times each
//! against a process that exits at once. `receive` and `call` return
//! `TIMED_OUT` no earlier than the timeout and within it plus two ticks; a
//! timed-out `call` leaves nothing queued; `sleep` sleeps at least as long
//! as asked; in a race of replies against the deadline, every reply the
//! server delivered reached the client and every late one got `REVOKED`.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, Object, RECEIVE, SEND};
use pharos_kernel::fs::Fs;
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `timeprobe`'s race rounds and its code for an unexpected result.
const ROUNDS: u64 = 8;
const BAD: u64 = 0xbad;
/// Timer period.
const TICK: Duration = Duration::from_millis(10);

fn endpoint_cap(endpoint: &Arc<Endpoint>, rights: u32) -> Arc<Capability> {
    Capability::new(Object::Endpoint(endpoint.clone()), rights)
}

/// Waits up to 20 s for `id` to exit; returns its code and when it exited.
fn wait_exit(id: TaskId) -> Option<(u64, Duration)> {
    for _ in 0..400 {
        if let Some(e) = process::exits().into_iter().find(|e| e.task == id) {
            return Some((e.code, e.at));
        }
        sched::sleep(Duration::from_millis(50));
    }
    None
}

/// Runs case `arg` with `caps`; returns its exit code and run time.
fn timed(programs: &Fs, arg: u64, caps: Vec<Arc<Capability>>) -> Option<(u64, Duration)> {
    let start = time::uptime();
    let id = process::spawn_elf(programs, b"bin/timeprobe", arg, caps).ok()?;
    wait_exit(id).map(|(code, at)| (code, at.saturating_sub(start)))
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    let Some(hhdm) = requests::HHDM.response() else {
        return;
    };
    if memory {
        storage::record_modules(requests::MODULES.response(), hhdm.offset);
    }
    let ready = memory
        && mm::init_heap().is_ok()
        && apic::init(hhdm.offset).is_ok()
        && time::init().is_ok()
        && sched::init().is_ok();
    t.check("memory, heap, APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    process::init();
    t.check("preemption enabled", sched::enable_preemption().is_ok());
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };

    // Start-up and exit cost of a process, the slowest of three.
    let base = (0..3)
        .filter_map(|_| timed(&programs, 0, vec![]))
        .map(|(_, d)| d)
        .max()
        .unwrap_or(Duration::MAX);
    kprintln!("  baseline: {} ms", base.as_millis());
    // A wait of `want` ends at least `want` and at most two ticks later.
    let within = |run: Duration, want: Duration| {
        kprintln!(
            "  {} ms for a {} ms wait",
            run.as_millis(),
            want.as_millis()
        );
        run >= want && run <= want + base + 2 * TICK
    };

    let silent = Endpoint::new();
    let got = timed(&programs, 1, vec![endpoint_cap(&silent, RECEIVE)]);
    t.check(
        "receive: timeout 0 and 200 ms both return TIMED_OUT",
        got.is_some_and(|(code, _)| code == 0),
    );
    t.check(
        "receive: 200 ms timeout ends within its deadline plus two ticks",
        got.is_some_and(|(_, d)| within(d, Duration::from_millis(200))),
    );
    t.check(
        "receive: the timed-out receiver left the queue",
        silent.waiting() == (0, 0),
    );

    let server = Endpoint::new();
    let reply = Endpoint::new();
    let caps = vec![
        endpoint_cap(&server, SEND),
        endpoint_cap(&reply, SEND | RECEIVE),
    ];
    let got = timed(&programs, 2, caps);
    t.check(
        "call to a silent server returns TIMED_OUT",
        got.is_some_and(|(code, _)| code == 0),
    );
    t.check(
        "call: 100 ms timeout ends within its deadline plus two ticks",
        got.is_some_and(|(_, d)| within(d, Duration::from_millis(100))),
    );
    t.check(
        "call: the request was withdrawn and the reply endpoint is idle",
        server.waiting() == (0, 0) && reply.waiting() == (0, 0) && reply.is_idle(),
    );

    let got = timed(&programs, 3, vec![]);
    t.check(
        "sleep for 100 ms lasts within its deadline plus two ticks",
        got.is_some_and(|(code, d)| code == 0 && within(d, Duration::from_millis(100))),
    );

    // The race: replies after 10·k ms against a 40 ms timeout.
    let server = Endpoint::new();
    let reply = Endpoint::new();
    let client_caps = vec![
        endpoint_cap(&server, SEND),
        endpoint_cap(&reply, SEND | RECEIVE),
    ];
    let s = process::spawn_elf(
        &programs,
        b"bin/timeprobe",
        5,
        vec![endpoint_cap(&server, RECEIVE)],
    );
    let c = process::spawn_elf(&programs, b"bin/timeprobe", 4, client_caps);
    let (s, c) = (s.ok().and_then(wait_exit), c.ok().and_then(wait_exit));
    let (client, server_bits) = (c.map_or(BAD, |e| e.0), s.map_or(BAD, |e| e.0));
    kprintln!("  race: client {client:#b}, server {server_bits:#b}");
    t.check(
        "race: both sides finished every round",
        client != BAD && server_bits != BAD,
    );
    t.check(
        "race: every reply the server delivered reached the client",
        client == server_bits,
    );
    let all = ((1 << ROUNDS) - 1) << 1;
    t.check(
        &format!("race: early replies arrived, late ones got REVOKED ({client:#b})"),
        client & 0b10 != 0 && client & (1 << ROUNDS) == 0 && client & !all == 0,
    );

    t.check("no process was killed", process::kills().is_empty());
}
