//! Test kernel: `init` starts services from its test table (issue #61,
//! services.md). Services start in order; a crashing one is reported by
//! name and its dependent skipped while independent ones still start; a
//! missing program and a missing device are reported; a daemon reports
//! ready; the summary reaches the kernel. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `init`'s lines for the test table, in the order they must appear.
const EXPECTED: [&str; 12] = [
    "init: first started",
    "init: first done",
    "init: daemon started",
    "init: daemon ready",
    "init: crasher started",
    "init: crasher killed 14",
    // Its policy (#150).
    "init: crasher not restarted: restart policy never",
    "init: after-crasher skipped",
    "init: independent started",
    "init: independent done",
    "init: missing missing program",
    "init: virtio-blk no device",
];

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
    // No devices: the virtio-blk entry must report a missing device.
    let report = ipc::Endpoint::new();
    let caps = process::init_capabilities(programs.clone(), report.clone(), false);
    let id = process::spawn_elf(&programs, b"bin/init", 1, caps);
    t.check("init started with the test table", id.is_ok());
    let id = id.unwrap_or(u64::MAX);

    let summary = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "the summary reaches the kernel: 3 ready, 4 failed",
        summary.is_some_and(|m| m.bytes() == [3, 4, 0]),
    );
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, line)| line)
        .collect();
    for line in &lines {
        kprintln!("  init: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let expected: Vec<&[u8]> = EXPECTED.iter().map(|s| s.as_bytes()).collect();
    t.check(
        "init's lines, in order: start, done, ready, killed, skipped, missing",
        lines == expected,
    );
    t.check(
        "the daemon still runs, and so does init",
        process::by_id(id).is_some() && process::count() == 2,
    );
    let daemons: Vec<u64> = (id + 1..id + 64)
        .filter(|&d| process::by_id(d).is_some_and(|p| p.parent == Some(id)))
        .collect();
    t.check(
        "init is trusted and starts its services in the services class (D-022)",
        sched::class_of(id) == Some(sched::TRUSTED)
            && daemons.len() == 1
            && sched::class_of(daemons[0]) == Some(sched::SERVICES),
    );
    let killed = process::kills();
    t.check(
        "only the crasher was killed",
        killed.len() == 1 && killed[0].vector == 14,
    );
}
