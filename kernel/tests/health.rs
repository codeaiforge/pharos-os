//! Test kernel: `init`'s health checks (M4.5, services.md "Configuration
//! and health"). `init` runs its `health` table (argument 4): `net`, a
//! daemon that sends `ready` and never receives on the network endpoint
//! `init` checks it on, and `steady`, whose name no endpoint has. Every
//! 10 s `init` sends each checked daemon `INFO`; `net` answers none, so
//! past its 30 s window it is unresponsive, stopped, restarted once by its
//! policy (`Up(1)`), unresponsive again, and given up. `steady` is never
//! checked or stopped. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `init`'s last line: `net`'s restarts are used up.
const END: &[u8] = b"init: net not restarted: restarts used up";

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
    let report = ipc::Endpoint::new();
    let caps = process::init_capabilities(programs.clone(), report.clone(), false);
    let id = process::spawn_elf(&programs, b"bin/init", 4, caps);
    t.check("init started with the health table", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    t.check(
        "both daemons ready",
        ipc::poll(&report, Duration::from_secs(10)).is_some_and(|m| m.bytes() == [2, 0, 0, 0]),
    );
    let lines = || -> Vec<Vec<u8>> {
        (process::debug_output().into_iter())
            .filter(|(t, _)| *t == id)
            .map(|(_, line)| line)
            .collect()
    };
    let start = time::uptime();
    while !lines().iter().any(|l| l == END) && time::uptime() - start < Duration::from_secs(100) {
        sched::sleep(Duration::from_millis(500));
    }
    let took = time::uptime() - start;
    let lines = lines();
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let at = |want: &[u8]| lines.iter().position(|l| l.starts_with(want));
    let silent: Vec<u32> = (lines.iter())
        .filter_map(|l| l.strip_prefix(b"init: net unresponsive for "))
        .filter_map(|r| {
            core::str::from_utf8(r.strip_suffix(b" s; stopped")?)
                .ok()?
                .parse()
                .ok()
        })
        .collect();
    kprintln!("  silent for {silent:?} s; {} s in all", took.as_secs());
    t.check(
        "net found unresponsive twice, each after 30 s but within one more check",
        silent.len() == 2 && silent.iter().all(|s| (30..=41).contains(s)),
    );
    let order = [
        at(b"init: net ready"),
        at(b"init: net unresponsive for "),
        at(b"init: net restarting 1 of 1"),
        at(END),
    ];
    t.check(
        "ready, unresponsive, restarted by its policy, then given up",
        order.iter().all(Option::is_some) && order.windows(2).all(|w| w[0] < w[1]),
    );
    t.check(
        "steady never checked or stopped: one start, still running",
        (lines.iter())
            .filter(|l| *l == b"init: steady started")
            .count()
            == 1
            && !lines
                .iter()
                .any(|l| l.starts_with(b"init: steady unresponsive")),
    );
    t.check(
        "init and steady run; net does not",
        process::by_id(id).is_some() && process::count() == 2,
    );
}
