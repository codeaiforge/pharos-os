//! Test kernel: durable tasks across QEMU kills (#99, agents.md). The
//! kernel starts `store`, `infer`, `trust`, and the agent runtime as the
//! `agents` kernel does, then `agentclient` in mode 1, which submits the
//! `counter` task if the store has none and waits for it. The task counts
//! to 30, one keyed operation and one checkpoint per step, and on every
//! attempt checks that each step before its checkpoint is recorded as
//! done. Under `cargo xtask runner` this kernel is first booted several
//! times and killed at random moments while the task runs; this run then
//! lets it finish on the store the last kill left. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

#[path = "common/agents.rs"]
mod common;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{ipc, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

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
    let Some(services) = common::setup(t) else {
        return;
    };
    let Some(runtime) = common::start_runtime(t, &services) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 1);
    let mut passed: Vec<Vec<u8>> = Vec::new();
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(200) {
        match ipc::poll(&steps, Duration::from_millis(100)) {
            Some(m) if m.bytes() == b"done" => break,
            Some(m) => {
                kprintln!("  {}", core::str::from_utf8(m.bytes()).unwrap_or("?"));
                passed.push(m.bytes().to_vec());
            }
            None => {}
        }
    }
    for step in [
        "the counter task completed, each step's record checked on every attempt",
        "it needed at most its 10 attempts",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    let mut exit = None;
    for _ in 0..40 {
        exit = process::exits().into_iter().find(|e| e.task == client);
        if exit.is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    t.check(
        "the client exited with no failed step",
        exit.is_some_and(|e| e.code == 0),
    );
    for (id, line) in process::debug_output() {
        if id == runtime {
            kprintln!("  runtime: {}", core::str::from_utf8(&line).unwrap_or("?"));
        }
    }
}
