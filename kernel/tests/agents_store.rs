//! Test kernel: a task whose retry the store refused (#99, #100,
//! agents.md). The kernel starts `store`, `infer`, `trust`, and the agent
//! runtime as the `agents` kernel does, then `agentclient` in mode 1,
//! which submits the `counter` task and waits for it. Once the task has
//! counted a while, the kernel kills the storage service and the agent
//! together, as a crash would (the runtime, waiting on the dead store,
//! may see the attempt's end as a hang). The runtime cannot record the
//! retry, so the task stays marked running with no process: it must not
//! restart while the store is down, and must restart and finish once the
//! kernel starts the store again on the same endpoint and disk. Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

#[path = "common/agents.rs"]
mod common;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{ipc, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// The vector the killed processes' ends report.
const KILLED: u64 = 13;

/// The runtime's lines so far.
fn said(runtime: TaskId) -> Vec<Vec<u8>> {
    process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == runtime)
        .map(|(_, l)| l)
        .collect()
}

fn has(lines: &[Vec<u8>], text: &str) -> bool {
    lines.iter().any(|l| l == text.as_bytes())
}

/// Waits up to `secs` for the runtime to say `text`.
fn wait_for(runtime: TaskId, text: &str, secs: u64) -> bool {
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(secs) {
        if has(&said(runtime), text) {
            return true;
        }
        sched::sleep(Duration::from_millis(50));
    }
    false
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
    let Some(services) = common::setup(t) else {
        return;
    };
    let Some(runtime) = common::start_runtime(t, &services) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 1);

    // A fresh store: the counter is task 1. Let it store a few steps.
    t.check(
        "the counter task started",
        wait_for(runtime, "agents: counter task 1 started", 20),
    );
    sched::sleep(Duration::from_secs(1));
    let agent = (runtime + 1..runtime + 400)
        .find(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(runtime)));
    let killed = process::kill(services.store_id, KILLED)
        && agent.is_some_and(|id| process::kill(id, KILLED));
    t.check(
        "the kernel killed the storage service and the agent",
        killed,
    );

    // Each store call now waits out its 10 s limit.
    t.check(
        "the runtime could not record the retry",
        wait_for(runtime, "agents: counter task 1 not stored", 40),
    );
    // A refused retry is tried again within a second: a restart without
    // the store would show by now.
    sched::sleep(Duration::from_secs(3));
    let lines = said(runtime);
    t.check(
        "while the store is down the task does not restart",
        !has(&lines, "agents: counter task 1 restarting 2/10")
            && (runtime + 1..runtime + 400)
                .all(|id| process::by_id(id).is_none_or(|p| p.parent != Some(runtime))),
    );

    // Checked as `bin/store started and reported ready`.
    if common::restart_store(t, &services).is_none() {
        return;
    }
    t.check(
        "with the store back, the stranded task restarts",
        wait_for(runtime, "agents: counter task 1 restarting 2/10", 15),
    );

    let mut passed: Vec<Vec<u8>> = Vec::new();
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(60) {
        match ipc::poll(&steps, Duration::from_millis(100)) {
            Some(m) if m.bytes() == b"done" => break,
            Some(m) => {
                kprintln!("  {}", core::str::from_utf8(m.bytes()).unwrap_or("?"));
                passed.push(m.bytes().to_vec());
            }
            None => {}
        }
    }
    t.check(
        "and completes, each step's record checked on its attempts",
        passed.iter().any(|l| {
            l == b"ok the counter task completed, each step's record checked on every attempt"
        }),
    );
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
    for line in said(runtime) {
        kprintln!("  runtime: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
}
