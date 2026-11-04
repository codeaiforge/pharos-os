//! Test kernel: one agent cannot hold the runtime for the others (#117,
//! resources.md). The kernel starts the services and the network service
//! as the `budgets` kernel does, then stops the network service, so calls
//! to it time out, and starts the runtime with the `budgets` policy table
//! and `agentclient` in mode 6: `flooder` sends 30 datagrams, of which only
//! the first waits; `ticker` is served within 400 ms throughout but once;
//! `rater` (2 requests a second) has a request held and one more `BUSY`;
//! `queuer` may have one approval request waiting. Runs under UEFI (D-009).

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
    let Some(mut services) = common::setup(t) else {
        return;
    };
    if !common::start_net(t, &mut services) {
        return;
    }
    // Calls to a stopped service wait their whole timeout.
    process::stop(services.net_id);
    for _ in 0..40 {
        if process::by_id(services.net_id).is_none() {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    t.check(
        "the network service is stopped",
        process::by_id(services.net_id).is_none(),
    );
    let Some(runtime) = common::start_runtime_table(t, &services, 2) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 6);
    let mut passed: Vec<Vec<u8>> = Vec::new();
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(90) {
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
        "requests for a stalled service are BUSY at once",
        "another agent is served while one floods a stalled service",
        "an agent past its rate is held, then served at the rate",
        "an agent may have one approval request waiting",
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
    for (_, line) in process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == runtime)
    {
        kprintln!("  runtime: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
}
