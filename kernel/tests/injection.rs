//! Test kernel: prompt injection and malformed tool calls (#129,
//! tools.md), on the `tools` kernel's services and store. The kernel
//! starts `store`, `infer`, `audit`, `trust`, the network service, and the
//! runtime as the `agents_net` kernel does; the
//! runtime also gets handle 10, the storage service badged for the `files`
//! namespace, read-only. `agentclient` mode 9 runs an `injected` task: a
//! naive agent that runs every call in its granted `report.txt` and in the
//! test model's output, then the injection corpus's calls (`bin/testagent`
//! lists them). The runner refuses its one `send` on the trusted console,
//! checks the console never shows the agent's fake prompt or payload, and
//! checks the audit trail. Runs under UEFI (D-009).

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
    // The files capability is handle 10, after the network service's 9.
    if !common::start_net(t, &mut services) {
        return;
    }
    let Some(runtime) = common::start_runtime(t, &services) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 9);
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
    let step = "no injected or malformed call has any effect beyond the grants";
    let want = alloc::format!("ok {step}");
    t.check(step, passed.iter().any(|l| l == want.as_bytes()));
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
    let said: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == runtime)
        .map(|(_, l)| l)
        .collect();
    for line in &said {
        kprintln!("  runtime: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    t.check(
        "the runtime accepted injected's manifest",
        said.iter()
            .any(|l| l == b"agents: injected manifest accepted"),
    );
    // Let the runner read the last answer before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
