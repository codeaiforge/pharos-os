//! Test kernel: agent networking (#109, capabilities.md). The kernel
//! starts `store`, `infer`, `audit`, and `trust` as the `agents` kernel
//! does, then the network service, which it tells (as `init` would) that
//! the runtime's port may reach only `10.0.2.2:47000` and `10.0.2.2:47001`,
//! then the runtime with handle 9 on it, and `agentclient` in mode 3. A
//! `netter` task, `net-talk`, exchanges a datagram with the host echo
//! server (`cargo xtask`), is refused other destinations, asks for
//! `10.0.2.2:47001` (the runner answers `yes`), and has `10.0.2.2:47000`
//! revoked on the trusted console; a `listener` task, `net-quiet`, with
//! the same grant, sends nothing and must receive nothing. Afterwards the runner checks the
//! audit trail for each send's intent and outcome. Runs under UEFI (D-009).

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
    let Some(runtime) = common::start_runtime(t, &services) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 3);
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
        "an agent sends only to granted destinations and gets their replies until revoked",
        "another agent with the same grant that sent nothing receives nothing",
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
    let said: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == runtime)
        .map(|(_, l)| l)
        .collect();
    for line in &said {
        kprintln!("  runtime: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    t.check(
        "the runtime accepted netter's and listener's manifests",
        said.iter()
            .any(|l| l == b"agents: netter manifest accepted")
            && said
                .iter()
                .any(|l| l == b"agents: listener manifest accepted"),
    );
    // Let the runner read the last answer before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
