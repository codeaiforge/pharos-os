//! Test kernel: agent budgets and groups (#116, resources.md). The kernel
//! starts the services and the network service as the `agents_net` kernel
//! does, then the runtime with its `budgets` policy table and `agentclient`
//! in mode 5: `spender` is refused past its tokens, datagrams, bytes, and
//! files; `grouper` past its group's tokens and bytes this minute; `hog`
//! spins and is stopped over its 300 ms of CPU time; `pair` and `big`
//! tasks run one at a time, held by their groups' attempts and pages.
//! An `idler` task runs while the runner types `usage` on the trusted
//! console (#119) and checks the runtime's, the agent's, and its group's
//! lines. Afterwards the runner checks the audit trail holds each kind of
//! limit once and `spender`'s usage. Runs under UEFI (D-009).

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
    let Some(runtime) = common::start_runtime_table(t, &services, 2) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 5);
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
        "an agent is refused past its tokens, datagrams, bytes, and files",
        "an agent is refused past its group's tokens and bytes this minute",
        "an agent over its CPU time is stopped, a failed attempt",
        "a group of one runs its agents' tasks one at a time",
        "a group's pages hold a second task until the first ends",
        "an idle agent ran while usage was asked",
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
        "the runtime accepted the five budget agents' manifests",
        ["spender", "grouper", "hog", "pair", "big"]
            .iter()
            .all(|n| {
                let want = alloc::format!("agents: {n} manifest accepted");
                said.iter().any(|l| l == want.as_bytes())
            }),
    );
    t.check(
        "the runtime said hog went over its CPU time",
        said.iter()
            .any(|l| l.starts_with(b"agents: hog task") && l.ends_with(b"over cpu")),
    );
    // Let the runner read the trail's last records before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
