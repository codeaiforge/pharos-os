//! Test kernel: a hostile agent (#110, capabilities.md "The sandbox"). The
//! kernel starts `store`, `infer`, `audit`, `trust`, and the runtime as the
//! `permissions` kernel does (the `inference` test's store, for model 2),
//! and `agentclient` in mode 4: a `hostile` task beside a `keeper-a` task.
//! When `hostile` logs `check me`, the kernel checks what it holds: one
//! `SEND` on the runtime badged with its slot, and no other service's
//! endpoint. `hostile` then tries everything listed in testing.md and must
//! be refused each time; `keeper-a` must complete as if alone. The runner
//! checks the trusted console never showed the prompt `hostile` faked or a
//! fifth approval request, and that the audit trail holds each kind of
//! refusal once and the attempt's total. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

#[path = "common/agents.rs"]
mod common;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::SEND;
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// The agent that said `check me` holds one `SEND` on the runtime with an
/// agent badge, and nothing else but what it made itself.
fn check(agent: TaskId, runtime_ep: &Arc<Endpoint>, services: &[&Arc<Endpoint>]) -> bool {
    let caps = common::caps_of(agent);
    let to_runtime: Vec<_> = caps
        .iter()
        .filter(|c| common::endpoint(c).is_some_and(|e| Arc::ptr_eq(e, runtime_ep)))
        .collect();
    let only_own = caps.iter().all(|c| match common::endpoint(c) {
        Some(e) => !services.iter().any(|s| Arc::ptr_eq(e, s)),
        None => false,
    });
    kprintln!("  the hostile agent holds {} capabilities", caps.len());
    to_runtime.len() == 1
        && to_runtime[0].rights() == SEND
        && (1..=16).contains(&to_runtime[0].badge())
        && only_own
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
    let (client, steps) = common::client(t, &services, 4);
    let mut passed: Vec<Vec<u8>> = Vec::new();
    let mut checked = None;
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(90) {
        if checked.is_none() {
            let agent = process::debug_output()
                .into_iter()
                .find(|(id, l)| *id == runtime && l == b"agents: hostile: check me")
                .and_then(|_| {
                    (runtime + 1..runtime + 50).find(|&id| {
                        process::by_id(id).is_some_and(|p| p.parent == Some(runtime))
                            && !common::caps_of(id).is_empty()
                    })
                });
            if let Some(agent) = agent {
                let s = &services;
                let all = [&s.infer, &s.trust_ep, &s.store, &s.audit, &s.report];
                checked = Some(check(agent, &s.runtime_ep, &all));
            }
        }
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
        "the hostile agent holds one SEND on the runtime and no service's endpoint",
        checked == Some(true),
    );
    for step in [
        "a hostile agent is refused everything it should not do",
        "an agent beside it completes unaffected",
        "the runtime still serves control requests",
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
    t.check(
        "the runtime was not killed",
        !process::kills().iter().any(|k| k.task == runtime),
    );
    for (_, line) in process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == runtime)
    {
        kprintln!("  runtime: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
    // Let the runner read the last answer before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
