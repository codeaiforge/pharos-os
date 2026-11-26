//! Test kernel: people, owners, and actors (#313, M6.5, identity.md). The
//! kernel starts `store`, `infer`, `audit`, `knowledge`, `trust` (with a
//! 3 s idle limit, its argument), and the runtime as the `agents` kernel
//! does, then waits 5 s, so the runner's logged-out steps and its refused
//! login come first, and starts `agentclient` mode 19: `orphan` (owned by
//! no person) must fail at its start; an `asker` owned by the seeded
//! `admin` starts and runs until the runner stops it on the trusted
//! console; then an `asker` that must hold only what its manifest gives,
//! though `admin` now has a role. Meanwhile the runner (`IDENTITY_SCRIPT`,
//! not logged in first) checks only `login`, the stops, and `help` answer
//! logged out, a wrong passphrase is refused and the next login delayed,
//! logs in, adds `bob` with a role, gives `admin` a role, types `audit
//! rotate` logged in, logs out, logs in as `bob`, whose session ends idle,
//! and stops the `asker` logged out. Afterwards it checks the trail (the
//! role was given before the last `asker` started, which got no grant, and
//! no passphrase is in it) and resolves every record. The kernel checks no
//! agent or the runtime holds the store's `identity` namespace. Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

#[path = "common/agents.rs"]
mod common;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{ipc, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `trust`'s idle limit here, in seconds (its argument).
const IDLE_SECS: u64 = 3;

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
    let Some(services) = common::setup_with(t, IDLE_SECS) else {
        return;
    };
    let Some(runtime) = common::start_runtime(t, &services) else {
        return;
    };
    // The runner's logged-out steps and refused login come first.
    sched::sleep(Duration::from_secs(5));
    let (client, steps) = common::client(t, &services, 19);
    let mut passed: Vec<Vec<u8>> = Vec::new();
    // Holds the `identity` namespace: only `trust` may (#310).
    let identity = |id| {
        common::caps_of(id).iter().any(|c| {
            c.badge() & 0xffff == pharos_services::IDENTITY_STORE
                && common::endpoint(c).is_some_and(|e| Arc::ptr_eq(e, &services.store))
        })
    };
    let mut agents_held = false;
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(170) {
        match ipc::poll(&steps, Duration::from_millis(100)) {
            Some(m) if m.bytes() == b"done" => break,
            Some(m) => {
                kprintln!("  {}", core::str::from_utf8(m.bytes()).unwrap_or("?"));
                passed.push(m.bytes().to_vec());
            }
            None => {}
        }
        agents_held |= (runtime + 1..runtime + 100)
            .filter(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(runtime)))
            .any(identity);
    }
    for step in [
        "an agent whose owner is no person fails at its start: no owner nobody",
        "an agent whose owner was checked started, and was stopped on the trusted console",
        "an agent whose owner has a role holds only what its manifest gives",
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
        "only trust holds the identity namespace: not the runtime, nor an agent",
        identity(services.trust) && !identity(runtime) && !agents_held,
    );
    // Let the runner read the last answers before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
