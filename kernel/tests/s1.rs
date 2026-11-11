//! Test kernel: scenario S1 with the real model driving an agent (#190,
//! testing.md "S1 end to end"). The services, store, and runtime of
//! `tools`; `cargo xtask s1` writes the S1 model and `report.txt` to the
//! store and boots it under KVM with 2 GiB. `agentclient` mode 16 runs an
//! `s1` task (agent `s1`: model 1 and `read_file` on `report.txt`): the
//! model's call goes through the runtime's `TOOL`, the file back to the
//! model, and both turns' text is the result, printed in hexadecimal.
//! The runner compares it with the host's and checks the audit trail.
//! Without `PHAROS_MODEL` the runner skips it. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

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
    // The files capability comes with the network service's.
    if !common::start_net(t, &mut services) || common::start_runtime(t, &services).is_none() {
        return;
    }
    let (client, steps) = common::client(t, &services, 16);
    let step = "the model's tool call ran and its answer is the result";
    let want = alloc::format!("ok {step}");
    let mut passed = false;
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(660) {
        match ipc::poll(&steps, Duration::from_millis(100)) {
            Some(m) if m.bytes() == b"done" => break,
            Some(m) => passed |= m.bytes() == want.as_bytes(),
            None => {}
        }
    }
    t.check(step, passed);
    let exited = (0..40).any(|_| {
        let e = process::exits().into_iter().find(|e| e.task == client);
        if e.is_none() {
            sched::sleep(Duration::from_millis(50));
        }
        e.is_some_and(|e| e.code == 0)
    });
    t.check("the client exited with no failed step", exited);
    kprintln!("s1: done in {} s", (time::uptime() - start).as_secs());
}
