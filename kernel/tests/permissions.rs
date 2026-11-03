//! Test kernel: agent permissions revoked while the agent runs (#105,
//! capabilities.md). The kernel starts `store`, `infer`, `trust`, and the
//! agent runtime as the `agents` kernel does (the `inference` test's store,
//! for model 2), then `agentclient` in mode 2. It submits two `keeper`
//! tasks: `keeper-a` uses its grants (its own file, model 2), and
//! `keeper-b` holds an inference session and polls. While `keeper-b` runs,
//! `cargo xtask runner` types on the trusted console (`PERMISSIONS_SCRIPT`):
//! a permission `keeper` does not hold, an agent that does not run, then
//! `revoke keeper data read` and `revoke keeper model 2`. `keeper-b` must
//! be refused after each without a restart and its session ended; then it
//! crashes, and on attempt 2 both must still be refused. Then an `asker`
//! task asks for permissions (#106): the runner answers `yes` to model 2
//! for 2 s, `no` to `data write`, and nothing to `data read` (refused after
//! the test table's 5 s), then answers that one late (`no request #3`).
//! A refused permission must not be asked for again (`approve #4`). Runs
//! under UEFI (D-009).

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
    let (client, steps) = common::client(t, &services, 2);
    let mut passed: Vec<Vec<u8>> = Vec::new();
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(100) {
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
        "with its grants, an agent writes and reads its own file and generates from model 2",
        "revoked while it runs: refused at once, its session ended, and still after a restart",
        "asked: approved for 2 s then refused again, refused by the user, unanswered refused",
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
        "the runtime accepted asker's manifest",
        said.iter().any(|l| l == b"agents: asker manifest accepted"),
    );
    t.check(
        "the runtime accepted keeper's manifest",
        said.iter()
            .any(|l| l == b"agents: keeper manifest accepted"),
    );
    // Let the runner read the last answer before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
