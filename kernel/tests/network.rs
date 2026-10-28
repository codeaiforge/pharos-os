//! Test kernel: `init` starts the network service and three clients from
//! its network table (issue #63, networking.md). Clients reach the network
//! only through badged capabilities: one pings the slirp gateway and
//! exchanges datagrams with another over our own address, a datagram to a
//! port nobody holds is counted, and an unbadged client is refused. Runs
//! under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// Client steps that must pass.
const STEPS: [&str; 10] = [
    "echoer: registered",
    "sender: non-blocking send with nobody waiting: WOULD_BLOCK",
    "sender: ping 10.0.2.2 answered",
    "sender: datagram to 10.0.2.15:40001 accepted",
    "echoer: hello from 10.0.2.15:40000",
    "echoer: pong sent",
    "sender: pong from 10.0.2.15:40001",
    "sender: datagram to a port nobody holds accepted",
    "sender: counters show frames both ways and the lost datagram",
    "unbadged: refused with NO_PORT",
];

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
    pci::enumerate();
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    let report = ipc::Endpoint::new();
    let caps = process::init_capabilities(programs.clone(), report.clone(), true);
    let id = process::spawn_elf(&programs, b"bin/init", 2, caps);
    t.check("init started with the network table", id.is_ok());

    let summary = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "every service and client succeeded: 4 ready, 0 failed",
        summary.is_some_and(|m| m.bytes() == [4, 0]),
    );
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .map(|(_, l)| l)
        .collect();
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in STEPS {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "no client reported a failure",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
    t.check("nothing was killed", process::kills().is_empty());
}
