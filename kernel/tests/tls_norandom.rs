//! Test kernel: the TLS service without virtio-rng (#273, tls.md).
//! `init` starts its `tls_norandom` table, where the service's handle 2 is
//! the console instead of the device, so no seed can be had and the
//! client's `OPEN` (`netclient` 7) must be `NO_RANDOM`, before anything
//! is sent. Runs under UEFI (D-009).

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
const STEPS: [&str; 1] = ["tlsclient: OPEN without virtio-rng is NO_RANDOM"];

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
    t.check(
        "the date at boot is kept, for clock_real (#271)",
        time::set_boot_date(requests::DATE_AT_BOOT.response().map(|d| d.timestamp)),
    );
    t.check("preemption enabled", sched::enable_preemption().is_ok());
    pharos_kernel::testing::init_iommu(crate::requests::RSDP.response());
    pci::enumerate();
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    let report = ipc::Endpoint::new();
    pharos_kernel::testing::init_key();
    let caps = process::init_capabilities(programs.clone(), report.clone(), true);
    let id =
        process::spawn_elf_limited(&programs, b"bin/init", 9, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the tls_norandom table", id.is_ok());

    let summary = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "every service and client succeeded: 3 ready, 0 failed",
        summary.is_some_and(|m| m.bytes() == [3, 0, 0, 0]),
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
