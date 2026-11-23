//! Test kernel: the vault and the host's secrets file (#281, gateway.md,
//! D-035). `cargo xtask` passes a secrets file through `fw_cfg`; the
//! kernel keeps it and gives it to `init`, which passes it to the vault
//! without reading it. `init` starts its `secrets` table: the store, the
//! audit service, the vault, and `vaulter` (`netclient` 8), which asks
//! for releases as the gateway and as another client. The runner checks
//! the audit trail and that the secret's value appears in neither the
//! console nor the trail. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// Client steps that must pass, and the vault's own line.
const STEPS: [&str; 9] = [
    "vaulter: a release before ATTACH is NO_BUFFER",
    "vaulter: buffer attached",
    "vaulter: route 0's prefix and secret are released",
    "vaulter: a route whose secret the file lacks is NO_SECRET",
    "vaulter: a route with no secret is NO_SECRET",
    "vaulter: a route that does not exist is NOT_FOUND",
    "vaulter: another client's release is NO_ACCESS",
    "vaulter: secrets_read without the capability is refused",
    "vaulter: INFO names vault, version 1",
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
    t.check(
        "the host's secrets file was read (one secret)",
        pharos_kernel::key::secrets_init().is_ok_and(|n| n > 0),
    );
    let caps = process::init_capabilities(programs.clone(), report.clone(), true);
    let id =
        process::spawn_elf_limited(&programs, b"bin/init", 10, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the secrets table", id.is_ok());

    let summary = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "every service and client succeeded: 4 ready, 0 failed",
        summary.is_some_and(|m| m.bytes() == [4, 0, 0, 0]),
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
        "the vault parsed one secret",
        lines.iter().any(|l| l == b"vault: secrets: 1"),
    );
    t.check(
        "no client reported a failure",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
    t.check("nothing was killed", process::kills().is_empty());
}
