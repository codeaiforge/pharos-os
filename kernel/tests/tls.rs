//! Test kernel: TLS (#273, tls.md). `init` starts its `tls` table: the
//! network, storage, and audit services, the TLS service with its audit
//! trail and virtio-rng, and `tlsclient` (`netclient` 6). `cargo xtask`
//! runs an `openssl s_server` on the host for each of four certificates
//! from a throwaway test authority, whose certificate is the image's one
//! root (`system/tls/roots`). The client makes an HTTPS round trip to the
//! good one, and the expired one, the one for another name, and the one
//! from an authority that is not pinned are each refused with their
//! reason; afterwards the runner checks the audit trail for each intent
//! and outcome. Runs under UEFI (D-009).

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
const STEPS: [&str; 14] = [
    "tlsclient: buffer attached",
    "tlsclient: the good server's handshake completed",
    "tlsclient: the HTTP request written",
    "tlsclient: the HTTP reply came back over TLS",
    "tlsclient: closed",
    "tlsclient: CLOSE during the handshake answers OK",
    "tlsclient: an expired certificate refused with EXPIRED",
    "tlsclient: a certificate for another name refused with NAME",
    "tlsclient: an authority not pinned refused with UNKNOWN_ISSUER",
    "tlsclient: a destination not listed refused with NO_ACCESS",
    "tlsclient: a TCP_POLL count over the window is a TCP error (review F1)",
    "tlsclient: a success whose outcome is not stored is NO_AUDIT (review F5)",
    "tlsclient: a connection idle past the limit is closed (review F3)",
    "tlsclient: a loop of OPENs refused with OVER_LIMIT, then one earned back",
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
    let caps = process::init_capabilities(programs.clone(), report.clone(), true);
    let id =
        process::spawn_elf_limited(&programs, b"bin/init", 8, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the tls table", id.is_ok());

    let summary = ipc::poll(&report, Duration::from_secs(30));
    t.check(
        "every service and client succeeded: 6 ready, 0 failed",
        summary.is_some_and(|m| m.bytes() == [6, 0, 0, 0]),
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
