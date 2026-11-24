//! Test kernel: the Tier 3 channel between two booted VMs (#297, M6.3,
//! bridge.md, D-036). `cargo xtask runner` boots it with a second
//! `virtio-serial-pci` whose port 0 is a host unix socket's server end,
//! and, once that socket exists, the guest image (`cargo xtask guest`) as
//! a second VM whose one `virtserialport` is the client end, with no relay
//! between them. The launch tool checks the guest's command line before
//! it starts, and both VMs' devices through QMP. The kernel starts `init`
//! with the `channel` table (argument 12): `channelprobe` holds the
//! second virtio-console, waits for the guest's `hello from the guest`,
//! and answers `hello from pharos`; the runner checks the guest's serial
//! log shows the answer. Runs under UEFI (D-009), in the `kvm` matrix
//! cell only (bridge.md, decided open question 4).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

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
    testing::init_iommu(crate::requests::RSDP.response());
    pci::enumerate();
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = ipc::Endpoint::new();
    testing::init_key();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let id = process::spawn_elf_limited(&root, b"bin/init", 12, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the channel table", id.is_ok());
    // The probe waits up to 120 s for the guest, which boots beside us.
    let summary = ipc::poll(&report, Duration::from_secs(150)).map(|m| m.bytes().to_vec());
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .map(|(_, l)| l)
        .collect();
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let has = |want: &[u8]| lines.iter().any(|l| l == want);
    t.check(
        "the probe got the guest's line through the channel",
        has(b"channelprobe: got hello from the guest"),
    );
    t.check(
        "the probe answered on the channel",
        has(b"channelprobe: answered"),
    );
    t.check(
        "the probe succeeded: 1 ready, 0 failed",
        summary.as_deref() == Some(&[1, 0, 0, 0][..]),
    );
    t.check("nothing was killed", process::kills().is_empty());
}
