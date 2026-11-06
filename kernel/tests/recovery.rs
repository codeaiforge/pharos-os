//! Test kernel: booting from an image slot, with fallback (#163, boot.md
//! section 8). It starts `init` with the boot table and the boot image's
//! `root`, as the main kernel does, waits up to 75 s for its report
//! `[ready, failed, image]`, prints the image, and checks every boot
//! service is ready. `cargo xtask runner` boots it on stores with
//! prepared slots and checks which image ran and the slot record `init`
//! left (`xtask/src/recovery.rs`). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

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
    pci::enumerate();
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let init = process::spawn_elf_limited(&root, b"bin/init", 0, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the boot table", init.is_ok());
    let summary = ipc::poll(&report, Duration::from_secs(75)).map(|m| m.bytes().to_vec());
    let Some([ready, failed, image]) = summary.as_deref().and_then(|s| <[u8; 3]>::try_from(s).ok())
    else {
        t.check("init reported [ready, failed, image] within 75 s", false);
        return;
    };
    let name = match image {
        0 => "the factory image",
        1 => "slot A",
        2 => "slot B",
        _ => "an unknown image",
    };
    kprintln!("recovery: running {name}");
    t.check(
        "every boot service is ready",
        (ready, failed) == (pharos_services::BOOT.len() as u8, 0),
    );
}
