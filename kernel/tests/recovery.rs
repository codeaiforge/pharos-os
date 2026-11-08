//! Test kernel: booting from an image slot, with fallback (#163, boot.md
//! section 8), and safe mode and recovery (#164). As the main kernel
//! does, it reads the mode from the command line, mounts `root` or else
//! its copy `recovery`, starts `init` with the boot table in that mode,
//! waits up to 75 s for its report `[ready, failed, image, mode]`, prints
//! the image and mode, and checks every boot service is ready (all but
//! the agent runtime outside normal mode). `cargo xtask runner` boots it on stores with
//! prepared slots and checks which image ran and the slot record `init`
//! left (`xtask/src/recovery.rs`). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::boot_info::{BootMode, boot_mode};
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let cmdline = requests::CMDLINE.response().and_then(|r| r.cmdline());
    let mut mode = boot_mode(cmdline).unwrap_or(BootMode::Normal);
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
    match fs::mount_root() {
        Ok((_, Some(why))) => {
            kprintln!("recovery: root not mounted: {why}; recovery copy mounted");
            mode = BootMode::RecoveryCopy;
        }
        Ok((_, None)) => {}
        Err(why) => kprintln!("recovery: no root filesystem: {why}"),
    }
    let Some(root) = fs::root() else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let init = process::spawn_elf_limited(
        &root,
        b"bin/init",
        mode.init_arg(),
        caps,
        process::INIT_MEMORY_LIMIT,
    );
    t.check("init started with the boot table", init.is_ok());
    let summary = ipc::poll(&report, Duration::from_secs(75)).map(|m| m.bytes().to_vec());
    let Some([ready, failed, image, mode]) =
        summary.as_deref().and_then(|s| <[u8; 4]>::try_from(s).ok())
    else {
        t.check(
            "init reported [ready, failed, image, mode] within 75 s",
            false,
        );
        return;
    };
    let name = match image {
        0 => "the factory image",
        1 => "slot A",
        2 => "slot B",
        3 => "the recovery copy",
        _ => "an unknown image",
    };
    let word = match mode {
        0 => "normal",
        1 => "safe",
        2 => "recovery",
        _ => "unknown",
    };
    kprintln!("recovery: running {name}");
    kprintln!("recovery: {word} mode");
    // Outside normal mode the agent runtime is off.
    // Every entry started at boot: not a driver waiting for its device (#171).
    let boot = pharos_services::BOOT
        .iter()
        .filter(|s| s.driver().is_none())
        .count();
    let all = boot as u8 - u8::from(mode != 0);
    t.check("every boot service is ready", (ready, failed) == (all, 0));
}
