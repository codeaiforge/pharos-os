//! Test kernel: updates with the user's approval, and rollback (#165,
//! boot.md section 8). As the `recovery` kernel does, it mounts `root`,
//! starts `init` with the boot table, and checks its report; then it keeps
//! running while the runner plays the user on the trusted console, until
//! `init` says how the update ended (a line starting `init: system:
//! update `), or 100 s. `cargo xtask runner` boots it on stores with
//! prepared slots and incoming images and checks the slot record and the
//! store `init` left (`xtask/src/recovery.rs`). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// How `init` says an update, a discard, a refusal, or a rollback ended.
const END: &[u8] = b"init: system: update ";

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
    let Some(root) = fs::mount_root().ok().and_then(|_| fs::root()) else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let init = process::spawn_elf_limited(&root, b"bin/init", 0, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the boot table", init.is_ok());
    let summary = ipc::poll(&report, Duration::from_secs(75)).map(|m| m.bytes().to_vec());
    let all = pharos_services::BOOT.len() as u8;
    t.check(
        "init reported every boot service ready",
        summary
            .as_deref()
            .is_some_and(|s| s.get(..2) == Some(&[all, 0])),
    );
    let start = time::uptime();
    let end = loop {
        let found = (process::debug_output().into_iter()).find(|(_, l)| l.starts_with(END));
        if let Some((_, line)) = found {
            // `trust` writes its line just after `init`'s.
            sched::sleep(Duration::from_secs(1));
            break Some(line);
        }
        if time::uptime() - start > Duration::from_secs(100) {
            break None;
        }
        sched::sleep(Duration::from_millis(50));
    };
    t.check("init said how the update ended within 100 s", end.is_some());
    if let Some(line) = end {
        kprintln!("update: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
}
