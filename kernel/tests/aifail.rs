//! Test kernel: the system stays usable when an AI service fails (M4.6,
//! D-031, services.md "AI services"). `cargo xtask runner` boots it with
//! the boot image's modules and disks; the kernel starts `init` with the
//! `aifail` table (argument 5): the boot table with `infer` replaced by
//! `rogue` 3, which reports `ready` and never receives (#182, gap 1). The
//! agent runtime must still start, saying it runs without inference, and
//! every service must be ready. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// The runtime's line when the inference service does not take its buffer.
const WITHOUT: &[u8] = b"agents: inference service not taking requests; starting without it";

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
    let init = process::spawn_elf_limited(&root, b"bin/init", 5, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the aifail table", init.is_ok());
    // Without the fix the runtime fails its 10 s start 4 times first.
    let summary = ipc::poll(&report, Duration::from_secs(50)).map(|m| m.bytes().to_vec());
    let lines: Vec<(TaskId, Vec<u8>)> = process::debug_output();
    for (task, line) in &lines {
        kprintln!("  {task}: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let has = |want: &[u8]| lines.iter().any(|(_, l)| l == want);
    t.check(
        "the stand-in for infer is ready and never receives",
        has(b"init: infer ready") && has(b"rogue: ready, never receiving"),
    );
    t.check("the runtime starts without inference", has(WITHOUT));
    t.check(
        "the runtime is ready, never restarted",
        has(b"init: agents ready")
            && !lines
                .iter()
                .any(|(_, l)| l.starts_with(b"init: agents restarting")),
    );
    let boot = (pharos_services::BOOT.iter())
        .filter(|s| s.driver().is_none())
        .count();
    t.check(
        "every service ready: [8, 0]",
        summary
            .as_deref()
            .is_some_and(|s| s.len() == 4 && usize::from(s[0]) == boot && s[1] == 0),
    );
}
