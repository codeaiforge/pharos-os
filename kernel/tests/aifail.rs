//! Test kernel: the system stays usable when an AI service fails (M4.6,
//! D-031, services.md "AI services"). `cargo xtask runner` boots it with
//! the boot image's modules and disks; the kernel starts `init` with the
//! `aifail` table (argument 5): the boot table with `infer` replaced by
//! `rogue` 3, which reports `ready` and never receives. Checked (#182):
//! - gap 1: the agent runtime still starts, saying it runs without
//!   inference, and every service is ready;
//! - gap 2: told `exhaust`, `rogue` maps memory until refused, which
//!   leaves the trusted class's reserve free, and keeps asking for more;
//!   the kernel then kills `trust`, and `init` starts it again, ready,
//!   though `rogue` would take every frame `trust` gave back.
//!
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{MAX_HANDLES, Object};
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::sched::TaskId;
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};
use pharos_services::MODELS_READ_ONLY;

pharos_kernel::test_kernel!(run);

/// The runtime's line when the inference service does not take its buffer.
const WITHOUT: &[u8] = b"agents: inference service not taking requests; starting without it";
const VIRTIO_CONSOLE: u16 = 0x1043;
/// The vector `process::kill` reports, as a crash would.
const KILLED: u64 = 13;
/// `rogue`'s own endpoint: the first handle after its 4 manifest ones.
const ROGUE_OWN: u64 = 5;

/// The child of `init` whose capabilities satisfy `f`.
fn child(init: TaskId, f: impl Fn(&[(&Object, u32)]) -> bool) -> Option<TaskId> {
    (init + 1..init + 400).find(|&id| {
        process::by_id(id).is_some_and(|p| {
            let mut caps = p.caps.lock();
            let held: Vec<_> = (1..=MAX_HANDLES as u64)
                .filter_map(|h| caps.get(h, 0).ok())
                .collect();
            let held: Vec<(&Object, u32)> = held.iter().map(|c| (c.object(), c.badge())).collect();
            p.parent == Some(init) && f(&held)
        })
    })
}

/// `init`'s debug lines and every other process's, so far.
fn lines() -> Vec<(TaskId, Vec<u8>)> {
    process::debug_output()
}

fn has(want: &[u8]) -> bool {
    lines().iter().any(|(_, l)| l == want)
}

fn count(want: &[u8]) -> usize {
    lines().iter().filter(|(_, l)| l == want).count()
}

/// Waits up to `secs` for `done`.
fn wait(secs: u64, done: impl Fn() -> bool) -> bool {
    let start = time::uptime();
    while !done() && time::uptime() - start < Duration::from_secs(secs) {
        sched::sleep(Duration::from_millis(50));
    }
    done()
}

fn free_frames() -> u64 {
    mm::frames().as_ref().map_or(0, |f| f.stats().free as u64)
}

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
    let Ok(init) = init else {
        return;
    };

    // Gap 1. Without the fix the runtime fails its 10 s start 4 times.
    let summary = ipc::poll(&report, Duration::from_secs(50)).map(|m| m.bytes().to_vec());
    t.check(
        "the stand-in for infer is ready and never receives",
        has(b"init: infer ready") && has(b"rogue: ready, never receiving"),
    );
    t.check("the runtime starts without inference", has(WITHOUT));
    t.check(
        "the runtime is ready, never restarted",
        has(b"init: agents ready")
            && !(lines().iter()).any(|(_, l)| l.starts_with(b"init: agents restarting")),
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

    // Gap 2: the stand-in takes every frame it may.
    let rogue = child(init, |caps| {
        caps.iter()
            .any(|(o, b)| matches!(o, Object::Endpoint(_)) && *b == MODELS_READ_ONLY)
    });
    let own = rogue
        .and_then(process::by_id)
        .and_then(|p| p.caps.lock().get(ROGUE_OWN, 0).ok());
    let Some(Object::Endpoint(own)) = own.as_ref().map(|c| c.object()) else {
        t.check("rogue's own endpoint found", false);
        return;
    };
    let mut data = [0; MAX_MESSAGE];
    data[..7].copy_from_slice(b"exhaust");
    ipc::send(
        own,
        Message {
            data,
            len: 7,
            cap: None,
            badge: 0,
        },
    );
    let held = wait(20, || {
        (lines().iter()).any(|(_, l)| l.starts_with(b"rogue: holding "))
    });
    let free = free_frames();
    kprintln!(
        "  after exhaust: {free} frames free, reserve {}",
        process::TRUSTED_RESERVE
    );
    t.check("rogue maps memory until refused", held);
    t.check(
        "the trusted class's reserve is still free",
        free >= process::TRUSTED_RESERVE,
    );

    // `trust` crashes now and must come back.
    sched::sleep(Duration::from_millis(500));
    kprintln!("  before the kill: {} frames free", free_frames());
    let trust = child(init, |caps| {
        caps.iter()
            .any(|(o, _)| matches!(o, Object::Device(d) if d.pci.device == VIRTIO_CONSOLE))
    });
    t.check(
        "trust killed",
        trust.is_some_and(|id| process::kill(id, KILLED)),
    );
    t.check(
        "init starts trust again, and it is ready",
        wait(20, || count(b"init: trust ready") == 2),
    );
    kprintln!("  after the restart: {} frames free", free_frames());
    for (task, line) in lines() {
        kprintln!("  {task}: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
}
