//! Test kernel: `fs_mount` (#163, boot.md section 8). `mountprobe` gets a
//! filesystem with `MOUNT` and one without, builds images in a shared
//! buffer, and mounts them: without `MOUNT` refused, a corrupt image
//! `BAD_IMAGE`, 17 MiB and a range past the buffer `TOO_LARGE`, a third
//! mount `NO_MEMORY`; the copy keeps its bytes after the buffer changes,
//! a mount at a byte offset works, and a freed copy gives its pages back
//! (20 more mounts in turn, #167). While it waits, the kernel counts
//! two copies; once it has ended, none, and every frame is back. Runs
//! under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, GRANT, MOUNT, Object, READ, WRITE};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

fn exit_code(id: TaskId) -> Option<u64> {
    process::exits()
        .iter()
        .find(|e| e.task == id)
        .map(|e| e.code)
        .or_else(|| {
            process::kills()
                .iter()
                .any(|k| k.task == id)
                .then_some(u64::MAX)
        })
}

fn printed(id: TaskId, line: &[u8]) -> bool {
    process::debug_output()
        .iter()
        .any(|(t, l)| *t == id && l == line)
}

const STEPS: [&str; 12] = [
    "without MOUNT: missing right",
    "mount an image",
    "read its file",
    "a changed buffer leaves the mount unchanged",
    "a corrupt image: bad image",
    "17 MiB: too large",
    "past the buffer's end: too large",
    "mount a second image at offset 128",
    "read the second image's file",
    "a third mount: no memory",
    "after one is deleted, another mounts",
    "a copy's pages come back: 20 more mounts in turn",
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
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    for _ in 0..8 {
        let _ = sched::spawn(|| sched::sleep(Duration::from_millis(30)));
    }
    sched::sleep(Duration::from_millis(100));
    let before = free_frames();

    let fs = |rights| Capability::new(Object::Filesystem(programs.clone()), rights);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        fs(READ | GRANT | MOUNT),
        fs(READ),
    ];
    let Ok(probe) = process::spawn_elf_limited(&programs, b"bin/mountprobe", 0, caps, 64) else {
        t.check("mountprobe started", false);
        return;
    };
    for _ in 0..400 {
        if printed(probe, b"ok done") || exit_code(probe).is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(25));
    }
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == probe)
        .map(|(_, l)| l)
        .collect();
    for l in &lines {
        kprintln!("  {}", core::str::from_utf8(l).unwrap_or("?"));
    }
    for step in STEPS {
        t.check(step, printed(probe, alloc::format!("ok {step}").as_bytes()));
    }
    t.check(
        "two copies are mounted while it waits",
        fs::copies() == fs::MAX_COPIES,
    );
    for _ in 0..800 {
        if exit_code(probe).is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(25));
    }
    t.check(
        "mountprobe exited with no failures",
        exit_code(probe) == Some(0),
    );
    // The process's table is dropped as it ends; give it a moment.
    sched::sleep(Duration::from_millis(200));
    t.check("no copy is left once it ended", fs::copies() == 0);
    t.check("no shared memory is left", process::shared_objects() == 0);
    t.check("every frame returned", free_frames() == before);
}
