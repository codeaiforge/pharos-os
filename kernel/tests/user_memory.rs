//! Test kernel: processes map memory under a page limit (issue #75,
//! user-environment.md). The `memprobe` program maps up to its limit and
//! is refused beyond it, has bad and partial unmaps refused, maps and
//! unmaps far more than the machine has, uses the allocator's large and
//! small blocks, and starts children with and without a limit. Every frame
//! returns afterwards. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, GRANT, Object, READ, WRITE};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `memprobe`'s limit: 32 MiB.
const LIMIT: u64 = 8192;

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Steps `memprobe` must report as passed.
const STEPS: [&str; 17] = [
    "mem_map up to the limit",
    "one page past the limit: NO_MEMORY",
    "mappings are placed in the map region",
    "length 0: TOO_LARGE",
    "part of a mapping: BAD_ADDRESS",
    "no mapping there: BAD_ADDRESS",
    "unmapping (length rounded up) returns the limit",
    "a refused unmap changed nothing",
    "16 rounds of 32 MiB: frames are freed",
    "allocator: 16 large vectors of 8 MiB",
    "allocator: small blocks are reused",
    "spawn with a limit above its own: TOO_LARGE",
    "a child may not get more pages than are left: TOO_LARGE",
    "a child given half the limit maps it all, and no more",
    "the half returns when it ends: a second child gets it too",
    "while a child holds half, this process cannot map it",
    "a child without a limit cannot map",
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
    let Ok(file) = programs.lookup(b"bin/memprobe") else {
        t.check("bin/memprobe in the programs image", false);
        return;
    };
    // Touch the stack-window slots three threads use, so the frame count
    // below sees only what processes use (as in the `spawn` test).
    for _ in 0..8 {
        let _ = sched::spawn(|| sched::sleep(Duration::from_millis(30)));
    }
    sched::sleep(Duration::from_millis(100));
    let before = free_frames();
    let live = process::count();

    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE | GRANT),
        Capability::new(
            Object::File {
                fs: programs.clone(),
                file,
            },
            READ,
        ),
    ];
    let id = process::spawn_elf_limited(&programs, b"bin/memprobe", 0, caps, LIMIT);
    t.check("memprobe started with a limit of 32 MiB", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    for _ in 0..1200 {
        sched::sleep(Duration::from_millis(100));
        if process::exits().iter().any(|e| e.task == id) {
            break;
        }
    }
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, line)| line)
        .collect();
    for line in &lines {
        kprintln!("  memprobe: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in STEPS {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "memprobe exited with no failures",
        process::exits().iter().any(|e| e.task == id && e.code == 0),
    );
    t.check("no process was killed", process::kills().is_empty());
    sched::sleep(Duration::from_millis(100));
    t.check("every process ended", process::count() == live);
    t.check("every frame returned", free_frames() == before);
}
