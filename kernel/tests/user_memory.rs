//! Test kernel: processes map memory under a page limit (issue #75,
//! user-environment.md). The `memprobe` program maps up to its limit and
//! is refused beyond it, has bad and partial unmaps refused, maps and
//! unmaps far more than the machine has, uses the allocator's large and
//! small blocks, and starts children with and without a limit. Every frame
//! returns afterwards, also from a `memprobe` stopped while it maps 64 MiB. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, GRANT, Object, READ, SEND, WRITE};
use pharos_kernel::ipc::Endpoint;
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

    // Stopped while it maps 64 MiB (#120): a tick in a pause between
    // batches must not end it mid-call, or what the call holds (its
    // process, and so its capabilities) is never dropped.
    // It holds an endpoint: once it ends, the kernel's must be the last.
    let held = Endpoint::new();
    let caps = vec![Capability::new(Object::Endpoint(held.clone()), SEND)];
    let mapper = process::spawn_elf_limited(&programs, b"bin/memprobe", 6, caps, 32_900);
    t.check("memprobe started to map 64 MiB", mapper.is_ok());
    let mapper = mapper.unwrap_or(u64::MAX);
    sched::sleep(Duration::from_millis(30));
    let mapping = process::by_id(mapper).is_some();
    process::stop(mapper);
    for _ in 0..100 {
        if process::by_id(mapper).is_none() {
            break;
        }
        sched::sleep(Duration::from_millis(10));
    }
    sched::sleep(Duration::from_millis(100));
    t.check(
        "stopped while mapping 64 MiB, it ended, dropped what it held, and every frame returned",
        mapping
            && process::count() == live
            && free_frames() == before
            && Arc::strong_count(&held) == 1,
    );

    // A mapping larger than memory (#198): the kernel maps until the
    // trusted reserve refuses it, then rolls back every page it mapped.
    // Both in batches with interrupts let in, so a trusted task's sleeps
    // stay within the `classes` kernel's bound; rolled back whole, about
    // 50,000 pages kept interrupts off for about 250 ms under TCG.
    let probe = process::spawn_elf_limited(&programs, b"bin/memprobe", 7, Vec::new(), 1 << 22);
    t.check("memprobe started to map 16 GiB", probe.is_ok());
    let probe = probe.unwrap_or(u64::MAX);
    let mut late = Duration::ZERO;
    let start = time::uptime();
    while process::by_id(probe).is_some() && time::uptime() - start < Duration::from_secs(60) {
        let before = time::uptime();
        sched::sleep(Duration::from_millis(20));
        late = late.max(time::uptime() - before - Duration::from_millis(20));
    }
    kprintln!(
        "  latest 20 ms sleep while mapping 16 GiB: {} us late",
        late.as_micros()
    );
    t.check(
        "a mapping larger than memory is refused (NO_MEMORY)",
        process::exits()
            .iter()
            .any(|e| e.task == probe && e.code == 0),
    );
    t.check(
        "meanwhile a trusted task's 20 ms sleeps ended at most 40 ms late",
        late <= Duration::from_millis(40),
    );
    sched::sleep(Duration::from_millis(100));
    t.check(
        "after it, every process ended and every frame returned",
        process::count() == live && free_frames() == before,
    );
}
