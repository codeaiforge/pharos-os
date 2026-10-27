//! Test kernel: bootloader-reclaimable memory joins the frame allocator
//! once nothing uses it (D-005, issue #28). Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{gdt, idt, paging};
use pharos_kernel::boot_info::summarize;
use pharos_kernel::limine::MEMMAP_BOOTLOADER_RECLAIMABLE;
use pharos_kernel::mm::{self, frame::Span};
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    t.check("frame allocator and kernel page tables set up", memory);
    let Some(map) = requests::MEMMAP.response() else {
        t.check("memory map present", false);
        return;
    };
    if !memory {
        return;
    }

    // Everything needed from Limine, read before reclaim.
    let expected: usize = map
        .entries()
        .filter(|e| e.kind == MEMMAP_BOOTLOADER_RECLAIMABLE)
        .filter_map(|e| Span::usable(e.base, e.length))
        .map(|s| s.frames)
        .sum();
    let summary_before = summarize(map.entries().map(|e| (e.kind, e.length)));
    let limine_entries = map.entries().count();

    {
        let copy = mm::memory_map();
        t.check(
            "memory map copied completely",
            copy.as_ref()
                .is_some_and(|c| c.entries().len() == limine_entries && c.truncated() == 0),
        );
    }
    let (free_before, pending) = {
        let frames = mm::frames();
        let frames = frames.as_ref();
        (
            frames.map_or(0, |f| f.stats().free),
            frames.map_or(0, |f| f.pending_frames()),
        )
    };
    t.check("reclaimable memory present", expected > 0);
    t.check(
        "reclaimable frames waiting, not handed out",
        pending == expected,
    );

    // Reclaim. Limine responses are invalid from here on.
    let reclaimed = mm::reclaim_bootloader_memory();
    t.check("reclaim succeeded", reclaimed.is_ok());
    t.check(
        "reclaimed exactly the reclaimable frames",
        reclaimed.as_ref().is_ok_and(|&n| n == expected),
    );
    t.check(
        "Limine responses retired",
        requests::MEMMAP.response().is_none(),
    );
    t.check(
        "second reclaim gains nothing",
        mm::reclaim_bootloader_memory() == Ok(0),
    );

    let mut guard = mm::frames();
    let Some(frames) = guard.as_mut() else {
        t.check("allocator available", false);
        return;
    };
    t.check(
        "free frames grew by the reclaimed amount",
        frames.stats().free == free_before + expected,
    );

    // Use every free frame, including the reclaimed ones.
    let (mut count, mut all_written) = (0, true);
    while let Ok(frame) = frames.alloc() {
        all_written &= paging::fill_frame_for_test(frame, 0xa5);
        count += 1;
    }
    t.check(
        "every free frame allocated",
        count == free_before + expected,
    );
    t.check("every frame written and read back", all_written);
    drop(guard);

    // The kernel still works and the copied map still matches.
    let copy = mm::memory_map();
    t.check(
        "copied memory map unchanged after overwriting bootloader memory",
        copy.as_ref()
            .is_some_and(|c| summarize(c.tuples().map(|(_, l, k)| (k, l))) == summary_before),
    );
}
