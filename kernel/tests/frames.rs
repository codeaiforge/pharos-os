//! Test kernel: the physical frame allocator built from the Limine memory
//! map (D-005, issue #26). Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::limine::{MEMMAP_USABLE, MemmapResponse};
use pharos_kernel::mm;
use pharos_kernel::mm::frame::{FRAME_SIZE, Frame, FrameFreeError, LOW_MEMORY_END, OutOfMemory};
use pharos_kernel::testing::TestRun;

pharos_kernel::test_kernel!(run);

/// Frames allocated, checked, and freed in the first round.
const SAMPLE: usize = 512;

/// True if the whole frame at `addr` lies in a usable memory-map entry.
fn in_usable_entry(map: &MemmapResponse, addr: u64) -> bool {
    map.entries().any(|e| {
        e.kind == MEMMAP_USABLE && addr >= e.base && addr + FRAME_SIZE <= e.base + e.length
    })
}

fn run(t: &mut TestRun) {
    let (Some(map), Some(hhdm)) = (requests::MEMMAP.response(), requests::HHDM.response()) else {
        t.check("Limine memory map and HHDM present", false);
        return;
    };
    let entries = || map.entries().map(|e| (e.base, e.length, e.kind));

    let start = mm::init_frames(hhdm.offset, entries());
    t.check("frame allocator initialized", start.is_ok());
    let Ok(start) = start else { return };
    t.check(
        "some frames free, bitmap storage reserved",
        start.free > 0 && start.free < start.total,
    );
    t.check("no usable regions skipped", start.skipped_regions == 0);
    t.check(
        "second init rejected",
        mm::init_frames(hhdm.offset, entries()).is_err(),
    );

    let mut guard = mm::frames();
    let Some(frames) = guard.as_mut() else {
        t.check("allocator available after init", false);
        return;
    };

    // Round 1: a sample of single frames.
    let mut kept = [0u64; SAMPLE];
    let mut ok = true;
    for slot in kept.iter_mut() {
        match frames.alloc() {
            Ok(frame) => *slot = frame.addr(),
            Err(OutOfMemory) => ok = false,
        }
    }
    t.check("512 frames allocated", ok);
    t.check(
        "sample frames aligned, at or above 1 MiB, inside usable entries",
        kept.iter()
            .all(|&a| a % FRAME_SIZE == 0 && a >= LOW_MEMORY_END && in_usable_entry(map, a)),
    );
    // A fresh next-fit allocator hands out increasing addresses, so strictly
    // increasing also means distinct.
    t.check(
        "sample frames distinct",
        kept.windows(2).all(|w| w[0] < w[1]),
    );
    t.check(
        "free count dropped by the sample",
        frames.stats().free == start.free - SAMPLE,
    );

    let first = Frame::from_addr(kept[0]).unwrap_or(Frame::from_addr(0).unwrap());
    t.check("free a frame", frames.free(first).is_ok());
    t.check(
        "double free rejected",
        frames.free(first) == Err(FrameFreeError::NotAllocated),
    );
    t.check(
        "unknown frame rejected",
        frames.free(Frame::from_addr(0).unwrap()) == Err(FrameFreeError::Unknown),
    );
    let rest_freed = kept[1..]
        .iter()
        .all(|&a| Frame::from_addr(a).is_some_and(|f| frames.free(f).is_ok()));
    t.check("free the rest of the sample", rest_freed);
    t.check(
        "free count back to start",
        frames.stats().free == start.free,
    );

    // Round 2: an aligned contiguous run.
    let run16 = frames.alloc_contiguous(16, 16);
    t.check(
        "16 contiguous frames, 64 KiB aligned",
        run16
            .as_ref()
            .is_ok_and(|f| f.addr() % (16 * FRAME_SIZE) == 0),
    );
    if let Ok(f) = run16 {
        t.check(
            "free the contiguous run",
            frames.free_contiguous(f, 16).is_ok(),
        );
    }

    // Round 3: exhaust physical memory.
    let mut count = 0;
    let mut aligned = true;
    while let Ok(frame) = frames.alloc() {
        aligned &= frame.addr() % FRAME_SIZE == 0 && frame.addr() >= LOW_MEMORY_END;
        count += 1;
    }
    t.check(
        "every free frame handed out exactly once",
        count == start.free,
    );
    t.check("exhaustion frames aligned and above 1 MiB", aligned);
    t.check("out of memory reported", frames.alloc() == Err(OutOfMemory));
    t.check("no frames left", frames.stats().free == 0);
}
