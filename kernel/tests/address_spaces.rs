//! Test kernel: process address spaces that share the kernel half, switch
//! with the task, and return all their frames (issue #38). Runs under UEFI
//! (D-009).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, Ordering};

use pharos_kernel::arch::x86_64::paging::{
    self, AddressSpace, Flags, MapError, PageSize, USER_TEST_PAGE, read_user_test_page,
};
use pharos_kernel::arch::x86_64::{gdt, idt};
use pharos_kernel::mm::{self, frame::FRAME_SIZE, heap::HEAP_BASE};
use pharos_kernel::sched;
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

static A_OK: AtomicBool = AtomicBool::new(true);
static B_OK: AtomicBool = AtomicBool::new(true);
static MAIN_OK: AtomicBool = AtomicBool::new(true);

const USER_PAGE: u64 = 0x2000_0000;
const ROUNDS: usize = 3;

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// A process address space with a kernel-only page at [`USER_TEST_PAGE`]
/// whose first byte is `marker`, and one user data page.
fn space_with_marker(marker: u8) -> Option<AddressSpace> {
    let mut guard = mm::frames();
    let frames = guard.as_mut()?;
    let mut space = AddressSpace::new_user(frames).ok()?;
    let probe = frames.alloc().ok()?;
    let data = frames.alloc().ok()?;
    let ok = paging::fill_frame_for_test(probe, marker)
        && space
            .map(
                USER_TEST_PAGE,
                probe.addr(),
                PageSize::Size4K,
                Flags::DATA,
                frames,
            )
            .is_ok()
        && space
            .map(
                USER_PAGE,
                data.addr(),
                PageSize::Size4K,
                Flags::USER_DATA,
                frames,
            )
            .is_ok();
    ok.then_some(space)
}

/// Body of a task in a process address space: it must see its own marker
/// and its own root every time it runs.
fn visitor(marker: u8, root: u64, ok: &'static AtomicBool) {
    for _ in 0..ROUNDS {
        if read_user_test_page() != Some(marker) || paging::active_root() != root {
            ok.store(false, Ordering::Relaxed);
        }
        sched::yield_now();
    }
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    let ready = memory && mm::init_heap().is_ok() && sched::init().is_ok();
    t.check("memory, heap, and scheduler set up", ready);
    if !ready {
        return;
    }
    // Warm up: the first task stack creates the stack window's tables,
    // which stay; measure frames after that.
    let warm = sched::spawn(|| {}).is_ok();
    sched::yield_now();
    sched::yield_now();
    let start = free_frames();
    t.check("warm-up task ran", warm && sched::live_tasks() == 1);

    let (Some(mut a), Some(b)) = (space_with_marker(0xa1), space_with_marker(0xb2)) else {
        t.check("two process address spaces built", false);
        return;
    };
    t.check("two process address spaces built", true);
    let kernel_root = paging::kernel_root();
    let code = run as *const () as u64;
    t.check(
        "the kernel half is shared: code and heap translate the same",
        a.translate(code) == paging::translate_kernel(code)
            && b.translate(HEAP_BASE) == paging::translate_kernel(HEAP_BASE)
            && a.translate(code).is_some(),
    );
    t.check(
        "the same user address maps to different frames",
        matches!(
            (a.translate(USER_TEST_PAGE), b.translate(USER_TEST_PAGE)),
            (Some(x), Some(y)) if x.phys != y.phys
        ),
    );
    t.check(
        "user pages are user-accessible, the probe page and kernel half are not",
        a.translate(USER_PAGE).is_some_and(|t| t.flags.user)
            && a.translate(USER_TEST_PAGE).is_some_and(|t| !t.flags.user)
            && a.translate(code).is_some_and(|t| !t.flags.user),
    );
    t.check(
        "the kernel does not see process pages",
        paging::translate_kernel(USER_TEST_PAGE).is_none() && read_user_test_page().is_none(),
    );
    let refused = mm::frames().as_mut().is_some_and(|frames| {
        let process_maps_kernel = a.map(
            paging::TEST_PAGE,
            0x1000,
            PageSize::Size4K,
            Flags::DATA,
            frames,
        );
        let kernel_maps_user = paging::map_kernel_page(
            paging::TEST_PAGE,
            0x1000,
            PageSize::Size4K,
            Flags::USER_DATA,
            frames,
        );
        process_maps_kernel == Err(MapError::WrongHalf)
            && kernel_maps_user == Err(MapError::WrongHalf)
            && a.unmap(paging::TEST_PAGE) == Err(MapError::WrongHalf)
    });
    t.check(
        "a process cannot map into the kernel half; the kernel has no user pages",
        refused,
    );

    let (root_a, root_b) = (a.root(), b.root());
    let spawned = sched::spawn_in(a, move || visitor(0xa1, root_a, &A_OK)).is_ok()
        && sched::spawn_in(b, move || visitor(0xb2, root_b, &B_OK)).is_ok();
    t.check("a task spawned in each address space", spawned);
    let mut yields = 0;
    while sched::live_tasks() > 1 && yields < 100 {
        sched::yield_now();
        if read_user_test_page().is_some() || Some(paging::active_root()) != kernel_root {
            MAIN_OK.store(false, Ordering::Relaxed);
        }
        yields += 1;
    }
    t.check("both tasks finished", sched::live_tasks() == 1);
    t.check(
        "each task saw its own page and root on every turn",
        A_OK.load(Ordering::Relaxed) && B_OK.load(Ordering::Relaxed),
    );
    t.check(
        "task 0 ran on the kernel root without process pages",
        MAIN_OK.load(Ordering::Relaxed),
    );
    sched::yield_now(); // reap the last exited task
    t.check(
        "ended tasks returned every frame: stacks, tables, and pages",
        free_frames() == start,
    );

    // Destroying a space directly frees its pages and tables.
    let freed = {
        let mut guard = mm::frames();
        guard.as_mut().and_then(|frames| {
            let before = frames.stats().free;
            let mut c = AddressSpace::new_user(frames).ok()?;
            for i in 0..10 {
                let frame = frames.alloc().ok()?;
                let virt = 0x40_0000 + i * FRAME_SIZE;
                c.map(
                    virt,
                    frame.addr(),
                    PageSize::Size4K,
                    Flags::USER_CODE,
                    frames,
                )
                .ok()?;
            }
            let freed = c.destroy(frames);
            Some((freed, frames.stats().free == before))
        })
    };
    t.check(
        "destroy frees 10 pages and 4 tables (root, PDPT, PD, PT)",
        freed == Some((14, true)),
    );

    // A kernel mapping made after a process space exists (in a part of the
    // kernel half nothing used before) is visible there too. Last, because
    // the kernel keeps the page tables it creates here.
    let late_kernel_mapping = mm::frames().as_mut().is_some_and(|frames| {
        let (Ok(d), Ok(frame)) = (AddressSpace::new_user(frames), frames.alloc()) else {
            return false;
        };
        let mapped = paging::map_kernel_page(
            paging::TEST_PAGE,
            frame.addr(),
            PageSize::Size4K,
            Flags::DATA,
            frames,
        )
        .is_ok();
        let seen = mapped && d.translate(paging::TEST_PAGE).map(|t| t.phys) == Some(frame.addr());
        let undone = paging::unmap_kernel_page(paging::TEST_PAGE) == Ok(frame.addr())
            && frames.free(frame).is_ok();
        d.destroy(frames);
        seen && undone
    });
    t.check(
        "a kernel mapping added later appears in existing process spaces",
        late_kernel_mapping,
    );
}
