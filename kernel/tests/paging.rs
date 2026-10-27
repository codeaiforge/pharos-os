//! Test kernel: the kernel's own page tables (D-005, issue #27): mappings
//! and permissions per segment, guard pages, map and unmap, and a page fault
//! after unmapping. Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::paging::{self, Flags, PageSize};
use pharos_kernel::arch::x86_64::{gdt, idt, kernel_stack_bounds};
use pharos_kernel::mm;
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

const PAGE: u64 = 4096;

fn flags_at(virt: u64) -> Option<Flags> {
    paging::translate_kernel(virt).map(|t| t.flags)
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    t.check("frame allocator and kernel page tables set up", memory);
    if !memory {
        return;
    }
    t.check(
        "CR3 holds the kernel root table",
        paging::kernel_root() == Some(paging::active_root()),
    );

    // Kernel image, per segment.
    t.check(
        "text is read+execute",
        flags_at(run as *const () as u64) == Some(Flags::CODE),
    );
    t.check(
        "rodata is read-only, no-execute",
        flags_at(paging::rodata_probe_addr()) == Some(Flags::READ_ONLY),
    );
    t.check(
        "data is writable, no-execute",
        flags_at(paging::data_probe_addr()) == Some(Flags::DATA),
    );
    let image = requests::EXECUTABLE_ADDRESS.response();
    t.check(
        "text maps to the kernel's physical load address",
        image.is_some_and(|i| {
            paging::translate_kernel(i.virtual_base + PAGE)
                .is_some_and(|tr| tr.phys == i.physical_base + PAGE)
        }),
    );

    // Stacks and guard pages.
    let (stack_bottom, _) = kernel_stack_bounds();
    let (df_bottom, _) = gdt::double_fault_stack_bounds();
    t.check(
        "kernel stack mapped writable",
        flags_at(stack_bottom) == Some(Flags::DATA),
    );
    t.check(
        "kernel stack guard page unmapped",
        flags_at(stack_bottom - PAGE).is_none(),
    );
    t.check(
        "double-fault stack mapped writable",
        flags_at(df_bottom) == Some(Flags::DATA),
    );
    t.check(
        "double-fault stack guard page unmapped",
        flags_at(df_bottom - PAGE).is_none(),
    );

    // Direct map.
    let hhdm = requests::HHDM.response().map_or(0, |h| h.offset);
    let memmap = requests::MEMMAP.response();
    let usable = memmap.and_then(|m| {
        m.entries()
            .filter(|e| e.kind == pharos_kernel::limine::MEMMAP_USABLE)
            .max_by_key(|e| e.length)
    });
    t.check(
        "direct map covers the largest usable region, no-execute",
        usable.is_some_and(|e| {
            paging::translate_kernel(hhdm + e.base)
                .is_some_and(|tr| tr.phys == e.base && tr.flags == Flags::DATA)
        }),
    );
    t.check(
        "direct map uses 2 MiB pages",
        usable.is_some_and(|e| {
            let aligned = e.base.next_multiple_of(paging::HUGE_PAGE);
            paging::translate_kernel(hhdm + aligned).is_some_and(|tr| tr.size == PageSize::Size2M)
        }),
    );
    t.check(
        "Limine responses still readable after the switch",
        memmap.is_some_and(|m| m.entries().count() > 0),
    );

    // Map, write through two addresses, unmap.
    let alias = {
        let mut frames = mm::frames();
        frames.as_mut().map(paging::alias_check)
    };
    match alias {
        Some(Ok(a)) => {
            t.check("test page mapped", a.mapped);
            t.check("translate agrees with the mapping", a.translated);
            t.check(
                "write via the test page, read via the direct map",
                a.alias_matches,
            );
            t.check("test page unmapped", a.unmapped);
        }
        _ => t.check("alias check ran", false),
    }

    // Must be last: touching the unmapped page faults; the hook finishes.
    idt::set_fatal_hook(on_page_fault);
    paging::touch_test_page();
    t.check("access to the unmapped page faulted", false);
}

fn on_page_fault(frame: &idt::ExceptionFrame) -> ! {
    let mut t = TestRun::new();
    t.check(
        "page fault after unmap",
        frame.vector == u64::from(idt::PAGE_FAULT),
    );
    t.check("CR2 is the test page", idt::read_cr2() == paging::TEST_PAGE);
    t.check("error code: not present, read", frame.error_code == 0);
    t.finish()
}
