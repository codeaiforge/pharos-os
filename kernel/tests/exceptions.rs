//! Test kernel: the IDT and CPU exception handlers (issue #21). A breakpoint
//! is reported and execution continues; a page fault is reported with the
//! faulting address and error code. Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{gdt, idt};
use pharos_kernel::testing::TestRun;

pharos_kernel::test_kernel!(run);

/// Lowest address Limine loads the kernel at (`linker.ld`).
const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    t.check("IDT loaded", idt::loaded());

    idt::breakpoint();
    idt::breakpoint();
    t.check(
        "two breakpoints handled, execution continued",
        idt::breakpoint_count() == 2,
    );
    t.check(
        "registers preserved across a breakpoint",
        idt::breakpoint_preserves_registers(),
    );

    // Must be last: the page fault does not return; the hook finishes the run.
    idt::set_fatal_hook(on_page_fault);
    idt::touch_unmapped_probe();
    t.check("page fault raised", false);
}

fn on_page_fault(frame: &idt::ExceptionFrame) -> ! {
    let mut t = TestRun::new();
    t.check(
        "page fault vector",
        frame.vector == u64::from(idt::PAGE_FAULT),
    );
    t.check(
        "CR2 is the probed address",
        idt::read_cr2() == idt::UNMAPPED_PROBE,
    );
    t.check(
        "error code: not present, read, kernel mode",
        frame.error_code == 0,
    );
    t.check("RIP points into the kernel", frame.rip >= KERNEL_BASE);
    t.check(
        "CS is the kernel code selector",
        frame.cs == u64::from(gdt::KERNEL_CODE),
    );
    t.finish()
}
