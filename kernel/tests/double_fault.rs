//! Test kernel: a kernel stack overflow hits the guard page and is reported
//! as a double fault on its own stack, not a triple-fault reboot (issue #22),
//! with the kernel's own page tables and guard pages active (issue #27).
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{gdt, idt, kernel_stack_bounds, stack_pointer};
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

const PAGE: u64 = 4096;

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
    let (bottom, top) = kernel_stack_bounds();
    let sp = stack_pointer();
    t.check("running on the kernel stack", sp > bottom && sp <= top);

    // Must be last: the double fault does not return; the hook finishes the run.
    idt::set_fatal_hook(on_double_fault);
    overflow(0);
    t.check("stack overflow detected", false);
}

/// Recurses until the stack runs into the guard page.
#[allow(unconditional_recursion)]
fn overflow(depth: u64) -> u64 {
    let pad = core::hint::black_box([depth; 16]);
    overflow(depth + 1) + pad[0]
}

fn on_double_fault(frame: &idt::ExceptionFrame) -> ! {
    let mut t = TestRun::new();
    t.check(
        "double fault vector",
        frame.vector == u64::from(idt::DOUBLE_FAULT),
    );
    t.check("double fault error code is 0", frame.error_code == 0);
    let (df_bottom, df_top) = gdt::double_fault_stack_bounds();
    let sp = stack_pointer();
    t.check(
        "handler runs on the double-fault stack (IST1)",
        sp > df_bottom && sp <= df_top,
    );
    let (bottom, _) = kernel_stack_bounds();
    t.check(
        "faulting RSP is at the bottom of the kernel stack",
        frame.rsp >= bottom - PAGE && frame.rsp < bottom + PAGE,
    );
    t.finish()
}
