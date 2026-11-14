//! Test kernel: NMI (vector 2) and machine check (vector 18) run on their
//! own TSS IST stacks, distinct from each other, the double-fault stack, and
//! the kernel stack (#222). `int 2` and `int 18` enter through the same
//! gates as the real events. Runs under UEFI (D-009).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, Ordering};

use pharos_kernel::arch::x86_64::{gdt, idt, kernel_stack_bounds, stack_pointer};
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

/// Set once the NMI hook has run, so the machine-check hook knows the order.
static NMI_SEEN: AtomicBool = AtomicBool::new(false);

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

    let nmi = gdt::nmi_stack_bounds();
    let mc = gdt::machine_check_stack_bounds();
    let df = gdt::double_fault_stack_bounds();
    let kernel = kernel_stack_bounds();
    t.check(
        "TSS IST2 is the top of the NMI stack",
        gdt::ist_top(gdt::NMI_IST) == nmi.1,
    );
    t.check(
        "TSS IST3 is the top of the machine-check stack",
        gdt::ist_top(gdt::MACHINE_CHECK_IST) == mc.1,
    );
    t.check(
        "IST tops are 16-byte aligned",
        nmi.1 % 16 == 0 && mc.1 % 16 == 0,
    );
    let disjoint = |a: (u64, u64), b: (u64, u64)| a.1 <= b.0 || b.1 <= a.0;
    t.check(
        "NMI, machine-check, double-fault, and kernel stacks do not overlap",
        disjoint(nmi, mc)
            && disjoint(nmi, df)
            && disjoint(mc, df)
            && disjoint(nmi, kernel)
            && disjoint(mc, kernel),
    );

    // Must be last: neither handler returns; the hook finishes the run.
    idt::set_fatal_hook(on_fatal);
    idt::raise_nmi_vector();
    t.check("NMI handler ran", false);
}

/// Checks the stack each handler runs on. The NMI hook raises vector 18,
/// whose hook ends the run.
fn on_fatal(frame: &idt::ExceptionFrame) -> ! {
    let mut t = TestRun::new();
    let sp = stack_pointer();
    let (kernel_bottom, kernel_top) = kernel_stack_bounds();
    if frame.vector == u64::from(idt::NMI) && !NMI_SEEN.swap(true, Ordering::Relaxed) {
        let (bottom, top) = gdt::nmi_stack_bounds();
        t.check(
            "NMI handler runs on the NMI stack (IST2)",
            sp > bottom && sp <= top,
        );
        t.check(
            "NMI interrupted the kernel stack",
            frame.rsp > kernel_bottom && frame.rsp <= kernel_top,
        );
        idt::raise_machine_check_vector();
        t.check("machine-check handler ran", false);
        t.finish()
    }
    t.check(
        "machine check after the NMI",
        frame.vector == u64::from(idt::MACHINE_CHECK) && NMI_SEEN.load(Ordering::Relaxed),
    );
    let (bottom, top) = gdt::machine_check_stack_bounds();
    t.check(
        "machine-check handler runs on the machine-check stack (IST3)",
        sp > bottom && sp <= top,
    );
    let (nmi_bottom, nmi_top) = gdt::nmi_stack_bounds();
    t.check(
        "machine check interrupted the NMI stack",
        frame.rsp > nmi_bottom && frame.rsp <= nmi_top,
    );
    t.finish()
}
