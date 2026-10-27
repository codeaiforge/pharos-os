//! Test kernel: the kernel's own GDT and TSS are loaded (issue #20). Runs
//! under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::gdt;
use pharos_kernel::testing::TestRun;

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    t.check("Limine's GDT active at entry", !gdt::kernel_gdt_loaded());
    t.check(
        "no double-fault stack before init",
        gdt::double_fault_stack_top() == 0,
    );

    gdt::init();
    gdt::init(); // a second call must be harmless (ltr would fault)

    let s = gdt::segment_state();
    t.check("GDTR points at the kernel GDT", gdt::kernel_gdt_loaded());
    t.check("CS is the kernel code selector", s.cs == gdt::KERNEL_CODE);
    t.check("SS is the kernel data selector", s.ss == gdt::KERNEL_DATA);
    t.check("DS is the kernel data selector", s.ds == gdt::KERNEL_DATA);
    t.check("TR is the TSS selector", s.tr == gdt::TSS);

    let (bottom, top) = gdt::double_fault_stack_bounds();
    let ist = gdt::double_fault_stack_top();
    t.check(
        "TSS IST1 is the top of the double-fault stack",
        ist == top && top > bottom,
    );
    t.check("double-fault stack top is 16-byte aligned", ist % 16 == 0);
}
