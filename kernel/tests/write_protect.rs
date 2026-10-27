//! Test kernel: writing to read-only kernel data faults under the kernel's
//! own page tables (D-005, issue #27). Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{gdt, idt, paging};
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
    if !memory {
        return;
    }
    idt::set_fatal_hook(on_page_fault);
    paging::write_rodata_probe();
    t.check("write to rodata faulted", false);
}

fn on_page_fault(frame: &idt::ExceptionFrame) -> ! {
    let mut t = TestRun::new();
    t.check("page fault", frame.vector == u64::from(idt::PAGE_FAULT));
    t.check(
        "CR2 is the rodata probe",
        idt::read_cr2() == paging::rodata_probe_addr(),
    );
    // Present (bit 0) and write (bit 1): a protection violation.
    t.check(
        "error code: protection violation, write",
        frame.error_code == 0b11,
    );
    t.finish()
}
