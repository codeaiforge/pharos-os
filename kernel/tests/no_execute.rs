//! Test kernel: executing writable kernel data faults under the kernel's own
//! page tables (D-005, issue #27). Runs under UEFI (D-009).

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
    paging::execute_data_probe();
    t.check("executing data faulted", false);
}

fn on_page_fault(frame: &idt::ExceptionFrame) -> ! {
    let mut t = TestRun::new();
    t.check("page fault", frame.vector == u64::from(idt::PAGE_FAULT));
    t.check(
        "CR2 is the data probe",
        idt::read_cr2() == paging::data_probe_addr(),
    );
    t.check(
        "RIP is the data probe",
        frame.rip == paging::data_probe_addr(),
    );
    // Present (bit 0) and instruction fetch (bit 4).
    t.check(
        "error code: protection violation, instruction fetch",
        frame.error_code == 0b1_0001,
    );
    t.finish()
}
