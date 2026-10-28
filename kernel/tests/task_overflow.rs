//! Test kernel: a task's stack overflow hits its guard area and is
//! reported as a double fault (D-013, issue #33). Runs under UEFI (D-009).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use pharos_kernel::arch::x86_64::context::{SLOT_SIZE, STACK_SIZE, STACK_WINDOW};
use pharos_kernel::arch::x86_64::{gdt, idt, stack_pointer};
use pharos_kernel::mm;
use pharos_kernel::sched;
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

/// Stack pointer seen at the start of the task; 0 if it never ran.
static TASK_SP: AtomicU64 = AtomicU64::new(0);

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
    t.check(
        "task spawned",
        sched::spawn(|| {
            TASK_SP.store(stack_pointer(), Ordering::Relaxed);
            overflow(0);
        })
        .is_ok(),
    );
    // Must be last: the double fault does not return; the hook finishes.
    idt::set_fatal_hook(on_double_fault);
    sched::yield_now();
    t.check("task stack overflow detected", false);
}

/// Recurses until the stack runs into the guard area.
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
    let task_sp = TASK_SP.load(Ordering::Relaxed);
    t.check(
        "the overflowing code was the task, in the stack window",
        task_sp > STACK_WINDOW && task_sp < STACK_WINDOW + SLOT_SIZE,
    );
    // Slot 0: the stack is [WINDOW + SLOT_SIZE - STACK_SIZE, WINDOW + SLOT_SIZE).
    let bottom = STACK_WINDOW + SLOT_SIZE - STACK_SIZE;
    t.check(
        "faulting RSP is at the bottom of the task stack",
        frame.rsp >= bottom - 4096 && frame.rsp < bottom + 4096,
    );
    t.finish()
}
