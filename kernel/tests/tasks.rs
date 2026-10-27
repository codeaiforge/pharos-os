//! Test kernel: kernel tasks with their own stacks and cooperative
//! switching (D-013, issue #33). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use pharos_kernel::arch::x86_64::context::{
    MAX_STACKS, SLOT_SIZE, STACK_WINDOW, call_preserves_callee_saved,
};
use pharos_kernel::arch::x86_64::{gdt, idt, interrupts_enabled, stack_pointer};
use pharos_kernel::mm::{self, raw::IrqMutex};
use pharos_kernel::sched;
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

/// Markers written by the tasks, in the order they ran.
static LOG: IrqMutex<Vec<u8>> = IrqMutex::new(Vec::new());
static ON_OWN_STACK: AtomicBool = AtomicBool::new(true);
static INTERRUPTS_ON: AtomicBool = AtomicBool::new(true);
/// Bit `id` set when task `id` saw itself as the current task.
static IDS_SEEN: AtomicU64 = AtomicU64::new(0);
static LATE_TASK_VALUE: AtomicU64 = AtomicU64::new(0);
/// Held across a yield by the last check.
static SOME_LOCK: IrqMutex<()> = IrqMutex::new(());
static REGISTERS_KEPT: AtomicBool = AtomicBool::new(true);

const ROUNDS: usize = 3;

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Body of the three interleaved tasks.
fn worker(marker: u8) {
    let sp = stack_pointer();
    let window_end = STACK_WINDOW + MAX_STACKS * SLOT_SIZE;
    if !(STACK_WINDOW..window_end).contains(&sp) {
        ON_OWN_STACK.store(false, Ordering::Relaxed);
    }
    if !interrupts_enabled() {
        INTERRUPTS_ON.store(false, Ordering::Relaxed);
    }
    if let Some(id) = sched::current_id() {
        IDS_SEEN.fetch_or(1 << id, Ordering::Relaxed);
    }
    for _ in 0..ROUNDS {
        LOG.lock().push(marker);
        sched::yield_now();
    }
}

extern "C" fn yield_c() {
    sched::yield_now();
}

/// Yields a few times with known values in the callee-saved registers.
fn register_worker() {
    for _ in 0..ROUNDS {
        if !call_preserves_callee_saved(yield_c) {
            REGISTERS_KEPT.store(false, Ordering::Relaxed);
        }
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
    let heap = memory && mm::init_heap().is_ok();
    t.check("memory management and heap set up", heap);
    if !heap {
        return;
    }

    t.check("scheduler initialized", sched::init().is_ok());
    t.check(
        "second init rejected",
        sched::init() == Err(sched::SchedError::AlreadyInitialized),
    );
    t.check("boot thread is task 0", sched::current_id() == Some(0));
    sched::yield_now();
    t.check(
        "yield with nothing ready returns",
        sched::current_id() == Some(0),
    );

    let ids: Vec<_> = b"abc"
        .iter()
        .map(|&marker| sched::spawn(move || worker(marker)))
        .collect();
    t.check(
        "three tasks spawned with IDs 1, 2, 3",
        ids == [Ok(1), Ok(2), Ok(3)],
    );
    t.check("four live tasks", sched::live_tasks() == 4);
    let after_spawn = free_frames();

    let mut yields = 0;
    while sched::live_tasks() > 1 && yields < 100 {
        sched::yield_now();
        yields += 1;
    }
    t.check("all tasks finished", sched::live_tasks() == 1);
    t.check(
        "tasks interleaved round-robin: abcabcabc",
        LOG.lock().as_slice() == b"abcabcabc",
    );
    t.check(
        "every task ran on its own stack in the stack window",
        ON_OWN_STACK.load(Ordering::Relaxed),
    );
    t.check(
        "tasks start with interrupts enabled",
        INTERRUPTS_ON.load(Ordering::Relaxed),
    );
    t.check(
        "each task saw its own ID",
        IDS_SEEN.load(Ordering::Relaxed) == 0b1110,
    );
    t.check("back on task 0", sched::current_id() == Some(0));

    // The last exited task is reaped by the next scheduling call.
    sched::yield_now();
    t.check(
        "exited tasks returned their 12 stack frames",
        free_frames() == after_spawn + 12,
    );

    // Callee-saved registers survive switches, in tasks and in task 0.
    let spawned = (0..2).all(|_| sched::spawn(register_worker).is_ok());
    let mut main_kept = true;
    let mut yields = 0;
    while sched::live_tasks() > 1 && yields < 100 {
        main_kept &= call_preserves_callee_saved(yield_c);
        yields += 1;
    }
    t.check(
        "callee-saved registers survive task switches",
        spawned && main_kept && REGISTERS_KEPT.load(Ordering::Relaxed),
    );

    let captured = 0x5eed_u64;
    let late = sched::spawn(move || LATE_TASK_VALUE.store(captured, Ordering::Relaxed));
    t.check(
        "a task spawned after others exited gets ID 6",
        late == Ok(6),
    );
    sched::yield_now();
    t.check(
        "it ran its closure with the captured value",
        LATE_TASK_VALUE.load(Ordering::Relaxed) == captured,
    );

    // Must be last: yielding with a lock held panics; the hook finishes.
    testing::set_panic_hook(on_panic);
    let _guard = SOME_LOCK.lock();
    sched::yield_now();
    t.check("yield while holding a lock was refused", false);
}

fn on_panic(info: &PanicInfo<'_>) -> ! {
    let message = alloc::format!("{}", info.message());
    let mut t = TestRun::new();
    t.check(
        "yield while holding an IrqMutex panics (D-013)",
        message.contains("holding an IrqMutex"),
    );
    t.finish()
}
