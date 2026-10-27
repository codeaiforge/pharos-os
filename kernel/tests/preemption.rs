//! Test kernel: preemptive scheduling on the timer tick, the idle task,
//! and sleeping (D-013, issue #34). Runs under UEFI (D-009). Timing bounds
//! are wide on purpose (QEMU under TCG on a loaded runner).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::mm::{self, raw::IrqMutex};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, sched, time};

pharos_kernel::test_kernel!(run);

/// Sleepers' markers in the order they woke.
static LOG: IrqMutex<Vec<u8>> = IrqMutex::new(Vec::new());
static SLEPT_ENOUGH: AtomicBool = AtomicBool::new(true);
/// Loop counts of the task that never yields and of the two workers.
static SPINS: AtomicU64 = AtomicU64::new(0);
static WORK: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// Largest number of ticks a worker saw pass between two of its turns.
static MAX_GAP: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Largest tick gap a worker may see: three busy tasks plus task 0, with
/// room for ticks delayed by a loaded host.
const GAP_BOUND: u64 = 10;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn sleeper(marker: u8, millis: u64) {
    let before = time::uptime();
    sched::sleep(ms(millis));
    if time::uptime() - before < ms(millis) {
        SLEPT_ENOUGH.store(false, Ordering::Relaxed);
    }
    LOG.lock().push(marker);
}

/// Counts forever without yielding, noting how many ticks pass between turns.
fn worker(i: usize) {
    let mut last = apic::timer_ticks();
    loop {
        WORK[i].fetch_add(1, Ordering::Relaxed);
        let now = apic::timer_ticks();
        if now != last {
            MAX_GAP[i].fetch_max(now - last, Ordering::Relaxed);
            last = now;
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
    let ready = memory
        && mm::init_heap().is_ok()
        && requests::HHDM
            .response()
            .is_some_and(|hhdm| apic::init(hhdm.offset).is_ok())
        && time::init().is_ok()
        && sched::init().is_ok();
    t.check("memory, heap, APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    t.check("preemption enabled", sched::enable_preemption().is_ok());

    // Sleepers wake in deadline order, not spawn order; the trace shows the
    // switches over serial.
    sched::set_trace(true);
    let spawned = [(b'a', 50), (b'b', 10), (b'c', 30)]
        .into_iter()
        .all(|(marker, millis)| sched::spawn(move || sleeper(marker, millis)).is_ok());
    let before = time::uptime();
    sched::sleep(ms(100));
    let slept = time::uptime() - before;
    sched::set_trace(false);
    t.check("three sleepers spawned", spawned);
    t.check(
        "sleepers woke in deadline order (10, 30, 50 ms): bca",
        LOG.lock().as_slice() == b"bca",
    );
    t.check(
        "every sleep lasted at least as long as asked",
        SLEPT_ENOUGH.load(Ordering::Relaxed) && slept >= ms(100),
    );
    t.check("sleepers exited", sched::live_tasks() == 1);

    // A task that never yields cannot starve the others.
    let spawned = sched::spawn(|| {
        loop {
            SPINS.fetch_add(1, Ordering::Relaxed);
        }
    })
    .is_ok()
        && sched::spawn(|| worker(0)).is_ok()
        && sched::spawn(|| worker(1)).is_ok();
    t.check("spinning task and two workers spawned", spawned);
    let before = time::uptime();
    sched::sleep(ms(300));
    let slept = time::uptime() - before;
    kprintln!(
        "task 0 slept {} ms among three busy tasks",
        slept.as_millis()
    );
    t.check(
        "task 0 woke from a 300 ms sleep within 2 s despite busy tasks",
        slept >= ms(300) && slept < ms(2_000),
    );
    let first = [
        SPINS.load(Ordering::Relaxed),
        WORK[0].load(Ordering::Relaxed),
        WORK[1].load(Ordering::Relaxed),
    ];
    t.check("every busy task ran", first.iter().all(|&n| n > 0));
    sched::sleep(ms(200));
    let second = [
        SPINS.load(Ordering::Relaxed),
        WORK[0].load(Ordering::Relaxed),
        WORK[1].load(Ordering::Relaxed),
    ];
    t.check(
        "every busy task kept making progress",
        first.iter().zip(&second).all(|(a, b)| b > a),
    );
    let gaps = [
        MAX_GAP[0].load(Ordering::Relaxed),
        MAX_GAP[1].load(Ordering::Relaxed),
    ];
    kprintln!("largest tick gaps between worker turns: {gaps:?}");
    t.check(
        "workers were preempted and resumed within 10 ticks",
        gaps.iter().all(|&g| g > 0 && g <= GAP_BOUND),
    );
    t.check("the scheduler counted ticks", sched::ticks() >= 50);
}
