//! Test kernel: scheduling classes and CPU time (D-022, issue #114). A
//! trusted task's sleeps end on time among spinning agent-class tasks; a
//! spinning services-class task holds agents off the CPU; a wake-up of a
//! higher class runs at once; CPU time grows only while a task runs. Runs
//! under UEFI (D-009). Timing bounds are wide on purpose (QEMU under TCG on
//! a loaded runner); with one queue for all, a sleep could wait up to 20
//! slices.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt, without_interrupts};
use pharos_kernel::mm;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, sched, time};

pharos_kernel::test_kernel!(run);

const SPINNERS: usize = 20;
/// Most a trusted task's 20 ms sleep may end late: the sleep's own extra
/// tick, one slice, and a delayed tick. Round robin among the spinners
/// would be about 200 ms.
const LATE_BOUND: Duration = Duration::from_millis(40);

static AGENT_WORK: [AtomicU64; SPINNERS] = [const { AtomicU64::new(0) }; SPINNERS];
static SERVICE_SPINS: AtomicBool = AtomicBool::new(false);
static SERVICE_WORK: AtomicU64 = AtomicU64::new(0);
/// The trusted waiter's ID, once it is about to block.
static WAITER: AtomicU64 = AtomicU64::new(u64::MAX);
static WAITER_RAN: AtomicBool = AtomicBool::new(false);
/// What the agent saw right after waking the waiter and calling `preempt`.
static RAN_AT_ONCE: AtomicBool = AtomicBool::new(false);
static WOKEN: AtomicBool = AtomicBool::new(false);

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

static AGENTS_STOP: AtomicBool = AtomicBool::new(false);

fn agent_spinner(i: usize) {
    while !AGENTS_STOP.load(Ordering::Relaxed) {
        AGENT_WORK[i].fetch_add(1, Ordering::Relaxed);
    }
}

fn agent_work() -> u64 {
    AGENT_WORK.iter().map(|w| w.load(Ordering::Relaxed)).sum()
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

    // Agents spinning: the trusted task 0 still wakes on time.
    let spawned =
        (0..SPINNERS).all(|i| sched::spawn_class(sched::AGENTS, move || agent_spinner(i)).is_ok());
    t.check("20 spinning agent-class tasks spawned", spawned);
    let mut late = Duration::ZERO;
    for _ in 0..20 {
        let before = time::uptime();
        sched::sleep(ms(20));
        late = late.max(time::uptime() - before - ms(20));
    }
    kprintln!(
        "latest 20 ms sleep among {SPINNERS} spinners: {} us late",
        late.as_micros()
    );
    t.check(
        "a trusted task's 20 ms sleeps end at most 40 ms late among 20 spinning agents",
        late <= LATE_BOUND,
    );
    t.check("the agents ran while it slept", agent_work() > 0);

    // A spinning service holds every agent off the CPU.
    let spinner = sched::spawn_class(sched::SERVICES, || {
        SERVICE_SPINS.store(true, Ordering::Relaxed);
        while SERVICE_SPINS.load(Ordering::Relaxed) {
            SERVICE_WORK.fetch_add(1, Ordering::Relaxed);
        }
    });
    t.check("a spinning services-class task spawned", spinner.is_ok());
    sched::sleep(ms(30));
    let agent_cpu = |ids: &[u64]| {
        ids.iter()
            .filter_map(|&id| sched::cpu_cycles(id))
            .sum::<u64>()
    };
    // Agent tasks are 2..=21 (task 1 is the idle task).
    let agent_ids: alloc::vec::Vec<u64> = (2..2 + SPINNERS as u64).collect();
    let (work, cpu, service) = (
        agent_work(),
        agent_cpu(&agent_ids),
        SERVICE_WORK.load(Ordering::Relaxed),
    );
    sched::sleep(ms(200));
    let held = agent_work() == work && agent_cpu(&agent_ids) == cpu;
    let service_ran = SERVICE_WORK.load(Ordering::Relaxed) > service;
    t.check("the service ran while task 0 slept", service_ran);
    t.check(
        "no agent ran, or was charged CPU time, while the service spun",
        held,
    );
    let service_cpu = spinner.ok().and_then(sched::cpu_cycles).unwrap_or(0);
    t.check(
        "the spinning service was charged at least 150 ms of CPU",
        time::cycles_to_micros(service_cpu) >= 150_000,
    );
    SERVICE_SPINS.store(false, Ordering::Relaxed);
    sched::sleep(ms(50));
    t.check("the agents run again once it stops", agent_work() > work);
    AGENTS_STOP.store(true, Ordering::Relaxed);
    sched::sleep(ms(300));

    // A wake-up of a higher class runs at once, not at the next tick.
    let waiter = sched::spawn(|| {
        without_interrupts(|| {
            WAITER.store(sched::current_id().unwrap_or(u64::MAX), Ordering::Relaxed);
            sched::block_current();
        });
        WAITER_RAN.store(true, Ordering::Relaxed);
    });
    let waker = sched::spawn_class(sched::AGENTS, || {
        while WAITER.load(Ordering::Relaxed) == u64::MAX {
            core::hint::spin_loop();
        }
        // Interrupts off: no tick can make the switch instead of `preempt`.
        without_interrupts(|| {
            WOKEN.store(
                sched::wake(WAITER.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
            sched::preempt();
            RAN_AT_ONCE.store(WAITER_RAN.load(Ordering::Relaxed), Ordering::Relaxed);
        });
    });
    t.check(
        "a trusted waiter and an agent-class waker spawned",
        waiter.is_ok() && waker.is_ok(),
    );
    sched::sleep(ms(100));
    t.check(
        "the agent woke the blocked trusted task",
        WOKEN.load(Ordering::Relaxed),
    );
    t.check(
        "the woken trusted task ran before the agent's next instruction",
        RAN_AT_ONCE.load(Ordering::Relaxed),
    );

    // CPU time grows only while a task runs.
    let sleeper = sched::spawn(|| sched::sleep(Duration::from_secs(60))).ok();
    sched::sleep(ms(20));
    let before = sleeper.and_then(sched::cpu_cycles);
    sched::sleep(ms(200));
    let after = sleeper.and_then(sched::cpu_cycles);
    t.check(
        "a sleeping task's CPU time stays under 1 ms over 200 ms",
        before
            .zip(after)
            .is_some_and(|(b, a)| time::cycles_to_micros(a - b) < 1_000),
    );
    // The running task's own count includes its current turn: 5 ms busy
    // with interrupts off, so no switch happens in between.
    let (first, second) = without_interrupts(|| {
        let me = sched::current_id().unwrap_or(u64::MAX);
        let first = sched::cpu_cycles(me);
        time::delay(ms(5));
        (first, sched::cpu_cycles(me))
    });
    t.check(
        "task 0's CPU time grows by at least 4 ms during 5 ms of its own turn",
        first
            .zip(second)
            .is_some_and(|(a, b)| time::cycles_to_micros(b - a) >= 4_000),
    );
}
