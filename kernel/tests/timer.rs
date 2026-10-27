//! Test kernel: timer calibration and the kernel clock (D-006 timer part,
//! issue #32). Timing bounds are wide on purpose: QEMU under TCG runs on
//! the host clock, and a loaded CI runner delays the emulated CPU.

#![no_std]
#![no_main]

use core::time::Duration;

use pharos_kernel::arch::x86_64::{
    PIT_HZ, apic, disable_interrupts, enable_interrupts, gdt, idt, pit_wait, wait_for_interrupt,
};
use pharos_kernel::kprintln;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::time::{self, TICK_HZ};

pharos_kernel::test_kernel!(run);

const MS: Duration = Duration::from_millis(1);
/// Ticks the tick-rate check waits for.
const TICKS: u64 = 20;

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    t.check("frame allocator and kernel page tables set up", memory);
    let Some(hhdm) = requests::HHDM.response() else {
        t.check("HHDM response present", false);
        return;
    };
    let apic_ok = memory && apic::init(hhdm.offset).is_ok();
    t.check("local APIC mapped and enabled", apic_ok);
    if !apic_ok {
        return;
    }

    t.check(
        "uptime is zero before calibration",
        time::uptime() == Duration::ZERO,
    );
    let calibration = time::init();
    if let Err(error) = &calibration {
        kprintln!("time::init failed: {error}");
    }
    t.check("calibration accepted", calibration.is_ok());
    let Ok(c) = calibration else { return };
    kprintln!(
        "calibrated: APIC {} ticks/ms, TSC {} cycles/ms, tick count {}",
        c.apic_per_ms,
        c.tsc_per_ms,
        c.tick_count()
    );
    t.check(
        "tick period is 10 ms of APIC timer counts",
        u64::from(c.tick_count()) == u64::from(c.apic_per_ms) * 1_000 / u64::from(TICK_HZ),
    );

    // The TSC clock against the PIT, which calibration does not change.
    let before = time::uptime();
    pit_wait((PIT_HZ * 50 / 1_000) as u16);
    let pit_50ms = time::uptime() - before;
    kprintln!(
        "50 ms by the PIT = {} us by the TSC clock",
        pit_50ms.as_micros()
    );
    t.check(
        "50 ms by the PIT reads 45 ms to 500 ms on the clock",
        pit_50ms >= 45 * MS && pit_50ms < 500 * MS,
    );

    let before = time::uptime();
    time::delay(100 * MS);
    let delayed = time::uptime() - before;
    t.check(
        "delay(100 ms) lasts at least 100 ms and under 1 s",
        delayed >= 100 * MS && delayed < 1_000 * MS,
    );

    let mut last = time::uptime();
    let mut monotonic = true;
    for _ in 0..10_000 {
        let now = time::uptime();
        monotonic &= now >= last;
        last = now;
    }
    t.check("uptime never goes backwards", monotonic);

    // The periodic tick: a tick period is never shorter than 10 ms, because
    // calibration can only overestimate the APIC rate.
    let start_ticks = apic::timer_ticks();
    let before = time::uptime();
    time::start_tick();
    enable_interrupts();
    while apic::timer_ticks() - start_ticks < TICKS {
        wait_for_interrupt();
    }
    disable_interrupts();
    apic::stop_timer();
    let elapsed = time::uptime() - before;
    kprintln!("{TICKS} ticks took {} ms", elapsed.as_millis());
    t.check(
        "20 ticks take 190 ms to 2 s",
        elapsed >= 190 * MS && elapsed < 2_000 * MS,
    );
}
