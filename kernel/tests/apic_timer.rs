//! Test kernel: the local APIC timer delivers interrupts (D-006, issue #23).
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{
    apic, disable_interrupts, enable_interrupts, gdt, idt, wait_for_interrupt,
};
use pharos_kernel::kprintln;
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

/// Timer interrupts the test waits for.
const TICKS: u64 = 20;
/// Upper bound on wake-ups, so a flood of other interrupts cannot spin forever.
const MAX_WAKEUPS: u64 = 10_000;

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
    let Some(hhdm) = requests::HHDM.response() else {
        t.check("HHDM response present", false);
        return;
    };
    let init = apic::init(hhdm.offset);
    if let Err(error) = &init {
        kprintln!("apic::init failed: {error}");
    }
    t.check("local APIC mapped and enabled", init.is_ok());
    if init.is_err() {
        return;
    }
    let version = apic::version() & 0xff;
    t.check(
        "APIC version register plausible (integrated APIC)",
        (0x10..=0x15).contains(&version),
    );
    t.check("no timer interrupts before start", apic::timer_ticks() == 0);

    apic::start_timer(100_000);
    enable_interrupts();
    let mut wakeups = 0;
    while apic::timer_ticks() < TICKS && wakeups < MAX_WAKEUPS {
        wait_for_interrupt();
        wakeups += 1;
    }
    disable_interrupts();
    apic::stop_timer();
    let ticks = apic::timer_ticks();
    kprintln!(
        "timer: {ticks} interrupts, {wakeups} wake-ups, {} spurious",
        apic::spurious_count()
    );
    t.check("at least 20 timer interrupts handled", ticks >= TICKS);
    t.check(
        "every wake-up was a timer or spurious interrupt",
        wakeups == ticks + apic::spurious_count(),
    );
}
