//! Test kernel: printing and `without_interrupts` restore the previous
//! interrupt state (issue #19). Runs under UEFI (D-009).
//!
//! Interrupts are enabled briefly with no IDT loaded. That is safe here
//! because every maskable source is masked as Limine leaves it (legacy PICs,
//! I/O APIC entries, local APIC LVT entries), so nothing is delivered.

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{
    disable_interrupts, enable_interrupts, interrupts_enabled, without_interrupts,
};
use pharos_kernel::kprintln;
use pharos_kernel::testing::TestRun;

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    t.check("interrupts disabled at entry", !interrupts_enabled());

    kprintln!("printing with interrupts disabled");
    t.check("printing keeps interrupts disabled", !interrupts_enabled());

    t.check(
        "without_interrupts runs with interrupts disabled",
        without_interrupts(|| !interrupts_enabled()),
    );
    t.check(
        "without_interrupts keeps disabled state",
        !interrupts_enabled(),
    );

    enable_interrupts();
    let enabled = interrupts_enabled();
    kprintln!("printing with interrupts enabled");
    let after_print = interrupts_enabled();
    let inside = without_interrupts(|| without_interrupts(|| !interrupts_enabled()));
    let after_nested = interrupts_enabled();
    disable_interrupts();

    t.check("enable_interrupts sets IF", enabled);
    t.check("printing keeps interrupts enabled", after_print);
    t.check("nested without_interrupts disables inside", inside);
    t.check("nested without_interrupts restores enabled", after_nested);
    t.check("disable_interrupts clears IF", !interrupts_enabled());
}
