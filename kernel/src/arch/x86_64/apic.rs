//! Local APIC (xAPIC mode) and its timer, the first hardware interrupt
//! source (decision D-006, issue #23).
//!
//! Limine leaves the local APIC enabled with every local interrupt masked.
//! [`init`] maps the register page uncached at `HHDM + physical address` in
//! the kernel address space (D-005; the kernel's direct map does not cover
//! it), then software-enables the APIC with a spurious-interrupt vector. The
//! legacy PICs stay masked.

// The interrupt handlers are reached only from the kernel-target entry stubs.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::fmt;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use super::paging::{self, Flags, MapError, PageSize};

/// Vector of the local APIC timer (the first vector after CPU exceptions).
pub const TIMER_VECTOR: u8 = 32;
/// Spurious-interrupt vector. Its low 4 bits must be 1s on older APICs.
pub const SPURIOUS_VECTOR: u8 = 0xff;

// Register offsets (Intel SDM vol. 3A, table 12-1).
const REG_ID: u64 = 0x20;
const REG_VERSION: u64 = 0x30;
const REG_TPR: u64 = 0x80;
const REG_EOI: u64 = 0xb0;
const REG_SVR: u64 = 0xf0;
const REG_LVT_TIMER: u64 = 0x320;
const REG_TIMER_INITIAL: u64 = 0x380;
const REG_TIMER_CURRENT: u64 = 0x390;
const REG_TIMER_DIVIDE: u64 = 0x3e0;

const SVR_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// Divide configuration value for "divide by 16".
const DIVIDE_BY_16: u32 = 0b0011;

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC: u64 = 1 << 10;
/// Physical address bits of `IA32_APIC_BASE`.
const APIC_BASE_ADDRESS: u64 = 0x000f_ffff_ffff_f000;
/// Why [`init`] failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ApicError {
    /// CPUID reports no local APIC.
    NoApic,
    /// The local APIC is disabled or in x2APIC mode; D-006 expects xAPIC.
    NotXapicMode,
    /// The frame allocator is not set up yet.
    NoFrameAllocator,
    /// Mapping the register page failed.
    Map(MapError),
}

impl fmt::Display for ApicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoApic => f.write_str("CPUID reports no local APIC"),
            Self::NotXapicMode => {
                f.write_str("local APIC is disabled or in x2APIC mode (xAPIC expected)")
            }
            Self::NoFrameAllocator => f.write_str("frame allocator not set up"),
            Self::Map(error) => write!(f, "cannot map the APIC registers: {error}"),
        }
    }
}

/// Virtual address of the mapped register page; 0 until [`init`].
static BASE: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

fn read(offset: u64) -> u32 {
    let base = BASE.load(Ordering::Relaxed);
    debug_assert!(base != 0, "local APIC used before init");
    // SAFETY: after `init`, `base` is the uncached mapping of the local APIC
    // register page and `offset` is one of the register offsets above.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write(offset: u64, value: u32) {
    let base = BASE.load(Ordering::Relaxed);
    debug_assert!(base != 0, "local APIC used before init");
    // SAFETY: as in `read`; writing an APIC register touches no memory.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) };
}

/// Maps the local APIC registers into the kernel address space and
/// software-enables the APIC. `hhdm` is the direct-map offset. Call once,
/// with interrupts disabled, after the IDT and the kernel address space
/// (`mm::init_paging`).
pub fn init(hhdm: u64) -> Result<(), ApicError> {
    if BASE.load(Ordering::Relaxed) != 0 {
        return Ok(());
    }
    if !super::cpu_has_apic() {
        return Err(ApicError::NoApic);
    }
    let apic_base = super::rdmsr(IA32_APIC_BASE);
    if apic_base & APIC_BASE_ENABLE == 0 || apic_base & APIC_BASE_X2APIC != 0 {
        return Err(ApicError::NotXapicMode);
    }
    let phys = apic_base & APIC_BASE_ADDRESS;
    let virt = hhdm + phys;
    {
        let mut frames = crate::mm::frames();
        let frames = frames.as_mut().ok_or(ApicError::NoFrameAllocator)?;
        paging::map_kernel_page(virt, phys, PageSize::Size4K, Flags::MMIO, frames)
            .map_err(ApicError::Map)?;
    }
    BASE.store(virt, Ordering::Relaxed);
    write(REG_TPR, 0); // accept all priorities
    write(REG_SVR, SVR_ENABLE | u32::from(SPURIOUS_VECTOR));
    Ok(())
}

/// Local APIC ID of this CPU.
pub fn id() -> u32 {
    read(REG_ID) >> 24
}

/// Local APIC version register (version in bits 0–7).
pub fn version() -> u32 {
    read(REG_VERSION)
}

/// Starts the timer: one interrupt on [`TIMER_VECTOR`] every `count` ticks
/// of the APIC timer clock divided by 16.
pub fn start_timer(count: u32) {
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, u32::from(TIMER_VECTOR) | LVT_TIMER_PERIODIC);
    write(REG_TIMER_INITIAL, count);
}

/// Measures how far the APIC timer (divided by 16) and the TSC advance
/// while PIT channel 2 counts `pit_ticks` periods (D-006 timer part). Both
/// counters start just before the PIT, so a delay can only make the result
/// larger, never smaller. Call with interrupts disabled; leaves the timer
/// stopped and masked.
pub fn measure_against_pit(pit_ticks: u16) -> (u32, u64) {
    let pit_ticks = pit_ticks.max(1);
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, LVT_MASKED); // one-shot, no interrupt
    super::pit_arm(pit_ticks);
    write(REG_TIMER_INITIAL, u32::MAX);
    let tsc_start = super::rdtsc();
    super::pit_start(pit_ticks);
    super::pit_wait_done();
    let tsc = super::rdtsc() - tsc_start;
    let apic = u32::MAX - read(REG_TIMER_CURRENT);
    write(REG_TIMER_INITIAL, 0);
    (apic, tsc)
}

/// Stops the timer and masks its interrupt.
pub fn stop_timer() {
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_TIMER_INITIAL, 0);
}

/// Timer interrupts handled so far.
pub fn timer_ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Spurious interrupts seen so far.
pub fn spurious_count() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

/// Function called on every timer interrupt after EOI; null if none.
static TICK_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Calls `handler` on every timer interrupt, after EOI, with interrupts
/// disabled, on the interrupted code's stack, telling it whether user mode
/// was interrupted. The scheduler uses it to preempt tasks (D-013); it may
/// switch stacks and return much later.
pub fn set_tick_handler(handler: fn(bool)) {
    TICK_HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Timer interrupt handler, called by the IDT dispatcher.
pub(super) fn on_timer(from_user: bool) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    // EOI first: the handler may switch to another task, which must be able
    // to receive the next tick.
    write(REG_EOI, 0);
    let handler = TICK_HANDLER.load(Ordering::Acquire);
    if !handler.is_null() {
        // SAFETY: the only non-null values stored in `TICK_HANDLER` come
        // from `set_tick_handler`, which stores a `fn(bool)`. Function and
        // data pointers have the same size on x86-64.
        let handler = unsafe { core::mem::transmute::<*mut (), fn(bool)>(handler) };
        handler(from_user);
    }
}

/// Signals the end of a device interrupt (vectors 48–63, `irq.rs`).
pub fn eoi() {
    write(REG_EOI, 0);
}

/// Spurious-interrupt handler. The APIC expects no EOI for these.
pub(super) fn on_spurious() {
    SPURIOUS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spurious_vector_low_bits_set() {
        assert_eq!(SPURIOUS_VECTOR & 0xf, 0xf);
        assert!(TIMER_VECTOR >= 32, "vectors below 32 are CPU exceptions");
    }
}
