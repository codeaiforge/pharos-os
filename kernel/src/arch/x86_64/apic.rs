//! Local APIC (xAPIC mode) and its timer, the first hardware interrupt
//! source (decision D-006, issue #23).
//!
//! Limine leaves the local APIC enabled with every local interrupt masked,
//! and its higher-half direct map (HHDM) does not cover the APIC registers.
//! [`init`] maps the register page uncached at `HHDM + physical address` in
//! Limine's page tables, using page-table pages reserved in the kernel image
//! (no frame allocator; M2.5 takes the mapping over), then software-enables
//! the APIC with a spurious-interrupt vector. The legacy PICs stay masked.

// The interrupt handlers are reached only from the kernel-target entry stubs.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
const REG_TIMER_DIVIDE: u64 = 0x3e0;

const SVR_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// Divide configuration value for "divide by 16".
const DIVIDE_BY_16: u32 = 0b0011;

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const IA32_EFER: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;

// Page-table entry bits (Intel SDM vol. 3A, section 5.5).
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Why [`init`] failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ApicError {
    /// CPUID reports no local APIC.
    NoApic,
    /// The local APIC is disabled or in x2APIC mode; D-006 expects xAPIC.
    NotXapicMode,
    /// A large page already covers the register page's address.
    HugePageInTheWay,
    /// The reserved page-table pages are used up.
    OutOfTables,
    /// The address is already mapped to a different physical page.
    MappedElsewhere,
    /// A kernel address could not be translated to a physical one.
    NotMapped,
}

impl fmt::Display for ApicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoApic => "CPUID reports no local APIC",
            Self::NotXapicMode => "local APIC is disabled or in x2APIC mode (xAPIC expected)",
            Self::HugePageInTheWay => "a large page covers the APIC register address",
            Self::OutOfTables => "no reserved page-table pages left",
            Self::MappedElsewhere => "the APIC register address is mapped to another page",
            Self::NotMapped => "kernel address not mapped",
        })
    }
}

/// Indexes into the four page-table levels (PML4, PDPT, PD, PT) for `virt`.
pub const fn table_indexes(virt: u64) -> [usize; 4] {
    [
        ((virt >> 39) & 0x1ff) as usize,
        ((virt >> 30) & 0x1ff) as usize,
        ((virt >> 21) & 0x1ff) as usize,
        ((virt >> 12) & 0x1ff) as usize,
    ]
}

/// Leaf entry for an uncached, writable MMIO page.
pub const fn mmio_entry(phys: u64, no_execute: bool) -> u64 {
    let nx = if no_execute { NO_EXECUTE } else { 0 };
    (phys & ADDRESS_MASK) | PRESENT | WRITABLE | WRITE_THROUGH | CACHE_DISABLE | nx
}

/// Entry pointing at a lower-level table.
pub const fn table_entry(phys: u64) -> u64 {
    (phys & ADDRESS_MASK) | PRESENT | WRITABLE
}

#[repr(C, align(4096))]
struct PageTable([u64; 512]);

/// Number of reserved page-table pages: enough for a PDPT, PD, and PT.
const SPARE_TABLES: usize = 3;
static mut TABLES: [PageTable; SPARE_TABLES] = [const { PageTable([0; 512]) }; SPARE_TABLES];
static TABLES_USED: AtomicUsize = AtomicUsize::new(0);

/// Virtual address of the mapped register page; 0 until [`init`].
static BASE: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller reads an architectural MSR that exists on every
    // x86-64 CPU (IA32_APIC_BASE, IA32_EFER); reading has no side effects.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    u64::from(hi) << 32 | u64::from(lo)
}

fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    cr3
}

/// Pointer to entry `index` of the table at physical `table`, through the HHDM.
fn entry_ptr(hhdm: u64, table: u64, index: usize) -> *mut u64 {
    (hhdm + table + index as u64 * 8) as *mut u64
}

/// Translates a mapped virtual address to its physical address by walking
/// the active page tables.
fn translate(hhdm: u64, virt: u64) -> Result<u64, ApicError> {
    let mut table = read_cr3() & ADDRESS_MASK;
    for (level, &index) in table_indexes(virt).iter().enumerate() {
        // SAFETY: page tables live in memory the HHDM maps (Limine's tables
        // are bootloader-reclaimable, ours are in the kernel image); the
        // read has no side effects.
        let entry = unsafe { entry_ptr(hhdm, table, index).read_volatile() };
        if entry & PRESENT == 0 {
            return Err(ApicError::NotMapped);
        }
        // Large pages: 1 GiB at the PDPT level, 2 MiB at the PD level.
        if level != 0 && level != 3 && entry & HUGE != 0 {
            let page_bits = if level == 1 { 30 } else { 21 };
            let offset = virt & ((1 << page_bits) - 1);
            return Ok((entry & ADDRESS_MASK & !((1 << page_bits) - 1)) + offset);
        }
        table = entry & ADDRESS_MASK;
    }
    Ok(table + (virt & 0xfff))
}

/// Takes one reserved page-table page and returns its physical address.
fn take_table(hhdm: u64) -> Result<u64, ApicError> {
    let index = TABLES_USED.fetch_add(1, Ordering::Relaxed);
    if index >= SPARE_TABLES {
        return Err(ApicError::OutOfTables);
    }
    let virt = (&raw const TABLES) as u64 + (index * size_of::<PageTable>()) as u64;
    translate(hhdm, virt)
}

/// Maps the 4 KiB page `virt` to MMIO page `phys` in the active page tables.
fn map_mmio_page(hhdm: u64, virt: u64, phys: u64) -> Result<(), ApicError> {
    let no_execute = rdmsr(IA32_EFER) & EFER_NXE != 0;
    let indexes = table_indexes(virt);
    let mut table = read_cr3() & ADDRESS_MASK;
    for &index in &indexes[..3] {
        let entry = entry_ptr(hhdm, table, index);
        // SAFETY: as in `translate`, the table is HHDM-mapped. Interrupts
        // are off during `init` and there is one CPU, so nothing else walks
        // or changes these tables concurrently. A new entry points at a
        // zeroed reserved page, which marks every lower entry not present.
        unsafe {
            let value = entry.read_volatile();
            if value & PRESENT == 0 {
                let new = take_table(hhdm)?;
                // Reserved tables are zeroed statics; nothing else writes them.
                entry.write_volatile(table_entry(new));
                table = new;
            } else if value & HUGE != 0 {
                return Err(ApicError::HugePageInTheWay);
            } else {
                table = value & ADDRESS_MASK;
            }
        }
    }
    let leaf = entry_ptr(hhdm, table, indexes[3]);
    // SAFETY: as above. The leaf maps an MMIO page uncached; no Rust
    // reference to that address exists, and the old entry was not present
    // (or already this mapping), so `invlpg` only drops a negative entry.
    unsafe {
        let value = leaf.read_volatile();
        if value & PRESENT != 0 && value & ADDRESS_MASK != phys & ADDRESS_MASK {
            return Err(ApicError::MappedElsewhere);
        }
        leaf.write_volatile(mmio_entry(phys, no_execute));
        asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags));
    }
    Ok(())
}

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

/// Maps the local APIC registers and software-enables the APIC. `hhdm` is
/// the offset from Limine's HHDM response. Call once, with interrupts
/// disabled, after the IDT is loaded.
pub fn init(hhdm: u64) -> Result<(), ApicError> {
    if BASE.load(Ordering::Relaxed) != 0 {
        return Ok(());
    }
    if !super::cpu_has_apic() {
        return Err(ApicError::NoApic);
    }
    let apic_base = rdmsr(IA32_APIC_BASE);
    if apic_base & APIC_BASE_ENABLE == 0 || apic_base & APIC_BASE_X2APIC != 0 {
        return Err(ApicError::NotXapicMode);
    }
    let phys = apic_base & ADDRESS_MASK;
    let virt = hhdm + phys;
    map_mmio_page(hhdm, virt, phys)?;
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

/// Timer interrupt handler, called by the IDT dispatcher.
pub(super) fn on_timer() {
    TICKS.fetch_add(1, Ordering::Relaxed);
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
    fn indexes_of_hhdm_apic_address() {
        // HHDM at 0xffff_8000_0000_0000 plus the usual APIC base.
        assert_eq!(
            table_indexes(0xffff_8000_fee0_0000),
            [256, 3, 503, 0],
            "PML4 256, PDPT 3 (3-4 GiB), PD 503, PT 0"
        );
        assert_eq!(table_indexes(0xffff_ffff_8000_1000), [511, 510, 0, 1]);
    }

    #[test]
    fn mmio_entry_is_uncached_and_writable() {
        let e = mmio_entry(0xfee0_0000, true);
        assert_eq!(e & ADDRESS_MASK, 0xfee0_0000);
        assert_eq!(
            e & 0xfff,
            PRESENT | WRITABLE | WRITE_THROUGH | CACHE_DISABLE
        );
        assert_ne!(e & NO_EXECUTE, 0);
        assert_eq!(mmio_entry(0xfee0_0000, false) & NO_EXECUTE, 0);
        assert_eq!(e & HUGE, 0);
    }

    #[test]
    fn table_entry_points_at_the_table() {
        assert_eq!(table_entry(0x1234_5000), 0x1234_5000 | PRESENT | WRITABLE);
        assert_eq!(table_entry(0x1234_5fff) & ADDRESS_MASK, 0x1234_5000);
    }

    #[test]
    fn spurious_vector_low_bits_set() {
        assert_eq!(SPURIOUS_VECTOR & 0xf, 0xf);
        assert!(TIMER_VECTOR >= 32, "vectors below 32 are CPU exceptions");
    }
}
