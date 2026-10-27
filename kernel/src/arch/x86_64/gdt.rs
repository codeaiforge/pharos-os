//! The kernel's own GDT and TSS (issue #20).
//!
//! Limine's GDT lives in bootloader-reclaimable memory, which M2.5 will reuse,
//! and Limine loads no TSS. [`init`] loads a static GDT (null, kernel code,
//! kernel data, TSS) and a static TSS whose interrupt stack table (IST) gives
//! the double-fault handler its own stack.
//!
//! Descriptor layout: Intel SDM vol. 3A, sections 3.4.5 (segment descriptors)
//! and 8.2.3 (64-bit TSS descriptor). User segments come with M2.7.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

/// Kernel code segment selector (GDT index 1, ring 0).
pub const KERNEL_CODE: u16 = 0x08;
/// Kernel data segment selector (GDT index 2, ring 0).
pub const KERNEL_DATA: u16 = 0x10;
/// TSS selector (GDT index 3; the descriptor takes indexes 3 and 4).
pub const TSS: u16 = 0x18;

/// IST slot (1-based, as IDT gates name it) of the double-fault stack.
pub const DOUBLE_FAULT_IST: u8 = 1;
/// Size of the double-fault stack.
pub const DOUBLE_FAULT_STACK_SIZE: usize = 16 * 1024;

/// Access byte: present, ring 0, code, executable, readable.
const ACCESS_CODE: u8 = 0x9a;
/// Access byte: present, ring 0, data, writable.
const ACCESS_DATA: u8 = 0x92;
/// Access byte: present, ring 0, available 64-bit TSS.
const ACCESS_TSS: u8 = 0x89;
/// Flags nibble: 4 KiB granularity, 64-bit code (L).
const FLAGS_CODE64: u8 = 0xa;
/// Flags nibble: 4 KiB granularity, 32-bit default size (ignored in 64-bit mode).
const FLAGS_DATA: u8 = 0xc;

/// Encodes an 8-byte segment descriptor.
pub const fn descriptor(base: u32, limit: u32, access: u8, flags: u8) -> u64 {
    (limit as u64 & 0xffff)
        | (base as u64 & 0xff_ffff) << 16
        | (access as u64) << 40
        | ((limit as u64 >> 16) & 0xf) << 48
        | (flags as u64 & 0xf) << 52
        | (base as u64 >> 24) << 56
}

/// Encodes the 16-byte TSS descriptor for a TSS at `base`.
pub const fn tss_descriptor(base: u64) -> [u64; 2] {
    let limit = (size_of::<Tss>() - 1) as u32;
    [descriptor(base as u32, limit, ACCESS_TSS, 0), base >> 32]
}

/// 64-bit task-state segment (Intel SDM vol. 3A, figure 8-11).
#[repr(C, packed(4))]
pub struct Tss {
    reserved0: u32,
    /// Stack pointers for privilege changes to rings 0–2 (used from M2.7).
    rsp: [u64; 3],
    reserved1: u64,
    /// Interrupt stack table, IST1–IST7.
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            // No I/O permission bitmap: the base points past the TSS limit.
            iomap_base: size_of::<Tss>() as u16,
        }
    }
}

#[repr(C, align(4096))]
struct Stack([u8; DOUBLE_FAULT_STACK_SIZE]);

/// `linker.ld` places this in its own segment after an unmapped guard page,
/// like the kernel stack.
// SAFETY: `.double_fault_stack` is a NOLOAD section in `linker.ld` reserved
// for this one static; placing it there has no other effect.
#[unsafe(link_section = ".double_fault_stack")]
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; DOUBLE_FAULT_STACK_SIZE]);
static mut TSS_SEGMENT: Tss = Tss::new();
static mut GDT: [u64; 5] = [0; 5];
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Operand of `lgdt`/`sgdt`.
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

/// Loads the kernel's GDT and TSS and reloads all segment registers. Call
/// once, early, with interrupts disabled; later calls do nothing.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    let stack_top = (&raw const DOUBLE_FAULT_STACK) as u64 + DOUBLE_FAULT_STACK_SIZE as u64;
    let tss = &raw mut TSS_SEGMENT;
    let gdt = &raw mut GDT;
    let [tss_low, tss_high] = tss_descriptor(tss as u64);
    // SAFETY: `INITIALIZED` makes this the only access to the TSS and GDT
    // statics, which nothing else references until they are loaded below.
    // Unaligned field writes go through `write_unaligned` (the TSS is packed).
    unsafe {
        (&raw mut (*tss).ist[(DOUBLE_FAULT_IST - 1) as usize]).write_unaligned(stack_top);
        *gdt = [
            0,
            descriptor(0, 0xf_ffff, ACCESS_CODE, FLAGS_CODE64),
            descriptor(0, 0xf_ffff, ACCESS_DATA, FLAGS_DATA),
            tss_low,
            tss_high,
        ];
    }
    let pointer = DescriptorTablePointer {
        limit: (size_of::<[u64; 5]>() - 1) as u16,
        base: gdt as u64,
    };
    // SAFETY: the GDT is static, so it outlives its use by the CPU, and holds
    // valid descriptors for every selector loaded here. CS is reloaded with a
    // far return to the next instruction; the data registers get the flat
    // kernel data segment (all bases 0, as Limine left them). `ltr` marks the
    // TSS descriptor busy, which is why `init` runs only once.
    unsafe {
        asm!(
            "lgdt [{ptr}]",
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov fs, {data:x}",
            "mov gs, {data:x}",
            "mov ss, {data:x}",
            "ltr {tss:x}",
            ptr = in(reg) &pointer,
            code = in(reg) u64::from(KERNEL_CODE),
            data = in(reg) KERNEL_DATA,
            tss = in(reg) TSS,
            tmp = lateout(reg) _,
            options(preserves_flags),
        );
    }
}

/// Segment registers and descriptor-table state, for tests and diagnostics.
pub struct SegmentState {
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub tr: u16,
    pub gdt_base: u64,
    pub gdt_limit: u16,
}

/// Reads the current segment selectors, task register, and GDTR.
pub fn segment_state() -> SegmentState {
    let (cs, ss, ds, tr): (u16, u16, u16, u16);
    let mut gdtr = DescriptorTablePointer { limit: 0, base: 0 };
    // SAFETY: these instructions only read segment and descriptor-table
    // registers; `sgdt` writes 10 bytes into `gdtr`, which is that size.
    unsafe {
        asm!(
            "mov {cs:x}, cs",
            "mov {ss:x}, ss",
            "mov {ds:x}, ds",
            "str {tr:x}",
            "sgdt [{gdtr}]",
            cs = out(reg) cs,
            ss = out(reg) ss,
            ds = out(reg) ds,
            tr = out(reg) tr,
            gdtr = in(reg) &raw mut gdtr,
            options(nostack, preserves_flags),
        );
    }
    SegmentState {
        cs,
        ss,
        ds,
        tr,
        gdt_base: gdtr.base,
        gdt_limit: gdtr.limit,
    }
}

/// True if the GDTR points at the kernel's own GDT.
pub fn kernel_gdt_loaded() -> bool {
    let state = segment_state();
    state.gdt_base == (&raw const GDT) as u64 && state.gdt_limit == 39
}

/// Top of the double-fault stack as stored in the TSS (0 before [`init`]).
pub fn double_fault_stack_top() -> u64 {
    let tss = &raw const TSS_SEGMENT;
    // SAFETY: after `init` nothing writes the TSS (the CPU only reads it), so
    // this unaligned read of a packed field races with nothing.
    unsafe { (&raw const (*tss).ist[(DOUBLE_FAULT_IST - 1) as usize]).read_unaligned() }
}

/// Bounds of the double-fault stack, `(bottom, top)`.
pub fn double_fault_stack_bounds() -> (u64, u64) {
    let bottom = (&raw const DOUBLE_FAULT_STACK) as u64;
    (bottom, bottom + DOUBLE_FAULT_STACK_SIZE as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_segments_match_reference_values() {
        // Well-known flat 64-bit code and data descriptors.
        assert_eq!(
            descriptor(0, 0xf_ffff, ACCESS_CODE, FLAGS_CODE64),
            0x00af_9a00_0000_ffff
        );
        assert_eq!(
            descriptor(0, 0xf_ffff, ACCESS_DATA, FLAGS_DATA),
            0x00cf_9200_0000_ffff
        );
    }

    #[test]
    fn base_and_limit_fields() {
        let d = descriptor(0xaabb_ccdd, 0x5_4321, 0, 0);
        assert_eq!(d & 0xffff, 0x4321, "limit 15:0");
        assert_eq!((d >> 16) & 0xff_ffff, 0xbb_ccdd, "base 23:0");
        assert_eq!((d >> 48) & 0xf, 0x5, "limit 19:16");
        assert_eq!(d >> 56, 0xaa, "base 31:24");
    }

    #[test]
    fn tss_descriptor_layout() {
        let [low, high] = tss_descriptor(0x1122_3344_5566_7788);
        assert_eq!(low, 0x5500_8966_7788_0067);
        assert_eq!(high, 0x1122_3344);
    }

    #[test]
    fn tss_size_matches_sdm() {
        assert_eq!(size_of::<Tss>(), 104);
        assert_eq!(core::mem::offset_of!(Tss, ist), 0x24);
        assert_eq!(core::mem::offset_of!(Tss, iomap_base), 0x66);
    }

    #[test]
    fn selectors_index_the_table() {
        assert_eq!(KERNEL_CODE >> 3, 1);
        assert_eq!(KERNEL_DATA >> 3, 2);
        assert_eq!(TSS >> 3, 3);
        assert_eq!(KERNEL_CODE & 0b111, 0, "ring 0, GDT");
    }
}
