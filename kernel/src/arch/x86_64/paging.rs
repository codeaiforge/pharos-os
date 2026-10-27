//! The kernel's own page tables (decision D-005, issue #27).
//!
//! [`AddressSpace`] owns a 4-level page-table tree whose table frames come
//! from the frame allocator and are reached through the direct map.
//! [`init_kernel_space`] builds the kernel address space and switches CR3 to
//! it:
//!
//! - the direct map at Limine's HHDM offset for usable, bootloader-
//!   reclaimable, ACPI, framebuffer, and reserved-mapped regions (writable,
//!   no-execute; executable/module regions read-only), with 2 MiB pages where
//!   both ends allow;
//! - the kernel image at its link address, per segment: requests and GOT
//!   writable, text read+execute, rodata read-only, data/bss writable;
//! - the kernel stack and the double-fault stack, each with the page below
//!   left unmapped as a guard page.
//!
//! Page-table and CR3 writes are `unsafe` and stay in this module.

// The kernel-space builder needs linker symbols, so it exists only on the
// kernel target; host builds compile the rest for unit tests.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mm::frame::{FRAME_SIZE, FrameAllocator};
use crate::mm::raw::IrqMutex;

/// Bytes in a 2 MiB page.
pub const HUGE_PAGE: u64 = 2 * 1024 * 1024;

// Page-table entry bits (Intel SDM vol. 3A, section 5.5).
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

const IA32_EFER: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;

/// Size of one mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Size4K,
    Size2M,
}

impl PageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size4K => FRAME_SIZE,
            Self::Size2M => HUGE_PAGE,
        }
    }
}

/// Access rights of a mapping. Every mapping is readable and kernel-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    pub writable: bool,
    pub executable: bool,
    /// Caching disabled (for MMIO).
    pub uncached: bool,
}

impl Flags {
    pub const DATA: Flags = Flags {
        writable: true,
        executable: false,
        uncached: false,
    };
    pub const READ_ONLY: Flags = Flags {
        writable: false,
        executable: false,
        uncached: false,
    };
    pub const CODE: Flags = Flags {
        writable: false,
        executable: true,
        uncached: false,
    };
    pub const MMIO: Flags = Flags {
        writable: true,
        executable: false,
        uncached: true,
    };

    fn from_entry(entry: u64) -> Flags {
        Flags {
            writable: entry & WRITABLE != 0,
            executable: entry & NO_EXECUTE == 0,
            uncached: entry & CACHE_DISABLE != 0,
        }
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

/// A leaf entry mapping `phys` with `flags`. `nx` says whether the CPU has
/// no-execute enabled; without it the NX bit is reserved and must stay 0.
pub const fn leaf_entry(phys: u64, flags: Flags, size: PageSize, nx: bool) -> u64 {
    let mut entry = (phys & ADDRESS_MASK) | PRESENT;
    if flags.writable {
        entry |= WRITABLE;
    }
    if flags.uncached {
        entry |= CACHE_DISABLE | WRITE_THROUGH;
    }
    if matches!(size, PageSize::Size2M) {
        entry |= HUGE;
    }
    if !flags.executable && nx {
        entry |= NO_EXECUTE;
    }
    entry
}

/// Entry pointing at a lower-level table. Permissions are enforced at the
/// leaf, so table entries allow everything.
pub const fn table_entry(phys: u64) -> u64 {
    (phys & ADDRESS_MASK) | PRESENT | WRITABLE
}

/// Splits `len` bytes (a multiple of 4 KiB) from `virt`/`phys` into pages:
/// 2 MiB where both addresses are 2 MiB-aligned and enough remains, else
/// 4 KiB.
pub fn pages(virt: u64, phys: u64, len: u64) -> impl Iterator<Item = (u64, u64, PageSize)> {
    let mut offset = 0;
    core::iter::from_fn(move || {
        if offset >= len {
            return None;
        }
        let (v, p) = (virt + offset, phys + offset);
        let size = if v % HUGE_PAGE == 0 && p % HUGE_PAGE == 0 && len - offset >= HUGE_PAGE {
            PageSize::Size2M
        } else {
            PageSize::Size4K
        };
        offset += size.bytes();
        Some((v, p, size))
    })
}

/// Why a mapping operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum MapError {
    /// An address is not aligned to the page size.
    Misaligned,
    /// The page is already mapped.
    AlreadyMapped,
    /// A 2 MiB page covers the address where a 4 KiB mapping was asked for.
    HugePageInTheWay,
    /// No frame left for a page table.
    OutOfMemory,
    /// The address is not mapped.
    NotMapped,
    /// The kernel address space does not exist yet.
    NotInitialized,
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Misaligned => "address not aligned to the page size",
            Self::AlreadyMapped => "page already mapped",
            Self::HugePageInTheWay => "a 2 MiB page covers the address",
            Self::OutOfMemory => "out of frames for page tables",
            Self::NotMapped => "address not mapped",
            Self::NotInitialized => "kernel address space not built yet",
        })
    }
}

/// Result of [`AddressSpace::translate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub phys: u64,
    pub flags: Flags,
    pub size: PageSize,
}

/// Direct-map offset; set by [`init_kernel_space`] before any table access.
static HHDM: AtomicU64 = AtomicU64::new(0);
/// Whether EFER.NXE is on (NX bits allowed).
static NX: AtomicBool = AtomicBool::new(false);

fn entry_ptr(table: u64, index: usize) -> *mut u64 {
    (HHDM.load(Ordering::Relaxed) + table + index as u64 * 8) as *mut u64
}

fn read_entry(table: u64, index: usize) -> u64 {
    // SAFETY: `table` is the physical address of a page-table frame owned by
    // an `AddressSpace` (allocated by `alloc_table`), or of the active root;
    // both are in RAM the direct map covers, and `index < 512`.
    unsafe { entry_ptr(table, index).read_volatile() }
}

fn write_entry(table: u64, index: usize, value: u64) {
    // SAFETY: as in `read_entry`. Callers hold `&mut AddressSpace`, so no
    // one else changes this tree; the CPU only reads it.
    unsafe { entry_ptr(table, index).write_volatile(value) }
}

fn alloc_table(frames: &mut FrameAllocator<'_>) -> Result<u64, MapError> {
    let frame = frames.alloc().map_err(|_| MapError::OutOfMemory)?;
    let virt = HHDM.load(Ordering::Relaxed) + frame.addr();
    // SAFETY: the frame was just allocated, so nothing else uses it, and the
    // direct map covers it; zeroing makes every entry not present.
    unsafe { core::ptr::write_bytes(virt as *mut u8, 0, FRAME_SIZE as usize) };
    Ok(frame.addr())
}

fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    cr3
}

/// Physical address of the active root table.
pub fn active_root() -> u64 {
    read_cr3() & ADDRESS_MASK
}

/// A page-table tree. The kernel has one; later address spaces will share
/// its upper half (PML4 entries 256–511).
pub struct AddressSpace {
    root: u64,
}

impl AddressSpace {
    /// An empty address space.
    pub fn new(frames: &mut FrameAllocator<'_>) -> Result<Self, MapError> {
        Ok(Self {
            root: alloc_table(frames)?,
        })
    }

    /// Physical address of the root table (the CR3 value).
    pub fn root(&self) -> u64 {
        self.root
    }

    fn is_active(&self) -> bool {
        active_root() == self.root
    }

    /// Maps the page at `virt` to `phys`. Both must be aligned to `size`.
    pub fn map(
        &mut self,
        virt: u64,
        phys: u64,
        size: PageSize,
        flags: Flags,
        frames: &mut FrameAllocator<'_>,
    ) -> Result<(), MapError> {
        if virt % size.bytes() != 0 || phys % size.bytes() != 0 {
            return Err(MapError::Misaligned);
        }
        let levels = match size {
            PageSize::Size4K => 3,
            PageSize::Size2M => 2,
        };
        let indexes = table_indexes(virt);
        let mut table = self.root;
        for &index in &indexes[..levels] {
            let entry = read_entry(table, index);
            if entry & PRESENT == 0 {
                let new = alloc_table(frames)?;
                write_entry(table, index, table_entry(new));
                table = new;
            } else if entry & HUGE != 0 {
                return Err(MapError::HugePageInTheWay);
            } else {
                table = entry & ADDRESS_MASK;
            }
        }
        if read_entry(table, indexes[levels]) & PRESENT != 0 {
            return Err(MapError::AlreadyMapped);
        }
        // The entry was not present, and x86 does not cache not-present
        // translations, so no TLB flush is needed.
        let nx = NX.load(Ordering::Relaxed);
        write_entry(table, indexes[levels], leaf_entry(phys, flags, size, nx));
        Ok(())
    }

    /// Unmaps the page at `virt` and returns its physical address. Empty
    /// page tables are kept.
    // ponytail: empty intermediate tables are never freed; free them when
    // address spaces come and go (M2.7).
    pub fn unmap(&mut self, virt: u64) -> Result<u64, MapError> {
        let indexes = table_indexes(virt);
        let mut table = self.root;
        for (level, &index) in indexes.iter().enumerate() {
            let entry = read_entry(table, index);
            if entry & PRESENT == 0 {
                return Err(MapError::NotMapped);
            }
            let leaf = level == 3 || (level == 2 && entry & HUGE != 0);
            if leaf {
                write_entry(table, index, 0);
                if self.is_active() {
                    // SAFETY: `invlpg` only drops the TLB entry for `virt`.
                    unsafe { asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
                }
                return Ok(entry & ADDRESS_MASK);
            }
            table = entry & ADDRESS_MASK;
        }
        Err(MapError::NotMapped)
    }

    /// Where `virt` is mapped, if it is.
    pub fn translate(&self, virt: u64) -> Option<Translation> {
        let indexes = table_indexes(virt);
        let mut table = self.root;
        for (level, &index) in indexes.iter().enumerate() {
            let entry = read_entry(table, index);
            if entry & PRESENT == 0 {
                return None;
            }
            if level == 2 && entry & HUGE != 0 {
                return Some(Translation {
                    phys: (entry & ADDRESS_MASK & !(HUGE_PAGE - 1)) + virt % HUGE_PAGE,
                    flags: Flags::from_entry(entry),
                    size: PageSize::Size2M,
                });
            }
            if level == 3 {
                return Some(Translation {
                    phys: (entry & ADDRESS_MASK) + virt % FRAME_SIZE,
                    flags: Flags::from_entry(entry),
                    size: PageSize::Size4K,
                });
            }
            table = entry & ADDRESS_MASK;
        }
        None
    }

    /// Maps `[virt, virt + len)` to `[phys, ...)` with 2 MiB pages where
    /// possible, skipping pages that are already mapped (shared edge pages
    /// of neighbouring memory-map regions).
    fn map_range(
        &mut self,
        virt: u64,
        phys: u64,
        len: u64,
        flags: Flags,
        frames: &mut FrameAllocator<'_>,
    ) -> Result<(), MapError> {
        for (v, p, size) in pages(virt, phys, len) {
            if self.translate(v).is_some() {
                continue;
            }
            match self.map(v, p, size, flags, frames) {
                // A 2 MiB slot already holding 4 KiB pages: map page by page.
                Err(MapError::AlreadyMapped) if size == PageSize::Size2M => {
                    for offset in (0..HUGE_PAGE).step_by(FRAME_SIZE as usize) {
                        if self.translate(v + offset).is_none() {
                            self.map(v + offset, p + offset, PageSize::Size4K, flags, frames)?;
                        }
                    }
                }
                other => other?,
            }
        }
        Ok(())
    }
}

// Segment boundaries from `linker.ld`.
#[cfg(target_os = "none")]
unsafe extern "C" {
    safe static __kernel_start: u8;
    safe static __text_start: u8;
    safe static __rodata_start: u8;
    safe static __data_start: u8;
    safe static __data_end: u8;
}

/// Where Limine loaded the kernel image (executable-address response).
#[derive(Clone, Copy, Debug)]
pub struct KernelImage {
    pub physical_base: u64,
    pub virtual_base: u64,
}

/// Memory-map kinds the direct map covers, with their access rights.
fn direct_map_flags(kind: u64) -> Option<Flags> {
    use crate::limine::*;
    match kind {
        MEMMAP_USABLE
        | MEMMAP_BOOTLOADER_RECLAIMABLE
        | MEMMAP_ACPI_RECLAIMABLE
        | MEMMAP_ACPI_NVS
        | MEMMAP_RESERVED_MAPPED => Some(Flags::DATA),
        // The kernel image and modules: no writable or executable alias.
        MEMMAP_EXECUTABLE_AND_MODULES => Some(Flags::READ_ONLY),
        MEMMAP_FRAMEBUFFER => Some(Flags::MMIO),
        _ => None,
    }
}

static KERNEL_SPACE: IrqMutex<Option<AddressSpace>> = IrqMutex::new(None);

/// Builds the kernel address space (see the module docs) and switches to it.
#[cfg(target_os = "none")]
/// `entries` are memory-map entries `(base, length, kind)`. Call once, after
/// the GDT and IDT, with the frame allocator ready.
pub fn init_kernel_space(
    hhdm: u64,
    entries: impl Iterator<Item = (u64, u64, u64)>,
    image: KernelImage,
    frames: &mut FrameAllocator<'_>,
) -> Result<(), MapError> {
    let mut kernel = KERNEL_SPACE.lock();
    if kernel.is_some() {
        return Err(MapError::AlreadyMapped);
    }
    HHDM.store(hhdm, Ordering::Relaxed);
    NX.store(super::rdmsr(IA32_EFER) & EFER_NXE != 0, Ordering::Relaxed);
    let mut space = AddressSpace::new(frames)?;

    for (base, length, kind) in entries {
        let Some(flags) = direct_map_flags(kind) else {
            continue;
        };
        let start = base / FRAME_SIZE * FRAME_SIZE;
        let end = (base + length).next_multiple_of(FRAME_SIZE);
        space.map_range(hhdm + start, start, end - start, flags, frames)?;
    }

    let phys = |virt: u64| image.physical_base + (virt - image.virtual_base);
    let addr = |symbol: &u8| symbol as *const u8 as u64;
    let segments = [
        (addr(&__kernel_start), addr(&__text_start), Flags::DATA),
        (addr(&__text_start), addr(&__rodata_start), Flags::CODE),
        (addr(&__rodata_start), addr(&__data_start), Flags::READ_ONLY),
        (addr(&__data_start), addr(&__data_end), Flags::DATA),
    ];
    let (stack_bottom, stack_top) = super::kernel_stack_bounds();
    let (df_bottom, df_top) = super::gdt::double_fault_stack_bounds();
    let stacks = [
        (stack_bottom, stack_top, Flags::DATA),
        (df_bottom, df_top, Flags::DATA),
    ];
    for (start, end, flags) in segments.into_iter().chain(stacks) {
        let len = end.next_multiple_of(FRAME_SIZE) - start;
        space.map_range(start, phys(start), len, flags, frames)?;
    }

    // SAFETY: the new tables map everything the kernel uses from here on:
    // its code, data, and both stacks at their link addresses (the CPU is on
    // the kernel stack), and the direct map, which holds the frame
    // allocator's bitmaps, these page tables, and Limine's responses. GDT,
    // IDT, and TSS are kernel statics. Writing CR3 flushes the old
    // non-global translations.
    unsafe { asm!("mov cr3, {}", in(reg) space.root(), options(nostack, preserves_flags)) };
    *kernel = Some(space);
    Ok(())
}

/// Maps one page into the kernel address space.
pub fn map_kernel_page(
    virt: u64,
    phys: u64,
    size: PageSize,
    flags: Flags,
    frames: &mut FrameAllocator<'_>,
) -> Result<(), MapError> {
    KERNEL_SPACE
        .lock()
        .as_mut()
        .ok_or(MapError::NotInitialized)?
        .map(virt, phys, size, flags, frames)
}

/// Unmaps one page from the kernel address space.
pub fn unmap_kernel_page(virt: u64) -> Result<u64, MapError> {
    KERNEL_SPACE
        .lock()
        .as_mut()
        .ok_or(MapError::NotInitialized)?
        .unmap(virt)
}

/// Where `virt` is mapped in the kernel address space.
pub fn translate_kernel(virt: u64) -> Option<Translation> {
    KERNEL_SPACE.lock().as_ref()?.translate(virt)
}

/// True once CR3 holds the kernel address space (Limine's tables unused).
pub fn kernel_space_active() -> bool {
    kernel_root() == Some(active_root())
}

/// Root table of the kernel address space, once built.
pub fn kernel_root() -> Option<u64> {
    KERNEL_SPACE.lock().as_ref().map(AddressSpace::root)
}

// ---- Test helpers -------------------------------------------------------

/// Virtual page reserved for tests of mapping and unmapping (outside the
/// direct map and the planned heap window).
pub const TEST_PAGE: u64 = 0xffff_d000_0000_0000;

/// What [`alias_check`] observed.
pub struct AliasCheck {
    pub mapped: bool,
    pub translated: bool,
    /// A value written through `TEST_PAGE` was read back through the
    /// direct map.
    pub alias_matches: bool,
    pub unmapped: bool,
}

/// Maps a fresh frame at [`TEST_PAGE`], writes through it, reads through
/// the direct map, then unmaps and frees the frame.
pub fn alias_check(frames: &mut FrameAllocator<'_>) -> Result<AliasCheck, MapError> {
    let frame = frames.alloc().map_err(|_| MapError::OutOfMemory)?;
    let mapped = map_kernel_page(
        TEST_PAGE,
        frame.addr(),
        PageSize::Size4K,
        Flags::DATA,
        frames,
    )
    .is_ok();
    let translated = translate_kernel(TEST_PAGE).is_some_and(|t| t.phys == frame.addr());
    let mut alias_matches = false;
    if mapped {
        let pattern = 0x5048_4152_4f53_0001_u64; // "PHAROS" + 1
        // SAFETY: `TEST_PAGE` now maps the frame just allocated, which
        // nothing else uses; both accesses are aligned and inside it.
        unsafe {
            (TEST_PAGE as *mut u64).write_volatile(pattern);
            let alias = (HHDM.load(Ordering::Relaxed) + frame.addr()) as *const u64;
            alias_matches = alias.read_volatile() == pattern;
        }
    }
    let unmapped =
        unmap_kernel_page(TEST_PAGE) == Ok(frame.addr()) && translate_kernel(TEST_PAGE).is_none();
    let _ = frames.free(frame);
    Ok(AliasCheck {
        mapped,
        translated,
        alias_matches,
        unmapped,
    })
}

/// Fills `frame` with `byte` through the direct map and reads back its
/// first and last bytes. For test kernels: `frame` must have just been
/// allocated by the caller, so nothing else uses it.
#[doc(hidden)]
pub fn fill_frame_for_test(frame: crate::mm::frame::Frame, byte: u8) -> bool {
    let virt = (HHDM.load(Ordering::Relaxed) + frame.addr()) as *mut u8;
    // SAFETY: per the contract the frame is owned by the caller and unused;
    // the direct map covers all managed frames writable, and the accesses
    // stay inside the 4 KiB frame.
    unsafe {
        core::ptr::write_bytes(virt, byte, FRAME_SIZE as usize);
        virt.read_volatile() == byte && virt.add(FRAME_SIZE as usize - 1).read_volatile() == byte
    }
}

/// Reads [`TEST_PAGE`]; faults if it is unmapped (after [`alias_check`]).
pub fn touch_test_page() {
    // SAFETY: a read of the test page: it faults if unmapped; if mapped, it
    // is a frame owned by the test and the read changes nothing.
    unsafe {
        asm!("mov al, byte ptr [{}]", in(reg) TEST_PAGE, out("al") _,
            options(readonly, nostack, preserves_flags))
    };
}

/// A read-only static (in `.rodata`) for the write-protection test.
static RODATA_PROBE: u64 = 0x5a5a;
/// A `ret` instruction in writable data (`.data`) for the no-execute test.
static mut DATA_PROBE: [u8; 16] = [0xc3; 16];

/// Address of the read-only probe.
pub fn rodata_probe_addr() -> u64 {
    &raw const RODATA_PROBE as u64
}

/// Address of the data probe.
pub fn data_probe_addr() -> u64 {
    &raw const DATA_PROBE as u64
}

/// Writes to the read-only probe; faults when write protection works.
pub fn write_rodata_probe() {
    // SAFETY: the write targets a read-only page and is expected to fault
    // before it happens. If protection were broken, it would store the same
    // kind of value into a static nobody reads afterwards.
    unsafe {
        asm!("mov qword ptr [{}], 0", in(reg) rodata_probe_addr(), options(nostack, preserves_flags))
    };
}

/// Calls the data probe; faults when no-execute works.
pub fn execute_data_probe() {
    // SAFETY: the target is a `ret` in a no-execute page, so the call is
    // expected to fault on the fetch. If NX were broken, `ret` would return
    // here at once; the C ABI clobbers are declared.
    unsafe { asm!("call {}", in(reg) data_probe_addr(), clobber_abi("C")) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes() {
        assert_eq!(table_indexes(0xffff_8000_fee0_0000), [256, 3, 503, 0]);
        assert_eq!(table_indexes(0xffff_ffff_8000_1000), [511, 510, 0, 1]);
        assert_eq!(table_indexes(TEST_PAGE), [416, 0, 0, 0]);
    }

    #[test]
    fn leaf_entries() {
        let code = leaf_entry(0x20_0000, Flags::CODE, PageSize::Size4K, true);
        assert_eq!(code, 0x20_0000 | PRESENT, "read+execute: no W, no NX");
        let data = leaf_entry(0x20_0000, Flags::DATA, PageSize::Size2M, true);
        assert_eq!(data, 0x20_0000 | PRESENT | WRITABLE | HUGE | NO_EXECUTE);
        let mmio = leaf_entry(0xfee0_0000, Flags::MMIO, PageSize::Size4K, true);
        assert_eq!(
            mmio & (CACHE_DISABLE | WRITE_THROUGH),
            CACHE_DISABLE | WRITE_THROUGH
        );
        let no_nx = leaf_entry(0x1000, Flags::READ_ONLY, PageSize::Size4K, false);
        assert_eq!(no_nx & NO_EXECUTE, 0, "NX bit reserved without EFER.NXE");
        assert_eq!(Flags::from_entry(data), Flags::DATA);
        assert_eq!(Flags::from_entry(code), Flags::CODE);
        assert_eq!(table_entry(0x1234_5fff), 0x1234_5000 | PRESENT | WRITABLE);
    }

    #[test]
    fn page_splitting() {
        let all: Vec<_> = pages(0xffff_8000_001f_f000, 0x1f_f000, 0x40_2000).collect();
        assert_eq!(all[0], (0xffff_8000_001f_f000, 0x1f_f000, PageSize::Size4K));
        assert_eq!(all[1], (0xffff_8000_0020_0000, 0x20_0000, PageSize::Size2M));
        assert_eq!(all[2], (0xffff_8000_0040_0000, 0x40_0000, PageSize::Size2M));
        assert_eq!(all[3].2, PageSize::Size4K, "tail shorter than 2 MiB");
        let total: u64 = all.iter().map(|p| p.2.bytes()).sum();
        assert_eq!(total, 0x40_2000);
        // Misaligned physical address: no 2 MiB pages at all.
        assert!(pages(0x20_0000, 0x20_1000, 0x40_0000).all(|p| p.2 == PageSize::Size4K));
    }

    #[test]
    fn direct_map_kinds() {
        use crate::limine::*;
        assert_eq!(direct_map_flags(MEMMAP_USABLE), Some(Flags::DATA));
        assert_eq!(
            direct_map_flags(MEMMAP_EXECUTABLE_AND_MODULES),
            Some(Flags::READ_ONLY)
        );
        assert_eq!(direct_map_flags(MEMMAP_FRAMEBUFFER), Some(Flags::MMIO));
        assert_eq!(direct_map_flags(MEMMAP_RESERVED), None);
        assert_eq!(direct_map_flags(MEMMAP_BAD_MEMORY), None);
    }
}
