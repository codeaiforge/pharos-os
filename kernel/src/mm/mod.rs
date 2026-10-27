//! Memory management (decision D-005). `bitmap` and `frame` are safe,
//! host-tested logic; `raw` holds the little `unsafe` code that touches raw
//! memory.

pub mod bitmap;
pub mod frame;
#[cfg(target_arch = "x86_64")]
pub mod raw;

#[cfg(target_arch = "x86_64")]
pub use global::*;

#[cfg(target_arch = "x86_64")]
mod global {
    use core::fmt;

    use super::frame::{FrameAllocator, FrameStats, MAX_REGIONS, Span, plan_storage};
    use super::raw::{IrqMutex, IrqMutexGuard, bitmap_storage};
    #[cfg(target_os = "none")]
    use crate::arch::x86_64::paging::KernelImage;
    use crate::arch::x86_64::paging::{self, MapError};
    use crate::boot_info::MemoryMapCopy;
    use crate::limine::{MEMMAP_BOOTLOADER_RECLAIMABLE, MEMMAP_USABLE};

    static FRAMES: IrqMutex<Option<FrameAllocator<'static>>> = IrqMutex::new(None);
    static MEMORY_MAP: IrqMutex<Option<MemoryMapCopy>> = IrqMutex::new(None);

    /// Why the memory manager could not start.
    #[derive(Debug, PartialEq, Eq)]
    pub enum MmError {
        AlreadyInitialized,
        /// No usable region can hold the frame bitmaps.
        NoUsableMemory,
        /// `init_paging` or reclaim was called before `init_frames`.
        FramesNotReady,
        /// Reclaim was called before the kernel's own page tables are active.
        PagingNotReady,
        /// Building the kernel address space failed.
        Paging(MapError),
    }

    impl fmt::Display for MmError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::AlreadyInitialized => f.write_str("memory manager already initialized"),
                Self::NoUsableMemory => {
                    f.write_str("no usable memory region can hold the frame bitmaps")
                }
                Self::FramesNotReady => f.write_str("frame allocator not set up"),
                Self::PagingNotReady => {
                    f.write_str("bootloader page tables still active; cannot reclaim")
                }
                Self::Paging(error) => write!(f, "kernel page tables: {error}"),
            }
        }
    }

    /// Copies the memory map from `(base, length, kind)` entries into kernel
    /// memory, then builds the frame allocator: usable regions are free, and
    /// bootloader-reclaimable regions wait for
    /// [`reclaim_bootloader_memory`]. The bitmaps go in usable memory reached
    /// through the direct map at `hhdm`. Call once.
    pub fn init_frames(
        hhdm: u64,
        entries: impl Iterator<Item = (u64, u64, u64)>,
    ) -> Result<FrameStats, MmError> {
        let mut frames = FRAMES.lock();
        if frames.is_some() {
            return Err(MmError::AlreadyInitialized);
        }
        let mut map = MEMORY_MAP.lock();
        let copy = map.insert(MemoryMapCopy::new(entries));

        let spans_of = |kind: u64| {
            let mut spans = [Span { base: 0, frames: 0 }; MAX_REGIONS];
            let (mut count, mut extra) = (0, 0);
            for span in copy
                .tuples()
                .filter(|&(_, _, k)| k == kind)
                .filter_map(|(base, length, _)| Span::usable(base, length))
            {
                if count < MAX_REGIONS {
                    spans[count] = span;
                    count += 1;
                } else {
                    extra += 1;
                }
            }
            (spans, count, extra)
        };
        let (usable, usable_count, usable_extra) = spans_of(MEMMAP_USABLE);
        let (pending, pending_count, pending_extra) = spans_of(MEMMAP_BOOTLOADER_RECLAIMABLE);
        let (usable, pending) = (&usable[..usable_count], &pending[..pending_count]);

        let plan = plan_storage(usable, pending).ok_or(MmError::NoUsableMemory)?;
        let storage =
            bitmap_storage(hhdm, plan.base, plan.words).ok_or(MmError::AlreadyInitialized)?;
        let mut allocator = FrameAllocator::new(usable, pending, storage, plan.base);
        allocator.note_skipped(usable_extra + pending_extra);
        let stats = allocator.stats();
        *frames = Some(allocator);
        Ok(stats)
    }

    /// Hands bootloader-reclaimable memory to the frame allocator and
    /// retires Limine's responses, which live there (every `response()`
    /// returns `None` afterwards). Call once nothing uses bootloader memory:
    /// after the switch to the kernel's own stack, GDT, and page tables, and
    /// after the last read of a Limine response. Returns the frames gained.
    pub fn reclaim_bootloader_memory() -> Result<usize, MmError> {
        let mut frames = FRAMES.lock();
        let frames = frames.as_mut().ok_or(MmError::FramesNotReady)?;
        if !paging::kernel_space_active() {
            return Err(MmError::PagingNotReady);
        }
        crate::limine::retire_responses();
        Ok(frames.release_pending())
    }

    /// The memory map as copied by [`init_frames`] (`None` before).
    pub fn memory_map() -> IrqMutexGuard<'static, Option<MemoryMapCopy>> {
        MEMORY_MAP.lock()
    }

    /// Builds the kernel's own page tables and switches to them (D-005).
    /// Needs [`init_frames`] first. Returns the frames the page tables took.
    #[cfg(target_os = "none")]
    pub fn init_paging(
        hhdm: u64,
        entries: impl Iterator<Item = (u64, u64, u64)>,
        image: KernelImage,
    ) -> Result<usize, MmError> {
        let mut frames = FRAMES.lock();
        let frames = frames.as_mut().ok_or(MmError::FramesNotReady)?;
        let before = frames.stats().free;
        paging::init_kernel_space(hhdm, entries, image, frames).map_err(MmError::Paging)?;
        Ok(before - frames.stats().free)
    }

    /// The frame allocator, locked (interrupts disabled while held). `None`
    /// before [`init_frames`].
    pub fn frames() -> IrqMutexGuard<'static, Option<FrameAllocator<'static>>> {
        FRAMES.lock()
    }
}
