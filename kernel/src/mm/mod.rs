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
    use crate::arch::x86_64::paging::MapError;
    #[cfg(target_os = "none")]
    use crate::arch::x86_64::paging::{self, KernelImage};
    use crate::limine::MEMMAP_USABLE;

    static FRAMES: IrqMutex<Option<FrameAllocator<'static>>> = IrqMutex::new(None);

    /// Why the memory manager could not start.
    #[derive(Debug, PartialEq, Eq)]
    pub enum MmError {
        AlreadyInitialized,
        /// No usable region can hold the frame bitmaps.
        NoUsableMemory,
        /// `init_paging` was called before `init_frames`.
        FramesNotReady,
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
                Self::Paging(error) => write!(f, "kernel page tables: {error}"),
            }
        }
    }

    /// Builds the frame allocator from memory-map entries `(base, length,
    /// kind)`, with its bitmaps in usable memory reached through the direct
    /// map at `hhdm`. Call once.
    pub fn init_frames(
        hhdm: u64,
        entries: impl Iterator<Item = (u64, u64, u64)>,
    ) -> Result<FrameStats, MmError> {
        let mut frames = FRAMES.lock();
        if frames.is_some() {
            return Err(MmError::AlreadyInitialized);
        }
        let mut spans = [Span { base: 0, frames: 0 }; MAX_REGIONS];
        let (mut count, mut extra) = (0, 0);
        for span in entries
            .filter(|&(_, _, kind)| kind == MEMMAP_USABLE)
            .filter_map(|(base, length, _)| Span::usable(base, length))
        {
            if count < MAX_REGIONS {
                spans[count] = span;
                count += 1;
            } else {
                extra += 1;
            }
        }
        let spans = &spans[..count];
        let plan = plan_storage(spans).ok_or(MmError::NoUsableMemory)?;
        let storage =
            bitmap_storage(hhdm, plan.base, plan.words).ok_or(MmError::AlreadyInitialized)?;
        let mut allocator = FrameAllocator::new(spans, storage, plan.base);
        allocator.note_skipped(extra);
        let stats = allocator.stats();
        *frames = Some(allocator);
        Ok(stats)
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
