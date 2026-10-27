//! Physical frame allocator (decision D-005, issue #26): one bitmap per
//! usable memory region, one bit per 4 KiB frame. Safe Rust; the bitmap
//! storage is handed in by the caller. Unit-tested on the host.

use core::fmt;

use super::bitmap::{Bitmap, FreeError};

/// Size of a physical frame.
pub const FRAME_SIZE: u64 = 4096;
/// Frames below 1 MiB are never handed out (legacy areas; later possibly
/// real-mode trampolines for other CPUs).
pub const LOW_MEMORY_END: u64 = 0x10_0000;
/// Most regions the allocator tracks; further regions are skipped and
/// counted.
pub const MAX_REGIONS: usize = 64;

/// A 4 KiB-aligned physical frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Frame(u64);

impl Frame {
    /// The frame starting at `addr`, which must be 4 KiB-aligned.
    pub const fn from_addr(addr: u64) -> Option<Frame> {
        if addr % FRAME_SIZE == 0 {
            Some(Frame(addr))
        } else {
            None
        }
    }

    pub const fn addr(self) -> u64 {
        self.0
    }
}

/// No free frame satisfies the request.
#[derive(Debug, PartialEq, Eq)]
pub struct OutOfMemory;

impl fmt::Display for OutOfMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("out of physical memory")
    }
}

/// Why a frame could not be freed.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameFreeError {
    /// The frame is not in any region the allocator manages.
    Unknown,
    /// The frame (or one in the range) was not allocated.
    NotAllocated,
}

/// A usable span of physical memory, 4 KiB-aligned on both ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub base: u64,
    pub frames: usize,
}

impl Span {
    /// The aligned, frame-sized part of `[base, base + length)` at or above
    /// [`LOW_MEMORY_END`], or `None` if nothing is left.
    pub fn usable(base: u64, length: u64) -> Option<Span> {
        let end = base.checked_add(length)? / FRAME_SIZE * FRAME_SIZE;
        let base = base.max(LOW_MEMORY_END).next_multiple_of(FRAME_SIZE);
        (end > base).then(|| Span {
            base,
            frames: ((end - base) / FRAME_SIZE) as usize,
        })
    }

    pub fn end(&self) -> u64 {
        self.base + self.frames as u64 * FRAME_SIZE
    }

    pub fn contains(&self, addr: u64) -> bool {
        (self.base..self.end()).contains(&addr)
    }
}

/// Where the bitmap storage goes and how big it is.
#[derive(Debug, PartialEq, Eq)]
pub struct StoragePlan {
    /// Physical address of the storage (start of the largest span).
    pub base: u64,
    /// Number of `u64` words for all bitmaps.
    pub words: usize,
}

impl StoragePlan {
    /// Frames the storage occupies.
    pub fn frames(&self) -> usize {
        (self.words as u64 * 8).div_ceil(FRAME_SIZE) as usize
    }
}

/// Picks the storage for the bitmaps of `spans`: the start of the largest
/// span, if it can hold them.
pub fn plan_storage(spans: &[Span]) -> Option<StoragePlan> {
    let words = spans.iter().map(|s| Bitmap::words_for(s.frames)).sum();
    let largest = spans.iter().max_by_key(|s| s.frames)?;
    let plan = StoragePlan {
        base: largest.base,
        words,
    };
    (plan.frames() < largest.frames).then_some(plan)
}

struct Region<'a> {
    span: Span,
    bitmap: Bitmap<'a>,
}

/// Counters for reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameStats {
    pub total: usize,
    pub free: usize,
    /// Usable regions beyond [`MAX_REGIONS`] that were ignored.
    pub skipped_regions: usize,
}

/// Hands out 4 KiB frames from the usable regions it was built with.
pub struct FrameAllocator<'a> {
    regions: [Option<Region<'a>>; MAX_REGIONS],
    count: usize,
    skipped: usize,
}

impl<'a> FrameAllocator<'a> {
    /// Builds the allocator for `spans` (at most [`MAX_REGIONS`] are used),
    /// with the bitmaps in `storage` (from [`plan_storage`]). Frames that
    /// hold the storage itself, at `storage_base`, are reserved.
    pub fn new(spans: &[Span], storage: &'a mut [u64], storage_base: u64) -> Self {
        let mut allocator = FrameAllocator {
            regions: [const { None }; MAX_REGIONS],
            count: 0,
            skipped: spans.len().saturating_sub(MAX_REGIONS),
        };
        let mut rest = storage;
        for span in spans.iter().take(MAX_REGIONS) {
            let (words, tail) = rest.split_at_mut(Bitmap::words_for(span.frames));
            rest = tail;
            allocator.regions[allocator.count] = Some(Region {
                span: *span,
                bitmap: Bitmap::new(words, span.frames),
            });
            allocator.count += 1;
        }
        let storage_bytes = (allocator.storage_words() * 8) as u64;
        allocator.reserve(storage_base, storage_bytes.div_ceil(FRAME_SIZE) as usize);
        allocator
    }

    fn storage_words(&self) -> usize {
        self.regions()
            .map(|r| Bitmap::words_for(r.span.frames))
            .sum()
    }

    fn regions(&self) -> impl Iterator<Item = &Region<'a>> {
        self.regions.iter().flatten()
    }

    fn regions_mut(&mut self) -> impl Iterator<Item = &mut Region<'a>> {
        self.regions.iter_mut().flatten()
    }

    /// Marks `frames` frames from `base` as used, where they fall in a region.
    fn reserve(&mut self, base: u64, frames: usize) {
        for i in 0..frames as u64 {
            let addr = base + i * FRAME_SIZE;
            if let Some(region) = self.regions_mut().find(|r| r.span.contains(addr)) {
                let index = ((addr - region.span.base) / FRAME_SIZE) as usize;
                region.bitmap.reserve(index, 1);
            }
        }
    }

    /// Allocates one frame. The frame's contents are undefined.
    pub fn alloc(&mut self) -> Result<Frame, OutOfMemory> {
        self.alloc_contiguous(1, 1)
    }

    /// Allocates `count` physically contiguous frames, the first aligned to
    /// `align` frames (a power of two).
    pub fn alloc_contiguous(&mut self, count: usize, align: usize) -> Result<Frame, OutOfMemory> {
        let align_bytes = align as u64 * FRAME_SIZE;
        for region in self.regions_mut() {
            let start = if align == 1 {
                region.bitmap.alloc(count, 1)
            } else {
                // Alignment is about physical addresses, and the region base
                // need not be aligned: runs start at `skip + k * align`.
                let skip = (region.span.base.next_multiple_of(align_bytes) - region.span.base)
                    / FRAME_SIZE;
                alloc_with_offset(&mut region.bitmap, count, align, skip as usize)
            };
            if let Some(start) = start {
                return Ok(Frame(region.span.base + start as u64 * FRAME_SIZE));
            }
        }
        Err(OutOfMemory)
    }

    /// Frees one frame.
    pub fn free(&mut self, frame: Frame) -> Result<(), FrameFreeError> {
        self.free_contiguous(frame, 1)
    }

    /// Frees `count` contiguous frames starting at `frame`.
    pub fn free_contiguous(&mut self, frame: Frame, count: usize) -> Result<(), FrameFreeError> {
        let region = self
            .regions_mut()
            .find(|r| r.span.contains(frame.0))
            .ok_or(FrameFreeError::Unknown)?;
        let index = ((frame.0 - region.span.base) / FRAME_SIZE) as usize;
        region.bitmap.free(index, count).map_err(|e| match e {
            FreeError::OutOfRange => FrameFreeError::Unknown,
            FreeError::NotAllocated => FrameFreeError::NotAllocated,
        })
    }

    pub fn stats(&self) -> FrameStats {
        FrameStats {
            total: self.regions().map(|r| r.bitmap.len()).sum(),
            free: self.regions().map(|r| r.bitmap.free_count()).sum(),
            skipped_regions: self.skipped,
        }
    }

    /// Counts usable regions the caller could not pass in.
    pub fn note_skipped(&mut self, regions: usize) {
        self.skipped += regions;
    }

    /// True if `addr` lies in a region this allocator manages.
    pub fn manages(&self, addr: u64) -> bool {
        self.regions().any(|r| r.span.contains(addr))
    }
}

/// Aligned allocation in a region whose base is not aligned: the run must
/// start at `skip + k * align` units.
fn alloc_with_offset(
    bitmap: &mut Bitmap<'_>,
    count: usize,
    align: usize,
    skip: usize,
) -> Option<usize> {
    let mut start = skip;
    while start + count <= bitmap.len() {
        if (start..start + count).all(|u| !bitmap.is_used(u)) {
            bitmap.reserve(start, count);
            return Some(start);
        }
        start += align;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(list: &[(u64, u64)]) -> Vec<Span> {
        list.iter()
            .filter_map(|&(b, l)| Span::usable(b, l))
            .collect()
    }

    #[test]
    fn span_alignment_and_low_memory() {
        assert_eq!(Span::usable(0x1000, 0x9f000), None, "below 1 MiB");
        assert_eq!(
            Span::usable(0xf_f800, 0x2800),
            Some(Span {
                base: 0x10_0000,
                frames: 2
            }),
            "clipped to 1 MiB"
        );
        assert_eq!(
            Span::usable(0x10_0800, 0x3000),
            Some(Span {
                base: 0x10_1000,
                frames: 2
            }),
            "unaligned base rounds up, end rounds down"
        );
        assert_eq!(Span::usable(0x20_0000, 0x800), None, "less than a frame");
        assert_eq!(Span::usable(0x20_0000, 0), None, "zero length");
        assert_eq!(Span::usable(u64::MAX - 0xfff, 0x2000), None, "overflow");
    }

    #[test]
    fn storage_goes_in_the_largest_span() {
        let s = spans(&[(0x10_0000, 0x10_0000), (0x100_0000, 0x400_0000)]);
        let plan = plan_storage(&s).unwrap();
        assert_eq!(plan.base, 0x100_0000);
        // 256 + 16384 frames -> 4 + 256 words.
        assert_eq!(plan.words, 4 + 256);
        assert_eq!(plan.frames(), 1);
        assert_eq!(plan_storage(&[]), None);
    }

    fn build(list: &[(u64, u64)]) -> (FrameAllocator<'static>, StoragePlan) {
        let s = spans(list);
        let plan = plan_storage(&s).unwrap();
        let storage = Box::leak(vec![0u64; plan.words].into_boxed_slice());
        (FrameAllocator::new(&s, storage, plan.base), plan)
    }

    #[test]
    fn storage_frames_are_reserved() {
        let (mut a, plan) = build(&[(0x10_0000, 0x4000), (0x100_0000, 0x10000)]);
        let stats = a.stats();
        assert_eq!(stats.total, 4 + 16);
        assert_eq!(stats.free, 4 + 16 - plan.frames());
        let all: Vec<u64> = std::iter::from_fn(|| a.alloc().ok().map(Frame::addr)).collect();
        assert!(!all.contains(&plan.base), "storage frame handed out");
        assert_eq!(all.len(), stats.free);
    }

    #[test]
    fn frames_are_distinct_aligned_and_in_regions() {
        let list = [(0x10_0000, 0x8000), (0x30_0000, 0x6000)];
        let (mut a, _) = build(&list);
        let s = spans(&list);
        let mut all: Vec<u64> = std::iter::from_fn(|| a.alloc().ok().map(Frame::addr)).collect();
        assert!(all.iter().all(|f| f % FRAME_SIZE == 0));
        assert!(all.iter().all(|&f| s.iter().any(|sp| sp.contains(f))));
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "a frame was handed out twice");
        assert_eq!(a.alloc(), Err(OutOfMemory));
        assert_eq!(a.stats().free, 0);
    }

    #[test]
    fn free_and_reuse() {
        let (mut a, _) = build(&[(0x10_0000, 0x10000)]);
        let before = a.stats().free;
        let f = a.alloc().unwrap();
        assert_eq!(a.free(f), Ok(()));
        assert_eq!(a.free(f), Err(FrameFreeError::NotAllocated));
        assert_eq!(a.free(Frame(0x9000_0000)), Err(FrameFreeError::Unknown));
        assert_eq!(a.stats().free, before);
    }

    #[test]
    fn contiguous_alignment_is_physical() {
        // Region starts at 1 MiB + 4 KiB: not 8-frame (32 KiB) aligned.
        let (mut a, _) = build(&[(0x10_1000, 0x10_0000)]);
        let f = a.alloc_contiguous(8, 8).unwrap();
        assert_eq!(f.addr() % (8 * FRAME_SIZE), 0);
        let g = a.alloc_contiguous(8, 8).unwrap();
        assert_eq!(g.addr() % (8 * FRAME_SIZE), 0);
        assert_ne!(f, g);
        assert_eq!(a.free_contiguous(f, 8), Ok(()));
    }

    #[test]
    fn extra_regions_are_counted() {
        let many: Vec<Span> = (0..MAX_REGIONS as u64 + 3)
            .map(|i| Span {
                base: 0x100_0000 + i * 0x10_0000,
                frames: 16,
            })
            .collect();
        let plan = plan_storage(&many).unwrap();
        let storage = Box::leak(vec![0u64; plan.words].into_boxed_slice());
        let a = FrameAllocator::new(&many, storage, plan.base);
        assert_eq!(a.stats().skipped_regions, 3);
        assert_eq!(a.stats().total, MAX_REGIONS * 16);
    }
}
