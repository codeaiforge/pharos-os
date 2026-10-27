//! Kernel heap allocator (decision D-005, issue #29): the bitmap range
//! allocator over 16-byte units of a fixed virtual window. Sizes come from
//! the `Layout` on free, so no headers live in allocated memory. Safe Rust,
//! unit-tested on the host; the `GlobalAlloc` glue is in `mm::raw`.

use super::bitmap::{Bitmap, FreeError};

/// Virtual base of the heap window (D-005).
pub const HEAP_BASE: u64 = 0xffff_c000_0000_0000;
/// Heap size (fixed for now).
pub const HEAP_SIZE: usize = 4 * 1024 * 1024;
/// Allocation granularity; every block is at least this aligned.
pub const UNIT: usize = 16;
/// Bitmap words for [`HEAP_SIZE`].
pub const HEAP_BITMAP_WORDS: usize = Bitmap::words_for(HEAP_SIZE / UNIT);

/// Why a free was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum HeapFreeError {
    /// The address is outside the heap or not unit-aligned.
    NotInHeap,
    /// The block (or part of it) was not allocated.
    NotAllocated,
}

/// Allocates blocks from `[base, base + size)`.
pub struct Heap<'a> {
    base: usize,
    bitmap: Bitmap<'a>,
}

fn units(size: usize) -> usize {
    size.max(1).div_ceil(UNIT)
}

fn align_units(align: usize) -> usize {
    align.div_ceil(UNIT).max(1)
}

impl<'a> Heap<'a> {
    /// A heap over `size` bytes at `base` (aligned to at least the largest
    /// alignment ever requested; the real heap's base is page-aligned and
    /// more), with its bitmap in `storage`.
    pub fn new(base: usize, size: usize, storage: &'a mut [u64]) -> Self {
        Self {
            base,
            bitmap: Bitmap::new(storage, size / UNIT),
        }
    }

    /// Allocates `size` bytes aligned to `align` (a power of two). Returns
    /// the address, or `None` if no block fits.
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<usize> {
        let start = self.bitmap.alloc(units(size), align_units(align))?;
        Some(self.base + start * UNIT)
    }

    /// Frees the block at `addr` that was allocated with `size` bytes.
    pub fn free(&mut self, addr: usize, size: usize) -> Result<(), HeapFreeError> {
        let offset = addr
            .checked_sub(self.base)
            .ok_or(HeapFreeError::NotInHeap)?;
        if offset % UNIT != 0 {
            return Err(HeapFreeError::NotInHeap);
        }
        self.bitmap
            .free(offset / UNIT, units(size))
            .map_err(|e| match e {
                FreeError::OutOfRange => HeapFreeError::NotInHeap,
                FreeError::NotAllocated => HeapFreeError::NotAllocated,
            })
    }

    /// Bytes in use (whole units).
    pub fn used_bytes(&self) -> usize {
        (self.bitmap.len() - self.bitmap.free_count()) * UNIT
    }

    pub fn size(&self) -> usize {
        self.bitmap.len() * UNIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heap(size: usize) -> Heap<'static> {
        let words = Box::leak(vec![0u64; Bitmap::words_for(size / UNIT)].into_boxed_slice());
        Heap::new(0x1000_0000, size, words)
    }

    #[test]
    fn sizes_round_up_to_units() {
        let mut h = heap(4096);
        let a = h.alloc(1, 1).unwrap();
        let b = h.alloc(17, 8).unwrap();
        assert_eq!(b - a, 16, "1 byte takes one unit");
        assert_eq!(h.used_bytes(), 16 + 32);
    }

    #[test]
    fn alignment_is_honoured() {
        let mut h = heap(64 * 1024);
        h.alloc(16, 1).unwrap();
        for align in [32, 64, 256, 4096] {
            let a = h.alloc(24, align).unwrap();
            assert_eq!(a % align, 0, "align {align}");
        }
    }

    #[test]
    fn free_and_coalesce() {
        let mut h = heap(256);
        let blocks: Vec<usize> = (0..16).map(|_| h.alloc(16, 16).unwrap()).collect();
        assert_eq!(h.alloc(16, 16), None, "full");
        for &b in &blocks[4..8] {
            h.free(b, 16).unwrap();
        }
        // Four adjacent freed units form one 64-byte block.
        assert_eq!(h.alloc(64, 16), Some(blocks[4]));
    }

    #[test]
    fn bad_frees_are_rejected() {
        let mut h = heap(256);
        let a = h.alloc(32, 16).unwrap();
        assert_eq!(
            h.free(a + 8, 16),
            Err(HeapFreeError::NotInHeap),
            "misaligned"
        );
        assert_eq!(
            h.free(0x10, 16),
            Err(HeapFreeError::NotInHeap),
            "below heap"
        );
        assert_eq!(
            h.free(a + 4096, 16),
            Err(HeapFreeError::NotInHeap),
            "past end"
        );
        assert_eq!(h.free(a, 32), Ok(()));
        assert_eq!(
            h.free(a, 32),
            Err(HeapFreeError::NotAllocated),
            "double free"
        );
        assert_eq!(h.used_bytes(), 0);
    }

    #[test]
    fn exhaustion_and_recovery() {
        let mut h = heap(1024);
        assert_eq!(h.alloc(2048, 16), None, "larger than the heap");
        let a = h.alloc(1024, 16).unwrap();
        assert_eq!(h.alloc(1, 1), None);
        h.free(a, 1024).unwrap();
        assert!(h.alloc(1024, 16).is_some());
    }

    #[test]
    fn real_heap_bitmap_size() {
        // 4 MiB in 16-byte units: 262,144 bits = 4,096 words (32 KiB).
        assert_eq!(HEAP_BITMAP_WORDS, 4096);
        assert_eq!(HEAP_BASE % (2 * 1024 * 1024), 0);
    }
}
