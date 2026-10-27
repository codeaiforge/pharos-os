//! Bitmap range allocator (decision D-005): one bit per unit, set = used.
//! Shared by the frame allocator (4 KiB units) and, later, the heap. Plain
//! safe Rust over a slice, unit-tested on the host.

/// Why a free was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum FreeError {
    /// The range extends past the end of the bitmap.
    OutOfRange,
    /// At least one unit in the range was already free (double free).
    NotAllocated,
}

/// Allocates runs of units from a bitmap it does not own.
pub struct Bitmap<'a> {
    words: &'a mut [u64],
    len: usize,
    free: usize,
    /// Where the next search starts (next fit).
    next: usize,
}

impl<'a> Bitmap<'a> {
    /// Number of `u64` words needed for `len` units.
    pub const fn words_for(len: usize) -> usize {
        len.div_ceil(64)
    }

    /// Creates a bitmap of `len` units, all free, over `words` (which must
    /// hold at least [`Self::words_for`]`(len)` words; extra words are unused).
    pub fn new(words: &'a mut [u64], len: usize) -> Self {
        let needed = Self::words_for(len);
        assert!(words.len() >= needed, "bitmap storage too small");
        let words = &mut words[..needed];
        words.fill(0);
        // Mark the unused tail bits of the last word as used, so searches
        // never return them.
        if len % 64 != 0 {
            words[needed - 1] = !0u64 << (len % 64);
        }
        Self {
            words,
            len,
            free: len,
            next: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn free_count(&self) -> usize {
        self.free
    }

    pub fn is_used(&self, unit: usize) -> bool {
        self.words[unit / 64] & (1 << (unit % 64)) != 0
    }

    fn set(&mut self, unit: usize, used: bool) {
        let bit = 1 << (unit % 64);
        if used {
            self.words[unit / 64] |= bit;
        } else {
            self.words[unit / 64] &= !bit;
        }
    }

    /// True if `count` units from `start` are all free.
    fn run_is_free(&self, start: usize, count: usize) -> bool {
        (start..start + count).all(|unit| !self.is_used(unit))
    }

    /// Allocates `count` consecutive units whose first index is a multiple
    /// of `align` (a power of two). Returns the first index, or `None` if no
    /// such run is free.
    // ponytail: linear scan, O(len) per allocation in the worst case; fine at
    // today's sizes (tens of thousands of frames). Add a free-run index if
    // profiling shows it matters.
    pub fn alloc(&mut self, count: usize, align: usize) -> Option<usize> {
        assert!(align.is_power_of_two(), "alignment must be a power of two");
        if count == 0 || count > self.free {
            return None;
        }
        let start_at = self.next.next_multiple_of(align);
        let found = self
            .search(start_at, self.len, count, align)
            .or_else(|| self.search(0, start_at.min(self.len), count, align));
        let start = found?;
        for unit in start..start + count {
            self.set(unit, true);
        }
        self.free -= count;
        self.next = start + count;
        Some(start)
    }

    /// Finds a free aligned run of `count` units starting in `from..to`.
    fn search(&self, from: usize, to: usize, count: usize, align: usize) -> Option<usize> {
        let mut start = from.next_multiple_of(align);
        while start < to && start + count <= self.len {
            // Skip whole used words quickly (the common case when full).
            if start % 64 == 0 && self.words[start / 64] == !0 {
                start += 64;
                continue;
            }
            if self.run_is_free(start, count) {
                return Some(start);
            }
            start += align;
        }
        None
    }

    /// Frees `count` units from `start`. Rejects the whole call, changing
    /// nothing, if any unit is out of range or already free.
    pub fn free(&mut self, start: usize, count: usize) -> Result<(), FreeError> {
        let end = start.checked_add(count).ok_or(FreeError::OutOfRange)?;
        if end > self.len {
            return Err(FreeError::OutOfRange);
        }
        if (start..end).any(|unit| !self.is_used(unit)) {
            return Err(FreeError::NotAllocated);
        }
        for unit in start..end {
            self.set(unit, false);
        }
        self.free += count;
        Ok(())
    }

    /// Marks `count` units from `start` as used whether or not they were
    /// free (for reserving ranges such as the bitmap storage itself).
    pub fn reserve(&mut self, start: usize, count: usize) {
        let end = (start + count).min(self.len);
        for unit in start..end {
            if !self.is_used(unit) {
                self.set(unit, true);
                self.free -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_every_unit_once_then_runs_out() {
        let mut words = [0u64; 2];
        let mut b = Bitmap::new(&mut words, 100);
        let got: Vec<usize> = (0..100).map(|_| b.alloc(1, 1).unwrap()).collect();
        assert_eq!(got, (0..100).collect::<Vec<_>>());
        assert_eq!(b.alloc(1, 1), None, "tail bits beyond len are never used");
        assert_eq!(b.free_count(), 0);
    }

    #[test]
    fn next_fit_wraps_around() {
        let mut words = [0u64; 1];
        let mut b = Bitmap::new(&mut words, 8);
        for _ in 0..8 {
            b.alloc(1, 1).unwrap();
        }
        b.free(2, 1).unwrap();
        assert_eq!(b.alloc(1, 1), Some(2));
    }

    #[test]
    fn aligned_runs() {
        let mut words = [0u64; 2];
        let mut b = Bitmap::new(&mut words, 128);
        assert_eq!(b.alloc(1, 1), Some(0));
        assert_eq!(b.alloc(4, 8), Some(8));
        assert_eq!(b.alloc(3, 1), Some(12));
        assert_eq!(b.alloc(64, 64), Some(64));
        assert_eq!(b.alloc(64, 64), None, "no second aligned run of 64");
        assert_eq!(b.free_count(), 128 - 1 - 4 - 3 - 64);
    }

    #[test]
    fn free_rejects_double_free_and_out_of_range() {
        let mut words = [0u64; 1];
        let mut b = Bitmap::new(&mut words, 10);
        let a = b.alloc(3, 1).unwrap();
        assert_eq!(b.free(a, 3), Ok(()));
        assert_eq!(b.free(a, 3), Err(FreeError::NotAllocated));
        assert_eq!(b.free(8, 3), Err(FreeError::OutOfRange));
        assert_eq!(b.free(usize::MAX, 2), Err(FreeError::OutOfRange));
        assert_eq!(b.free_count(), 10);
    }

    #[test]
    fn partial_double_free_changes_nothing() {
        let mut words = [0u64; 1];
        let mut b = Bitmap::new(&mut words, 10);
        b.alloc(2, 1).unwrap(); // units 0-1
        assert_eq!(b.free(0, 3), Err(FreeError::NotAllocated));
        assert!(b.is_used(0) && b.is_used(1));
        assert_eq!(b.free_count(), 8);
    }

    #[test]
    fn reserve_is_idempotent() {
        let mut words = [0u64; 1];
        let mut b = Bitmap::new(&mut words, 10);
        b.reserve(0, 4);
        b.reserve(2, 4);
        assert_eq!(b.free_count(), 4);
        assert_eq!(b.alloc(1, 1), Some(6));
    }

    #[test]
    fn zero_and_oversized_requests() {
        let mut words = [0u64; 1];
        let mut b = Bitmap::new(&mut words, 4);
        assert_eq!(b.alloc(0, 1), None);
        assert_eq!(b.alloc(5, 1), None);
        let mut empty: [u64; 0] = [];
        let mut e = Bitmap::new(&mut empty, 0);
        assert!(e.is_empty());
        assert_eq!(e.alloc(1, 1), None);
    }

    #[test]
    fn storage_is_cleared() {
        let mut words = [!0u64; 1];
        let b = Bitmap::new(&mut words, 64);
        assert_eq!(b.free_count(), 64);
        assert!(!b.is_used(63));
    }
}
