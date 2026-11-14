//! The audit service's next sequence number (#216, capabilities.md). The
//! store may commit an append whose answer is lost (it crashed, or did not
//! answer within the timeout): after any append that did not answer `OK`,
//! the next sequence is taken from the stream's record count (`STAT`)
//! before another record is written, so no two records share a number.

/// The next sequence number, and whether it may be stale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sequence {
    next: u64,
    unsure: bool,
}

impl Sequence {
    /// The number for the next record: `next`, or, after a failed append,
    /// the stream's record count from `count`. `None` if that is not known
    /// yet (nothing may be written).
    pub fn next(&mut self, count: impl FnOnce() -> Option<u64>) -> Option<u64> {
        if self.unsure {
            self.next = count()?;
            self.unsure = false;
        }
        Some(self.next)
    }

    /// The store took a record and says it is record `number`.
    pub fn stored(&mut self, number: u64) {
        self.next = number + 1;
    }

    /// An append the store did not answer `OK`: it may have been taken.
    pub fn failed(&mut self) {
        self.unsure = true;
    }

    /// Records stored as far as known, for `HEAD`.
    pub fn records(&self) -> u64 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_answer_is_not_a_reused_number() {
        let mut s = Sequence::default();
        assert_eq!(s.next(|| unreachable!()), Some(0));
        s.stored(0);
        assert_eq!(s.next(|| unreachable!()), Some(1), "no look-up when sure");
        // Record 1 committed, its answer lost.
        s.failed();
        assert_eq!(s.next(|| None), None, "the count unknown: nothing written");
        assert_eq!(s.next(|| Some(2)), Some(2), "not 1 again");
        s.stored(2);
        assert_eq!((s.next(|| unreachable!()), s.records()), (Some(3), 3));
        // Not committed after all: the count says so.
        s.failed();
        assert_eq!(s.next(|| Some(3)), Some(3));
    }
}
