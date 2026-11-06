//! `init`'s restart rules (#150, services.md, D-026): a policy per service
//! table entry, the delay before each restart, and who depends on whom.

use alloc::vec::Vec;

/// What happens when a service crashes, exits, or sends no `ready` in
/// time. A service the user stopped is never restarted, whatever this says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    Never,
    /// Up to this many restarts per boot.
    Up(u8),
}

impl Restart {
    /// Most restarts it allows.
    pub fn limit(self) -> u8 {
        match self {
            Self::Never => 0,
            Self::Up(n) => n,
        }
    }
}

/// The first restart's delay; each later one is 4 times the one before.
pub const FIRST_DELAY_US: u64 = 100_000;

/// How long to wait before restart `done + 1`, in microseconds; `None`
/// once the policy's restarts are used up.
pub fn delay(policy: Restart, done: u8) -> Option<u64> {
    (done < policy.limit()).then(|| FIRST_DELAY_US << (2 * u32::from(done.min(20))))
}

/// The entries that depend on entry `i`, directly or through others, in
/// table order; `after[j]` lists the entries `j` needs.
pub fn dependents(after: &[&[usize]], i: usize) -> Vec<usize> {
    let mut found: Vec<usize> = Vec::new();
    // Entries only depend on earlier ones, so one pass in order finds all.
    for (j, needs) in after.iter().enumerate() {
        if needs.iter().any(|&n| n == i || found.contains(&n)) {
            found.push(j);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_grow_and_end() {
        assert_eq!(delay(Restart::Never, 0), None);
        let up = Restart::Up(3);
        assert_eq!(
            [delay(up, 0), delay(up, 1), delay(up, 2), delay(up, 3)],
            [Some(100_000), Some(400_000), Some(1_600_000), None]
        );
        assert_eq!(delay(Restart::Up(255), 254), Some(FIRST_DELAY_US << 40));
        assert_eq!((Restart::Never.limit(), up.limit()), (0, 3));
    }

    #[test]
    fn dependents_directly_and_through_others() {
        // 0 store; 1 audit and 2 knowledge on it; 3 trust on 1 and 2; 4 on
        // nothing; 5 on 4.
        let after: [&[usize]; 6] = [&[], &[0], &[0], &[1, 2], &[], &[4]];
        assert_eq!(dependents(&after, 0), [1, 2, 3]);
        assert_eq!(dependents(&after, 2), [3]);
        assert_eq!(dependents(&after, 3), [] as [usize; 0]);
        assert_eq!(dependents(&after, 4), [5]);
    }
}
