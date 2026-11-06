//! `init`'s restart rules (#150, services.md, D-026): a policy per service
//! table entry, the delay before each restart, and who depends on whom.

use alloc::vec::Vec;

pub use pharos_services::Restart;

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

/// `text` cut to at most `max` bytes after a `,` or `;` (then ` ...`), so
/// a cut list never ends in part of a name (M4.1 review, F1); `text`
/// itself if it fits, its first `max` bytes if it has no such place.
pub fn cut_list(text: &[u8], max: usize) -> Vec<u8> {
    if text.len() <= max {
        return text.to_vec();
    }
    let room = max.saturating_sub(4);
    match text[..room].iter().rposition(|b| matches!(b, b',' | b';')) {
        Some(i) => [&text[..=i], b" ..."].concat(),
        None => text[..max].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_rights_are_the_kernels() {
        use pharos_services::rights as m;
        use pharos_user::rights as k;
        assert_eq!(
            [
                m::SEND,
                m::RECEIVE,
                m::GRANT,
                m::WRITE,
                m::READ,
                m::MAP,
                m::IRQ,
                m::CONFIG,
                m::WAIT,
                m::STOP
            ],
            [
                k::SEND,
                k::RECEIVE,
                k::GRANT,
                k::WRITE,
                k::READ,
                k::MAP,
                k::IRQ,
                k::CONFIG,
                k::WAIT,
                k::STOP
            ]
        );
    }

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

    #[test]
    fn lists_are_cut_after_a_whole_name() {
        let line = b"restarting 1 of 3 in 100 ms; used by audit, trust, infer, client, holder";
        let cut = cut_list(line, 64);
        assert_eq!(
            cut,
            b"restarting 1 of 3 in 100 ms; used by audit, trust, infer, ..."
        );
        assert!(cut.len() <= 64);
        assert_eq!(cut_list(b"killed 13", 64), b"killed 13");
        assert_eq!(cut_list(&line[..64], 64), &line[..64], "exactly the limit");
        // Only the dependents part is a list.
        assert_eq!(
            cut_list(b"used by audit-and-trust-infer", 12),
            b"used by audi"
        );
        assert_eq!(cut_list(b"ab; cdefgh", 8), b"ab; ...");
        for max in 0..line.len() + 2 {
            let c = cut_list(line, max);
            assert!(c.len() <= max.max(0), "{max}");
            assert!(c.ends_with(b" ...") || line.starts_with(&c) || c.is_empty());
        }
    }
}
