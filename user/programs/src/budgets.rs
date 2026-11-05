//! What agents use against their budgets and their groups' (D-022 items 4
//! and 5, resources.md, #116). The agent runtime keeps a [`Usage`] per
//! running attempt and a [`GroupUse`] per group; each request is checked
//! against both before anything is charged, so a refused request costs
//! nothing.

use pharos_proto::manifest::{Budget, Group};

/// The resource a request would exceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
    Tokens,
    NetSends,
    NetBytes,
    Data,
    /// Granted files read with `read_file` (#127).
    Files,
    GroupTokens,
    GroupNet,
}

/// A group's shared amount over one minute.
// ponytail: a fixed window from its first use, not a sliding one; up to
// twice the rate across a window's edge. A sliding log if that matters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    start_us: u64,
    used: u64,
}

const MINUTE_US: u64 = 60_000_000;

impl Window {
    /// Whether `amount` more fits `limit` in the minute at `now`.
    pub fn fits(&self, now: u64, limit: u32, amount: u64) -> bool {
        let used = if now.saturating_sub(self.start_us) >= MINUTE_US {
            0
        } else {
            self.used
        };
        used.saturating_add(amount) <= u64::from(limit)
    }

    /// Counts `amount` in the minute at `now`.
    pub fn charge(&mut self, now: u64, amount: u64) {
        if now.saturating_sub(self.start_us) >= MINUTE_US {
            *self = Self {
                start_us: now,
                used: 0,
            };
        }
        self.used = self.used.saturating_add(amount);
    }
}

impl Window {
    /// What this minute has used at `now`.
    pub fn used(&self, now: u64) -> u64 {
        if now.saturating_sub(self.start_us) >= MINUTE_US {
            0
        } else {
            self.used
        }
    }

    /// Gives back `amount` charged in this minute (what a request did not
    /// use, #118); nothing once the minute has passed.
    pub fn refund(&mut self, amount: u64) {
        self.used = self.used.saturating_sub(amount);
    }
}

/// What one group's agents have used this minute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupUse {
    pub tokens: Window,
    pub net: Window,
}

/// What one attempt has used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub tokens: u64,
    pub net_sends: u64,
    pub net_bytes: u64,
    /// Bytes of granted files read (#127).
    pub file_bytes: u64,
}

fn within(used: u64, amount: u64, limit: u32) -> bool {
    used.saturating_add(amount) <= u64::from(limit)
}

impl Usage {
    /// Charges `n` inference tokens, or refuses with what they would
    /// exceed.
    pub fn tokens(
        &mut self,
        budget: &Budget,
        group: Option<(&Group, &mut GroupUse)>,
        now: u64,
        n: u64,
    ) -> Result<(), Over> {
        if !within(self.tokens, n, budget.tokens) {
            return Err(Over::Tokens);
        }
        if let Some((g, u)) = &group {
            if !u.tokens.fits(now, g.tokens_per_min, n) {
                return Err(Over::GroupTokens);
            }
        }
        self.tokens += n;
        if let Some((_, u)) = group {
            u.tokens.charge(now, n);
        }
        Ok(())
    }

    /// Charges reading `bytes` of a granted file, or refuses (#127).
    pub fn read_file(&mut self, budget: &Budget, bytes: u64) -> Result<(), Over> {
        let limit = u64::from(budget.file_kb).saturating_mul(1024);
        if self.file_bytes.saturating_add(bytes) > limit {
            return Err(Over::Files);
        }
        self.file_bytes += bytes;
        Ok(())
    }

    /// Charges one datagram of `bytes`, or refuses with what it would
    /// exceed.
    pub fn send(
        &mut self,
        budget: &Budget,
        group: Option<(&Group, &mut GroupUse)>,
        now: u64,
        bytes: u64,
    ) -> Result<(), Over> {
        if !within(self.net_sends, 1, budget.net_sends) {
            return Err(Over::NetSends);
        }
        if !within(self.net_bytes, bytes, budget.net_bytes) {
            return Err(Over::NetBytes);
        }
        if let Some((g, u)) = &group {
            if !u.net.fits(now, g.net_bytes_per_min, bytes) {
                return Err(Over::GroupNet);
            }
        }
        self.net_sends += 1;
        self.net_bytes += bytes;
        if let Some((_, u)) = group {
            u.net.charge(now, bytes);
        }
        Ok(())
    }
}

/// An attempt's requests over time: `rate` a second, with a burst of
/// `rate` (D-022 item 4: one past it is held, not refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    /// Requests available, in millionths.
    level: u64,
    at_us: u64,
}

const ONE: u64 = 1_000_000;

impl Bucket {
    /// A full bucket at `now`.
    pub fn full(rate: u32, now: u64) -> Self {
        Self {
            level: u64::from(rate).saturating_mul(ONE),
            at_us: now,
        }
    }

    /// Takes one request at `now`; else how many microseconds until one is
    /// there. `u32::MAX` is no limit.
    pub fn take(&mut self, rate: u32, now: u64) -> Result<(), u64> {
        if rate == u32::MAX {
            return Ok(());
        }
        let rate = u64::from(rate);
        let gained = now.saturating_sub(self.at_us).saturating_mul(rate);
        self.level = self
            .level
            .saturating_add(gained)
            .min(rate.saturating_mul(ONE));
        self.at_us = now;
        if self.level >= ONE {
            self.level -= ONE;
            Ok(())
        } else if rate == 0 {
            Err(u64::MAX)
        } else {
            Err((ONE - self.level).div_ceil(rate))
        }
    }
}

impl Usage {
    /// Gives back `n` tokens charged but not used (#118).
    pub fn refund_tokens(&mut self, group: Option<&mut GroupUse>, n: u64) {
        self.tokens = self.tokens.saturating_sub(n);
        if let Some(g) = group {
            g.tokens.refund(n);
        }
    }
}

/// Whether replacing a file of `old` bytes by `new` keeps the agent's
/// files, now `stored` bytes in total, within its `data_kb`.
pub fn data_fits(budget: &Budget, stored: u64, old: u64, new: u64) -> Result<(), Over> {
    let total = stored.saturating_sub(old).saturating_add(new);
    if total <= u64::from(budget.data_kb).saturating_mul(1024) {
        Ok(())
    } else {
        Err(Over::Data)
    }
}

/// Whether one more attempt of `pages` fits `group`, which has `running`
/// attempts whose page limits come to `pages_running`.
pub fn room(group: &Group, running: u32, pages_running: u64, pages: u32) -> bool {
    running < group.agents
        && pages_running.saturating_add(u64::from(pages)) <= u64::from(group.pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITED: Budget = Budget {
        cpu_ms: 100,
        tokens: 40,
        net_sends: 2,
        net_bytes: 64,
        data_kb: 1,
        file_kb: 2,
        rate: 2,
        group: b"g",
    };
    const GROUP: Group = Group {
        name: b"g",
        agents: 1,
        pages: 300,
        tokens_per_min: 30,
        net_bytes_per_min: 48,
    };

    #[test]
    fn an_attempt_stays_within_its_budget() {
        let mut u = Usage::default();
        assert_eq!(u.tokens(&LIMITED, None, 0, 41), Err(Over::Tokens));
        assert_eq!(u.tokens(&LIMITED, None, 0, 40), Ok(()));
        assert_eq!(u.tokens(&LIMITED, None, 0, 1), Err(Over::Tokens));
        assert_eq!(u.send(&LIMITED, None, 0, 40), Ok(()));
        assert_eq!(u.send(&LIMITED, None, 0, 40), Err(Over::NetBytes));
        assert_eq!(u.send(&LIMITED, None, 0, 10), Ok(()));
        assert_eq!(u.send(&LIMITED, None, 0, 1), Err(Over::NetSends));
        assert_eq!((u.net_sends, u.net_bytes), (2, 50), "refusals cost nothing");
    }

    #[test]
    fn granted_files_read_within_the_budget() {
        let mut u = Usage::default();
        assert_eq!(u.read_file(&LIMITED, 2049), Err(Over::Files));
        assert_eq!(u.file_bytes, 0, "a refused read costs nothing");
        assert_eq!(u.read_file(&LIMITED, 2000), Ok(()));
        assert_eq!(u.read_file(&LIMITED, 48), Ok(()));
        assert_eq!(u.read_file(&LIMITED, 1), Err(Over::Files));
        assert_eq!(
            Usage::default().read_file(&Budget::UNLIMITED, u64::from(u32::MAX)),
            Ok(())
        );
    }

    #[test]
    fn a_group_shares_its_minute() {
        let mut g = GroupUse::default();
        let (mut a, mut b) = (Usage::default(), Usage::default());
        let free = Budget::UNLIMITED;
        assert_eq!(a.send(&free, Some((&GROUP, &mut g)), 1, 40), Ok(()));
        assert_eq!(
            b.send(&free, Some((&GROUP, &mut g)), 2, 10),
            Err(Over::GroupNet)
        );
        assert_eq!(b.net_sends, 0, "nothing charged");
        assert_eq!(b.send(&free, Some((&GROUP, &mut g)), 3, 8), Ok(()));
        assert_eq!(
            b.send(&free, Some((&GROUP, &mut g)), 1 + MINUTE_US, 40),
            Ok(()),
            "a new minute"
        );
        assert_eq!(
            a.tokens(&free, Some((&GROUP, &mut g)), 5, 31),
            Err(Over::GroupTokens)
        );
        assert_eq!(a.tokens(&free, Some((&GROUP, &mut g)), 5, 30), Ok(()));
    }

    #[test]
    fn unused_tokens_come_back() {
        let mut g = GroupUse::default();
        let mut u = Usage::default();
        assert_eq!(u.tokens(&LIMITED, Some((&GROUP, &mut g)), 0, 30), Ok(()));
        u.refund_tokens(Some(&mut g), 20);
        assert_eq!(u.tokens, 10);
        assert_eq!(
            u.tokens(&LIMITED, Some((&GROUP, &mut g)), 0, 20),
            Ok(()),
            "the group's too"
        );
        u.refund_tokens(None, 100);
        assert_eq!(u.tokens, 0, "never below zero");
    }

    #[test]
    fn data_counts_the_replaced_file_once() {
        assert_eq!(data_fits(&LIMITED, 0, 0, 600), Ok(()));
        assert_eq!(data_fits(&LIMITED, 600, 0, 600), Err(Over::Data));
        assert_eq!(data_fits(&LIMITED, 600, 600, 300), Ok(()));
        assert_eq!(data_fits(&LIMITED, 300, 0, 724), Ok(()), "exactly 1 KiB");
        assert_eq!(data_fits(&LIMITED, 300, 0, 725), Err(Over::Data));
    }

    #[test]
    fn requests_come_at_the_rate_after_a_burst() {
        let mut b = Bucket::full(2, 0);
        assert_eq!(b.take(2, 0), Ok(()));
        assert_eq!(b.take(2, 0), Ok(()), "a burst of 2");
        assert_eq!(b.take(2, 0), Err(500_000), "the next in half a second");
        assert_eq!(b.take(2, 499_999), Err(1));
        assert_eq!(b.take(2, 500_000), Ok(()));
        assert_eq!(b.take(2, 10_000_000), Ok(()), "refilled, at most 2");
        assert_eq!(b.take(2, 10_000_000), Ok(()));
        assert_eq!(b.take(2, 10_000_000), Err(500_000));
        assert_eq!(Bucket::full(0, 0).take(u32::MAX, 0), Ok(()), "no limit");
    }

    #[test]
    fn a_group_holds_attempts_and_pages() {
        assert!(room(&GROUP, 0, 0, 256));
        assert!(!room(&GROUP, 1, 0, 1), "one attempt at a time");
        let wide = Group { agents: 4, ..GROUP };
        assert!(room(&wide, 1, 256, 44));
        assert!(!room(&wide, 1, 256, 45), "pages together");
    }
}
