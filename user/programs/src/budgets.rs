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
    fn fits(&self, now: u64, limit: u32, amount: u64) -> bool {
        let used = if now.saturating_sub(self.start_us) >= MINUTE_US {
            0
        } else {
            self.used
        };
        used.saturating_add(amount) <= u64::from(limit)
    }

    fn charge(&mut self, now: u64, amount: u64) {
        if now.saturating_sub(self.start_us) >= MINUTE_US {
            *self = Self {
                start_us: now,
                used: 0,
            };
        }
        self.used = self.used.saturating_add(amount);
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
    fn data_counts_the_replaced_file_once() {
        assert_eq!(data_fits(&LIMITED, 0, 0, 600), Ok(()));
        assert_eq!(data_fits(&LIMITED, 600, 0, 600), Err(Over::Data));
        assert_eq!(data_fits(&LIMITED, 600, 600, 300), Ok(()));
        assert_eq!(data_fits(&LIMITED, 300, 0, 724), Ok(()), "exactly 1 KiB");
        assert_eq!(data_fits(&LIMITED, 300, 0, 725), Err(Over::Data));
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
