//! One task attempt's permissions in the agent runtime (capabilities.md,
//! #105): built from the policy entry and the manifest when the attempt
//! starts, checked on every request that needs one, revocable at any time,
//! and gone at their deadline. Nothing here outlives the attempt.

use alloc::vec::Vec;
use pharos_proto::manifest::{Data, Dest};
use pharos_proto::permission::Permission;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub permission: Permission,
    /// `uptime` microseconds from which it no longer holds.
    pub until: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    list: Vec<Grant>,
}

impl Grants {
    /// What an attempt gets: model `n` for each bit `n` of `models`,
    /// `data`, each destination in `net`, each of `files` (#127), and a
    /// channel to each of `channels` (#133). None of them expires.
    pub fn new(models: u32, data: Data, net: &[Dest], files: &[&[u8]], channels: &[&[u8]]) -> Self {
        let mut g = Self::default();
        for n in 1..=pharos_proto::permission::MAX_MODEL {
            if models & 1 << n != 0 {
                g.add(Permission::Model(n), None);
            }
        }
        match data {
            Data::None => {}
            Data::Read => g.add(Permission::DataRead, None),
            Data::Write => g.add(Permission::DataWrite, None),
        }
        for &(addr, port) in net {
            g.add(Permission::Net { addr, port }, None);
        }
        for p in files.iter().filter_map(|f| Permission::file(f)) {
            g.add(p, None);
        }
        for p in channels.iter().filter_map(|c| Permission::channel(c)) {
            g.add(p, None);
        }
        g
    }

    /// Adds a grant (an approval, #106), until `until` if given.
    pub fn add(&mut self, permission: Permission, until: Option<u64>) {
        self.list.push(Grant { permission, until });
    }

    /// True if a grant held at `now` allows `wanted`.
    pub fn allows(&self, wanted: &Permission, now: u64) -> bool {
        self.list
            .iter()
            .any(|g| g.permission.covers(wanted) && g.until.is_none_or(|u| now < u))
    }

    /// Takes away `permission` and every grant that overlaps it (revoking
    /// `data read` or `data write` takes all data access). Returns true if
    /// any was held.
    pub fn revoke(&mut self, permission: &Permission) -> bool {
        let before = self.list.len();
        self.list
            .retain(|g| !g.permission.covers(permission) && !permission.covers(&g.permission));
        self.list.len() != before
    }

    /// Removes the grants past their deadline at `now` and returns them.
    pub fn expire(&mut self, now: u64) -> Vec<Permission> {
        let (gone, kept): (Vec<Grant>, Vec<Grant>) = core::mem::take(&mut self.list)
            .into_iter()
            .partition(|g| g.until.is_some_and(|u| now >= u));
        self.list = kept;
        gone.into_iter().map(|g| g.permission).collect()
    }

    pub fn list(&self) -> &[Grant] {
        &self.list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Permission = Permission::Net {
        addr: [10, 0, 2, 2],
        port: 47_000,
    };

    #[test]
    fn built_from_the_entry() {
        let g = Grants::new(1 << 2 | 1 << 31, Data::Read, &[], &[], &[]);
        assert!(g.allows(&Permission::Model(2), 0));
        assert!(g.allows(&Permission::Model(31), 0));
        assert!(!g.allows(&Permission::Model(1), 0));
        assert!(g.allows(&Permission::DataRead, 0));
        assert!(!g.allows(&Permission::DataWrite, 0));
        assert!(!g.allows(&NET, 0), "nothing else");
        let g = Grants::new(0, Data::None, &[([10, 0, 2, 2], 47_000)], &[], &[]);
        assert!(g.allows(&NET, 0));
        let other = Permission::Net {
            addr: [10, 0, 2, 2],
            port: 47_001,
        };
        assert!(!g.allows(&other, 0), "only that destination");
        assert_eq!(
            Grants::new(1, Data::None, &[], &[], &[]).list(),
            &[],
            "no model 0"
        );
        assert!(Grants::new(0, Data::Write, &[], &[], &[]).allows(&Permission::DataRead, 0));
    }

    #[test]
    fn files_one_by_one() {
        let report = Permission::file(b"report.txt").unwrap();
        let notes = Permission::file(b"notes").unwrap();
        let mut g = Grants::new(0, Data::Write, &[], &[b"report.txt", b"notes"], &[]);
        assert!(g.allows(&report, 0) && g.allows(&notes, 0));
        assert!(!g.allows(&Permission::file(b"secrets.txt").unwrap(), 0));
        assert!(
            !g.allows(&Permission::file(b"report.tx").unwrap(), 0),
            "the whole name"
        );
        assert!(g.revoke(&report));
        assert!(
            !g.allows(&report, 0) && g.allows(&notes, 0),
            "only that file"
        );
        assert!(
            g.allows(&Permission::DataRead, 0),
            "data is not a file grant"
        );
        assert!(
            !Grants::new(0, Data::Write, &[], &[], &[]).allows(&notes, 0),
            "data write reads no granted file"
        );
    }

    #[test]
    fn channels_one_by_one() {
        let listener = Permission::channel(b"listener").unwrap();
        let mut g = Grants::new(0, Data::None, &[], &[b"listener"], &[b"listener", b"boss"]);
        assert!(g.allows(&listener, 0));
        assert!(!g.allows(&Permission::channel(b"other").unwrap(), 0));
        assert!(g.revoke(&listener));
        assert!(!g.allows(&listener, 0));
        assert!(
            g.allows(&Permission::channel(b"boss").unwrap(), 0),
            "only that channel"
        );
        assert!(
            g.allows(&Permission::file(b"listener").unwrap(), 0),
            "a file of the same name stays"
        );
    }

    #[test]
    fn revoked_at_once() {
        let mut g = Grants::new(1 << 2 | 1 << 3, Data::Write, &[], &[], &[]);
        assert!(g.revoke(&Permission::Model(2)));
        assert!(!g.allows(&Permission::Model(2), 0));
        assert!(g.allows(&Permission::Model(3), 0), "only that one");
        assert!(!g.revoke(&Permission::Model(2)), "not held any more");
        assert!(g.revoke(&Permission::DataRead), "read takes write too");
        assert!(!g.allows(&Permission::DataRead, 0));
        assert!(!g.allows(&Permission::DataWrite, 0));
        let mut g = Grants::new(0, Data::Read, &[], &[], &[]);
        assert!(g.revoke(&Permission::DataWrite), "write takes read too");
        assert!(!g.allows(&Permission::DataRead, 0));
    }

    #[test]
    fn expire_at_their_deadline() {
        let mut g = Grants::new(0, Data::None, &[], &[], &[]);
        g.add(NET, Some(100));
        g.add(Permission::Model(1), None);
        assert!(g.allows(&NET, 99));
        assert!(!g.allows(&NET, 100), "not at the deadline itself");
        assert_eq!(g.expire(99), []);
        assert_eq!(g.expire(100), [NET]);
        assert_eq!(g.expire(1_000), [], "once");
        assert!(g.allows(&Permission::Model(1), u64::MAX), "no deadline");
    }
}
