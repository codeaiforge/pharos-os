//! One task attempt's permissions in the agent runtime (capabilities.md,
//! #105): built from the policy entry and the manifest when the attempt
//! starts, checked on every request that needs one, revocable at any time,
//! and gone at their deadline. Only [`Kept`] outlives the attempt: what
//! the runtime keeps by task, for the task's later attempts.

use crate::tasks::Tasks;
use alloc::vec::Vec;
use pharos_proto::knowledge::SCOPES;
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
    /// `data`, each destination in `net`, each of `files` (#127), a
    /// channel to each of `channels` (#133), and `knowledge read` and
    /// `write` for each bit of `knowledge`'s two masks over
    /// [`SCOPES`] (#144). None of them expires.
    pub fn new(
        models: u32,
        data: Data,
        net: &[Dest],
        files: &[&[u8]],
        channels: &[&[u8]],
        knowledge: (u8, u8),
    ) -> Self {
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
        for (i, scope) in SCOPES.iter().enumerate() {
            for (mask, write) in [(knowledge.0, false), (knowledge.1, true)] {
                if let Some(p) = Permission::knowledge(scope, write).filter(|_| mask & 1 << i != 0)
                {
                    g.add(p, None);
                }
            }
        }
        g
    }

    /// The scopes held for reading at `now`, a bit each over [`SCOPES`]:
    /// what the knowledge service may answer with.
    pub fn readable(&self, now: u64) -> u8 {
        (SCOPES.iter().enumerate())
            .filter(|(_, s)| Permission::knowledge(s, false).is_some_and(|p| self.allows(&p, now)))
            .fold(0, |m, (i, _)| m | 1 << i)
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

    /// The deadline of a grant held at `now` that allows `wanted`, the
    /// latest if several do (`Some(None)`: one without a deadline).
    pub fn until(&self, wanted: &Permission, now: u64) -> Option<Option<u64>> {
        self.list
            .iter()
            .filter(|g| g.permission.covers(wanted) && g.until.is_none_or(|u| now < u))
            .map(|g| g.until)
            .max_by_key(|u| u.unwrap_or(u64::MAX))
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

/// What the agent runtime keeps by task for its later attempts:
/// approvals (#106), revocations, and refusals (also in the task's record,
/// #207).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    /// Revoked, kept for the task's restarts.
    pub revoked: Vec<(u32, Permission)>,
    /// Approved (and until when), kept for its restarts.
    pub approved: Vec<(u32, Permission, Option<u64>)>,
    /// Refused, or not answered: not asked again.
    pub refused: Vec<(u32, Permission)>,
}

impl Kept {
    /// Drops what it keeps for tasks that have ended or are gone, unless
    /// an attempt of one still runs (`running`): no later attempt needs it
    /// (#233). A task not ended keeps everything, as it may run again.
    pub fn prune(&mut self, tasks: &Tasks, running: impl Fn(u32) -> bool) {
        let live = |id: u32| running(id) || tasks.find(id).is_some_and(|i| !tasks.list[i].ended());
        self.revoked.retain(|(t, _)| live(*t));
        self.approved.retain(|(t, ..)| live(*t));
        self.refused.retain(|(t, _)| live(*t));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Files, StoreFailed};
    use pharos_proto::agents::State;
    use std::collections::BTreeMap;

    /// Files in memory.
    #[derive(Default)]
    struct Mem(BTreeMap<Vec<u8>, Vec<u8>>);

    impl Files for Mem {
        fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
            self.0.insert(path.to_vec(), bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed> {
            Ok(self.0.get(path).cloned())
        }
        fn delete(&mut self, path: &[u8]) -> Result<(), StoreFailed> {
            self.0.remove(path);
            Ok(())
        }
        fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed> {
            Ok(self
                .0
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    const NET: Permission = Permission::Net {
        addr: [10, 0, 2, 2],
        port: 47_000,
    };

    #[test]
    fn knowledge_scopes_by_bit() {
        // `notes` (0) and `hr` (2) to read, `notes` to write.
        let mut g = Grants::new(0, Data::None, &[], &[], &[], (0b101, 0b001));
        let read = |s: &[u8]| Permission::knowledge(s, false).unwrap();
        let write = |s: &[u8]| Permission::knowledge(s, true).unwrap();
        assert!(g.allows(&read(b"notes"), 0) && g.allows(&read(b"hr"), 0));
        assert!(g.allows(&write(b"notes"), 0));
        assert!(!g.allows(&read(b"ops"), 0) && !g.allows(&write(b"hr"), 0));
        assert_eq!(g.readable(0), 0b101);
        assert!(g.revoke(&read(b"notes")));
        assert_eq!(g.readable(0), 0b100, "revoked at once");
        assert!(g.allows(&write(b"notes"), 0), "writing stays");
        g.add(read(b"ops"), Some(10));
        assert_eq!(g.readable(9), 0b110);
        assert_eq!(g.readable(10), 0b100, "until its deadline");
    }

    #[test]
    fn built_from_the_entry() {
        let g = Grants::new(1 << 2 | 1 << 31, Data::Read, &[], &[], &[], (0, 0));
        assert!(g.allows(&Permission::Model(2), 0));
        assert!(g.allows(&Permission::Model(31), 0));
        assert!(!g.allows(&Permission::Model(1), 0));
        assert!(g.allows(&Permission::DataRead, 0));
        assert!(!g.allows(&Permission::DataWrite, 0));
        assert!(!g.allows(&NET, 0), "nothing else");
        let g = Grants::new(0, Data::None, &[([10, 0, 2, 2], 47_000)], &[], &[], (0, 0));
        assert!(g.allows(&NET, 0));
        let other = Permission::Net {
            addr: [10, 0, 2, 2],
            port: 47_001,
        };
        assert!(!g.allows(&other, 0), "only that destination");
        assert_eq!(
            Grants::new(1, Data::None, &[], &[], &[], (0, 0)).list(),
            &[],
            "no model 0"
        );
        assert!(
            Grants::new(0, Data::Write, &[], &[], &[], (0, 0)).allows(&Permission::DataRead, 0)
        );
    }

    #[test]
    fn files_one_by_one() {
        let report = Permission::file(b"report.txt").unwrap();
        let notes = Permission::file(b"notes").unwrap();
        let mut g = Grants::new(0, Data::Write, &[], &[b"report.txt", b"notes"], &[], (0, 0));
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
            !Grants::new(0, Data::Write, &[], &[], &[], (0, 0)).allows(&notes, 0),
            "data write reads no granted file"
        );
    }

    #[test]
    fn channels_one_by_one() {
        let listener = Permission::channel(b"listener").unwrap();
        let mut g = Grants::new(
            0,
            Data::None,
            &[],
            &[b"listener"],
            &[b"listener", b"boss"],
            (0, 0),
        );
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
        let mut g = Grants::new(1 << 2 | 1 << 3, Data::Write, &[], &[], &[], (0, 0));
        assert!(g.revoke(&Permission::Model(2)));
        assert!(!g.allows(&Permission::Model(2), 0));
        assert!(g.allows(&Permission::Model(3), 0), "only that one");
        assert!(!g.revoke(&Permission::Model(2)), "not held any more");
        assert!(g.revoke(&Permission::DataRead), "read takes write too");
        assert!(!g.allows(&Permission::DataRead, 0));
        assert!(!g.allows(&Permission::DataWrite, 0));
        let mut g = Grants::new(0, Data::Read, &[], &[], &[], (0, 0));
        assert!(g.revoke(&Permission::DataWrite), "write takes read too");
        assert!(!g.allows(&Permission::DataRead, 0));
    }

    #[test]
    fn the_latest_deadline_that_allows() {
        let mut g = Grants::new(0, Data::None, &[], &[], &[], (0, 0));
        assert_eq!(g.until(&NET, 0), None);
        g.add(NET, Some(100));
        g.add(NET, Some(200));
        assert_eq!(g.until(&NET, 0), Some(Some(200)));
        assert_eq!(g.until(&NET, 200), None, "past both");
        g.add(Permission::DataWrite, None);
        assert_eq!(
            g.until(&Permission::DataRead, 0),
            Some(None),
            "write covers read"
        );
    }

    #[test]
    fn kept_until_the_task_ends_or_is_forgotten() {
        let mut f = Mem::default();
        let (mut tasks, _) = Tasks::load(&mut f, |_| Some(3)).unwrap();
        let [a, b, c, d] =
            [b"a", b"b", b"c", b"d"].map(|n| tasks.submit(&mut f, n, &[], b"").unwrap());
        let mut kept = Kept::default();
        for t in [a, b, c, d, 99] {
            kept.revoked.push((t, Permission::Model(2)));
            kept.approved.push((t, NET, None));
            kept.refused.push((t, Permission::DataWrite));
        }
        // `a` waits, `b` runs, `c` ended while its last attempt still
        // runs, `d` ended and is forgotten, 99 is gone.
        let at = |tasks: &Tasks, id| tasks.find(id).unwrap();
        tasks.start(&mut f, at(&tasks, b)).unwrap();
        for t in [c, d] {
            tasks
                .finish(&mut f, at(&tasks, t), State::Done, b"")
                .unwrap();
        }
        tasks.forget(&mut f, d).unwrap();
        kept.prune(&tasks, |id| id == c);
        assert_eq!(kept.revoked, [a, b, c].map(|t| (t, Permission::Model(2))));
        assert_eq!(kept.approved, [a, b, c].map(|t| (t, NET, None)));
        assert_eq!(kept.refused, [a, b, c].map(|t| (t, Permission::DataWrite)));
        // `c`'s attempt ended too; `a` and `b` have not.
        kept.prune(&tasks, |_| false);
        assert_eq!(kept.revoked, [a, b].map(|t| (t, Permission::Model(2))));
        assert_eq!(kept.approved.len(), 2);
        assert_eq!(kept.refused.len(), 2);
    }

    #[test]
    fn expire_at_their_deadline() {
        let mut g = Grants::new(0, Data::None, &[], &[], &[], (0, 0));
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
