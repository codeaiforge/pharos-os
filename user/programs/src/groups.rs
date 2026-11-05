//! Which groups coordinate, and who may assign work to whom (#134,
//! coordination.md, D-024 item 2). A group coordinates only if it names a
//! supervisor and a verifier, and the supervisor and every worker have a
//! policy entry naming the group; anything else is a budget-only group.
//! A supervisor delegates only what it holds (#135, D-024 item 3).

use crate::grants::Grants;
use alloc::vec::Vec;
use pharos_proto::manifest::{Entry, Group, Verifier};
use pharos_proto::permission::Permission;

/// True if `g` coordinates: a supervisor, a verifier, and every member's
/// entry (found with `entry`) in the group.
pub fn coordinated<'e>(g: &Group, entry: impl Fn(&[u8]) -> Option<&'e Entry>) -> bool {
    let member = |name: &[u8]| entry(name).is_some_and(|e| e.budget.group == g.name);
    !g.supervisor.is_empty()
        && g.verifier != Verifier::None
        && member(g.supervisor)
        && g.workers.iter().all(|w| member(w) && *w != g.supervisor)
}

/// The coordinated group in which `supervisor` may give `worker` a
/// subtask.
pub fn assigning<'g, 'e>(
    groups: &'g [Group],
    entry: impl Fn(&[u8]) -> Option<&'e Entry> + Copy,
    supervisor: &[u8],
    worker: &[u8],
) -> Option<&'g Group> {
    groups.iter().find(|g| {
        g.supervisor == supervisor && g.workers.contains(&worker) && coordinated(g, entry)
    })
}

/// Each of `wanted` with the deadline it gets: the latest of a grant in
/// `held` (the supervisor's, at `now`) that allows it. The first one not
/// held refuses them all.
pub fn delegable(
    held: &Grants,
    wanted: impl IntoIterator<Item = Permission>,
    now: u64,
) -> Result<Vec<(Permission, Option<u64>)>, Permission> {
    wanted
        .into_iter()
        .map(|p| held.until(&p, now).map(|u| (p, u)).ok_or(p))
        .collect()
}

/// What a subtask's attempt gets when it starts: each of `delegated` its
/// supervisor's running attempt (`held`, `None` if it does not run) still
/// holds at `now`, with that grant's deadline. One no longer held is
/// left out; the rest are given.
pub fn given(
    held: Option<&Grants>,
    delegated: impl IntoIterator<Item = Permission>,
    now: u64,
) -> Vec<(Permission, Option<u64>)> {
    let Some(held) = held else {
        return Vec::new();
    };
    delegated
        .into_iter()
        .filter_map(|p| held.until(&p, now).map(|u| (p, u)))
        .collect()
}

/// Why the verifier refused a result (#137).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unverified {
    /// Not UTF-8, longer than the check allows, or with a control
    /// character other than newline and tab.
    Text,
    /// A subtask of the goal did not end done (so verified).
    Subtask,
}

impl Unverified {
    pub fn detail(self) -> &'static [u8] {
        match self {
            Self::Text => b"not verified: text",
            Self::Subtask => b"not verified: subtask",
        }
    }
}

/// The verifier's check of `result`, given whether every subtask of the
/// task ended done. Reads the result only as bytes; no agent or model
/// decides (D-024 item 4).
pub fn verify(v: Verifier, result: &[u8], subtasks_done: bool) -> Result<(), Unverified> {
    match v {
        Verifier::None => Ok(()),
        Verifier::Text(max) => {
            let text = core::str::from_utf8(result).map_err(|_| Unverified::Text)?;
            let control = text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t');
            if result.len() > max as usize || control {
                Err(Unverified::Text)
            } else if !subtasks_done {
                Err(Unverified::Subtask)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_proto::manifest::{Budget, Data};

    const fn entry(name: &'static [u8], group: &'static [u8]) -> Entry {
        Entry {
            name,
            program: b"bin/testagent",
            pages: 64,
            models: 0,
            attempts: 1,
            progress_ms: 1,
            task_ms: 1,
            data: Data::None,
            ask_models: 0,
            ask_data: Data::None,
            net: &[],
            ask_net: &[],
            budget: Budget {
                group,
                ..Budget::UNLIMITED
            },
            tools: 0,
            files: &[],
            ask_files: &[],
            channels: &[],
        }
    }

    const TABLE: &[Entry] = &[
        entry(b"boss", b"crew"),
        entry(b"helper", b"crew"),
        entry(b"aide", b"crew"),
        entry(b"loner", b""),
    ];
    const CREW: Group = Group {
        name: b"crew",
        agents: 3,
        pages: 1 << 12,
        tokens_per_min: u32::MAX,
        net_bytes_per_min: u32::MAX,
        supervisor: b"boss",
        workers: &[b"helper", b"aide"],
        verifier: Verifier::Text(100),
    };

    fn find(name: &[u8]) -> Option<&'static Entry> {
        TABLE.iter().find(|e| e.name == name)
    }

    #[test]
    fn only_a_complete_group_coordinates() {
        assert!(coordinated(&CREW, find));
        for g in [
            Group {
                supervisor: b"",
                ..CREW
            },
            Group {
                verifier: Verifier::None,
                ..CREW
            },
            Group {
                supervisor: b"loner",
                ..CREW
            },
            Group {
                workers: &[b"helper", b"loner"],
                ..CREW
            },
            Group {
                workers: &[b"helper", b"absent"],
                ..CREW
            },
            Group {
                workers: &[b"boss"],
                ..CREW
            },
        ] {
            assert!(!coordinated(&g, find), "{g:?}");
        }
    }

    #[test]
    fn a_supervisor_assigns_only_its_workers() {
        let groups = [CREW];
        assert_eq!(assigning(&groups, find, b"boss", b"helper"), Some(&CREW));
        assert_eq!(assigning(&groups, find, b"boss", b"aide"), Some(&CREW));
        assert_eq!(
            assigning(&groups, find, b"boss", b"loner"),
            None,
            "not a worker"
        );
        assert_eq!(
            assigning(&groups, find, b"boss", b"boss"),
            None,
            "not itself"
        );
        assert_eq!(
            assigning(&groups, find, b"helper", b"aide"),
            None,
            "a worker assigns nothing"
        );
        let broken = [Group {
            verifier: Verifier::None,
            ..CREW
        }];
        assert_eq!(
            assigning(&broken, find, b"boss", b"helper"),
            None,
            "not coordinated"
        );
    }

    #[test]
    fn only_what_the_supervisor_holds_and_no_longer() {
        let report = Permission::file(b"report.txt").unwrap();
        let mut held = Grants::new(1 << 2, Data::Write, &[], &[b"report.txt"], &[]);
        held.add(Permission::Model(3), Some(500));
        assert_eq!(delegable(&held, [], 0), Ok(Vec::new()), "nothing");
        assert_eq!(
            delegable(
                &held,
                [Permission::Model(2), report, Permission::DataRead],
                0
            ),
            Ok(alloc::vec![
                (Permission::Model(2), None),
                (report, None),
                (Permission::DataRead, None)
            ]),
            "a subset, and data read under data write"
        );
        assert_eq!(
            delegable(&held, [Permission::Model(3)], 0),
            Ok(alloc::vec![(Permission::Model(3), Some(500))]),
            "its source's deadline"
        );
        assert_eq!(
            delegable(&held, [Permission::Model(3)], 500),
            Err(Permission::Model(3)),
            "not past it"
        );
        let other = Permission::file(b"secrets.txt").unwrap();
        assert_eq!(
            delegable(&held, [Permission::Model(2), other], 0),
            Err(other),
            "one wider refuses all"
        );
        let held = Grants::new(0, Data::Read, &[], &[], &[]);
        assert_eq!(
            delegable(&held, [Permission::DataWrite], 0),
            Err(Permission::DataWrite),
            "no write from read"
        );
        assert!(held.allows(&Permission::DataRead, 0));
    }

    #[test]
    fn given_at_start_only_while_still_held() {
        let mut held = Grants::new(1 << 2, Data::None, &[], &[], &[]);
        held.add(Permission::Model(3), Some(500));
        let both = [Permission::Model(2), Permission::Model(3)];
        assert_eq!(
            given(Some(&held), both, 0),
            alloc::vec![
                (Permission::Model(2), None),
                (Permission::Model(3), Some(500))
            ]
        );
        assert_eq!(
            given(Some(&held), both, 500),
            alloc::vec![(Permission::Model(2), None)],
            "the expired one left out"
        );
        held.revoke(&Permission::Model(2));
        assert_eq!(given(Some(&held), both, 500), [], "nor a revoked one");
        assert_eq!(
            given(None, both, 0),
            [],
            "nothing without a running supervisor"
        );
    }

    #[test]
    fn the_verifier_reads_only_bytes() {
        let v = Verifier::Text(12);
        assert_eq!(verify(v, b"", true), Ok(()));
        assert_eq!(
            verify(v, b"boss ok\n\tyes", false),
            Err(Unverified::Subtask)
        );
        assert_eq!(verify(v, "caf\u{e9} ok".as_bytes(), true), Ok(()), "UTF-8");
        assert_eq!(verify(v, b"twelve bytes", true), Ok(()), "at the limit");
        assert_eq!(verify(v, b"thirteen byte", true), Err(Unverified::Text));
        for bad in [
            &b"\x1b[2Jdone"[..],
            b"done\r",
            b"a\0b",
            b"\x7f",
            b"\xff\xfe",
            "\u{85}".as_bytes(),
        ] {
            assert_eq!(verify(v, bad, true), Err(Unverified::Text), "{bad:?}");
        }
        assert_eq!(verify(Verifier::None, b"\x1b", false), Ok(()), "no check");
    }
}
