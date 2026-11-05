//! Which groups coordinate, and who may assign work to whom (#134,
//! coordination.md, D-024 item 2). A group coordinates only if it names a
//! supervisor and a verifier, and the supervisor and every worker have a
//! policy entry naming the group; anything else is a budget-only group.

use pharos_proto::manifest::{Entry, Group, Verifier};

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
}
