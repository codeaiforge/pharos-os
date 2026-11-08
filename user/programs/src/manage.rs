//! `init`'s rules for the user's start, stop, and restart of a service
//! (#170, services.md, D-029). `init` only carries out the [`Plan`].

pub use pharos_proto::service::{Action, State};

/// Services that can be restarted but never stopped: stopping one would
/// end the trusted console, the audit trail, or both.
pub use pharos_services::PROTECTED;

/// What `init` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Stop,
    Start,
    StopThenStart,
}

/// Why it does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not in the running table (left off in safe mode or recovery).
    Unknown,
    Protected,
    Running,
    NotRunning,
    /// This entry (a table index), which it needs, does not run.
    Needs(usize),
}

/// The plan for `action` on the service `name` in `state`; `unmet` is the
/// first entry of its `after` that is neither ready nor done.
pub fn decide(
    action: Action,
    name: &str,
    state: State,
    unmet: Option<usize>,
) -> Result<Plan, Refusal> {
    use State::*;
    let runs = matches!(state, Starting | Ready | Restarting);
    let start = || match unmet {
        Some(i) => Err(Refusal::Needs(i)),
        None => Ok(Plan::Start),
    };
    match (action, state) {
        (_, Off) => Err(Refusal::Unknown),
        (Action::Stop, _) if PROTECTED.contains(&name) => Err(Refusal::Protected),
        (Action::Stop, _) if runs => Ok(Plan::Stop),
        (Action::Stop, _) => Err(Refusal::NotRunning),
        (Action::Start, _) if runs => Err(Refusal::Running),
        (Action::Restart, _) if runs => start().map(|_| Plan::StopThenStart),
        (Action::Start | Action::Restart, _) => start(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [State; 10] = [
        State::Pending,
        State::Starting,
        State::Ready,
        State::Done,
        State::Restarting,
        State::Failed,
        State::Skipped,
        State::Stopped,
        State::Off,
        State::NoDevice,
    ];
    const RUNS: [State; 3] = [State::Starting, State::Ready, State::Restarting];

    #[test]
    fn stop_only_what_runs_and_never_a_protected_service() {
        for s in ALL {
            let want = match s {
                State::Off => Err(Refusal::Unknown),
                _ if RUNS.contains(&s) => Ok(Plan::Stop),
                _ => Err(Refusal::NotRunning),
            };
            assert_eq!(decide(Action::Stop, "net", s, None), want, "{s:?}");
            for p in PROTECTED {
                let want = if s == State::Off {
                    Err(Refusal::Unknown)
                } else {
                    Err(Refusal::Protected)
                };
                assert_eq!(decide(Action::Stop, p, s, None), want, "{p} {s:?}");
            }
        }
        // A stop needs nothing to run.
        assert_eq!(
            decide(Action::Stop, "net", State::Ready, Some(0)),
            Ok(Plan::Stop)
        );
    }

    #[test]
    fn start_what_does_not_run_once_its_dependencies_do() {
        for s in ALL {
            let want = match s {
                State::Off => Err(Refusal::Unknown),
                _ if RUNS.contains(&s) => Err(Refusal::Running),
                _ => Ok(Plan::Start),
            };
            assert_eq!(decide(Action::Start, "net", s, None), want, "{s:?}");
            if !RUNS.contains(&s) && s != State::Off {
                assert_eq!(
                    decide(Action::Start, "agents", s, Some(4)),
                    Err(Refusal::Needs(4))
                );
            }
        }
        // Protected services start like any other.
        assert_eq!(
            decide(Action::Start, "audit", State::Failed, None),
            Ok(Plan::Start)
        );
    }

    #[test]
    fn restart_is_a_stop_and_a_start_and_protected_services_restart() {
        for s in ALL {
            let want = match s {
                State::Off => Err(Refusal::Unknown),
                _ if RUNS.contains(&s) => Ok(Plan::StopThenStart),
                _ => Ok(Plan::Start),
            };
            for name in ["net", "trust", "store", "audit"] {
                assert_eq!(decide(Action::Restart, name, s, None), want, "{name} {s:?}");
            }
            if s != State::Off {
                assert_eq!(
                    decide(Action::Restart, "trust", s, Some(5)),
                    Err(Refusal::Needs(5)),
                    "{s:?}"
                );
            }
        }
    }
}
