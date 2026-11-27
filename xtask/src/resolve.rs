//! Actor resolution (#312, identity.md): each audit record's actor, read
//! with its audit client, resolved to a person, an agent and its owner,
//! or a service, from the trail's own records alone, so an auditor's copy
//! of the trail resolves the same way.

use std::collections::{HashMap, HashSet};

use pharos_proto::audit::{action, client, outcome};

/// What resolution reads of one record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    pub client: u8,
    pub action: u8,
    pub actor: String,
    /// 0: not an attempt's (a control client's request).
    pub task: u32,
    pub outcome: u8,
    pub detail: String,
}

/// What the trail has shown so far: people (a login they passed, or a
/// `person add`) and each agent's owner (its last attempt's `start`).
#[derive(Default)]
pub struct Resolver {
    people: HashSet<String>,
    owners: HashMap<String, String>,
    services: HashSet<&'static str>,
}

impl Resolver {
    pub fn new() -> Self {
        let services = (0..)
            .map(pharos_services::table)
            .take_while(|t| !t.is_empty())
            .flatten()
            .map(|s| s.name)
            .collect();
        Self {
            services,
            ..Self::default()
        }
    }

    /// Resolves `r`, the next record of the trail, after learning what it
    /// shows; `Err` says why it does not resolve.
    pub fn resolve(&mut self, r: &Fields) -> Result<String, String> {
        let ok = r.outcome == outcome::OK;
        let after = |prefix: &str| r.detail.strip_prefix(prefix).map(str::to_owned);
        match r.client {
            client::TRUST => {
                let joined = match r.action {
                    action::LOGIN if ok => after("login "),
                    action::IDENTITY if ok => after("person add ")
                        .map(|rest| rest.split(' ').next().unwrap_or("").to_owned()),
                    _ => None,
                };
                self.people.extend(joined);
                match r.actor.as_str() {
                    "console" => Ok("the console, no one logged in".into()),
                    "user" => Ok("the console, before identities".into()),
                    a if self.people.contains(a) => Ok(format!("person {a}")),
                    a => Err(format!("{a} is no person the trail shows")),
                }
            }
            // A control client's request (`submit`), before any attempt:
            // the runtime's own, naming the agent it is for.
            client::RUNTIME if r.task == 0 => Ok(format!(
                "the runtime, for a control client (agent {})",
                r.actor
            )),
            client::RUNTIME => {
                if r.action == action::START {
                    match after("owner ") {
                        Some(owner) if ok => {
                            self.owners.insert(r.actor.clone(), owner);
                        }
                        // A start refused for its owner names no owner;
                        // that is what it records.
                        _ => return Ok(format!("agent {} (refused: {})", r.actor, r.detail)),
                    }
                }
                match self.owners.get(&r.actor) {
                    Some(owner) => Ok(format!("agent {} (owner {owner})", r.actor)),
                    None => Err(format!("agent {} has no start record", r.actor)),
                }
            }
            client::INIT => match r.actor.as_str() {
                "init" => Ok("init".into()),
                a if self.services.contains(a) => Ok(format!("service {a}")),
                a => Err(format!("{a} is no service in init's tables")),
            },
            client::AUDIT => Ok("service audit".into()),
            client::TLS => Ok("service tls".into()),
            client::VAULT => Ok("service vault".into()),
            client::GATEWAY => Ok("service gateway".into()),
            c => Err(format!("client {c} is no audit client")),
        }
    }
}

/// The asks each task put to a person (#329, approval fatigue): one per
/// runtime record that ends one, `approve` or `refuse` with `user`, `no
/// answer`, or `task ended` as its detail; a refusal for any other reason
/// (`no grant`, `malformed`, ...) asked no one. Keyed by agent and task.
pub fn asks<'a>(records: impl IntoIterator<Item = &'a Fields>) -> HashMap<(String, u32), usize> {
    let mut count = HashMap::new();
    for r in records {
        let ended = matches!(r.detail.as_str(), "user" | "no answer" | "task ended");
        if r.client == client::RUNTIME
            && matches!(r.action, action::APPROVE | action::REFUSE)
            && ended
        {
            *count.entry((r.actor.clone(), r.task)).or_default() += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_count_only_what_a_person_answered() {
        let rec = |act, detail: &str, task| Fields {
            client: client::RUNTIME,
            action: act,
            actor: "fetcher".into(),
            task,
            outcome: outcome::OK,
            detail: detail.into(),
        };
        let trail = [
            rec(action::APPROVE, "user", 1),
            rec(action::REFUSE, "no answer", 1),
            rec(action::REFUSE, "user", 1),
            rec(action::REFUSE, "no grant", 1),
            rec(action::REFUSE, "malformed", 1),
            rec(action::GRANT, "user", 1),
            rec(action::REFUSE, "task ended", 2),
            Fields {
                client: client::TRUST,
                ..rec(action::APPROVE, "user", 1)
            },
        ];
        let n = asks(&trail);
        assert_eq!(n.get(&("fetcher".into(), 1)), Some(&3));
        assert_eq!(n.get(&("fetcher".into(), 2)), Some(&1));
    }

    fn rec(client: u8, act: u8, actor: &str, result: u8, detail: &str) -> Fields {
        Fields {
            client,
            action: act,
            actor: actor.into(),
            task: 1,
            outcome: result,
            detail: detail.into(),
        }
    }

    #[test]
    fn people_agents_and_services_resolve_from_the_trail_alone() {
        let mut r = Resolver::new();
        let trail = [
            (
                rec(client::AUDIT, action::BOOT, "audit", 0, ""),
                Ok("service audit"),
            ),
            (
                rec(client::INIT, action::SERVICE, "init", 1, "ready"),
                Ok("init"),
            ),
            (
                rec(client::INIT, action::SERVICE, "tls", 1, "started"),
                Ok("service tls"),
            ),
            (rec(client::INIT, action::SERVICE, "nosuch", 1, ""), Err(())),
            (
                rec(client::TRUST, action::STOP, "console", 0, "all"),
                Ok("the console, no one logged in"),
            ),
            (
                rec(client::TRUST, action::STOP, "user", 0, "all"),
                Ok("the console, before identities"),
            ),
            // Before its login, a name is no person.
            (rec(client::TRUST, action::STOP, "admin", 0, "x"), Err(())),
            // A refused login teaches nothing.
            (
                rec(
                    client::TRUST,
                    action::LOGIN,
                    "console",
                    outcome::REFUSED,
                    "login admin",
                ),
                Ok("the console, no one logged in"),
            ),
            (rec(client::TRUST, action::STOP, "admin", 0, "x"), Err(())),
            (
                rec(
                    client::TRUST,
                    action::LOGIN,
                    "admin",
                    outcome::OK,
                    "login admin",
                ),
                Ok("person admin"),
            ),
            (
                rec(
                    client::TRUST,
                    action::IDENTITY,
                    "admin",
                    outcome::OK,
                    "person add alice roles ops",
                ),
                Ok("person admin"),
            ),
            (
                rec(client::TRUST, action::STOP, "alice", 0, "x"),
                Ok("person alice"),
            ),
            // An agent named like a person is still an agent, and needs
            // its own start record.
            (rec(client::RUNTIME, action::GRANT, "alice", 0, ""), Err(())),
            (
                rec(
                    client::RUNTIME,
                    action::START,
                    "fetcher",
                    outcome::OK,
                    "owner alice",
                ),
                Ok("agent fetcher (owner alice)"),
            ),
            (
                rec(client::RUNTIME, action::GRANT, "fetcher", 0, ""),
                Ok("agent fetcher (owner alice)"),
            ),
            (
                rec(
                    client::RUNTIME,
                    action::START,
                    "orphan",
                    outcome::REFUSED,
                    "no owner nobody",
                ),
                Ok("agent orphan (refused: no owner nobody)"),
            ),
            (
                rec(client::RUNTIME, action::GRANT, "orphan", 0, ""),
                Err(()),
            ),
            (
                rec(client::GATEWAY, action::HTTPS, "fetcher", 0, ""),
                Ok("service gateway"),
            ),
            (rec(9, action::STOP, "x", 0, ""), Err(())),
        ];
        let submit = Fields {
            task: 0,
            ..rec(client::RUNTIME, action::SUBMIT, "keeper", 0, "")
        };
        assert_eq!(
            Resolver::new().resolve(&submit).as_deref(),
            Ok("the runtime, for a control client (agent keeper)")
        );
        for (i, (f, want)) in trail.iter().enumerate() {
            let got = r.resolve(f);
            match want {
                Ok(w) => assert_eq!(got.as_deref(), Ok(*w), "record {i}"),
                Err(()) => assert!(got.is_err(), "record {i}: {got:?}"),
            }
        }
    }
}
