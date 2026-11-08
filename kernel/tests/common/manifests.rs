//! The capability audit (#158, D-027, services.md): every live child of
//! `init` holds exactly its manifest, the `pharos_services` table entry
//! `init` started it from, and nothing beyond the gains the entry
//! declares.
//!
//! [`Audit::new`], while every service is up, learns which of `init`'s
//! endpoints is which: the report endpoint is the one most services send
//! on, each service is known by its report badge (its entry's index + 1),
//! and each other endpoint by the service that receives on it. Endpoints
//! outlive restarts, so [`Audit::check`] can run again after faults.
//!
//! A capability is matched to one `Give` (same object, rights, and badge),
//! or to a gain: an endpoint or memory object no other process holds (one
//! it created), an interrupt of one of its devices, a file it opened from
//! its root, a process capability (`Gain::Processes`, at most `STOP |
//! WAIT`, and `GRANT` on one it started), or `trust`'s channel to the runtime (`Gain::RuntimeChannel`).
//! A one-shot reply capability lives only during a call, so a capability
//! is a finding only if it is in each of three snapshots 100 ms apart.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::cap::{self, Capability, MAX_HANDLES, Object};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::sched::{self, TaskId};
use pharos_kernel::{pci, process};
use pharos_services::{Ep, Gain, Object as Is, Service, rights};

const EPS: [Ep; 8] = [
    Ep::Events,
    Ep::Net,
    Ep::Store,
    Ep::Infer,
    Ep::Trust,
    Ep::Agents,
    Ep::Audit,
    Ep::Knowledge,
];

/// A process's capabilities, each with its handle.
type Caps = Vec<(u64, Arc<Capability>)>;

/// Every capability `id` holds, with its handle.
fn caps_of(id: TaskId) -> Caps {
    process::by_id(id).map_or_else(Vec::new, |p| {
        let mut caps = p.caps.lock();
        (1..=MAX_HANDLES as u64)
            .filter_map(|h| caps.get(h, 0).ok().map(|c| (h, c)))
            .collect()
    })
}

/// The live processes `init` started.
fn children(init: TaskId) -> Vec<TaskId> {
    (init + 1..init + 400)
        .filter(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(init)))
        .collect()
}

fn endpoint(c: &Capability) -> Option<&Arc<Endpoint>> {
    match c.object() {
        Object::Endpoint(e) => Some(e),
        _ => None,
    }
}

pub struct Audit<'a> {
    init: TaskId,
    table: &'a [Service],
    /// `init`'s endpoints, as `pharos_services` names them.
    eps: Vec<(Ep, Arc<Endpoint>)>,
    /// `init`'s other endpoints (its reply endpoint): given to no one.
    others: Vec<Arc<Endpoint>>,
}

impl<'a> Audit<'a> {
    /// Learns `init`'s endpoints; `report` is the kernel's own, which
    /// `init` holds too. Every service must be up.
    pub fn new(init: TaskId, report: &Arc<Endpoint>, table: &'a [Service]) -> Result<Self, String> {
        // The kernel and `pharos_services` must number rights alike.
        let same = [
            (cap::SEND, rights::SEND),
            (cap::RECEIVE, rights::RECEIVE),
            (cap::GRANT, rights::GRANT),
            (cap::WRITE, rights::WRITE),
            (cap::READ, rights::READ),
            (cap::MAP, rights::MAP),
            (cap::IRQ, rights::IRQ),
            (cap::CONFIG, rights::CONFIG),
            (cap::WAIT, rights::WAIT),
            (cap::STOP, rights::STOP),
        ];
        if same.iter().any(|(k, m)| k != m) {
            return Err("the kernel's rights differ from pharos_services::rights".into());
        }
        let mut owned: Vec<Arc<Endpoint>> = Vec::new();
        for (_, c) in caps_of(init) {
            if let Some(e) = endpoint(&c) {
                if !Arc::ptr_eq(e, report) && !owned.iter().any(|o| Arc::ptr_eq(o, e)) {
                    owned.push(e.clone());
                }
            }
        }
        let kids: Vec<Caps> = children(init).into_iter().map(caps_of).collect();
        // The report endpoint: the one most services send on.
        let senders = |e: &Arc<Endpoint>| {
            kids.iter()
                .filter(|caps| {
                    caps.iter().any(|(_, c)| {
                        c.rights() & cap::SEND != 0
                            && endpoint(c).is_some_and(|x| Arc::ptr_eq(x, e))
                    })
                })
                .count()
        };
        let events = owned
            .iter()
            .max_by_key(|e| senders(e))
            .cloned()
            .ok_or("init holds no endpoint")?;
        let mut eps = alloc::vec![(Ep::Events, events.clone())];
        // Each other endpoint: the one its receiver holds with RECEIVE.
        for e in EPS.into_iter().skip(1) {
            let Some(index) = e
                .receiver()
                .and_then(|name| table.iter().position(|s| s.name == name))
            else {
                continue;
            };
            let found = kids.iter().find_map(|caps| {
                let mine = caps.iter().any(|(_, c)| {
                    endpoint(c).is_some_and(|x| Arc::ptr_eq(x, &events))
                        && c.badge() == index as u32 + 1
                });
                let receives = caps.iter().find_map(|(_, c)| {
                    let x = endpoint(c)?;
                    (c.rights() & cap::RECEIVE != 0 && owned.iter().any(|o| Arc::ptr_eq(o, x)))
                        .then(|| x.clone())
                });
                if mine { receives } else { None }
            });
            match found {
                Some(x) => eps.push((e, x)),
                None => return Err(format!("no {e:?} endpoint: is its service up?")),
            }
        }
        let others = owned
            .into_iter()
            .filter(|o| !eps.iter().any(|(_, x)| Arc::ptr_eq(x, o)))
            .collect();
        Ok(Self {
            init,
            table,
            eps,
            others,
        })
    }

    /// `init`'s endpoint `e`, as learned.
    #[allow(dead_code)] // Used by the `manage` kernel only.
    pub fn endpoint_of(&self, e: Ep) -> Option<Arc<Endpoint>> {
        self.eps
            .iter()
            .find(|(name, _)| *name == e)
            .map(|(_, x)| x.clone())
    }

    fn ep(&self, e: &Arc<Endpoint>) -> Option<Ep> {
        self.eps
            .iter()
            .find(|(_, x)| Arc::ptr_eq(x, e))
            .map(|(name, _)| *name)
    }

    /// Findings in each of three snapshots 100 ms apart, and each
    /// service's table from the last, one line each.
    pub fn check(&self) -> (Vec<String>, Vec<String>) {
        let mut found = self.snapshot();
        for _ in 0..2 {
            sched::sleep(Duration::from_millis(100));
            let next = self.snapshot();
            found.0.retain(|f| next.0.contains(f));
            found.1 = next.1;
        }
        found
    }

    fn snapshot(&self) -> (Vec<String>, Vec<String>) {
        let (mut findings, mut lines) = (Vec::new(), Vec::new());
        let events = &self.eps[0].1;
        // Every process's capabilities, to tell objects only one holds.
        let everyone: Vec<(TaskId, Caps)> = (1..self.init + 400)
            .filter(|&id| process::by_id(id).is_some())
            .map(|id| (id, caps_of(id)))
            .collect();
        let only = |me: TaskId, same: &dyn Fn(&Object) -> bool| {
            !everyone
                .iter()
                .any(|(id, caps)| *id != me && caps.iter().any(|(_, c)| same(c.object())))
        };
        for id in children(self.init) {
            let caps = caps_of(id);
            let index = caps.iter().find_map(|(_, c)| {
                let on = endpoint(c).is_some_and(|x| Arc::ptr_eq(x, events));
                (on && c.rights() & cap::RECEIVE == 0).then(|| c.badge() as usize)
            });
            let Some(s) = index.and_then(|b| self.table.get(b.wrapping_sub(1))) else {
                findings.push(format!("process {id}: no report capability, so no entry"));
                continue;
            };
            let i = index.unwrap_or(0) - 1;
            let mut matched = alloc::vec![false; s.caps.len()];
            let mut held = Vec::new();
            for (h, c) in &caps {
                let (r, b) = (c.rights(), c.badge());
                let is: Option<Is> = match c.object() {
                    Object::DebugConsole => Some(Is::DebugConsole),
                    Object::Filesystem(_) => Some(Is::Root),
                    Object::Device(d) => {
                        let id = u32::from(d.pci.device) << 16 | u32::from(d.pci.vendor);
                        let same = |x: &Arc<pci::Device>| {
                            x.vendor == d.pci.vendor && x.device == d.pci.device
                        };
                        let nth = (pci::devices().iter().filter(|x| same(x)))
                            .position(|x| Arc::ptr_eq(x, &d.pci));
                        nth.map(|n| Is::Device(id, n as u8))
                    }
                    Object::Endpoint(e) => self.ep(e).map(Is::Endpoint),
                    _ => None,
                };
                let give = is.and_then(|is| {
                    (s.caps.iter().enumerate()).position(|(k, g)| {
                        !matched[k] && g.object == is && g.rights == r && g.badge.value(i) == b
                    })
                });
                if let Some(k) = give {
                    matched[k] = true;
                    held.push(format!("{h} {:?}", s.caps[k].object));
                    continue;
                }
                let (gain, label) = match c.object() {
                    Object::Endpoint(e) if self.ep(e) == Some(Ep::Agents) => (
                        s.gains.contains(&Gain::RuntimeChannel) && r == cap::SEND && b != 0,
                        "runtime channel",
                    ),
                    Object::Endpoint(e) => (
                        !self.others.iter().any(|o| Arc::ptr_eq(o, e))
                            && self.ep(e).is_none()
                            && only(id, &|o| matches!(o, Object::Endpoint(x) if Arc::ptr_eq(x, e))),
                        "own endpoint",
                    ),
                    Object::Memory(m) => (
                        only(id, &|o| matches!(o, Object::Memory(x) if Arc::ptr_eq(x, m))),
                        "own memory",
                    ),
                    Object::Interrupt(q) => (
                        caps.iter().any(|(_, x)| {
                            matches!(x.object(), Object::Device(d) if Arc::ptr_eq(d, &q.device))
                        }),
                        "its device's interrupt",
                    ),
                    // `GRANT` only on a process it started (the runtime gives
                    // `trust` each agent's `STOP | WAIT`; M4.2 review F1).
                    Object::Process(p) => {
                        let mine = process::by_id(p.id).is_some_and(|q| q.parent == Some(id));
                        let allowed = cap::STOP | cap::WAIT | if mine { cap::GRANT } else { 0 };
                        (
                            s.gains.contains(&Gain::Processes) && r & !allowed == 0,
                            "process",
                        )
                    }
                    Object::File { .. } => (
                        r & !cap::READ == 0 && s.caps.iter().any(|g| g.object == Is::Root),
                        "file from its root",
                    ),
                    _ => (false, ""),
                };
                if gain {
                    held.push(format!("{h} {label}"));
                } else {
                    findings.push(format!(
                        "{} (process {id}) holds handle {h}, {:?} rights {r:#x} badge {b}: not in its manifest",
                        s.name,
                        c.object()
                    ));
                }
            }
            for (k, g) in s.caps.iter().enumerate().filter(|(k, _)| !matched[*k]) {
                findings.push(format!("{} lacks entry {k}: {g:?}", s.name));
            }
            lines.push(format!("{}: {}", s.name, held.join(", ")));
        }
        (findings, lines)
    }
}
