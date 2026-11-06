//! The service tables `init` starts (services.md, D-026, D-027): each
//! entry is a service's manifest, every capability written out as the
//! object, the rights, and the badge it gets, and what it may gain while it
//! runs. `init` grants exactly the entry; the host tests below check the
//! rules every table keeps ([`check`]); the `system` test kernel compares
//! each live service with its entry.
//!
//! `no_std`, no dependencies, `unsafe` forbidden (workspace lint): the
//! kernel's test kernels use it too, as a dev-dependency.

#![no_std]

#[cfg(test)]
extern crate std;

mod tables;

pub use tables::*;

/// Capability rights, as the kernel and `pharos_user::rights` number them
/// (`pharos-programs` tests that they agree).
pub mod rights {
    pub const SEND: u32 = 1;
    pub const RECEIVE: u32 = 1 << 1;
    pub const GRANT: u32 = 1 << 2;
    pub const WRITE: u32 = 1 << 3;
    pub const READ: u32 = 1 << 4;
    pub const MAP: u32 = 1 << 5;
    pub const IRQ: u32 = 1 << 6;
    pub const CONFIG: u32 = 1 << 7;
    pub const WAIT: u32 = 1 << 8;
    pub const STOP: u32 = 1 << 9;
    /// What a driver gets on its device.
    pub const DEVICE: u32 = MAP | CONFIG | IRQ;
}

use rights::*;

/// Most capabilities one `spawn` passes (the kernel's `MAX_SPAWN_CAPS`).
pub const MAX_CAPS: usize = 12;
/// Most entries in a table (one notification bit each).
pub const MAX_SERVICES: usize = 32;

/// An IPv4 address and UDP port (`pharos_proto::net::Dest`).
pub type Dest = ([u8; 4], u16);

/// What happens when a service crashes, exits, or sends no `ready` in
/// time (#150). A service the user stopped is never restarted, whatever
/// this says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    Never,
    /// Up to this many restarts per boot.
    Up(u8),
}

impl Restart {
    /// Most restarts it allows.
    pub fn limit(self) -> u8 {
        match self {
            Self::Never => 0,
            Self::Up(n) => n,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Succeeds by exiting with code 0.
    OneShot,
    /// Succeeds by sending `ready`; must not end.
    Daemon,
}

/// One of `init`'s endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ep {
    /// `init`'s report endpoint: `ready`, and `trust`'s `SERVICES`.
    Events,
    Net,
    Store,
    Infer,
    Trust,
    Agents,
    Audit,
    Knowledge,
}

impl Ep {
    /// The service that receives on it (`None`: `init` itself).
    pub fn receiver(self) -> Option<&'static str> {
        Some(match self {
            Self::Events => return None,
            Self::Net => "net",
            Self::Store => "store",
            Self::Infer => "infer",
            Self::Trust => "trust",
            Self::Agents => "agents",
            Self::Audit => "audit",
            Self::Knowledge => "knowledge",
        })
    }
}

/// What a capability refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    /// The kernel's serial debug console.
    DebugConsole,
    /// The root filesystem.
    Root,
    /// The `nth` device (from 0) with this PCI vendor and device ID.
    Device(u32, u8),
    Endpoint(Ep),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Badge {
    None,
    Fixed(u32),
    /// The entry's index + 1: its report badge on [`Ep::Events`].
    Own,
}

impl Badge {
    /// The badge for entry `index`.
    pub fn value(self, index: usize) -> u32 {
        match self {
            Self::None => 0,
            Self::Fixed(b) => b,
            Self::Own => index as u32 + 1,
        }
    }
}

/// One capability a service gets, in handle order from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Give {
    pub object: Object,
    pub rights: u32,
    pub badge: Badge,
}

/// What a service may hold beyond its [`Give`]s (D-027). Objects it
/// created itself (an endpoint no other process holds, an interrupt
/// object of one of its devices) every service may hold; one-shot reply
/// capabilities live only during a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gain {
    /// Process capabilities with `STOP | WAIT`: `trust` (the runtime and
    /// each agent) and the runtime (its agents).
    Processes,
    /// `SEND` on [`Ep::Agents`] badged `agents::TRUST`, which the runtime
    /// gives `trust` (`CHANNEL`).
    RuntimeChannel,
}

pub struct Service {
    pub name: &'static str,
    pub path: &'static [u8],
    pub arg: u64,
    pub kind: Kind,
    pub restart: Restart,
    /// Its manifest: each capability, in handle order.
    pub caps: &'static [Give],
    /// The destinations its network capability may send to (#109).
    pub net: &'static [Dest],
    /// Indexes of earlier entries that must have succeeded first.
    pub after: &'static [usize],
    /// Pages it may `mem_map` (0: none).
    pub limit: u32,
    pub gains: &'static [Gain],
}

/// `Give` shorthands; each still names the object, rights, and badge.
pub const fn give(object: Object, rights: u32, badge: Badge) -> Give {
    Give {
        object,
        rights,
        badge,
    }
}
/// `WRITE` on the debug console.
pub const CONSOLE: Give = give(Object::DebugConsole, WRITE, Badge::None);
/// `SEND` on `init`'s report endpoint, badged with the entry's number.
pub const REPORT: Give = give(Object::Endpoint(Ep::Events), SEND, Badge::Own);
/// `READ` on the root filesystem.
pub const ROOT: Give = give(Object::Root, READ, Badge::None);
/// `RECEIVE` on `e`: the service itself.
pub const fn receive(e: Ep) -> Give {
    give(Object::Endpoint(e), RECEIVE, Badge::None)
}
/// `SEND` on `e`, badged `badge`.
pub const fn send(e: Ep, badge: u32) -> Give {
    give(Object::Endpoint(e), SEND, Badge::Fixed(badge))
}
/// The driver's rights on the `nth` device with PCI ID `id`.
pub const fn device(id: u32, nth: u8) -> Give {
    give(Object::Device(id, nth), DEVICE, Badge::None)
}

/// A rule a table breaks (services.md, D-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// More entries than notification bits, or more capabilities than
    /// `spawn` passes.
    TooMany,
    /// `after` names this entry or a later one.
    After,
    /// `SEND` on another service's endpoint with badge 0, `init`'s own.
    BadgeZero,
    /// Two capabilities on one endpoint with the same badge.
    SameBadge,
    /// A second receiver, or a receiver other than the service named for
    /// the endpoint.
    Receiver,
    /// `GRANT` without `RECEIVE` on the endpoint.
    Grant,
    /// Rights that do not fit the object: device rights only on devices,
    /// `READ` only on the root, `WRITE` only on the console.
    Rights,
    /// A device given twice.
    SameDevice,
    /// A daemon without exactly one [`REPORT`], or a one-shot with one, or
    /// [`Badge::Own`] anywhere else.
    Report,
}

/// Checks every rule on `table`; the first broken one, with its entry.
pub fn check(table: &[Service]) -> Result<(), (usize, Broken)> {
    if table.len() > MAX_SERVICES {
        return Err((MAX_SERVICES, Broken::TooMany));
    }
    for (i, s) in table.iter().enumerate() {
        let fail = |b| Err((i, b));
        if s.caps.len() > MAX_CAPS {
            return fail(Broken::TooMany);
        }
        if s.after.iter().any(|&a| a >= i) {
            return fail(Broken::After);
        }
        let reports = s.caps.iter().filter(|g| **g == REPORT).count();
        let own = s.caps.iter().filter(|g| g.badge == Badge::Own).count();
        if own != reports || reports != usize::from(s.kind == Kind::Daemon) {
            return fail(Broken::Report);
        }
        for g in s.caps {
            let fits = match g.object {
                Object::DebugConsole => g.rights == WRITE,
                Object::Root => g.rights == READ,
                Object::Device(..) => g.rights == DEVICE,
                Object::Endpoint(_) => g.rights & !(SEND | RECEIVE | GRANT) == 0 && g.rights != 0,
            };
            if !fits {
                return fail(Broken::Rights);
            }
            if g.badge != Badge::None && !matches!(g.object, Object::Endpoint(_)) {
                return fail(Broken::Rights);
            }
            let Object::Endpoint(e) = g.object else {
                continue;
            };
            if g.rights & GRANT != 0 && g.rights & RECEIVE == 0 {
                return fail(Broken::Grant);
            }
            if g.rights & RECEIVE != 0 && e.receiver() != Some(s.name) {
                return fail(Broken::Receiver);
            }
            // Its own endpoint may be unbadged: no one else receives there.
            if g.rights & SEND != 0 && g.badge.value(i) == 0 && g.rights & RECEIVE == 0 {
                return fail(Broken::BadgeZero);
            }
        }
    }
    // Pairs across the table: receivers, badges, devices.
    let all = || (table.iter().enumerate()).flat_map(|(i, s)| s.caps.iter().map(move |g| (i, g)));
    for (n, (i, a)) in all().enumerate() {
        for (j, b) in all().skip(n + 1) {
            if a.object != b.object {
                continue;
            }
            let fail = |r| Err((j, r));
            match a.object {
                Object::Device(..) => return fail(Broken::SameDevice),
                Object::Endpoint(_) if a.rights & b.rights & RECEIVE != 0 => {
                    return fail(Broken::Receiver);
                }
                Object::Endpoint(_)
                    if a.rights & b.rights & SEND != 0 && a.badge.value(i) == b.badge.value(j) =>
                {
                    return fail(Broken::SameBadge);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_keeps_the_rules() {
        for (name, table) in [
            ("boot", BOOT),
            ("test", TEST),
            ("network", NETWORK),
            ("supervision", SUPERVISE),
        ] {
            assert_eq!(check(table), Ok(()), "{name}");
        }
    }

    /// `table` with entry `i`'s capabilities replaced by `caps`.
    fn with(table: &'static [Service], i: usize, caps: &'static [Give]) -> std::vec::Vec<Service> {
        (table.iter().enumerate())
            .map(|(j, s)| Service {
                caps: if i == j { caps } else { s.caps },
                ..*s
            })
            .collect()
    }

    #[test]
    fn a_table_breaking_each_rule_is_refused() {
        const BLK: Give = device(VIRTIO_BLK, 0);
        // BOOT: 0 virtio-blk, 1 net, 2 store, 3 infer, 4 audit, 5
        // knowledge, 6 trust, 7 agents.
        const CASES: [(usize, &[Give], Broken); 11] = [
            // `init`'s own badge on the store.
            (
                3,
                &[CONSOLE, receive(Ep::Infer), REPORT, send(Ep::Store, 0)],
                Broken::BadgeZero,
            ),
            // The audit service's storage badge taken by the inference service.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    send(Ep::Store, AUDIT_TRAIL),
                ],
                Broken::SameBadge,
            ),
            // Receiving on the store's endpoint.
            (3, &[CONSOLE, receive(Ep::Store), REPORT], Broken::Receiver),
            // GRANT to pass on its storage capability.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    give(
                        Object::Endpoint(Ep::Store),
                        SEND | GRANT,
                        Badge::Fixed(MODELS_READ_ONLY),
                    ),
                ],
                Broken::Grant,
            ),
            // The root filesystem written, the console read.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    give(Object::Root, READ | WRITE, Badge::None),
                ],
                Broken::Rights,
            ),
            (
                3,
                &[
                    give(Object::DebugConsole, READ, Badge::None),
                    receive(Ep::Infer),
                    REPORT,
                ],
                Broken::Rights,
            ),
            // The read-only disk to a second driver.
            (
                3,
                &[CONSOLE, receive(Ep::Infer), REPORT, BLK],
                Broken::SameDevice,
            ),
            // A daemon with no report capability, or two.
            (3, &[CONSOLE, receive(Ep::Infer)], Broken::Report),
            (
                3,
                &[CONSOLE, receive(Ep::Infer), REPORT, REPORT],
                Broken::Report,
            ),
            // A one-shot with one.
            (0, &[CONSOLE, BLK, REPORT], Broken::Report),
            // Thirteen capabilities.
            (3, &[CONSOLE; 13], Broken::TooMany),
        ];
        for (i, caps, broken) in CASES {
            let t = with(BOOT, i, caps);
            assert_eq!(check(&t).map_err(|e| e.1), Err(broken), "{caps:?}");
        }
        // `after` naming a later entry.
        let t: std::vec::Vec<Service> = (BOOT.iter().enumerate())
            .map(|(j, s)| Service {
                after: if j == 1 { &[2] } else { s.after },
                ..*s
            })
            .collect();
        assert_eq!(check(&t), Err((1, Broken::After)));
    }

    #[test]
    fn own_badges_are_entry_numbers() {
        assert_eq!(Badge::Own.value(0), 1);
        assert_eq!(Badge::Fixed(7).value(3), 7);
        assert_eq!(Badge::None.value(3), 0);
        assert_eq!((Restart::Never.limit(), Restart::Up(3).limit()), (0, 3));
    }
}
