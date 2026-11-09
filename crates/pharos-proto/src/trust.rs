//! The trusted service's interface, version 1 (agents.md, D-018), and the
//! commands the user types on the trusted path.
//!
//! Messages carry a process capability (`STOP` and `WAIT`) and nothing
//! else is asked of the service:
//! - `RUNTIME` `[version, op]`, from `init` only: the agent runtime;
//! - `REGISTER` `[version, op, slot, name length, name, group length,
//!   group]`, from the runtime only: an agent and its policy entry's group
//!   (empty for none; #136), before the runtime grants it anything.
//!
//! And from the runtime only (#105):
//! - `CHANNEL` `[version, op]`, carrying `SEND` on the runtime's endpoint
//!   badged [`crate::agents::TRUST`], on which `trust` sends `REVOKE`
//!   without ever waiting;
//! - `REVOKED` `[version, op, outcome, name length, name, permission]`,
//!   the runtime's answer to a `REVOKE`, carrying no capability;
//! - `APPROVE` `[version, op, number (2), name length, name, task (4),
//!   permission, for_ms (4)]` (#106): ask the user; `trust` writes the
//!   prompt itself from these fields;
//! - `RESOLVED` `[version, op, number (2), result]`: how request `number`
//!   ended, decided by the runtime (granted, refused, or not answered in
//!   time);
//! - `CONFIRM` `[version, op, number (2), name length, name, task (4),
//!   tool, address (4), port (2), bytes (2)]` (#128, tools.md): ask the
//!   user to confirm one call of a sensitive tool; `trust` writes the
//!   prompt from these fields, never from agent or model text, and the
//!   answer and `RESOLVED` work as for `APPROVE`.
//!
//! And from `init` only:
//! - `SERVICE` (#151): a service event or the system's state;
//! - `OFFER` `[version, op, number (2), refused, name length, name,
//!   version (8), sha256 (8), image, image version (8)]` (#165): an
//!   incoming image the user may apply (`refused` 0, `number` not 0) or
//!   one refused (`refused` 1 + an index into [`image::REASONS`], `number`
//!   0 when it was never offered), with the image running and its version;
//!   `trust` writes the prompt from these fields.
//!
//! The badge says who sends: [`INIT`] or [`RUNTIME`]. There is no reply:
//! the sender's blocking `send` returns once the service has the message,
//! and the service never refuses a valid one (it replaces a slot's entry).

use crate::permission::Permission;
use crate::service::Action;
use crate::{Reader, Refused, Writer, split};

pub const NAME: &[u8] = b"trust";
pub const VERSION: u8 = 1;

/// How long `trust` waits on each call it makes (M4.6 review F1): to
/// `init` (each page of `SERVICES`, `RUNTIME`), to the audit service, to
/// the knowledge service, and for a stopped process to end.
pub const INIT_US: u64 = 1_000_000;
pub const AUDIT_US: u64 = 1_000_000;
pub const KNOWLEDGE_US: u64 = 1_000_000;
pub const STOP_WAIT_US: u64 = 1_000_000;
/// How long `trust` keeps offering a message to the runtime, which may be
/// busy or hung.
pub const RUNTIME_SEND_US: u64 = 2_000_000;
/// How long `init` keeps an event (`SERVICE`) or offer for `trust`, which
/// it never waits on: longer than any one wait above, so an event is not
/// lost while `trust` waits (M4.6 review F1; it was 100 ms).
pub const EVENT_US: u64 = 2_500_000;

/// Operation codes.
pub mod op {
    pub const RUNTIME: u8 = 1;
    pub const REGISTER: u8 = 2;
    pub const CHANNEL: u8 = 3;
    pub const REVOKED: u8 = 4;
    pub const APPROVE: u8 = 5;
    pub const RESOLVED: u8 = 6;
    /// What one running attempt uses, and one group (#119).
    pub const USED: u8 = 7;
    pub const GROUP_USED: u8 = 8;
    /// Confirm one call of a sensitive tool (#128).
    pub const CONFIRM: u8 = 9;
    /// A service event or the system's ready state, from `init` (#151).
    pub const SERVICE: u8 = 10;
    /// An incoming image offered or refused, from `init` (#165).
    pub const OFFER: u8 = 11;
}

/// What happened to a service, or to the system (#151, D-026).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    /// Exited with `numbers[0]`.
    Exited = 0,
    /// Killed by vector `numbers[0]`.
    Killed = 1,
    /// Sent no `ready` within 10 s, so stopped.
    NoReady = 2,
    /// A service it depends on failed.
    Skipped = 3,
    /// Restart `numbers[0]` of `numbers[1]` in `numbers[2]` ms; `names`
    /// are the services that depend on it.
    Restarting = 4,
    /// Not restarted: its restarts are used up.
    GivenUp = 5,
    /// Not restarted: its policy is never.
    Never = 6,
    /// Stopped by the user; never restarted.
    Stopped = 7,
    /// The system is ready: `numbers[0]` services (no name).
    Ready = 8,
    /// The system is not ready: `numbers[0]` failed, `names` (no name).
    NotReady = 9,
    /// Could not be started (#152): `numbers[0]` is a [`not_started`]
    /// reason, and for a spawn error `numbers[1]` its code.
    NotStarted = 10,
    /// The image the system runs (#163, no name): `numbers` are an
    /// [`image`] step, the image, and for a refusal its reason.
    Image = 11,
    /// The user's action on the service (#170): `numbers[0]` a
    /// [`by_user`] code; `names` are its dependents, which keep running.
    ByUser = 12,
    /// A device arrived in a hotplug slot (#171, no name): `numbers` the
    /// slot and the PCI ID (vendor in the low half); `names` the driver
    /// started for it, none if no driver is free.
    DeviceAdded = 13,
    /// A device left its slot (no name): `numbers` as for
    /// [`Self::DeviceAdded`]; `names` the driver stopped first, if any.
    DeviceRemoved = 14,
    /// It answered no health check for `numbers[0]` seconds (M4.5):
    /// stopped, and then handled by its restart policy.
    Unresponsive = 15,
}

/// What [`Event::ByUser`] reports.
pub mod by_user {
    pub const STOPPED: u32 = 0;
    pub const STARTED: u32 = 1;
    pub const RESTARTED: u32 = 2;
    /// A daemon the user started or restarted sent `ready`.
    pub const READY: u32 = 3;
}

/// What [`Event::Image`] reports (boot.md section 8): `numbers[0]` a step,
/// `numbers[1]` the image (0 factory, 1 slot A, 2 slot B), `numbers[2]`
/// for [`REFUSED`](image::REFUSED) an index into [`REASONS`](image::REASONS).
pub mod image {
    /// The services run from the image.
    pub const RUNNING: u32 = 0;
    /// The image failed its checks.
    pub const REFUSED: u32 = 1;
    /// Not every service was ready within 20 s: its services were stopped.
    pub const NOT_READY: u32 = 2;
    /// The boot's mode (#164), the second number: 1 safe, 2 recovery.
    pub const MODE: u32 = 3;
    /// An approved update reached ready (#165): it runs.
    pub const UPDATED: u32 = 4;
    /// An approved update was not ready, or the user rolled back: the
    /// image named runs instead.
    pub const ROLLED_BACK: u32 = 5;

    /// Why a slot was refused: read, record, and mount failures, then
    /// `pharos_image::Error::reason` for each signature check.
    pub const REASONS: &[&[u8]] = &[
        b"cannot be read",
        b"not the image the record names",
        b"filesystem check failed",
        b"no key to verify it with",
        b"truncated",
        b"not a Pharos image",
        b"unknown header version",
        b"reserved bytes set",
        b"image over 16 MiB",
        b"length does not match",
        b"bad signature",
        b"SHA-256 does not match",
        b"version too old",
        // #165: an update with the image of a bad slot.
        b"the image of a bad slot",
        b"changed since it was offered",
        // M4.5: its `etc/system.conf` was refused; the offer's `version`
        // holds the line (0: the whole file).
        b"bad configuration",
    ];

    /// The image's name: `factory image`, `slot A`, `slot B`, `recovery
    /// copy`.
    pub fn name(image: u32) -> &'static [u8] {
        match image {
            1 => b"slot A",
            2 => b"slot B",
            3 => b"recovery copy",
            _ => b"factory image",
        }
    }
}

/// Why a service could not be started ([`Event::NotStarted`]).
pub mod not_started {
    pub const MISSING_PROGRAM: u32 = 0;
    pub const NO_DEVICE: u32 = 1;
    pub const SPAWN_ERROR: u32 = 2;
}

impl Event {
    fn from_code(c: u8) -> Option<Self> {
        use Event::*;
        [
            Exited,
            Killed,
            NoReady,
            Skipped,
            Restarting,
            GivenUp,
            Never,
            Stopped,
            Ready,
            NotReady,
            NotStarted,
            Image,
            ByUser,
            DeviceAdded,
            DeviceRemoved,
            Unresponsive,
        ]
        .get(usize::from(c))
        .copied()
    }

    /// True for the system's state, which names no service.
    pub fn system(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::NotReady | Self::Image | Self::DeviceAdded | Self::DeviceRemoved
        )
    }
}

/// Most names one `SERVICE` lists.
pub const MAX_NAMES: usize = 8;

/// A list of names on the wire: a count, then each name's length and
/// bytes, each a [`valid_name`]. Built with [`Names::build`], read with
/// [`Names::iter`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Names<'a>(&'a [u8]);

impl<'a> Names<'a> {
    /// `names` in wire form in `out`; `None` if one is not a valid name,
    /// there are more than [`MAX_NAMES`], or they do not fit.
    pub fn build(names: &[&[u8]], out: &'a mut [u8]) -> Option<Self> {
        if names.len() > MAX_NAMES || !names.iter().all(|n| valid_name(n)) {
            return None;
        }
        let mut w = Writer::new(out);
        w.bytes(&[names.len() as u8])?;
        for n in names {
            w.bytes(&[n.len() as u8])?;
            w.bytes(n)?;
        }
        let len = w.len();
        Some(Self(&out[..len]))
    }

    fn read(r: &mut Reader<'a>) -> Option<Self> {
        let start: &'a [u8] = r.0;
        let count = usize::from(r.u8()?);
        if count > MAX_NAMES {
            return None;
        }
        // No names reads back as the default, as it was built.
        if count == 0 {
            return Some(Self::default());
        }
        for _ in 0..count {
            let len = usize::from(r.u8()?);
            r.take(len).filter(|n| valid_name(n))?;
        }
        Some(Self(&start[..start.len() - r.0.len()]))
    }

    pub fn iter(self) -> impl Iterator<Item = &'a [u8]> {
        let mut rest = self.0.get(1..).unwrap_or(&[]);
        core::iter::from_fn(move || {
            let (&len, tail) = rest.split_first()?;
            let (name, tail) = tail.split_at(usize::from(len));
            rest = tail;
            Some(name)
        })
    }
}

/// How an approval request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Resolution {
    Granted = 0,
    Refused = 1,
    /// No answer within the runtime's timeout: refused.
    Unanswered = 2,
    /// The task ended first.
    Ended = 3,
}

/// What a `REVOKE` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// Taken from at least one running agent of that name.
    Revoked = 0,
    /// Agents of that name run, but none held it.
    NotHeld = 1,
    /// No agent of that name runs.
    NoAgent = 2,
}

/// The badge `init` sends with: none. `init` created the endpoint and is
/// the only holder of an unbadged `SEND` on it; it grants `trust` only
/// `RECEIVE` and every other sender a badged copy, which cannot be
/// re-badged. (A process cannot badge its own copy: sending it to itself
/// would block.)
pub const INIT: u32 = 0;
/// The badge the agent runtime sends with.
pub const RUNTIME: u32 = 2;
/// Agent slots (the runtime's, agents.md).
pub const SLOTS: u8 = 16;
/// Longest agent name.
pub const MAX_NAME: usize = 32;

/// A valid agent name: 1 to 32 letters, digits, `-`, or `_`.
pub fn valid_name(name: &[u8]) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Runtime,
    Register {
        slot: u8,
        name: &'a [u8],
        /// Its policy entry's group, or empty (#136).
        group: &'a [u8],
    },
    Channel,
    Approve {
        number: u16,
        name: &'a [u8],
        task: u32,
        permission: Permission,
        for_ms: u32,
    },
    Resolved {
        number: u16,
        resolution: Resolution,
    },
    /// One call of tool `tool` (`pharos_proto::tool::number`): for `send`,
    /// `bytes` to `addr:port` (#128).
    Confirm {
        number: u16,
        name: &'a [u8],
        task: u32,
        tool: u8,
        addr: [u8; 4],
        port: u16,
        bytes: u16,
    },
    Revoked {
        outcome: Outcome,
        name: &'a [u8],
        permission: Permission,
    },
    /// What a running attempt has used (#119), from the runtime.
    Used {
        name: &'a [u8],
        task: u32,
        used: Used,
    },
    /// What a group's running attempts hold and used this minute.
    GroupUsed {
        name: &'a [u8],
        running: u32,
        pages: u32,
        tokens: u32,
        bytes: u32,
    },
    /// A service event or the system's state, from `init` (#151): `name`
    /// is the service's table name (empty for the system), and `trust`
    /// writes the line from these fields.
    Service {
        event: Event,
        name: &'a [u8],
        numbers: [u32; 3],
        names: Names<'a>,
    },
    /// An incoming image (#165), from `init`.
    Offer(Offer<'a>),
}

/// An incoming image offered to the user, or refused, as `init` checked
/// it: numbers and its file's name only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer<'a> {
    /// 0 when it was refused before it was offered.
    pub number: u16,
    /// `None` if offered, else an index into [`image::REASONS`].
    pub refused: Option<u8>,
    pub name: &'a [u8],
    pub version: u64,
    pub sha256: [u8; 8],
    /// What runs now (0 factory, 1 A, 2 B, 3 the recovery copy) and its
    /// version (0 for the factory image).
    pub image: u8,
    pub now: u64,
}

/// An attempt's usage, as numbers only: `trust` writes the text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Used {
    pub cpu_ms: u32,
    pub pages: u32,
    pub tokens: u32,
    pub sends: u32,
    pub bytes: u32,
    pub requests: u32,
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = match code {
        op::RUNTIME => Some(Request::Runtime),
        op::REGISTER => (|| {
            let slot = r.u8().filter(|s| *s < SLOTS)?;
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            let len = usize::from(r.u8()?);
            let group = r.take(len).filter(|g| g.is_empty() || valid_name(g))?;
            Some(Request::Register { slot, name, group })
        })(),
        op::CHANNEL => Some(Request::Channel),
        op::APPROVE => (|| {
            let number = r.u16()?;
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            Some(Request::Approve {
                number,
                name,
                task: r.u32()?,
                permission: Permission::read(&mut r)?,
                for_ms: r.u32()?,
            })
        })(),
        op::CONFIRM => (|| {
            let number = r.u16()?;
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            Some(Request::Confirm {
                number,
                name,
                task: r.u32()?,
                tool: r.u8()?,
                addr: r.take(4)?.try_into().ok()?,
                port: r.u16()?,
                bytes: r.u16()?,
            })
        })(),
        op::RESOLVED => (|| {
            let number = r.u16()?;
            let resolution = match r.u8()? {
                0 => Resolution::Granted,
                1 => Resolution::Refused,
                2 => Resolution::Unanswered,
                3 => Resolution::Ended,
                _ => return None,
            };
            Some(Request::Resolved { number, resolution })
        })(),
        op::USED => (|| {
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            let task = r.u32()?;
            let used = Used {
                cpu_ms: r.u32()?,
                pages: r.u32()?,
                tokens: r.u32()?,
                sends: r.u32()?,
                bytes: r.u32()?,
                requests: r.u32()?,
            };
            Some(Request::Used { name, task, used })
        })(),
        op::GROUP_USED => (|| {
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            Some(Request::GroupUsed {
                name,
                running: r.u32()?,
                pages: r.u32()?,
                tokens: r.u32()?,
                bytes: r.u32()?,
            })
        })(),
        op::REVOKED => (|| {
            let outcome = match r.u8()? {
                0 => Outcome::Revoked,
                1 => Outcome::NotHeld,
                2 => Outcome::NoAgent,
                _ => return None,
            };
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            let permission = Permission::read(&mut r)?;
            Some(Request::Revoked {
                outcome,
                name,
                permission,
            })
        })(),
        op::SERVICE => (|| {
            let event = Event::from_code(r.u8()?)?;
            let len = usize::from(r.u8()?);
            let name = r.take(len)?;
            if event.system() != name.is_empty() || !(name.is_empty() || valid_name(name)) {
                return None;
            }
            let numbers = [r.u32()?, r.u32()?, r.u32()?];
            let names = Names::read(&mut r)?;
            Some(Request::Service {
                event,
                name,
                numbers,
                names,
            })
        })(),
        op::OFFER => (|| {
            let number = r.u16()?;
            let refused = match r.u8()? {
                0 => None,
                n if usize::from(n) <= image::REASONS.len() => Some(n - 1),
                _ => return None,
            };
            let len = usize::from(r.u8()?);
            let name = r.take(len).filter(|n| valid_name(n))?;
            let offer = Offer {
                number,
                refused,
                name,
                version: r.u64()?,
                sha256: r.take(8)?.try_into().ok()?,
                image: r.u8().filter(|i| *i <= 3)?,
                now: r.u64()?,
            };
            (refused.is_some() || number != 0).then_some(Request::Offer(offer))
        })(),
        _ => None,
    };
    match req {
        Some(req) if r.is_empty() => Ok(req),
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    match *req {
        Request::Runtime => w.bytes(&[VERSION, op::RUNTIME])?,
        Request::Register { slot, name, group } => {
            if slot >= SLOTS || !valid_name(name) || !(group.is_empty() || valid_name(group)) {
                return None;
            }
            w.bytes(&[VERSION, op::REGISTER, slot, name.len() as u8])?;
            w.bytes(name)?;
            w.bytes(&[group.len() as u8])?;
            w.bytes(group)?;
        }
        Request::Channel => w.bytes(&[VERSION, op::CHANNEL])?,
        Request::Approve {
            number,
            name,
            task,
            permission,
            for_ms,
        } => {
            if !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, op::APPROVE])?;
            w.u16(number)?;
            w.bytes(&[name.len() as u8])?;
            w.bytes(name)?;
            w.u32(task)?;
            permission.write(&mut w)?;
            w.u32(for_ms)?;
        }
        Request::Confirm {
            number,
            name,
            task,
            tool,
            addr,
            port,
            bytes,
        } => {
            if !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, op::CONFIRM])?;
            w.u16(number)?;
            w.bytes(&[name.len() as u8])?;
            w.bytes(name)?;
            w.u32(task)?;
            w.bytes(&[tool])?;
            w.bytes(&addr)?;
            w.u16(port)?;
            w.u16(bytes)?;
        }
        Request::Resolved { number, resolution } => {
            w.bytes(&[VERSION, op::RESOLVED])?;
            w.u16(number)?;
            w.bytes(&[resolution as u8])?;
        }
        Request::Revoked {
            outcome,
            name,
            permission,
        } => {
            if !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, op::REVOKED, outcome as u8, name.len() as u8])?;
            w.bytes(name)?;
            permission.write(&mut w)?;
        }
        Request::Used { name, task, used } => {
            if !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, op::USED, name.len() as u8])?;
            w.bytes(name)?;
            w.u32(task)?;
            for v in [
                used.cpu_ms,
                used.pages,
                used.tokens,
                used.sends,
                used.bytes,
                used.requests,
            ] {
                w.u32(v)?;
            }
        }
        Request::GroupUsed {
            name,
            running,
            pages,
            tokens,
            bytes,
        } => {
            if !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, op::GROUP_USED, name.len() as u8])?;
            w.bytes(name)?;
            for v in [running, pages, tokens, bytes] {
                w.u32(v)?;
            }
        }
        Request::Service {
            event,
            name,
            numbers,
            names,
        } => {
            if event.system() != name.is_empty() || !(name.is_empty() || valid_name(name)) {
                return None;
            }
            w.bytes(&[VERSION, op::SERVICE, event as u8, name.len() as u8])?;
            w.bytes(name)?;
            for v in numbers {
                w.u32(v)?;
            }
            w.bytes(if names.0.is_empty() { &[0] } else { names.0 })?;
        }
        Request::Offer(o) => {
            let refused = match o.refused {
                None if o.number != 0 => 0,
                Some(i) if usize::from(i) < image::REASONS.len() => i + 1,
                _ => return None,
            };
            if !valid_name(o.name) || o.image > 3 {
                return None;
            }
            w.bytes(&[VERSION, op::OFFER])?;
            w.u16(o.number)?;
            w.bytes(&[refused, o.name.len() as u8])?;
            w.bytes(o.name)?;
            w.u64(o.version)?;
            w.bytes(&o.sha256)?;
            w.bytes(&[o.image])?;
            w.u64(o.now)?;
        }
    }
    Some(w.len())
}

/// A command typed on the trusted path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// `list`: the registered agents and whether each runs.
    List,
    /// `stop <agent>`.
    Stop(&'a [u8]),
    /// `stop all`: the runtime, so every agent (the emergency stop).
    StopAll,
    /// `stop group <name>`: every agent registered in that group (#136).
    StopGroup(&'a [u8]),
    /// `start <service>`, `restart <service>`, and `stop service
    /// <service>` (#170): `init`'s table names.
    Manage(Action, &'a [u8]),
    /// `revoke <agent> <permission>` (#105).
    Revoke(&'a [u8], Permission),
    /// `yes <n>` or `no <n>`: the answer to approval request `n` (#106).
    Answer(u16, bool),
    /// `audit`: the audit trail's boot, record count, and chain head (#107).
    Audit,
    /// `usage`: what the runtime, each running agent, and each group use
    /// (#119).
    Usage,
    /// `verify <scope> <key> <version> <hash>`: marks a knowledge version
    /// verified (#144); `hash` is the first 8 hexadecimal digits of its
    /// content's SHA-256, as 4 bytes.
    Verify {
        scope: &'a [u8],
        key: &'a [u8],
        version: u32,
        prefix: [u8; 4],
    },
    /// `services`: each service's state, from `init` (#152).
    Services,
    /// `health`: each service's state, uptime, and last health check,
    /// and each agent's process (M4.5).
    Health,
    /// `config`: the configuration in use (M4.5).
    Config,
    /// `system`: the mode, the image running, and each slot, from `init`
    /// (#164).
    System,
    /// `safe` or `recovery`: that mode for the next boot (#164); the
    /// mode's code (1 or 2).
    NextBoot(u8),
    /// `update`: check and offer the incoming images (#165).
    Update,
    /// `apply <n>` or `discard <n>`: the answer to update offer `n`.
    UpdateAnswer(u16, bool),
    /// `rollback`: back to the other slot, if it is good.
    Rollback,
    /// Anything else: the service answers with the commands it knows.
    Help,
}

/// Parses one line (without its newline). Spaces around words are
/// ignored; anything else is [`Command::Help`].
pub fn command(line: &[u8]) -> Command<'_> {
    let mut words = line
        .split(|b| *b == b' ' || *b == b'\t')
        .filter(|w| !w.is_empty());
    let mut all: [&[u8]; 5] = [b""; 5];
    let mut count = 0;
    for w in words.clone() {
        if count == all.len() {
            return Command::Help;
        }
        all[count] = w;
        count += 1;
    }
    if let [b"verify", scope, key, version, hash] = &all[..count] {
        return match (version_number(version), hash_prefix(hash)) {
            (Some(version), Some(prefix)) if valid_name(scope) && valid_name(key) => {
                Command::Verify {
                    scope,
                    key,
                    version,
                    prefix,
                }
            }
            _ => Command::Help,
        };
    }
    if let [b"revoke", name, rest @ ..] = &all[..count] {
        return match Permission::parse(rest) {
            Some(p) if valid_name(name) => Command::Revoke(name, p),
            _ => Command::Help,
        };
    }
    match (words.next(), words.next(), words.next()) {
        (Some(b"list"), None, None) => Command::List,
        (Some(b"audit"), None, None) => Command::Audit,
        (Some(b"usage"), None, None) => Command::Usage,
        (Some(b"services"), None, None) => Command::Services,
        (Some(b"health"), None, None) => Command::Health,
        (Some(b"config"), None, None) => Command::Config,
        (Some(b"system"), None, None) => Command::System,
        (Some(b"safe"), None, None) => Command::NextBoot(1),
        (Some(b"recovery"), None, None) => Command::NextBoot(2),
        (Some(b"update"), None, None) => Command::Update,
        (Some(b"rollback"), None, None) => Command::Rollback,
        (Some(word @ (b"apply" | b"discard")), Some(n), None) => match request_number(n) {
            Some(n) => Command::UpdateAnswer(n, word == b"apply"),
            None => Command::Help,
        },
        (Some(b"stop"), Some(b"all"), None) => Command::StopAll,
        (Some(b"stop"), Some(b"service"), Some(name))
            if valid_name(name) && words.next().is_none() =>
        {
            Command::Manage(Action::Stop, name)
        }
        (Some(b"start"), Some(name), None) if valid_name(name) => {
            Command::Manage(Action::Start, name)
        }
        (Some(b"restart"), Some(name), None) if valid_name(name) => {
            Command::Manage(Action::Restart, name)
        }
        (Some(b"stop"), Some(b"group"), Some(name))
            if valid_name(name) && words.next().is_none() =>
        {
            Command::StopGroup(name)
        }
        (Some(b"stop"), Some(name), None) if valid_name(name) => Command::Stop(name),
        (Some(word @ (b"yes" | b"no")), Some(n), None) => match request_number(n) {
            Some(n) => Command::Answer(n, word == b"yes"),
            None => Command::Help,
        },
        _ => Command::Help,
    }
}

/// An approval request's number: 1 to 65535, no leading zero.
fn request_number(v: &[u8]) -> Option<u16> {
    if v.is_empty() || v.len() > 5 || v[0] == b'0' || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = v.iter().fold(0u32, |n, b| n * 10 + u32::from(b - b'0'));
    u16::try_from(n).ok()
}

/// A version number: 1 to `u32::MAX`, no leading zero.
fn version_number(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 10 || v[0] == b'0' || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = v.iter().fold(0u64, |n, b| n * 10 + u64::from(b - b'0'));
    u32::try_from(n).ok()
}

/// Exactly 8 hexadecimal digits, either case.
fn hash_prefix(v: &[u8]) -> Option<[u8; 4]> {
    let digit = |b: u8| char::from(b).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 4];
    if v.len() != 8 {
        return None;
    }
    for (o, pair) in out.iter_mut().zip(v.chunks_exact(2)) {
        *o = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// Collects typed bytes into lines of at most [`Lines::MAX`] bytes. A line
/// ends at `\n` or `\r`; other control bytes are dropped; a longer line is
/// thrown away whole and reported as [`Line::TooLong`].
pub struct Lines {
    buf: [u8; Lines::MAX],
    len: usize,
    over: bool,
}

/// What one typed byte completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line {
    None,
    Done(usize),
    TooLong,
}

impl Lines {
    pub const MAX: usize = 64;

    pub const fn new() -> Self {
        Self {
            buf: [0; Self::MAX],
            len: 0,
            over: false,
        }
    }

    /// The line a [`Line::Done`] of length `n` completed (valid until the
    /// next [`Self::push`]).
    pub fn line(&self, n: usize) -> &[u8] {
        &self.buf[..n.min(Self::MAX)]
    }

    /// Adds `b`.
    pub fn push(&mut self, b: u8) -> Line {
        match b {
            b'\n' | b'\r' => {
                let (len, over) = (self.len, self.over);
                self.len = 0;
                self.over = false;
                match (over, len) {
                    (true, _) => Line::TooLong,
                    (false, 0) => Line::None,
                    (false, n) => Line::Done(n),
                }
            }
            b' '..=b'~' | b'\t' if !self.over => {
                if self.len == Self::MAX {
                    self.over = true;
                } else {
                    self.buf[self.len] = b;
                    self.len += 1;
                }
                Line::None
            }
            _ => Line::None,
        }
    }
}

impl Default for Lines {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `init` offers each event longer than `trust` ever waits (M4.6
    /// review F1).
    #[test]
    fn init_outlasts_every_wait_of_trust() {
        for wait in [
            INIT_US,
            AUDIT_US,
            KNOWLEDGE_US,
            STOP_WAIT_US,
            RUNTIME_SEND_US,
        ] {
            assert!(EVENT_US > wait, "{EVENT_US} <= {wait}");
        }
    }

    #[test]
    fn requests_round_trip() {
        let long = [b'a'; MAX_NAME];
        for req in [
            Request::Runtime,
            Request::Register {
                slot: 0,
                name: b"summarize",
                group: b"",
            },
            Request::Register {
                slot: SLOTS - 1,
                name: &long,
                group: &long,
            },
            Request::Channel,
            Request::Used {
                name: &long,
                task: u32::MAX,
                used: Used {
                    cpu_ms: 1,
                    pages: 2,
                    tokens: 3,
                    sends: 4,
                    bytes: 5,
                    requests: u32::MAX,
                },
            },
            Request::GroupUsed {
                name: b"pair",
                running: 1,
                pages: 64,
                tokens: 0,
                bytes: u32::MAX,
            },
            Request::Approve {
                number: 3,
                name: b"asker",
                task: 12,
                permission: Permission::Model(2),
                for_ms: 2_000,
            },
            Request::Resolved {
                number: u16::MAX,
                resolution: Resolution::Ended,
            },
            Request::Confirm {
                number: 4,
                name: &long,
                task: u32::MAX,
                tool: 2,
                addr: [10, 0, 2, 2],
                port: 47_000,
                bytes: 248,
            },
            Request::Revoked {
                outcome: Outcome::NotHeld,
                name: b"worker",
                permission: Permission::DataWrite,
            },
            Request::Revoked {
                outcome: Outcome::NoAgent,
                name: &long,
                permission: Permission::Net {
                    addr: [1, 2, 3, 4],
                    port: 9,
                },
            },
        ] {
            let mut buf = [0u8; 80];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(req));
            assert_eq!(parse(&buf[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
            assert!(parse(&buf[..n - 1]).is_err(), "{req:?} truncated");
            let mut other = buf;
            other[0] = VERSION + 1;
            assert_eq!(parse(&other[..n]), Err(Refused::Version));
        }
    }

    #[test]
    fn service_events_round_trip_and_bad_ones_are_refused() {
        let long = [b'a'; MAX_NAME];
        let mut wire = [0u8; 300];
        let eight: [&[u8]; 8] = [
            &long,
            &long,
            &long,
            b"d",
            b"e",
            b"f",
            b"g",
            b"after-crasher",
        ];
        let names = Names::build(&eight, &mut wire).unwrap();
        assert_eq!(names.iter().collect::<std::vec::Vec<_>>(), eight);
        let ev = |event, name, names| Request::Service {
            event,
            name,
            numbers: [1, u32::MAX, 1600],
            names,
        };
        let mut few = [0u8; 40];
        let two = Names::build(&[b"infer", b"client"], &mut few).unwrap();
        for req in [
            ev(Event::Restarting, &b"store"[..], names),
            ev(Event::Restarting, b"store", two),
            ev(Event::Killed, &long, Names::default()),
            ev(Event::Ready, b"", Names::default()),
            ev(Event::NotReady, b"", two),
            ev(Event::NotStarted, b"missing", Names::default()),
            ev(Event::Image, b"", Names::default()),
            ev(Event::ByUser, b"knowledge", two),
            ev(Event::DeviceAdded, b"", two),
            ev(Event::DeviceRemoved, b"", Names::default()),
        ] {
            let mut buf = [0u8; 256];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(req));
            assert_eq!(parse(&buf[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
            for cut in 0..n {
                assert!(parse(&buf[..cut]).is_err(), "{req:?} cut at {cut}");
            }
        }
        let nine: [&[u8]; 9] = [b"a"; 9];
        assert_eq!(Names::build(&nine, &mut [0; 40]), None, "nine names");
        assert_eq!(Names::build(&[b"a b"], &mut [0; 40]), None, "a space");
        for bad in [
            ev(Event::Ready, b"store", Names::default()),
            ev(Event::Exited, b"", Names::default()),
            ev(Event::Exited, b"a b", Names::default()),
        ] {
            assert_eq!(encode(&bad, &mut [0; 256]), None, "{bad:?}");
        }
        // On the wire: an unknown event, nine names, and a bad listed name.
        let msg = |event: u8, list: &[u8]| {
            let mut m = std::vec![VERSION, op::SERVICE, event, 1, b's'];
            m.extend_from_slice(&[0; 12]);
            m.extend_from_slice(list);
            m
        };
        assert!(parse(&msg(4, &[1, 1, b'a'])).is_ok());
        assert_eq!(parse(&msg(11, &[0])), Err(Refused::Bad), "event 11");
        assert!(parse(&msg(12, &[0])).is_ok(), "event 12");
        assert_eq!(
            parse(&msg(14, &[0])),
            Err(Refused::Bad),
            "a device event with a name"
        );
        assert!(parse(&msg(15, &[0])).is_ok(), "event 15");
        assert_eq!(parse(&msg(16, &[0])), Err(Refused::Bad), "event 16");
        let mut many = std::vec![9];
        for _ in 0..9 {
            many.extend_from_slice(&[1, b'a']);
        }
        assert_eq!(parse(&msg(4, &many)), Err(Refused::Bad), "nine names");
        assert_eq!(parse(&msg(4, &[1, 3, b'a', b' ', b'b'])), Err(Refused::Bad));
        crate::fuzz(100_000, 6, |m| {
            let mut v = std::vec![VERSION, op::SERVICE];
            v.extend_from_slice(m);
            if let Ok(Request::Service {
                event, name, names, ..
            }) = parse(&v)
            {
                assert!(event.system() == name.is_empty());
                assert!(names.iter().all(valid_name) && names.iter().count() <= MAX_NAMES);
            }
        });
    }

    #[test]
    fn offers_round_trip_and_bad_ones_are_refused() {
        let offered = Offer {
            number: 7,
            refused: None,
            name: b"summarize-1",
            version: u64::MAX,
            sha256: [0xab; 8],
            image: 1,
            now: 6,
        };
        let refused = Offer {
            number: 0,
            refused: Some(image::REASONS.len() as u8 - 1),
            ..offered
        };
        for o in [offered, refused] {
            let mut buf = [0u8; 256];
            let n = encode(&Request::Offer(o), &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(Request::Offer(o)));
            for cut in 0..n {
                assert!(parse(&buf[..cut]).is_err(), "cut at {cut}");
            }
        }
        let mut buf = [0u8; 256];
        for bad in [
            Offer {
                number: 0,
                ..offered
            },
            Offer {
                refused: Some(image::REASONS.len() as u8),
                ..offered
            },
            Offer {
                name: b"a/b",
                ..offered
            },
            Offer {
                image: 4,
                ..offered
            },
        ] {
            assert_eq!(encode(&Request::Offer(bad), &mut buf), None, "{bad:?}");
        }
        let n = encode(&Request::Offer(offered), &mut buf).unwrap();
        // On the wire: a reason past the list, an offer numbered 0, an
        // unknown image.
        for (at, value) in [(4, image::REASONS.len() as u8 + 1), (2, 0), (n - 9, 4)] {
            let mut b = buf;
            if at == 2 {
                b[3] = 0;
            }
            b[at] = value;
            assert_eq!(parse(&b[..n]), Err(Refused::Bad), "byte {at} = {value}");
        }
        crate::fuzz(100_000, 11, |m| {
            let _ = parse(m);
        });
    }

    #[test]
    fn bad_requests_are_refused() {
        let reg_in = |slot: u8, name: &[u8], group: &[u8]| {
            let mut m = std::vec![VERSION, op::REGISTER, slot, name.len() as u8];
            m.extend_from_slice(name);
            m.push(group.len() as u8);
            m.extend_from_slice(group);
            m
        };
        let reg = |slot: u8, name: &[u8]| reg_in(slot, name, b"");
        assert!(parse(&reg(0, b"a")).is_ok());
        assert_eq!(
            parse(&reg_in(0, b"a", b"a b")),
            Err(Refused::Bad),
            "bad group"
        );
        assert_eq!(
            parse(&reg_in(0, b"a", &[b'g'; 33])),
            Err(Refused::Bad),
            "long group"
        );
        assert_eq!(
            parse(&reg(0, b"a")[..5]),
            Err(Refused::Bad),
            "no group length"
        );
        assert_eq!(parse(&reg(SLOTS, b"a")), Err(Refused::Bad), "slot 16");
        assert_eq!(parse(&reg(0, b"")), Err(Refused::Bad), "empty name");
        assert_eq!(parse(&reg(0, &[b'a'; 33])), Err(Refused::Bad), "long name");
        assert_eq!(parse(&reg(0, b"a b")), Err(Refused::Bad), "space");
        assert_eq!(parse(&reg(0, b"a\n")), Err(Refused::Bad), "newline");
        assert_eq!(parse(&[VERSION, 9]), Err(Refused::Bad), "unknown op");
        let mut revoked = std::vec![VERSION, op::REVOKED, 3, 1, b'w'];
        revoked.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0]);
        assert_eq!(parse(&revoked), Err(Refused::Bad), "unknown outcome");
        let bad = Request::Register {
            slot: 0,
            name: b"x y",
            group: b"",
        };
        assert_eq!(encode(&bad, &mut [0; 80]), None);
        let bad = Request::Register {
            slot: 0,
            name: b"x",
            group: b"x\n",
        };
        assert_eq!(encode(&bad, &mut [0; 80]), None);
        crate::fuzz(100_000, 6, |m| {
            let mut v = [0u8; 302];
            v[0] = VERSION;
            v[1..1 + m.len()].copy_from_slice(m);
            if let Ok(Request::Register { name, slot, group }) = parse(&v[..1 + m.len()]) {
                assert!(valid_name(name) && slot < SLOTS);
                assert!(group.is_empty() || valid_name(group));
            }
            let _ = parse(m);
            let _ = command(m);
        });
    }

    #[test]
    fn commands_parse() {
        assert_eq!(command(b"list"), Command::List);
        assert_eq!(command(b"  list "), Command::List);
        assert_eq!(command(b"stop all"), Command::StopAll);
        assert_eq!(command(b"stop\tworker-1"), Command::Stop(b"worker-1"));
        assert_eq!(command(b"stop group crew"), Command::StopGroup(b"crew"));
        assert_eq!(
            command(b"stop group"),
            Command::Stop(b"group"),
            "an agent named group"
        );
        assert_eq!(command(b"stop group a b"), Command::Help);
        assert_eq!(
            command(b" stop  service net "),
            Command::Manage(Action::Stop, b"net")
        );
        assert_eq!(
            command(b"stop service"),
            Command::Stop(b"service"),
            "an agent named service"
        );
        assert_eq!(
            command(b"start knowledge"),
            Command::Manage(Action::Start, b"knowledge")
        );
        assert_eq!(
            command(b"restart trust"),
            Command::Manage(Action::Restart, b"trust")
        );
        for bad in [
            &b"start"[..],
            b"restart",
            b"start a b",
            b"restart a;b",
            b"stop service a b",
            b"stop service a;b",
            b"Start net",
        ] {
            assert_eq!(command(bad), Command::Help, "{bad:?}");
        }
        assert_eq!(command(b"stop group a;b"), Command::Help);
        assert_eq!(command(b"yes 3"), Command::Answer(3, true));
        assert_eq!(command(b"audit"), Command::Audit);
        assert_eq!(command(b" usage "), Command::Usage);
        assert_eq!(command(b"usage all"), Command::Help);
        assert_eq!(command(b" services "), Command::Services);
        assert_eq!(command(b"health"), Command::Health);
        assert_eq!(command(b"config"), Command::Config);
        assert_eq!(command(b"config net"), Command::Help);
        assert_eq!(command(b"services x"), Command::Help);
        assert_eq!(command(b" system "), Command::System);
        assert_eq!(command(b"system a"), Command::Help);
        assert_eq!(command(b"safe"), Command::NextBoot(1));
        assert_eq!(command(b" recovery"), Command::NextBoot(2));
        assert_eq!(command(b"safe mode"), Command::Help);
        assert_eq!(command(b" update "), Command::Update);
        assert_eq!(command(b"update 1"), Command::Help);
        assert_eq!(command(b"rollback"), Command::Rollback);
        assert_eq!(command(b"rollback A"), Command::Help);
        assert_eq!(command(b"apply 3"), Command::UpdateAnswer(3, true));
        assert_eq!(
            command(b"discard 65535"),
            Command::UpdateAnswer(65_535, false)
        );
        for bad in [
            &b"apply"[..],
            b"apply 0",
            b"apply 01",
            b"discard x",
            b"apply 1 2",
        ] {
            assert_eq!(command(bad), Command::Help, "{bad:?}");
        }
        assert_eq!(command(b"stop safe"), Command::Stop(b"safe"));
        assert_eq!(command(b"audit x"), Command::Help);
        assert_eq!(command(b" no  65535"), Command::Answer(65_535, false));
        assert_eq!(
            command(b"revoke worker model 2"),
            Command::Revoke(b"worker", Permission::Model(2))
        );
        assert_eq!(
            command(b" revoke  w  net 10.0.2.2:47000 "),
            Command::Revoke(
                b"w",
                Permission::Net {
                    addr: [10, 0, 2, 2],
                    port: 47_000
                }
            )
        );
        assert_eq!(
            command(b"verify notes vendor 3 0aB1c2D3"),
            Command::Verify {
                scope: b"notes",
                key: b"vendor",
                version: 3,
                prefix: [0x0a, 0xb1, 0xc2, 0xd3],
            }
        );
        assert_eq!(
            command(b"revoke w knowledge read notes"),
            Command::Revoke(b"w", Permission::knowledge(b"notes", false).unwrap())
        );
        for line in [
            &b""[..],
            b"verify notes vendor 3",
            b"verify notes vendor 0 0ab1c2d3",
            b"verify notes vendor 03 0ab1c2d3",
            b"verify notes vendor 4294967296 0ab1c2d3",
            b"verify notes vendor 3 0ab1c2d",
            b"verify notes vendor 3 0ab1c2d3e",
            b"verify notes vendor 3 0ab1c2dg",
            b"verify no;tes vendor 3 0ab1c2d3",
            b"verify notes ven/dor 3 0ab1c2d3",
            b"lis",
            b"list x",
            b"stop",
            b"stop a b",
            b"stop wor;ker",
            b"STOP all",
            b"revoke worker",
            b"revoke worker model",
            b"revoke worker model 0",
            b"revoke wor;ker data read",
            b"revoke worker data read extra",
            b"yes",
            b"yes 0",
            b"yes 03",
            b"no 65536",
            b"yes 1 2",
            b"Yes 1",
        ] {
            assert_eq!(command(line), Command::Help, "{line:?}");
        }
    }

    #[test]
    fn lines_collect_and_bound() {
        let mut l = Lines::new();
        fn feed(l: &mut Lines, bytes: &[u8]) -> Option<Line> {
            bytes.iter().map(|b| l.push(*b)).last()
        }
        assert_eq!(feed(&mut l, b"li\x07st\r"), Some(Line::Done(4)));
        assert_eq!(l.line(4), b"list");
        assert_eq!(feed(&mut l, b"\n"), Some(Line::None), "an empty line");
        assert_eq!(feed(&mut l, &[b'x'; Lines::MAX]), Some(Line::None));
        assert_eq!(
            feed(&mut l, b"\n"),
            Some(Line::Done(Lines::MAX)),
            "exactly the maximum"
        );
        assert_eq!(feed(&mut l, &[b'x'; Lines::MAX + 1]), Some(Line::None));
        assert_eq!(
            feed(&mut l, b"yy\n"),
            Some(Line::TooLong),
            "the whole line is dropped"
        );
        assert_eq!(
            feed(&mut l, b"stop all\n"),
            Some(Line::Done(8)),
            "the next line is whole"
        );
        assert_eq!(l.line(8), b"stop all");
    }
}
