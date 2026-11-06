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
//! The badge says who sends: [`INIT`] or [`RUNTIME`]. There is no reply:
//! the sender's blocking `send` returns once the service has the message,
//! and the service never refuses a valid one (it replaces a slot's entry).

use crate::permission::Permission;
use crate::{Reader, Refused, Writer, split};

pub const NAME: &[u8] = b"trust";
pub const VERSION: u8 = 1;

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
}

impl Event {
    fn from_code(c: u8) -> Option<Self> {
        use Event::*;
        [
            Exited, Killed, NoReady, Skipped, Restarting, GivenUp, Never, Stopped, Ready, NotReady,
        ]
        .get(usize::from(c))
        .copied()
    }

    /// True for the system's state, which names no service.
    pub fn system(self) -> bool {
        matches!(self, Self::Ready | Self::NotReady)
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
        (Some(b"stop"), Some(b"all"), None) => Command::StopAll,
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
        assert_eq!(parse(&msg(10, &[0])), Err(Refused::Bad), "event 10");
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
        assert_eq!(command(b"stop group a;b"), Command::Help);
        assert_eq!(command(b"yes 3"), Command::Answer(3, true));
        assert_eq!(command(b"audit"), Command::Audit);
        assert_eq!(command(b" usage "), Command::Usage);
        assert_eq!(command(b"usage all"), Command::Help);
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
