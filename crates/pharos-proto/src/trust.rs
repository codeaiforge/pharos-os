//! The trusted service's interface, version 1 (agents.md, D-018), and the
//! commands the user types on the trusted path.
//!
//! Messages carry a process capability (`STOP` and `WAIT`) and nothing
//! else is asked of the service:
//! - `RUNTIME` `[version, op]`, from `init` only: the agent runtime;
//! - `REGISTER` `[version, op, slot, name length, name]`, from the runtime
//!   only: an agent, before the runtime grants it anything.
//!
//! And from the runtime only (#105):
//! - `CHANNEL` `[version, op]`, carrying `SEND` on the runtime's endpoint
//!   badged [`crate::agents::TRUST`], on which `trust` sends `REVOKE`
//!   without ever waiting;
//! - `REVOKED` `[version, op, outcome, name length, name, permission]`,
//!   the runtime's answer to a `REVOKE`, carrying no capability.
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
    },
    Channel,
    Revoked {
        outcome: Outcome,
        name: &'a [u8],
        permission: Permission,
    },
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
            Some(Request::Register { slot, name })
        })(),
        op::CHANNEL => Some(Request::Channel),
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
        Request::Register { slot, name } => {
            if slot >= SLOTS || !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, op::REGISTER, slot, name.len() as u8])?;
            w.bytes(name)?;
        }
        Request::Channel => w.bytes(&[VERSION, op::CHANNEL])?,
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
    /// `revoke <agent> <permission>` (#105).
    Revoke(&'a [u8], Permission),
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
    if let [b"revoke", name, rest @ ..] = &all[..count] {
        return match Permission::parse(rest) {
            Some(p) if valid_name(name) => Command::Revoke(name, p),
            _ => Command::Help,
        };
    }
    match (words.next(), words.next(), words.next()) {
        (Some(b"list"), None, None) => Command::List,
        (Some(b"stop"), Some(b"all"), None) => Command::StopAll,
        (Some(b"stop"), Some(name), None) if valid_name(name) => Command::Stop(name),
        _ => Command::Help,
    }
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
            },
            Request::Register {
                slot: SLOTS - 1,
                name: &long,
            },
            Request::Channel,
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
            let mut buf = [0u8; 64];
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
    fn bad_requests_are_refused() {
        let reg = |slot: u8, name: &[u8]| {
            let mut m = std::vec![VERSION, op::REGISTER, slot, name.len() as u8];
            m.extend_from_slice(name);
            m
        };
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
        };
        assert_eq!(encode(&bad, &mut [0; 64]), None);
        crate::fuzz(100_000, 6, |m| {
            let mut v = [0u8; 302];
            v[0] = VERSION;
            v[1..1 + m.len()].copy_from_slice(m);
            if let Ok(Request::Register { name, slot }) = parse(&v[..1 + m.len()]) {
                assert!(valid_name(name) && slot < SLOTS);
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
        for line in [
            &b""[..],
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
