//! The audit service's interface, version 1 (capabilities.md, #107), and
//! the record it stores.
//!
//! Every request is a `call`:
//! - `APPEND` `[version, op, entry]`: one [`Entry`]; the reply is
//!   `[OK, sequence (8)]`, or [`UNWRITABLE`] if the store did not take it;
//! - `HEAD` `[version, op]`: `[OK, boot (4), records (8), head (32)]`, the
//!   current boot's stream, record count, and chain head.
//!
//! The badge says which client sends: none is `init` (the only holder of
//! an unbadged capability), and `trust` and the runtime have the badges
//! `init` gives them; badge 1 is refused, so no one else can write as
//! `init`. The service adds the sequence
//! number, the time, and that badge to every entry, so a client cannot
//! write as another. Records are one stream per boot, `log/<boot>`, in the
//! store's `audit` namespace, chained there with SHA-256 (D-017).

use crate::permission::Permission;
use crate::trust::valid_name;
use crate::{Reader, Refused, Writer, split};

pub const NAME: &[u8] = b"audit";
pub const VERSION: u8 = 1;

pub mod op {
    pub const APPEND: u8 = 1;
    pub const HEAD: u8 = 2;
}

/// The service's own status: the entry was not stored (store full,
/// failing, or unreachable). Callers refuse the action (D-012 item 11).
pub const UNWRITABLE: u8 = crate::status::OWN;

/// Longest detail text.
pub const MAX_DETAIL: usize = 64;

/// Badges `init` gives (the client number in each record).
pub mod client {
    /// The audit service itself (its boot record).
    pub const AUDIT: u8 = 0;
    pub const INIT: u8 = 1;
    pub const TRUST: u8 = 2;
    pub const RUNTIME: u8 = 3;
}

/// What kind of record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Something that happened.
    Event = 1,
    /// About to do a consequential action; acted on only once stored.
    Intent = 2,
    /// How the intent `refers` to ended.
    Outcome = 3,
}

/// What was done. Codes are fixed; new ones are added at the end.
pub mod action {
    pub const BOOT: u8 = 1;
    /// A service started by `init`, with what its table entry lists.
    pub const START: u8 = 2;
    pub const GRANT: u8 = 3;
    pub const REVOKE: u8 = 4;
    pub const APPROVE: u8 = 5;
    pub const REFUSE: u8 = 6;
    pub const EXPIRE: u8 = 7;
    pub const STOP: u8 = 8;
    pub const INFER: u8 = 9;
    pub const DATA_WRITE: u8 = 10;
    pub const NET_SEND: u8 = 11;
    pub const SUBMIT: u8 = 12;
    pub const CANCEL: u8 = 13;
    /// What an attempt used, when it ends (#119).
    pub const USAGE: u8 = 14;
    /// A tool call (#126), with the tool's name as detail.
    pub const TOOL: u8 = 15;
    /// A message to another agent (#133): kind and length as detail.
    pub const MESSAGE: u8 = 16;
    pub const LAST: u8 = MESSAGE;

    pub fn name(code: u8) -> &'static str {
        [
            "?",
            "boot",
            "start",
            "grant",
            "revoke",
            "approve",
            "refuse",
            "expire",
            "stop",
            "infer",
            "data write",
            "net send",
            "submit",
            "cancel",
            "usage",
            "tool",
            "message",
        ]
        .get(usize::from(code))
        .copied()
        .unwrap_or("?")
    }
}

/// How it went, for events and outcomes (0 for intents).
pub mod outcome {
    pub const NONE: u8 = 0;
    pub const OK: u8 = 1;
    pub const REFUSED: u8 = 2;
    pub const FAILED: u8 = 3;
    pub const LAST: u8 = FAILED;
}

/// What a client sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub kind: Kind,
    /// For an outcome: its intent's sequence number; else 0.
    pub refers: u64,
    /// Who: an agent's name, a service's, or `user` (empty: the client).
    pub actor: &'a [u8],
    /// The agent's task and attempt (0 for none).
    pub task: u32,
    pub attempt: u8,
    pub action: u8,
    pub permission: Option<Permission>,
    /// The service used, by name (empty for none).
    pub service: &'a [u8],
    pub outcome: u8,
    /// Printable text, at most [`MAX_DETAIL`] bytes.
    pub detail: &'a [u8],
}

fn optional_name(n: &[u8]) -> bool {
    n.is_empty() || valid_name(n)
}

fn printable(t: &[u8]) -> bool {
    t.len() <= MAX_DETAIL && t.iter().all(|b| (b' '..=b'~').contains(b))
}

impl<'a> Entry<'a> {
    fn valid(&self) -> bool {
        optional_name(self.actor)
            && optional_name(self.service)
            && (1..=action::LAST).contains(&self.action)
            && self.outcome <= outcome::LAST
            && printable(self.detail)
            && (self.kind == Kind::Outcome) == (self.refers != 0)
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        if !self.valid() {
            return None;
        }
        w.bytes(&[self.kind as u8])?;
        w.u64(self.refers)?;
        w.bytes(&[self.actor.len() as u8])?;
        w.bytes(self.actor)?;
        w.u32(self.task)?;
        w.bytes(&[self.attempt, self.action])?;
        match self.permission {
            Some(p) => {
                w.bytes(&[1])?;
                p.write(w)?;
            }
            None => w.bytes(&[0])?,
        }
        w.bytes(&[self.service.len() as u8])?;
        w.bytes(self.service)?;
        w.bytes(&[self.outcome, self.detail.len() as u8])?;
        w.bytes(self.detail)
    }

    pub fn read(r: &mut Reader<'a>) -> Option<Self> {
        let kind = match r.u8()? {
            1 => Kind::Event,
            2 => Kind::Intent,
            3 => Kind::Outcome,
            _ => return None,
        };
        let refers = r.u64()?;
        let n = usize::from(r.u8()?);
        let actor = r.take(n)?;
        let task = r.u32()?;
        let attempt = r.u8()?;
        let action = r.u8()?;
        let permission = match r.u8()? {
            0 => None,
            1 => Some(Permission::read(r)?),
            _ => return None,
        };
        let n = usize::from(r.u8()?);
        let service = r.take(n)?;
        let outcome = r.u8()?;
        let n = usize::from(r.u8()?);
        let detail = r.take(n)?;
        let e = Self {
            kind,
            refers,
            actor,
            task,
            attempt,
            action,
            permission,
            service,
            outcome,
            detail,
        };
        e.valid().then_some(e)
    }
}

/// A stored record: what the service added, and the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub sequence: u64,
    /// `uptime` microseconds when stored.
    pub time: u64,
    pub client: u8,
    pub entry: Entry<'a>,
}

impl<'a> Record<'a> {
    /// The stored form; `None` if the entry is invalid or `out` too small.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.u64(self.sequence)?;
        w.u64(self.time)?;
        w.bytes(&[self.client])?;
        self.entry.write(&mut w)?;
        Some(w.len())
    }

    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let rec = Self {
            sequence: r.u64()?,
            time: r.u64()?,
            client: r.u8()?,
            entry: Entry::read(&mut r)?,
        };
        r.is_empty().then_some(rec)
    }
}

/// Largest stored record (within the store's inline append).
pub const MAX_RECORD: usize =
    17 + 1 + 8 + 33 + 4 + 2 + 1 + crate::permission::WIRE + 33 + 2 + MAX_DETAIL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Append(Entry<'a>),
    Head,
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = match code {
        op::APPEND => Entry::read(&mut r).map(Request::Append),
        op::HEAD => Some(Request::Head),
        _ => None,
    };
    match req {
        Some(req) if r.is_empty() => Ok(req),
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    match req {
        Request::Append(e) => {
            w.bytes(&[VERSION, op::APPEND])?;
            e.write(&mut w)?;
        }
        Request::Head => w.bytes(&[VERSION, op::HEAD])?,
    }
    Some(w.len())
}

/// The `HEAD` reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub boot: u32,
    pub records: u64,
    pub head: [u8; 32],
}

impl Head {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[crate::status::OK])?;
        w.u32(self.boot)?;
        w.u64(self.records)?;
        w.bytes(&self.head)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        if r.u8()? != crate::status::OK {
            return None;
        }
        let h = Self {
            boot: r.u32()?,
            records: r.u64()?,
            head: r.take(32)?.try_into().ok()?,
        };
        r.is_empty().then_some(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry<'static> {
        Entry {
            kind: Kind::Intent,
            refers: 0,
            actor: b"keeper",
            task: 12,
            attempt: 2,
            action: action::INFER,
            permission: Some(Permission::Model(2)),
            service: b"infer",
            outcome: outcome::NONE,
            detail: b"max_new 20",
        }
    }

    #[test]
    fn records_round_trip() {
        let long = [b'a'; 32];
        let detail = [b'd'; MAX_DETAIL];
        for e in [
            entry(),
            Entry {
                kind: Kind::Outcome,
                refers: u64::MAX,
                actor: &long,
                permission: Some(Permission::Net {
                    addr: [255; 4],
                    port: 65_535,
                }),
                service: &long,
                outcome: outcome::FAILED,
                detail: &detail,
                ..entry()
            },
            // The longest record: a 32-byte file name (#127).
            Entry {
                kind: Kind::Outcome,
                refers: u64::MAX,
                actor: &long,
                action: action::TOOL,
                permission: Permission::file(&long),
                service: &long,
                outcome: outcome::FAILED,
                detail: &detail,
                ..entry()
            },
            Entry {
                kind: Kind::Event,
                actor: b"",
                permission: None,
                service: b"",
                detail: b"",
                outcome: outcome::OK,
                ..entry()
            },
        ] {
            let rec = Record {
                sequence: 7,
                time: 1_234_567,
                client: client::RUNTIME,
                entry: e,
            };
            let mut buf = [0u8; 256];
            let n = rec.encode(&mut buf).unwrap();
            assert!(n <= MAX_RECORD, "{n}");
            if e.permission.is_some_and(|p| p.file_name() == Some(&long)) {
                assert_eq!(n, MAX_RECORD, "the bound is exact");
            }
            assert_eq!(Record::parse(&buf[..n]), Some(rec));
            assert_eq!(Record::parse(&buf[..n - 1]), None, "truncated");
            let mut longer = buf;
            longer[n] = 0;
            assert_eq!(Record::parse(&longer[..n + 1]), None, "trailing byte");
            let req = Request::Append(e);
            let m = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..m]), Ok(req));
        }
        const { assert!(MAX_RECORD <= crate::store::MAX_INLINE) };
        let mut buf = [0u8; 8];
        let n = encode(&Request::Head, &mut buf).unwrap();
        assert_eq!(parse(&buf[..n]), Ok(Request::Head));
        let h = Head {
            boot: 3,
            records: 9,
            head: [7; 32],
        };
        let mut out = [0u8; 64];
        let n = h.encode(&mut out).unwrap();
        assert_eq!(Head::parse(&out[..n]), Some(h));
    }

    #[test]
    fn bad_entries_are_refused() {
        let bad = [
            Entry {
                actor: b"a b",
                ..entry()
            },
            Entry {
                service: b"x\n",
                ..entry()
            },
            Entry {
                detail: b"line\nbreak",
                ..entry()
            },
            Entry {
                detail: &[b'd'; MAX_DETAIL + 1],
                ..entry()
            },
            Entry {
                action: 0,
                ..entry()
            },
            Entry {
                action: action::LAST + 1,
                ..entry()
            },
            Entry {
                outcome: outcome::LAST + 1,
                ..entry()
            },
            Entry {
                refers: 3,
                ..entry()
            },
            Entry {
                kind: Kind::Outcome,
                refers: 0,
                ..entry()
            },
        ];
        for e in bad {
            assert_eq!(encode(&Request::Append(e), &mut [0; 256]), None, "{e:?}");
        }
        assert_eq!(parse(&[VERSION, 9]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, op::HEAD, 0]), Err(Refused::Bad));
        crate::fuzz(100_000, 9, |m| {
            if let Some(r) = Record::parse(m) {
                assert!(r.entry.valid());
            }
            let _ = parse(m);
        });
    }
}
