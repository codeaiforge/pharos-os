//! `init`'s service list, version 1 (#152, services.md, D-026): what the
//! trusted console's `services` shows.
//!
//! - `SERVICES` `[version, op, from]`: the entries from table index
//!   `from`, sent by `trust` with a call on its report capability (`init`
//!   answers only `trust`'s badge);
//! - the reply `[OK, total, count, entries…]`, each entry `[name length,
//!   name, state, restarts done, restart limit]`, as many as fit in one
//!   message; `trust` asks again from `from + count` until `total`.
//!
//! Names are `init`'s table names ([`crate::trust::valid_name`]), never
//! text from a service.

use crate::trust::valid_name;
use crate::{Reader, Refused, Writer, split, status};

pub const VERSION: u8 = 1;

pub mod op {
    pub const SERVICES: u8 = 1;
}

/// A service's state, as `init` holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// Not started yet: earlier entries are still starting.
    Pending = 0,
    /// Started; a daemon has not sent `ready` yet.
    Starting = 1,
    /// A daemon that sent `ready`.
    Ready = 2,
    /// A one-shot that exited with 0.
    Done = 3,
    /// Waiting for its restart's delay.
    Restarting = 4,
    /// Crashed, exited, sent no `ready`, or could not start; not restarted.
    Failed = 5,
    /// A service it depends on failed.
    Skipped = 6,
    /// Stopped by the user; never restarted.
    Stopped = 7,
}

impl State {
    fn from_code(c: u8) -> Option<Self> {
        use State::*;
        [
            Pending, Starting, Ready, Done, Restarting, Failed, Skipped, Stopped,
        ]
        .get(usize::from(c))
        .copied()
    }

    pub fn word(self) -> &'static [u8] {
        match self {
            Self::Pending => b"pending",
            Self::Starting => b"starting",
            Self::Ready => b"ready",
            Self::Done => b"done",
            Self::Restarting => b"restarting",
            Self::Failed => b"failed",
            Self::Skipped => b"skipped",
            Self::Stopped => b"stopped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Services { from: u8 },
}

pub fn parse(msg: &[u8]) -> Result<Request, Refused> {
    match split(msg, VERSION)? {
        (op::SERVICES, [from]) => Ok(Request::Services { from: *from }),
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request, out: &mut [u8]) -> Option<usize> {
    let Request::Services { from } = *req;
    let mut w = Writer::new(out);
    w.bytes(&[VERSION, op::SERVICES, from])?;
    Some(w.len())
}

/// One service in the reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub state: State,
    pub restarts: u8,
    pub limit: u8,
}

impl<'a> Entry<'a> {
    fn read(r: &mut Reader<'a>) -> Option<Self> {
        let len = usize::from(r.u8()?);
        let name = r.take(len).filter(|n| valid_name(n))?;
        Some(Self {
            name,
            state: State::from_code(r.u8()?)?,
            restarts: r.u8()?,
            limit: r.u8()?,
        })
    }
}

/// A reply: the table's size and some of its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    pub total: u8,
    pub count: u8,
    entries: &'a [u8],
}

impl<'a> Reply<'a> {
    /// Writes as many of `entries` as fit in `out`; returns the length and
    /// how many it wrote. `None` if an entry's name is not valid.
    pub fn write(total: u8, entries: &[Entry<'_>], out: &mut [u8]) -> Option<(usize, usize)> {
        if out.len() < 3 || !entries.iter().all(|e| valid_name(e.name)) {
            return None;
        }
        let mut w = Writer::new(&mut out[3..]);
        let mut count = 0;
        for e in entries.iter().take(usize::from(u8::MAX)) {
            let size = 4 + e.name.len();
            let mut one = [0u8; 4 + crate::trust::MAX_NAME];
            one[0] = e.name.len() as u8;
            one[1..1 + e.name.len()].copy_from_slice(e.name);
            one[size - 3..size].copy_from_slice(&[e.state as u8, e.restarts, e.limit]);
            if w.bytes(&one[..size]).is_none() {
                break;
            }
            count += 1;
        }
        let n = 3 + w.len();
        out[..3].copy_from_slice(&[status::OK, total, count as u8]);
        Some((n, count))
    }

    pub fn parse(reply: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        if r.u8()? != status::OK {
            return None;
        }
        let (total, count) = (r.u8()?, r.u8()?);
        let entries = r.rest();
        let mut check = Reader::new(entries);
        for _ in 0..count {
            Entry::read(&mut check)?;
        }
        check.is_empty().then_some(Self {
            total,
            count,
            entries,
        })
    }

    pub fn iter(self) -> impl Iterator<Item = Entry<'a>> {
        let mut r = Reader::new(self.entries);
        core::iter::from_fn(move || Entry::read(&mut r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_bad_ones_are_refused() {
        for from in [0, 7, u8::MAX] {
            let req = Request::Services { from };
            let mut buf = [0u8; 8];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(req));
            assert_eq!(parse(&buf[..n - 1]), Err(Refused::Bad), "no index");
            assert_eq!(parse(&[VERSION, op::SERVICES, from, 0]), Err(Refused::Bad));
        }
        assert_eq!(parse(&[VERSION, 2, 0]), Err(Refused::Bad), "unknown op");
        assert_eq!(parse(&[2, op::SERVICES, 0]), Err(Refused::Version));
        crate::fuzz(100_000, 4, |m| {
            let _ = parse(m);
        });
    }

    #[test]
    fn replies_round_trip_page_and_refuse_bad_entries() {
        let long = [b'a'; crate::trust::MAX_NAME];
        let entries = [
            Entry {
                name: b"store",
                state: State::Ready,
                restarts: 1,
                limit: 3,
            },
            Entry {
                name: &long,
                state: State::Stopped,
                restarts: 0,
                limit: 0,
            },
            Entry {
                name: b"after-crasher",
                state: State::Skipped,
                restarts: 0,
                limit: 0,
            },
        ];
        let mut out = [0u8; 256];
        let (n, count) = Reply::write(9, &entries, &mut out).unwrap();
        assert_eq!(count, 3);
        let reply = Reply::parse(&out[..n]).unwrap();
        assert_eq!((reply.total, reply.count), (9, 3));
        assert!(reply.iter().eq(entries.iter().copied()));
        for cut in 0..n {
            assert_eq!(Reply::parse(&out[..cut]), None, "cut at {cut}");
        }
        let mut longer = out;
        longer[n] = 0;
        assert_eq!(Reply::parse(&longer[..n + 1]), None, "a trailing byte");
        // Paging: only the first two fit.
        let (n, count) = Reply::write(3, &entries, &mut out[..3 + 9 + 36]).unwrap();
        assert_eq!(count, 2);
        assert!(
            Reply::parse(&out[..n])
                .unwrap()
                .iter()
                .eq(entries[..2].iter().copied())
        );
        let bad = Entry {
            name: b"a b",
            ..entries[0]
        };
        assert_eq!(Reply::write(1, &[bad], &mut out), None, "a bad name");
        // On the wire: an unknown state and a bad name.
        assert_eq!(Reply::parse(&[0, 1, 1, 1, b'a', 8, 0, 0]), None);
        assert_eq!(Reply::parse(&[0, 1, 1, 1, b' ', 2, 0, 0]), None);
        assert!(Reply::parse(&[0, 1, 1, 1, b'a', 7, 0, 0]).is_some());
        crate::fuzz(100_000, 9, |m| {
            if let Some(r) = Reply::parse(m) {
                assert_eq!(r.iter().count(), usize::from(r.count));
                assert!(r.iter().all(|e| valid_name(e.name)));
            }
        });
    }
}
