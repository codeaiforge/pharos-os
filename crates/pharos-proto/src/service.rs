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
//! - `SYSTEM` `[version, op]` (#164): the reply `[OK, mode, image,
//!   active, incoming, slot A, slot B]` (incoming: how many files wait in
//!   `system/incoming`, #165), each slot `[state, attempts, version (u64),
//!   first 8 bytes of its SHA-256]`; codes as in `pharos_image::slots`
//!   (mode 0 normal, 1 safe, 2 recovery; image 0 factory, 1 A, 2 B, 3 the
//!   recovery copy; active 0 none, 1 A, 2 B; state 0 empty to 4 bad);
//! - `NEXT` `[version, op, mode]` (#164): the next boot's mode (1 safe or
//!   2 recovery) written to the slot record; the reply `[OK]`, or
//!   `[INTERNAL]` if the record could not be written.
//!
//! Updates (#165, boot.md section 8):
//! - `UPDATE` `[version, op]`: the reply `[OK, count]`, the incoming
//!   images `init` checks; it then sends `trust` an `OFFER` for each
//!   (`crate::trust`), so `trust` never waits for the checks;
//! - `ANSWER` `[version, op, number (2), apply]`: the user's answer to
//!   offer `number`, 1 apply, 0 discard; the reply `[OK]` (applying or
//!   discarded), `[NOT_FOUND]` (no such offer), `[CANCELLED]` (not
//!   answered within 60 s), or `[BUSY]` (`init` is booting or applying,
//!   or the mode is not normal);
//! - `ROLLBACK` `[version, op]`: the reply `[OK]` (rolling back),
//!   `[NOT_FOUND]` (no good slot to roll back to), or `[BUSY]`.
//!
//! Runtime management (#170, M4.4, D-029, services.md):
//! - `START`, `STOP`, `RESTART` `[version, op, length, name…]`: the
//!   user's action on the service with that table name; the reply is a
//!   [`Managed`] (`[OK]`, `[NOT_FOUND]` no such entry, `[BUSY]` not now,
//!   `[PROTECTED]`, `[RUNNING]`, `[NOT_RUNNING]`, or `[NEEDS, length,
//!   name…]`, the first dependency that does not run).
//!
//! - `RUNTIME` `[version, op]` (#170): `trust` asks once it is ready;
//!   the reply `[OK]` carries the running agent runtime's process
//!   capability (`STOP`, `WAIT`), so a restarted `trust` holds the
//!   emergency stop before it reads the console; `[NOT_FOUND]` if the
//!   runtime does not run (at boot it registers when it starts).
//!
//! Names are `init`'s table names ([`crate::trust::valid_name`]), never
//! text from a service.

use crate::trust::valid_name;
use crate::{Reader, Refused, Writer, split, status};

pub const VERSION: u8 = 1;

pub mod op {
    pub const SERVICES: u8 = 1;
    pub const SYSTEM: u8 = 2;
    pub const NEXT: u8 = 3;
    pub const UPDATE: u8 = 4;
    pub const ANSWER: u8 = 5;
    pub const ROLLBACK: u8 = 6;
    pub const START: u8 = 7;
    pub const STOP: u8 = 8;
    pub const RESTART: u8 = 9;
    pub const RUNTIME: u8 = 10;
}

/// Statuses only management replies use (#170).
pub mod managed {
    use crate::status::OWN;
    /// `stop` on `trust`, `audit`, or `store`.
    pub const PROTECTED: u8 = OWN;
    /// `start` on a service that runs.
    pub const RUNNING: u8 = OWN + 1;
    /// `stop` on a service that does not run.
    pub const NOT_RUNNING: u8 = OWN + 2;
    /// A dependency does not run; its name follows.
    pub const NEEDS: u8 = OWN + 3;
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
    /// Not started in safe mode or recovery (#164).
    Off = 8,
}

impl State {
    fn from_code(c: u8) -> Option<Self> {
        use State::*;
        [
            Pending, Starting, Ready, Done, Restarting, Failed, Skipped, Stopped, Off,
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
            Self::Off => b"off (safe mode)",
        }
    }
}

/// What the user asks of a service (#170).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    fn op(self) -> u8 {
        match self {
            Self::Start => op::START,
            Self::Stop => op::STOP,
            Self::Restart => op::RESTART,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Services {
        from: u8,
    },
    System,
    /// 1 safe or 2 recovery.
    Next {
        mode: u8,
    },
    Update,
    Answer {
        number: u16,
        apply: bool,
    },
    Rollback,
    Runtime,
    /// A table name ([`valid_name`]).
    Manage {
        action: Action,
        name: &'a [u8],
    },
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    match split(msg, VERSION)? {
        (op::SERVICES, [from]) => Ok(Request::Services { from: *from }),
        (op::SYSTEM, []) => Ok(Request::System),
        (op::NEXT, [mode @ (1 | 2)]) => Ok(Request::Next { mode: *mode }),
        (op::UPDATE, []) => Ok(Request::Update),
        (op::ANSWER, [a, b, apply @ (0 | 1)]) => Ok(Request::Answer {
            number: u16::from_le_bytes([*a, *b]),
            apply: *apply == 1,
        }),
        (op::ROLLBACK, []) => Ok(Request::Rollback),
        (op::RUNTIME, []) => Ok(Request::Runtime),
        (o @ (op::START | op::STOP | op::RESTART), [len, name @ ..])
            if usize::from(*len) == name.len() && valid_name(name) =>
        {
            let action = match o {
                op::START => Action::Start,
                op::STOP => Action::Stop,
                _ => Action::Restart,
            };
            Ok(Request::Manage { action, name })
        }
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    match *req {
        Request::Services { from } => w.bytes(&[VERSION, op::SERVICES, from])?,
        Request::System => w.bytes(&[VERSION, op::SYSTEM])?,
        Request::Next { mode } => w.bytes(&[VERSION, op::NEXT, mode])?,
        Request::Update => w.bytes(&[VERSION, op::UPDATE])?,
        Request::Answer { number, apply } => {
            w.bytes(&[VERSION, op::ANSWER])?;
            w.u16(number)?;
            w.bytes(&[u8::from(apply)])?
        }
        Request::Rollback => w.bytes(&[VERSION, op::ROLLBACK])?,
        Request::Runtime => w.bytes(&[VERSION, op::RUNTIME])?,
        Request::Manage { action, name } => {
            if !valid_name(name) {
                return None;
            }
            w.bytes(&[VERSION, action.op(), name.len() as u8])?;
            w.bytes(name)?
        }
    }
    Some(w.len())
}

/// The reply to `START`, `STOP`, or `RESTART` (#170).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Managed<'a> {
    Ok,
    /// No entry by that name in the running table.
    Unknown,
    /// Booting, switching images, or in recovery.
    Busy,
    Protected,
    Running,
    NotRunning,
    /// This dependency (a table name) does not run.
    Needs(&'a [u8]),
}

impl<'a> Managed<'a> {
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        match *self {
            Self::Ok => w.bytes(&[status::OK])?,
            Self::Unknown => w.bytes(&[status::NOT_FOUND])?,
            Self::Busy => w.bytes(&[status::BUSY])?,
            Self::Protected => w.bytes(&[managed::PROTECTED])?,
            Self::Running => w.bytes(&[managed::RUNNING])?,
            Self::NotRunning => w.bytes(&[managed::NOT_RUNNING])?,
            Self::Needs(name) => {
                if !valid_name(name) {
                    return None;
                }
                w.bytes(&[managed::NEEDS, name.len() as u8])?;
                w.bytes(name)?
            }
        }
        Some(w.len())
    }

    pub fn parse(reply: &'a [u8]) -> Option<Self> {
        Some(match reply {
            [status::OK] => Self::Ok,
            [status::NOT_FOUND] => Self::Unknown,
            [status::BUSY] => Self::Busy,
            [managed::PROTECTED] => Self::Protected,
            [managed::RUNNING] => Self::Running,
            [managed::NOT_RUNNING] => Self::NotRunning,
            [managed::NEEDS, len, name @ ..]
                if usize::from(*len) == name.len() && valid_name(name) =>
            {
                Self::Needs(name)
            }
            _ => return None,
        })
    }
}

/// A slot in the `SYSTEM` reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Slot {
    /// 0 empty, 1 staged, 2 trying, 3 good, 4 bad.
    pub state: u8,
    pub attempts: u8,
    pub version: u64,
    pub sha256: [u8; 8],
}

impl Slot {
    pub fn word(self) -> &'static [u8] {
        match self.state {
            0 => b"empty",
            1 => b"staged",
            2 => b"trying",
            3 => b"good",
            _ => b"bad",
        }
    }
}

/// The `SYSTEM` reply: what runs and what the slot record holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct System {
    /// 0 normal, 1 safe, 2 recovery.
    pub mode: u8,
    /// 0 factory, 1 slot A, 2 slot B, 3 the recovery copy.
    pub image: u8,
    /// 0 none, 1 A, 2 B.
    pub active: u8,
    /// Files waiting in `system/incoming` (#165).
    pub incoming: u8,
    pub slots: [Slot; 2],
}

/// Length of a `SYSTEM` reply.
pub const SYSTEM_LEN: usize = 5 + 2 * 18;

impl System {
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[
            status::OK,
            self.mode,
            self.image,
            self.active,
            self.incoming,
        ])?;
        for s in &self.slots {
            w.bytes(&[s.state, s.attempts])?;
            w.u64(s.version)?;
            w.bytes(&s.sha256)?;
        }
        Some(w.len())
    }

    /// The reply, or `None` if any field is out of range.
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        if r.u8()? != status::OK {
            return None;
        }
        let (mode, image, active, incoming) = (r.u8()?, r.u8()?, r.u8()?, r.u8()?);
        if mode > 2 || image > 3 || active > 2 {
            return None;
        }
        let mut slots = [Slot::default(); 2];
        for s in &mut slots {
            s.state = r.u8().filter(|&v| v <= 4)?;
            s.attempts = r.u8()?;
            s.version = r.u64()?;
            s.sha256 = r.take(8)?.try_into().ok()?;
        }
        r.is_empty().then_some(Self {
            mode,
            image,
            active,
            incoming,
            slots,
        })
    }

    pub fn mode_word(&self) -> &'static [u8] {
        match self.mode {
            0 => b"normal",
            1 => b"safe",
            _ => b"recovery",
        }
    }
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
        assert_eq!(parse(&[VERSION, 15, 0]), Err(Refused::Bad), "unknown op");
        for req in [
            Request::System,
            Request::Next { mode: 1 },
            Request::Next { mode: 2 },
            Request::Update,
            Request::Rollback,
            Request::Runtime,
            Request::Answer {
                number: 1,
                apply: true,
            },
            Request::Answer {
                number: 0xbeef,
                apply: false,
            },
        ] {
            let mut buf = [0u8; 8];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(req));
        }
        assert_eq!(parse(&[VERSION, op::SYSTEM, 0]), Err(Refused::Bad));
        for mode in [0, 3, 255] {
            assert_eq!(
                parse(&[VERSION, op::NEXT, mode]),
                Err(Refused::Bad),
                "mode {mode}"
            );
        }
        assert_eq!(parse(&[VERSION, op::UPDATE, 0]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, op::ROLLBACK, 0]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, op::RUNTIME, 0]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, op::ANSWER, 1, 0]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, op::ANSWER, 1, 0, 2]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, op::ANSWER, 1, 0, 1, 0]), Err(Refused::Bad));
        assert_eq!(parse(&[2, op::SERVICES, 0]), Err(Refused::Version));
        crate::fuzz(100_000, 4, |m| {
            let _ = parse(m);
        });
    }

    #[test]
    fn management_requests_and_replies_round_trip() {
        for action in [Action::Start, Action::Stop, Action::Restart] {
            for name in [
                &b"net"[..],
                b"virtio-blk",
                b"a_name_of_exactly_32_bytes_long_",
            ] {
                let req = Request::Manage { action, name };
                let mut buf = [0u8; 48];
                let n = encode(&req, &mut buf).unwrap();
                assert_eq!(parse(&buf[..n]), Ok(req));
                assert_eq!(parse(&buf[..n - 1]), Err(Refused::Bad), "cut");
                let mut long = buf;
                long[n] = b'x';
                assert_eq!(parse(&long[..n + 1]), Err(Refused::Bad), "trailing");
            }
            let mut buf = [0u8; 48];
            for bad in [
                &b""[..],
                b"a b",
                b"a_name_of_33_bytes_is_one_too_lon",
                b"n\0",
            ] {
                let req = Request::Manage { action, name: bad };
                assert_eq!(encode(&req, &mut buf), None, "{bad:?}");
                let mut msg = std::vec![VERSION, action.op(), bad.len() as u8];
                msg.extend_from_slice(bad);
                assert_eq!(parse(&msg), Err(Refused::Bad), "{bad:?}");
            }
        }
        for m in [
            Managed::Ok,
            Managed::Unknown,
            Managed::Busy,
            Managed::Protected,
            Managed::Running,
            Managed::NotRunning,
            Managed::Needs(b"store"),
        ] {
            let mut buf = [0u8; 48];
            let n = m.write(&mut buf).unwrap();
            assert_eq!(Managed::parse(&buf[..n]), Some(m));
        }
        assert_eq!(Managed::Needs(b"").write(&mut [0u8; 8]), None);
        assert_eq!(Managed::parse(&[managed::NEEDS, 3, b'n', b'e']), None);
        assert_eq!(Managed::parse(&[status::OK, 0]), None);
        assert_eq!(Managed::parse(&[]), None);
        crate::fuzz(100_000, 64, |m| {
            let _ = Managed::parse(m);
        });
    }

    #[test]
    fn the_system_reply_round_trips_and_refuses_bad_fields() {
        let sys = System {
            mode: 1,
            image: 2,
            active: 2,
            incoming: 4,
            slots: [
                Slot {
                    state: 4,
                    attempts: 3,
                    version: 7,
                    sha256: [0xab; 8],
                },
                Slot {
                    state: 3,
                    attempts: 0,
                    version: u64::MAX,
                    sha256: [1, 2, 3, 4, 5, 6, 7, 8],
                },
            ],
        };
        let mut out = [0u8; 64];
        let n = sys.write(&mut out).unwrap();
        assert_eq!(n, SYSTEM_LEN);
        assert_eq!(System::parse(&out[..n]), Some(sys));
        for cut in 0..n {
            assert_eq!(System::parse(&out[..cut]), None, "cut at {cut}");
        }
        assert_eq!(System::parse(&out[..n + 1]), None, "a trailing byte");
        for (at, bad) in [(0, 1), (1, 3), (2, 4), (3, 3), (5, 5), (23, 5)] {
            let mut b = out;
            b[at] = bad;
            assert_eq!(System::parse(&b[..n]), None, "byte {at} = {bad}");
        }
        assert_eq!(sys.mode_word(), b"safe");
        assert_eq!(sys.slots[0].word(), b"bad");
        crate::fuzz(100_000, 6, |m| {
            let _ = System::parse(m);
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
        assert_eq!(Reply::parse(&[0, 1, 1, 1, b'a', 9, 0, 0]), None);
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
