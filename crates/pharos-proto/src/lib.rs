//! Service interfaces (D-019): every request starts with the interface
//! version and an operation, every reply with a status. Status codes 0–31
//! and operations 0xF0 and up mean the same in every interface; each
//! interface module ([`store`], [`net`], [`infer`], [`trust`], [`agents`], and the
//! [`manifest`] and [`tool`] text formats) defines the rest, with `parse` and
//! `encode` shared by the service and its clients.
//!
//! Parsers take untrusted bytes: they check every length, refuse trailing
//! bytes, and never panic (fuzzed in each module's tests). `no_std`, no
//! allocation, `unsafe` forbidden (workspace lint).

#![no_std]

#[cfg(test)]
extern crate std;

pub mod agents;
pub mod audit;
pub mod infer;
pub mod manifest;
pub mod net;
pub mod permission;
pub mod store;
pub mod tool;
pub mod trust;

/// Status codes common to every interface; an interface's own start at 32.
pub mod status {
    pub const OK: u8 = 0;
    pub const BAD_REQUEST: u8 = 1;
    /// The request's version is not supported; the reply carries the
    /// lowest and highest supported versions.
    pub const VERSION: u8 = 2;
    pub const NO_ACCESS: u8 = 3;
    pub const BUSY: u8 = 4;
    pub const TOO_LARGE: u8 = 5;
    /// No attached buffer, or a range outside it.
    pub const NO_BUFFER: u8 = 6;
    pub const NOT_FOUND: u8 = 7;
    pub const CANCELLED: u8 = 8;
    pub const INTERNAL: u8 = 9;
    /// Over a resource limit (D-022): the request is refused; the caller
    /// may carry on without it.
    pub const OVER_LIMIT: u8 = 10;
    /// First code an interface may define.
    pub const OWN: u8 = 32;
}

/// Operations common to every interface.
pub mod op {
    /// The interface's name and versions, and what the service offers.
    pub const INFO: u8 = 0xf0;
    /// A `send` carrying a `Memory` capability: the client's buffer for
    /// bulk data, with its size (u64).
    pub const ATTACH: u8 = 0xf1;
}

/// Why a request could not be parsed: the status to reply with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not a version this side speaks ([`status::VERSION`]).
    Version,
    /// Malformed ([`status::BAD_REQUEST`]).
    Bad,
}

/// Splits a request into its operation and body, if it is `version`.
pub fn split(msg: &[u8], version: u8) -> Result<(u8, &[u8]), Refused> {
    match msg {
        [v, op, body @ ..] if *v == version => Ok((*op, body)),
        [_, _, ..] => Err(Refused::Version),
        _ => Err(Refused::Bad),
    }
}

/// The reply to `refused`, for a service speaking only `version`; returns
/// its length.
pub fn refusal(refused: Refused, version: u8, out: &mut [u8]) -> usize {
    match refused {
        Refused::Version => {
            out[..3].copy_from_slice(&[status::VERSION, version, version]);
            3
        }
        Refused::Bad => {
            out[0] = status::BAD_REQUEST;
            1
        }
    }
}

/// The supported version range in a `VERSION` reply.
pub fn versions(reply: &[u8]) -> Option<(u8, u8)> {
    match reply {
        [status::VERSION, low, high] => Some((*low, *high)),
        _ => None,
    }
}

/// An `INFO` reply: `[OK, low, high, name length, name, details]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info<'a> {
    pub name: &'a [u8],
    pub low: u8,
    pub high: u8,
    /// Interface-defined: what the service offers.
    pub details: &'a [u8],
}

impl<'a> Info<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[
            status::OK,
            self.low,
            self.high,
            u8::try_from(self.name.len()).ok()?,
        ])?;
        w.bytes(self.name)?;
        w.bytes(self.details)?;
        Some(w.len())
    }

    pub fn parse(reply: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        if r.u8()? != status::OK {
            return None;
        }
        let (low, high) = (r.u8()?, r.u8()?);
        let n = usize::from(r.u8()?);
        Some(Self {
            low,
            high,
            name: r.take(n)?,
            details: r.rest(),
        })
    }
}

/// Reads little-endian fields from untrusted bytes; every read is checked.
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        (n <= self.0.len()).then(|| {
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            a
        })
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    /// The next byte, without taking it.
    pub fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    /// Whatever is left.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.0)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Writes little-endian fields; `None` once `out` is full.
pub struct Writer<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, n: 0 }
    }
    pub fn bytes(&mut self, b: &[u8]) -> Option<()> {
        self.out
            .get_mut(self.n..self.n + b.len())?
            .copy_from_slice(b);
        self.n += b.len();
        Some(())
    }
    pub fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }
    pub fn u32(&mut self, v: u32) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }
    pub fn u64(&mut self, v: u64) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }
    pub fn len(&self) -> usize {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

/// Bytes from a xorshift generator, for the modules' fuzz tests.
#[cfg(test)]
pub(crate) fn fuzz(rounds: usize, alphabet: u8, mut f: impl FnMut(&[u8])) {
    let mut x = 0x1234_5678_9abc_def1u64;
    for _ in 0..rounds {
        let mut msg = [0u8; 300];
        for b in msg.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x % u64::from(alphabet)) as u8;
        }
        f(&msg[..(x % 300) as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_version_refusal() {
        assert_eq!(split(&[1, 7, 9], 1), Ok((7, &[9][..])));
        assert_eq!(split(&[1, 7], 1), Ok((7, &[][..])));
        assert_eq!(split(&[2, 7], 1), Err(Refused::Version));
        assert_eq!(split(&[1], 1), Err(Refused::Bad));
        assert_eq!(split(&[], 1), Err(Refused::Bad));
        let mut out = [0u8; 8];
        let n = refusal(Refused::Version, 1, &mut out);
        assert_eq!(versions(&out[..n]), Some((1, 1)));
        assert_eq!(refusal(Refused::Bad, 1, &mut out), 1);
        assert_eq!(out[0], status::BAD_REQUEST);
        assert_eq!(versions(&[status::OK, 1, 1]), None);
    }

    #[test]
    fn info_round_trips() {
        let info = Info {
            name: b"store",
            low: 1,
            high: 1,
            details: &[4, 5],
        };
        let mut out = [0u8; 32];
        let n = info.encode(&mut out).unwrap();
        assert_eq!(Info::parse(&out[..n]), Some(info));
        assert_eq!(Info::parse(&out[..3]), None, "truncated");
        assert_eq!(Info::parse(&[status::BUSY, 1, 1, 0]), None);
        assert_eq!(info.encode(&mut [0u8; 5]), None, "too small");
        fuzz(100_000, 255, |m| {
            let _ = Info::parse(m);
            let _ = split(m, 1);
        });
    }

    #[test]
    fn reader_and_writer_check_bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16(), Some(0x0201));
        assert_eq!(r.u16(), None);
        assert_eq!(r.u8(), Some(3));
        assert!(r.is_empty());
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.u16(5), Some(()));
        assert_eq!(w.u16(6), None);
        assert_eq!(w.len(), 2);
    }
}
