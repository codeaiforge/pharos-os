//! The network interface, version 1 (networking.md): UDP send and
//! receive, ping, and counters. A client is known by its badge, which is
//! its UDP port; the service builds every header itself.
//!
//! Requests: `[version, op, port or sequence (u16), IPv4 address (4),
//! payload]` for `SEND` and `PING`, `[version, op]` otherwise. Replies
//! start with a status.

use crate::{Reader, Refused, Writer, op as common, split, status};

pub const NAME: &[u8] = b"net";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    pub const SEND: u8 = 1;
    pub const RECV: u8 = 2;
    pub const PING: u8 = 3;
    pub const STATS: u8 = 4;
}

pub const OK: u8 = status::OK;
pub const BAD_REQUEST: u8 = status::BAD_REQUEST;
pub const BUSY: u8 = status::BUSY;
/// The client's badge is not a port (0, or over 16 bits).
pub const NO_PORT: u8 = status::OWN;
/// Every client slot is taken.
pub const NO_ROOM: u8 = status::OWN + 1;

/// Largest payload in one request or reply.
pub const MAX_PAYLOAD: usize = 248;
/// Counters the service reports with `STATS`.
pub const STATS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Send {
        ip: [u8; 4],
        port: u16,
        payload: &'a [u8],
    },
    Recv,
    Ping {
        ip: [u8; 4],
        seq: u16,
    },
    Stats,
    Info,
}

/// Parses a request. A payload over [`MAX_PAYLOAD`] is `Bad`; it cannot
/// arrive in a 256-byte message anyway.
pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let addressed = |r: &mut Reader<'_>| -> Option<(u16, [u8; 4])> {
        Some((r.u16()?, r.take(4)?.try_into().ok()?))
    };
    let req = match code {
        op::SEND => addressed(&mut r).and_then(|(port, ip)| {
            let payload = r.rest();
            (payload.len() <= MAX_PAYLOAD).then_some(Request::Send { ip, port, payload })
        }),
        op::PING => addressed(&mut r).map(|(seq, ip)| Request::Ping { ip, seq }),
        op::RECV => Some(Request::Recv),
        op::STATS => Some(Request::Stats),
        common::INFO => Some(Request::Info),
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
        Request::Send { ip, port, payload } => {
            if payload.len() > MAX_PAYLOAD {
                return None;
            }
            w.bytes(&[VERSION, op::SEND])?;
            w.u16(port)?;
            w.bytes(&ip)?;
            w.bytes(payload)?;
        }
        Request::Ping { ip, seq } => {
            w.bytes(&[VERSION, op::PING])?;
            w.u16(seq)?;
            w.bytes(&ip)?;
        }
        Request::Recv => w.bytes(&[VERSION, op::RECV])?,
        Request::Stats => w.bytes(&[VERSION, op::STATS])?,
        Request::Info => w.bytes(&[VERSION, common::INFO])?,
    }
    Some(w.len())
}

/// A received datagram's reply: `[OK, 0, source port, source IPv4,
/// payload]`.
pub fn encode_datagram(ip: [u8; 4], port: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let mut w = Writer::new(out);
    w.bytes(&[OK, 0])?;
    w.u16(port)?;
    w.bytes(&ip)?;
    w.bytes(payload)?;
    Some(w.len())
}

/// `(source ip, source port, payload)` from an `OK` datagram reply.
pub fn parse_datagram(reply: &[u8]) -> Option<([u8; 4], u16, &[u8])> {
    let mut r = Reader::new(reply);
    if r.u8()? != OK {
        return None;
    }
    r.u8()?;
    let port = r.u16()?;
    let ip = r.take(4)?.try_into().ok()?;
    Some((ip, port, r.rest()))
}

/// A ping's reply: `[OK, 0, sequence]`.
pub fn encode_pong(seq: u16) -> [u8; 4] {
    let s = seq.to_le_bytes();
    [OK, 0, s[0], s[1]]
}

/// A `STATS` reply: `[OK, 0, 0, 0, counters (u32 each)]`.
pub fn encode_stats(counters: &[u32; STATS], out: &mut [u8; 4 + 4 * STATS]) {
    out[..4].copy_from_slice(&[OK, 0, 0, 0]);
    for (k, v) in counters.iter().enumerate() {
        out[4 + 4 * k..8 + 4 * k].copy_from_slice(&v.to_le_bytes());
    }
}

/// The counters from an `OK` `STATS` reply.
pub fn parse_stats(reply: &[u8]) -> Option<[u32; STATS]> {
    let mut r = Reader::new(reply);
    if r.u8()? != OK {
        return None;
    }
    r.take(3)?;
    let mut out = [0u32; STATS];
    for v in out.iter_mut() {
        *v = r.u32()?;
    }
    r.is_empty().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let reqs = [
            Request::Send {
                ip: [10, 0, 2, 2],
                port: 47000,
                payload: &[7; MAX_PAYLOAD],
            },
            Request::Send {
                ip: [1, 2, 3, 4],
                port: 1,
                payload: &[],
            },
            Request::Ping {
                ip: [10, 0, 2, 2],
                seq: 9,
            },
            Request::Recv,
            Request::Stats,
            Request::Info,
        ];
        for req in reqs {
            let mut buf = [0u8; 300];
            let n = encode(&req, &mut buf).unwrap();
            assert!(n <= 256, "{req:?} fits a message");
            assert_eq!(parse(&buf[..n]), Ok(req));
            let mut other = buf;
            other[0] = VERSION + 1;
            assert_eq!(parse(&other[..n]), Err(Refused::Version), "{req:?} v2");
            if !matches!(req, Request::Send { .. }) {
                // A send's payload is the rest, so only fixed layouts
                // refuse a trailing byte or a missing one.
                assert_eq!(parse(&buf[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
                assert!(parse(&buf[..n - 1]).is_err(), "{req:?} truncated");
            }
        }
    }

    #[test]
    fn bad_requests_are_refused() {
        assert_eq!(parse(&[VERSION, 0]), Err(Refused::Bad), "unknown op");
        assert_eq!(
            parse(&[VERSION, op::SEND, 0, 0, 1, 2, 3]),
            Err(Refused::Bad),
            "address cut short"
        );
        let mut big = [0u8; 2 + 6 + MAX_PAYLOAD + 1];
        big[..2].copy_from_slice(&[VERSION, op::SEND]);
        assert_eq!(parse(&big), Err(Refused::Bad), "payload over the maximum");
        let too_big = Request::Send {
            ip: [0; 4],
            port: 1,
            payload: &[0; MAX_PAYLOAD + 1],
        };
        assert_eq!(encode(&too_big, &mut [0; 300]), None);
        crate::fuzz(100_000, 6, |m| {
            let mut v = [0u8; 302];
            v[0] = VERSION;
            v[1..1 + m.len()].copy_from_slice(m);
            let _ = parse(&v[..1 + m.len()]);
            let _ = parse(m);
            let _ = parse_datagram(m);
            let _ = parse_stats(m);
        });
    }

    #[test]
    fn replies_round_trip() {
        let mut out = [0u8; 256];
        let n = encode_datagram([10, 0, 2, 15], 40001, b"pong", &mut out).unwrap();
        assert_eq!(
            parse_datagram(&out[..n]),
            Some(([10, 0, 2, 15], 40001, &b"pong"[..]))
        );
        assert_eq!(parse_datagram(&out[..7]), None, "truncated");
        assert_eq!(parse_datagram(&[BUSY]), None);
        let counters = [1, 2, 3, 4, 5, u32::MAX];
        let mut s = [0u8; 4 + 4 * STATS];
        encode_stats(&counters, &mut s);
        assert_eq!(parse_stats(&s), Some(counters));
        assert_eq!(parse_stats(&s[..s.len() - 1]), None);
        assert_eq!(encode_pong(0x0102), [OK, 0, 2, 1]);
        assert_eq!(NO_PORT, status::OWN);
    }
}
