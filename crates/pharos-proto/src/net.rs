//! The network interface, versions 1 and 2 (networking.md, tls.md): UDP
//! send and receive, ping, and counters (version 1), and TCP (version 2,
//! M6.1, D-034). A client is known by its badge, which is its UDP port; the
//! service builds every header itself.
//!
//! Version 2 is version 1 plus the TCP operations: the version 1 requests
//! are accepted with either version byte, the TCP ones only with 2. TCP
//! data moves through one shared buffer per client, attached with
//! `ATTACH` (a `send` carrying the `Memory` capability), and `TCP_WRITE` and
//! `TCP_READ` name a range of it. A client opens TCP only to an address and
//! port `init` listed for it with `ALLOW_TCP`.
//!
//! Requests: `[version, op, port or sequence (u16), IPv4 address (4),
//! payload]` for `SEND` and `PING`; `[version, ALLOW, client port (u16),
//! count, (IPv4 address, port (u16)) each]`; `[version, op]` otherwise.
//! Replies start with a status.
//!
//! Destinations (#109): a client may send only to the destinations `init`
//! listed for it with `ALLOW`, and ping only their addresses; anything
//! else is `NO_ACCESS`. A client with no list can send nowhere. `ALLOW` is
//! accepted only without a badge: only `init` holds such a capability.

use crate::{Reader, Refused, Writer, op as common, status};

pub const NAME: &[u8] = b"net";
/// The version of the UDP requests; the service also accepts them as
/// [`TCP_VERSION`].
pub const VERSION: u8 = 1;
/// The version of the TCP requests, and the highest the service speaks.
pub const TCP_VERSION: u8 = 2;

/// Operation codes.
pub mod op {
    pub const SEND: u8 = 1;
    pub const RECV: u8 = 2;
    pub const PING: u8 = 3;
    pub const STATS: u8 = 4;
    /// `init` only: the destinations of client `port`, replacing any.
    pub const ALLOW: u8 = 5;
    /// A waiting datagram, or `NOT_FOUND` at once: never deferred.
    pub const POLL: u8 = 6;
    /// Version 2: connect to a listed address and port.
    pub const TCP_OPEN: u8 = 7;
    /// Version 2: queue a range of the buffer on a connection.
    pub const TCP_WRITE: u8 = 8;
    /// Version 2: read into a range of the buffer, deferred until data.
    pub const TCP_READ: u8 = 9;
    pub const TCP_CLOSE: u8 = 10;
    /// Version 2, `init` only: the TCP destinations of client `port`.
    pub const ALLOW_TCP: u8 = 11;
    /// Version 2: `TCP_OPEN` answered at once with the connection, which
    /// connects in the background (`TCP_POLL` says `REFUSED` if it fails),
    /// for a service that cannot wait in a deferred call (#271).
    pub const TCP_CONNECT: u8 = 12;
    /// Version 2: `TCP_READ` answered at once: `NOT_FOUND` if nothing has
    /// arrived (or it is still connecting).
    pub const TCP_POLL: u8 = 13;
}

pub const OK: u8 = status::OK;
pub const BAD_REQUEST: u8 = status::BAD_REQUEST;
pub const BUSY: u8 = status::BUSY;
pub const NO_ACCESS: u8 = status::NO_ACCESS;
pub const NOT_FOUND: u8 = status::NOT_FOUND;
/// The client's badge is not a port (0, or over 16 bits).
pub const NO_PORT: u8 = status::OWN;
/// Every client slot is taken.
pub const NO_ROOM: u8 = status::OWN + 1;
/// The peer refused the connection (reset), or did not answer in time.
pub const REFUSED: u8 = status::OWN + 2;
/// The connection is gone: closed, reset, or never opened.
pub const CLOSED: u8 = status::OWN + 3;
/// No buffer attached, or a range outside it.
pub const NO_BUFFER: u8 = status::NO_BUFFER;

/// Largest buffer a client may attach.
pub const MAX_BUFFER: u64 = 64 * 1024;

/// Largest payload in one request or reply.
pub const MAX_PAYLOAD: usize = 248;
/// Counters the service reports with `STATS`.
pub const STATS: usize = 6;
/// Most destinations one client may have.
pub const MAX_ALLOWED: usize = 8;

/// A UDP destination: IPv4 address and port.
pub type Dest = ([u8; 4], u16);

/// A client's destinations; unused entries are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Allowed {
    list: [Dest; MAX_ALLOWED],
    len: u8,
}

impl Allowed {
    pub const NONE: Self = Self {
        list: [([0; 4], 0); MAX_ALLOWED],
        len: 0,
    };

    /// `None` if more than [`MAX_ALLOWED`] or one has port 0.
    pub fn new(dests: &[Dest]) -> Option<Self> {
        let mut a = Self::default();
        for (slot, d) in a.list.iter_mut().zip(dests) {
            *slot = *d;
        }
        let ok = dests.len() <= MAX_ALLOWED && dests.iter().all(|d| d.1 != 0);
        a.len = dests.len() as u8;
        ok.then_some(a)
    }

    pub fn as_slice(&self) -> &[Dest] {
        &self.list[..usize::from(self.len)]
    }

    /// True if `ip:port` is listed.
    pub fn sends_to(&self, ip: [u8; 4], port: u16) -> bool {
        self.as_slice().contains(&(ip, port))
    }

    /// True if any destination has address `ip` (for `PING`).
    pub fn pings(&self, ip: [u8; 4]) -> bool {
        self.as_slice().iter().any(|d| d.0 == ip)
    }
}

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
    Allow {
        client: u16,
        dests: Allowed,
    },
    Poll,
    /// A `send`, not a `call`: its capability is the buffer.
    Attach {
        len: u64,
    },
    TcpOpen {
        ip: [u8; 4],
        port: u16,
    },
    TcpWrite {
        conn: u8,
        offset: u32,
        len: u32,
    },
    TcpRead {
        conn: u8,
        offset: u32,
        max: u32,
    },
    TcpClose {
        conn: u8,
    },
    TcpConnect {
        ip: [u8; 4],
        port: u16,
    },
    TcpPoll {
        conn: u8,
        offset: u32,
        max: u32,
    },
    AllowTcp {
        client: u16,
        dests: Allowed,
    },
}

/// Parses a request. A payload over [`MAX_PAYLOAD`] is `Bad`; it cannot
/// arrive in a 256-byte message anyway.
pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (version, code, body) = match msg {
        [v @ (VERSION | TCP_VERSION), op, body @ ..] => (*v, *op, body),
        [_, _, ..] => return Err(Refused::Version),
        _ => return Err(Refused::Bad),
    };
    let tcp = version == TCP_VERSION;
    let mut r = Reader::new(body);
    let addressed = |r: &mut Reader<'_>| -> Option<(u16, [u8; 4])> {
        Some((r.u16()?, r.take(4)?.try_into().ok()?))
    };
    let allowed = |r: &mut Reader<'_>| -> Option<(u16, Allowed)> {
        let client = r.u16()?;
        let count = usize::from(r.u8()?);
        let mut list = [([0u8; 4], 0u16); MAX_ALLOWED];
        for d in list.get_mut(..count)? {
            *d = (r.take(4)?.try_into().ok()?, r.u16()?);
        }
        Some((client, Allowed::new(&list[..count])?))
    };
    let range =
        |r: &mut Reader<'_>| -> Option<(u8, u32, u32)> { Some((r.u8()?, r.u32()?, r.u32()?)) };
    let req = match code {
        common::ATTACH => r.u64().map(|len| Request::Attach { len }),
        op::TCP_OPEN if tcp => addressed(&mut r).map(|(port, ip)| Request::TcpOpen { ip, port }),
        op::TCP_CONNECT if tcp => {
            addressed(&mut r).map(|(port, ip)| Request::TcpConnect { ip, port })
        }
        op::TCP_POLL if tcp => {
            range(&mut r).map(|(conn, offset, max)| Request::TcpPoll { conn, offset, max })
        }
        op::TCP_WRITE if tcp => {
            range(&mut r).map(|(conn, offset, len)| Request::TcpWrite { conn, offset, len })
        }
        op::TCP_READ if tcp => {
            range(&mut r).map(|(conn, offset, max)| Request::TcpRead { conn, offset, max })
        }
        op::TCP_CLOSE if tcp => r.u8().map(|conn| Request::TcpClose { conn }),
        op::ALLOW_TCP if tcp => {
            allowed(&mut r).map(|(client, dests)| Request::AllowTcp { client, dests })
        }
        op::SEND => addressed(&mut r).and_then(|(port, ip)| {
            let payload = r.rest();
            (payload.len() <= MAX_PAYLOAD).then_some(Request::Send { ip, port, payload })
        }),
        op::PING => addressed(&mut r).map(|(seq, ip)| Request::Ping { ip, seq }),
        op::RECV => Some(Request::Recv),
        op::STATS => Some(Request::Stats),
        op::POLL => Some(Request::Poll),
        op::ALLOW => allowed(&mut r).map(|(client, dests)| Request::Allow { client, dests }),
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
        Request::Poll => w.bytes(&[VERSION, op::POLL])?,
        Request::Allow { client, dests } => allow(&mut w, VERSION, op::ALLOW, client, dests)?,
        Request::AllowTcp { client, dests } => {
            allow(&mut w, TCP_VERSION, op::ALLOW_TCP, client, dests)?;
        }
        Request::Info => w.bytes(&[VERSION, common::INFO])?,
        Request::Attach { len } => {
            w.bytes(&[TCP_VERSION, common::ATTACH])?;
            w.u64(len)?;
        }
        Request::TcpOpen { ip, port } => {
            w.bytes(&[TCP_VERSION, op::TCP_OPEN])?;
            w.u16(port)?;
            w.bytes(&ip)?;
        }
        Request::TcpWrite { conn, offset, len } => {
            w.bytes(&[TCP_VERSION, op::TCP_WRITE, conn])?;
            w.u32(offset)?;
            w.u32(len)?;
        }
        Request::TcpRead { conn, offset, max } => {
            w.bytes(&[TCP_VERSION, op::TCP_READ, conn])?;
            w.u32(offset)?;
            w.u32(max)?;
        }
        Request::TcpClose { conn } => w.bytes(&[TCP_VERSION, op::TCP_CLOSE, conn])?,
        Request::TcpConnect { ip, port } => {
            w.bytes(&[TCP_VERSION, op::TCP_CONNECT])?;
            w.u16(port)?;
            w.bytes(&ip)?;
        }
        Request::TcpPoll { conn, offset, max } => {
            w.bytes(&[TCP_VERSION, op::TCP_POLL, conn])?;
            w.u32(offset)?;
            w.u32(max)?;
        }
    }
    Some(w.len())
}

fn allow(w: &mut Writer<'_>, version: u8, code: u8, client: u16, dests: Allowed) -> Option<()> {
    w.bytes(&[version, code])?;
    w.u16(client)?;
    w.bytes(&[dests.len])?;
    for (ip, port) in dests.as_slice() {
        w.bytes(ip)?;
        w.u16(*port)?;
    }
    Some(())
}

/// A `TCP_OPEN` reply: `[status, connection]`.
pub fn encode_opened(status: u8, conn: u8) -> [u8; 2] {
    [status, conn]
}

/// A `TCP_WRITE` or `TCP_READ` reply: `[status, 0, bytes (u32)]`.
pub fn encode_count(status: u8, n: u32) -> [u8; 6] {
    let b = n.to_le_bytes();
    [status, 0, b[0], b[1], b[2], b[3]]
}

/// `(status, bytes)` from a `TCP_WRITE` or `TCP_READ` reply; a bare status
/// (a refusal) counts 0.
pub fn parse_count(reply: &[u8]) -> Option<(u8, u32)> {
    match reply {
        [s] => Some((*s, 0)),
        [s, 0, n @ ..] => Some((*s, u32::from_le_bytes(n.try_into().ok()?))),
        _ => None,
    }
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
            Request::Poll,
            Request::Allow {
                client: 40_100,
                dests: Allowed::new(&[([10, 0, 2, 2], 47_000); MAX_ALLOWED]).unwrap(),
            },
            Request::Allow {
                client: 1,
                dests: Allowed::default(),
            },
            Request::Attach { len: MAX_BUFFER },
            Request::TcpOpen {
                ip: [10, 0, 2, 2],
                port: 443,
            },
            Request::TcpWrite {
                conn: 3,
                offset: 1,
                len: u32::MAX,
            },
            Request::TcpRead {
                conn: 0,
                offset: 0,
                max: 4096,
            },
            Request::TcpClose { conn: 255 },
            Request::TcpConnect {
                ip: [10, 0, 2, 2],
                port: 47_443,
            },
            Request::TcpPoll {
                conn: 15,
                offset: 2048,
                max: 8192,
            },
            Request::AllowTcp {
                client: 40_100,
                dests: Allowed::new(&[([10, 0, 2, 2], 443); MAX_ALLOWED]).unwrap(),
            },
        ];
        for req in reqs {
            let mut buf = [0u8; 300];
            let n = encode(&req, &mut buf).unwrap();
            assert!(n <= 256, "{req:?} fits a message");
            assert_eq!(parse(&buf[..n]), Ok(req));
            let tcp = matches!(
                req,
                Request::TcpOpen { .. }
                    | Request::TcpWrite { .. }
                    | Request::TcpRead { .. }
                    | Request::TcpClose { .. }
                    | Request::TcpConnect { .. }
                    | Request::TcpPoll { .. }
                    | Request::AllowTcp { .. }
            );
            assert_eq!(
                buf[0],
                if tcp || matches!(req, Request::Attach { .. }) {
                    TCP_VERSION
                } else {
                    VERSION
                }
            );
            let mut other = buf;
            other[0] = TCP_VERSION + 1;
            assert_eq!(parse(&other[..n]), Err(Refused::Version), "{req:?} v3");
            other[0] = if tcp { VERSION } else { TCP_VERSION };
            if tcp {
                assert_eq!(parse(&other[..n]), Err(Refused::Bad), "{req:?} as v1");
            } else {
                assert_eq!(parse(&other[..n]), Ok(req), "{req:?} as the other version");
            }
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
        let mut allow = [VERSION, op::ALLOW, 1, 0, 1, 10, 0, 2, 2, 0, 0];
        assert_eq!(parse(&allow), Err(Refused::Bad), "port 0");
        allow[9] = 1;
        assert!(parse(&allow).is_ok());
        allow[4] = MAX_ALLOWED as u8 + 1;
        assert_eq!(parse(&allow), Err(Refused::Bad), "more than the maximum");
        assert_eq!(Allowed::new(&[([1; 4], 1); MAX_ALLOWED + 1]), None);
        let a = Allowed::new(&[([10, 0, 2, 2], 47_000)]).unwrap();
        assert!(a.sends_to([10, 0, 2, 2], 47_000) && a.pings([10, 0, 2, 2]));
        assert!(!a.sends_to([10, 0, 2, 2], 47_001) && !a.pings([10, 0, 2, 3]));
        assert!(!Allowed::default().sends_to([0; 4], 0), "none: nothing");
        assert_eq!(
            parse(&[VERSION, op::TCP_CLOSE, 0]),
            Err(Refused::Bad),
            "TCP needs version 2"
        );
        assert_eq!(
            parse(&[TCP_VERSION, op::TCP_CLOSE]),
            Err(Refused::Bad),
            "no connection"
        );
        // Bytes 0-15 reach every operation, the TCP ones (7-13) included.
        crate::fuzz(100_000, 16, |m| {
            let mut v = [0u8; 302];
            v[0] = if m.first().is_some_and(|b| b & 1 == 0) {
                VERSION
            } else {
                TCP_VERSION
            };
            v[1..1 + m.len()].copy_from_slice(m);
            let _ = parse(&v[..1 + m.len()]);
            let _ = parse(m);
            let _ = parse_datagram(m);
            let _ = parse_count(m);
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
        assert_eq!(encode_opened(REFUSED, 0), [REFUSED, 0]);
        assert_eq!(parse_count(&encode_count(OK, 70_000)), Some((OK, 70_000)));
        assert_eq!(parse_count(&[CLOSED]), Some((CLOSED, 0)), "a bare refusal");
        assert_eq!(parse_count(&encode_count(OK, 1)[..5]), None, "truncated");
        assert_eq!((REFUSED, CLOSED), (status::OWN + 2, status::OWN + 3));
        assert_eq!(NO_PORT, status::OWN);
    }
}
