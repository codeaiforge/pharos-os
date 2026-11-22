//! The TLS interface, version 1 (tls.md, D-034): TLS 1.3 connections to
//! destinations `init` lists, opened by index. A client is known by its
//! badge (1 to [`MAX_CLIENTS`]); badge 0 is `init`'s, the only one that may
//! `ALLOW`.
//!
//! Destinations come from `init`, never from the client: `ALLOW` sets, for
//! one client, destination *i*: an IPv4 address, a port, and the server
//! name checked against the certificate and sent as SNI. A client opens a
//! connection by index, so it can neither name another host nor have a
//! certificate checked against a name of its choosing.
//!
//! Data moves through one shared buffer per client, attached with `ATTACH`
//! (a `send` carrying the `Memory` capability); `WRITE` and `READ` name a
//! range of it, and reply as `net`'s TCP ones do
//! ([`net::encode_count`](crate::net::encode_count)).
//!
//! Requests: `[1, OPEN, destination]`, `[1, WRITE or READ, conn, offset
//! (u32), length (u32)]`, `[1, CLOSE, conn]`, `[1, ALLOW, client,
//! destination, IPv4 address (4), port (u16), name length, name]`.

use crate::{Reader, Refused, Writer, op as common, status};

pub const NAME: &[u8] = b"tls";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    /// Handshake with a listed destination; the reply waits for its end.
    pub const OPEN: u8 = 1;
    /// Encrypt and send a range of the buffer.
    pub const WRITE: u8 = 2;
    /// Decrypt into a range of the buffer, deferred until data.
    pub const READ: u8 = 3;
    /// Send `close_notify` and end the connection.
    pub const CLOSE: u8 = 4;
    /// `init` only: destination *i* of a client, replacing it.
    pub const ALLOW: u8 = 5;
}

pub const OK: u8 = status::OK;
pub const BAD_REQUEST: u8 = status::BAD_REQUEST;
pub const NO_ACCESS: u8 = status::NO_ACCESS;
pub const NO_BUFFER: u8 = status::NO_BUFFER;
pub const OVER_LIMIT: u8 = status::OVER_LIMIT;
/// The handshake failed; the reply's third byte is a [`reason`].
pub const HANDSHAKE: u8 = status::OWN;
/// No wall-clock time: certificates cannot be checked.
pub const NO_CLOCK: u8 = status::OWN + 1;
/// No seed for the random generator.
pub const NO_RANDOM: u8 = status::OWN + 2;
/// The connection is gone: the server reset it, a record failed to
/// decrypt, or it was never opened.
pub const CLOSED: u8 = status::OWN + 3;
/// The audit service could not store the intent, so nothing was sent.
pub const NO_AUDIT: u8 = status::OWN + 4;

/// Why a handshake failed (`HANDSHAKE`'s reason byte).
pub mod reason {
    pub const UNKNOWN_ISSUER: u8 = 1;
    /// Expired or not yet valid.
    pub const EXPIRED: u8 = 2;
    pub const NAME: u8 = 3;
    pub const CERTIFICATE: u8 = 4;
    /// A protocol error or an alert, including no suite or group in common.
    pub const PROTOCOL: u8 = 5;
    /// The TCP connection was refused or not answered.
    pub const TCP: u8 = 6;
    /// The handshake did not end in time.
    pub const TIMEOUT: u8 = 7;
}

/// Most clients (badges 1 to 8).
pub const MAX_CLIENTS: u8 = 8;
/// Most destinations per client.
pub const MAX_DESTINATIONS: u8 = 8;
/// Longest server name (a DNS name; no IP-address names).
pub const MAX_NAME: usize = 64;
/// Largest buffer a client may attach.
pub const MAX_BUFFER: u64 = 64 * 1024;

/// A destination: address, port, and the server's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destination<'a> {
    pub ip: [u8; 4],
    pub port: u16,
    pub name: &'a [u8],
}

/// Whether `name` is a DNS name this interface accepts: 1 to 64 bytes of
/// labels (letters, digits, `-`, not at either end of a label) separated
/// by dots, with at least one letter (so `10.0.2.2` is not one).
pub fn valid_name(name: &[u8]) -> bool {
    name.len() <= MAX_NAME
        && name.iter().any(u8::is_ascii_alphabetic)
        && name.split(|b| *b == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// A `send`, not a `call`: its capability is the buffer.
    Attach {
        len: u64,
    },
    Open {
        destination: u8,
    },
    Write {
        conn: u8,
        offset: u32,
        len: u32,
    },
    Read {
        conn: u8,
        offset: u32,
        max: u32,
    },
    Close {
        conn: u8,
    },
    Allow {
        client: u8,
        destination: u8,
        dest: Destination<'a>,
    },
    Info,
}

/// Parses a request; anything malformed, out of range, or with an invalid
/// name is `Bad`.
pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = crate::split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let range = |r: &mut Reader<'_>| Some((r.u8()?, r.u32()?, r.u32()?));
    let req = match code {
        common::ATTACH => r.u64().map(|len| Request::Attach { len }),
        op::OPEN => r.u8().map(|destination| Request::Open { destination }),
        op::WRITE => range(&mut r).map(|(conn, offset, len)| Request::Write { conn, offset, len }),
        op::READ => range(&mut r).map(|(conn, offset, max)| Request::Read { conn, offset, max }),
        op::CLOSE => r.u8().map(|conn| Request::Close { conn }),
        op::ALLOW => (|| {
            let (client, destination) = (r.u8()?, r.u8()?);
            let ip = r.take(4)?.try_into().ok()?;
            let port = r.u16()?;
            let n = usize::from(r.u8()?);
            let name = r.take(n)?;
            let ok = (1..=MAX_CLIENTS).contains(&client)
                && destination < MAX_DESTINATIONS
                && port != 0
                && valid_name(name);
            ok.then_some(Request::Allow {
                client,
                destination,
                dest: Destination { ip, port, name },
            })
        })(),
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
        Request::Attach { len } => {
            w.bytes(&[VERSION, common::ATTACH])?;
            w.u64(len)?;
        }
        Request::Open { destination } => w.bytes(&[VERSION, op::OPEN, destination])?,
        Request::Write { conn, offset, len } => {
            w.bytes(&[VERSION, op::WRITE, conn])?;
            w.u32(offset)?;
            w.u32(len)?;
        }
        Request::Read { conn, offset, max } => {
            w.bytes(&[VERSION, op::READ, conn])?;
            w.u32(offset)?;
            w.u32(max)?;
        }
        Request::Close { conn } => w.bytes(&[VERSION, op::CLOSE, conn])?,
        Request::Allow {
            client,
            destination,
            dest,
        } => {
            if !valid_name(dest.name) {
                return None;
            }
            w.bytes(&[VERSION, op::ALLOW, client, destination])?;
            w.bytes(&dest.ip)?;
            w.u16(dest.port)?;
            w.bytes(&[dest.name.len() as u8])?;
            w.bytes(dest.name)?;
        }
        Request::Info => w.bytes(&[VERSION, common::INFO])?,
    }
    Some(w.len())
}

/// An `OPEN` reply: `[status, connection, reason]` (reason 0 unless
/// `HANDSHAKE`).
pub fn encode_opened(status: u8, conn: u8, reason: u8) -> [u8; 3] {
    [status, conn, reason]
}

/// `(status, connection, reason)` from an `OPEN` reply; a bare status (a
/// refusal) has connection and reason 0.
pub fn parse_opened(reply: &[u8]) -> Option<(u8, u8, u8)> {
    match reply {
        [s] => Some((*s, 0, 0)),
        [s, c, r] => Some((*s, *c, *r)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: Destination<'static> = Destination {
        ip: [10, 0, 2, 2],
        port: 47_443,
        name: b"pharos-test.local",
    };

    fn all() -> [Request<'static>; 7] {
        [
            Request::Attach { len: 65_536 },
            Request::Open { destination: 3 },
            Request::Write {
                conn: 1,
                offset: 4,
                len: 100,
            },
            Request::Read {
                conn: 2,
                offset: 1024,
                max: 4096,
            },
            Request::Close { conn: 1 },
            Request::Allow {
                client: 8,
                destination: 7,
                dest: DEST,
            },
            Request::Info,
        ]
    }

    #[test]
    fn every_request_round_trips_and_every_truncation_is_refused() {
        for req in all() {
            let mut buf = [0u8; 256];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(req), "{req:?}");
            for cut in 0..n {
                assert!(parse(&buf[..cut]).is_err(), "{req:?} cut at {cut}");
            }
            let mut long = buf[..=n].to_vec();
            long[n] = 0;
            assert_eq!(parse(&long), Err(Refused::Bad), "{req:?} with a byte more");
        }
    }

    #[test]
    fn other_versions_and_operations_are_refused() {
        assert_eq!(parse(&[2, op::OPEN, 0]), Err(Refused::Version));
        assert_eq!(parse(&[0, op::OPEN, 0]), Err(Refused::Version));
        assert_eq!(parse(&[VERSION, 6]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION]), Err(Refused::Bad));
    }

    #[test]
    fn allow_refuses_bad_clients_destinations_ports_and_names() {
        let allow = |client, destination, port, name: &[u8]| {
            let mut buf = [0u8; 256];
            let mut w = Writer::new(&mut buf);
            w.bytes(&[VERSION, op::ALLOW, client, destination]).unwrap();
            w.bytes(&[10, 0, 2, 2]).unwrap();
            w.u16(port).unwrap();
            w.bytes(&[name.len() as u8]).unwrap();
            w.bytes(name).unwrap();
            let n = w.len();
            parse(&buf[..n]).is_ok()
        };
        assert!(allow(1, 0, 443, b"example.test"));
        assert!(!allow(0, 0, 443, b"example.test"), "client 0 is init");
        assert!(!allow(9, 0, 443, b"example.test"), "client 9");
        assert!(!allow(1, 8, 443, b"example.test"), "destination 8");
        assert!(!allow(1, 0, 0, b"example.test"), "port 0");
        assert!(!allow(1, 0, 443, b"10.0.2.2"), "an IP address");
        assert!(!allow(1, 0, 443, b""), "empty");
        assert!(!allow(1, 0, 443, b"bad..name"), "an empty label");
        assert!(!allow(1, 0, 443, b"-bad.test"), "a leading hyphen");
        assert!(!allow(1, 0, 443, b"bad_name.test"), "an underscore");
        let mut name = b"a.".repeat(31);
        name.extend_from_slice(b"ab");
        assert!(allow(1, 0, 443, &name), "64 bytes");
        name.push(b'c');
        assert!(!allow(1, 0, 443, &name), "65 bytes");
        // encode refuses an invalid name too.
        let mut buf = [0u8; 256];
        let bad = Request::Allow {
            client: 1,
            destination: 0,
            dest: Destination {
                name: b"10.0.2.2",
                ..DEST
            },
        };
        assert_eq!(encode(&bad, &mut buf), None);
    }

    #[test]
    fn open_replies_round_trip() {
        let r = encode_opened(HANDSHAKE, 0, reason::NAME);
        assert_eq!(parse_opened(&r), Some((HANDSHAKE, 0, reason::NAME)));
        assert_eq!(parse_opened(&[NO_ACCESS]), Some((NO_ACCESS, 0, 0)));
        assert_eq!(parse_opened(&r[..2]), None);
        assert_eq!(parse_opened(&[]), None);
    }
}
