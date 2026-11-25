//! The gateway interface, version 1 (gateway.md, D-035): an HTTPS request
//! on a compiled route, with the route's secret injected by the gateway
//! and stripped from the answer.
//!
//! A client names a route by its name, and puts the path (with any
//! query) and then the body at offset 0 of its attached buffer. The answer
//! comes back in the same buffer: the content type, then the body. The
//! client never names a host, a header, or a secret.
//!
//! Requests: `[1, ATTACH, size (u64)]` (a `send` with the buffer),
//! `[1, REQUEST, name length, route name, path length (u16), body length
//! (u32)]`, `[1, INFO]`.
//! A `REQUEST` reply is `[status, detail, http (u16), type length,
//! answer length (u32), stripped, sent]`; a refusal before the request is
//! sent is a bare status. `sent` is 1 once the request may have reached
//! the server, whatever the status (#293, M6.2 review R-11).

use crate::{Reader, Refused, Writer, op as common, status};

pub const NAME: &[u8] = b"gateway";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    /// An HTTPS request on a route; deferred until the answer.
    pub const REQUEST: u8 = 1;
}

pub const OK: u8 = status::OK;
/// A path the route's pattern refuses.
pub const BAD_REQUEST: u8 = status::BAD_REQUEST;
/// A route not listed for this client.
pub const NO_ACCESS: u8 = status::NO_ACCESS;
pub const BUSY: u8 = status::BUSY;
/// A body over the route's `max_body`.
pub const TOO_LARGE: u8 = status::TOO_LARGE;
pub const NO_BUFFER: u8 = status::NO_BUFFER;
pub const NOT_FOUND: u8 = status::NOT_FOUND;
/// The route's secret is not in the host's file.
pub const NO_SECRET: u8 = crate::vault::NO_SECRET;
/// The TLS service refused: `detail` is its status, `http` its reason.
pub const TLS: u8 = status::OWN + 9;
/// The server's answer was refused: `detail` is an
/// [`http::reason`](crate::http::reason).
pub const ANSWER: u8 = status::OWN + 10;
/// The request or its outcome could not be recorded.
pub const NO_AUDIT: u8 = crate::vault::NO_AUDIT;
/// The whole request took over [`TIMEOUT_US`].
pub const TIMEOUT: u8 = status::OWN + 12;

/// Largest buffer a client may attach.
pub const MAX_BUFFER: u64 = 64 * 1024;
/// How long one request may take, end to end, from when the gateway takes
/// it: past this the gateway neither writes an answer nor replies (#289).
pub const TIMEOUT_US: u64 = 30_000_000;
/// The gateway's TLS exchange ends this long before [`TIMEOUT_US`], room
/// for what follows it: the close, the second release (two tries), and
/// the outcome record, 1 s each (#289, M6.2 review R-6).
pub const TAIL_US: u64 = 5_000_000;
/// How long the runtime waits for a request: the gateway's whole bound and
/// a margin, so the runtime never gives up on a request that then takes
/// effect, unless the gateway was not answering at all.
pub const WAIT_US: u64 = TIMEOUT_US + 5_000_000;
const _: () = assert!(TAIL_US >= 4 * crate::vault::RELEASE_US);
const _: () = assert!(WAIT_US >= TIMEOUT_US + 2_000_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// A `send`, not a `call`: its capability is the buffer.
    Attach {
        len: u64,
    },
    Request {
        /// A route's name (`vault::valid_name`).
        route: &'a [u8],
        path_len: u16,
        body_len: u32,
    },
    Info,
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = crate::split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = match code {
        common::ATTACH => r.u64().map(|len| Request::Attach { len }),
        op::REQUEST => (|| {
            let n = usize::from(r.u8()?);
            Some(Request::Request {
                route: r.take(n).filter(|n| crate::vault::valid_name(n))?,
                path_len: r.u16()?,
                body_len: r.u32()?,
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
        Request::Request {
            route,
            path_len,
            body_len,
        } => {
            if !crate::vault::valid_name(route) {
                return None;
            }
            w.bytes(&[VERSION, op::REQUEST, route.len() as u8])?;
            w.bytes(route)?;
            w.u16(path_len)?;
            w.u32(body_len)?;
        }
        Request::Info => w.bytes(&[VERSION, common::INFO])?,
    }
    Some(w.len())
}

/// A `REQUEST` reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Answered {
    pub status: u8,
    /// `ANSWER`'s reason, or the TLS service's status on `TLS`.
    pub detail: u8,
    /// The HTTP status on `OK`; the TLS service's reason on `TLS`.
    pub http: u16,
    pub type_len: u8,
    pub answer_len: u32,
    /// How many times the secret was replaced by `[secret]`.
    pub stripped: u8,
    /// The gateway began writing the request: the server may have acted
    /// on it, even when the status says the answer failed (#293).
    pub sent: bool,
}

impl Answered {
    /// A full reply's length. Version 1 grew from 10 bytes to 11 with
    /// `sent` (#293): the gateway, the runtime, and the guest library all
    /// build from this tree, so none speaks the older length.
    pub const LEN: usize = 11;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.status;
        out[1] = self.detail;
        out[2..4].copy_from_slice(&self.http.to_le_bytes());
        out[4] = self.type_len;
        out[5..9].copy_from_slice(&self.answer_len.to_le_bytes());
        out[9] = self.stripped;
        out[10] = self.sent.into();
        out
    }

    /// A full reply, or a bare status (with everything else 0).
    pub fn parse(reply: &[u8]) -> Option<Self> {
        if let [s] = reply {
            return Some(Self {
                status: *s,
                ..Self::default()
            });
        }
        let mut r = Reader::new(reply);
        let a = Self {
            status: r.u8()?,
            detail: r.u8()?,
            http: r.u16()?,
            type_len: r.u8()?,
            answer_len: r.u32()?,
            stripped: r.u8()?,
            sent: match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            },
        };
        r.is_empty().then_some(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_replies_round_trip_and_truncations_are_refused() {
        for req in [
            Request::Attach { len: 65_536 },
            Request::Request {
                route: b"issues",
                path_len: 300,
                body_len: 70_000,
            },
            Request::Info,
        ] {
            let mut out = [0u8; 32];
            let n = encode(&req, &mut out).unwrap();
            assert_eq!(parse(&out[..n]), Ok(req));
            for cut in 0..n {
                assert!(parse(&out[..cut]).is_err(), "{req:?} cut at {cut}");
            }
            let mut long = out;
            long[n] = 0;
            assert_eq!(parse(&long[..=n]), Err(Refused::Bad));
        }
        assert_eq!(parse(&[2, op::REQUEST]), Err(Refused::Version));
        assert_eq!(parse(&[1, 7]), Err(Refused::Bad));
        assert_eq!(
            parse(&[1, op::REQUEST, 1, b'A', 0, 0, 0, 0, 0, 0]),
            Err(Refused::Bad)
        );
        assert_eq!(
            parse(&[1, op::REQUEST, 0, 0, 0, 0, 0, 0, 0]),
            Err(Refused::Bad)
        );
        let bad = Request::Request {
            route: b"a.b",
            path_len: 1,
            body_len: 0,
        };
        assert_eq!(encode(&bad, &mut [0u8; 32]), None);
        let a = Answered {
            status: ANSWER,
            detail: 3,
            http: 200,
            type_len: 16,
            answer_len: 40_000,
            stripped: 2,
            sent: true,
        };
        assert_eq!(a.encode()[10], 1);
        assert_eq!(Answered::parse(&a.encode()), Some(a));
        let unsent = Answered { sent: false, ..a };
        assert_eq!(unsent.encode()[10], 0);
        assert_eq!(Answered::parse(&unsent.encode()), Some(unsent));
        for cut in 2..Answered::LEN {
            assert_eq!(Answered::parse(&a.encode()[..cut]), None, "cut at {cut}");
        }
        let mut bad = a.encode();
        bad[10] = 2;
        assert_eq!(Answered::parse(&bad), None, "sent is 0 or 1");
        assert_eq!(
            Answered::parse(&[a.encode().as_slice(), &[0]].concat()),
            None
        );
        assert_eq!(
            Answered::parse(&[NO_SECRET]).map(|a| (a.status, a.sent)),
            Some((NO_SECRET, false))
        );
        assert_eq!(Answered::parse(&[]), None);
    }

    #[test]
    fn statuses_are_the_designs_and_distinct() {
        assert_eq!(
            [NO_SECRET, TLS, ANSWER, NO_AUDIT, TIMEOUT],
            [40, 41, 42, 43, 44]
        );
    }

    #[test]
    fn fuzzed_messages_never_panic_and_what_parses_round_trips() {
        // #283: half the messages start as a `REQUEST` with a short name
        // of route characters, so the deep path is reached.
        let mut accepted = 0;
        crate::fuzz(100_000, 255, |m| {
            let _ = Answered::parse(m);
            let mut msg = std::vec![VERSION, op::REQUEST, (m.len() % 6) as u8];
            msg.extend(
                m.iter()
                    .map(|b| b"ab-_9Z."[usize::from(*b) % 7])
                    .take(m.len() % 6),
            );
            msg.extend(m.iter().take(6));
            for msg in [&msg[..], m] {
                if let Ok(req) = parse(msg) {
                    accepted += 1;
                    let mut out = [0u8; 300];
                    let n = encode(&req, &mut out).expect("what parses encodes");
                    assert_eq!(&out[..n], msg, "{req:?}");
                }
            }
        });
        assert!(accepted > 100, "only {accepted} fuzzed messages parsed");
    }
}
