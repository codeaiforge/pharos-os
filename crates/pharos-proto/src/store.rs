//! The storage interface, version 1 (storage.md part 8): requests,
//! replies, status codes, and the namespaces clients get from their badge.
//!
//! Every request is a `call` except `ATTACH` ([`crate::op::ATTACH`]), a
//! plain `send` that carries a `Memory` capability: the client's buffer for
//! file data. A `call` carries only its reply capability, so file data
//! cannot travel with each request; each client attaches one buffer, and
//! `read` and `write` name a range of it.

use crate::{Reader, Refused, Writer, op as common, split, status};

pub const NAME: &[u8] = b"store";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    pub const STAT: u8 = 1;
    pub const READ: u8 = 2;
    pub const WRITE: u8 = 3;
    pub const APPEND: u8 = 4;
    pub const LIST: u8 = 5;
    pub const DELETE: u8 = 6;
    /// Reports the attached buffer's size (0: none).
    pub const BUFFER: u8 = 8;
    /// From `init` only (no badge): forget client `badge`'s buffer, as its
    /// process ended (#100).
    pub const RELEASE: u8 = 9;
}

/// Reply status codes: the common ones this interface uses, then its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = status::OK,
    BadRequest = status::BAD_REQUEST,
    Version = status::VERSION,
    NoAccess = status::NO_ACCESS,
    /// `read` or `write` with no attached buffer, or a range outside it.
    NoBuffer = status::NO_BUFFER,
    NotFound = status::NOT_FOUND,
    NoSpace = status::OWN,
    ReadOnly = status::OWN + 1,
    IoError = status::OWN + 2,
    Corrupt = status::OWN + 3,
}

impl Status {
    pub fn from_code(code: u8) -> Self {
        [
            Self::Ok,
            Self::Version,
            Self::NoAccess,
            Self::NoBuffer,
            Self::NotFound,
            Self::NoSpace,
            Self::ReadOnly,
            Self::IoError,
            Self::Corrupt,
        ]
        .into_iter()
        .find(|s| *s as u8 == code)
        .unwrap_or(Self::BadRequest)
    }
}

/// Largest record sent inline with `append`.
pub const MAX_INLINE: usize = 200;
/// Largest path a client names (its namespace prefix is added).
pub const MAX_CLIENT_PATH: usize = 80;
/// Largest buffer a client may attach (bytes): 16 clients fit in the
/// service's limit, so one client cannot take it all.
pub const MAX_BUFFER: u64 = 32 << 20;
/// Badge bit: the client may only read.
pub const READ_ONLY: u32 = 1 << 16;

/// Namespaces by number (badge bits 0–15): the path prefix each sees.
/// Reviewed code, like `init`'s service table.
pub const NAMESPACES: &[(u16, &[u8])] = &[
    (1, b"test"),
    (2, b"spare"),
    (3, b"models"),
    (4, b"crash"),
    // The agent runtime's tasks (#99), held only by the runtime.
    (5, b"agents"),
    // The audit trail (#107), held only by the audit service.
    (6, b"audit"),
    // Files the user gives agents (#127, tools.md), filled by the host
    // tool; the runtime holds it read-only.
    (7, b"files"),
    // Shared knowledge (#143, knowledge.md), held only by the knowledge
    // service.
    (8, b"knowledge"),
];

/// The namespace prefix for `badge` and whether it is read-only; `None`
/// for badge 0 or an unknown namespace.
pub fn namespace(badge: u32) -> Option<(&'static [u8], bool)> {
    let number = (badge & 0xffff) as u16;
    let (_, prefix) = NAMESPACES.iter().find(|(n, _)| *n == number && *n != 0)?;
    Some((prefix, badge & READ_ONLY != 0))
}

/// A parsed request. Paths are as the client sent them (relative to its
/// namespace) and not yet checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Stat {
        path: &'a [u8],
    },
    /// File bytes `offset..offset + len` into the buffer at `at`.
    Read {
        path: &'a [u8],
        offset: u64,
        len: u64,
        at: u64,
    },
    /// `len` bytes from the buffer at `at` become the whole file.
    Write {
        path: &'a [u8],
        len: u64,
        at: u64,
    },
    Append {
        path: &'a [u8],
        record: &'a [u8],
    },
    /// Names under `prefix`, from the `start`-th.
    List {
        prefix: &'a [u8],
        start: u32,
    },
    Delete {
        path: &'a [u8],
    },
    /// The attached capability's size in bytes.
    Attach {
        len: u64,
    },
    Buffer,
    /// The client badge whose buffer to drop.
    Release {
        client: u32,
    },
    Info,
}

fn path<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let n = usize::from(r.u8()?);
    if n > MAX_CLIENT_PATH {
        return None;
    }
    r.take(n)
}

/// Parses a request message (including trailing bytes: refused).
pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = (|| {
        Some(match code {
            op::STAT => Request::Stat {
                path: path(&mut r)?,
            },
            op::READ => Request::Read {
                path: path(&mut r)?,
                offset: r.u64()?,
                len: r.u64()?,
                at: r.u64()?,
            },
            op::WRITE => Request::Write {
                path: path(&mut r)?,
                len: r.u64()?,
                at: r.u64()?,
            },
            op::APPEND => {
                let path = path(&mut r)?;
                let n = usize::from(r.u8()?);
                if n == 0 || n > MAX_INLINE {
                    return None;
                }
                Request::Append {
                    path,
                    record: r.take(n)?,
                }
            }
            op::LIST => Request::List {
                prefix: path(&mut r)?,
                start: r.u32()?,
            },
            op::DELETE => Request::Delete {
                path: path(&mut r)?,
            },
            op::BUFFER => Request::Buffer,
            op::RELEASE => Request::Release { client: r.u32()? },
            common::ATTACH => Request::Attach { len: r.u64()? },
            common::INFO => Request::Info,
            _ => return None,
        })
    })();
    match req {
        Some(req) if r.is_empty() => Ok(req),
        _ => Err(Refused::Bad),
    }
}

/// Writes `req` into `out`; returns its length (`None` if it does not fit
/// or a field is too long).
pub fn encode(req: &Request<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    let path_len = |p: &[u8]| (p.len() <= MAX_CLIENT_PATH).then_some(p.len() as u8);
    let head = |w: &mut Writer<'_>, code: u8| w.bytes(&[VERSION, code]);
    match *req {
        Request::Stat { path: p } | Request::Delete { path: p } => {
            let code = if matches!(req, Request::Stat { .. }) {
                op::STAT
            } else {
                op::DELETE
            };
            head(&mut w, code)?;
            w.bytes(&[path_len(p)?])?;
            w.bytes(p)?;
        }
        Request::Read {
            path: p,
            offset,
            len,
            at,
        } => {
            head(&mut w, op::READ)?;
            w.bytes(&[path_len(p)?])?;
            w.bytes(p)?;
            w.u64(offset)?;
            w.u64(len)?;
            w.u64(at)?;
        }
        Request::Write { path: p, len, at } => {
            head(&mut w, op::WRITE)?;
            w.bytes(&[path_len(p)?])?;
            w.bytes(p)?;
            w.u64(len)?;
            w.u64(at)?;
        }
        Request::Append { path: p, record } => {
            if record.is_empty() || record.len() > MAX_INLINE {
                return None;
            }
            head(&mut w, op::APPEND)?;
            w.bytes(&[path_len(p)?])?;
            w.bytes(p)?;
            w.bytes(&[record.len() as u8])?;
            w.bytes(record)?;
        }
        Request::List { prefix, start } => {
            head(&mut w, op::LIST)?;
            w.bytes(&[path_len(prefix)?])?;
            w.bytes(prefix)?;
            w.u32(start)?;
        }
        Request::Attach { len } => {
            head(&mut w, common::ATTACH)?;
            w.u64(len)?;
        }
        Request::Buffer => head(&mut w, op::BUFFER)?,
        Request::Release { client } => {
            head(&mut w, op::RELEASE)?;
            w.u32(client)?;
        }
        Request::Info => head(&mut w, common::INFO)?,
    }
    Some(w.len())
}

/// `prefix/path` (or `prefix` for an empty `path` in `list`) in `out`, if
/// the result is a valid store path; returns its length.
pub fn full_path(prefix: &[u8], path: &[u8], out: &mut [u8; 104]) -> Option<usize> {
    let n = prefix.len() + 1 + path.len();
    if n > out.len() {
        return None;
    }
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()] = b'/';
    out[prefix.len() + 1..n].copy_from_slice(path);
    pharos_fs::valid_path(&out[..n]).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let reqs = [
            Request::Stat { path: b"a/b" },
            Request::Read {
                path: b"m.bin",
                offset: 7,
                len: 1 << 40,
                at: 4096,
            },
            Request::Write {
                path: b"x",
                len: 3,
                at: 0,
            },
            Request::Append {
                path: b"log",
                record: &[9; MAX_INLINE],
            },
            Request::List {
                prefix: b"",
                start: 5,
            },
            Request::Delete { path: b"old" },
            Request::Attach { len: 65536 },
            Request::Buffer,
            Request::Release {
                client: 3 | READ_ONLY,
            },
            Request::Info,
        ];
        for req in reqs {
            let mut buf = [0u8; 256];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(
                &buf[..2],
                &[VERSION, buf[1]],
                "{req:?} starts with the version"
            );
            assert_eq!(parse(&buf[..n]), Ok(req));
            assert!(parse(&buf[..n - 1]).is_err(), "{req:?} truncated");
            let mut long = buf;
            long[n] = 0;
            assert_eq!(parse(&long[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
            let mut other = buf;
            other[0] = VERSION + 1;
            assert_eq!(parse(&other[..n]), Err(Refused::Version), "{req:?} v2");
        }
    }

    #[test]
    fn bad_requests_are_refused() {
        assert_eq!(parse(&[]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, 0]), Err(Refused::Bad), "unknown op");
        assert_eq!(
            parse(&[VERSION, op::STAT, 200]),
            Err(Refused::Bad),
            "path length past the message"
        );
        let mut long = [0u8; 100];
        long[..3].copy_from_slice(&[VERSION, op::STAT, 81]);
        assert_eq!(parse(&long[..84]), Err(Refused::Bad), "path over 80 bytes");
        assert_eq!(
            parse(&[VERSION, op::APPEND, 1, b'a', 0]),
            Err(Refused::Bad),
            "empty record"
        );
        let path = [b'a'; 81];
        assert_eq!(encode(&Request::Stat { path: &path }, &mut [0; 256]), None);
        let empty = Request::Append {
            path: b"a",
            record: &[],
        };
        assert_eq!(encode(&empty, &mut [0; 256]), None);
        assert_eq!(
            encode(&Request::Stat { path: b"abc" }, &mut [0; 4]),
            None,
            "too small"
        );
        crate::fuzz(100_000, 12, |m| {
            let _ = parse(m);
        });
        // With the right version, so the fuzzer reaches the bodies.
        crate::fuzz(100_000, 12, |m| {
            let mut v = [0u8; 302];
            v[0] = VERSION;
            v[1..1 + m.len()].copy_from_slice(m);
            let _ = parse(&v[..1 + m.len()]);
        });
    }

    #[test]
    fn namespaces_paths_and_statuses() {
        assert_eq!(namespace(1), Some((&b"test"[..], false)));
        assert_eq!(namespace(1 | READ_ONLY), Some((&b"test"[..], true)));
        assert_eq!(namespace(0), None, "badge 0");
        assert_eq!(namespace(99), None, "unknown");
        let mut out = [0u8; 104];
        let n = full_path(b"test", b"a/b.txt", &mut out).unwrap();
        assert_eq!(&out[..n], b"test/a/b.txt");
        assert_eq!(full_path(b"test", b"../x", &mut out), None, "no escape");
        assert_eq!(full_path(b"test", b"", &mut out), None, "empty path");
        assert_eq!(full_path(b"test", b"a//b", &mut out), None);
        assert_eq!(full_path(b"test", &[b'a'; 100], &mut out), None, "too long");
        for s in [
            Status::Ok,
            Status::Version,
            Status::NoAccess,
            Status::NoBuffer,
            Status::NotFound,
            Status::NoSpace,
            Status::ReadOnly,
            Status::IoError,
            Status::Corrupt,
        ] {
            assert_eq!(Status::from_code(s as u8), s);
        }
        assert_eq!(Status::from_code(200), Status::BadRequest);
        assert_eq!(Status::NoSpace as u8, status::OWN, "own codes from 32");
    }
}
