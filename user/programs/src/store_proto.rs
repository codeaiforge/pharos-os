//! The storage service's protocol (storage.md part 8): requests, replies,
//! status codes, and the namespaces clients get from their badge. Shared
//! by the service and its clients, and host-tested.
//!
//! Every request is a `call` (one message, little-endian fields, the path
//! as a length byte and bytes) except `ATTACH`, a plain `send` that carries
//! a `Memory` capability: the client's buffer for file data. A `call`
//! carries only its reply capability, so file data cannot travel with each
//! request; each client attaches one buffer instead, and `read` and `write`
//! name a range of it.

/// Request codes.
pub mod op {
    pub const STAT: u8 = 1;
    pub const READ: u8 = 2;
    pub const WRITE: u8 = 3;
    pub const APPEND: u8 = 4;
    pub const LIST: u8 = 5;
    pub const DELETE: u8 = 6;
    /// `send` with a `Memory` capability (`READ | WRITE`) and its size:
    /// the buffer.
    pub const ATTACH: u8 = 7;
    /// Reports the attached buffer's size (0: none).
    pub const BUFFER: u8 = 8;
}

/// Reply status codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    BadRequest = 1,
    NotFound = 2,
    NoSpace = 3,
    ReadOnly = 4,
    NoAccess = 5,
    IoError = 6,
    Corrupt = 7,
    /// `read` or `write` with no attached buffer, or a range outside it.
    NoBuffer = 8,
}

impl Status {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Ok,
            2 => Self::NotFound,
            3 => Self::NoSpace,
            4 => Self::ReadOnly,
            5 => Self::NoAccess,
            6 => Self::IoError,
            7 => Self::Corrupt,
            8 => Self::NoBuffer,
            _ => Self::BadRequest,
        }
    }
}

/// Largest record sent inline with `append`.
pub const MAX_INLINE: usize = 200;
/// Largest path a client names (its namespace prefix is added).
pub const MAX_CLIENT_PATH: usize = 80;
/// Badge bit: the client may only read.
pub const READ_ONLY: u32 = 1 << 16;

/// Namespaces by number (badge bits 0–15): the path prefix each sees.
/// Reviewed code, like `init`'s service table.
pub const NAMESPACES: &[(u16, &[u8])] =
    &[(1, b"test"), (2, b"spare"), (3, b"models"), (4, b"crash")];

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
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        (n <= self.0.len()).then(|| {
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            a
        })
    }
    fn path(&mut self) -> Option<&'a [u8]> {
        let n = *self.take(1)?.first()? as usize;
        if n > MAX_CLIENT_PATH {
            return None;
        }
        self.take(n)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
}

/// Parses a request message; `None` if malformed (including trailing
/// bytes).
pub fn parse(msg: &[u8]) -> Option<Request<'_>> {
    let (&code, rest) = msg.split_first()?;
    let mut r = Reader(rest);
    let req = match code {
        op::STAT => Request::Stat { path: r.path()? },
        op::READ => Request::Read {
            path: r.path()?,
            offset: r.u64()?,
            len: r.u64()?,
            at: r.u64()?,
        },
        op::WRITE => Request::Write {
            path: r.path()?,
            len: r.u64()?,
            at: r.u64()?,
        },
        op::APPEND => {
            let path = r.path()?;
            let n = *r.take(1)?.first()? as usize;
            if n == 0 || n > MAX_INLINE {
                return None;
            }
            Request::Append {
                path,
                record: r.take(n)?,
            }
        }
        op::LIST => Request::List {
            prefix: r.path()?,
            start: r.u32()?,
        },
        op::DELETE => Request::Delete { path: r.path()? },
        op::ATTACH => Request::Attach { len: r.u64()? },
        op::BUFFER => Request::Buffer,
        _ => return None,
    };
    r.0.is_empty().then_some(req)
}

/// Writes `req` into `out`; returns its length (`None` if it does not fit
/// or a field is too long).
pub fn encode(req: &Request<'_>, out: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    let mut put = |bytes: &[u8]| -> Option<()> {
        out.get_mut(n..n + bytes.len())?.copy_from_slice(bytes);
        n += bytes.len();
        Some(())
    };
    let path = |p: &[u8]| (p.len() <= MAX_CLIENT_PATH).then_some(p.len() as u8);
    match *req {
        Request::Stat { path: p } | Request::Delete { path: p } => {
            let code = if matches!(req, Request::Stat { .. }) {
                op::STAT
            } else {
                op::DELETE
            };
            put(&[code, path(p)?])?;
            put(p)?;
        }
        Request::Read {
            path: p,
            offset,
            len,
            at,
        } => {
            put(&[op::READ, path(p)?])?;
            put(p)?;
            put(&offset.to_le_bytes())?;
            put(&len.to_le_bytes())?;
            put(&at.to_le_bytes())?;
        }
        Request::Write { path: p, len, at } => {
            put(&[op::WRITE, path(p)?])?;
            put(p)?;
            put(&len.to_le_bytes())?;
            put(&at.to_le_bytes())?;
        }
        Request::Append { path: p, record } => {
            if record.is_empty() || record.len() > MAX_INLINE {
                return None;
            }
            put(&[op::APPEND, path(p)?])?;
            put(p)?;
            put(&[record.len() as u8])?;
            put(record)?;
        }
        Request::List { prefix, start } => {
            put(&[op::LIST, path(prefix)?])?;
            put(prefix)?;
            put(&start.to_le_bytes())?;
        }
        Request::Attach { len } => {
            put(&[op::ATTACH])?;
            put(&len.to_le_bytes())?;
        }
        Request::Buffer => put(&[op::BUFFER])?,
    }
    Some(n)
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
        ];
        for req in reqs {
            let mut buf = [0u8; 256];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Some(req));
            assert_eq!(
                parse(&buf[..n - 1]).filter(|_| n > 1),
                None,
                "{req:?} truncated"
            );
            let mut long = buf;
            long[n] = 0;
            assert_eq!(parse(&long[..n + 1]), None, "{req:?} with a trailing byte");
        }
    }

    #[test]
    fn bad_requests_are_refused() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0]), None, "unknown op");
        assert_eq!(
            parse(&[op::STAT, 200]),
            None,
            "path length past the message"
        );
        let mut long = [0u8; 100];
        long[..2].copy_from_slice(&[op::STAT, 81]);
        assert_eq!(parse(&long[..83]), None, "path over 80 bytes");
        assert_eq!(parse(&[op::APPEND, 1, b'a', 0]), None, "empty record");
        let path = [b'a'; 81];
        assert_eq!(encode(&Request::Stat { path: &path }, &mut [0; 256]), None);
        assert_eq!(
            encode(
                &Request::Append {
                    path: b"a",
                    record: &[]
                },
                &mut [0; 256]
            ),
            None
        );
        assert_eq!(
            encode(&Request::Stat { path: b"abc" }, &mut [0; 3]),
            None,
            "too small"
        );
        // Random bytes never panic.
        let mut x = 0x1234_5678_9abc_def1u64;
        for _ in 0..100_000 {
            let mut msg = [0u8; 64];
            for b in msg.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8 % 12;
            }
            let _ = parse(&msg[..(x % 64) as usize]);
        }
    }

    #[test]
    fn namespaces_and_paths() {
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
        assert_eq!(Status::from_code(8), Status::NoBuffer);
        assert_eq!(Status::from_code(200), Status::BadRequest);
    }
}
