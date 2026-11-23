//! The vault interface, version 1, and the host's secrets file
//! (gateway.md, D-035).
//!
//! **The secrets file** reaches the vault from the host through `fw_cfg`
//! and the kernel, which never parses it. It is text, one secret a line:
//! `<name> <value>\n`. A name is 1 to [`MAX_NAME`] bytes of `a`–`z`,
//! `0`–`9`, `-`, `_`; a value is 1 to [`MAX_VALUE`] bytes of visible ASCII
//! (0x21–0x7E), so it can never break a header line. At most
//! [`MAX_SECRETS`] secrets and [`MAX_FILE`] bytes; a name given twice, or
//! any other fault, refuses the whole file, by line number and never by
//! content.
//!
//! **The interface:** the vault's only client is the gateway (badge 1).
//! `RELEASE` names a route; the vault writes that route's header prefix
//! and secret into the gateway's attached buffer and answers
//! `[status, 0, length (u16)]`. There is no request that lists secrets or
//! returns one by name.
//!
//! Requests: `[1, ATTACH, size (u64)]` (a `send` with the buffer),
//! `[1, RELEASE, route]`, `[1, INFO]`.

use crate::{Reader, Refused, Writer, op as common, status};

pub const NAME: &[u8] = b"vault";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    /// A route's header prefix and secret, into the attached buffer.
    pub const RELEASE: u8 = 1;
}

pub const OK: u8 = status::OK;
pub const BAD_REQUEST: u8 = status::BAD_REQUEST;
pub const NO_ACCESS: u8 = status::NO_ACCESS;
pub const NO_BUFFER: u8 = status::NO_BUFFER;
/// No such route.
pub const NOT_FOUND: u8 = status::NOT_FOUND;
/// The route names no secret, or one the file does not hold
/// (gateway.md's 40, shared with the gateway).
pub const NO_SECRET: u8 = status::OWN + 8;
/// The release could not be recorded, so nothing was released
/// (gateway.md's 43).
pub const NO_AUDIT: u8 = status::OWN + 11;

/// Most secrets in the file.
pub const MAX_SECRETS: usize = 16;
/// Largest file (the kernel's limit too).
pub const MAX_FILE: usize = 4096;
/// Longest secret name.
pub const MAX_NAME: usize = 32;
/// Longest secret value.
pub const MAX_VALUE: usize = 1024;
/// Largest buffer the gateway may attach: a prefix and a value.
pub const MAX_BUFFER: u64 = 4096;

/// Whether `name` is a secret's name: 1 to 32 bytes of `a`–`z`, `0`–`9`,
/// `-`, `_`.
pub fn valid_name(name: &[u8]) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_')
}

/// Whether `value` may be a secret: 1 to 1,024 bytes of visible ASCII.
pub fn valid_value(value: &[u8]) -> bool {
    (1..=MAX_VALUE).contains(&value.len()) && value.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// A parsed secrets file, borrowing it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Secrets<'a> {
    entries: [(&'a [u8], &'a [u8]); MAX_SECRETS],
    len: usize,
}

impl<'a> Secrets<'a> {
    /// The value of the secret `name`.
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.names_values()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    /// How many secrets.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn names_values(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + '_ {
        self.entries[..self.len].iter().copied()
    }
}

/// Parses the secrets file. `Err(line)`, counting from 1, names the line
/// at fault; `Err(0)` is a file over [`MAX_FILE`].
pub fn parse_secrets(file: &[u8]) -> Result<Secrets<'_>, usize> {
    if file.len() > MAX_FILE {
        return Err(0);
    }
    let mut s = Secrets::default();
    let mut rest = file;
    let mut line = 0;
    while !rest.is_empty() {
        line += 1;
        // Every line ends in `\n`, the last one included.
        let end = rest.iter().position(|b| *b == b'\n').ok_or(line)?;
        let (text, after) = (&rest[..end], &rest[end + 1..]);
        rest = after;
        let space = text.iter().position(|b| *b == b' ').ok_or(line)?;
        let (name, value) = (&text[..space], &text[space + 1..]);
        if !valid_name(name) || !valid_value(value) || s.get(name).is_some() {
            return Err(line);
        }
        let slot = s.entries.get_mut(s.len).ok_or(line)?;
        *slot = (name, value);
        s.len += 1;
    }
    Ok(s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// A `send`, not a `call`: its capability is the buffer.
    Attach {
        len: u64,
    },
    Release {
        route: u8,
    },
    Info,
}

/// Parses a request; anything malformed is `Bad`.
pub fn parse(msg: &[u8]) -> Result<Request, Refused> {
    let (code, body) = crate::split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = match code {
        common::ATTACH => r.u64().map(|len| Request::Attach { len }),
        op::RELEASE => r.u8().map(|route| Request::Release { route }),
        common::INFO => Some(Request::Info),
        _ => None,
    };
    match req {
        Some(req) if r.is_empty() => Ok(req),
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    match *req {
        Request::Attach { len } => {
            w.bytes(&[VERSION, common::ATTACH])?;
            w.u64(len)?;
        }
        Request::Release { route } => w.bytes(&[VERSION, op::RELEASE, route])?,
        Request::Info => w.bytes(&[VERSION, common::INFO])?,
    }
    Some(w.len())
}

/// A `RELEASE` reply: the status and the bytes written to the buffer.
pub fn encode_released(status: u8, len: u16) -> [u8; 4] {
    let [a, b] = len.to_le_bytes();
    [status, 0, a, b]
}

/// `(status, length)` from a `RELEASE` reply; a bare status (a refusal)
/// has length 0.
pub fn parse_released(reply: &[u8]) -> Option<(u8, u16)> {
    match reply {
        [s] => Some((*s, 0)),
        [s, 0, a, b] => Some((*s, u16::from_le_bytes([*a, *b]))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;

    #[test]
    fn a_file_parses_and_each_secret_is_found_by_name() {
        let s = parse_secrets(b"github-token ghp_abc123\nkey_2 A!~z\n").unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.get(b"github-token"), Some(&b"ghp_abc123"[..]));
        assert_eq!(s.get(b"key_2"), Some(&b"A!~z"[..]));
        assert_eq!(s.get(b"other"), None);
        assert!(parse_secrets(b"").unwrap().is_empty());
    }

    #[test]
    fn each_fault_is_refused_by_its_line() {
        let cases: [(&[u8], usize); 12] = [
            (b"a b", 1),                // no final `\n`
            (b"ab\n", 1),               // no space
            (b" v\n", 1),               // empty name
            (b"a \n", 1),               // empty value
            (b"A v\n", 1),              // upper case in a name
            (b"a.b v\n", 1),            // `.` in a name
            (b"a v w\n", 1),            // a space in a value
            (b"a v\tw\n", 1),           // a tab
            (b"ok v\na v\x7f\n", 2),    // DEL
            (b"ok v\na \xc3\xa9\n", 2), // not ASCII
            (b"a v\r\n", 1),            // `\r`
            (b"a v\nb w\na x\n", 3),    // a name given twice
        ];
        for (file, line) in cases {
            assert_eq!(
                parse_secrets(file),
                Err(line),
                "{:?}",
                String::from_utf8_lossy(file)
            );
        }
    }

    #[test]
    fn limits_hold_names_values_count_and_size() {
        let name = "n".repeat(MAX_NAME);
        let value = "v".repeat(MAX_VALUE);
        assert!(parse_secrets(format!("{name} {value}\n").as_bytes()).is_ok());
        assert_eq!(parse_secrets(format!("{name}n v\n").as_bytes()), Err(1));
        assert_eq!(parse_secrets(format!("a {value}v\n").as_bytes()), Err(1));
        let sixteen: String = (0..16).map(|i| format!("s{i} v\n")).collect();
        assert_eq!(parse_secrets(sixteen.as_bytes()).unwrap().len(), 16);
        assert_eq!(
            parse_secrets(format!("{sixteen}s16 v\n").as_bytes()),
            Err(17)
        );
        let big = std::vec![b'a'; MAX_FILE + 1];
        assert_eq!(parse_secrets(&big), Err(0));
    }

    #[test]
    fn requests_round_trip_and_malformed_ones_are_refused() {
        for req in [
            Request::Attach { len: 4096 },
            Request::Release { route: 3 },
            Request::Info,
        ] {
            let mut out = [0u8; 16];
            let n = encode(&req, &mut out).unwrap();
            assert_eq!(parse(&out[..n]), Ok(req));
            for cut in 0..n {
                assert!(parse(&out[..cut]).is_err(), "{req:?} cut at {cut}");
            }
        }
        assert_eq!(parse(&[1, op::RELEASE, 0, 0]), Err(Refused::Bad));
        assert_eq!(parse(&[1, 9]), Err(Refused::Bad));
        assert_eq!(parse(&[2, op::RELEASE, 0]), Err(Refused::Version));
        assert_eq!(parse_released(&encode_released(OK, 300)), Some((OK, 300)));
        assert_eq!(parse_released(&[NO_SECRET]), Some((NO_SECRET, 0)));
        assert_eq!(parse_released(&[OK, 1, 0, 0]), None);
    }

    #[test]
    fn fuzzed_files_and_requests_never_panic() {
        // Bytes 0-7 stand for the characters that matter to the file.
        const MAP: &[u8; 8] = b"a b\n-!\x7fA";
        let mut parsed = 0;
        crate::fuzz(20_000, 8, |msg| {
            let _ = parse(msg);
            let text: std::vec::Vec<u8> = msg.iter().map(|b| MAP[usize::from(*b)]).collect();
            if let Ok(s) = parse_secrets(&text) {
                parsed += 1;
                for (name, value) in s.names_values() {
                    assert!(valid_name(name) && valid_value(value));
                }
            }
        });
        assert!(parsed > 0, "no fuzzed file parsed");
        // #283: a valid file with 1 to 4 bytes changed; what parses holds
        // only valid, distinct secrets, each found by name.
        const GOOD: &[u8] = b"github-token ghp_abc123\nkey_2 A!~z\nthird v\n";
        let mut x = 0x6a09_e667_f3bc_c908u64;
        let mut changed = 0;
        for _ in 0..50_000 {
            let mut text = GOOD.to_vec();
            for _ in 0..1 + x % 4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize >> 8) % text.len();
                text[i] = b"a \nA-_.~\x7f"[(x % 9) as usize];
            }
            if let Ok(s) = parse_secrets(&text) {
                changed += usize::from(text != GOOD);
                let all: std::vec::Vec<_> = s.names_values().collect();
                for (i, (name, value)) in all.iter().enumerate() {
                    assert!(valid_name(name) && valid_value(value));
                    assert!(all[..i].iter().all(|(n, _)| n != name), "a name twice");
                    assert_eq!(s.get(name), Some(*value));
                }
            }
        }
        assert!(changed > 0, "no mutated file parsed");
    }
}
