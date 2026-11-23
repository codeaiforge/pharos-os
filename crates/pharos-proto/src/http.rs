//! The gateway's HTTP/1.1 (gateway.md, D-035): checking an agent's path
//! against a route's pattern, writing the request head, parsing a server's
//! answer, and stripping a secret from what reaches the client.
//!
//! Everything here reads untrusted bytes, the answer most of all: it is
//! own, small, and strict (no obsolete folding, no bare `\n`, no transfer
//! coding but `chunked`, no compressed bodies), checks every length, and
//! never panics (fuzzed below and in #283).

use crate::Writer;

/// Longest path an agent may give, and longest query.
pub const MAX_PATH: usize = 256;
pub const MAX_QUERY: usize = 256;
/// Longest route pattern.
pub const MAX_PATTERN: usize = 128;
/// Largest answer head (status line and headers), and most header lines.
pub const MAX_HEAD: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 64;
/// Longest `Content-Type` passed on.
pub const MAX_CONTENT_TYPE: usize = 64;
/// What a stripped secret becomes.
pub const STRIPPED: &[u8] = b"[secret]";

/// The methods a route may name.
pub const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
/// Headers only the gateway writes (lower case).
pub const RESERVED: [&str; 5] = [
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "transfer-encoding",
];

/// Why an answer was refused (the gateway's `ANSWER` reasons).
pub mod reason {
    pub const MALFORMED: u8 = 1;
    /// Over the route's `max_answer`.
    pub const TOO_LARGE: u8 = 2;
    /// A `Content-Encoding` other than `identity`.
    pub const ENCODED: u8 = 3;
    /// A 1xx status.
    pub const INFORMATIONAL: u8 = 4;
    /// The connection ended before the answer did.
    pub const CUT_SHORT: u8 = 5;
}

/// Whether a method takes a body (and so a `Content-Length`).
pub fn takes_body(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// An RFC 9110 token: a header's name.
pub fn valid_token(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

/// A fixed header's value: visible ASCII and inner spaces.
pub fn valid_value(value: &[u8]) -> bool {
    value.iter().all(|b| (0x20..=0x7e).contains(b))
        && value.first() != Some(&b' ')
        && value.last() != Some(&b' ')
}

/// Whether `name` is one only the gateway writes.
pub fn reserved(name: &str) -> bool {
    RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name))
}

/// Whether `pattern` is a route's path pattern: `/`, then segments of
/// unreserved characters or `*`, at most [`MAX_PATTERN`] bytes.
pub fn valid_pattern(pattern: &[u8]) -> bool {
    pattern.len() <= MAX_PATTERN
        && pattern.first() == Some(&b'/')
        && pattern[1..]
            .split(|b| *b == b'/')
            .all(|s| s == b"*" || (s.iter().all(|b| unreserved(*b)) && s != b"." && s != b".."))
}

/// Whether `target` (a path and, where `query` allows, `?` and a query)
/// is one `pattern` allows: the same number of segments, each literal one
/// equal, each `*` exactly one non-empty segment. No `%`, `#`, `.`, `..`,
/// or byte outside RFC 3986's unreserved characters reaches a match.
pub fn matches(pattern: &[u8], target: &[u8], query: bool) -> bool {
    let (path, q) = match target.iter().position(|b| *b == b'?') {
        Some(i) => (&target[..i], Some(&target[i + 1..])),
        None => (target, None),
    };
    let query_ok = match q {
        None => true,
        Some(q) => {
            query
                && (1..=MAX_QUERY).contains(&q.len())
                && q.iter().all(|b| unreserved(*b) || *b == b'=' || *b == b'&')
        }
    };
    if !query_ok || path.len() > MAX_PATH || path.first() != Some(&b'/') {
        return false;
    }
    if pattern.first() != Some(&b'/') {
        return false;
    }
    let mut want = pattern[1..].split(|b| *b == b'/');
    let mut got = path[1..].split(|b| *b == b'/');
    loop {
        match (want.next(), got.next()) {
            (None, None) => return true,
            (Some(w), Some(g)) => {
                let clean = g.iter().all(|b| unreserved(*b)) && g != b"." && g != b"..";
                let fits = if w == b"*" { !g.is_empty() } else { w == g };
                if !clean || !fits {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// A request's head, written by the gateway alone.
pub struct Head<'a> {
    pub method: &'a str,
    /// Checked by [`matches()`].
    pub target: &'a [u8],
    pub host: &'a [u8],
    pub headers: &'a [(&'a str, &'a str)],
    /// The secret's header name and `prefix ‖ value`.
    pub secret: Option<(&'a str, &'a [u8])>,
    pub body_len: usize,
}

/// Writes `head` into `out`; its length, or `None` if it does not fit.
pub fn write_head(head: &Head<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    let line = |w: &mut Writer<'_>, parts: &[&[u8]]| {
        parts.iter().try_for_each(|p| w.bytes(p))?;
        w.bytes(b"\r\n")
    };
    line(
        &mut w,
        &[head.method.as_bytes(), b" ", head.target, b" HTTP/1.1"],
    )?;
    line(&mut w, &[b"Host: ", head.host])?;
    for (name, value) in head.headers {
        line(&mut w, &[name.as_bytes(), b": ", value.as_bytes()])?;
    }
    if let Some((name, line_value)) = head.secret {
        line(&mut w, &[name.as_bytes(), b": ", line_value])?;
    }
    if takes_body(head.method) {
        let mut digits = [0u8; 20];
        let n = decimal(head.body_len, &mut digits);
        line(&mut w, &[b"Content-Length: ", &digits[20 - n..]])?;
    }
    line(&mut w, &[b"Accept-Encoding: identity"])?;
    line(&mut w, &[b"Connection: close"])?;
    w.bytes(b"\r\n")?;
    Some(w.len())
}

/// Writes `n`'s digits at the end of `out`; how many.
fn decimal(mut n: usize, out: &mut [u8; 20]) -> usize {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return out.len() - i;
        }
    }
}

/// A parsed answer: the status, the content type (borrowed from the raw
/// answer), and the decoded body's length in `out`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer<'a> {
    pub status: u16,
    pub content_type: &'a [u8],
    pub body_len: usize,
}

enum Length {
    Fixed(usize),
    Chunked,
    ToClose,
}

/// Parses `raw`, a whole answer as read until the connection ended
/// (`complete` if it ended with `close_notify`), decoding the body into
/// `out`, of which at most `max` bytes may be used. `Err` is a [`reason`].
pub fn parse_answer<'a>(
    raw: &'a [u8],
    complete: bool,
    max: usize,
    out: &mut [u8],
) -> Result<Answer<'a>, u8> {
    use reason::*;
    let cut = |within_head: bool| {
        if within_head && raw.len() >= MAX_HEAD {
            MALFORMED
        } else {
            CUT_SHORT
        }
    };
    let window = &raw[..raw.len().min(MAX_HEAD)];
    let end = window
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| cut(true))?;
    let head = &raw[..end + 2];
    let body = &raw[end + 4..];
    // Every line ends in `\r\n`: no bare `\r` or `\n` anywhere.
    let mut lines = head.split(|b| *b == b'\n');
    let status_line = (lines.next())
        .and_then(|l| l.strip_suffix(b"\r"))
        .ok_or(MALFORMED)?;
    let status = parse_status(status_line).ok_or(MALFORMED)?;
    if (100..200).contains(&status) {
        return Err(INFORMATIONAL);
    }
    let mut content_type: Option<&[u8]> = None;
    let mut length: Option<usize> = None;
    let mut chunked = false;
    let mut count = 0;
    while let Some(line) = lines.next() {
        if line.is_empty() {
            // The split's final empty piece, after the last `\n`.
            if lines.next().is_some() {
                return Err(MALFORMED);
            }
            break;
        }
        let line = line.strip_suffix(b"\r").ok_or(MALFORMED)?;
        count += 1;
        if count > MAX_HEADERS {
            return Err(MALFORMED);
        }
        let (name, value) = header(line).ok_or(MALFORMED)?;
        if name.eq_ignore_ascii_case(b"content-type") {
            if content_type.is_some() || value.len() > MAX_CONTENT_TYPE {
                return Err(MALFORMED);
            }
            content_type = Some(value);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() {
                return Err(MALFORMED);
            }
            length = Some(parse_decimal(value).ok_or(MALFORMED)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(MALFORMED);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"content-encoding")
            && !value.eq_ignore_ascii_case(b"identity")
        {
            return Err(ENCODED);
        }
    }
    let length = match (length, chunked) {
        (Some(_), true) => return Err(MALFORMED),
        _ if status == 204 || status == 304 => Length::Fixed(0),
        (Some(n), false) => Length::Fixed(n),
        (None, true) => Length::Chunked,
        (None, false) => Length::ToClose,
    };
    let room = max.min(out.len());
    let body_len = match length {
        Length::Fixed(n) => {
            if n > room {
                return Err(TOO_LARGE);
            }
            match body.len() {
                l if l < n => return Err(CUT_SHORT),
                l if l > n => return Err(MALFORMED),
                _ => {}
            }
            out[..n].copy_from_slice(body);
            n
        }
        Length::ToClose => {
            if body.len() > room {
                return Err(TOO_LARGE);
            }
            if !complete {
                return Err(CUT_SHORT);
            }
            out[..body.len()].copy_from_slice(body);
            body.len()
        }
        Length::Chunked => dechunk(body, &mut out[..room])?,
    };
    Ok(Answer {
        status,
        content_type: content_type.unwrap_or(b""),
        body_len,
    })
}

fn parse_status(line: &[u8]) -> Option<u16> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))?;
    let (code, reason) = (rest.get(..3)?, &rest[3..]);
    if !code.iter().all(u8::is_ascii_digit) || code[0] == b'0' {
        return None;
    }
    if !(reason.is_empty() || reason[0] == b' ') || !reason.iter().all(|b| text(*b)) {
        return None;
    }
    Some(code.iter().fold(0, |n, d| n * 10 + u16::from(d - b'0')))
}

/// A byte allowed in a reason or a header's value: visible, space, tab,
/// or obs-text.
fn text(b: u8) -> bool {
    b == b'\t' || b >= 0x20 && b != 0x7f
}

/// `name: value`, the value without surrounding whitespace.
fn header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|b| *b == b':')?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if !valid_token(name) || !value.iter().all(|b| text(*b)) {
        return None;
    }
    let ws = |b: &u8| *b == b' ' || *b == b'\t';
    let start = value.iter().position(|b| !ws(b)).unwrap_or(value.len());
    let end = value.iter().rposition(|b| !ws(b)).map_or(start, |i| i + 1);
    Some((name, &value[start..end]))
}

fn parse_decimal(digits: &[u8]) -> Option<usize> {
    if digits.is_empty() || digits.len() > 9 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(digits.iter().fold(0, |n, d| n * 10 + usize::from(d - b'0')))
}

/// Decodes a chunked body into `out`; its length. Extensions are skipped,
/// trailers checked as headers and dropped.
fn dechunk(mut body: &[u8], out: &mut [u8]) -> Result<usize, u8> {
    use reason::*;
    let mut n = 0;
    loop {
        let eol = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(CUT_SHORT)?;
        let line = &body[..eol];
        body = &body[eol + 2..];
        let size_end = line.iter().position(|b| *b == b';').unwrap_or(line.len());
        let (size, ext) = (&line[..size_end], &line[size_end..]);
        if size.is_empty()
            || size.len() > 8
            || !size.iter().all(u8::is_ascii_hexdigit)
            || !ext.iter().all(|b| text(*b))
        {
            return Err(MALFORMED);
        }
        let size = size.iter().fold(0usize, |v, d| {
            v * 16 + (*d as char).to_digit(16).unwrap_or(0) as usize
        });
        if size == 0 {
            break;
        }
        if size > out.len() - n {
            return Err(TOO_LARGE);
        }
        if body.len() < size + 2 {
            return Err(CUT_SHORT);
        }
        if &body[size..size + 2] != b"\r\n" {
            return Err(MALFORMED);
        }
        out[n..n + size].copy_from_slice(&body[..size]);
        n += size;
        body = &body[size + 2..];
    }
    // Trailers, then an empty line, then nothing.
    for _ in 0..=MAX_HEADERS {
        let eol = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(CUT_SHORT)?;
        let line = &body[..eol];
        body = &body[eol + 2..];
        if line.is_empty() {
            return if body.is_empty() {
                Ok(n)
            } else {
                Err(MALFORMED)
            };
        }
        if line.contains(&b'\n') || line.contains(&b'\r') || header(line).is_none() {
            return Err(MALFORMED);
        }
    }
    Err(MALFORMED)
}

/// Copies `input` into `out`, every `prefix ‖ value` and every `value`
/// replaced by [`STRIPPED`]; the length and how many were replaced, or
/// `None` if `out` is too small. An empty `value` strips nothing.
pub fn strip(input: &[u8], prefix: &[u8], value: &[u8], out: &mut [u8]) -> Option<(usize, u32)> {
    let mut w = Writer::new(out);
    let mut count = 0u32;
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        let whole = !prefix.is_empty()
            && rest.starts_with(prefix)
            && rest[prefix.len()..].starts_with(value);
        let n = match () {
            _ if value.is_empty() => 0,
            _ if whole => prefix.len() + value.len(),
            _ if rest.starts_with(value) => value.len(),
            _ => 0,
        };
        if n > 0 {
            w.bytes(STRIPPED)?;
            count = count.saturating_add(1);
            i += n;
        } else {
            w.bytes(&rest[..1])?;
            i += 1;
        }
    }
    Some((w.len(), count))
}

/// Whether `haystack` contains `value` (an empty one is never found).
pub fn contains(haystack: &[u8], value: &[u8]) -> bool {
    !value.is_empty() && haystack.windows(value.len()).any(|w| w == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn paths_match_their_pattern_segment_by_segment() {
        let p = b"/repos/*/issues";
        assert!(matches(p, b"/repos/pharos/issues", false));
        assert!(!matches(p, b"/repos/a/b/issues", false), "* is one segment");
        assert!(!matches(p, b"/repos//issues", false), "* is never empty");
        assert!(!matches(p, b"/repos/pharos/issues/", false), "a trailing /");
        assert!(
            !matches(p, b"/repos/pharos/issues/1", false),
            "no prefix match"
        );
        assert!(!matches(p, b"/repos/pharos", false));
        assert!(!matches(p, b"repos/pharos/issues", false), "no leading /");
        assert!(matches(b"/", b"/", false));
        assert!(
            matches(b"/a/", b"/a/", false),
            "a trailing / the pattern has"
        );
        assert!(!matches(b"/a", b"/a/", false));
        for bad in [
            &b"/repos/../issues"[..],
            b"/repos/./issues",
            b"/repos/%2e%2e/issues",
            b"/repos/a#b/issues",
            b"/repos/a b/issues",
            b"/repos/a\r\nX: y/issues",
            b"/repos/a\0/issues",
            b"/repos/\xc3\xa9/issues",
        ] {
            assert!(
                !matches(p, bad, true),
                "{:?}",
                std::string::String::from_utf8_lossy(bad)
            );
        }
        assert!(!matches(b"/*", b"/..", false));
        let long = [b"/".as_slice(), &[b'a'; MAX_PATH]].concat();
        assert!(!matches(b"/*", &long, false), "over 256 bytes");
        assert!(matches(b"/*", &long[..MAX_PATH], false));
    }

    #[test]
    fn a_query_only_where_the_route_allows_it() {
        assert!(matches(b"/search", b"/search?q=pharos&n=2", true));
        assert!(!matches(b"/search", b"/search?q=pharos", false));
        assert!(!matches(b"/search", b"/search?", true), "an empty query");
        assert!(!matches(b"/search", b"/search?q=a b", true));
        assert!(!matches(b"/search", b"/search?q=%41", true));
        assert!(!matches(b"/search", b"/search?q=a?b", true));
        let q = [b"/search?".as_slice(), &[b'a'; MAX_QUERY]].concat();
        assert!(matches(b"/search", &q, true));
        let q = [q.as_slice(), b"a"].concat();
        assert!(!matches(b"/search", &q, true));
    }

    #[test]
    fn patterns_tokens_and_values_are_checked() {
        assert!(valid_pattern(b"/repos/*/issues"));
        assert!(valid_pattern(b"/"));
        assert!(!valid_pattern(b"repos"));
        assert!(!valid_pattern(b"/a/../b"));
        assert!(!valid_pattern(b"/a/*b"));
        assert!(!valid_pattern(b"/a%20"));
        assert!(!valid_pattern(&[b'/'; MAX_PATTERN + 1]));
        assert!(valid_token(b"X-Api-Key") && !valid_token(b"X Key") && !valid_token(b""));
        assert!(!valid_token(b"X:Key"));
        assert!(valid_value(b"application/json") && !valid_value(b"a\r\nb"));
        assert!(!valid_value(b" lead"));
        assert!(reserved("Content-Length") && reserved("HOST") && !reserved("Accept"));
    }

    #[test]
    fn the_head_is_written_with_the_secret_and_the_gateways_headers() {
        let mut out = [0u8; 512];
        let head = Head {
            method: "POST",
            target: b"/repos/p/issues",
            host: b"api.example.test",
            headers: &[("Accept", "application/json")],
            secret: Some(("Authorization", b"Bearer tok")),
            body_len: 42,
        };
        let n = write_head(&head, &mut out).unwrap();
        assert_eq!(
            &out[..n],
            b"POST /repos/p/issues HTTP/1.1\r\nHost: api.example.test\r\n\
              Accept: application/json\r\nAuthorization: Bearer tok\r\n\
              Content-Length: 42\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
        let get = Head {
            method: "GET",
            secret: None,
            headers: &[],
            body_len: 0,
            ..head
        };
        let n = write_head(&get, &mut out).unwrap();
        assert!(!out[..n].windows(14).any(|w| w == b"Content-Length"));
        assert_eq!(write_head(&get, &mut [0u8; 20]), None);
    }

    fn parse(raw: &[u8], complete: bool, max: usize) -> Result<(u16, Vec<u8>, Vec<u8>), u8> {
        let mut out = vec![0u8; 1024];
        let a = parse_answer(raw, complete, max, &mut out)?;
        Ok((
            a.status,
            a.content_type.to_vec(),
            out[..a.body_len].to_vec(),
        ))
    }

    #[test]
    fn answers_with_each_length_parse() {
        let fixed =
            b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            parse(fixed, false, 100),
            Ok((201, b"text/plain".to_vec(), b"hello".to_vec()))
        );
        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n\
            3;ext=1\r\nhel\r\n2\r\nlo\r\n0\r\nX-Trailer: t\r\n\r\n";
        assert_eq!(
            parse(chunked, false, 100),
            Ok((200, vec![], b"hello".to_vec()))
        );
        let to_close = b"HTTP/1.0 404 \r\n\r\nnot here";
        assert_eq!(
            parse(to_close, true, 100),
            Ok((404, vec![], b"not here".to_vec()))
        );
        assert_eq!(parse(to_close, false, 100), Err(reason::CUT_SHORT));
        let no_content = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(parse(no_content, false, 100), Ok((204, vec![], vec![])));
        assert_eq!(
            parse(b"HTTP/1.1 200\r\n\r\n", true, 9),
            Ok((200, vec![], vec![]))
        );
    }

    #[test]
    fn each_malformed_answer_is_refused_with_its_reason() {
        use reason::*;
        let cases: [(&[u8], u8); 22] = [
            (b"HTTP/1.1 100 Continue\r\n\r\n", INFORMATIONAL),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                MALFORMED,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                MALFORMED,
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\n\r\n", MALFORMED),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                MALFORMED,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
                ENCODED,
            ),
            (b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 200 OK\nX: a\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 200 OK\r\nX a\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 200 OK\r\nX\0: a\r\n\r\n", MALFORMED),
            (b"HTTP/2 200 OK\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 20 OK\r\n\r\n", MALFORMED),
            (b"HTTP/1.1 2000 OK\r\n\r\n", MALFORMED),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel",
                CUT_SHORT,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhel",
                MALFORMED,
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n", TOO_LARGE),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel",
                CUT_SHORT,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhelXX0\r\n\r\n",
                MALFORMED,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n\r\n",
                MALFORMED,
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Le", CUT_SHORT),
        ];
        for (raw, why) in cases {
            assert_eq!(
                parse(raw, true, 100).map(|_| ()),
                Err(why),
                "{:?}",
                std::string::String::from_utf8_lossy(raw)
            );
        }
        let ct = [
            b"HTTP/1.1 200 OK\r\nContent-Type: ".as_slice(),
            &[b'a'; 65],
            b"\r\n\r\n",
        ]
        .concat();
        assert_eq!(parse(&ct, true, 100).map(|_| ()), Err(MALFORMED));
        let big_chunks =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n0\r\n\r\n";
        assert_eq!(parse(big_chunks, true, 5).map(|_| ()), Err(TOO_LARGE));
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\n\r\nhello!", true, 5).map(|_| ()),
            Err(TOO_LARGE)
        );
        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..=MAX_HEADERS {
            many.extend_from_slice(b"X: y\r\n");
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(
            parse(&many, true, 100).map(|_| ()),
            Err(MALFORMED),
            "65 headers"
        );
        let mut huge = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        huge.resize(MAX_HEAD + 10, b'a');
        assert_eq!(
            parse(&huge, false, 100).map(|_| ()),
            Err(MALFORMED),
            "a head over 8 KiB"
        );
    }

    #[test]
    fn stripping_finds_the_value_anywhere() {
        let strip_all = |input: &[u8]| {
            let mut out = [0u8; 256];
            let (n, c) = strip(input, b"Bearer ", b"tok3n", &mut out).unwrap();
            (out[..n].to_vec(), c)
        };
        assert_eq!(
            strip_all(b"tok3n at start"),
            (b"[secret] at start".to_vec(), 1)
        );
        assert_eq!(strip_all(b"at end tok3n"), (b"at end [secret]".to_vec(), 1));
        assert_eq!(
            strip_all(b"Bearer tok3n"),
            (b"[secret]".to_vec(), 1),
            "with its prefix"
        );
        assert_eq!(strip_all(b"tok3ntok3n"), (b"[secret][secret]".to_vec(), 2));
        assert_eq!(strip_all(b"tok3 n tok"), (b"tok3 n tok".to_vec(), 0));
        assert_eq!(strip_all(b"Bearer x"), (b"Bearer x".to_vec(), 0));
        // Across chunk boundaries: stripping runs on the decoded body.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ntok\r\n2\r\n3n\r\n0\r\n\r\n";
        let mut body = [0u8; 64];
        let a = parse_answer(raw, true, 64, &mut body).unwrap();
        assert_eq!(strip_all(&body[..a.body_len]), (b"[secret]".to_vec(), 1));
        // Growing past the output is refused, never cut.
        assert_eq!(strip(b"aaaa", b"", b"a", &mut [0u8; 31]), None);
        assert_eq!(strip(b"abc", b"", b"", &mut [0u8; 3]), Some((3, 0)));
        assert!(contains(b"text/tok3n", b"tok3n") && !contains(b"text", b""));
    }

    #[test]
    fn fuzzed_answers_never_panic_and_never_return_the_secret() {
        // Bytes 0-15 stand for the characters that matter to an answer.
        const MAP: &[u8; 16] = b"\r\n :0a9;HTTP/1.1";
        const SECRET: &[u8] = b"a9Z";
        let mut parsed = 0;
        crate::fuzz(50_000, 17, |m| {
            let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
            raw.extend(m.iter().map(|b| match b {
                16 => b'Z',
                b => MAP[usize::from(*b)],
            }));
            let mut out = [0u8; 400];
            if let Ok(a) = parse_answer(&raw, m.len() % 2 == 0, 300, &mut out) {
                parsed += 1;
                let mut clean = [0u8; 4096];
                let (n, _) = strip(&out[..a.body_len], b"", SECRET, &mut clean).unwrap();
                assert!(!contains(&clean[..n], SECRET));
            }
            let _ = matches(b"/a/*", m, true);
        });
        assert!(parsed > 0, "no fuzzed answer parsed");
    }
}
