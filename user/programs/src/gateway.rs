//! The egress gateway's decisions (gateway.md, D-035, #282), apart from
//! its I/O so the host tests reach each one: which requests a route
//! allows, the request it writes, the answer it hands back with the
//! secret stripped, and the audit details, which never carry a secret, a
//! body, or an answer.

use alloc::vec;
use alloc::vec::Vec;

use pharos_proto::gateway::{Answered, BAD_REQUEST, NO_ACCESS, NOT_FOUND, OK, TOO_LARGE};
use pharos_proto::http::{self, Head};
use pharos_services::Route;

/// Most bytes of a request head the gateway writes: the request line with
/// a 256-byte path and query, `Host`, 4 fixed headers, and the secret's.
pub const MAX_HEAD: usize = 4096;

/// Checks a client's request on `route` (`None`: no such route) before
/// anything is recorded or released. In order: `NOT_FOUND`, `NO_ACCESS`
/// (not listed for this client), `BAD_REQUEST` (a path the pattern
/// refuses), `TOO_LARGE` (a body over `max_body`).
pub fn check<'r>(
    route: Option<&'r Route>,
    client: u8,
    target: &[u8],
    body_len: usize,
) -> Result<&'r Route, u8> {
    let r = route.ok_or(NOT_FOUND)?;
    if !r.clients.contains(&client) {
        return Err(NO_ACCESS);
    }
    if !http::matches(r.path.as_bytes(), target, r.query) {
        return Err(BAD_REQUEST);
    }
    if body_len > r.max_body as usize {
        return Err(TOO_LARGE);
    }
    Ok(r)
}

/// The whole request: the head, with `secret` (`prefix ‖ value`) in the
/// route's header, then the body.
pub fn request(
    route: &Route,
    host: &[u8],
    target: &[u8],
    secret: &[u8],
    body: &[u8],
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; MAX_HEAD + body.len()];
    let head = Head {
        method: route.method,
        target,
        host,
        headers: route.headers,
        secret: route.secret.map(|_| (route.header.0, secret)),
        body_len: body.len(),
    };
    let n = http::write_head(&head, &mut out[..MAX_HEAD])?;
    out[n..n + body.len()].copy_from_slice(body);
    out.truncate(n + body.len());
    Some(out)
}

/// Overwrites `bytes` with zeros, best effort: user programs have no
/// volatile write, so `black_box` keeps the writes from being dropped.
pub fn erase(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

/// [`erase`] over the whole allocation, spare capacity too: what a
/// `truncate` left there is gone as well (#286).
pub fn erase_vec(v: &mut Vec<u8>) {
    v.resize(v.capacity(), 0);
    erase(v);
}

/// Bytes that may hold a server's echo of the secret (the raw answer,
/// #286): erased, capacity and all, when dropped, on every path.
pub struct Wiped(pub Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        erase_vec(&mut self.0);
    }
}

/// A parsed answer, before stripping: no secret is in the gateway's
/// memory while it is made. A server's echo of it may be, so both parts
/// are erased when dropped (#286).
pub struct Parsed {
    pub http: u16,
    pub content_type: Vec<u8>,
    pub body: Vec<u8>,
}

impl Drop for Parsed {
    fn drop(&mut self) {
        erase_vec(&mut self.content_type);
        erase_vec(&mut self.body);
    }
}

/// Parses the raw answer (`complete` if the server sent `close_notify`)
/// within the route's `max_answer`; `Err` is an
/// [`http::reason`](pharos_proto::http::reason).
pub fn parse(raw: &[u8], complete: bool, route: &Route) -> Result<Parsed, u8> {
    let max = route.max_answer as usize;
    let mut body = vec![0u8; max];
    let a = http::parse_answer(raw, complete, max, &mut body)?;
    body.truncate(a.body_len);
    Ok(Parsed {
        http: a.status,
        content_type: a.content_type.to_vec(),
        body,
    })
}

/// What the client gets: the content type then the body, every
/// `prefix ‖ value` and `value` replaced by `[secret]`, at most `room`
/// bytes; a content type holding the value is dropped (and counted).
/// `None` if it does not fit, which the gateway answers as too large.
pub fn strip(p: &Parsed, prefix: &[u8], value: &[u8], room: usize) -> Option<(Vec<u8>, Answered)> {
    let tainted = http::contains(&p.content_type, value);
    let ctype: &[u8] = if tainted { b"" } else { &p.content_type };
    let mut out = vec![0u8; room];
    if ctype.len() > room {
        return None;
    }
    out[..ctype.len()].copy_from_slice(ctype);
    let (n, count) = http::strip(&p.body, prefix, value, &mut out[ctype.len()..])?;
    out.truncate(ctype.len() + n);
    let stripped = count.saturating_add(u32::from(tainted));
    Some((
        out,
        Answered {
            status: OK,
            detail: 0,
            http: p.http,
            type_len: ctype.len() as u8,
            answer_len: n as u32,
            stripped: u8::try_from(stripped).unwrap_or(u8::MAX),
        },
    ))
}

fn number(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

fn cut(mut d: Vec<u8>) -> Vec<u8> {
    d.truncate(pharos_proto::audit::MAX_DETAIL);
    d
}

/// The vault's record of a release (gateway.md, Audit): `release <route
/// or its index>[ secret <name>][ status <n>]`, cut to the audit limit, as
/// two 32-byte names and a status would pass it and be refused, leaving
/// every release of that route `NO_AUDIT` (M6.2 review). The end is
/// what is cut, a refusal's status first; its outcome still says refused.
pub fn release_detail(
    route: Result<&[u8], u8>,
    secret: Option<&[u8]>,
    status: Option<u8>,
) -> Vec<u8> {
    let mut d = Vec::with_capacity(80);
    d.extend_from_slice(b"release ");
    match route {
        Ok(name) => d.extend_from_slice(name),
        Err(index) => number(&mut d, index.into()),
    }
    if let Some(name) = secret {
        d.extend_from_slice(b" secret ");
        d.extend_from_slice(name);
    }
    if let Some(s) = status {
        d.extend_from_slice(b" status ");
        number(&mut d, s.into());
    }
    cut(d)
}

/// The intent's detail: `c<client> <method> <body length> <hash> <route><path>`,
/// where the hash is the first 8 bytes of SHA-256 over the whole target
/// (path and query), a zero byte, and the body, in hex. Everything before
/// the route fits in the audit limit with any route name (#290, M6.2
/// review R-8), so the stored intent always identifies the target and the
/// body; only the path, last, is cut. A route name has no `/`, and a path
/// starts with one.
pub fn intent_detail(client: u8, route: &Route, target: &[u8], body: &[u8]) -> Vec<u8> {
    let path = target.split(|b| *b == b'?').next().unwrap_or(target);
    let mut d = Vec::with_capacity(128);
    d.push(b'c');
    number(&mut d, client.into());
    d.push(b' ');
    d.extend_from_slice(route.method.as_bytes());
    d.push(b' ');
    number(&mut d, body.len() as u64);
    d.push(b' ');
    let hash = pharos_crypto::sha256(&[target, &[0], body]);
    for b in &hash[..8] {
        d.extend_from_slice(&[hex(b >> 4), hex(b & 15)]);
    }
    d.push(b' ');
    d.extend_from_slice(route.name.as_bytes());
    d.extend_from_slice(path);
    cut(d)
}

fn hex(n: u8) -> u8 {
    b"0123456789abcdef"[usize::from(n)]
}

/// A refusal's detail, before anything was sent: the client, the route's
/// name as asked (a valid route name, whether or not the table has it),
/// and the status.
pub fn refusal_detail(client: u8, route: &[u8], status: u8) -> Vec<u8> {
    let mut d = Vec::with_capacity(64);
    d.push(b'c');
    number(&mut d, client.into());
    d.push(b' ');
    d.extend_from_slice(route);
    d.extend_from_slice(b" status ");
    number(&mut d, status.into());
    cut(d)
}

/// The outcome's detail: `status <s> [detail <d>] http <h> answer <n>
/// stripped <k>`.
pub fn outcome_detail(a: &Answered) -> Vec<u8> {
    let mut d = Vec::with_capacity(64);
    d.extend_from_slice(b"status ");
    number(&mut d, a.status.into());
    if a.detail != 0 {
        d.extend_from_slice(b" detail ");
        number(&mut d, a.detail.into());
    }
    d.extend_from_slice(b" http ");
    number(&mut d, a.http.into());
    d.extend_from_slice(b" answer ");
    number(&mut d, a.answer_len.into());
    d.extend_from_slice(b" stripped ");
    number(&mut d, a.stripped.into());
    cut(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_vec_clears_what_truncate_left() {
        // As `parse` leaves a body: written to its limit, then cut (#286).
        let mut v = vec![0xaa_u8; 64];
        v.truncate(10);
        let cap = v.capacity();
        erase_vec(&mut v);
        assert_eq!(v.len(), cap, "the spare capacity is erased too");
        assert!(v.iter().all(|&b| b == 0));
    }

    #[test]
    fn a_release_record_always_fits() {
        assert_eq!(
            release_detail(Ok(b"items"), Some(b"test-token"), None),
            b"release items secret test-token"
        );
        assert_eq!(release_detail(Err(9), None, Some(7)), b"release 9 status 7");
        let long = [b'a'; 32];
        let d = release_detail(Ok(&long), Some(&long), Some(40));
        assert!(d.len() <= pharos_proto::audit::MAX_DETAIL && d.starts_with(b"release aaaa"));
    }

    const ROUTE: Route = Route {
        name: "issues",
        dest: 0,
        method: "POST",
        path: "/repos/*/issues",
        query: false,
        secret: Some("github-token"),
        header: ("Authorization", "Bearer "),
        headers: &[("Accept", "application/json")],
        max_body: 100,
        max_answer: 200,
        clients: &[1],
    };

    #[test]
    fn each_refusal_comes_in_order() {
        assert_eq!(check(None, 1, b"/repos/a/issues", 0).err(), Some(NOT_FOUND));
        assert_eq!(
            check(Some(&ROUTE), 2, b"/repos/a/issues", 0).err(),
            Some(NO_ACCESS)
        );
        assert_eq!(
            check(Some(&ROUTE), 1, b"/repos/a/b/issues", 0).err(),
            Some(BAD_REQUEST)
        );
        assert_eq!(
            check(Some(&ROUTE), 1, b"/repos/a/issues?x=1", 0).err(),
            Some(BAD_REQUEST)
        );
        assert_eq!(
            check(Some(&ROUTE), 1, b"/repos/a/issues", 101).err(),
            Some(TOO_LARGE)
        );
        assert!(check(Some(&ROUTE), 1, b"/repos/a/issues", 100).is_ok());
    }

    #[test]
    fn the_request_carries_the_secret_and_the_body() {
        let r = request(
            &ROUTE,
            b"api.test",
            b"/repos/a/issues",
            b"Bearer tok",
            b"{}",
        )
        .unwrap();
        let text = core::str::from_utf8(&r).unwrap();
        assert!(text.starts_with("POST /repos/a/issues HTTP/1.1\r\nHost: api.test\r\n"));
        assert!(text.contains("\r\nAuthorization: Bearer tok\r\n"));
        assert!(text.contains("\r\nContent-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
        let open = Route {
            secret: None,
            header: ("", ""),
            ..ROUTE
        };
        let r = request(&open, b"api.test", b"/repos/a/issues", b"", b"").unwrap();
        assert!(!r.windows(13).any(|w| w == b"Authorization"));
        let mut secret = *b"Bearer tok";
        erase(&mut secret);
        assert_eq!(secret, [0; 10]);
    }

    #[test]
    fn the_answer_is_stripped_and_its_type_dropped_if_tainted() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 27\r\n\r\nyou sent: Bearer tok3n, ok.";
        let p = parse(raw, false, &ROUTE).unwrap();
        let (out, a) = strip(&p, b"Bearer ", b"tok3n", 4096).unwrap();
        assert_eq!(&out[..10], b"text/plain");
        assert_eq!(&out[10..], b"you sent: [secret], ok.");
        assert_eq!(
            (a.http, a.type_len, a.answer_len, a.stripped),
            (200, 10, 23, 1)
        );
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: x/tok3n\r\nContent-Length: 2\r\n\r\nok";
        let p = parse(raw, false, &ROUTE).unwrap();
        let (out, a) = strip(&p, b"Bearer ", b"tok3n", 4096).unwrap();
        assert_eq!((out.as_slice(), a.type_len, a.stripped), (&b"ok"[..], 0, 1));
        assert!(strip(&p, b"", b"tok3n", 1).is_none(), "no room");
        let big = b"HTTP/1.1 200 OK\r\nContent-Length: 201\r\n\r\n";
        assert_eq!(
            parse(big, true, &ROUTE).err(),
            Some(http::reason::TOO_LARGE)
        );
    }

    #[test]
    fn details_name_no_secret_and_fit_the_trail() {
        let d = intent_detail(1, &ROUTE, b"/repos/pharos/issues", b"{\"title\":\"x\"}");
        let text = core::str::from_utf8(&d).unwrap();
        assert!(text.starts_with("c1 POST 13 "), "{text}");
        assert!(text.ends_with(" issues/repos/pharos/issues"), "{text}");
        // The longest route name, method, and body length (#290): the hash
        // is whole, and only the path is cut.
        let name: &'static str = std::string::String::leak("n".repeat(32));
        let worst = Route {
            name,
            method: "PATCH",
            ..ROUTE
        };
        let long = [b"/repos/".as_slice(), &[b'a'; 200], b"/issues?q=1"].concat();
        let body = std::vec![b'x'; 60 * 1024];
        let d = intent_detail(2, &worst, &long, &body);
        assert_eq!(d.len(), pharos_proto::audit::MAX_DETAIL);
        let hash = pharos_crypto::sha256(&[&long, &[0], &body]);
        let hex: std::string::String = hash[..8].iter().map(|b| std::format!("{b:02x}")).collect();
        let want = std::format!("c2 PATCH 61440 {hex} {name}");
        assert_eq!(core::str::from_utf8(&d).unwrap(), want, "fits exactly");
        // Targets differing only past the cut, or in the query, differ.
        let other = [&long[..long.len() - 1], b"2"].concat();
        assert_ne!(intent_detail(2, &worst, &other, &body), d);
        assert_eq!(
            refusal_detail(2, b"issues", NO_ACCESS),
            b"c2 issues status 3"
        );
        assert_eq!(refusal_detail(1, b"other", NOT_FOUND), b"c1 other status 7");
        let a = Answered {
            status: OK,
            http: 201,
            answer_len: 40,
            stripped: 2,
            ..Answered::default()
        };
        assert_eq!(
            outcome_detail(&a),
            b"status 0 http 201 answer 40 stripped 2"
        );
    }

    #[test]
    fn fuzzed_routes_agree_with_the_gateways_http() {
        // #283: `pharos_services` checks routes with its own copy of the
        // HTTP rules (it has no dependencies); fuzzed patterns and headers
        // must be accepted there exactly when `pharos_proto::http` would,
        // and a route it accepts always gives a request head.
        use pharos_services::check_routes;
        const ALPHABET: &[u8] = b"/a*.%-~ :\r\nHostAccept";
        let mut x = 0x510e_527f_ade6_82d1u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0;
        for _ in 0..50_000 {
            let pick = next();
            let mut word = |n: u64| -> &'static str {
                let len = (next() % n) as usize;
                let bytes: Vec<u8> = (0..len)
                    .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
                    .collect();
                alloc::boxed::Box::leak(
                    alloc::string::String::from_utf8(bytes)
                        .unwrap()
                        .into_boxed_str(),
                )
            };
            let path: &'static str =
                alloc::boxed::Box::leak([&"/"[..], word(12)].concat().into_boxed_str());
            // Whole names half the time, so reserved ones come often.
            const NAMES: [&str; 9] = [
                "Host",
                "content-length",
                "Connection",
                "Accept-Encoding",
                "transfer-encoding",
                "authorization",
                "Accept",
                "X-Key",
                "",
            ];
            let name = if pick % 2 == 0 {
                NAMES[(pick / 2 % 9) as usize]
            } else {
                word(10)
            };
            let value = word(10);
            let fixed: &'static [(&str, &str)] =
                alloc::boxed::Box::leak(alloc::boxed::Box::new([(name, value)]));
            let route = Route {
                path,
                headers: fixed,
                ..ROUTE
            };
            let ok = check_routes(&[route], None).is_ok();
            let expected = http::valid_pattern(path.as_bytes())
                && http::valid_token(name.as_bytes())
                && !http::reserved(name)
                && !name.eq_ignore_ascii_case(ROUTE.header.0)
                && http::valid_value(value.as_bytes());
            assert_eq!(ok, expected, "{path:?} {name:?}: {value:?}");
            if ok {
                accepted += 1;
                let target: Vec<u8> = path
                    .bytes()
                    .map(|b| if b == b'*' { b'x' } else { b })
                    .collect();
                if http::matches(path.as_bytes(), &target, false) {
                    assert!(request(&route, b"api.test", &target, b"Bearer v", b"").is_some());
                }
            }
        }
        assert!(accepted > 100, "only {accepted} fuzzed routes accepted");
    }
}
