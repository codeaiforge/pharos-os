//! Person records, version 1 (identity.md, D-038, #310): one text file per
//! person, `people/<name>` in the store's `identity` namespace, written
//! only by `trust` and, before the first boot, by the host's `cargo xtask
//! identity first`. At most [`MAX_FILE`] bytes, one `key = value` per
//! line, every key exactly once:
//!
//! ```text
//! person = 1
//! name = alice
//! roles = approver,ops
//! salt = <64 hex digits>
//! iterations = 600000
//! hash = <64 hex digits>
//! ```
//!
//! `hash` is PBKDF2-HMAC-SHA256 of the passphrase with `salt` and
//! `iterations` (`pharos_crypto::pbkdf2`). Roles are data only: nothing
//! reads one to grant anything (D-018 item 2). A record is input from the
//! store: [`parse`] refuses unknown, repeated, and missing keys and values
//! out of range, and never panics.

use crate::trust::{MAX_NAME, valid_name};

/// The person files' directory in the `identity` namespace.
pub const PEOPLE: &[u8] = b"people/";
/// Largest record.
pub const MAX_FILE: usize = 1024;
/// Most roles one person has.
pub const MAX_ROLES: usize = 8;
/// Most people (one store `list` page of names, checked at `person add`).
pub const MAX_PEOPLE: usize = 64;
/// The iterations `person add` and `person passphrase` use (identity.md,
/// OWASP's 2023 figure for PBKDF2-HMAC-SHA256).
pub const ITERATIONS: u32 = 600_000;
/// A passphrase is one console line: 8 to 64 printable bytes.
pub const MIN_PASSPHRASE: usize = 8;
pub const MAX_PASSPHRASE: usize = 64;
/// Actor names that are not people (M6.5 review F2): `console` is the
/// trusted console with no one logged in, `user` its actor before M6.5.
/// A person so named would make their records read as no one's.
pub const RESERVED: &[&[u8]] = &[b"console", b"user"];

/// A valid person's name: an agent-style name that is not [`RESERVED`].
/// `const`, so compiled tables check owners with it (`manifest::owned`).
pub const fn valid_person(name: &[u8]) -> bool {
    if !valid_name(name) {
        return false;
    }
    let mut i = 0;
    while i < RESERVED.len() {
        let r = RESERVED[i];
        if r.len() == name.len() {
            let mut j = 0;
            while j < r.len() && r[j] == name[j] {
                j += 1;
            }
            if j == r.len() {
                return false;
            }
        }
        i += 1;
    }
    true
}

/// One person's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Person {
    pub name: [u8; MAX_NAME],
    pub name_len: usize,
    pub roles: [[u8; MAX_NAME]; MAX_ROLES],
    pub role_lens: [usize; MAX_ROLES],
    pub role_count: usize,
    pub salt: [u8; 32],
    pub iterations: u32,
    pub hash: [u8; 32],
}

/// Why a record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    TooLong,
    /// A line that is not `key = value`, an unknown key, or one repeated.
    Line,
    Missing,
    Version,
    Name,
    Roles,
    Hex,
    Iterations,
}

impl Person {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn role(&self, i: usize) -> &[u8] {
        &self.roles[i][..self.role_lens[i]]
    }

    /// A record for `name` with `roles` (comma-separated, may be empty),
    /// or `None` if either is not valid.
    pub fn new(
        name: &[u8],
        roles: &[u8],
        salt: [u8; 32],
        iterations: u32,
        hash: [u8; 32],
    ) -> Option<Self> {
        if !valid_person(name) || iterations == 0 {
            return None;
        }
        let mut p = Self {
            name: [0; MAX_NAME],
            name_len: name.len(),
            roles: [[0; MAX_NAME]; MAX_ROLES],
            role_lens: [0; MAX_ROLES],
            role_count: 0,
            salt,
            iterations,
            hash,
        };
        p.name[..name.len()].copy_from_slice(name);
        p.set_roles(roles).then_some(p)
    }

    /// Replaces the roles (comma-separated, may be empty); false, and
    /// nothing changed, if one is not a name, there are too many, or one
    /// is given twice.
    pub fn set_roles(&mut self, roles: &[u8]) -> bool {
        let mut new = [[0u8; MAX_NAME]; MAX_ROLES];
        let mut lens = [0usize; MAX_ROLES];
        let mut n = 0;
        if !roles.is_empty() {
            for r in roles.split(|b| *b == b',') {
                if !valid_name(r) || n == MAX_ROLES || (0..n).any(|i| new[i][..lens[i]] == *r) {
                    return false;
                }
                new[n][..r.len()].copy_from_slice(r);
                lens[n] = r.len();
                n += 1;
            }
        }
        (self.roles, self.role_lens, self.role_count) = (new, lens, n);
        true
    }

    /// The record as stored; `None` if `out` is too small.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Text { out, at: 0 };
        w.put(b"person = 1\nname = ")?;
        w.put(self.name())?;
        w.put(b"\nroles = ")?;
        for i in 0..self.role_count {
            if i > 0 {
                w.put(b",")?;
            }
            w.put(self.role(i))?;
        }
        w.put(b"\nsalt = ")?;
        w.hex(&self.salt)?;
        w.put(b"\niterations = ")?;
        let mut d = [0u8; 10];
        w.put(decimal(self.iterations, &mut d))?;
        w.put(b"\nhash = ")?;
        w.hex(&self.hash)?;
        w.put(b"\n")?;
        Some(w.at)
    }
}

struct Text<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Text<'_> {
    fn put(&mut self, b: &[u8]) -> Option<()> {
        self.out
            .get_mut(self.at..self.at + b.len())?
            .copy_from_slice(b);
        self.at += b.len();
        Some(())
    }

    fn hex(&mut self, b: &[u8; 32]) -> Option<()> {
        for x in b {
            self.put(&[HEX[usize::from(x >> 4)], HEX[usize::from(x & 15)]])?;
        }
        Some(())
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn decimal(mut n: u32, out: &mut [u8; 10]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &out[i..];
        }
    }
}

fn unhex(s: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    for (i, o) in out.iter_mut().enumerate() {
        *o = digit(s[2 * i])? << 4 | digit(s[2 * i + 1])?;
    }
    Some(out)
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| *b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|b| *b != b' ').map_or(start, |e| e + 1);
    &s[start..end]
}

const KEYS: [&[u8]; 6] = [
    b"person",
    b"name",
    b"roles",
    b"salt",
    b"iterations",
    b"hash",
];

/// Parses a stored record.
pub fn parse(text: &[u8]) -> Result<Person, Refusal> {
    if text.len() > MAX_FILE {
        return Err(Refusal::TooLong);
    }
    let mut values: [Option<&[u8]>; 6] = [None; 6];
    for line in text.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let eq = line.iter().position(|b| *b == b'=').ok_or(Refusal::Line)?;
        let key = trim(&line[..eq]);
        let k = KEYS.iter().position(|k| *k == key).ok_or(Refusal::Line)?;
        if values[k].replace(trim(&line[eq + 1..])).is_some() {
            return Err(Refusal::Line);
        }
    }
    let [
        Some(version),
        Some(name),
        Some(roles),
        Some(salt),
        Some(iterations),
        Some(hash),
    ] = values
    else {
        return Err(Refusal::Missing);
    };
    if version != b"1" {
        return Err(Refusal::Version);
    }
    if !valid_person(name) {
        return Err(Refusal::Name);
    }
    let salt = unhex(salt).ok_or(Refusal::Hex)?;
    let hash = unhex(hash).ok_or(Refusal::Hex)?;
    let iterations = core::str::from_utf8(iterations)
        .ok()
        .filter(|s| !s.starts_with('+'))
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .ok_or(Refusal::Iterations)?;
    Person::new(name, roles, salt, iterations, hash).ok_or(Refusal::Roles)
}

/// Whether `p` may be a passphrase: 8 to 64 printable bytes.
/// A stop command is never a passphrase: typed during a prompt, it stops.
pub fn valid_passphrase(p: &[u8]) -> bool {
    (MIN_PASSPHRASE..=MAX_PASSPHRASE).contains(&p.len())
        && p.iter().all(|b| (b' '..=b'~').contains(b))
        && !crate::trust::is_stop(&crate::trust::command(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Person {
        Person::new(b"alice", b"approver,ops", [1; 32], 600_000, [2; 32]).unwrap()
    }

    #[test]
    fn a_stop_is_never_a_passphrase() {
        for stop in [
            &b"stop all"[..],
            b"stop hunter22x",
            b"stop group ops-team",
            b"stop service infer",
        ] {
            assert!(!valid_passphrase(stop), "{stop:?}");
        }
        assert!(valid_passphrase(b"stop-all-please") && valid_passphrase(b"nonstop all"));
    }

    #[test]
    fn console_and_user_are_no_persons_names() {
        for name in RESERVED {
            assert!(!valid_person(name));
            assert!(Person::new(name, b"", [1; 32], 1, [2; 32]).is_none());
            let p = Person::new(b"alice", b"", [1; 32], 1, [2; 32]).unwrap();
            let mut out = [0u8; MAX_FILE];
            let n = p.encode(&mut out).unwrap();
            let text = core::str::from_utf8(&out[..n]).unwrap().replace(
                "name = alice",
                &std::format!("name = {}", core::str::from_utf8(name).unwrap()),
            );
            assert_eq!(parse(text.as_bytes()), Err(Refusal::Name));
        }
        assert!(valid_person(b"consoles") && valid_person(b"users"));
    }

    #[test]
    fn a_record_round_trips() {
        let p = alice();
        let mut out = [0u8; MAX_FILE];
        let n = p.encode(&mut out).unwrap();
        assert_eq!(parse(&out[..n]), Ok(p));
        let text = core::str::from_utf8(&out[..n]).unwrap();
        assert!(text.starts_with("person = 1\nname = alice\nroles = approver,ops\nsalt = 0101"));
        assert!(text.contains("\niterations = 600000\nhash = 0202"));
        // No roles, the most roles, and the longest names fit.
        let none = Person::new(b"bob", b"", [0; 32], 1, [0; 32]).unwrap();
        let n = none.encode(&mut out).unwrap();
        assert_eq!(parse(&out[..n]), Ok(none));
        let long = [b'r'; MAX_NAME];
        let roles = (0..MAX_ROLES)
            .map(|i| {
                let mut r = long.to_vec();
                r[0] = b'a' + i as u8;
                r
            })
            .collect::<std::vec::Vec<_>>()
            .join(&b","[..]);
        let most = Person::new(&[b'n'; MAX_NAME], &roles, [255; 32], u32::MAX, [255; 32]).unwrap();
        let n = most.encode(&mut out).unwrap();
        assert!(n <= MAX_FILE);
        assert_eq!(parse(&out[..n]), Ok(most));
        assert_eq!(most.encode(&mut [0u8; 100]), None, "out too small");
    }

    #[test]
    fn bad_records_are_refused() {
        let mut out = [0u8; MAX_FILE];
        let n = alice().encode(&mut out).unwrap();
        let good = std::string::String::from(std::str::from_utf8(&out[..n]).unwrap());
        let with = |from: &str, to: &str| {
            assert!(good.contains(from), "{from}");
            parse(good.replacen(from, to, 1).as_bytes())
        };
        assert_eq!(with("person = 1", "person = 2"), Err(Refusal::Version));
        assert_eq!(with("name = alice", "name = al/ce"), Err(Refusal::Name));
        assert_eq!(with("name = alice", "name ="), Err(Refusal::Name));
        assert_eq!(
            with("roles = approver,ops", "roles = ops,ops"),
            Err(Refusal::Roles)
        );
        assert_eq!(
            with("roles = approver,ops", "roles = a,,b"),
            Err(Refusal::Roles)
        );
        assert_eq!(
            with("roles = approver,ops", "roles = a,b,c,d,e,f,g,h,i"),
            Err(Refusal::Roles)
        );
        assert_eq!(with("salt = 01", "salt = 0G"), Err(Refusal::Hex));
        assert_eq!(
            with("salt = 01", "salt = 01A1"),
            Err(Refusal::Hex),
            "upper case"
        );
        assert_eq!(with("salt = 01", "salt = 0"), Err(Refusal::Hex), "short");
        assert_eq!(
            with("iterations = 600000", "iterations = 0"),
            Err(Refusal::Iterations)
        );
        assert_eq!(
            with("iterations = 600000", "iterations = +1"),
            Err(Refusal::Iterations)
        );
        assert_eq!(
            with("iterations = 600000", "iterations = 4294967296"),
            Err(Refusal::Iterations)
        );
        assert_eq!(with("name = alice\n", ""), Err(Refusal::Missing));
        assert_eq!(
            with("name = alice", "name = alice\nname = bob"),
            Err(Refusal::Line)
        );
        assert_eq!(
            with("name = alice", "name = alice\nowner = x"),
            Err(Refusal::Line)
        );
        assert_eq!(with("name = alice", "name alice"), Err(Refusal::Line));
        assert_eq!(parse(&[b'#'; MAX_FILE + 1]), Err(Refusal::TooLong));
    }

    #[test]
    fn passphrases_are_one_printable_console_line() {
        assert!(valid_passphrase(b"eight ch"));
        assert!(valid_passphrase(&[b'~'; MAX_PASSPHRASE]));
        assert!(!valid_passphrase(b"seven c"));
        assert!(!valid_passphrase(&[b'a'; MAX_PASSPHRASE + 1]));
        assert!(!valid_passphrase(b"tab\there!"));
    }

    /// Mutated and random records never panic, and whatever parses
    /// encodes back the same (the D-020 pattern, fixed seed and count).
    #[test]
    fn random_records_never_panic() {
        let mut out = [0u8; MAX_FILE];
        let n = alice().encode(&mut out).unwrap();
        let seed = out[..n].to_vec();
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..50_000 {
            let mut m = if i % 4 == 0 {
                std::vec![0u8; (next() % 300) as usize]
            } else {
                seed.clone()
            };
            for _ in 0..=next() % 4 {
                if m.is_empty() {
                    break;
                }
                let at = (next() as usize) % m.len();
                m[at] = next() as u8;
            }
            if let Ok(p) = parse(&m) {
                let mut again = [0u8; MAX_FILE];
                let k = p.encode(&mut again).unwrap();
                assert_eq!(parse(&again[..k]), Ok(p));
            }
        }
    }
}
