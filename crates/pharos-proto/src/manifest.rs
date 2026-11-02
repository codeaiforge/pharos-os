//! Agent manifests, version 1 (agents.md, #97): what an agent asks for, as
//! a text file in the read-only filesystem image. At most 4 KiB, one
//! `key = value` per line, `#` lines are comments, blank lines are
//! ignored. Every key appears exactly once:
//!
//! ```text
//! manifest = 1
//! name = summarize
//! program = agents/summarize
//! pages = 2048
//! models = 1
//! attempts = 3
//! progress_ms = 30000
//! task_ms = 600000
//! ```
//!
//! `models` lists model numbers, comma-separated, or is empty for none.
//! A manifest is untrusted: [`parse`] refuses unknown, repeated, and
//! missing keys and values out of range, and never panics. It only asks:
//! [`Manifest::within`] checks it against the runtime's reviewed policy
//! entry, and a manifest asking for more is refused, never narrowed.

use crate::Writer;
use crate::trust::valid_name;

pub const VERSION: u32 = 1;
/// Largest manifest file.
pub const MAX_SIZE: usize = 4096;
/// Longest program path.
pub const MAX_PROGRAM: usize = 64;
/// Most pages a manifest may ask for (1 GiB).
pub const MAX_PAGES: u32 = 262_144;
/// Highest model number.
pub const MAX_MODEL: u8 = 31;
/// Most attempts per task.
pub const MAX_ATTEMPTS: u8 = 10;
/// Longest `progress_ms`: one hour.
pub const MAX_PROGRESS_MS: u32 = 3_600_000;
/// Longest `task_ms`: one day.
pub const MAX_TASK_MS: u32 = 86_400_000;

/// A parsed manifest, borrowing its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest<'a> {
    pub name: &'a [u8],
    pub program: &'a [u8],
    pub pages: u32,
    /// Bit `n` set: model `n` may be used.
    pub models: u32,
    pub attempts: u8,
    pub progress_ms: u32,
    pub task_ms: u32,
}

/// What the runtime's policy table allows one agent: the most it may get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: &'static [u8],
    pub program: &'static [u8],
    pub pages: u32,
    pub models: u32,
    pub attempts: u8,
    pub progress_ms: u32,
    pub task_ms: u32,
}

/// Why a manifest was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    TooLarge,
    /// A byte other than printable ASCII or `\n`.
    BadByte,
    /// A line that is not `key = value`.
    BadLine,
    UnknownKey,
    RepeatedKey,
    MissingKey,
    /// `manifest` is not [`VERSION`].
    Version,
    /// A value that is malformed or out of range.
    BadValue,
    /// `progress_ms` above `task_ms`.
    ProgressOverTask,
    /// [`Manifest::within`]: no policy entry for this name.
    NoEntry,
    /// [`Manifest::within`]: a different program than the entry's.
    WrongProgram,
    /// [`Manifest::within`]: more than the entry allows.
    OverPolicy,
}

/// A refusal and the line it happened on (1-based; 0 for the whole file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub line: usize,
    pub why: Why,
}

const KEYS: [&[u8]; 8] = [
    b"manifest",
    b"name",
    b"program",
    b"pages",
    b"models",
    b"attempts",
    b"progress_ms",
    b"task_ms",
];

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| *b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|b| *b != b' ').map_or(start, |i| i + 1);
    &s[start..end]
}

/// A decimal number from 1 to `max`, digits only, no leading zero.
fn number(v: &[u8], max: u32) -> Option<u32> {
    if v.is_empty() || v.len() > 10 || v[0] == b'0' {
        return None;
    }
    let mut n: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    (n <= max).then_some(n)
}

/// A program path: `/`-separated parts of letters, digits, `-`, `_`, `.`,
/// none empty, `.`, or `..`.
fn valid_program(p: &[u8]) -> bool {
    (1..=MAX_PROGRAM).contains(&p.len())
        && p.split(|b| *b == b'/').all(|part| {
            !part.is_empty()
                && part != b"."
                && part != b".."
                && part
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
        })
}

/// Model numbers, comma-separated (spaces allowed around them), each at
/// most once; empty for none.
fn models(v: &[u8]) -> Option<u32> {
    let mut mask = 0u32;
    if v.is_empty() {
        return Some(0);
    }
    for part in v.split(|b| *b == b',') {
        let bit = 1u32 << number(trim(part), u32::from(MAX_MODEL))?;
        if mask & bit != 0 {
            return None;
        }
        mask |= bit;
    }
    Some(mask)
}

pub fn parse(text: &[u8]) -> Result<Manifest<'_>, Refusal> {
    let whole = |why| Refusal { line: 0, why };
    if text.len() > MAX_SIZE {
        return Err(whole(Why::TooLarge));
    }
    let mut values: [Option<&[u8]>; 8] = [None; 8];
    for (i, line) in text.split(|b| *b == b'\n').enumerate() {
        let at = |why| Refusal { line: i + 1, why };
        if !line.iter().all(|b| (b' '..=b'~').contains(b)) {
            return Err(at(Why::BadByte));
        }
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let eq = line
            .iter()
            .position(|b| *b == b'=')
            .ok_or(at(Why::BadLine))?;
        let (key, value) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        let k = KEYS
            .iter()
            .position(|k| *k == key)
            .ok_or(at(Why::UnknownKey))?;
        if values[k].replace(value).is_some() {
            return Err(at(Why::RepeatedKey));
        }
    }
    let mut v = [&b""[..]; 8];
    for (out, value) in v.iter_mut().zip(values) {
        *out = value.ok_or(whole(Why::MissingKey))?;
    }
    let [
        version,
        name,
        program,
        pages,
        model_list,
        attempts,
        progress,
        task,
    ] = v;
    let bad = whole(Why::BadValue);
    if number(version, u32::MAX) != Some(VERSION) {
        return Err(whole(Why::Version));
    }
    let m = Manifest {
        name: Some(name).filter(|n| valid_name(n)).ok_or(bad)?,
        program: Some(program).filter(|p| valid_program(p)).ok_or(bad)?,
        pages: number(pages, MAX_PAGES).ok_or(bad)?,
        models: models(model_list).ok_or(bad)?,
        attempts: number(attempts, u32::from(MAX_ATTEMPTS)).ok_or(bad)? as u8,
        progress_ms: number(progress, MAX_PROGRESS_MS).ok_or(bad)?,
        task_ms: number(task, MAX_TASK_MS).ok_or(bad)?,
    };
    if m.progress_ms > m.task_ms {
        return Err(whole(Why::ProgressOverTask));
    }
    Ok(m)
}

/// Writes `n` in decimal.
fn decimal(w: &mut Writer<'_>, mut n: u32) -> Option<()> {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    w.bytes(&digits[i..])
}

impl Manifest<'_> {
    /// Checks this manifest against the policy `table`: its name's entry
    /// must exist, name the same program, and allow at least everything
    /// asked for. Returns the entry.
    pub fn within<'t>(&self, table: &'t [Entry]) -> Result<&'t Entry, Why> {
        let e = table
            .iter()
            .find(|e| e.name == self.name)
            .ok_or(Why::NoEntry)?;
        if e.program != self.program {
            return Err(Why::WrongProgram);
        }
        let fits = self.pages <= e.pages
            && self.models & !e.models == 0
            && self.attempts <= e.attempts
            && self.progress_ms <= e.progress_ms
            && self.task_ms <= e.task_ms;
        if fits { Ok(e) } else { Err(Why::OverPolicy) }
    }

    /// Writes the manifest in its canonical form; `None` if `out` is too
    /// small.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(b"manifest = 1\nname = ")?;
        w.bytes(self.name)?;
        w.bytes(b"\nprogram = ")?;
        w.bytes(self.program)?;
        w.bytes(b"\npages = ")?;
        decimal(&mut w, self.pages)?;
        w.bytes(b"\nmodels =")?;
        let mut sep = &b" "[..];
        for n in 1..=MAX_MODEL {
            if self.models & (1 << n) != 0 {
                w.bytes(sep)?;
                decimal(&mut w, u32::from(n))?;
                sep = b", ";
            }
        }
        w.bytes(b"\nattempts = ")?;
        decimal(&mut w, u32::from(self.attempts))?;
        w.bytes(b"\nprogress_ms = ")?;
        decimal(&mut w, self.progress_ms)?;
        w.bytes(b"\ntask_ms = ")?;
        decimal(&mut w, self.task_ms)?;
        w.bytes(b"\n")?;
        Some(w.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &[u8] = b"manifest = 1\nname = summarize\nprogram = agents/summarize\n\
pages = 2048\nmodels = 1\nattempts = 3\nprogress_ms = 30000\ntask_ms = 600000\n";

    const TABLE: &[Entry] = &[Entry {
        name: b"summarize",
        program: b"agents/summarize",
        pages: 4096,
        models: 1 << 1 | 1 << 2,
        attempts: 3,
        progress_ms: 30_000,
        task_ms: 600_000,
    }];

    fn with(key: &str, value: &str) -> std::string::String {
        let text = std::str::from_utf8(S).unwrap();
        text.lines()
            .map(|l| {
                if l.split(" = ").next() == Some(key) {
                    std::format!("{key} = {value}\n")
                } else {
                    std::format!("{l}\n")
                }
            })
            .collect()
    }

    fn why(text: &[u8]) -> Option<Why> {
        parse(text).err().map(|r| r.why)
    }

    #[test]
    fn every_field_parses() {
        let m = parse(S).unwrap();
        assert_eq!(
            m,
            Manifest {
                name: b"summarize",
                program: b"agents/summarize",
                pages: 2048,
                models: 1 << 1,
                attempts: 3,
                progress_ms: 30_000,
                task_ms: 600_000,
            }
        );
        let text = "# an agent\n\n  manifest=1  \nname =summarize\nprogram= agents/summarize\n\
pages = 262144\nmodels = 31 , 2,1\nattempts = 10\n   # comment\nprogress_ms = 1\ntask_ms = 86400000";
        let m = parse(text.as_bytes()).unwrap();
        assert_eq!(
            (m.pages, m.models, m.attempts, m.progress_ms, m.task_ms),
            (MAX_PAGES, 1 << 31 | 1 << 2 | 1 << 1, 10, 1, MAX_TASK_MS),
            "spaces, comments, maxima, no final newline"
        );
        assert_eq!(parse(with("models", "").as_bytes()).unwrap().models, 0);
        assert_eq!(parse(with("pages", "1").as_bytes()).unwrap().pages, 1);
        let program = std::format!("a/{}", "b".repeat(MAX_PROGRAM - 2));
        assert!(parse(with("program", &program).as_bytes()).is_ok());
    }

    #[test]
    fn manifests_round_trip() {
        for text in [
            std::string::String::from_utf8(S.to_vec()).unwrap(),
            with("models", ""),
            with("models", "3, 1, 31"),
            with("name", &"n".repeat(32)),
        ] {
            let m = parse(text.as_bytes()).unwrap();
            let mut out = [0u8; MAX_SIZE];
            let n = m.encode(&mut out).unwrap();
            assert_eq!(parse(&out[..n]), Ok(m), "{text}");
            assert_eq!(m.encode(&mut out[..n - 1]), None, "too small");
        }
        let mut out = [0u8; MAX_SIZE];
        let n = parse(S).unwrap().encode(&mut out).unwrap();
        assert_eq!(&out[..n], S, "the canonical form");
    }

    #[test]
    fn every_refusal() {
        let at = |text: &str| parse(text.as_bytes()).err();
        assert_eq!(
            at(&std::format!(
                "{}\n{}",
                std::str::from_utf8(S).unwrap(),
                "#".repeat(MAX_SIZE)
            )),
            Some(Refusal {
                line: 0,
                why: Why::TooLarge
            })
        );
        assert_eq!(
            at("manifest = 1\nname = a\tb\n"),
            Some(Refusal {
                line: 2,
                why: Why::BadByte
            }),
            "tab"
        );
        assert_eq!(why(b"manifest = 1\r\n"), Some(Why::BadByte), "CR");
        assert_eq!(
            why("name = é\n".as_bytes()),
            Some(Why::BadByte),
            "non-ASCII"
        );
        assert_eq!(why(b"\0"), Some(Why::BadByte));
        assert_eq!(
            at("# x\nmanifest 1\n"),
            Some(Refusal {
                line: 2,
                why: Why::BadLine
            })
        );
        let extra = std::format!("{}colour = red\n", std::str::from_utf8(S).unwrap());
        assert_eq!(
            at(&extra),
            Some(Refusal {
                line: 9,
                why: Why::UnknownKey
            })
        );
        assert_eq!(
            why(b"Name = x\n"),
            Some(Why::UnknownKey),
            "keys are case-sensitive"
        );
        let twice = std::format!("{}pages = 1\n", std::str::from_utf8(S).unwrap());
        assert_eq!(
            at(&twice),
            Some(Refusal {
                line: 9,
                why: Why::RepeatedKey
            })
        );
        for key in KEYS {
            let key = std::str::from_utf8(key).unwrap();
            let missing: std::string::String = std::str::from_utf8(S)
                .unwrap()
                .lines()
                .filter(|l| !l.starts_with(&std::format!("{key} ")))
                .map(|l| std::format!("{l}\n"))
                .collect();
            assert_eq!(why(missing.as_bytes()), Some(Why::MissingKey), "{key}");
        }
        for v in ["2", "0", "01", "", "one"] {
            assert_eq!(
                why(with("manifest", v).as_bytes()),
                Some(Why::Version),
                "{v:?}"
            );
        }
        for (key, value) in [
            ("name", ""),
            ("name", "a b"),
            ("name", &"n".repeat(33)),
            ("program", ""),
            ("program", "/agents/x"),
            ("program", "agents//x"),
            ("program", "agents/../init"),
            ("program", "agents/./x"),
            ("program", "agents/x/"),
            ("program", "agents/x y"),
            (
                "program",
                &std::format!("a/{}", "b".repeat(MAX_PROGRAM - 1)),
            ),
            ("pages", "0"),
            ("pages", "262145"),
            ("pages", "-1"),
            ("pages", "+1"),
            ("pages", "1 2"),
            ("pages", "4294967296"),
            ("pages", "99999999999"),
            ("pages", "02"),
            ("models", "0"),
            ("models", "32"),
            ("models", "1,1"),
            ("models", "1,"),
            ("models", ",1"),
            ("models", "1 2"),
            ("attempts", "0"),
            ("attempts", "11"),
            ("progress_ms", "0"),
            ("progress_ms", "3600001"),
            ("task_ms", "0"),
            ("task_ms", "86400001"),
        ] {
            assert_eq!(
                why(with(key, value).as_bytes()),
                Some(Why::BadValue),
                "{key} = {value:?}"
            );
        }
        assert_eq!(
            why(with("progress_ms", "600001").as_bytes()),
            Some(Why::ProgressOverTask)
        );
        assert!(
            parse(with("progress_ms", "600000").as_bytes()).is_ok(),
            "equal"
        );
    }

    #[test]
    fn checked_against_the_policy() {
        let check = |key: &str, value: &str| {
            let text = with(key, value);
            parse(text.as_bytes()).unwrap().within(TABLE).map(|_| ())
        };
        assert_eq!(parse(S).unwrap().within(TABLE), Ok(&TABLE[0]));
        assert_eq!(check("pages", "4096"), Ok(()), "the entry's maximum");
        assert_eq!(check("models", "2, 1"), Ok(()));
        assert_eq!(check("models", ""), Ok(()));
        assert_eq!(check("name", "other"), Err(Why::NoEntry));
        assert_eq!(check("program", "agents/other"), Err(Why::WrongProgram));
        for (key, value) in [
            ("pages", "4097"),
            ("models", "3"),
            ("models", "1, 3"),
            ("attempts", "4"),
            ("progress_ms", "30001"),
            ("task_ms", "600001"),
        ] {
            assert_eq!(check(key, value), Err(Why::OverPolicy), "{key} = {value}");
        }
        assert_eq!(parse(S).unwrap().within(&[]), Err(Why::NoEntry));
    }

    #[test]
    fn fuzzed() {
        // Bytes from a manifest's alphabet, then mutations of a valid one.
        let alphabet = b"manifest=1\n #,.0/_-pgsoidkr";
        crate::fuzz(100_000, alphabet.len() as u8, |m| {
            let text: std::vec::Vec<u8> = m.iter().map(|b| alphabet[usize::from(*b)]).collect();
            let _ = parse(&text);
            let _ = parse(m);
        });
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..100_000 {
            let mut text = S.to_vec();
            for _ in 0..1 + x % 4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize >> 8) % text.len();
                text[i] = x as u8;
            }
            if let Ok(m) = parse(&text) {
                assert!(valid_name(m.name) && valid_program(m.program));
                assert!(m.attempts <= MAX_ATTEMPTS && m.progress_ms <= m.task_ms);
                assert_eq!(m.models & 1, 0, "no model 0");
                let mut out = [0u8; MAX_SIZE];
                let n = m.encode(&mut out).unwrap();
                assert_eq!(parse(&out[..n]), Ok(m));
                let _ = m.within(TABLE);
            }
        }
    }
}
