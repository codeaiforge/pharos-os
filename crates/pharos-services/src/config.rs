//! The system configuration, `etc/system.conf` (M4.5, D-030, services.md
//! "Configuration and health"): settings only, each within what the
//! compiled table allows. The file is untrusted text: [`parse`] refuses it
//! whole with the first error and its line, and never panics. A value over
//! its ceiling is refused, never narrowed.
//!
//! ```text
//! config = 1
//! [service net]
//! start = no
//! [service knowledge]
//! restarts = 1
//! delay_ms = 500
//! ```

use core::fmt;

use crate::{MAX_SERVICES, PROTECTED, Restart, Service};

/// Where `init` reads it, in the image it starts services from.
pub const PATH: &[u8] = b"etc/system.conf";
/// Largest file.
pub const MAX_SIZE: usize = 4096;
/// Longest line.
pub const MAX_LINE: usize = 128;
/// The first restart's delay, in ms (`delay_ms`).
pub const DELAY_MS: core::ops::RangeInclusive<u32> = 10..=60_000;

/// What a file sets; every entry not named keeps its compiled values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// A bit per entry not started at boot (`start = no`).
    off: u32,
    restarts: [Option<u8>; MAX_SERVICES],
    delay_ms: [Option<u32>; MAX_SERVICES],
}

impl Config {
    /// No file: every compiled value.
    pub const COMPILED: Self = Self {
        off: 0,
        restarts: [None; MAX_SERVICES],
        delay_ms: [None; MAX_SERVICES],
    };

    /// Whether entry `i` starts at boot.
    pub fn starts(&self, i: usize) -> bool {
        i >= MAX_SERVICES || self.off & (1 << i) == 0
    }

    /// Entry `i`'s restart policy: the file's limit (0 is `Never`), or
    /// `compiled`.
    pub fn restart(&self, i: usize, compiled: Restart) -> Restart {
        match self.restarts.get(i).copied().flatten() {
            Some(0) => Restart::Never,
            Some(n) => Restart::Up(n),
            None => compiled,
        }
    }

    /// Entry `i`'s first restart delay in µs, or `compiled`.
    pub fn first_delay_us(&self, i: usize, compiled: u64) -> u64 {
        self.delay_ms
            .get(i)
            .copied()
            .flatten()
            .map_or(compiled, |ms| u64::from(ms) * 1000)
    }

    /// Each setting that differs from the compiled table, in table order:
    /// the entry, `start` off, the restart limit, the first delay in ms.
    pub fn settings(&self) -> impl Iterator<Item = (usize, bool, Option<u8>, Option<u32>)> + '_ {
        (0..MAX_SERVICES)
            .map(|i| (i, !self.starts(i), self.restarts[i], self.delay_ms[i]))
            .filter(|(_, off, r, d)| *off || r.is_some() || d.is_some())
    }
}

/// Why a file was refused, and the line (0: the whole file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub why: Why,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    TooLarge,
    LineTooLong,
    /// A byte that is not printable ASCII.
    BadByte,
    /// The first setting is not `config = 1`.
    NoVersion,
    /// Neither `key = value` nor a `[service <name>]` section.
    BadLine,
    /// A section name that is no entry of the table.
    NoService,
    RepeatedSection,
    /// A key before the first section.
    NoSection,
    UnknownKey,
    RepeatedKey,
    BadValue,
    /// `start = no` for `trust`, `audit`, or `store`.
    Protected(&'static str),
    /// `restarts` or `delay_ms` for `trust`, `audit`, or `store`: their
    /// compiled values only, so a file cannot leave the console or the
    /// trail down for long (M4.5 review F3).
    Compiled(&'static str),
    /// `start = no` for a driver entry (it starts with its device).
    Driver(&'static str),
    /// `start = no` for a service that a started one needs.
    Needed(&'static str, &'static str),
    /// `restarts` over the compiled limit: the value and the limit.
    OverLimit(&'static str, u32, u8),
    DelayRange,
    /// The image or the file could not be read.
    Unreadable,
}

/// Room for the longest [`Error`] text.
pub const MAX_TEXT: usize = 128;

impl Error {
    /// Its text, written into `out` with no allocation (user programs
    /// cannot use `alloc::format!`: it may unwind). Cut if too long.
    pub fn text<'a>(&self, out: &'a mut [u8; MAX_TEXT]) -> &'a [u8] {
        struct Into<'b>(&'b mut [u8], usize);
        impl fmt::Write for Into<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let n = s.len().min(self.0.len() - self.1);
                self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
                self.1 += n;
                Ok(())
            }
        }
        let mut w = Into(out, 0);
        let _ = fmt::write(&mut w, format_args!("{self}"));
        let n = w.1;
        &out[..n]
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line > 0 {
            write!(f, "line {}: ", self.line)?;
        }
        match self.why {
            Why::TooLarge => write!(f, "over {MAX_SIZE} bytes"),
            Why::LineTooLong => write!(f, "over {MAX_LINE} bytes"),
            Why::BadByte => write!(f, "not printable ASCII"),
            Why::NoVersion => write!(f, "expected config = 1 first"),
            Why::BadLine => write!(f, "expected key = value or [service <name>]"),
            Why::NoService => write!(f, "no such service"),
            Why::RepeatedSection => write!(f, "section repeated"),
            Why::NoSection => write!(f, "setting before any [service <name>]"),
            Why::UnknownKey => write!(f, "unknown key"),
            Why::RepeatedKey => write!(f, "key repeated"),
            Why::BadValue => write!(f, "bad value"),
            Why::Protected(s) => write!(f, "{s} always starts"),
            Why::Compiled(s) => write!(f, "{s} restarts as compiled"),
            Why::Driver(s) => write!(f, "{s} starts with its device"),
            Why::Needed(s, by) => write!(f, "{s} is needed by {by}"),
            Why::OverLimit(s, n, max) => write!(f, "restarts {n} over {max} for {s}"),
            Why::Unreadable => write!(f, "cannot be read"),
            Why::DelayRange => write!(
                f,
                "delay_ms not from {} to {}",
                DELAY_MS.start(),
                DELAY_MS.end()
            ),
        }
    }
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| *b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|b| *b != b' ').map_or(start, |i| i + 1);
    &s[start..end]
}

/// A decimal number up to `max`, digits only, no leading zero but `0`.
fn number(v: &[u8], max: u32) -> Option<u32> {
    if v.is_empty() || v.len() > 10 || (v[0] == b'0' && v.len() > 1) {
        return None;
    }
    let mut n: u64 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u64::from(b - b'0');
    }
    u32::try_from(n).ok().filter(|n| *n <= max)
}

/// Checks `text` against `table`, the table `init` runs.
pub fn parse(text: &[u8], table: &[Service]) -> Result<Config, Error> {
    if text.len() > MAX_SIZE {
        return Err(Error {
            line: 0,
            why: Why::TooLarge,
        });
    }
    let mut config = Config::COMPILED;
    // The line that set each `start = no`, for `Needed`.
    let mut off_line = [0usize; MAX_SERVICES];
    let mut seen = 0u32;
    let mut versioned = false;
    let mut section: Option<usize> = None;
    let mut keys = 0u8;
    for (n, line) in text.split(|b| *b == b'\n').enumerate() {
        let at = |why| Error { line: n + 1, why };
        if line.len() > MAX_LINE {
            return Err(at(Why::LineTooLong));
        }
        if !line.iter().all(|b| (b' '..=b'~').contains(b)) {
            return Err(at(Why::BadByte));
        }
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if !versioned {
            let eq = line.iter().position(|b| *b == b'=');
            let ok =
                eq.is_some_and(|e| trim(&line[..e]) == b"config" && trim(&line[e + 1..]) == b"1");
            if !ok {
                return Err(at(Why::NoVersion));
            }
            versioned = true;
            continue;
        }
        if let Some(inner) = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")) {
            let inner = trim(inner);
            let name = inner
                .strip_prefix(b"service ")
                .map(trim)
                .ok_or(at(Why::BadLine))?;
            let i = (table.iter().take(MAX_SERVICES))
                .position(|s| s.name.as_bytes() == name)
                .ok_or(at(Why::NoService))?;
            if seen & (1 << i) != 0 {
                return Err(at(Why::RepeatedSection));
            }
            seen |= 1 << i;
            section = Some(i);
            keys = 0;
            continue;
        }
        let eq = line
            .iter()
            .position(|b| *b == b'=')
            .ok_or(at(Why::BadLine))?;
        let (key, value) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        let i = section.ok_or(at(Why::NoSection))?;
        let service = &table[i];
        let k = [&b"start"[..], b"restarts", b"delay_ms"]
            .iter()
            .position(|k| *k == key)
            .ok_or(at(Why::UnknownKey))?;
        if keys & (1 << k) != 0 {
            return Err(at(Why::RepeatedKey));
        }
        keys |= 1 << k;
        if k > 0 && PROTECTED.contains(&service.name) {
            return Err(at(Why::Compiled(service.name)));
        }
        match k {
            0 => match value {
                b"yes" => {}
                b"no" if PROTECTED.contains(&service.name) => {
                    return Err(at(Why::Protected(service.name)));
                }
                b"no" if service.driver().is_some() => {
                    return Err(at(Why::Driver(service.name)));
                }
                b"no" => {
                    config.off |= 1 << i;
                    off_line[i] = n + 1;
                }
                _ => return Err(at(Why::BadValue)),
            },
            1 => {
                let r = number(value, u32::MAX).ok_or(at(Why::BadValue))?;
                let max = service.restart.limit();
                if r > u32::from(max) {
                    return Err(at(Why::OverLimit(service.name, r, max)));
                }
                config.restarts[i] = Some(r as u8);
            }
            _ => {
                let ms = number(value, u32::MAX).ok_or(at(Why::BadValue))?;
                if !DELAY_MS.contains(&ms) {
                    return Err(at(Why::DelayRange));
                }
                config.delay_ms[i] = Some(ms);
            }
        }
    }
    if !versioned {
        return Err(Error {
            line: 0,
            why: Why::NoVersion,
        });
    }
    // A service off that a started one needs: the first such line.
    let mut first: Option<Error> = None;
    for (j, user) in table.iter().enumerate().take(MAX_SERVICES) {
        if !config.starts(j) {
            continue;
        }
        for &a in user.after {
            if !config.starts(a) && first.is_none_or(|e| off_line[a] < e.line) {
                first = Some(Error {
                    line: off_line[a],
                    why: Why::Needed(table[a].name, user.name),
                });
            }
        }
    }
    first.map_or(Ok(config), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BOOT;
    use std::string::ToString;

    fn err(text: &str) -> std::string::String {
        parse(text.as_bytes(), BOOT).unwrap_err().to_string()
    }

    fn index(name: &str) -> usize {
        BOOT.iter().position(|s| s.name == name).unwrap()
    }

    #[test]
    fn a_file_sets_only_what_it_names() {
        let text = "# boot settings\nconfig = 1\n\n[service net]\nstart = no\n[service knowledge]\nrestarts = 1\ndelay_ms = 500\n";
        let c = parse(text.as_bytes(), BOOT).unwrap();
        let (net, knowledge) = (index("net"), index("knowledge"));
        assert!(!c.starts(net) && c.starts(knowledge));
        assert_eq!(c.restart(knowledge, Restart::Up(3)), Restart::Up(1));
        assert_eq!(c.first_delay_us(knowledge, 100_000), 500_000);
        assert_eq!(c.restart(net, Restart::Up(3)), Restart::Up(3));
        assert_eq!(c.first_delay_us(net, 100_000), 100_000);
        let set: std::vec::Vec<_> = c.settings().collect();
        assert_eq!(set.len(), 2);
        assert_eq!(set[0], (net, true, None, None));
        assert_eq!(set[1], (knowledge, false, Some(1), Some(500)));
        // Restarts 0 is never; the bare version is every compiled value.
        let c = parse(b"config = 1\n[service net]\nrestarts = 0", BOOT).unwrap();
        assert_eq!(c.restart(net, Restart::Up(3)), Restart::Never);
        assert_eq!(parse(b"config=1", BOOT), Ok(Config::COMPILED));
    }

    #[test]
    fn each_error_names_its_line() {
        assert_eq!(err(""), "expected config = 1 first");
        assert_eq!(err("# only\n"), "expected config = 1 first");
        assert_eq!(err("[service net]\n"), "line 1: expected config = 1 first");
        assert_eq!(err("config = 2\n"), "line 1: expected config = 1 first");
        assert_eq!(
            err("config = 1\nstart = no"),
            "line 2: setting before any [service <name>]"
        );
        assert_eq!(err("config = 1\n[service nope]"), "line 2: no such service");
        assert_eq!(
            err("config = 1\n[agent net]"),
            "line 2: expected key = value or [service <name>]"
        );
        assert_eq!(
            err("config = 1\n[service net]\n[service net]"),
            "line 3: section repeated"
        );
        assert_eq!(
            err("config = 1\n[service net]\nstop = no"),
            "line 3: unknown key"
        );
        assert_eq!(
            err("config = 1\n[service net]\nstart = no\nstart = no"),
            "line 4: key repeated"
        );
        assert_eq!(
            err("config = 1\n[service net]\nstart"),
            "line 3: expected key = value or [service <name>]"
        );
        for bad in ["off", "", "No"] {
            assert_eq!(
                err(&std::format!("config = 1\n[service net]\nstart = {bad}")),
                "line 3: bad value"
            );
        }
        for bad in ["-1", "01", "1x", "", "99999999999"] {
            assert_eq!(
                err(&std::format!("config = 1\n[service net]\nrestarts = {bad}")),
                "line 3: bad value"
            );
        }
        assert_eq!(
            err("config = 1\n[service net]\ndelay_ms = 9"),
            "line 3: delay_ms not from 10 to 60000"
        );
        assert_eq!(
            err("config = 1\n[service net]\ndelay_ms = 60001"),
            "line 3: delay_ms not from 10 to 60000"
        );
        assert_eq!(err("config = 1\n\t"), "line 2: not printable ASCII");
        assert_eq!(err("config = 1\r\n"), "line 1: not printable ASCII");
        let long = std::format!("config = 1\n#{}", "x".repeat(MAX_LINE));
        assert_eq!(err(&long), "line 2: over 128 bytes");
        let big = std::format!("config = 1\n{}", "#\n".repeat(MAX_SIZE));
        assert_eq!(err(&big), "over 4096 bytes");
    }

    #[test]
    fn the_text_needs_no_allocation() {
        let e = parse(
            b"config = 1\n[service knowledge]\nrestarts = 4294967295",
            BOOT,
        )
        .unwrap_err();
        let mut out = [0u8; MAX_TEXT];
        assert_eq!(e.text(&mut out), e.to_string().as_bytes());
        assert!(e.to_string().len() < MAX_TEXT);
    }

    #[test]
    fn nothing_is_widened_or_narrowed() {
        // Over the compiled limit: refused, not narrowed.
        assert_eq!(
            err("config = 1\n[service knowledge]\nrestarts = 4"),
            "line 3: restarts 4 over 3 for knowledge"
        );
        // A `Never` entry can only stay `Never`.
        let never = BOOT.iter().find(|s| s.restart == Restart::Never).unwrap();
        let text = std::format!("config = 1\n[service {}]\nrestarts = 1", never.name);
        assert_eq!(
            err(&text),
            std::format!("line 3: restarts 1 over 0 for {}", never.name)
        );
        for name in PROTECTED {
            let text = std::format!("config = 1\n[service {name}]\nstart = no");
            assert_eq!(err(&text), std::format!("line 3: {name} always starts"));
            // Nor restart less or later (M4.5 review F3).
            for key in [
                "restarts = 0",
                "restarts = 3",
                "delay_ms = 60000",
                "delay_ms = 100",
            ] {
                let text = std::format!("config = 1\n[service {name}]\n{key}");
                assert_eq!(
                    err(&text),
                    std::format!("line 3: {name} restarts as compiled")
                );
            }
            // `start = yes` is still allowed.
            let text = std::format!("config = 1\n[service {name}]\nstart = yes");
            assert!(parse(text.as_bytes(), BOOT).is_ok());
        }
        assert_eq!(
            err("config = 1\n[service disk]\nstart = no"),
            "line 3: disk starts with its device"
        );
    }

    #[test]
    fn a_service_others_need_stays_on() {
        // Every entry that needs another: off alone is refused, off with
        // every entry that needs it (and is not protected) is not.
        for (j, user) in BOOT.iter().enumerate() {
            for &a in user.after {
                let need = BOOT[a].name;
                if PROTECTED.contains(&need) || BOOT[a].driver().is_some() {
                    continue;
                }
                let text = std::format!("config = 1\n[service {need}]\nstart = no");
                let e = parse(text.as_bytes(), BOOT).unwrap_err();
                assert_eq!(e.line, 3, "{need} needed by {}", BOOT[j].name);
                assert!(matches!(e.why, Why::Needed(n, _) if n == need));
            }
        }
        assert_eq!(
            err("config = 1\n[service infer]\nstart = no"),
            "line 3: infer is needed by agents"
        );
        // `agents` needs `infer` and `knowledge`; with it off, they can be.
        let a = index("agents");
        let after: std::vec::Vec<&str> = BOOT[a].after.iter().map(|&i| BOOT[i].name).collect();
        let mut text = std::string::String::from("config = 1\n[service agents]\nstart = no\n");
        for name in &after {
            if !PROTECTED.contains(name) && *name != "virtio-blk" {
                text += &std::format!("[service {name}]\nstart = no\n");
            }
        }
        let c = parse(text.as_bytes(), BOOT);
        assert!(c.is_ok(), "{text}: {c:?}");
    }

    #[test]
    fn fuzzed() {
        let alphabet = b"config=1\n [service]netstaro_mydel";
        let mut x = 0x1234_5678_9abc_def1u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..100_000 {
            let len = (next() % 300) as usize;
            let text: std::vec::Vec<u8> = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let _ = parse(&text, BOOT);
        }
        let good = b"config = 1\n[service net]\nstart = no\n[service knowledge]\nrestarts = 1\n";
        for _ in 0..100_000 {
            let mut text = good.to_vec();
            for _ in 0..1 + next() % 4 {
                let r = next();
                let i = (r as usize >> 8) % text.len();
                text[i] = r as u8;
            }
            if let Ok(c) = parse(&text, BOOT) {
                for (i, s) in BOOT.iter().enumerate() {
                    assert!(c.restart(i, s.restart).limit() <= s.restart.limit());
                    assert!(c.starts(i) || !PROTECTED.contains(&s.name));
                }
            }
        }
    }
}
