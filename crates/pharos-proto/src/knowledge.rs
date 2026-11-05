//! Shared knowledge records, format 1 (#142, knowledge.md, D-025): one
//! immutable version of an entry, and one user's verification mark. The
//! `knowledge` service writes each once, as a store file, and never
//! rewrites it.
//!
//! A version: `["PKV", format, scope, key, version (4), kind, replaces
//! (4), author, source, boot (8), uptime (8), hash (32), tags, evidence,
//! evidence scopes, content length (2), content]`. Names are a length byte
//! and the name (agent-name rules; a promoted file, file rules); lists are
//! a count byte and their items.
//!
//! A mark: `["PKM", format, version (4), hash (32), boot (8), uptime (8)]`.

use crate::permission::valid_file;
use crate::trust::valid_name;
use crate::{Reader, Writer};

const VERSION_MAGIC: &[u8; 3] = b"PKV";
const MARK_MAGIC: &[u8; 3] = b"PKM";
pub const FORMAT: u8 = 1;

/// Largest content of one version.
pub const MAX_CONTENT: usize = 4096;
pub const MAX_TAGS: usize = 4;
pub const MAX_EVIDENCE: usize = 4;
/// Most scopes a version's evidence chain may reach, its own aside.
pub const MAX_EVIDENCE_SCOPES: usize = 8;
/// Largest encoded version (the largest of every field fits: tested).
pub const MAX_RECORD: usize = 5 * 1024;
pub const MARK_LEN: usize = 4 + 4 + 32 + 8 + 8;

/// Status bits, derived by the service, never stored (knowledge.md).
pub mod flag {
    /// Another version replaces it.
    pub const SUPERSEDED: u8 = 1;
    /// A retraction replaces it.
    pub const RETRACTED: u8 = 2;
    /// Superseded, or some of its evidence is (or is missing).
    pub const STALE: u8 = 4;
    /// The user marked this version, with its hash.
    pub const VERIFIED: u8 = 8;
    /// A head of a key with more than one claim among its heads.
    pub const CONFLICTING: u8 = 16;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Claim = 1,
    /// No content: the version it replaces no longer holds.
    Retraction = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Author<'a> {
    /// Named by the runtime, from the task it runs.
    Agent { name: &'a [u8], task: u32 },
    /// The host tool, or the user on the trusted path.
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    Written,
    /// From the agent's own `data` file (#145).
    Promoted(&'a [u8]),
    /// Loaded from the host.
    Host,
}

/// `scope/key/version`: a version cited as evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref<'a> {
    pub scope: &'a [u8],
    pub key: &'a [u8],
    pub version: u32,
}

/// At most `N` items, kept in order without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct List<T: Copy, const N: usize> {
    items: [Option<T>; N],
}

impl<T: Copy, const N: usize> Default for List<T, N> {
    fn default() -> Self {
        Self { items: [None; N] }
    }
}

impl<T: Copy, const N: usize> List<T, N> {
    pub fn new(items: &[T]) -> Option<Self> {
        let mut l = Self::default();
        for (slot, t) in l.items.iter_mut().zip(items) {
            *slot = Some(*t);
        }
        (items.len() <= N).then_some(l)
    }

    pub fn iter(&self) -> impl Iterator<Item = T> + Clone + '_ {
        self.items.iter().flatten().copied()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.items[..].first().is_none_or(Option::is_none)
    }

    fn push(&mut self, t: T) -> Option<()> {
        *self.items.iter_mut().find(|s| s.is_none())? = Some(t);
        Some(())
    }
}

/// One version of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version<'a> {
    pub scope: &'a [u8],
    pub key: &'a [u8],
    pub version: u32,
    pub kind: Kind,
    /// The version it corrects or retracts; 0 for a key's first.
    pub replaces: u32,
    pub author: Author<'a>,
    pub source: Source<'a>,
    /// The audit trail's boot number and `uptime` microseconds.
    pub boot: u64,
    pub uptime: u64,
    /// SHA-256 of the content, computed by the service.
    pub hash: [u8; 32],
    pub tags: List<&'a [u8], MAX_TAGS>,
    pub evidence: List<Ref<'a>, MAX_EVIDENCE>,
    /// The scopes its evidence chain reaches, other than `scope`.
    pub evidence_scopes: List<&'a [u8], MAX_EVIDENCE_SCOPES>,
    pub content: &'a [u8],
}

fn distinct<T: PartialEq + Copy>(items: impl Iterator<Item = T> + Clone) -> bool {
    items
        .clone()
        .enumerate()
        .all(|(i, a)| items.clone().skip(i + 1).all(|b| a != b))
}

impl Version<'_> {
    /// Every rule a stored version keeps (the service's index checks the
    /// hash and the evidence's existence).
    pub fn valid(&self) -> bool {
        let names = valid_name(self.scope) && valid_name(self.key);
        let numbers = self.version >= 1 && self.replaces < self.version;
        let kind = match self.kind {
            Kind::Claim => true,
            Kind::Retraction => self.replaces >= 1 && self.content.is_empty(),
        };
        let author = match self.author {
            Author::Agent { name, .. } => valid_name(name),
            Author::User => true,
        };
        let source = match self.source {
            Source::Promoted(f) => valid_file(f),
            _ => true,
        };
        let tags = self.tags.iter().all(valid_name) && distinct(self.tags.iter());
        let scopes = self.evidence_scopes.iter().all(valid_name)
            && distinct(self.evidence_scopes.iter())
            && !self.evidence_scopes.iter().any(|s| s == self.scope);
        // Each piece of evidence's scope is this one's or listed.
        let evidence = self.evidence.iter().all(|e| {
            valid_name(e.scope)
                && valid_name(e.key)
                && e.version >= 1
                && (e.scope == self.scope || self.evidence_scopes.iter().any(|s| s == e.scope))
        }) && distinct(self.evidence.iter());
        names
            && numbers
            && kind
            && author
            && source
            && tags
            && scopes
            && evidence
            && self.content.len() <= MAX_CONTENT
    }
}

fn name<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let n = usize::from(r.u8()?);
    r.take(n)
}

fn put_name(w: &mut Writer<'_>, n: &[u8]) -> Option<()> {
    w.bytes(&[u8::try_from(n.len()).ok()?])?;
    w.bytes(n)
}

/// Reads a version; `None` if it is malformed or breaks a rule.
pub fn parse_version(b: &[u8]) -> Option<Version<'_>> {
    let mut r = Reader::new(b);
    if r.take(3)? != VERSION_MAGIC || r.u8()? != FORMAT {
        return None;
    }
    let scope = name(&mut r)?;
    let key = name(&mut r)?;
    let version = r.u32()?;
    let kind = match r.u8()? {
        1 => Kind::Claim,
        2 => Kind::Retraction,
        _ => return None,
    };
    let replaces = r.u32()?;
    let author = match r.u8()? {
        1 => Author::Agent {
            name: name(&mut r)?,
            task: r.u32()?,
        },
        2 => Author::User,
        _ => return None,
    };
    let source = match r.u8()? {
        1 => Source::Written,
        2 => Source::Promoted(name(&mut r)?),
        3 => Source::Host,
        _ => return None,
    };
    let boot = r.u64()?;
    let uptime = r.u64()?;
    let hash = r.take(32)?.try_into().ok()?;
    let mut tags = List::default();
    for _ in 0..r.u8()? {
        tags.push(name(&mut r)?)?;
    }
    let mut evidence = List::default();
    for _ in 0..r.u8()? {
        evidence.push(Ref {
            scope: name(&mut r)?,
            key: name(&mut r)?,
            version: r.u32()?,
        })?;
    }
    let mut evidence_scopes = List::default();
    for _ in 0..r.u8()? {
        evidence_scopes.push(name(&mut r)?)?;
    }
    let n = usize::from(r.u16()?);
    let content = r.take(n)?;
    let v = Version {
        scope,
        key,
        version,
        kind,
        replaces,
        author,
        source,
        boot,
        uptime,
        hash,
        tags,
        evidence,
        evidence_scopes,
        content,
    };
    (r.is_empty() && v.valid()).then_some(v)
}

/// Writes `v`; `None` if it breaks a rule or does not fit.
pub fn encode_version(v: &Version<'_>, out: &mut [u8]) -> Option<usize> {
    if !v.valid() {
        return None;
    }
    let mut w = Writer::new(out);
    w.bytes(VERSION_MAGIC)?;
    w.bytes(&[FORMAT])?;
    put_name(&mut w, v.scope)?;
    put_name(&mut w, v.key)?;
    w.u32(v.version)?;
    w.bytes(&[v.kind as u8])?;
    w.u32(v.replaces)?;
    match v.author {
        Author::Agent { name, task } => {
            w.bytes(&[1])?;
            put_name(&mut w, name)?;
            w.u32(task)?;
        }
        Author::User => w.bytes(&[2])?,
    }
    match v.source {
        Source::Written => w.bytes(&[1])?,
        Source::Promoted(f) => {
            w.bytes(&[2])?;
            put_name(&mut w, f)?;
        }
        Source::Host => w.bytes(&[3])?,
    }
    w.u64(v.boot)?;
    w.u64(v.uptime)?;
    w.bytes(&v.hash)?;
    w.bytes(&[v.tags.len() as u8])?;
    for t in v.tags.iter() {
        put_name(&mut w, t)?;
    }
    w.bytes(&[v.evidence.len() as u8])?;
    for e in v.evidence.iter() {
        put_name(&mut w, e.scope)?;
        put_name(&mut w, e.key)?;
        w.u32(e.version)?;
    }
    w.bytes(&[v.evidence_scopes.len() as u8])?;
    for s in v.evidence_scopes.iter() {
        put_name(&mut w, s)?;
    }
    w.u16(v.content.len() as u16)?;
    w.bytes(v.content)?;
    Some(w.len())
}

/// The user's mark on one version: it holds only with this hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    pub version: u32,
    pub hash: [u8; 32],
    pub boot: u64,
    pub uptime: u64,
}

impl Mark {
    pub fn encode(&self) -> [u8; MARK_LEN] {
        let mut out = [0u8; MARK_LEN];
        out[..3].copy_from_slice(MARK_MAGIC);
        out[3] = FORMAT;
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..40].copy_from_slice(&self.hash);
        out[40..48].copy_from_slice(&self.boot.to_le_bytes());
        out[48..56].copy_from_slice(&self.uptime.to_le_bytes());
        out
    }

    pub fn parse(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.take(3)? != MARK_MAGIC || r.u8()? != FORMAT {
            return None;
        }
        let m = Self {
            version: r.u32()?,
            hash: r.take(32)?.try_into().ok()?,
            boot: r.u64()?,
            uptime: r.u64()?,
        };
        (r.is_empty() && m.version >= 1).then_some(m)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const LONG: &[u8] = &[b'a'; 32];

    fn claim<'a>() -> Version<'a> {
        Version {
            scope: b"notes",
            key: b"release",
            version: 1,
            kind: Kind::Claim,
            replaces: 0,
            author: Author::Agent {
                name: b"worker",
                task: 7,
            },
            source: Source::Written,
            boot: 3,
            uptime: 1_000,
            hash: [9; 32],
            tags: List::new(&[&b"plan"[..]]).unwrap(),
            evidence: List::default(),
            evidence_scopes: List::default(),
            content: b"ship on friday",
        }
    }

    fn round_trip(v: &Version<'_>) -> usize {
        let mut out = [0u8; MAX_RECORD];
        let n = encode_version(v, &mut out).expect("encodes");
        assert_eq!(parse_version(&out[..n]), Some(*v));
        let mut longer = std::vec::Vec::from(&out[..n]);
        longer.push(0);
        assert_eq!(parse_version(&longer), None, "a trailing byte");
        for cut in 0..n {
            assert_eq!(parse_version(&out[..cut]), None, "cut at {cut}");
        }
        n
    }

    #[test]
    fn versions_round_trip_at_every_limit() {
        round_trip(&claim());
        let tags = [LONG, b"b", b"c", b"d"];
        let scopes: [&[u8]; 8] = [b"s1", b"s2", b"s3", b"s4", b"s5", b"s6", b"s7", LONG];
        let refs = [
            Ref {
                scope: LONG,
                key: LONG,
                version: u32::MAX,
            },
            Ref {
                scope: b"notes",
                key: b"k",
                version: 1,
            },
            Ref {
                scope: b"s1",
                key: LONG,
                version: 2,
            },
            Ref {
                scope: b"s7",
                key: b"k",
                version: 3,
            },
        ];
        let content = [0xffu8; MAX_CONTENT];
        let largest = Version {
            scope: b"notes",
            key: LONG,
            version: u32::MAX,
            replaces: u32::MAX - 1,
            author: Author::Agent {
                name: LONG,
                task: u32::MAX,
            },
            source: Source::Promoted(LONG),
            boot: u64::MAX,
            uptime: u64::MAX,
            tags: List::new(&tags).unwrap(),
            evidence: List::new(&refs).unwrap(),
            evidence_scopes: List::new(&scopes).unwrap(),
            content: &content,
            ..claim()
        };
        let n = round_trip(&largest);
        assert!(n <= MAX_RECORD, "{n} bytes");
        round_trip(&Version {
            author: Author::User,
            source: Source::Host,
            ..claim()
        });
        round_trip(&Version {
            kind: Kind::Retraction,
            version: 2,
            replaces: 1,
            content: b"",
            ..claim()
        });
    }

    #[test]
    fn versions_breaking_a_rule_are_refused() {
        let good = claim();
        let refs = [Ref {
            scope: b"other",
            key: b"k",
            version: 1,
        }];
        let other: [&[u8]; 1] = [b"other"];
        let own: [&[u8]; 1] = [b"notes"];
        let content = [0u8; MAX_CONTENT + 1];
        for (why, v) in [
            (
                "bad scope",
                Version {
                    scope: b"a b",
                    ..good
                },
            ),
            (
                "long key",
                Version {
                    key: &[b'k'; 33],
                    ..good
                },
            ),
            ("empty key", Version { key: b"", ..good }),
            ("version 0", Version { version: 0, ..good }),
            (
                "replaces itself",
                Version {
                    replaces: 1,
                    ..good
                },
            ),
            (
                "retraction with content",
                Version {
                    kind: Kind::Retraction,
                    version: 2,
                    replaces: 1,
                    ..good
                },
            ),
            (
                "retraction of nothing",
                Version {
                    kind: Kind::Retraction,
                    content: b"",
                    ..good
                },
            ),
            (
                "bad author",
                Version {
                    author: Author::Agent { name: b"", task: 1 },
                    ..good
                },
            ),
            (
                "promoted path",
                Version {
                    source: Source::Promoted(b"../x"),
                    ..good
                },
            ),
            (
                "repeated tag",
                Version {
                    tags: List::new(&[&b"a"[..], b"a"]).unwrap(),
                    ..good
                },
            ),
            (
                "evidence scope not listed",
                Version {
                    evidence: List::new(&refs).unwrap(),
                    ..good
                },
            ),
            (
                "own scope listed",
                Version {
                    evidence_scopes: List::new(&own).unwrap(),
                    ..good
                },
            ),
            (
                "evidence version 0",
                Version {
                    evidence: List::new(&[Ref {
                        version: 0,
                        ..refs[0]
                    }])
                    .unwrap(),
                    evidence_scopes: List::new(&other).unwrap(),
                    ..good
                },
            ),
            (
                "content over 4 KiB",
                Version {
                    content: &content,
                    ..good
                },
            ),
        ] {
            assert!(!v.valid(), "{why}");
            assert_eq!(encode_version(&v, &mut [0; MAX_RECORD + 2]), None, "{why}");
        }
        assert!(
            Version {
                evidence: List::new(&refs).unwrap(),
                evidence_scopes: List::new(&other).unwrap(),
                ..good
            }
            .valid(),
            "listed evidence scope"
        );
        assert_eq!(List::<u8, 2>::new(&[1, 2, 3]), None, "too many");
        let mut out = [0u8; MAX_RECORD];
        let n = encode_version(&good, &mut out).unwrap();
        for (at, byte, why) in [(0, b'X', "magic"), (3, 2, "format")] {
            let mut bad = out;
            bad[at] = byte;
            assert_eq!(parse_version(&bad[..n]), None, "{why}");
        }
    }

    #[test]
    fn marks_round_trip() {
        let m = Mark {
            version: 3,
            hash: [7; 32],
            boot: 2,
            uptime: u64::MAX,
        };
        let b = m.encode();
        assert_eq!(Mark::parse(&b), Some(m));
        assert_eq!(Mark::parse(&b[..MARK_LEN - 1]), None);
        let mut v0 = m;
        v0.version = 0;
        assert_eq!(Mark::parse(&v0.encode()), None, "version 0");
        let mut bad = b;
        bad[0] = b'X';
        assert_eq!(Mark::parse(&bad), None, "magic");
    }

    #[test]
    fn fuzzed_records_never_panic_and_hold_the_rules() {
        let mut base = [0u8; MAX_RECORD];
        let n = encode_version(&claim(), &mut base).unwrap();
        crate::fuzz(200_000, 11, |m| {
            if let Some(v) = parse_version(m) {
                assert!(v.valid());
            }
            let _ = Mark::parse(m);
            // Mutated valid records too.
            let mut b = base;
            for (i, x) in m.iter().enumerate().take(8) {
                b[usize::from(*x) % n] ^= m.get(i + 8).copied().unwrap_or(1);
            }
            if let Some(v) = parse_version(&b[..n]) {
                assert!(v.valid());
            }
        });
    }
}
