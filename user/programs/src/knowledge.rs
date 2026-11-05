//! The knowledge service's index (#142, knowledge.md, D-025): every
//! stored version's metadata, rebuilt from the store at start, and the
//! rules derived from it. A version is one store file, `<scope>/<key>/v<n>`,
//! and the user's mark on it is another, `<scope>/<key>/m<n>`; both are
//! written once. Status (superseded, retracted, stale, verified,
//! conflicting) is derived here, never stored.

use crate::tasks::{Files, StoreFailed};
use alloc::vec::Vec;
use pharos_proto::knowledge::{
    self as k, Kind, MAX_EVIDENCE_SCOPES, Mark, Ref, Version, flag, parse_version,
};
use pharos_store::sha256;

/// Most keys in one scope, and versions of one key.
pub const MAX_KEYS: usize = 256;
pub const MAX_VERSIONS: usize = 64;

/// Why a write or a mark was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No such version, or one the caller cannot read (never told apart).
    NotFound,
    /// A key's first version must replace nothing, and a later one must
    /// name the version it replaces.
    Replaces,
    /// Over `MAX_KEYS`, `MAX_VERSIONS`, or `MAX_EVIDENCE_SCOPES`.
    Full,
    /// The hash prefix does not match the version's content.
    HashDiffers,
}

/// What the index keeps of one version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub version: u32,
    pub kind: Kind,
    pub replaces: u32,
    pub hash: [u8; 32],
    pub tags: Vec<Vec<u8>>,
    pub evidence: Vec<(Vec<u8>, Vec<u8>, u32)>,
    pub evidence_scopes: Vec<Vec<u8>>,
    /// The hash in the user's mark, if any.
    pub marked: Option<[u8; 32]>,
}

struct Entry {
    scope: Vec<u8>,
    key: Vec<u8>,
    /// In version order.
    versions: Vec<Meta>,
}

/// What [`Index::load`] found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    pub versions: usize,
    pub marks: usize,
    /// Files that are not a valid version or mark where they are (bad
    /// record, hash, or path); left in place and not used.
    pub unreadable: usize,
}

/// A planned write: its number and evidence scopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    pub version: u32,
    pub evidence_scopes: Vec<Vec<u8>>,
}

/// `<scope>/<key>/v<n>`, or `m<n>` for its mark.
pub fn path(scope: &[u8], key: &[u8], version: u32, mark: bool) -> Vec<u8> {
    let mut d = [0u8; 10];
    let mut n = version;
    let mut at = d.len();
    loop {
        at -= 1;
        d[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let letter: &[u8] = if mark { b"m" } else { b"v" };
    [scope, b"/", key, b"/", letter, &d[at..]].concat()
}

/// Splits a path made by [`path`]: scope, key, version, and whether it is
/// a mark. A leading zero or anything else is `None`.
fn split(p: &[u8]) -> Option<(&[u8], &[u8], u32, bool)> {
    let mut parts = p.split(|b| *b == b'/');
    let (scope, key, file) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let (letter, digits) = file.split_first()?;
    let mark = match letter {
        b'v' => false,
        b'm' => true,
        _ => return None,
    };
    if digits.is_empty() || digits[0] == b'0' || digits.len() > 10 {
        return None;
    }
    let mut v: u64 = 0;
    for d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(d - b'0');
    }
    Some((scope, key, u32::try_from(v).ok()?, mark))
}

#[derive(Default)]
pub struct Index {
    entries: Vec<Entry>,
}

impl Index {
    /// Rebuilds the index from every file in the namespace: versions
    /// first, then marks.
    pub fn load(f: &mut impl Files) -> Result<(Self, Loaded), StoreFailed> {
        let mut index = Self::default();
        let mut loaded = Loaded::default();
        let (mut versions, mut marks) = (Vec::new(), Vec::new());
        for name in f.list(b"")? {
            let Some((scope, key, number, mark)) = split(&name) else {
                loaded.unreadable += 1;
                continue;
            };
            let Some(bytes) = f.read(&name)? else {
                continue;
            };
            let item = (number, scope.to_vec(), key.to_vec(), bytes);
            if mark {
                marks.push(item);
            } else {
                versions.push(item);
            }
        }
        // In number order, so each version's predecessor comes first.
        versions.sort();
        for (number, scope, key, bytes) in versions {
            let good = parse_version(&bytes).filter(|v| {
                v.scope == scope
                    && v.key == key
                    && v.version == number
                    && v.hash == sha256(&[v.content])
            });
            match good {
                Some(v) if index.insert(&v) => loaded.versions += 1,
                _ => loaded.unreadable += 1,
            }
        }
        for (number, scope, key, bytes) in marks {
            let m = Mark::parse(&bytes).filter(|m| m.version == number);
            match (m, index.meta_mut(&scope, &key, number)) {
                (Some(m), Some(meta)) => {
                    meta.marked = Some(m.hash);
                    loaded.marks += 1;
                }
                _ => loaded.unreadable += 1,
            }
        }
        Ok((index, loaded))
    }

    fn entry(&self, scope: &[u8], key: &[u8]) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.scope == scope && e.key == key)
    }

    pub fn meta(&self, scope: &[u8], key: &[u8], version: u32) -> Option<&Meta> {
        self.entry(scope, key)?
            .versions
            .iter()
            .find(|m| m.version == version)
    }

    fn meta_mut(&mut self, scope: &[u8], key: &[u8], version: u32) -> Option<&mut Meta> {
        self.entries
            .iter_mut()
            .find(|e| e.scope == scope && e.key == key)?
            .versions
            .iter_mut()
            .find(|m| m.version == version)
    }

    /// Adds a stored version; `false` if its number is taken or a limit is
    /// reached. A version whose predecessor is missing (an unreadable file)
    /// is kept: [`Index::plan`] checks `replaces` before anything is
    /// written.
    pub fn insert(&mut self, v: &Version<'_>) -> bool {
        let keys = self.entries.iter().filter(|e| e.scope == v.scope).count();
        let at = match self
            .entries
            .iter()
            .position(|e| e.scope == v.scope && e.key == v.key)
        {
            Some(at) => at,
            None if keys < MAX_KEYS => {
                self.entries.push(Entry {
                    scope: v.scope.to_vec(),
                    key: v.key.to_vec(),
                    versions: Vec::new(),
                });
                self.entries.len() - 1
            }
            None => return false,
        };
        let versions = &mut self.entries[at].versions;
        let taken = versions.iter().any(|m| m.version == v.version);
        if taken || versions.len() >= MAX_VERSIONS {
            return false;
        }
        let names = |l: &mut dyn Iterator<Item = &[u8]>| l.map(<[u8]>::to_vec).collect();
        let meta = Meta {
            version: v.version,
            kind: v.kind,
            replaces: v.replaces,
            hash: v.hash,
            tags: names(&mut v.tags.iter()),
            evidence: v
                .evidence
                .iter()
                .map(|e| (e.scope.to_vec(), e.key.to_vec(), e.version))
                .collect(),
            evidence_scopes: names(&mut v.evidence_scopes.iter()),
            marked: None,
        };
        let pos = versions.partition_point(|m| m.version < v.version);
        versions.insert(pos, meta);
        true
    }

    /// The versions no other version replaces.
    pub fn heads(&self, scope: &[u8], key: &[u8]) -> Vec<u32> {
        let Some(e) = self.entry(scope, key) else {
            return Vec::new();
        };
        e.versions
            .iter()
            .filter(|m| !e.versions.iter().any(|n| n.replaces == m.version))
            .map(|m| m.version)
            .collect()
    }

    /// True if another version replaces this one.
    fn superseded(&self, scope: &[u8], key: &[u8], version: u32) -> bool {
        self.entry(scope, key)
            .is_some_and(|e| e.versions.iter().any(|n| n.replaces == version))
    }

    /// A version's status bits (`pharos_proto::knowledge::flag`).
    pub fn status(&self, scope: &[u8], key: &[u8], version: u32) -> Option<u8> {
        let e = self.entry(scope, key)?;
        let m = e.versions.iter().find(|m| m.version == version)?;
        let mut s = 0;
        let by: Vec<&Meta> = e
            .versions
            .iter()
            .filter(|n| n.replaces == version)
            .collect();
        if !by.is_empty() {
            s |= flag::SUPERSEDED | flag::STALE;
        }
        if by.iter().any(|n| n.kind == Kind::Retraction) {
            s |= flag::RETRACTED;
        }
        // Evidence replaced, retracted, or missing makes it stale.
        let shaky = m
            .evidence
            .iter()
            .any(|(es, ek, ev)| self.meta(es, ek, *ev).is_none() || self.superseded(es, ek, *ev));
        if shaky {
            s |= flag::STALE;
        }
        if m.marked == Some(m.hash) {
            s |= flag::VERIFIED;
        }
        let heads = self.heads(scope, key);
        let claims = heads
            .iter()
            .filter(|h| {
                self.meta(scope, key, **h)
                    .is_some_and(|n| n.kind == Kind::Claim)
            })
            .count();
        if claims > 1 && heads.contains(&version) {
            s |= flag::CONFLICTING;
        }
        Some(s)
    }

    /// True if a reader of `readable` may see version `m` of `scope`: its
    /// scope and every scope its evidence chain reaches.
    pub fn readable(scope: &[u8], m: &Meta, readable: &[&[u8]]) -> bool {
        let can = |s: &[u8]| readable.contains(&s);
        can(scope) && m.evidence_scopes.iter().all(|s| can(s))
    }

    /// Checks a write by a writer who may read `readable`; its number and
    /// evidence scopes. Evidence the writer cannot read is `NotFound`.
    pub fn plan<'r>(
        &self,
        scope: &[u8],
        key: &[u8],
        replaces: u32,
        evidence: impl IntoIterator<Item = Ref<'r>>,
        readable: &[&[u8]],
    ) -> Result<Planned, Refused> {
        let e = self.entry(scope, key);
        let last = e.and_then(|e| e.versions.last()).map_or(0, |m| m.version);
        match (e, replaces) {
            (None, 0) => {
                let keys = self.entries.iter().filter(|e| e.scope == scope).count();
                if keys >= MAX_KEYS {
                    return Err(Refused::Full);
                }
            }
            (None, _) | (Some(_), 0) => return Err(Refused::Replaces),
            (Some(e), r) => {
                if !e.versions.iter().any(|m| m.version == r) {
                    return Err(Refused::Replaces);
                }
                if e.versions.len() >= MAX_VERSIONS {
                    return Err(Refused::Full);
                }
            }
        }
        let version = last.checked_add(1).ok_or(Refused::Full)?;
        let mut scopes: Vec<Vec<u8>> = Vec::new();
        let mut add = |s: &[u8]| {
            if s != scope && !scopes.iter().any(|t| t == s) {
                scopes.push(s.to_vec());
            }
        };
        for r in evidence {
            let m = self
                .meta(r.scope, r.key, r.version)
                .filter(|m| Self::readable(r.scope, m, readable))
                .ok_or(Refused::NotFound)?;
            add(r.scope);
            for s in &m.evidence_scopes {
                add(s);
            }
        }
        if scopes.len() > MAX_EVIDENCE_SCOPES {
            return Err(Refused::Full);
        }
        Ok(Planned {
            version,
            evidence_scopes: scopes,
        })
    }

    /// Checks the user's mark on a version, given the first 4 bytes of its
    /// hash (8 hexadecimal digits); the mark to store.
    pub fn plan_mark(
        &self,
        scope: &[u8],
        key: &[u8],
        version: u32,
        prefix: [u8; 4],
    ) -> Result<[u8; 32], Refused> {
        let m = self.meta(scope, key, version).ok_or(Refused::NotFound)?;
        if m.hash[..4] != prefix {
            return Err(Refused::HashDiffers);
        }
        Ok(m.hash)
    }

    /// Records a stored mark.
    pub fn marked(&mut self, scope: &[u8], key: &[u8], version: u32, hash: [u8; 32]) {
        if let Some(m) = self.meta_mut(scope, key, version) {
            m.marked = Some(hash);
        }
    }

    /// The keys of `scope` with a head tagged `tag` and readable by
    /// `readable`, in key order, at most `max`.
    pub fn tagged(&self, scope: &[u8], tag: &[u8], readable: &[&[u8]], max: usize) -> Vec<Vec<u8>> {
        let mut keys: Vec<Vec<u8>> = self
            .entries
            .iter()
            .filter(|e| e.scope == scope)
            .filter(|e| {
                self.heads(scope, &e.key).iter().any(|h| {
                    self.meta(scope, &e.key, *h).is_some_and(|m| {
                        m.tags.iter().any(|t| t == tag) && Self::readable(scope, m, readable)
                    })
                })
            })
            .map(|e| e.key.clone())
            .collect();
        keys.sort();
        keys.truncate(max);
        keys
    }
}

/// The SHA-256 a version of `content` carries.
pub fn hash(content: &[u8]) -> [u8; 32] {
    sha256(&[content])
}

/// The largest version record, for buffers.
pub const MAX_RECORD: usize = k::MAX_RECORD;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use pharos_proto::knowledge::{Author, List, Source, encode_version};

    #[derive(Default)]
    struct Mem {
        files: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl Files for Mem {
        fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
            self.files.insert(path.to_vec(), bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed> {
            Ok(self.files.get(path).cloned())
        }
        fn delete(&mut self, path: &[u8]) -> Result<(), StoreFailed> {
            self.files.remove(path);
            Ok(())
        }
        fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed> {
            Ok(self
                .files
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    const ALL: &[&[u8]] = &[
        b"notes", b"ops", b"hr", b"s1", b"s2", b"s3", b"s4", b"s5", b"s6", b"s7", b"s8",
    ];

    /// Plans, stores, and indexes one version; its number.
    #[derive(Default)]
    struct T {
        ix: Index,
        f: Mem,
    }

    impl T {
        fn put(
            &mut self,
            scope: &[u8],
            key: &[u8],
            kind: Kind,
            replaces: u32,
            evidence: &[Ref<'_>],
            content: &[u8],
        ) -> Result<u32, Refused> {
            let p = self
                .ix
                .plan(scope, key, replaces, evidence.iter().copied(), ALL)?;
            let scopes: Vec<&[u8]> = p.evidence_scopes.iter().map(Vec::as_slice).collect();
            let v = Version {
                scope,
                key,
                version: p.version,
                kind,
                replaces,
                author: Author::Agent {
                    name: b"worker",
                    task: 1,
                },
                source: Source::Written,
                boot: 1,
                uptime: 0,
                hash: hash(content),
                tags: List::new(&[&b"plan"[..]]).unwrap(),
                evidence: List::new(evidence).unwrap(),
                evidence_scopes: List::new(&scopes).unwrap(),
                content,
            };
            let mut out = alloc::vec![0u8; MAX_RECORD];
            let n = encode_version(&v, &mut out).unwrap();
            self.f
                .write(&path(scope, key, p.version, false), &out[..n])
                .unwrap();
            assert!(self.ix.insert(&v));
            Ok(p.version)
        }
    }

    fn r<'a>(scope: &'a [u8], key: &'a [u8], version: u32) -> Ref<'a> {
        Ref {
            scope,
            key,
            version,
        }
    }

    #[test]
    fn paths_round_trip() {
        assert_eq!(path(b"notes", b"release", 12, false), b"notes/release/v12");
        assert_eq!(path(b"n", b"k", u32::MAX, true), b"n/k/m4294967295");
        for p in [
            &b"n/k/v0"[..],
            b"n/k/v01",
            b"n/k/x1",
            b"n/k/v",
            b"n/k/v1/x",
            b"n/k",
            b"n/k/v4294967296",
        ] {
            assert_eq!(split(p), None, "{:?}", core::str::from_utf8(p));
        }
        assert_eq!(split(b"n/k/m7"), Some((&b"n"[..], &b"k"[..], 7, true)));
    }

    #[test]
    fn corrections_retractions_and_conflicts() {
        let mut t = T::default();
        let claim = |t: &mut T, rep| t.put(b"notes", b"k", Kind::Claim, rep, &[], b"x");
        assert_eq!(claim(&mut t, 0), Ok(1));
        assert_eq!(claim(&mut t, 0), Err(Refused::Replaces), "the key exists");
        assert_eq!(claim(&mut t, 5), Err(Refused::Replaces), "no version 5");
        assert_eq!(
            t.put(b"notes", b"new", Kind::Claim, 1, &[], b"x"),
            Err(Refused::Replaces),
            "a first version replaces nothing"
        );
        assert_eq!(t.ix.status(b"notes", b"k", 1), Some(0));
        assert_eq!(claim(&mut t, 1), Ok(2));
        let s = flag::SUPERSEDED | flag::STALE;
        assert_eq!(t.ix.status(b"notes", b"k", 1), Some(s), "corrected");
        assert_eq!(t.ix.heads(b"notes", b"k"), [2]);
        // A second writer corrects version 1 too, unaware of 2.
        assert_eq!(claim(&mut t, 1), Ok(3));
        assert_eq!(t.ix.heads(b"notes", b"k"), [2, 3]);
        assert_eq!(t.ix.status(b"notes", b"k", 2), Some(flag::CONFLICTING));
        assert_eq!(t.ix.status(b"notes", b"k", 3), Some(flag::CONFLICTING));
        assert_eq!(t.ix.status(b"notes", b"k", 1), Some(s), "not a head");
        // Retracting one side ends the conflict; the retracted one says so.
        assert_eq!(t.put(b"notes", b"k", Kind::Retraction, 3, &[], b""), Ok(4));
        assert_eq!(t.ix.heads(b"notes", b"k"), [2, 4]);
        assert_eq!(t.ix.status(b"notes", b"k", 2), Some(0));
        assert_eq!(t.ix.status(b"notes", b"k", 3), Some(s | flag::RETRACTED));
        assert_eq!(t.ix.status(b"notes", b"k", 4), Some(0));
        assert_eq!(t.ix.status(b"notes", b"k", 9), None);
        // Nothing earlier changed: every version is still there.
        assert!((1..=4).all(|v| t.ix.meta(b"notes", b"k", v).is_some()));
    }

    #[test]
    fn stale_through_evidence() {
        let mut t = T::default();
        t.put(b"ops", b"fact", Kind::Claim, 0, &[], b"f").unwrap();
        let cite = [r(b"ops", b"fact", 1)];
        t.put(b"notes", b"plan", Kind::Claim, 0, &cite, b"p")
            .unwrap();
        assert_eq!(t.ix.status(b"notes", b"plan", 1), Some(0));
        assert_eq!(
            t.ix.meta(b"notes", b"plan", 1).unwrap().evidence_scopes,
            [b"ops".to_vec()]
        );
        t.put(b"ops", b"fact", Kind::Claim, 1, &[], b"g").unwrap();
        assert_eq!(
            t.ix.status(b"notes", b"plan", 1),
            Some(flag::STALE),
            "its evidence changed"
        );
        assert_eq!(
            t.put(
                b"notes",
                b"plan2",
                Kind::Claim,
                0,
                &[r(b"ops", b"fact", 9)],
                b"p"
            ),
            Err(Refused::NotFound),
            "evidence that does not exist"
        );
    }

    #[test]
    fn evidence_scopes_follow_the_chain_and_are_bounded() {
        let mut t = T::default();
        // s1..s8 each cite the previous; s8's version reaches 7 others.
        t.put(b"s1", b"k", Kind::Claim, 0, &[], b"1").unwrap();
        let scopes: [&[u8]; 8] = [b"s1", b"s2", b"s3", b"s4", b"s5", b"s6", b"s7", b"s8"];
        for w in scopes.windows(2) {
            t.put(w[1], b"k", Kind::Claim, 0, &[r(w[0], b"k", 1)], b"n")
                .unwrap();
        }
        let m = t.ix.meta(b"s8", b"k", 1).unwrap();
        assert_eq!(m.evidence_scopes.len(), 7);
        assert!(
            !Index::readable(b"s8", m, &[b"s8", b"s7"]),
            "the whole chain"
        );
        assert!(Index::readable(b"s8", m, &scopes));
        // From notes, citing s8 reaches 8 other scopes: allowed; one more
        // through ops is a ninth.
        t.put(b"ops", b"k", Kind::Claim, 0, &[], b"o").unwrap();
        assert!(
            t.ix.plan(b"notes", b"k", 0, [r(b"s8", b"k", 1)], ALL)
                .is_ok()
        );
        assert_eq!(
            t.ix.plan(
                b"notes",
                b"k",
                0,
                [r(b"s8", b"k", 1), r(b"ops", b"k", 1)],
                ALL
            ),
            Err(Refused::Full)
        );
        // Evidence the writer cannot read is as if it did not exist.
        assert_eq!(
            t.ix.plan(b"notes", b"k", 0, [r(b"s8", b"k", 1)], &[b"notes", b"s8"]),
            Err(Refused::NotFound)
        );
    }

    #[test]
    fn verified_only_by_a_matching_mark() {
        let mut t = T::default();
        t.put(b"notes", b"k", Kind::Claim, 0, &[], b"text").unwrap();
        let h = hash(b"text");
        let prefix: [u8; 4] = h[..4].try_into().unwrap();
        assert_eq!(
            t.ix.plan_mark(b"notes", b"k", 1, [0; 4]),
            Err(Refused::HashDiffers)
        );
        assert_eq!(
            t.ix.plan_mark(b"notes", b"k", 2, prefix),
            Err(Refused::NotFound)
        );
        assert_eq!(t.ix.plan_mark(b"notes", b"k", 1, prefix), Ok(h));
        assert_eq!(t.ix.status(b"notes", b"k", 1), Some(0), "not until stored");
        t.ix.marked(b"notes", b"k", 1, h);
        assert_eq!(t.ix.status(b"notes", b"k", 1), Some(flag::VERIFIED));
        let other = [1u8; 32];
        t.ix.marked(b"notes", b"k", 1, other);
        assert_eq!(
            t.ix.status(b"notes", b"k", 1),
            Some(0),
            "a mark for other bytes"
        );
    }

    #[test]
    fn queries_see_only_readable_heads() {
        let mut t = T::default();
        t.put(b"hr", b"salary", Kind::Claim, 0, &[], b"s").unwrap();
        t.put(b"notes", b"b", Kind::Claim, 0, &[], b"b").unwrap();
        t.put(
            b"notes",
            b"a",
            Kind::Claim,
            0,
            &[r(b"hr", b"salary", 1)],
            b"a",
        )
        .unwrap();
        assert_eq!(
            t.ix.tagged(b"notes", b"plan", ALL, 16),
            [b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(
            t.ix.tagged(b"notes", b"plan", ALL, 1),
            [b"a".to_vec()],
            "at most max"
        );
        assert_eq!(
            t.ix.tagged(b"notes", b"plan", &[b"notes"], 16),
            [b"b".to_vec()],
            "a cites hr, which it cannot read"
        );
        assert_eq!(
            t.ix.tagged(b"notes", b"other", ALL, 16),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            t.ix.tagged(b"hr", b"plan", &[b"notes"], 16),
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn limits() {
        let mut t = T::default();
        for v in 0..MAX_VERSIONS as u32 {
            // Each corrects the one before: 64 versions, numbered 1 to 64.
            t.put(b"notes", b"k", Kind::Claim, v, &[], b"x").unwrap();
        }
        assert_eq!(
            t.put(b"notes", b"k", Kind::Claim, 64, &[], b"x"),
            Err(Refused::Full)
        );
        for i in 1..MAX_KEYS {
            let key = alloc::format!("k{i}").into_bytes();
            t.put(b"notes", &key, Kind::Claim, 0, &[], b"x").unwrap();
        }
        assert_eq!(
            t.put(b"notes", b"one-more", Kind::Claim, 0, &[], b"x"),
            Err(Refused::Full)
        );
        assert!(
            t.put(b"ops", b"one-more", Kind::Claim, 0, &[], b"x")
                .is_ok(),
            "per scope"
        );
    }

    #[test]
    fn rebuilt_from_the_store() {
        let mut t = T::default();
        t.put(b"ops", b"fact", Kind::Claim, 0, &[], b"f").unwrap();
        t.put(
            b"notes",
            b"k",
            Kind::Claim,
            0,
            &[r(b"ops", b"fact", 1)],
            b"x",
        )
        .unwrap();
        t.put(b"notes", b"k", Kind::Claim, 1, &[], b"y").unwrap();
        let h = hash(b"y");
        let mark = Mark {
            version: 2,
            hash: h,
            boot: 1,
            uptime: 5,
        };
        t.f.write(&path(b"notes", b"k", 2, true), &mark.encode())
            .unwrap();
        let (again, loaded) = Index::load(&mut t.f).unwrap();
        assert_eq!(
            loaded,
            Loaded {
                versions: 3,
                marks: 1,
                unreadable: 0
            }
        );
        for (s, k, v) in [
            (&b"ops"[..], &b"fact"[..], 1),
            (b"notes", b"k", 1),
            (b"notes", b"k", 2),
        ] {
            assert_eq!(
                again.meta(s, k, v).map(|m| m.hash),
                t.ix.meta(s, k, v).map(|m| m.hash)
            );
        }
        assert_eq!(again.status(b"notes", b"k", 2), Some(flag::VERIFIED));
        // Bad files are counted and not used.
        let good =
            t.f.files
                .get(&path(b"notes", b"k", 1, false)[..])
                .unwrap()
                .clone();
        let mut tampered = good.clone();
        *tampered.last_mut().unwrap() ^= 1;
        t.f.write(b"notes/k/v1", &tampered).unwrap();
        t.f.write(b"notes/other/v1", &good).unwrap();
        t.f.write(b"notes/k/m9", &mark.encode()).unwrap();
        t.f.write(b"stray", b"x").unwrap();
        let (again, loaded) = Index::load(&mut t.f).unwrap();
        assert_eq!(
            loaded,
            Loaded {
                versions: 2,
                marks: 1,
                unreadable: 4
            },
            "a changed byte, a version at another path, a mark of no version, a stray file"
        );
        assert_eq!(again.meta(b"notes", b"k", 1), None);
        assert_eq!(again.status(b"notes", b"k", 2), Some(flag::VERIFIED));
    }

    #[test]
    fn any_subset_of_files_loads_without_panicking() {
        let mut t = T::default();
        t.put(b"ops", b"fact", Kind::Claim, 0, &[], b"f").unwrap();
        t.put(
            b"notes",
            b"k",
            Kind::Claim,
            0,
            &[r(b"ops", b"fact", 1)],
            b"x",
        )
        .unwrap();
        t.put(b"notes", b"k", Kind::Claim, 1, &[], b"y").unwrap();
        t.put(b"notes", b"k", Kind::Retraction, 2, &[], b"")
            .unwrap();
        let all: Vec<(Vec<u8>, Vec<u8>)> = t.f.files.clone().into_iter().collect();
        for keep in 0u32..1 << all.len() {
            let mut g = Mem::default();
            for (i, (p, b)) in all.iter().enumerate() {
                if keep & 1 << i != 0 {
                    g.write(p, b).unwrap();
                }
            }
            let (again, loaded) = Index::load(&mut g).unwrap();
            // Every file is used or counted; a version kept says it is
            // stale if its evidence is gone.
            assert_eq!(loaded.versions, keep.count_ones() as usize);
            assert_eq!(loaded.unreadable, 0);
            // Files in name order: notes/k/v1, v2, v3, then ops/fact/v1.
            if keep & 8 == 0 {
                if let Some(s) = again.status(b"notes", b"k", 1) {
                    assert!(s & flag::STALE != 0, "evidence missing");
                }
            }
        }
    }
}
