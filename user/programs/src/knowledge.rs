//! The knowledge service's index (#142, knowledge.md, D-025): every
//! stored version's metadata, rebuilt from the store at start, and the
//! rules derived from it. A version is one store file, `<scope>/<key>/v<n>`,
//! and the user's mark on it is another, `<scope>/<key>/m<n>`; both are
//! written once. Status (superseded, retracted, stale, verified,
//! conflicting) is derived here, never stored.

use crate::tasks::{Files, StoreFailed};
use alloc::vec::Vec;
use pharos_proto::knowledge::{
    self as k, Author, Kind, List, MAX_EVIDENCE_SCOPES, MAX_HEADS, MAX_PAGE, Mark, Put, Ref,
    Request, SCOPES, Source, Summary, Version, client, code, encode_version, flag, parse_version,
};
use pharos_proto::{Info, Writer, status};
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
    /// The agent and task that wrote it; `None` for the user.
    pub author: Option<(Vec<u8>, u32)>,
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
            if name == STARTS {
                continue;
            }
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
            author: match v.author {
                Author::Agent { name, task } => Some((name.to_vec(), task)),
                Author::User => None,
            },
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

/// The service's start counter, the `boot` in each version's time.
pub const STARTS: &[u8] = b"starts";

/// The names of the scopes in `mask`, a bit each.
pub fn readable(mask: u8) -> Vec<&'static [u8]> {
    SCOPES
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & 1 << i != 0)
        .map(|(_, s)| *s)
        .collect()
}

/// A reply: the message, and what goes into the caller's buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub reply: Vec<u8>,
    pub buffer: Vec<u8>,
}

fn only(code: u8) -> Answer {
    Answer {
        reply: alloc::vec![code],
        buffer: Vec::new(),
    }
}

fn refused(r: Refused) -> Answer {
    only(match r {
        Refused::NotFound => status::NOT_FOUND,
        Refused::Replaces => code::REPLACES,
        Refused::Full => code::FULL,
        Refused::HashDiffers => code::HASH_DIFFERS,
    })
}

/// The knowledge service's logic over its store (#143): the program
/// around it only receives requests, copies the buffer, and replies.
pub struct Service {
    pub index: Index,
    /// This start's number (the `boot` of what it writes).
    pub starts: u32,
}

impl Service {
    /// Counts this start and rebuilds the index.
    pub fn start(f: &mut impl Files) -> Result<(Self, Loaded), StoreFailed> {
        let last = f
            .read(STARTS)?
            .and_then(|b| b.get(..4).and_then(|b| b.try_into().ok()))
            .map_or(0, u32::from_le_bytes);
        let starts = last.wrapping_add(1);
        f.write(STARTS, &starts.to_le_bytes())?;
        let (index, loaded) = Index::load(f)?;
        Ok((Self { index, starts }, loaded))
    }

    /// True if `badge` may make `req`: puts and reads for the runtime, marks
    /// for `trust`.
    pub fn allowed(badge: u32, req: &Request<'_>) -> bool {
        match req {
            Request::Verify { .. } => badge == client::TRUST,
            Request::Info | Request::Attach { .. } => true,
            _ => badge == client::RUNTIME,
        }
    }

    /// One request from `badge`; `input` is a copy of the caller's buffer
    /// (only `PUT` reads it), and `now` the time in microseconds.
    pub fn handle(
        &mut self,
        f: &mut impl Files,
        badge: u32,
        req: Request<'_>,
        input: &[u8],
        now: u64,
    ) -> Answer {
        if !Self::allowed(badge, &req) {
            return only(status::NO_ACCESS);
        }
        match req {
            Request::Put { len } => match input.get(..usize::from(len)).and_then(Put::parse) {
                Some(p) => self.put(f, &p, now),
                None => only(status::BAD_REQUEST),
            },
            Request::Get {
                scope,
                key,
                version,
                readable: mask,
            } => self.get(f, SCOPES[usize::from(scope)], key, version, &readable(mask)),
            Request::History {
                scope,
                key,
                from,
                readable: mask,
            } => self.history(SCOPES[usize::from(scope)], key, from, &readable(mask)),
            Request::Query {
                scope,
                tag,
                start,
                readable: mask,
            } => {
                let start = usize::from(start);
                let mut keys = self.index.tagged(
                    SCOPES[usize::from(scope)],
                    tag,
                    &readable(mask),
                    start + MAX_PAGE + 1,
                );
                let more = keys.len() > start + MAX_PAGE;
                let mut buffer = Vec::new();
                let page: Vec<Vec<u8>> = keys.drain(..).skip(start).take(MAX_PAGE).collect();
                for k in &page {
                    buffer.push(k.len() as u8);
                    buffer.extend_from_slice(k);
                }
                Answer {
                    reply: alloc::vec![status::OK, page.len() as u8, u8::from(more)],
                    buffer,
                }
            }
            Request::Verify {
                scope,
                key,
                version,
                prefix,
            } => self.verify(f, SCOPES[usize::from(scope)], key, version, prefix, now),
            Request::Info => {
                let mut out = [0u8; 64];
                let details = [SCOPES.len() as u8];
                let n = Info {
                    name: k::NAME,
                    low: k::VERSION,
                    high: k::VERSION,
                    details: &details,
                }
                .encode(&mut out)
                .unwrap_or(0);
                Answer {
                    reply: out[..n].to_vec(),
                    buffer: Vec::new(),
                }
            }
            // The program maps the buffer itself.
            Request::Attach { .. } => only(status::BAD_REQUEST),
        }
    }

    fn put(&mut self, f: &mut impl Files, p: &Put<'_>, now: u64) -> Answer {
        // Only the host image writes as the user (D-025 item 4).
        if p.author == Author::User || p.source == Source::Host {
            return only(status::NO_ACCESS);
        }
        let scope = SCOPES[usize::from(p.scope)];
        let refs: Vec<Ref<'_>> = p
            .evidence
            .iter()
            .map(|(s, key, version)| Ref {
                scope: SCOPES[usize::from(s)],
                key,
                version,
            })
            .collect();
        // At most `MAX_EVIDENCE`, as `Put::parse` read them.
        let refs = List::new(&refs).unwrap_or_default();
        let planned =
            match self
                .index
                .plan(scope, p.key, p.replaces, refs.iter(), &readable(p.readable))
            {
                Ok(planned) => planned,
                Err(r) => return refused(r),
            };
        let scopes: Vec<&[u8]> = planned.evidence_scopes.iter().map(Vec::as_slice).collect();
        let v = Version {
            scope,
            key: p.key,
            version: planned.version,
            kind: p.kind,
            replaces: p.replaces,
            author: p.author,
            source: p.source,
            boot: u64::from(self.starts),
            uptime: now,
            hash: hash(p.content),
            tags: p.tags,
            evidence: refs,
            evidence_scopes: match List::new(&scopes) {
                Some(l) => l,
                None => return only(code::FULL),
            },
            content: p.content,
        };
        let mut out = alloc::vec![0u8; MAX_RECORD];
        let Some(n) = encode_version(&v, &mut out) else {
            return only(status::BAD_REQUEST);
        };
        if f.write(&path(scope, p.key, v.version, false), &out[..n])
            .is_err()
        {
            return only(code::UNWRITABLE);
        }
        self.index.insert(&v);
        let mut reply = alloc::vec![status::OK];
        reply.extend_from_slice(&v.version.to_le_bytes());
        Answer {
            reply,
            buffer: Vec::new(),
        }
    }

    fn get(
        &self,
        f: &mut impl Files,
        scope: &[u8],
        key: &[u8],
        version: u32,
        readable: &[&[u8]],
    ) -> Answer {
        let wanted = if version == 0 {
            self.index.heads(scope, key)
        } else {
            alloc::vec![version]
        };
        let visible: Vec<u32> = wanted
            .into_iter()
            .filter(|v| {
                self.index
                    .meta(scope, key, *v)
                    .is_some_and(|m| Index::readable(scope, m, readable))
            })
            .take(MAX_HEADS)
            .collect();
        if visible.is_empty() {
            return only(status::NOT_FOUND);
        }
        let mut buffer = Vec::new();
        for v in &visible {
            let Ok(Some(record)) = f.read(&path(scope, key, *v, false)) else {
                return only(code::UNWRITABLE);
            };
            buffer.push(self.index.status(scope, key, *v).unwrap_or(0));
            buffer.extend_from_slice(&(record.len() as u16).to_le_bytes());
            buffer.extend_from_slice(&record);
        }
        let mut reply = alloc::vec![status::OK, visible.len() as u8];
        reply.extend_from_slice(&(buffer.len() as u32).to_le_bytes());
        Answer { reply, buffer }
    }

    fn history(&self, scope: &[u8], key: &[u8], from: u32, readable: &[&[u8]]) -> Answer {
        let Some(e) = self.index.entry(scope, key) else {
            return only(status::NOT_FOUND);
        };
        let seen: Vec<&Meta> = e
            .versions
            .iter()
            .filter(|m| m.version >= from && Index::readable(scope, m, readable))
            .collect();
        if seen.is_empty()
            && !e
                .versions
                .iter()
                .any(|m| Index::readable(scope, m, readable))
        {
            return only(status::NOT_FOUND);
        }
        let mut out = alloc::vec![0u8; MAX_PAGE * 64];
        let mut w = Writer::new(&mut out);
        for m in seen.iter().take(MAX_PAGE) {
            let author = match &m.author {
                Some((name, task)) => Author::Agent { name, task: *task },
                None => Author::User,
            };
            let s = Summary {
                version: m.version,
                kind: m.kind,
                replaces: m.replaces,
                status: self.index.status(scope, key, m.version).unwrap_or(0),
                author,
            };
            if s.write(&mut w).is_none() {
                return only(status::INTERNAL);
            }
        }
        let n = w.len();
        let count = seen.len().min(MAX_PAGE);
        Answer {
            reply: alloc::vec![status::OK, count as u8, u8::from(seen.len() > MAX_PAGE)],
            buffer: out[..n].to_vec(),
        }
    }

    fn verify(
        &mut self,
        f: &mut impl Files,
        scope: &[u8],
        key: &[u8],
        version: u32,
        prefix: [u8; 4],
        now: u64,
    ) -> Answer {
        let hash = match self.index.plan_mark(scope, key, version, prefix) {
            Ok(h) => h,
            Err(r) => return refused(r),
        };
        let Some(m) = self.index.meta(scope, key, version) else {
            return only(status::NOT_FOUND);
        };
        let author = m.author.clone();
        // Written once: a second mark of the same bytes changes nothing.
        if m.marked != Some(hash) {
            let mark = Mark {
                version,
                hash,
                boot: u64::from(self.starts),
                uptime: now,
            };
            if f.write(&path(scope, key, version, true), &mark.encode())
                .is_err()
            {
                return only(code::UNWRITABLE);
            }
            self.index.marked(scope, key, version, hash);
        }
        let mut out = [0u8; 64];
        let a = match &author {
            Some((name, task)) => Author::Agent { name, task: *task },
            None => Author::User,
        };
        let n = k::encode_author(a, &mut out).unwrap_or(0);
        let mut reply = alloc::vec![status::OK];
        reply.extend_from_slice(&out[..n]);
        Answer {
            reply,
            buffer: Vec::new(),
        }
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
        /// Every write fails while set.
        broken: bool,
    }

    impl Files for Mem {
        fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
            if self.broken {
                return Err(StoreFailed);
            }
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

    const NOTES: u8 = 0;
    const OPS: u8 = 1;
    const HR: u8 = 2;
    /// notes, ops, and hr.
    const READ_ALL: u8 = 0b111;

    fn put_req<'a>(scope: u8, key: &'a [u8], replaces: u32, content: &'a [u8]) -> Put<'a> {
        Put {
            scope,
            key,
            kind: Kind::Claim,
            replaces,
            author: Author::Agent {
                name: b"worker",
                task: 4,
            },
            source: Source::Written,
            readable: READ_ALL,
            tags: List::new(&[&b"plan"[..]]).unwrap(),
            evidence: List::default(),
            content,
        }
    }

    fn send(s: &mut Service, f: &mut Mem, badge: u32, p: &Put<'_>) -> Vec<u8> {
        let mut input = alloc::vec![0u8; MAX_RECORD];
        let n = p.encode(&mut input).unwrap();
        let req = Request::Put { len: n as u16 };
        s.handle(f, badge, req, &input, 77).reply
    }

    fn ok_version(v: u32) -> Vec<u8> {
        let mut r = alloc::vec![status::OK];
        r.extend_from_slice(&v.to_le_bytes());
        r
    }

    fn get(s: &mut Service, f: &mut Mem, scope: u8, key: &[u8], version: u32, mask: u8) -> Answer {
        let req = Request::Get {
            scope,
            key,
            version,
            readable: mask,
        };
        s.handle(f, client::RUNTIME, req, &[], 0)
    }

    /// The (status, record) pairs in a `GET` answer's buffer.
    fn records(a: &Answer) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut b = &a.buffer[..];
        while let [status, l0, l1, rest @ ..] = b {
            let n = usize::from(u16::from_le_bytes([*l0, *l1]));
            out.push((*status, rest[..n].to_vec()));
            b = &rest[n..];
        }
        assert_eq!(usize::from(a.reply[1]), out.len());
        out
    }

    #[test]
    fn the_service_puts_reads_and_marks() {
        let mut f = Mem::default();
        let (mut s, loaded) = Service::start(&mut f).unwrap();
        assert_eq!((s.starts, loaded), (1, Loaded::default()));
        let p = put_req(NOTES, b"release", 0, b"ship friday");
        assert_eq!(
            send(&mut s, &mut f, client::TRUST, &p),
            [status::NO_ACCESS],
            "not trust"
        );
        let as_user = Put {
            author: Author::User,
            ..p
        };
        assert_eq!(
            send(&mut s, &mut f, client::RUNTIME, &as_user),
            [status::NO_ACCESS]
        );
        let as_host = Put {
            source: Source::Host,
            ..p
        };
        assert_eq!(
            send(&mut s, &mut f, client::RUNTIME, &as_host),
            [status::NO_ACCESS]
        );
        assert_eq!(send(&mut s, &mut f, client::RUNTIME, &p), ok_version(1));
        assert_eq!(
            s.handle(&mut f, client::RUNTIME, Request::Put { len: 3 }, b"bad", 0)
                .reply,
            [status::BAD_REQUEST]
        );
        // The record carries what the service set, not the caller.
        let a = get(&mut s, &mut f, NOTES, b"release", 0, READ_ALL);
        let r = records(&a);
        let v = parse_version(&r[0].1).unwrap();
        assert_eq!(
            (r[0].0, v.version, v.boot, v.uptime, v.hash, v.content),
            (0, 1, 1, 77, hash(b"ship friday"), &b"ship friday"[..])
        );
        assert_eq!(v.author, p.author);
        // A correction, and a stale reader of version 1.
        let fix = put_req(NOTES, b"release", 1, b"ship monday");
        assert_eq!(send(&mut s, &mut f, client::RUNTIME, &fix), ok_version(2));
        let a = get(&mut s, &mut f, NOTES, b"release", 1, READ_ALL);
        assert_eq!(records(&a)[0].0, flag::SUPERSEDED | flag::STALE);
        let a = get(&mut s, &mut f, NOTES, b"release", 0, READ_ALL);
        assert_eq!(
            parse_version(&records(&a)[0].1).unwrap().version,
            2,
            "the head"
        );
        assert_eq!(
            get(&mut s, &mut f, NOTES, b"nothing", 0, READ_ALL).reply,
            [status::NOT_FOUND]
        );
        // Verified only by trust, with the right prefix, once.
        let h = hash(b"ship monday");
        let verify = |prefix: [u8; 4]| Request::Verify {
            scope: NOTES,
            key: b"release",
            version: 2,
            prefix,
        };
        let right: [u8; 4] = h[..4].try_into().unwrap();
        assert_eq!(
            s.handle(&mut f, client::RUNTIME, verify(right), &[], 0)
                .reply,
            [status::NO_ACCESS]
        );
        assert_eq!(
            s.handle(&mut f, client::TRUST, verify([0; 4]), &[], 0)
                .reply,
            [code::HASH_DIFFERS]
        );
        let mut author = [0u8; 64];
        let n = k::encode_author(p.author, &mut author).unwrap();
        let mut want = alloc::vec![status::OK];
        want.extend_from_slice(&author[..n]);
        assert_eq!(
            s.handle(&mut f, client::TRUST, verify(right), &[], 5).reply,
            want
        );
        let marks = f.files.len();
        assert_eq!(
            s.handle(&mut f, client::TRUST, verify(right), &[], 6).reply,
            want
        );
        assert_eq!(f.files.len(), marks, "the mark is written once");
        let a = get(&mut s, &mut f, NOTES, b"release", 2, READ_ALL);
        assert_eq!(records(&a)[0].0, flag::VERIFIED);
        // A query, and the history.
        let q = Request::Query {
            scope: NOTES,
            tag: b"plan",
            start: 0,
            readable: READ_ALL,
        };
        let a = s.handle(&mut f, client::RUNTIME, q, &[], 0);
        assert_eq!(
            (a.reply, a.buffer),
            (alloc::vec![status::OK, 1, 0], b"\x07release".to_vec())
        );
        let hist = Request::History {
            scope: NOTES,
            key: b"release",
            from: 1,
            readable: READ_ALL,
        };
        let a = s.handle(&mut f, client::RUNTIME, hist, &[], 0);
        assert_eq!(a.reply, [status::OK, 2, 0]);
        let mut r = pharos_proto::Reader::new(&a.buffer);
        let first = Summary::read(&mut r).unwrap();
        let second = Summary::read(&mut r).unwrap();
        assert_eq!(
            (first.version, first.status),
            (1, flag::SUPERSEDED | flag::STALE)
        );
        assert_eq!(
            (second.version, second.replaces, second.status),
            (2, 1, flag::VERIFIED)
        );
        assert!(r.is_empty());
        // Everything survives a restart.
        let (mut again, loaded) = Service::start(&mut f).unwrap();
        assert_eq!(
            (again.starts, loaded),
            (
                2,
                Loaded {
                    versions: 2,
                    marks: 1,
                    unreadable: 0
                }
            )
        );
        let a = get(&mut again, &mut f, NOTES, b"release", 2, READ_ALL);
        assert_eq!(records(&a)[0].0, flag::VERIFIED);
        let next = put_req(NOTES, b"release", 2, b"ship tuesday");
        assert_eq!(
            send(&mut again, &mut f, client::RUNTIME, &next),
            ok_version(3)
        );
        let a = get(&mut again, &mut f, NOTES, b"release", 3, READ_ALL);
        assert_eq!(
            parse_version(&records(&a)[0].1).unwrap().boot,
            2,
            "this start"
        );
    }

    #[test]
    fn what_the_caller_cannot_read_does_not_exist() {
        let mut f = Mem::default();
        let (mut s, _) = Service::start(&mut f).unwrap();
        let salary = put_req(HR, b"salary", 0, b"secret");
        assert_eq!(
            send(&mut s, &mut f, client::RUNTIME, &salary),
            ok_version(1)
        );
        let cites = Put {
            evidence: List::new(&[(HR, &b"salary"[..], 1)]).unwrap(),
            ..put_req(NOTES, b"budget", 0, b"derived")
        };
        assert_eq!(send(&mut s, &mut f, client::RUNTIME, &cites), ok_version(1));
        let plain = put_req(NOTES, b"plain", 0, b"open");
        assert_eq!(send(&mut s, &mut f, client::RUNTIME, &plain), ok_version(1));
        let notes = 1 << NOTES;
        let missing = get(&mut s, &mut f, NOTES, b"nothing", 0, notes);
        for (scope, key) in [(HR, &b"salary"[..]), (NOTES, b"budget")] {
            for version in [0, 1] {
                assert_eq!(get(&mut s, &mut f, scope, key, version, notes), missing);
            }
            let hist = Request::History {
                scope,
                key,
                from: 1,
                readable: notes,
            };
            assert_eq!(s.handle(&mut f, client::RUNTIME, hist, &[], 0), missing);
        }
        let q = Request::Query {
            scope: NOTES,
            tag: b"plan",
            start: 0,
            readable: notes,
        };
        let a = s.handle(&mut f, client::RUNTIME, q, &[], 0);
        assert_eq!(a.buffer, b"\x05plain", "budget left out");
        // A writer who cannot read the evidence cannot cite it.
        let blind = Put {
            readable: notes,
            key: b"other",
            ..cites
        };
        assert_eq!(
            send(&mut s, &mut f, client::RUNTIME, &blind),
            [status::NOT_FOUND]
        );
        assert_eq!(
            get(&mut s, &mut f, NOTES, b"budget", 0, READ_ALL).reply[0],
            status::OK
        );
    }

    #[test]
    fn a_failed_write_changes_nothing() {
        let mut f = Mem::default();
        let (mut s, _) = Service::start(&mut f).unwrap();
        let p = put_req(OPS, b"k", 0, b"x");
        f.broken = true;
        assert_eq!(
            send(&mut s, &mut f, client::RUNTIME, &p),
            [code::UNWRITABLE]
        );
        f.broken = false;
        assert_eq!(
            get(&mut s, &mut f, OPS, b"k", 0, READ_ALL).reply,
            [status::NOT_FOUND]
        );
        assert_eq!(
            send(&mut s, &mut f, client::RUNTIME, &p),
            ok_version(1),
            "the same number"
        );
        let right: [u8; 4] = hash(b"x")[..4].try_into().unwrap();
        let verify = Request::Verify {
            scope: OPS,
            key: b"k",
            version: 1,
            prefix: right,
        };
        f.broken = true;
        assert_eq!(
            s.handle(&mut f, client::TRUST, verify, &[], 0).reply,
            [code::UNWRITABLE]
        );
        f.broken = false;
        assert_eq!(
            records(&get(&mut s, &mut f, OPS, b"k", 1, READ_ALL))[0].0,
            0,
            "not verified"
        );
        let mut broken = Mem {
            broken: true,
            ..Mem::default()
        };
        assert!(Service::start(&mut broken).is_err());
    }

    #[test]
    fn pages_of_history_and_queries() {
        let mut f = Mem::default();
        let (mut s, _) = Service::start(&mut f).unwrap();
        for v in 0..20 {
            assert_eq!(
                send(
                    &mut s,
                    &mut f,
                    client::RUNTIME,
                    &put_req(NOTES, b"k", v, b"x")
                ),
                ok_version(v + 1)
            );
        }
        let hist = |from| Request::History {
            scope: NOTES,
            key: b"k",
            from,
            readable: READ_ALL,
        };
        assert_eq!(
            s.handle(&mut f, client::RUNTIME, hist(1), &[], 0).reply,
            [status::OK, 16, 1]
        );
        assert_eq!(
            s.handle(&mut f, client::RUNTIME, hist(17), &[], 0).reply,
            [status::OK, 4, 0]
        );
        for i in 0..20 {
            let key = alloc::format!("q{i:02}").into_bytes();
            send(
                &mut s,
                &mut f,
                client::RUNTIME,
                &put_req(OPS, &key, 0, b"x"),
            );
        }
        let q = |start| Request::Query {
            scope: OPS,
            tag: b"plan",
            start,
            readable: READ_ALL,
        };
        let a = s.handle(&mut f, client::RUNTIME, q(0), &[], 0);
        assert_eq!(a.reply, [status::OK, 16, 1]);
        assert!(a.buffer.starts_with(b"\x03q00\x03q01"));
        let a = s.handle(&mut f, client::RUNTIME, q(16), &[], 0);
        assert_eq!(
            (a.reply, a.buffer),
            (
                alloc::vec![status::OK, 4, 0],
                b"\x03q16\x03q17\x03q18\x03q19".to_vec()
            )
        );
        // At most 4 heads come back from one `GET`.
        for _ in 0..5 {
            send(
                &mut s,
                &mut f,
                client::RUNTIME,
                &put_req(NOTES, b"k", 20, b"y"),
            );
        }
        assert_eq!(s.index.heads(b"notes", b"k").len(), 5);
        let a = get(&mut s, &mut f, NOTES, b"k", 0, READ_ALL);
        let r = records(&a);
        assert_eq!(r.len(), MAX_HEADS);
        assert!(r.iter().all(|(st, _)| st & flag::CONFLICTING != 0));
        assert!(a.buffer.len() as u64 <= k::MIN_BUFFER);
    }
}
