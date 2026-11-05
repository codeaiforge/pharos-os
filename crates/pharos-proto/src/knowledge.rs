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
//!
//! The service's interface, version 1 (#143), `[version, op, …]`, by
//! badge: [`client::RUNTIME`] puts and reads for agents, [`client::TRUST`]
//! marks versions verified for the user. A scope is named by its number in
//! [`SCOPES`], and a caller's readable scopes by a bit each. Bulk data goes
//! through the caller's attached buffer (`ATTACH`, at least
//! [`MIN_BUFFER`]), copied out before it is read:
//! - `PUT` `[v, op, length (2)]`: a [`Put`] at the buffer's start; replies
//!   `[OK, version (4)]`;
//! - `GET` `[v, op, scope, key, version (4), readable]` (version 0: the
//!   heads, at most [`MAX_HEADS`]): replies `[OK, count, length (4)]`, and
//!   the buffer holds, for each, `[status, record length (2), record]`;
//! - `HISTORY` `[v, op, scope, key, from (4), readable]`: replies `[OK,
//!   count, more]`, and the buffer holds up to [`MAX_PAGE`] [`Summary`]s
//!   from version `from`;
//! - `QUERY` `[v, op, scope, tag, start (2), readable]`: replies `[OK,
//!   count, more]`, and the buffer holds up to [`MAX_PAGE`] keys whose
//!   heads carry the tag, each a length byte and the key;
//! - `VERIFY` `[v, op, scope, key, version (4), hash prefix (4)]`: replies
//!   `[OK]` and the version's author (as in a record), from `trust` only.
//!
//! Anything the readable scopes do not reach, directly or through its
//! evidence, is answered as if it did not exist (`NOT_FOUND`, or left
//! out).

use crate::permission::valid_file;
use crate::trust::valid_name;
use crate::{Reader, Refused, Writer, split};

pub const NAME: &[u8] = b"knowledge";
pub const VERSION: u8 = 1;

/// The scopes, by number (reviewed code, like the store's namespaces).
pub const SCOPES: &[&[u8]] = &[b"notes", b"ops", b"hr", b"team", b"test"];

/// A scope's number.
pub fn scope_number(name: &[u8]) -> Option<u8> {
    SCOPES.iter().position(|s| *s == name).map(|i| i as u8)
}

/// Operation codes.
pub mod op {
    pub const PUT: u8 = 1;
    pub const GET: u8 = 2;
    pub const HISTORY: u8 = 3;
    pub const QUERY: u8 = 4;
    pub const VERIFY: u8 = 5;
}

/// Who calls, by badge.
pub mod client {
    pub const RUNTIME: u32 = 1;
    pub const TRUST: u32 = 2;
}

/// The service's own status codes.
pub mod code {
    /// A key, a scope's keys, or the evidence scopes are at their limit.
    pub const FULL: u8 = crate::status::OWN;
    /// A key's first version must replace nothing; a later one must name
    /// one of its versions.
    pub const REPLACES: u8 = crate::status::OWN + 1;
    /// The hash prefix does not match the version's content.
    pub const HASH_DIFFERS: u8 = crate::status::OWN + 2;
    /// The store did not take the write; nothing changed.
    pub const UNWRITABLE: u8 = crate::status::OWN + 3;
}

/// Most heads a `GET` returns, and items a `HISTORY` or `QUERY` page.
pub const MAX_HEADS: usize = 4;
pub const MAX_PAGE: usize = 16;
/// The smallest buffer a client attaches: room for `MAX_HEADS` records.
pub const MIN_BUFFER: u64 = 24 * 1024;

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

/// What a `PUT` asks for, at the buffer's start: `[scope, key, kind,
/// replaces (4), author, source, readable, tags, evidence (scope number,
/// key, version (4) each), content length (2), content]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Put<'a> {
    pub scope: u8,
    pub key: &'a [u8],
    pub kind: Kind,
    pub replaces: u32,
    pub author: Author<'a>,
    pub source: Source<'a>,
    /// The scopes the writer may read, a bit each: its evidence must be
    /// readable.
    pub readable: u8,
    pub tags: List<&'a [u8], MAX_TAGS>,
    pub evidence: List<(u8, &'a [u8], u32), MAX_EVIDENCE>,
    pub content: &'a [u8],
}

fn scope_ok(n: u8) -> bool {
    usize::from(n) < SCOPES.len()
}

fn read_author<'a>(r: &mut Reader<'a>) -> Option<Author<'a>> {
    match r.u8()? {
        1 => Some(Author::Agent {
            name: name(r).filter(|n| valid_name(n))?,
            task: r.u32()?,
        }),
        2 => Some(Author::User),
        _ => None,
    }
}

fn write_author(w: &mut Writer<'_>, a: Author<'_>) -> Option<()> {
    match a {
        Author::Agent { name, task } => {
            w.bytes(&[1])?;
            put_name(w, name)?;
            w.u32(task)
        }
        Author::User => w.bytes(&[2]),
    }
}

impl<'a> Put<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let scope = r.u8().filter(|s| scope_ok(*s))?;
        let key = name(&mut r).filter(|k| valid_name(k))?;
        let kind = match r.u8()? {
            1 => Kind::Claim,
            2 => Kind::Retraction,
            _ => return None,
        };
        let replaces = r.u32()?;
        let author = read_author(&mut r)?;
        let source = match r.u8()? {
            1 => Source::Written,
            2 => Source::Promoted(name(&mut r).filter(|f| valid_file(f))?),
            3 => Source::Host,
            _ => return None,
        };
        let readable = r.u8()?;
        let mut tags = List::default();
        for _ in 0..r.u8()? {
            tags.push(name(&mut r).filter(|t| valid_name(t))?)?;
        }
        let mut evidence = List::default();
        for _ in 0..r.u8()? {
            let s = r.u8().filter(|s| scope_ok(*s))?;
            let k = name(&mut r).filter(|k| valid_name(k))?;
            evidence.push((s, k, r.u32().filter(|v| *v >= 1)?))?;
        }
        let n = usize::from(r.u16()?);
        let content = r.take(n).filter(|c| c.len() <= MAX_CONTENT)?;
        let p = Self {
            scope,
            key,
            kind,
            replaces,
            author,
            source,
            readable,
            tags,
            evidence,
            content,
        };
        let retraction_ok = kind == Kind::Claim || (replaces >= 1 && content.is_empty());
        (r.is_empty() && retraction_ok && distinct(tags.iter()) && distinct(evidence.iter()))
            .then_some(p)
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[self.scope])?;
        put_name(&mut w, self.key)?;
        w.bytes(&[self.kind as u8])?;
        w.u32(self.replaces)?;
        write_author(&mut w, self.author)?;
        match self.source {
            Source::Written => w.bytes(&[1])?,
            Source::Promoted(f) => {
                w.bytes(&[2])?;
                put_name(&mut w, f)?;
            }
            Source::Host => w.bytes(&[3])?,
        }
        w.bytes(&[self.readable, self.tags.len() as u8])?;
        for t in self.tags.iter() {
            put_name(&mut w, t)?;
        }
        w.bytes(&[self.evidence.len() as u8])?;
        for (s, k, v) in self.evidence.iter() {
            w.bytes(&[s])?;
            put_name(&mut w, k)?;
            w.u32(v)?;
        }
        w.u16(u16::try_from(self.content.len()).ok()?)?;
        w.bytes(self.content)?;
        Some(w.len())
    }
}

/// One line of a `HISTORY` page: `[version (4), kind, replaces (4),
/// status, author]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary<'a> {
    pub version: u32,
    pub kind: Kind,
    pub replaces: u32,
    pub status: u8,
    pub author: Author<'a>,
}

impl<'a> Summary<'a> {
    pub fn read(r: &mut Reader<'a>) -> Option<Self> {
        Some(Self {
            version: r.u32()?,
            kind: match r.u8()? {
                1 => Kind::Claim,
                2 => Kind::Retraction,
                _ => return None,
            },
            replaces: r.u32()?,
            status: r.u8()?,
            author: read_author(r)?,
        })
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        w.u32(self.version)?;
        w.bytes(&[self.kind as u8])?;
        w.u32(self.replaces)?;
        w.bytes(&[self.status])?;
        write_author(w, self.author)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Put {
        len: u16,
    },
    Get {
        scope: u8,
        key: &'a [u8],
        version: u32,
        readable: u8,
    },
    History {
        scope: u8,
        key: &'a [u8],
        from: u32,
        readable: u8,
    },
    Query {
        scope: u8,
        tag: &'a [u8],
        start: u16,
        readable: u8,
    },
    Verify {
        scope: u8,
        key: &'a [u8],
        version: u32,
        prefix: [u8; 4],
    },
    /// A buffer of this many bytes (with a `Memory` capability).
    Attach {
        len: u64,
    },
    Info,
}

/// A scope number and a name, which four requests start with.
fn scope_key<'a>(r: &mut Reader<'a>) -> Option<(u8, &'a [u8])> {
    let s = r.u8().filter(|s| scope_ok(*s))?;
    Some((s, name(r).filter(|k| valid_name(k))?))
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = match code {
        op::PUT => r.u16().map(|len| Request::Put { len }),
        op::GET => (|| {
            let (scope, key) = scope_key(&mut r)?;
            Some(Request::Get {
                scope,
                key,
                version: r.u32()?,
                readable: r.u8()?,
            })
        })(),
        op::HISTORY => (|| {
            let (scope, key) = scope_key(&mut r)?;
            Some(Request::History {
                scope,
                key,
                from: r.u32()?,
                readable: r.u8()?,
            })
        })(),
        op::QUERY => (|| {
            let (scope, tag) = scope_key(&mut r)?;
            Some(Request::Query {
                scope,
                tag,
                start: r.u16()?,
                readable: r.u8()?,
            })
        })(),
        op::VERIFY => (|| {
            let (scope, key) = scope_key(&mut r)?;
            Some(Request::Verify {
                scope,
                key,
                version: r.u32().filter(|v| *v >= 1)?,
                prefix: r.take(4)?.try_into().ok()?,
            })
        })(),
        crate::op::ATTACH => r.u64().map(|len| Request::Attach { len }),
        crate::op::INFO => Some(Request::Info),
        _ => None,
    };
    match req {
        Some(req) if r.is_empty() => Ok(req),
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    let head = |w: &mut Writer<'_>, op: u8, scope: u8, n: &[u8]| -> Option<()> {
        if !scope_ok(scope) || !valid_name(n) {
            return None;
        }
        w.bytes(&[VERSION, op, scope])?;
        put_name(w, n)
    };
    match *req {
        Request::Put { len } => {
            w.bytes(&[VERSION, op::PUT])?;
            w.u16(len)?;
        }
        Request::Get {
            scope,
            key,
            version,
            readable,
        } => {
            head(&mut w, op::GET, scope, key)?;
            w.u32(version)?;
            w.bytes(&[readable])?;
        }
        Request::History {
            scope,
            key,
            from,
            readable,
        } => {
            head(&mut w, op::HISTORY, scope, key)?;
            w.u32(from)?;
            w.bytes(&[readable])?;
        }
        Request::Query {
            scope,
            tag,
            start,
            readable,
        } => {
            head(&mut w, op::QUERY, scope, tag)?;
            w.u16(start)?;
            w.bytes(&[readable])?;
        }
        Request::Verify {
            scope,
            key,
            version,
            prefix,
        } => {
            if version == 0 {
                return None;
            }
            head(&mut w, op::VERIFY, scope, key)?;
            w.u32(version)?;
            w.bytes(&prefix)?;
        }
        Request::Attach { len } => {
            w.bytes(&[VERSION, crate::op::ATTACH])?;
            w.u64(len)?;
        }
        Request::Info => w.bytes(&[VERSION, crate::op::INFO])?,
    }
    Some(w.len())
}

/// The longest `HISTORY` or `QUERY` page: [`MAX_PAGE`] summaries of an
/// agent author with a 32-byte name.
pub const MAX_PAGE_BYTES: usize = MAX_PAGE * (4 + 1 + 4 + 1 + 1 + 33 + 4);

/// The bytes of a `HISTORY` (`query` false) or `QUERY` page of `count`
/// items at the start of `b`; `None` if they do not parse.
pub fn page_len(b: &[u8], count: u8, query: bool) -> Option<usize> {
    let mut r = Reader::new(b);
    for _ in 0..count {
        if query {
            name(&mut r).filter(|k| valid_name(k))?;
        } else {
            Summary::read(&mut r)?;
        }
    }
    Some(b.len() - r.rest().len())
}

/// Reads the author a `VERIFY` reply carries after its status.
pub fn parse_author(b: &[u8]) -> Option<Author<'_>> {
    let mut r = Reader::new(b);
    let a = read_author(&mut r)?;
    r.is_empty().then_some(a)
}

/// Writes an author, as a `VERIFY` reply carries it.
pub fn encode_author(a: Author<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    write_author(&mut w, a)?;
    Some(w.len())
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

    #[test]
    fn requests_round_trip() {
        for req in [
            Request::Put { len: u16::MAX },
            Request::Get {
                scope: 0,
                key: LONG,
                version: 0,
                readable: 0xff,
            },
            Request::History {
                scope: 4,
                key: b"k",
                from: u32::MAX,
                readable: 1,
            },
            Request::Query {
                scope: 1,
                tag: LONG,
                start: u16::MAX,
                readable: 0,
            },
            Request::Verify {
                scope: 2,
                key: b"k",
                version: 1,
                prefix: [1, 2, 3, 4],
            },
            Request::Attach { len: MIN_BUFFER },
            Request::Info,
        ] {
            let mut out = [0u8; 256];
            let n = encode(&req, &mut out).unwrap();
            assert_eq!(parse(&out[..n]), Ok(req));
            assert_eq!(parse(&out[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
            for cut in 2..n {
                assert_eq!(
                    parse(&out[..cut]),
                    Err(Refused::Bad),
                    "{req:?} cut at {cut}"
                );
            }
            out[0] = VERSION + 1;
            assert_eq!(parse(&out[..n]), Err(Refused::Version));
        }
        let mut out = [0u8; 256];
        for bad in [
            Request::Get {
                scope: SCOPES.len() as u8,
                key: b"k",
                version: 0,
                readable: 0,
            },
            Request::Query {
                scope: 0,
                tag: b"a b",
                start: 0,
                readable: 0,
            },
            Request::Verify {
                scope: 0,
                key: b"k",
                version: 0,
                prefix: [0; 4],
            },
        ] {
            assert_eq!(encode(&bad, &mut out), None, "{bad:?}");
        }
        assert_eq!(parse(&[VERSION, 9]), Err(Refused::Bad), "unknown op");
        assert_eq!(scope_number(b"notes"), Some(0));
        assert_eq!(scope_number(b"test"), Some(4));
        assert_eq!(scope_number(b"nope"), None);
        assert!(SCOPES.len() <= 8 && SCOPES.iter().all(|s| valid_name(s)));
    }

    #[test]
    fn puts_round_trip_and_bad_ones_are_refused() {
        let tags = [LONG, b"b", b"c", b"d"];
        let ev = [
            (0u8, LONG, u32::MAX),
            (1, &b"k"[..], 1),
            (2, b"k", 2),
            (4, b"k", 3),
        ];
        let content = [7u8; MAX_CONTENT];
        let p = Put {
            scope: 3,
            key: LONG,
            kind: Kind::Claim,
            replaces: 9,
            author: Author::Agent {
                name: LONG,
                task: u32::MAX,
            },
            source: Source::Promoted(LONG),
            readable: 0xff,
            tags: List::new(&tags).unwrap(),
            evidence: List::new(&ev).unwrap(),
            content: &content,
        };
        let mut out = [0u8; MAX_RECORD];
        let n = p.encode(&mut out).unwrap();
        assert_eq!(Put::parse(&out[..n]), Some(p));
        assert_eq!(Put::parse(&out[..n + 1]), None, "a trailing byte");
        for cut in 0..n {
            assert_eq!(Put::parse(&out[..cut]), None, "cut at {cut}");
        }
        let small = Put {
            key: b"k",
            author: Author::User,
            source: Source::Written,
            tags: List::default(),
            evidence: List::default(),
            content: b"",
            ..p
        };
        let retraction = Put {
            kind: Kind::Retraction,
            ..small
        };
        for (why, bad) in [
            ("unknown scope", Put { scope: 5, ..small }),
            ("bad key", Put { key: b"", ..small }),
            (
                "retraction of nothing",
                Put {
                    replaces: 0,
                    ..retraction
                },
            ),
            (
                "retraction with content",
                Put {
                    content: b"x",
                    ..retraction
                },
            ),
            (
                "repeated tag",
                Put {
                    tags: List::new(&[&b"t"[..], b"t"]).unwrap(),
                    ..small
                },
            ),
            (
                "evidence version 0",
                Put {
                    evidence: List::new(&[(0, &b"k"[..], 0)]).unwrap(),
                    ..small
                },
            ),
        ] {
            let n = bad.encode(&mut out).unwrap();
            assert_eq!(Put::parse(&out[..n]), None, "{why}");
        }
        let n = small.encode(&mut out).unwrap();
        assert!(Put::parse(&out[..n]).is_some());
        let mut over = std::vec![0u8; MAX_CONTENT + 1];
        let big = Put {
            content: &over,
            ..small
        };
        let n = big.encode(&mut out).unwrap();
        assert_eq!(Put::parse(&out[..n]), None, "content over 4 KiB");
        over.clear();
    }

    #[test]
    fn summaries_and_authors_round_trip() {
        for author in [
            Author::User,
            Author::Agent {
                name: LONG,
                task: 3,
            },
        ] {
            let s = Summary {
                version: 2,
                kind: Kind::Retraction,
                replaces: 1,
                status: flag::STALE | flag::VERIFIED,
                author,
            };
            let mut out = [0u8; 64];
            let mut w = Writer::new(&mut out);
            s.write(&mut w).unwrap();
            let n = w.len();
            assert_eq!(Summary::read(&mut Reader::new(&out[..n])), Some(s));
            let n = encode_author(author, &mut out).unwrap();
            assert_eq!(parse_author(&out[..n]), Some(author));
            assert_eq!(parse_author(&out[..n - 1]), None);
        }
    }

    #[test]
    fn pages_measured_exactly() {
        let s = Summary {
            version: u32::MAX,
            kind: Kind::Claim,
            replaces: 1,
            status: 0,
            author: Author::Agent {
                name: LONG,
                task: 3,
            },
        };
        let mut out = [0xffu8; MAX_PAGE_BYTES + 8];
        let mut w = Writer::new(&mut out);
        for _ in 0..MAX_PAGE {
            s.write(&mut w).unwrap();
        }
        let n = w.len();
        assert_eq!(n, MAX_PAGE_BYTES, "the longest page");
        assert_eq!(page_len(&out, MAX_PAGE as u8, false), Some(n));
        assert_eq!(page_len(&out[..n - 1], MAX_PAGE as u8, false), None);
        assert_eq!(page_len(&out, 0, false), Some(0));
        let keys = b"\x03abc\x01k\xff";
        assert_eq!(page_len(keys, 2, true), Some(6), "not the byte after");
        assert_eq!(page_len(keys, 3, true), None);
        assert_eq!(page_len(b"\x02a.", 1, true), None, "not a key");
    }

    #[test]
    fn fuzzed_requests_never_panic() {
        crate::fuzz(200_000, 12, |m| {
            let _ = parse(m);
            if let Some(p) = Put::parse(m) {
                let mut out = [0u8; MAX_RECORD];
                let n = p.encode(&mut out).unwrap();
                assert_eq!(Put::parse(&out[..n]), Some(p));
            }
            let _ = parse_author(m);
            let _ = Summary::read(&mut Reader::new(m));
        });
    }
}
