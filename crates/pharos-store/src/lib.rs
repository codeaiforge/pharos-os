//! The Pharos OS writable store (D-017, storage.md part 8): a copy-on-write
//! format with two superblock slots, so a crash at any point leaves the
//! old or the new generation and nothing else.
//!
//! A commit writes new data and the new index to free blocks, flushes,
//! then writes a superblock with the next generation into the older slot
//! and flushes. No flush is needed between data and index: a superblock is
//! valid only if its index checks out, and the flush before it makes data
//! and index durable together. Live blocks of the two
//! newest generations are never written. Files are written whole; streams
//! hold records chained with SHA-256.
//!
//! `no_std` with `alloc`, `unsafe` forbidden. The only dependency is
//! `pharos-fs` (CRC-32 and the path rules). Everything read from the device
//! is untrusted and checked before use.

#![no_std]

extern crate alloc;

mod sha256;
#[cfg(test)]
mod tests;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

pub use pharos_fs::{Crc32, MAX_PATH, crc32, valid_path};
pub use sha256::{Sha256, sha256};

/// Bytes per block (8 virtio-blk sectors).
pub const BLOCK: usize = 4096;
/// Superblock magic.
pub const MAGIC: [u8; 8] = *b"PHAROSST";
/// Format version.
pub const VERSION: u32 = 1;
/// Most objects in a store.
pub const MAX_OBJECTS: usize = 4096;
/// Most extents per object.
pub const MAX_EXTENTS: usize = 64;
/// Largest index.
pub const MAX_INDEX: usize = 1 << 20;
/// Bytes before a record's payload: length, CRC-32, chain value.
pub const RECORD_HEADER: usize = 40;
/// Largest record payload.
pub const MAX_RECORD: usize = BLOCK - 64;
/// The share of a store's blocks and of its object table kept for the
/// audit trail (D-046, #212): one part in this many.
pub const RESERVE_PART: u64 = 8;
/// Smallest store: two superblocks, an index block, a data block.
pub const MIN_BLOCKS: u64 = 4;
/// First block after the superblock slots.
const FIRST: u64 = 2;
/// Superblock field offsets.
const SB_CRC: usize = 52;

/// One block.
pub type Block = [u8; BLOCK];

/// A device error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// The block device under a store. Writes may be cached until
/// [`flush`](Self::flush), which makes every earlier write durable.
pub trait Device {
    /// Blocks on the device.
    fn blocks(&self) -> u64;
    fn read(&mut self, block: u64, buf: &mut Block) -> Result<(), IoError>;
    fn write(&mut self, block: u64, buf: &Block) -> Result<(), IoError>;
    fn flush(&mut self) -> Result<(), IoError>;
}

/// What an object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Written whole.
    File = 1,
    /// Append-only records.
    Stream = 2,
}

/// Why a superblock slot is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    Io,
    BadMagic,
    BadVersion,
    BadBlockSize,
    SlotCrc,
    /// A size or block number outside the store or the limits.
    OutOfRange,
    IndexCrc,
    /// The index ends inside an entry, or has bytes after the last.
    Truncated,
    TooManyObjects,
    BadPath,
    /// Paths not strictly increasing (also catches duplicates).
    Unsorted,
    BadKind,
    TooManyExtents,
    /// An extent outside the data blocks, or empty.
    BadExtent,
    /// The extents do not hold exactly the object's length.
    LengthMismatch,
    /// Two objects, or an object and the index, share a block.
    SharedBlock,
}

/// A store operation's error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    /// Neither superblock slot is valid: why, for slots 0 and 1.
    NoStore(SlotError, SlotError),
    /// The device is smaller than [`MIN_BLOCKS`].
    TooSmall,
    BadPath,
    NotFound,
    /// A file where a stream is needed, or the other way round.
    WrongKind,
    /// An empty or oversized record, or more objects or a larger index
    /// than the format allows.
    TooLarge,
    /// Not enough free blocks (refused before anything is written).
    NoSpace,
    /// Content that fails its CRC-32 or chain check.
    Corrupt,
}

impl From<IoError> for Error {
    fn from(_: IoError) -> Self {
        Self::Io
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => f.write_str("device error"),
            Self::NoStore(a, b) => write!(f, "no valid superblock (slot 0: {a:?}, slot 1: {b:?})"),
            Self::TooSmall => write!(f, "device smaller than {MIN_BLOCKS} blocks"),
            Self::BadPath => f.write_str("invalid path"),
            Self::NotFound => f.write_str("no such object"),
            Self::WrongKind => f.write_str("wrong kind of object"),
            Self::TooLarge => f.write_str("too large for the format"),
            Self::NoSpace => f.write_str("not enough free blocks"),
            Self::Corrupt => f.write_str("content fails its checksum"),
        }
    }
}

/// A run of blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub count: u32,
}

/// An object in the index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub path: Vec<u8>,
    pub kind: Kind,
    /// Bytes (for a stream: up to the end of its last record, counting
    /// whole earlier blocks).
    pub len: u64,
    /// CRC-32 of the content (files) or of the last block (streams).
    pub crc: u32,
    /// Streams: records and the last chain value.
    pub records: u64,
    pub head: [u8; 32],
    pub extents: Vec<Extent>,
}

impl Object {
    fn blocks(&self) -> impl Iterator<Item = u64> + '_ {
        self.extents
            .iter()
            .flat_map(|e| e.start..e.start + u64::from(e.count))
    }
}

/// One committed generation: what a valid superblock describes.
#[derive(Clone, Debug)]
struct Generation {
    number: u64,
    total: u64,
    index: Extent,
    objects: Vec<Object>,
}

/// Little-endian reader over untrusted bytes; `None` past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// The index for `objects`.
fn encode_index(objects: &[Object]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(objects.len() as u32).to_le_bytes());
    for o in objects {
        out.push(o.path.len() as u8);
        out.extend_from_slice(&o.path);
        out.push(o.kind as u8);
        out.extend_from_slice(&o.len.to_le_bytes());
        out.extend_from_slice(&o.crc.to_le_bytes());
        if o.kind == Kind::Stream {
            out.extend_from_slice(&o.records.to_le_bytes());
            out.extend_from_slice(&o.head);
        }
        out.extend_from_slice(&(o.extents.len() as u16).to_le_bytes());
        for e in &o.extents {
            out.extend_from_slice(&e.start.to_le_bytes());
            out.extend_from_slice(&e.count.to_le_bytes());
        }
    }
    out
}

/// Parses and checks an index for a store of `total` blocks whose index
/// occupies `index`.
fn decode_index(bytes: &[u8], total: u64, index: Extent) -> Result<Vec<Object>, SlotError> {
    use SlotError::*;
    let mut r = Reader(bytes);
    let count = r.u32().ok_or(Truncated)? as usize;
    if count > MAX_OBJECTS {
        return Err(TooManyObjects);
    }
    let mut used = vec![false; total as usize];
    for b in index.start..index.start + u64::from(index.count) {
        used[b as usize] = true;
    }
    let mut objects: Vec<Object> = Vec::with_capacity(count);
    for _ in 0..count {
        let n = r.u8().ok_or(Truncated)? as usize;
        let path = r.take(n).ok_or(Truncated)?;
        if !valid_path(path) {
            return Err(BadPath);
        }
        if objects.last().is_some_and(|p| p.path.as_slice() >= path) {
            return Err(Unsorted);
        }
        let kind = match r.u8().ok_or(Truncated)? {
            1 => Kind::File,
            2 => Kind::Stream,
            _ => return Err(BadKind),
        };
        let len = r.u64().ok_or(Truncated)?;
        let crc = r.u32().ok_or(Truncated)?;
        let (records, head) = match kind {
            Kind::Stream => {
                let records = r.u64().ok_or(Truncated)?;
                let head: [u8; 32] = r
                    .take(32)
                    .ok_or(Truncated)?
                    .try_into()
                    .map_err(|_| Truncated)?;
                (records, head)
            }
            Kind::File => (0, [0; 32]),
        };
        let extent_count = r.u16().ok_or(Truncated)? as usize;
        if extent_count > MAX_EXTENTS {
            return Err(TooManyExtents);
        }
        let mut extents = Vec::with_capacity(extent_count);
        let mut blocks = 0u64;
        for _ in 0..extent_count {
            let start = r.u64().ok_or(Truncated)?;
            let count = r.u32().ok_or(Truncated)?;
            let end = start.checked_add(u64::from(count)).ok_or(BadExtent)?;
            if count == 0 || start < FIRST || end > total {
                return Err(BadExtent);
            }
            for b in start..end {
                if core::mem::replace(&mut used[b as usize], true) {
                    return Err(SharedBlock);
                }
            }
            blocks += u64::from(count);
            extents.push(Extent { start, count });
        }
        if len.div_ceil(BLOCK as u64) != blocks {
            return Err(LengthMismatch);
        }
        objects.push(Object {
            path: path.to_vec(),
            kind,
            len,
            crc,
            records,
            head,
            extents,
        });
    }
    if !r.0.is_empty() {
        return Err(Truncated);
    }
    Ok(objects)
}

/// A superblock for `g`, given its index's byte length and CRC.
fn encode_superblock(g: &Generation, index_len: u32, index_crc: u32) -> Block {
    let mut b = [0u8; BLOCK];
    b[..8].copy_from_slice(&MAGIC);
    b[8..12].copy_from_slice(&VERSION.to_le_bytes());
    b[12..16].copy_from_slice(&(BLOCK as u32).to_le_bytes());
    b[16..24].copy_from_slice(&g.number.to_le_bytes());
    b[24..32].copy_from_slice(&g.total.to_le_bytes());
    b[32..40].copy_from_slice(&g.index.start.to_le_bytes());
    b[40..44].copy_from_slice(&g.index.count.to_le_bytes());
    b[44..48].copy_from_slice(&index_len.to_le_bytes());
    b[48..52].copy_from_slice(&index_crc.to_le_bytes());
    let crc = crc32(&b[..SB_CRC]);
    b[SB_CRC..SB_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    b
}

/// Reads and checks superblock slot `slot` and its index.
fn read_slot<D: Device>(dev: &mut D, slot: u64) -> Result<Generation, SlotError> {
    use SlotError::*;
    let mut b = [0u8; BLOCK];
    dev.read(slot, &mut b).map_err(|_| Io)?;
    if b[..8] != MAGIC {
        return Err(BadMagic);
    }
    if u32_at(&b, 8) != VERSION {
        return Err(BadVersion);
    }
    if u32_at(&b, 12) != BLOCK as u32 {
        return Err(BadBlockSize);
    }
    if crc32(&b[..SB_CRC]) != u32_at(&b, SB_CRC) {
        return Err(SlotCrc);
    }
    let number = u64_at(&b, 16);
    let total = u64_at(&b, 24);
    let index = Extent {
        start: u64_at(&b, 32),
        count: u32_at(&b, 40),
    };
    let (len, crc) = (u32_at(&b, 44) as usize, u32_at(&b, 48));
    let index_end = index.start.checked_add(u64::from(index.count));
    let in_range = (MIN_BLOCKS..=dev.blocks()).contains(&total)
        && index.start >= FIRST
        && index_end.is_some_and(|end| end <= total)
        && (4..=MAX_INDEX).contains(&len)
        && len.div_ceil(BLOCK) == index.count as usize;
    if !in_range {
        return Err(OutOfRange);
    }
    let mut bytes = vec![0u8; index.count as usize * BLOCK];
    for (i, chunk) in bytes.chunks_exact_mut(BLOCK).enumerate() {
        let chunk: &mut Block = chunk.try_into().map_err(|_| Io)?;
        dev.read(index.start + i as u64, chunk).map_err(|_| Io)?;
    }
    bytes.truncate(len);
    if crc32(&bytes) != crc {
        return Err(IndexCrc);
    }
    let objects = decode_index(&bytes, total, index)?;
    Ok(Generation {
        number,
        total,
        index,
        objects,
    })
}

/// Blocks a generation uses.
fn mark(g: &Generation, used: &mut [bool]) {
    for b in g.index.start..g.index.start + u64::from(g.index.count) {
        used[b as usize] = true;
    }
    for o in &g.objects {
        for b in o.blocks() {
            used[b as usize] = true;
        }
    }
}

/// Free-block allocation for one commit: never hands out a block of the
/// two newest generations or one it handed out already.
// ponytail: linear first-fit scans; a free-extent tree if stores get big
// enough for this to show in commit times.
struct Alloc {
    taken: Vec<bool>,
}

impl Alloc {
    /// Up to `max` extents holding `blocks` blocks, longest runs first-fit.
    fn take(&mut self, mut blocks: u64, max: usize) -> Result<Vec<Extent>, Error> {
        let mut out = Vec::new();
        let mut b = FIRST as usize;
        while blocks > 0 {
            while b < self.taken.len() && self.taken[b] {
                b += 1;
            }
            if b >= self.taken.len() || out.len() == max {
                return Err(Error::NoSpace);
            }
            let start = b;
            while b < self.taken.len()
                && !self.taken[b]
                && ((b - start) as u64) < blocks.min(u64::from(u32::MAX))
            {
                self.taken[b] = true;
                b += 1;
            }
            let count = (b - start) as u32;
            blocks -= u64::from(count);
            out.push(Extent {
                start: start as u64,
                count,
            });
        }
        Ok(out)
    }

    /// One run of exactly `blocks` blocks.
    fn take_run(&mut self, blocks: u64) -> Result<Extent, Error> {
        let n = blocks as usize;
        let mut start = FIRST as usize;
        while start + n <= self.taken.len() {
            match self.taken[start..start + n].iter().rposition(|&t| t) {
                Some(at) => start += at + 1,
                None => {
                    self.taken[start..start + n].fill(true);
                    return Ok(Extent {
                        start: start as u64,
                        count: blocks as u32,
                    });
                }
            }
        }
        Err(Error::NoSpace)
    }
}

/// What [`Store::stat`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub kind: Kind,
    pub len: u64,
    pub records: u64,
    pub head: [u8; 32],
}

/// A mounted store.
pub struct Store<D> {
    dev: D,
    current: Generation,
    /// The slot holding `current`.
    slot: u64,
    /// Blocks of the current generation.
    live: Vec<bool>,
    /// Blocks of the current and the previous generation.
    used: Vec<bool>,
}

impl<D: Device> Store<D> {
    /// Writes an empty store over the whole device: slot 1 invalid, an
    /// empty index, generation 1 in slot 0.
    pub fn format(mut dev: D) -> Result<Self, Error> {
        let total = dev.blocks();
        if total < MIN_BLOCKS {
            return Err(Error::TooSmall);
        }
        let g = Generation {
            number: 1,
            total,
            index: Extent {
                start: FIRST,
                count: 1,
            },
            objects: Vec::new(),
        };
        let index = encode_index(&g.objects);
        let mut block = [0u8; BLOCK];
        dev.write(1, &block)?;
        block[..index.len()].copy_from_slice(&index);
        dev.write(FIRST, &block)?;
        dev.flush()?;
        dev.write(0, &encode_superblock(&g, index.len() as u32, crc32(&index)))?;
        dev.flush()?;
        let mut live = vec![false; total as usize];
        mark(&g, &mut live);
        Ok(Self {
            dev,
            current: g,
            slot: 0,
            used: live.clone(),
            live,
        })
    }

    /// Mounts the store on `dev`: the valid slot with the higher
    /// generation, or the other if only it is valid.
    pub fn mount(mut dev: D) -> Result<Self, Error> {
        if dev.blocks() < MIN_BLOCKS {
            return Err(Error::TooSmall);
        }
        let slots = [read_slot(&mut dev, 0), read_slot(&mut dev, 1)];
        let (slot, current, previous) = match slots {
            [Ok(a), Ok(b)] if b.number > a.number => (1, b, Some(a)),
            [Ok(a), Ok(b)] => (0, a, Some(b)),
            [Ok(a), Err(_)] => (0, a, None),
            [Err(_), Ok(b)] => (1, b, None),
            [Err(a), Err(b)] => return Err(Error::NoStore(a, b)),
        };
        let mut live = vec![false; current.total as usize];
        mark(&current, &mut live);
        let mut used = live.clone();
        if let Some(p) = previous.filter(|p| p.total == current.total) {
            mark(&p, &mut used);
        }
        Ok(Self {
            dev,
            current,
            slot,
            live,
            used,
        })
    }

    /// The device (for tests and the host tool).
    pub fn into_device(self) -> D {
        self.dev
    }

    /// The current generation number.
    pub fn generation(&self) -> u64 {
        self.current.number
    }

    /// Blocks no generation uses.
    pub fn free_blocks(&self) -> u64 {
        self.used[FIRST as usize..].iter().filter(|u| !**u).count() as u64
    }

    /// True if writing `bytes` to `path` leaves the audit trail's reserve
    /// free ([`RESERVE_PART`] of the blocks and of the object table), as
    /// every other namespace must (D-046). One block more than the data,
    /// for the index.
    pub fn leaves_reserve(&self, path: &[u8], bytes: u64) -> bool {
        let total = (self.used.len() as u64).saturating_sub(FIRST);
        let objects = self.current.objects.len() as u64 + u64::from(self.find(path).is_err());
        let max = MAX_OBJECTS as u64;
        objects <= max - max / RESERVE_PART
            && self.free_blocks() >= bytes.div_ceil(BLOCK as u64) + 1 + total / RESERVE_PART
    }

    fn find(&self, path: &[u8]) -> Result<usize, usize> {
        self.current
            .objects
            .binary_search_by(|o| o.path.as_slice().cmp(path))
    }

    fn object(&self, path: &[u8]) -> Result<&Object, Error> {
        if !valid_path(path) {
            return Err(Error::BadPath);
        }
        self.find(path)
            .map(|i| &self.current.objects[i])
            .map_err(|_| Error::NotFound)
    }

    /// The object at `path`.
    pub fn stat(&self, path: &[u8]) -> Result<Info, Error> {
        let o = self.object(path)?;
        Ok(Info {
            kind: o.kind,
            len: o.len,
            records: o.records,
            head: o.head,
        })
    }

    /// Paths starting with `prefix`, in order.
    pub fn list<'a>(&'a self, prefix: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.current
            .objects
            .iter()
            .map(|o| o.path.as_slice())
            .filter(move |p| p.starts_with(prefix))
    }

    /// Reads up to `buf.len()` bytes of the file at `path` from `offset`;
    /// returns the bytes read (0 at the end). A read of the whole file
    /// from offset 0 checks its CRC-32 ([`Error::Corrupt`]).
    pub fn read(&mut self, path: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let mut done = 0;
        let n = self.read_with(path, offset, buf.len() as u64, |bytes| {
            buf[done..done + bytes.len()].copy_from_slice(bytes);
            done += bytes.len();
        })?;
        Ok(n as usize)
    }

    /// Reads up to `len` bytes of the file at `path` from `offset`, passing
    /// them to `f` in order, a block or less at a time; returns how many.
    /// A read of the whole file checks its CRC-32 at the end
    /// ([`Error::Corrupt`], after `f` has seen the bytes: callers must not
    /// trust them then).
    pub fn read_with(
        &mut self,
        path: &[u8],
        offset: u64,
        len: u64,
        mut f: impl FnMut(&[u8]),
    ) -> Result<u64, Error> {
        let o = self.object(path)?;
        if o.kind != Kind::File {
            return Err(Error::WrongKind);
        }
        let n = o.len.saturating_sub(offset).min(len);
        let whole = offset == 0 && n == o.len;
        let (want, blocks): (u32, Vec<u64>) = (o.crc, o.blocks().collect());
        let mut crc = Crc32::new();
        let mut block = [0u8; BLOCK];
        let mut done = 0;
        while done < n {
            let at = offset + done;
            let i = (at / BLOCK as u64) as usize;
            let within = (at % BLOCK as u64) as usize;
            self.dev.read(blocks[i], &mut block)?;
            let k = (BLOCK - within).min((n - done) as usize);
            let bytes = &block[within..within + k];
            crc.update(bytes);
            f(bytes);
            done += k as u64;
        }
        if whole && crc.finish() != want {
            return Err(Error::Corrupt);
        }
        Ok(n)
    }

    /// Calls `f` with each record of the stream at `path`, in order,
    /// checking every record's CRC-32 and chain value, the tail block's
    /// CRC-32, the record count, and the head ([`Error::Corrupt`]).
    pub fn records(&mut self, path: &[u8], mut f: impl FnMut(&[u8])) -> Result<(), Error> {
        let o = self.object(path)?.clone();
        if o.kind != Kind::Stream {
            return Err(Error::WrongKind);
        }
        let blocks: Vec<u64> = o.blocks().collect();
        let mut prev = [0u8; 32];
        let mut count = 0u64;
        let mut block = [0u8; BLOCK];
        for (i, &b) in blocks.iter().enumerate() {
            self.dev.read(b, &mut block)?;
            let last = i + 1 == blocks.len();
            let end = match o.len % BLOCK as u64 {
                0 => BLOCK,
                n if last => n as usize,
                _ => BLOCK,
            };
            if last && crc32(&block) != o.crc {
                return Err(Error::Corrupt);
            }
            let mut at = 0;
            while at + RECORD_HEADER <= end {
                let len = u32_at(&block, at) as usize;
                if len == 0 && !last {
                    break;
                }
                let payload_end = at + RECORD_HEADER + len;
                if len == 0 || len > MAX_RECORD || payload_end > end {
                    return Err(Error::Corrupt);
                }
                let payload = &block[at + RECORD_HEADER..payload_end];
                let chain = sha256(&[&prev, payload]);
                if crc32(payload) != u32_at(&block, at + 4) || block[at + 8..at + 40] != chain {
                    return Err(Error::Corrupt);
                }
                f(payload);
                prev = chain;
                count += 1;
                at = payload_end;
            }
            if last && at != end {
                return Err(Error::Corrupt);
            }
        }
        if count != o.records || prev != o.head {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn alloc(&self) -> Alloc {
        Alloc {
            taken: self.used.clone(),
        }
    }

    /// The object list with `object` put in (replacing one at its path).
    fn with(&self, object: Object) -> Result<Vec<Object>, Error> {
        let mut objects = self.current.objects.clone();
        match self.find(&object.path) {
            Ok(i) => objects[i] = object,
            Err(i) => {
                if objects.len() >= MAX_OBJECTS {
                    return Err(Error::TooLarge);
                }
                objects.insert(i, object);
            }
        }
        Ok(objects)
    }

    /// Commits `objects` after `writes` (new data blocks): allocates the
    /// index before writing anything, then writes data and index, flushes,
    /// writes the superblock, flushes.
    fn commit(
        &mut self,
        mut alloc: Alloc,
        objects: Vec<Object>,
        writes: &[(u64, Block)],
    ) -> Result<(), Error> {
        let run = plan_index(&mut alloc, &objects)?;
        for (b, data) in writes {
            self.dev.write(*b, data)?;
        }
        self.finish(run, objects)
    }

    /// The second half of a commit, after the data is written: the index
    /// at `run`, a flush, the superblock, a flush.
    fn finish(&mut self, run: Extent, objects: Vec<Object>) -> Result<(), Error> {
        let index = encode_index(&objects);
        let g = Generation {
            number: self.current.number + 1,
            total: self.current.total,
            index: run,
            objects,
        };
        for (i, chunk) in index.chunks(BLOCK).enumerate() {
            let mut block = [0u8; BLOCK];
            block[..chunk.len()].copy_from_slice(chunk);
            self.dev.write(run.start + i as u64, &block)?;
        }
        self.dev.flush()?;
        let slot = 1 - self.slot;
        self.dev.write(
            slot,
            &encode_superblock(&g, index.len() as u32, crc32(&index)),
        )?;
        self.dev.flush()?;
        // The old current generation becomes the fallback.
        let mut live = vec![false; g.total as usize];
        mark(&g, &mut live);
        self.used = live.iter().zip(&self.live).map(|(a, b)| *a || *b).collect();
        self.live = live;
        self.current = g;
        self.slot = slot;
        Ok(())
    }

    /// Replaces (or creates) the file at `path` with `data`, atomically.
    pub fn write(&mut self, path: &[u8], data: &[u8]) -> Result<(), Error> {
        self.write_with(path, data.len() as u64, |offset, block| {
            let chunk = &data[offset as usize..];
            let n = chunk.len().min(BLOCK);
            block[..n].copy_from_slice(&chunk[..n]);
        })
    }

    /// Replaces (or creates) the file at `path` with `len` bytes, atomically,
    /// asking `fill(offset, block)` for each block's bytes in order (the
    /// block is zeroed; bytes past `len` are ignored). Streams: nothing but
    /// one block is held in memory. Space is checked before anything is
    /// written.
    pub fn write_with(
        &mut self,
        path: &[u8],
        len: u64,
        mut fill: impl FnMut(u64, &mut Block),
    ) -> Result<(), Error> {
        if !valid_path(path) {
            return Err(Error::BadPath);
        }
        if let Ok(i) = self.find(path) {
            if self.current.objects[i].kind != Kind::File {
                return Err(Error::WrongKind);
            }
        }
        let mut alloc = self.alloc();
        let extents = alloc.take(len.div_ceil(BLOCK as u64), MAX_EXTENTS)?;
        let object = Object {
            path: path.to_vec(),
            kind: Kind::File,
            len,
            crc: 0,
            records: 0,
            head: [0; 32],
            extents,
        };
        let blocks: Vec<u64> = object.blocks().collect();
        let mut objects = self.with(object)?;
        // The CRC does not change the index's size: plan it now.
        let run = plan_index(&mut alloc, &objects)?;
        let mut crc = Crc32::new();
        for (i, &b) in blocks.iter().enumerate() {
            let offset = i as u64 * BLOCK as u64;
            let mut block = [0u8; BLOCK];
            fill(offset, &mut block);
            let used = (len - offset).min(BLOCK as u64) as usize;
            block[used..].fill(0);
            crc.update(&block[..used]);
            self.dev.write(b, &block)?;
        }
        let i = self.find_in(&objects, path);
        objects[i].crc = crc.finish();
        self.finish(run, objects)
    }

    fn find_in(&self, objects: &[Object], path: &[u8]) -> usize {
        objects
            .binary_search_by(|o| o.path.as_slice().cmp(path))
            .unwrap_or(0)
    }

    /// Appends a record (1 to [`MAX_RECORD`] bytes) to the stream at
    /// `path`, creating it if absent; returns the record number (from 0)
    /// and the new chain head. The tail block is copied, never rewritten.
    pub fn append(&mut self, path: &[u8], payload: &[u8]) -> Result<(u64, [u8; 32]), Error> {
        if !valid_path(path) {
            return Err(Error::BadPath);
        }
        if payload.is_empty() || payload.len() > MAX_RECORD {
            return Err(Error::TooLarge);
        }
        let mut o = match self.find(path) {
            Ok(i) if self.current.objects[i].kind != Kind::Stream => return Err(Error::WrongKind),
            Ok(i) => self.current.objects[i].clone(),
            Err(_) => Object {
                path: path.to_vec(),
                kind: Kind::Stream,
                len: 0,
                crc: 0,
                records: 0,
                head: [0; 32],
                extents: Vec::new(),
            },
        };
        let size = RECORD_HEADER + payload.len();
        let used_in_tail = (o.len % BLOCK as u64) as usize;
        let mut tail = [0u8; BLOCK];
        let mut blocks: Vec<u64> = o.blocks().collect();
        let at = if o.len > 0 && used_in_tail != 0 && used_in_tail + size <= BLOCK {
            let last = blocks.pop().ok_or(Error::Corrupt)?;
            self.dev.read(last, &mut tail)?;
            if crc32(&tail) != o.crc {
                return Err(Error::Corrupt);
            }
            used_in_tail
        } else {
            0
        };
        let head = sha256(&[&o.head, payload]);
        tail[at..at + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        tail[at + 4..at + 8].copy_from_slice(&crc32(payload).to_le_bytes());
        tail[at + 8..at + 40].copy_from_slice(&head);
        tail[at + 40..at + size].copy_from_slice(payload);
        let mut alloc = self.alloc();
        // The new tail goes right after the block before it if that is
        // free, to keep extents few.
        let after = blocks.last().map(|b| *b as usize + 1);
        let new = match after.filter(|&b| alloc.taken.get(b) == Some(&false)) {
            Some(b) => {
                alloc.taken[b] = true;
                b as u64
            }
            None => alloc.take(1, 1)?[0].start,
        };
        blocks.push(new);
        let mut writes = vec![(new, tail)];
        let mut extents = to_extents(&blocks);
        if extents.len() > MAX_EXTENTS {
            // Too fragmented: move the whole stream into one run.
            alloc.taken[new as usize] = false;
            let run = alloc.take_run(blocks.len() as u64)?;
            writes.clear();
            for (i, &b) in blocks.iter().enumerate() {
                let mut block = [0u8; BLOCK];
                if b == new {
                    block = tail;
                } else {
                    self.dev.read(b, &mut block)?;
                }
                writes.push((run.start + i as u64, block));
            }
            extents = vec![run];
        }
        o.len = (blocks.len() as u64 - 1) * BLOCK as u64 + (at + size) as u64;
        o.crc = crc32(&tail);
        o.records += 1;
        o.head = head;
        o.extents = extents;
        let number = o.records - 1;
        let objects = self.with(o)?;
        self.commit(alloc, objects, &writes)?;
        Ok((number, head))
    }

    /// Removes the object at `path`.
    pub fn delete(&mut self, path: &[u8]) -> Result<(), Error> {
        self.object(path)?;
        let i = self.find(path).map_err(|_| Error::NotFound)?;
        let mut objects = self.current.objects.clone();
        objects.remove(i);
        self.commit(self.alloc(), objects, &[])
    }
}

/// Allocates the index blocks for `objects` (before anything is written).
fn plan_index(alloc: &mut Alloc, objects: &[Object]) -> Result<Extent, Error> {
    let len = encode_index(objects).len();
    if len > MAX_INDEX {
        return Err(Error::TooLarge);
    }
    alloc.take_run(len.div_ceil(BLOCK) as u64)
}

/// Blocks in order as extents, merging neighbours.
fn to_extents(blocks: &[u64]) -> Vec<Extent> {
    let mut out: Vec<Extent> = Vec::new();
    for &b in blocks {
        match out.last_mut() {
            Some(e) if e.start + u64::from(e.count) == b && e.count < u32::MAX => e.count += 1,
            _ => out.push(Extent { start: b, count: 1 }),
        }
    }
    out
}
