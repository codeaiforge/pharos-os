//! The Pharos OS read-only filesystem image, format version 1
//! ([storage.md](../../../docs/architecture/storage.md), decision D-007).
//!
//! One crate for both sides: the host tool builds images with [`Builder`],
//! and the kernel and the host mount them with [`Image::mount`], which
//! checks everything before any data is used. The image is untrusted input:
//! every offset and size is checked with overflow checks, limits are fixed,
//! and no input makes the parser panic (fuzzed in the tests).
//!
//! `no_std` with `alloc`, no dependencies, `unsafe` forbidden (workspace
//! lint).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// Bytes per block.
pub const BLOCK_SIZE: usize = 512;
/// Magic bytes at offset 0.
pub const MAGIC: [u8; 8] = *b"PHAROSFS";
/// The format version this crate reads and writes.
pub const VERSION: u32 = 1;
/// Header size in bytes; the directory starts here.
pub const HEADER_SIZE: usize = 64;
/// Directory entry size in bytes.
pub const ENTRY_SIZE: usize = 128;
/// Largest number of files.
pub const MAX_ENTRIES: usize = 1024;
/// Longest path in bytes.
pub const MAX_PATH: usize = 104;
/// Largest image in bytes.
pub const MAX_IMAGE: u64 = 16 << 20;

/// Why a block read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// The read reaches past the last block.
    OutOfRange,
    /// The buffer is empty or not a multiple of [`BLOCK_SIZE`].
    BadLength,
}

/// A device read in [`BLOCK_SIZE`]-byte blocks.
pub trait BlockDevice {
    /// Number of blocks.
    fn block_count(&self) -> u64;
    /// Reads `buf.len() / BLOCK_SIZE` blocks starting at `block`.
    fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError>;
}

/// A byte slice is a RAM disk: its whole blocks, any shorter tail ignored.
impl BlockDevice for [u8] {
    fn block_count(&self) -> u64 {
        (self.len() / BLOCK_SIZE) as u64
    }

    fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 {
            return Err(BlockError::BadLength);
        }
        let count = (buf.len() / BLOCK_SIZE) as u64;
        match block.checked_add(count) {
            Some(end) if end <= self.block_count() => {}
            _ => return Err(BlockError::OutOfRange),
        }
        // Both fit in usize: they are at most self.len().
        let start = block as usize * BLOCK_SIZE;
        buf.copy_from_slice(&self[start..start + buf.len()]);
        Ok(())
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for &D {
    fn block_count(&self) -> u64 {
        (**self).block_count()
    }

    fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        (**self).read(block, buf)
    }
}

/// Why an image did not mount, or a lookup or read failed. Entry indexes
/// count from 0 in directory order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// The device failed a read.
    Device(BlockError),
    /// The device is smaller than the header, or than `image_size`.
    DeviceTooSmall,
    /// The magic bytes are wrong.
    BadMagic,
    /// The format version is not [`VERSION`].
    BadVersion(u32),
    /// The header checksum does not match.
    HeaderCrc,
    /// The header's reserved bytes are not zero.
    HeaderReserved,
    /// More than [`MAX_ENTRIES`] entries.
    TooManyEntries(u32),
    /// `image_size` is not a multiple of the block size, too small for the
    /// directory, or larger than [`MAX_IMAGE`].
    BadImageSize(u64),
    /// The directory checksum does not match.
    DirCrc,
    /// An entry's path breaks the path rules.
    EntryPath { index: usize },
    /// An entry's reserved bytes, or its path padding, are not zero.
    EntryReserved { index: usize },
    /// An entry is not after the previous one in byte order (unsorted or
    /// duplicate).
    EntryOrder { index: usize },
    /// An entry's path is also a directory of a later entry (`a` and `a/b`).
    EntryPrefix { index: usize },
    /// An entry's data is outside the image or overlaps earlier data.
    EntryRange { index: usize },
    /// A file's checksum does not match its data.
    FileCrc { index: usize },
    /// No file with this path.
    NotFound,
    /// A [`FileId`] from another image.
    BadFile,
}

impl From<BlockError> for FsError {
    fn from(e: BlockError) -> Self {
        Self::Device(e)
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(e) => write!(f, "device read failed: {e:?}"),
            Self::DeviceTooSmall => f.write_str("device smaller than the image"),
            Self::BadMagic => f.write_str("not a Pharos filesystem image (bad magic)"),
            Self::BadVersion(v) => write!(f, "unsupported format version {v}"),
            Self::HeaderCrc => f.write_str("header checksum mismatch"),
            Self::HeaderReserved => f.write_str("header reserved bytes not zero"),
            Self::TooManyEntries(n) => write!(f, "{n} entries (at most {MAX_ENTRIES})"),
            Self::BadImageSize(s) => write!(f, "bad image size {s}"),
            Self::DirCrc => f.write_str("directory checksum mismatch"),
            Self::EntryPath { index } => write!(f, "entry {index}: invalid path"),
            Self::EntryReserved { index } => write!(f, "entry {index}: reserved bytes not zero"),
            Self::EntryOrder { index } => write!(f, "entry {index}: not sorted or duplicate"),
            Self::EntryPrefix { index } => {
                write!(f, "entry {index}: path is also a directory")
            }
            Self::EntryRange { index } => {
                write!(f, "entry {index}: data out of range or overlapping")
            }
            Self::FileCrc { index } => write!(f, "entry {index}: file checksum mismatch"),
            Self::NotFound => f.write_str("no such file"),
            Self::BadFile => f.write_str("file id not from this image"),
        }
    }
}

/// CRC-32 (IEEE, reflected `0xEDB88320`), as in zlib. Feed data with
/// [`update`](Self::update), then take [`finish`](Self::finish).
#[derive(Clone, Copy)]
pub struct Crc32(u32);

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

impl Crc32 {
    /// A new checksum over no data.
    pub const fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 = CRC_TABLE[((self.0 ^ b as u32) & 0xFF) as usize] ^ (self.0 >> 8);
        }
    }

    /// The checksum of everything added.
    pub const fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

/// CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finish()
}

/// True if `path` follows the path rules: 1 to [`MAX_PATH`] bytes of
/// `A–Z a–z 0–9 . _ -` and `/`, components separated by single slashes,
/// no slash at either end, no `.` or `..` component.
pub fn valid_path(path: &[u8]) -> bool {
    if path.is_empty() || path.len() > MAX_PATH {
        return false;
    }
    let allowed = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
    path.split(|&b| b == b'/')
        .all(|c| !c.is_empty() && c != b"." && c != b".." && c.iter().all(allowed))
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut a = [0; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Reads `buf.len()` bytes at byte `offset` through whole-block reads.
/// The caller has checked that the range is inside the device.
fn read_bytes<D: BlockDevice>(dev: &D, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
    let mut block = [0u8; BLOCK_SIZE];
    let mut done = 0;
    while done < buf.len() {
        let pos = offset + done as u64;
        let skip = (pos % BLOCK_SIZE as u64) as usize;
        dev.read(pos / BLOCK_SIZE as u64, &mut block)?;
        let n = (BLOCK_SIZE - skip).min(buf.len() - done);
        buf[done..done + n].copy_from_slice(&block[skip..skip + n]);
        done += n;
    }
    Ok(())
}

/// A validated directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    offset: u64,
    size: u64,
    crc: u32,
    path_len: u8,
    path: [u8; MAX_PATH],
}

impl Entry {
    fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }
}

/// A file in a mounted image, from [`Image::lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId(usize);

/// One file's metadata, from [`Image::entries`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo<'a> {
    /// The full path, for example `etc/motd`.
    pub path: &'a [u8],
    /// Size in bytes.
    pub size: u64,
    /// CRC-32 of the data.
    pub crc: u32,
}

/// A mounted, fully validated image.
pub struct Image<D> {
    dev: D,
    entries: Vec<Entry>,
}

impl<D: BlockDevice> Image<D> {
    /// Checks the whole image on `dev` (header, directory, every entry,
    /// every file's checksum) and mounts it. Nothing is used before it has
    /// been checked; at most 128 KiB is allocated, after the entry count
    /// passed its check.
    pub fn mount(dev: D) -> Result<Self, FsError> {
        let device_bytes = dev
            .block_count()
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(FsError::DeviceTooSmall)?;
        if device_bytes < BLOCK_SIZE as u64 {
            return Err(FsError::DeviceTooSmall);
        }

        // 1. Header.
        let mut first = [0u8; BLOCK_SIZE];
        dev.read(0, &mut first)?;
        let h = &first[..HEADER_SIZE];
        if h[..8] != MAGIC {
            return Err(FsError::BadMagic);
        }
        let version = u32_at(h, 8);
        if version != VERSION {
            return Err(FsError::BadVersion(version));
        }
        if crc32(&h[..60]) != u32_at(h, 60) {
            return Err(FsError::HeaderCrc);
        }
        if h[28..60].iter().any(|&b| b != 0) {
            return Err(FsError::HeaderReserved);
        }
        let count = u32_at(h, 12);
        if count as usize > MAX_ENTRIES {
            return Err(FsError::TooManyEntries(count));
        }
        let count = count as usize;
        let dir_end = (HEADER_SIZE + count * ENTRY_SIZE) as u64;
        let image_size = u64_at(h, 16);
        if image_size % BLOCK_SIZE as u64 != 0 || image_size < dir_end || image_size > MAX_IMAGE {
            return Err(FsError::BadImageSize(image_size));
        }
        if image_size > device_bytes {
            return Err(FsError::DeviceTooSmall);
        }

        // 2. Directory.
        let mut dir = vec![0u8; count * ENTRY_SIZE];
        read_bytes(&dev, HEADER_SIZE as u64, &mut dir)?;
        if crc32(&dir) != u32_at(h, 24) {
            return Err(FsError::DirCrc);
        }

        // 3. Entries.
        let mut entries: Vec<Entry> = Vec::with_capacity(count);
        let mut data_end = dir_end;
        for (index, raw) in dir.chunks_exact(ENTRY_SIZE).enumerate() {
            let path_len = u16_at(raw, 20) as usize;
            if path_len == 0 || path_len > MAX_PATH {
                return Err(FsError::EntryPath { index });
            }
            let path_bytes = &raw[24..];
            if u16_at(raw, 22) != 0 || path_bytes[path_len..].iter().any(|&b| b != 0) {
                return Err(FsError::EntryReserved { index });
            }
            if !valid_path(&path_bytes[..path_len]) {
                return Err(FsError::EntryPath { index });
            }
            if let Some(prev) = entries.last() {
                if prev.path() >= &path_bytes[..path_len] {
                    return Err(FsError::EntryOrder { index });
                }
            }
            let (offset, size) = (u64_at(raw, 0), u64_at(raw, 8));
            match offset.checked_add(size) {
                Some(end) if offset >= data_end && end <= image_size => data_end = end,
                _ => return Err(FsError::EntryRange { index }),
            }
            let mut path = [0u8; MAX_PATH];
            path.copy_from_slice(path_bytes);
            entries.push(Entry {
                offset,
                size,
                crc: u32_at(raw, 16),
                path_len: path_len as u8,
                path,
            });
        }
        // A path that is also a directory: `a` and some later `a/...`.
        // Sorted order puts `a/` at the binary-search point for it.
        for (index, e) in entries.iter().enumerate() {
            let mut dir_prefix = [0u8; MAX_PATH + 1];
            let p = e.path();
            dir_prefix[..p.len()].copy_from_slice(p);
            dir_prefix[p.len()] = b'/';
            let dir_prefix = &dir_prefix[..=p.len()];
            let at = entries.partition_point(|x| x.path() < dir_prefix);
            if entries
                .get(at)
                .is_some_and(|x| x.path().starts_with(dir_prefix))
            {
                return Err(FsError::EntryPrefix { index });
            }
        }

        // 4. File checksums.
        let mut buf = [0u8; BLOCK_SIZE];
        for (index, e) in entries.iter().enumerate() {
            let mut crc = Crc32::new();
            let mut done = 0u64;
            while done < e.size {
                let n = (e.size - done).min(BLOCK_SIZE as u64) as usize;
                read_bytes(&dev, e.offset + done, &mut buf[..n])?;
                crc.update(&buf[..n]);
                done += n as u64;
            }
            if crc.finish() != e.crc {
                return Err(FsError::FileCrc { index });
            }
        }

        Ok(Self { dev, entries })
    }

    /// The file at `path`. Any byte string is accepted; one that breaks the
    /// path rules matches nothing.
    pub fn lookup(&self, path: &[u8]) -> Result<FileId, FsError> {
        self.entries
            .binary_search_by(|e| e.path().cmp(path))
            .map(FileId)
            .map_err(|_| FsError::NotFound)
    }

    /// The file's size in bytes.
    pub fn size(&self, file: FileId) -> Result<u64, FsError> {
        Ok(self.entries.get(file.0).ok_or(FsError::BadFile)?.size)
    }

    /// Reads from `file` at byte `offset` into `buf`; returns the bytes
    /// read, 0 at or past the end of the file.
    pub fn read(&self, file: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let e = self.entries.get(file.0).ok_or(FsError::BadFile)?;
        if offset >= e.size {
            return Ok(0);
        }
        // Fits in usize: at most buf.len().
        let n = (e.size - offset).min(buf.len() as u64) as usize;
        read_bytes(&self.dev, e.offset + offset, &mut buf[..n])?;
        Ok(n)
    }

    /// Every file, in path order.
    pub fn entries(&self) -> impl Iterator<Item = FileInfo<'_>> {
        self.entries.iter().map(|e| FileInfo {
            path: e.path(),
            size: e.size,
            crc: e.crc,
        })
    }
}

/// Why [`Builder`] refused a file or an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The path breaks the path rules.
    BadPath,
    /// Two files have the same path.
    Duplicate,
    /// A path is also a directory of another (`a` and `a/b`).
    PathIsDirectory,
    /// More than [`MAX_ENTRIES`] files.
    TooManyFiles,
    /// The image would be larger than [`MAX_IMAGE`].
    TooLarge,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadPath => "invalid path (allowed: A-Z a-z 0-9 . _ - and /, at most 104 bytes)",
            Self::Duplicate => "duplicate path",
            Self::PathIsDirectory => "a file path is also used as a directory",
            Self::TooManyFiles => "too many files (at most 1024)",
            Self::TooLarge => "image larger than 16 MiB",
        })
    }
}

/// Builds an image from files added in any order. The output depends only
/// on the paths and contents, so builds are reproducible.
#[derive(Default)]
pub struct Builder {
    files: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Builder {
    /// An empty image.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file. Paths are checked here; conflicts between paths are
    /// checked by [`build`](Self::build).
    pub fn add(&mut self, path: &[u8], data: &[u8]) -> Result<(), BuildError> {
        if !valid_path(path) {
            return Err(BuildError::BadPath);
        }
        if self.files.len() == MAX_ENTRIES {
            return Err(BuildError::TooManyFiles);
        }
        self.files.push((path.to_vec(), data.to_vec()));
        Ok(())
    }

    /// The image bytes, padded to a whole number of blocks.
    pub fn build(mut self) -> Result<Vec<u8>, BuildError> {
        self.files.sort_by(|a, b| a.0.cmp(&b.0));
        if self.files.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(BuildError::Duplicate);
        }
        for (path, _) in &self.files {
            let mut prefix = path.clone();
            prefix.push(b'/');
            if self.files.iter().any(|(p, _)| p.starts_with(&prefix)) {
                return Err(BuildError::PathIsDirectory);
            }
        }
        let dir_end = HEADER_SIZE + self.files.len() * ENTRY_SIZE;
        let data: u64 = self.files.iter().map(|(_, d)| d.len() as u64).sum();
        let size = (dir_end as u64 + data).next_multiple_of(BLOCK_SIZE as u64);
        if size > MAX_IMAGE {
            return Err(BuildError::TooLarge);
        }

        let mut image = vec![0u8; size as usize];
        let mut offset = dir_end;
        for (i, (path, bytes)) in self.files.iter().enumerate() {
            let e = &mut image[HEADER_SIZE + i * ENTRY_SIZE..][..ENTRY_SIZE];
            e[0..8].copy_from_slice(&(offset as u64).to_le_bytes());
            e[8..16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            e[16..20].copy_from_slice(&crc32(bytes).to_le_bytes());
            e[20..22].copy_from_slice(&(path.len() as u16).to_le_bytes());
            e[24..24 + path.len()].copy_from_slice(path);
            image[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }
        let dir_crc = crc32(&image[HEADER_SIZE..dir_end]);
        let h = &mut image[..HEADER_SIZE];
        h[..8].copy_from_slice(&MAGIC);
        h[8..12].copy_from_slice(&VERSION.to_le_bytes());
        h[12..16].copy_from_slice(&(self.files.len() as u32).to_le_bytes());
        h[16..24].copy_from_slice(&size.to_le_bytes());
        h[24..28].copy_from_slice(&dir_crc.to_le_bytes());
        let header_crc = crc32(&h[..60]);
        h[60..64].copy_from_slice(&header_crc.to_le_bytes());
        Ok(image)
    }
}

#[cfg(test)]
mod tests;
