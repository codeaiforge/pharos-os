//! Static ELF64 executables for Pharos OS user programs
//! ([drivers.md](../../../docs/architecture/drivers.md), decision D-008).
//!
//! [`parse`] checks a program's headers completely and returns its entry
//! point and loadable segments; the loader allocates nothing before that.
//! Only a small subset is accepted: ELF64, little-endian, `ET_EXEC`,
//! x86-64, at most [`MAX_SEGMENTS`] `PT_LOAD` segments inside the allowed
//! range, never writable and executable at once, not sharing pages, and an
//! entry point in an executable segment. The file is untrusted input: every
//! offset and size is checked with overflow checks, and no input makes the
//! parser panic (fuzzed in the tests).
//!
//! `no_std`, no dependencies, `unsafe` forbidden (workspace lint).

#![no_std]

#[cfg(test)]
extern crate std;

use core::fmt;
use core::ops::Range;

/// Most `PT_LOAD` segments accepted.
pub const MAX_SEGMENTS: usize = 8;
/// Page size segments are mapped with.
pub const PAGE: u64 = 4096;
/// ELF header size.
pub const EHDR_SIZE: usize = 64;
/// Program header size.
pub const PHDR_SIZE: usize = 56;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Why a file is not an acceptable program. Segment indexes count program
/// headers from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Shorter than the headers it declares.
    Truncated,
    /// Not an ELF file.
    BadMagic,
    /// Not ELF64, little-endian, version 1.
    BadIdent,
    /// Not an executable (`ET_EXEC`).
    NotExecutable,
    /// Not x86-64.
    WrongMachine,
    /// Header or program-header size is not the standard one.
    BadHeaderSize,
    /// No loadable segment, or more than [`MAX_SEGMENTS`].
    SegmentCount,
    /// Needs a dynamic linker, dynamic linking, or thread-local storage.
    Unsupported { index: usize },
    /// A segment's sizes, file range, alignment, or address range is bad.
    BadSegment { index: usize },
    /// A segment is writable and executable.
    WritableCode { index: usize },
    /// A segment shares pages with an earlier one, or is out of order.
    Overlap { index: usize },
    /// The entry point is not inside an executable segment.
    BadEntry,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("file shorter than its headers"),
            Self::BadMagic => f.write_str("not an ELF file"),
            Self::BadIdent => f.write_str("not ELF64 little-endian version 1"),
            Self::NotExecutable => f.write_str("not a static executable (ET_EXEC)"),
            Self::WrongMachine => f.write_str("not an x86-64 program"),
            Self::BadHeaderSize => f.write_str("unexpected header sizes"),
            Self::SegmentCount => write!(f, "needs 1 to {MAX_SEGMENTS} loadable segments"),
            Self::Unsupported { index } => {
                write!(
                    f,
                    "segment {index}: dynamic linking or TLS is not supported"
                )
            }
            Self::BadSegment { index } => write!(f, "segment {index}: bad size, range, or address"),
            Self::WritableCode { index } => write!(f, "segment {index}: writable and executable"),
            Self::Overlap { index } => write!(f, "segment {index}: overlaps or out of order"),
            Self::BadEntry => f.write_str("entry point not in an executable segment"),
        }
    }
}

/// A checked loadable segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Segment {
    /// First virtual address.
    pub vaddr: u64,
    /// Bytes in memory (the part past `filesz` is zero).
    pub memsz: u64,
    /// Where its bytes start in the file.
    pub offset: u64,
    /// Bytes taken from the file.
    pub filesz: u64,
    pub writable: bool,
    pub executable: bool,
}

impl Segment {
    /// The page-aligned virtual range the segment covers.
    pub fn pages(&self) -> Range<u64> {
        // Cannot overflow: checked by `parse` against the allowed range.
        self.vaddr / PAGE * PAGE..(self.vaddr + self.memsz).div_ceil(PAGE) * PAGE
    }

    /// For the page at `page` (page-aligned, inside [`pages`](Self::pages)):
    /// the byte range within the page that comes from the file, and the
    /// file offset of its first byte. `None` if the page holds no file
    /// bytes (all zero).
    pub fn file_part(&self, page: u64) -> Option<(Range<usize>, u64)> {
        let start = page.max(self.vaddr);
        let end = (page + PAGE).min(self.vaddr + self.filesz);
        (start < end).then(|| {
            let in_page = (start - page) as usize..(end - page) as usize;
            (in_page, self.offset + (start - self.vaddr))
        })
    }
}

/// A checked program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    pub entry: u64,
    segments: [Segment; MAX_SEGMENTS],
    count: usize,
}

impl Program {
    /// The loadable segments, in address order.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }
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

/// Checks a program whose file is `file_size` bytes long, given its first
/// bytes in `head` (the ELF header and all program headers must lie in
/// `head`). Segments must lie in `range` (page-aligned).
pub fn parse(head: &[u8], file_size: u64, range: Range<u64>) -> Result<Program, ElfError> {
    if head.len() < EHDR_SIZE || (head.len() as u64) > file_size {
        return Err(ElfError::Truncated);
    }
    if head[..4] != *b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    // Class 64-bit, little-endian, ident version 1, and e_version 1.
    if head[4] != 2 || head[5] != 1 || head[6] != 1 || u32_at(head, 20) != 1 {
        return Err(ElfError::BadIdent);
    }
    if u16_at(head, 16) != ET_EXEC {
        return Err(ElfError::NotExecutable);
    }
    if u16_at(head, 18) != EM_X86_64 {
        return Err(ElfError::WrongMachine);
    }
    if u16_at(head, 52) as usize != EHDR_SIZE || u16_at(head, 54) as usize != PHDR_SIZE {
        return Err(ElfError::BadHeaderSize);
    }
    let entry = u64_at(head, 24);
    let phoff = u64_at(head, 32);
    let phnum = u16_at(head, 56) as u64;
    phoff
        .checked_add(phnum * PHDR_SIZE as u64)
        .filter(|&end| end <= head.len() as u64)
        .ok_or(ElfError::Truncated)?;

    let mut segments = [Segment::default(); MAX_SEGMENTS];
    let mut count = 0;
    let mut prev_end = range.start;
    for index in 0..phnum as usize {
        let ph = &head[phoff as usize + index * PHDR_SIZE..][..PHDR_SIZE];
        match u32_at(ph, 0) {
            PT_LOAD => {}
            PT_INTERP | PT_DYNAMIC | PT_TLS => return Err(ElfError::Unsupported { index }),
            _ => continue,
        }
        if count == MAX_SEGMENTS {
            return Err(ElfError::SegmentCount);
        }
        let flags = u32_at(ph, 4);
        let (offset, vaddr, filesz, memsz) = (
            u64_at(ph, 8),
            u64_at(ph, 16),
            u64_at(ph, 32),
            u64_at(ph, 40),
        );
        let file_ok = offset
            .checked_add(filesz)
            .is_some_and(|end| end <= file_size);
        let mem_end = vaddr.checked_add(memsz);
        let mem_ok = mem_end.is_some_and(|end| vaddr >= range.start && end <= range.end);
        if memsz == 0
            || filesz > memsz
            || !file_ok
            || !mem_ok
            || vaddr % PAGE != offset % PAGE
            || flags & !(PF_R | PF_W | PF_X) != 0
        {
            return Err(ElfError::BadSegment { index });
        }
        if flags & PF_W != 0 && flags & PF_X != 0 {
            return Err(ElfError::WritableCode { index });
        }
        let segment = Segment {
            vaddr,
            memsz,
            offset,
            filesz,
            writable: flags & PF_W != 0,
            executable: flags & PF_X != 0,
        };
        let pages = segment.pages();
        if pages.start < prev_end {
            return Err(ElfError::Overlap { index });
        }
        prev_end = pages.end;
        segments[count] = segment;
        count += 1;
    }
    if count == 0 {
        return Err(ElfError::SegmentCount);
    }
    let in_code = segments[..count]
        .iter()
        .any(|s| s.executable && s.vaddr <= entry && entry < s.vaddr + s.memsz);
    if !in_code {
        return Err(ElfError::BadEntry);
    }
    Ok(Program {
        entry,
        segments,
        count,
    })
}

#[cfg(test)]
mod tests;
