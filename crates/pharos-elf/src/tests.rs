use super::*;
use std::vec::Vec;

const RANGE: Range<u64> = 0x40_0000..0x140_0000;

/// One program header: type, flags, offset, vaddr, filesz, memsz.
type Ph = (u32, u32, u64, u64, u64, u64);

/// A small valid layout: code at 0x401000 (file 0x1000), data at 0x402000.
fn phs() -> Vec<Ph> {
    std::vec![
        (PT_LOAD, PF_R | PF_X, 0x1000, 0x40_1000, 0x80, 0x80),
        (PT_LOAD, PF_R | PF_W, 0x2000, 0x40_2000, 0x10, 0x3000),
        (0x6474_e551, PF_R | PF_W, 0, 0, 0, 0), // PT_GNU_STACK: ignored
    ]
}

fn elf(entry: u64, phs: &[Ph]) -> Vec<u8> {
    let mut f = std::vec![0u8; 0x2010];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4..7].copy_from_slice(&[2, 1, 1]);
    f[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    f[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    f[20..24].copy_from_slice(&1u32.to_le_bytes());
    f[24..32].copy_from_slice(&entry.to_le_bytes());
    f[32..40].copy_from_slice(&64u64.to_le_bytes());
    f[52..54].copy_from_slice(&64u16.to_le_bytes());
    f[54..56].copy_from_slice(&56u16.to_le_bytes());
    f[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
    for (i, &(ty, flags, off, va, fsz, msz)) in phs.iter().enumerate() {
        let p = &mut f[64 + i * 56..][..56];
        p[0..4].copy_from_slice(&ty.to_le_bytes());
        p[4..8].copy_from_slice(&flags.to_le_bytes());
        p[8..16].copy_from_slice(&off.to_le_bytes());
        p[16..24].copy_from_slice(&va.to_le_bytes());
        p[32..40].copy_from_slice(&fsz.to_le_bytes());
        p[40..48].copy_from_slice(&msz.to_le_bytes());
    }
    f
}

fn check(f: &[u8]) -> Result<Program, ElfError> {
    parse(&f[..f.len().min(4096)], f.len() as u64, RANGE)
}

#[test]
fn accepts_a_valid_program() {
    let p = check(&elf(0x40_1010, &phs())).unwrap();
    assert_eq!(p.entry, 0x40_1010);
    let s = p.segments();
    assert_eq!(s.len(), 2, "PT_GNU_STACK ignored");
    assert!(s[0].executable && !s[0].writable);
    assert!(s[1].writable && !s[1].executable);
    assert_eq!(s[1].pages(), 0x40_2000..0x40_5000);
}

#[test]
fn file_part_covers_only_file_bytes() {
    let seg = Segment {
        vaddr: 0x40_1100,
        memsz: 0x2000,
        offset: 0x100,
        filesz: 0x1000,
        writable: false,
        executable: true,
    };
    assert_eq!(seg.pages(), 0x40_1000..0x40_4000);
    assert_eq!(seg.file_part(0x40_1000), Some((0x100..0x1000, 0x100)));
    assert_eq!(seg.file_part(0x40_2000), Some((0..0x100, 0x1000)));
    assert_eq!(seg.file_part(0x40_3000), None, "bss only");
}

#[test]
fn each_problem_is_refused() {
    let good = elf(0x40_1010, &phs());
    let with = |edit: fn(&mut Vec<Ph>)| {
        let mut p = phs();
        edit(&mut p);
        elf(0x40_1010, &p)
    };
    let mut cases: Vec<(&str, Vec<u8>, ElfError)> = Vec::new();
    let mut bytes = |name, at: usize, value: &[u8], err| {
        let mut f = good.clone();
        f[at..at + value.len()].copy_from_slice(value);
        cases.push((name, f, err));
    };
    bytes("magic", 0, b"\x7fELG", ElfError::BadMagic);
    bytes("32-bit class", 4, &[1], ElfError::BadIdent);
    bytes("big-endian", 5, &[2], ElfError::BadIdent);
    bytes("e_version", 20, &[2], ElfError::BadIdent);
    bytes("ET_DYN", 16, &[3, 0], ElfError::NotExecutable);
    bytes("aarch64", 18, &[183, 0], ElfError::WrongMachine);
    bytes("ehsize", 52, &[65, 0], ElfError::BadHeaderSize);
    bytes("phentsize", 54, &[32, 0], ElfError::BadHeaderSize);
    bytes(
        "phoff past the head",
        32,
        &0x1_0000u64.to_le_bytes(),
        ElfError::Truncated,
    );
    bytes(
        "phoff overflows",
        32,
        &u64::MAX.to_le_bytes(),
        ElfError::Truncated,
    );
    bytes(
        "entry in data",
        24,
        &0x40_2000u64.to_le_bytes(),
        ElfError::BadEntry,
    );
    bytes(
        "entry past code",
        24,
        &0x40_1080u64.to_le_bytes(),
        ElfError::BadEntry,
    );
    bytes("no segments", 56, &[0, 0], ElfError::SegmentCount);
    cases.push((
        "interpreter",
        with(|p| p[2].0 = PT_INTERP),
        ElfError::Unsupported { index: 2 },
    ));
    cases.push((
        "dynamic",
        with(|p| p[2].0 = PT_DYNAMIC),
        ElfError::Unsupported { index: 2 },
    ));
    cases.push((
        "TLS",
        with(|p| p[2].0 = PT_TLS),
        ElfError::Unsupported { index: 2 },
    ));
    cases.push((
        "W+X",
        with(|p| p[0].1 |= PF_W),
        ElfError::WritableCode { index: 0 },
    ));
    cases.push((
        "unknown flag",
        with(|p| p[0].1 |= 8),
        ElfError::BadSegment { index: 0 },
    ));
    cases.push((
        "filesz > memsz",
        with(|p| p[1].4 = 0x4000),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "memsz 0",
        with(|p| p[1].5 = 0),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "file range past the end",
        with(|p| p[1].2 = 0x3000),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "offset overflow",
        with(|p| p[1].2 = u64::MAX),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "misaligned offset",
        with(|p| p[1].2 = 0x2008),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "below the range",
        with(|p| p[0].3 = 0x3f_f000),
        ElfError::BadSegment { index: 0 },
    ));
    cases.push((
        "kernel address",
        with(|p| p[1].3 = 0xffff_ffff_8000_0000),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "past the range",
        with(|p| p[1].5 = 0x100_0000),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "vaddr overflow",
        with(|p| p[1].3 = u64::MAX - 0xfff),
        ElfError::BadSegment { index: 1 },
    ));
    cases.push((
        "same page",
        with(|p| {
            p[1].3 = 0x40_1800;
            p[1].2 = 0x1800
        }),
        ElfError::Overlap { index: 1 },
    ));
    cases.push((
        "out of order",
        with(|p| p.swap(0, 1)),
        ElfError::Overlap { index: 1 },
    ));
    cases.push((
        "nine segments",
        {
            let p: Vec<Ph> = (0..9)
                .map(|i| {
                    (
                        PT_LOAD,
                        PF_R | PF_X,
                        0x1000,
                        0x40_1000 + i * 0x1000,
                        0x10,
                        0x10,
                    )
                })
                .collect();
            elf(0x40_1000, &p)
        },
        ElfError::SegmentCount,
    ));
    for (name, f, expected) in &cases {
        assert_eq!(check(f).err(), Some(*expected), "{name}");
    }
    assert_eq!(check(&good[..63]).err(), Some(ElfError::Truncated));
    assert_eq!(
        parse(&good[..100], 50, RANGE).err(),
        Some(ElfError::Truncated),
        "head longer than file"
    );
}

/// xorshift64*: deterministic, no dependencies.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Mutated headers never panic, and whatever passes respects every rule.
#[test]
fn random_mutations_never_panic_and_accepted_programs_follow_the_rules() {
    let good = elf(0x40_1010, &phs());
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut accepted = 0;
    for _ in 0..100_000 {
        let mut f = good.clone();
        for _ in 0..1 + rng.next() % 4 {
            let at = (rng.next() % (64 + 3 * 56)) as usize;
            match rng.next() % 3 {
                0 => f[at] ^= 1 << (rng.next() % 8),
                1 => f[at] = rng.next() as u8,
                _ => {
                    let at = at & !7;
                    f[at..at + 8].copy_from_slice(&rng.next().to_le_bytes());
                }
            }
        }
        let size = if rng.next() % 8 == 0 {
            rng.next() % 0x3000
        } else {
            f.len() as u64
        };
        let head_len = (f.len() as u64).min(size).min(4096) as usize;
        if let Ok(p) = parse(&f[..head_len], size, RANGE) {
            accepted += 1;
            let mut prev = RANGE.start;
            for s in p.segments() {
                assert!(!(s.writable && s.executable));
                assert!(s.filesz <= s.memsz && s.offset + s.filesz <= size);
                assert!(s.vaddr >= RANGE.start && s.vaddr + s.memsz <= RANGE.end);
                assert!(s.pages().start >= prev);
                prev = s.pages().end;
            }
            assert!(
                p.segments()
                    .iter()
                    .any(|s| s.executable && s.vaddr <= p.entry && p.entry < s.vaddr + s.memsz)
            );
        }
    }
    assert!(
        accepted > 100,
        "the mutations must also produce valid programs: {accepted}"
    );
}
