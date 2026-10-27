use super::*;
use std::vec::Vec;

fn sample() -> Vec<u8> {
    let mut b = Builder::new();
    b.add(b"etc/motd", b"Welcome to Pharos OS\n").unwrap();
    b.add(b"empty", b"").unwrap();
    b.add(b"bin/big", &[0xA5; 1500]).unwrap();
    b.add(b"a-b", b"x").unwrap();
    b.build().unwrap()
}

/// Recomputes the directory and header checksums after an edit, so a test
/// reaches the checks behind them.
fn reseal(img: &mut [u8]) {
    let n = u32_at(img, 12) as usize;
    let dir_end = (HEADER_SIZE + n * ENTRY_SIZE).min(img.len());
    let dir_crc = crc32(&img[HEADER_SIZE..dir_end]);
    img[24..28].copy_from_slice(&dir_crc.to_le_bytes());
    let header_crc = crc32(&img[..60]);
    img[60..64].copy_from_slice(&header_crc.to_le_bytes());
}

fn entry(img: &mut [u8], i: usize) -> &mut [u8] {
    &mut img[HEADER_SIZE + i * ENTRY_SIZE..][..ENTRY_SIZE]
}

fn mount(img: &[u8]) -> Result<Image<&[u8]>, FsError> {
    Image::mount(img)
}

#[test]
fn crc32_matches_known_values() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(
        crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
}

#[test]
fn round_trip() {
    let img = sample();
    assert_eq!(img.len() % BLOCK_SIZE, 0);
    let fs = mount(&img).unwrap();
    let paths: Vec<&[u8]> = fs.entries().map(|e| e.path).collect();
    assert_eq!(
        paths,
        [&b"a-b"[..], b"bin/big", b"empty", b"etc/motd"],
        "sorted by path"
    );
    let motd = fs.lookup(b"etc/motd").unwrap();
    let mut buf = [0u8; 64];
    let n = fs.read(motd, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"Welcome to Pharos OS\n");
    assert_eq!(fs.read(motd, 11, &mut buf).unwrap(), 10, "offset read");
    assert_eq!(&buf[..10], b"Pharos OS\n");
    assert_eq!(fs.read(motd, 21, &mut buf).unwrap(), 0, "end of file");
    assert_eq!(fs.read(motd, u64::MAX, &mut buf).unwrap(), 0);

    let big = fs.lookup(b"bin/big").unwrap();
    assert_eq!(fs.size(big), Ok(1500));
    let mut all = std::vec![0u8; 2000];
    assert_eq!(fs.read(big, 0, &mut all).unwrap(), 1500);
    assert!(all[..1500].iter().all(|&b| b == 0xA5));
    let mut small = [0u8; 3];
    assert_eq!(
        fs.read(big, 1498, &mut small).unwrap(),
        2,
        "short read at the end"
    );

    let empty = fs.lookup(b"empty").unwrap();
    assert_eq!(fs.read(empty, 0, &mut buf).unwrap(), 0);
}

#[test]
fn builds_are_reproducible_and_order_independent() {
    let mut b = Builder::new();
    b.add(b"a-b", b"x").unwrap();
    b.add(b"bin/big", &[0xA5; 1500]).unwrap();
    b.add(b"etc/motd", b"Welcome to Pharos OS\n").unwrap();
    b.add(b"empty", b"").unwrap();
    assert_eq!(b.build().unwrap(), sample());
}

#[test]
fn empty_image_mounts() {
    let img = Builder::new().build().unwrap();
    assert_eq!(img.len(), BLOCK_SIZE);
    let fs = mount(&img).unwrap();
    assert_eq!(fs.entries().count(), 0);
    assert_eq!(fs.lookup(b"x"), Err(FsError::NotFound));
}

#[test]
fn lookup_edge_cases() {
    let long = [b'a'; MAX_PATH];
    let deep: Vec<u8> = b"a/"
        .repeat(MAX_PATH / 2 - 1)
        .into_iter()
        .chain(*b"zz")
        .collect();
    assert_eq!(deep.len(), MAX_PATH);
    let mut b = Builder::new();
    b.add(&long, b"long").unwrap();
    b.add(&deep, b"deep").unwrap();
    let img = b.build().unwrap();
    let fs = mount(&img).unwrap();
    let mut buf = [0u8; 8];
    let n = fs.read(fs.lookup(&long).unwrap(), 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"long");
    let n = fs.read(fs.lookup(&deep).unwrap(), 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"deep");
    for missing in [
        &b""[..],
        b"a",
        b"a/",
        b"/aaa",
        b"../x",
        &[b'a'; MAX_PATH + 1],
    ] {
        assert_eq!(fs.lookup(missing), Err(FsError::NotFound), "{missing:?}");
    }
    assert_eq!(fs.size(FileId(99)), Err(FsError::BadFile));
}

#[test]
fn path_rules() {
    for ok in [&b"a"[..], b"a/b", b"A.z_9-x/y", b"...", b".hidden"] {
        assert!(valid_path(ok), "{ok:?}");
    }
    for bad in [
        &b""[..],
        b"/a",
        b"a/",
        b"a//b",
        b".",
        b"a/./b",
        b"a/..",
        b"a b",
        b"a\0",
        b"\xff",
        b"a\\b",
        &[b'a'; MAX_PATH + 1],
    ] {
        assert!(!valid_path(bad), "{bad:?}");
    }
}

#[test]
fn builder_refuses_bad_input() {
    let mut b = Builder::new();
    assert_eq!(b.add(b"/abs", b""), Err(BuildError::BadPath));
    b.add(b"x", b"1").unwrap();
    b.add(b"x", b"2").unwrap();
    assert_eq!(b.build(), Err(BuildError::Duplicate));

    let mut b = Builder::new();
    b.add(b"a", b"").unwrap();
    b.add(b"a-1", b"").unwrap();
    b.add(b"a/b", b"").unwrap();
    assert_eq!(b.build(), Err(BuildError::PathIsDirectory));

    let mut b = Builder::new();
    for i in 0..MAX_ENTRIES {
        b.add(std::format!("f{i}").as_bytes(), b"").unwrap();
    }
    assert_eq!(b.add(b"one-more", b""), Err(BuildError::TooManyFiles));
    assert!(b.build().is_ok(), "1024 files fit");

    let mut b = Builder::new();
    b.add(b"huge", &std::vec![0; MAX_IMAGE as usize]).unwrap();
    assert_eq!(b.build(), Err(BuildError::TooLarge));
}

#[test]
fn each_corruption_is_rejected_with_its_error() {
    let good = sample();
    // Entry indexes in sorted order: 0 a-b, 1 bin/big, 2 empty, 3 etc/motd.
    type Edit = fn(&mut Vec<u8>);
    let cases: &[(&str, Edit, FsError)] = &[
        ("bad magic", |i| i[0] = b'X', FsError::BadMagic),
        (
            "bad version",
            |i| {
                i[8] = 2;
                reseal(i)
            },
            FsError::BadVersion(2),
        ),
        ("header crc", |i| i[16] ^= 1, FsError::HeaderCrc),
        (
            "header reserved",
            |i| {
                i[40] = 1;
                reseal(i)
            },
            FsError::HeaderReserved,
        ),
        (
            "too many entries",
            |i| {
                i[12..16].copy_from_slice(&1025u32.to_le_bytes());
                reseal(i)
            },
            FsError::TooManyEntries(1025),
        ),
        (
            "image size not whole blocks",
            |i| {
                i[16..24].copy_from_slice(&1000u64.to_le_bytes());
                reseal(i)
            },
            FsError::BadImageSize(1000),
        ),
        (
            "image size larger than the device",
            |i| {
                let s = i.len() as u64 + 512;
                i[16..24].copy_from_slice(&s.to_le_bytes());
                reseal(i)
            },
            FsError::DeviceTooSmall,
        ),
        (
            "truncated image",
            |i| i.truncate(1024),
            FsError::DeviceTooSmall,
        ),
        ("dir crc", |i| entry(i, 0)[30] ^= 1, FsError::DirCrc),
        (
            "bad path byte",
            |i| {
                entry(i, 0)[24] = b' ';
                reseal(i)
            },
            FsError::EntryPath { index: 0 },
        ),
        (
            "path length zero",
            |i| {
                entry(i, 1)[20] = 0;
                reseal(i)
            },
            FsError::EntryPath { index: 1 },
        ),
        (
            "path length too long",
            |i| {
                entry(i, 1)[20] = 105;
                reseal(i)
            },
            FsError::EntryPath { index: 1 },
        ),
        (
            "entry reserved",
            |i| {
                entry(i, 2)[22] = 1;
                reseal(i)
            },
            FsError::EntryReserved { index: 2 },
        ),
        (
            "path padding",
            |i| {
                entry(i, 2)[127] = b'x';
                reseal(i)
            },
            FsError::EntryReserved { index: 2 },
        ),
        (
            "unsorted",
            |i| {
                // "empty" -> "aaaaa": now before "bin/big".
                entry(i, 2)[24..29].copy_from_slice(b"aaaaa");
                reseal(i)
            },
            FsError::EntryOrder { index: 2 },
        ),
        (
            "duplicate",
            |i| {
                let first: Vec<u8> = entry(i, 0)[20..].to_vec();
                entry(i, 1)[20..].copy_from_slice(&first);
                reseal(i)
            },
            FsError::EntryOrder { index: 1 },
        ),
        (
            "path also a directory",
            |i| {
                // "bin/big" -> "a-b/ig": "a-b" is now a directory too.
                entry(i, 1)[24..31].copy_from_slice(b"a-b/ig\0");
                entry(i, 1)[20] = 6;
                reseal(i)
            },
            FsError::EntryPrefix { index: 0 },
        ),
        (
            "overlapping data",
            |i| {
                let prev = u64_at(entry(i, 0), 0);
                entry(i, 1)[0..8].copy_from_slice(&prev.to_le_bytes());
                reseal(i)
            },
            FsError::EntryRange { index: 1 },
        ),
        (
            "data inside the directory",
            |i| {
                entry(i, 0)[0..8].copy_from_slice(&64u64.to_le_bytes());
                reseal(i)
            },
            FsError::EntryRange { index: 0 },
        ),
        (
            "data past the image",
            |i| {
                let len = i.len() as u64;
                entry(i, 3)[8..16].copy_from_slice(&len.to_le_bytes());
                reseal(i)
            },
            FsError::EntryRange { index: 3 },
        ),
        (
            "size overflows",
            |i| {
                entry(i, 3)[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
                reseal(i)
            },
            FsError::EntryRange { index: 3 },
        ),
        (
            "file crc",
            |i| {
                let at = u64_at(entry(i, 1), 0) as usize;
                i[at + 700] ^= 1;
            },
            FsError::FileCrc { index: 1 },
        ),
    ];
    for (name, edit, expected) in cases {
        let mut img = good.clone();
        edit(&mut img);
        assert_eq!(mount(&img).err(), Some(*expected), "{name}");
    }
    assert_eq!(mount(&[]).err(), Some(FsError::DeviceTooSmall));
    assert_eq!(mount(&good[..511]).err(), Some(FsError::DeviceTooSmall));
}

#[test]
fn slice_device_checks_reads() {
    let disk = [7u8; 1100]; // two whole blocks, tail ignored
    assert_eq!(disk[..].block_count(), 2);
    let mut buf = [0u8; 1024];
    assert_eq!(disk[..].read(0, &mut buf), Ok(()));
    assert_eq!(disk[..].read(1, &mut buf), Err(BlockError::OutOfRange));
    assert_eq!(
        disk[..].read(u64::MAX, &mut buf[..512]),
        Err(BlockError::OutOfRange)
    );
    assert_eq!(
        disk[..].read(0, &mut buf[..100]),
        Err(BlockError::BadLength)
    );
    assert_eq!(disk[..].read(0, &mut []), Err(BlockError::BadLength));
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

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Mutated images never panic the parser, and whatever mounts reads back
/// within bounds. Half the cases reseal the checksums so the mutations
/// reach the entry checks instead of stopping at a CRC.
#[test]
fn random_mutations_never_panic() {
    let good = sample();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut mounted, mut rejected) = (0u32, 0u32);
    for round in 0..100_000 {
        let mut img = good.clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(img.len().min(HEADER_SIZE + 4 * ENTRY_SIZE + 64));
            match rng.below(4) {
                0 => img[at] ^= 1 << rng.below(8),
                1 => img[at] = rng.next() as u8,
                2 => {
                    // A random 64-bit value over an offset or size field.
                    let at = at & !7;
                    if at + 8 <= img.len() {
                        img[at..at + 8].copy_from_slice(&rng.next().to_le_bytes());
                    }
                }
                _ => img[at] = 0,
            }
        }
        if rng.below(10) == 0 {
            let keep = rng.below(img.len() + 1);
            img.truncate(keep);
        }
        if round % 2 == 0 && img.len() >= HEADER_SIZE {
            reseal(&mut img);
        }
        match mount(&img) {
            Ok(fs) => {
                mounted += 1;
                let mut buf = [0u8; 2048];
                let infos: Vec<(Vec<u8>, u64)> =
                    fs.entries().map(|e| (e.path.to_vec(), e.size)).collect();
                for (path, size) in infos {
                    let id = fs.lookup(&path).unwrap();
                    let n = fs.read(id, 0, &mut buf).unwrap();
                    assert_eq!(n as u64, size.min(buf.len() as u64));
                }
            }
            Err(_) => rejected += 1,
        }
    }
    assert!(
        mounted > 0 && rejected > 50_000,
        "{mounted} mounted, {rejected} rejected"
    );
}
