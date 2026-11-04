//! `cargo xtask fs`: build and list Pharos filesystem images (storage.md).

use std::fs;
use std::path::Path;

use pharos_fs::{BLOCK_SIZE, Builder, ENTRY_SIZE, HEADER_SIZE, Image, crc32};

use crate::Result;

/// Packs every regular file under `dir` into an image. Paths are relative
/// to `dir`, with `/` between components. Symbolic links and other special
/// files are refused, so the image matches what a reviewer sees.
pub fn pack(dir: &Path) -> Result<Vec<u8>> {
    pack_with(dir, &[])
}

/// [`pack`] plus `extra` files given as `(path, contents)`.
pub fn pack_with(dir: &Path, extra: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut builder = Builder::new();
    add_dir(&mut builder, dir, "")?;
    for (path, data) in extra {
        builder
            .add(path.as_bytes(), data)
            .map_err(|e| format!("{path}: {e}"))?;
    }
    builder
        .build()
        .map_err(|e| format!("cannot build an image from {}: {e}", dir.display()))
}

fn add_dir(builder: &mut Builder, dir: &Path, prefix: &str) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("{}: name is not UTF-8: {n:?}", dir.display()))?;
        let image_path = format!("{prefix}{name}");
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if kind.is_dir() {
            add_dir(builder, &path, &format!("{image_path}/"))?;
        } else if kind.is_file() {
            let data =
                fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            builder
                .add(image_path.as_bytes(), &data)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        } else {
            return Err(format!(
                "{}: only regular files and directories can go into an image",
                path.display()
            ));
        }
    }
    Ok(())
}

/// `cargo xtask fs build <dir> <image>`.
pub fn build(dir: &Path, image: &Path) -> Result<()> {
    let bytes = pack(dir)?;
    fs::write(image, &bytes).map_err(|e| format!("cannot write {}: {e}", image.display()))?;
    println!("Image: {} ({} bytes)", image.display(), bytes.len());
    Ok(())
}

/// `cargo xtask fs ls <image>`: mounts with the kernel's parser and lists
/// every file. Fails with the parser's reason on a corrupt image.
pub fn ls(image: &Path) -> Result<()> {
    let bytes = fs::read(image).map_err(|e| format!("cannot read {}: {e}", image.display()))?;
    let fs = Image::mount(&bytes[..]).map_err(|e| format!("{}: {e}", image.display()))?;
    println!("{:>10}  {:<8}  path", "size", "crc32");
    for file in fs.entries() {
        println!(
            "{:>10}  {:08x}  {}",
            file.size,
            file.crc,
            String::from_utf8_lossy(file.path)
        );
    }
    Ok(())
}

/// The filesystem image test kernels read (`fs-good`). Must match
/// `kernel/tests/fs.rs`. Entries in path order: 0 `a-b`, 1 `dir/big.bin`,
/// 2 `dir/empty`, 3 `hello.txt`.
pub fn good_test_image() -> Vec<u8> {
    let mut b = Builder::new();
    let big: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    for (path, data) in [
        (
            &b"hello.txt"[..],
            &b"Hello from the Pharos filesystem.\n"[..],
        ),
        (b"dir/empty", b""),
        (b"dir/big.bin", &big),
        (b"a-b", b"x"),
    ] {
        b.add(path, data).expect("valid test file");
    }
    b.build().expect("test image fits")
}

/// Recomputes the directory and header checksums after an edit, so the
/// edit reaches the checks behind them.
fn reseal(img: &mut [u8]) {
    let n = u32::from_le_bytes(img[12..16].try_into().expect("4 bytes")) as usize;
    let dir_end = (HEADER_SIZE + n * ENTRY_SIZE).min(img.len());
    let dir_crc = crc32(&img[HEADER_SIZE..dir_end]);
    img[24..28].copy_from_slice(&dir_crc.to_le_bytes());
    let header_crc = crc32(&img[..60]);
    img[60..64].copy_from_slice(&header_crc.to_le_bytes());
}

fn entry(img: &mut [u8], i: usize) -> &mut [u8] {
    &mut img[HEADER_SIZE + i * ENTRY_SIZE..][..ENTRY_SIZE]
}

/// Corrupted copies of [`good_test_image`], one per check in storage.md,
/// named `fs-<check>`. Must match `kernel/tests/fs.rs`.
pub fn corrupt_test_images() -> Vec<(&'static str, Vec<u8>)> {
    type Edit = fn(&mut Vec<u8>);
    let edits: [(&'static str, Edit); 12] = [
        ("fs-magic", |i| i[0] = b'X'),
        ("fs-version", |i| {
            i[8] = 2;
            reseal(i)
        }),
        ("fs-header-crc", |i| i[16] ^= 1),
        ("fs-entry-count", |i| {
            i[12..16].copy_from_slice(&1025u32.to_le_bytes());
            reseal(i)
        }),
        ("fs-image-size", |i| {
            let size = i.len() as u64 + BLOCK_SIZE as u64;
            i[16..24].copy_from_slice(&size.to_le_bytes());
            reseal(i)
        }),
        ("fs-dir-crc", |i| entry(i, 0)[30] ^= 1),
        ("fs-path", |i| {
            entry(i, 0)[24] = b' ';
            reseal(i)
        }),
        ("fs-order", |i| {
            // "dir/empty" -> "aaaaaaaaa": now before "dir/big.bin".
            entry(i, 2)[24..33].copy_from_slice(b"aaaaaaaaa");
            reseal(i)
        }),
        ("fs-overlap", |i| {
            let first = entry(i, 0)[0..8].to_vec();
            entry(i, 1)[0..8].copy_from_slice(&first);
            reseal(i)
        }),
        ("fs-range", |i| {
            let len = i.len() as u64;
            entry(i, 3)[8..16].copy_from_slice(&len.to_le_bytes());
            reseal(i)
        }),
        ("fs-file-crc", |i| {
            let at = u64::from_le_bytes(entry(i, 1)[0..8].try_into().expect("8 bytes")) as usize;
            i[at + 1000] ^= 1;
        }),
        ("fs-truncated", |i| i.truncate(BLOCK_SIZE)),
    ];
    let good = good_test_image();
    edits
        .into_iter()
        .map(|(name, edit)| {
            let mut img = good.clone();
            edit(&mut img);
            (name, img)
        })
        .collect()
}

/// Malformed copies of a program, named `bad/<problem>`, for the loader
/// tests. Must match `kernel/tests/user_elf.rs`. `elf` must be a valid
/// program whose first program header is a `PT_LOAD` and whose header
/// table ends past byte 100.
pub fn bad_programs(elf: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let phoff = u64::from_le_bytes(elf[32..40].try_into().expect("8 bytes")) as usize;
    let with = |at: usize, bytes: &[u8]| {
        let mut f = elf.to_vec();
        f[at..at + bytes.len()].copy_from_slice(bytes);
        f
    };
    vec![
        ("bad/magic", with(1, b"X")),
        ("bad/class", with(4, &[1])),
        ("bad/type", with(16, &3u16.to_le_bytes())),
        ("bad/machine", with(18, &183u16.to_le_bytes())),
        ("bad/entry", with(24, &0x10u64.to_le_bytes())),
        ("bad/interp", with(phoff, &3u32.to_le_bytes())),
        ("bad/wx", with(phoff + 4, &7u32.to_le_bytes())),
        (
            "bad/kernel",
            with(phoff + 16, &0xffff_ffff_8000_0000u64.to_le_bytes()),
        ),
        ("bad/truncated", elf[..100].to_vec()),
        ("bad/empty", Vec::new()),
    ]
}

/// The filesystem image of programs the tests use (`programs`): every
/// program in `programs` (`bin/<name>`), and every [`bad_programs`] copy of
/// `bin/hello`.
/// The `agents` test kernels' manifests (#98, #99): `worker` and `counter`
/// within their policy entries, `greedy` asking for more pages than its
/// entry allows, `noentry`, which has no entry, and `keeper`, the
/// `permissions` kernel's, which may write its own files (#105), and
/// `asker`, which gets nothing and asks (#106), the `budgets` kernel's
/// five (#116), and the `fairness` kernel's four (#117).
pub const TEST_MANIFESTS: [(&str, &str); 18] = [
    (
        "agents/worker.manifest",
        "# The agents test kernel's worker.\nmanifest = 1\nname = worker\nprogram = bin/testagent\n\
         pages = 256\nmodels = 2\nattempts = 3\nprogress_ms = 2000\ntask_ms = 20000\ndata = none\nnet =\n",
    ),
    (
        "agents/greedy.manifest",
        "manifest = 1\nname = greedy\nprogram = bin/testagent\npages = 128\nmodels =\n\
         attempts = 1\nprogress_ms = 2000\ntask_ms = 20000\ndata = none\nnet =\n",
    ),
    (
        "agents/counter.manifest",
        "manifest = 1\nname = counter\nprogram = bin/testagent\npages = 64\nmodels =\n\
         attempts = 10\nprogress_ms = 5000\ntask_ms = 120000\ndata = none\nnet =\n",
    ),
    (
        "agents/noentry.manifest",
        "manifest = 1\nname = noentry\nprogram = bin/testagent\npages = 64\nmodels =\n\
         attempts = 1\nprogress_ms = 2000\ntask_ms = 20000\ndata = none\nnet =\n",
    ),
    (
        "agents/keeper.manifest",
        "manifest = 1\nname = keeper\nprogram = bin/testagent\npages = 256\nmodels = 2\n\
         attempts = 2\nprogress_ms = 5000\ntask_ms = 60000\ndata = write\nnet =\n",
    ),
    (
        "agents/asker.manifest",
        "manifest = 1\nname = asker\nprogram = bin/testagent\npages = 256\nmodels =\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 60000\ndata = none\nnet =\n",
    ),
    (
        "agents/netter.manifest",
        "manifest = 1\nname = netter\nprogram = bin/testagent\npages = 256\nmodels =\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 60000\ndata = none\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/listener.manifest",
        "manifest = 1\nname = listener\nprogram = bin/testagent\npages = 256\nmodels =\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 60000\ndata = none\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/hostile.manifest",
        "manifest = 1\nname = hostile\nprogram = bin/testagent\npages = 256\nmodels =\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 60000\ndata = write\nnet =\n",
    ),
    // The `budgets` kernel's (#116), each its policy entry's whole.
    (
        "agents/spender.manifest",
        "manifest = 1\nname = spender\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/grouper.manifest",
        "manifest = 1\nname = grouper\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/hog.manifest",
        "manifest = 1\nname = hog\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/pair.manifest",
        "manifest = 1\nname = pair\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/big.manifest",
        "manifest = 1\nname = big\nprogram = bin/testagent\npages = 256\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    // The `fairness` kernel's (#117).
    (
        "agents/flooder.manifest",
        "manifest = 1\nname = flooder\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/ticker.manifest",
        "manifest = 1\nname = ticker\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/rater.manifest",
        "manifest = 1\nname = rater\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
    (
        "agents/queuer.manifest",
        "manifest = 1\nname = queuer\nprogram = bin/testagent\npages = 64\nmodels = 2\n\
         attempts = 1\nprogress_ms = 10000\ntask_ms = 30000\ndata = write\nnet = 10.0.2.2:47000\n",
    ),
];

pub fn program_test_image(programs: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut b = Builder::new();
    for (path, bytes) in programs {
        b.add(path.as_bytes(), bytes).expect("valid path");
    }
    for (path, text) in TEST_MANIFESTS {
        b.add(path.as_bytes(), text.as_bytes()).expect("valid path");
    }
    if let Some((_, hello)) = programs.iter().find(|(p, _)| p == "bin/hello") {
        for (path, bytes) in bad_programs(hello) {
            b.add(path.as_bytes(), &bytes).expect("valid path");
        }
    }
    b.build().expect("program test image fits")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The smallest valid program: one read + execute segment.
    pub(crate) fn tiny_elf() -> Vec<u8> {
        let mut f = vec![0u8; 0x1010];
        f[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&62u16.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&0x40_1000u64.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&1u16.to_le_bytes());
        let p = &mut f[64..120];
        p[0..4].copy_from_slice(&1u32.to_le_bytes());
        p[4..8].copy_from_slice(&5u32.to_le_bytes());
        p[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        p[16..24].copy_from_slice(&0x40_1000u64.to_le_bytes());
        p[32..40].copy_from_slice(&0x10u64.to_le_bytes());
        p[40..48].copy_from_slice(&0x10u64.to_le_bytes());
        f
    }

    #[test]
    fn bad_programs_fail_with_the_expected_error() {
        use pharos_elf::ElfError::*;
        let check = |f: &[u8]| {
            pharos_elf::parse(
                &f[..f.len().min(4096)],
                f.len() as u64,
                0x40_0000..0x140_0000,
            )
        };
        let good = tiny_elf();
        assert!(check(&good).is_ok());
        let expected = [
            ("bad/magic", Some(BadMagic)),
            ("bad/class", Some(BadIdent)),
            ("bad/type", Some(NotExecutable)),
            ("bad/machine", Some(WrongMachine)),
            ("bad/entry", Some(BadEntry)),
            ("bad/interp", Some(Unsupported { index: 0 })),
            ("bad/wx", Some(WritableCode { index: 0 })),
            ("bad/kernel", Some(BadSegment { index: 0 })),
            ("bad/truncated", Some(Truncated)),
            ("bad/empty", None), // refused by the kernel before parsing
        ];
        let bad = bad_programs(&good);
        assert_eq!(bad.len(), expected.len());
        for ((name, bytes), (want_name, want)) in bad.iter().zip(expected) {
            assert_eq!(*name, want_name);
            if let Some(want) = want {
                assert_eq!(check(bytes).err(), Some(want), "{name}");
            }
        }
        let programs = [("bin/hello".to_owned(), good.clone())];
        let image = Image::mount(&program_test_image(&programs)[..]).map(|i| i.entries().count());
        // The program, its bad copies, and the agents test kernel's manifests.
        assert_eq!(image, Ok(11 + TEST_MANIFESTS.len()));
    }

    #[test]
    fn test_images_mount_or_fail_as_expected() {
        use pharos_fs::FsError::*;
        let good = good_test_image();
        assert!(good.len() > 2 * BLOCK_SIZE, "big.bin spans blocks");
        let image = Image::mount(&good[..]).unwrap();
        assert_eq!(image.entries().count(), 4);
        let expected = [
            ("fs-magic", BadMagic),
            ("fs-version", BadVersion(2)),
            ("fs-header-crc", HeaderCrc),
            ("fs-entry-count", TooManyEntries(1025)),
            ("fs-image-size", DeviceTooSmall),
            ("fs-dir-crc", DirCrc),
            ("fs-path", EntryPath { index: 0 }),
            ("fs-order", EntryOrder { index: 2 }),
            ("fs-overlap", EntryRange { index: 1 }),
            ("fs-range", EntryRange { index: 3 }),
            ("fs-file-crc", FileCrc { index: 1 }),
            ("fs-truncated", DeviceTooSmall),
        ];
        let images = corrupt_test_images();
        assert_eq!(images.len(), expected.len());
        for ((name, bytes), (want_name, want)) in images.iter().zip(expected) {
            assert_eq!(*name, want_name);
            assert_eq!(Image::mount(&bytes[..]).err(), Some(want), "{name}");
        }
    }

    #[test]
    fn packs_a_directory_tree() {
        let dir = std::env::temp_dir().join(format!("pharos-fs-pack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc/deep")).unwrap();
        fs::write(dir.join("etc/motd"), b"hello\n").unwrap();
        fs::write(dir.join("etc/deep/x"), b"").unwrap();
        fs::write(dir.join("top"), b"t").unwrap();
        let bytes = pack(&dir).unwrap();
        let image = Image::mount(&bytes[..]).unwrap();
        let paths: Vec<_> = image.entries().map(|f| f.path.to_vec()).collect();
        assert_eq!(paths, [&b"etc/deep/x"[..], b"etc/motd", b"top"]);
        assert_eq!(pack(&dir).unwrap(), bytes, "reproducible");

        fs::write(dir.join("bad name"), b"").unwrap();
        let err = pack(&dir).unwrap_err();
        assert!(
            err.contains("bad name") && err.contains("invalid path"),
            "{err}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
