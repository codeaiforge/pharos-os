//! Test kernel: the kernel mounts filesystem images from boot modules and
//! reads files; every corrupted image is rejected with its reason while the
//! kernel keeps running (issue #47). The images come from `cargo xtask`
//! (`good_test_image`, `corrupt_test_images`). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;

use pharos_fs::FsError::{self, *};
use pharos_kernel::arch::x86_64::{gdt, idt};
use pharos_kernel::fs::{self, MountError};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm, storage};

pharos_kernel::test_kernel!(run);

/// Each corrupted image and the error it must give. Must match `xtask`.
const CORRUPT: [(&str, FsError); 12] = [
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

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    t.check("frame allocator and kernel page tables set up", memory);
    let Some(hhdm) = requests::HHDM.response() else {
        return;
    };
    if !memory {
        return;
    }
    storage::record_modules(requests::MODULES.response(), hhdm.offset);
    t.check("heap set up", mm::init_heap().is_ok());

    // The good image.
    let Ok(good) = fs::mount("fs-good") else {
        t.check("good image mounts", false);
        return;
    };
    t.check("good image mounts", true);
    let paths: vec::Vec<&[u8]> = good.entries().map(|e| e.path).collect();
    t.check(
        "four files in path order",
        paths == [&b"a-b"[..], b"dir/big.bin", b"dir/empty", b"hello.txt"],
    );
    let mut buf = vec![0u8; 4096];
    let hello = good.lookup(b"hello.txt");
    let n = hello.and_then(|f| good.read(f, 0, &mut buf));
    t.check(
        "hello.txt reads back",
        n.is_ok_and(|n| &buf[..n] == b"Hello from the Pharos filesystem.\n"),
    );
    let big = good.lookup(b"dir/big.bin");
    let n = big.and_then(|f| good.read(f, 0, &mut buf));
    t.check(
        "dir/big.bin: 3000 bytes across blocks, every byte",
        n == Ok(3000)
            && buf[..3000]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i % 251) as u8),
    );
    let n = big.and_then(|f| good.read(f, 2990, &mut buf));
    t.check(
        "dir/big.bin: read at an offset stops at the end",
        n == Ok(10)
            && buf[..10]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == ((2990 + i) % 251) as u8),
    );
    let empty = good.lookup(b"dir/empty");
    t.check(
        "dir/empty: size 0, reads nothing",
        empty.and_then(|f| good.size(f)) == Ok(0)
            && empty.and_then(|f| good.read(f, 0, &mut buf)) == Ok(0),
    );
    t.check(
        "missing and invalid paths are not found",
        [&b"dir"[..], b"hello", b"/hello.txt", b"dir/../a-b", b""]
            .iter()
            .all(|p| good.lookup(p) == Err(NotFound)),
    );
    t.check(
        "no module: mount refused",
        fs::mount("missing").err() == Some(MountError::NoModule),
    );

    // Every corrupted image is rejected with its own reason.
    let heap_before = mm::heap_stats().used;
    for (name, expected) in CORRUPT {
        let result = fs::mount(name).err();
        if result != Some(MountError::Fs(expected)) {
            kprintln!("  {name}: got {result:?}");
        }
        let label = alloc::format!("{name}: rejected with {expected:?}");
        t.check(&label, result == Some(MountError::Fs(expected)));
    }
    t.check(
        "rejected mounts leave no heap memory behind",
        mm::heap_stats().used == heap_before,
    );
    t.check(
        "the good image still reads after the rejections",
        hello
            .and_then(|f| good.read(f, 0, &mut buf))
            .is_ok_and(|n| n == 34),
    );
}
