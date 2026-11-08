//! Mounts images for the `fsmount` test kernel (#163, boot.md section 8).
//!
//! Started with handles 1 the debug console (`WRITE`), 2 a filesystem with
//! `READ | GRANT | MOUNT`, and 3 the same filesystem with `READ` only. It
//! builds two small images in a shared buffer and mounts them with
//! `fs_mount`. Each step prints `ok <step>` or `FAIL <step>`; the exit
//! code is the number of failures. It then waits 10 s with both images
//! mounted, so the kernel can count the copies, and exits.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use pharos_user::{Error, Handle, debug_write, delete, fs_mount, mem_map_buffer, mem_share, open};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const MOUNT: Handle = 2;
const READ_ONLY: Handle = 3;
/// The shared buffer: 8 pages.
const BUFFER: u64 = 8 * 4096;
/// Where the second image starts in it, as after a slot's 128-byte header.
const AT: u64 = 128;

fn report(failures: &mut u64, step: &str, ok: bool) {
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let _ = debug_write(CONSOLE, &[prefix, step.as_bytes()].concat());
    if !ok {
        *failures += 1;
    }
}

/// An image with one file, `hello`, holding `text`.
fn image(text: &[u8]) -> Vec<u8> {
    let mut b = pharos_fs::Builder::new();
    let _ = b.add(b"hello", text);
    b.build().unwrap_or_default()
}

/// What `hello` holds in the filesystem behind `fs`.
fn hello(fs: Handle) -> Option<Vec<u8>> {
    let file = open(fs, b"hello").ok()?;
    let mut buf = [0u8; 16];
    let n = pharos_user::read(file, 0, &mut buf).ok();
    let _ = delete(file);
    Some(buf[..n?].to_vec())
}

fn main(_: u64) -> u64 {
    let mut failures = 0;
    let (first, second) = (image(b"first"), image(b"second"));
    let Ok(buffer) = mem_map_buffer(BUFFER) else {
        report(&mut failures, "map the buffer", false);
        return failures;
    };
    buffer.write_bytes(0, &first);
    let Ok(memory) = mem_share(buffer.addr(), BUFFER) else {
        report(&mut failures, "share the buffer", false);
        return failures;
    };
    let len = first.len() as u64;

    let refused = fs_mount(READ_ONLY, memory, 0, len);
    report(
        &mut failures,
        "without MOUNT: missing right",
        refused == Err(Error::MissingRight),
    );
    let a = fs_mount(MOUNT, memory, 0, len);
    report(&mut failures, "mount an image", a.is_ok());
    let a = a.unwrap_or(0);
    report(
        &mut failures,
        "read its file",
        hello(a).as_deref() == Some(b"first"),
    );

    // The caller changes its buffer: the mounted copy keeps the old bytes.
    buffer.write_bytes(0, &second);
    report(
        &mut failures,
        "a changed buffer leaves the mount unchanged",
        hello(a).as_deref() == Some(b"first"),
    );

    // A changed byte in the directory fails the checks.
    let mut bad = first.clone();
    bad[64] ^= 1;
    buffer.write_bytes(0, &bad);
    report(
        &mut failures,
        "a corrupt image: bad image",
        fs_mount(MOUNT, memory, 0, len) == Err(Error::BadImage),
    );
    report(
        &mut failures,
        "17 MiB: too large",
        fs_mount(MOUNT, memory, 0, 17 << 20) == Err(Error::TooLarge),
    );
    report(
        &mut failures,
        "past the buffer's end: too large",
        fs_mount(MOUNT, memory, BUFFER - 512, 1024) == Err(Error::TooLarge),
    );

    // At an offset that is no page boundary.
    buffer.write_bytes(AT as usize, &second);
    let b = fs_mount(MOUNT, memory, AT, second.len() as u64);
    report(
        &mut failures,
        "mount a second image at offset 128",
        b.is_ok(),
    );
    let b = b.unwrap_or(0);
    report(
        &mut failures,
        "read the second image's file",
        hello(b).as_deref() == Some(b"second"),
    );
    report(
        &mut failures,
        "a third mount: no memory",
        fs_mount(MOUNT, memory, AT, second.len() as u64) == Err(Error::NoMemory),
    );

    // A mount ends with its last capability.
    let _ = delete(a);
    let c = fs_mount(MOUNT, memory, AT, second.len() as u64);
    report(
        &mut failures,
        "after one is deleted, another mounts",
        c.is_ok() && hello(c.unwrap_or(0)).as_deref() == Some(b"second"),
    );

    // Each freed copy gives its pages back (#167, F1): 20 mounts would
    // take about 140 of its 64 pages if they were kept.
    let mut c = c.unwrap_or(0);
    let mut again = true;
    for _ in 0..20 {
        let _ = delete(c);
        match fs_mount(MOUNT, memory, AT, second.len() as u64) {
            Ok(h) => c = h,
            Err(_) => again = false,
        }
    }
    report(
        &mut failures,
        "a copy's pages come back: 20 more mounts in turn",
        again && hello(c).as_deref() == Some(b"second"),
    );
    report(&mut failures, "done", true);
    pharos_user::sleep(10_000_000);
    failures
}
