//! The virtio-blk driver (issue #56, drivers.md), as its first service:
//! it reads the disk through its own virtqueue, mounts the `pharos-fs`
//! image on it with the same parser as the kernel, and reports a file.
//!
//! Handles: 1 debug console, 2 the device (`MAP | CONFIG | IRQ`). With
//! argument 1 the driver crashes on purpose (a stack overflow) while a
//! request is in flight, so tests can check that a dying driver leaves its
//! device stopped. With argument 2 (a hot-added disk, M4.4) it checks the
//! image as below, then sends `ready` on handle 3 (its report capability)
//! and keeps the device until it is stopped. Exit codes:
//!
//! | Code | Meaning |
//! | --- | --- |
//! | 0 | The image mounted and its files read back correctly |
//! | 1 | Not a virtio-blk device |
//! | 2 | Interrupt or device setup failed (the device is left `FAILED`) |
//! | 3 | A read failed |
//! | 4 | The image did not mount |
//! | 5 | A file is missing or its contents are wrong |
//! | 6 | Argument 2: `ready` could not be sent |

#![no_std]
#![no_main]

use core::cell::RefCell;

use pharos_fs::{BLOCK_SIZE, BlockDevice, BlockError, Image};
use pharos_programs::virtio::{self, Blk, MAX_READ};
use pharos_user::{Handle, debug_write, irq_create, send, sleep};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
/// A daemon's report capability (argument 2).
const REPORT: Handle = 3;
const BASE: u64 = 0x1000_0000;

/// The disk as a `pharos-fs` block device.
struct Disk {
    blk: RefCell<Blk>,
    irq: Handle,
}

impl BlockDevice for Disk {
    fn block_count(&self) -> u64 {
        self.blk.borrow().capacity
    }

    fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 {
            return Err(BlockError::BadLength);
        }
        let mut blk = self.blk.borrow_mut();
        let mut sector = block;
        for chunk in buf.chunks_mut(MAX_READ) {
            blk.read(self.irq, sector, chunk).map_err(|why| {
                say(why);
                BlockError::OutOfRange
            })?;
            sector += (chunk.len() / BLOCK_SIZE) as u64;
        }
        Ok(())
    }
}

fn say(text: &str) {
    let _ = debug_write(CONSOLE, text.as_bytes());
}

/// Recurses until the stack runs out: a page fault in user mode.
fn overflow(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if frame[0] == u64::MAX {
        return 0;
    }
    overflow(depth + 1) + frame[1]
}

fn main(arg: u64) -> u64 {
    if !virtio::is_blk(DEVICE) {
        say("not a virtio-blk device");
        return 1;
    }
    let Ok(irq) = irq_create(DEVICE, 0) else {
        say("irq_create failed");
        return 2;
    };
    let mut blk = match Blk::init(DEVICE, 0, BASE) {
        Ok(blk) => blk,
        Err(why) => {
            say(why);
            return 2;
        }
    };
    if arg == 1 {
        let _ = blk.submit(0, MAX_READ);
        return overflow(0);
    }

    // Known blocks: the image header starts the disk.
    let mut sector = [0u8; BLOCK_SIZE];
    if blk.read(irq, 0, &mut sector).is_err() || !sector.starts_with(b"PHAROSFS") {
        say("sector 0 is not a filesystem header");
        return 3;
    }
    say("ok sector 0");

    let disk = Disk {
        blk: RefCell::new(blk),
        irq,
    };
    let Ok(fs) = Image::mount(&disk) else {
        say("mount failed");
        return 4;
    };
    say("ok mounted");

    let mut text = [0u8; 128];
    let n = fs
        .lookup(b"hello.txt")
        .and_then(|file| fs.read(file, 0, &mut text));
    match n {
        Ok(n) => {
            let line = text[..n].strip_suffix(b"\n").unwrap_or(&text[..n]);
            let _ = debug_write(CONSOLE, line);
        }
        Err(_) => {
            say("hello.txt missing");
            return 5;
        }
    }

    // A file spread over several sectors: byte i is i % 251.
    let Ok(big) = fs.lookup(b"dir/big.bin") else {
        say("dir/big.bin missing");
        return 5;
    };
    let mut buf = [0u8; 1000];
    let mut offset = 0u64;
    loop {
        match fs.read(big, offset, &mut buf) {
            Ok(0) => break,
            Ok(n)
                if buf[..n]
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| u64::from(b) == (offset + i as u64) % 251) =>
            {
                offset += n as u64;
            }
            _ => {
                say("dir/big.bin contents wrong");
                return 5;
            }
        }
    }
    if offset != 3000 {
        say("dir/big.bin has the wrong size");
        return 5;
    }
    say("ok dir/big.bin");
    if arg == 2 {
        if send(REPORT, b"ready", 0, 0, 0).is_err() {
            return 6;
        }
        // Holds the device until `init` stops it (before its slot powers
        // off, or on the user's `stop service`).
        loop {
            sleep(u64::MAX);
        }
    }
    disk.blk.borrow().reset();
    0
}
