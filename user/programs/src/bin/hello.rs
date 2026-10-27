//! The first Rust user program: prints a greeting on the debug console
//! (handle 1), counts in a writable static, and exits with its argument
//! plus the count, so a test can check code, data, and arguments.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use pharos_user::debug_write;

pharos_user::entry!(main);

static CALLS: AtomicU64 = AtomicU64::new(0);

fn main(arg: u64) -> u64 {
    for _ in 0..3 {
        CALLS.fetch_add(1, Ordering::Relaxed);
    }
    if debug_write(1, b"hello from a Rust user program").is_err() {
        return 0xbad;
    }
    arg + CALLS.load(Ordering::Relaxed)
}
