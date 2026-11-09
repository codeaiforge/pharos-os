//! A stand-in for a failed or compromised AI service (M4.6, D-031,
//! services.md "AI services"). `init` starts it from a test table in
//! place of `infer` or the agent runtime, with exactly that service's
//! manifest, so it holds only what the shipped service holds. Handle 3 is
//! `init`'s report endpoint in both manifests.
//!
//! - Argument 3 (as `infer`, #182): reports `ready` and never receives on
//!   the inference endpoint, a hung service. It creates one endpoint of
//!   its own (handle 5, after the manifest's 4) and waits there; when the
//!   test kernel sends it `exhaust`, it maps memory until refused (1 MiB
//!   pieces down to single pages), says how much it holds, and keeps
//!   asking every millisecond, so it takes any frame another process
//!   frees: a runaway service.

#![no_std]
#![no_main]

use pharos_user::{debug_write, endpoint_create, mem_map, receive, send, sleep};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const REPORT: u64 = 3;

/// `n` in decimal.
fn decimal(mut n: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &out[i..];
        }
    }
}

/// Maps as much as it may, in pieces from 1 MiB down to one page, so
/// few of its 1024 mappings are used; returns the bytes mapped.
fn grab() -> u64 {
    let mut bytes = 0;
    for size in [1 << 20, 1 << 18, 1 << 16, 1 << 14, 1 << 12] {
        while mem_map(size).is_ok() {
            bytes += size;
        }
    }
    bytes
}

/// Takes all it may, says how much, then keeps taking every freed frame.
fn exhaust() -> ! {
    let mut d = [0u8; 20];
    let mut line = [0u8; 64];
    let mut n = 0;
    for p in [b"rogue: holding ", decimal(grab() >> 20, &mut d), b" MiB"] {
        line[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let _ = debug_write(CONSOLE, &line[..n]);
    loop {
        grab();
        sleep(1_000);
    }
}

fn main(arg: u64) -> u64 {
    if arg != 3 || send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let Ok(own) = endpoint_create() else {
        return 2;
    };
    let _ = debug_write(CONSOLE, b"rogue: ready, never receiving");
    let mut buf = [0u8; 16];
    loop {
        if let Ok(pharos_user::Received::Message { len, .. }) = receive(own, &mut buf) {
            if buf[..len.min(16)] == *b"exhaust" {
                exhaust();
            }
        }
    }
}
