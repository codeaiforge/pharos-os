//! A test service for `init`'s test table (issue #61). Handles: 1 debug
//! console, 2 `init`'s report endpoint (`SEND`, badged) for daemons.
//!
//! - Argument 0: a one-shot service that succeeds (exits with 0).
//! - Argument 1: a daemon: reports ready, then waits forever.
//! - Argument 2: crashes (a stack overflow, so a page fault).

#![no_std]
#![no_main]

use pharos_user::{endpoint_create, receive, send};

pharos_user::entry!(main);

/// Recurses until the stack runs out: a page fault in user mode.
fn overflow(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if frame[0] == u64::MAX {
        return 0;
    }
    overflow(depth + 1) + frame[1]
}

fn main(arg: u64) -> u64 {
    match arg {
        0 => 0,
        1 => {
            if send(2, b"ready", 0, 0, 0).is_err() {
                return 1;
            }
            // Nothing ever arrives on a fresh endpoint: wait forever.
            let mut buf = [0u8; 8];
            match endpoint_create() {
                Ok(idle) => loop {
                    let _ = receive(idle, &mut buf);
                },
                Err(_) => 2,
            }
        }
        2 => overflow(0),
        _ => 99,
    }
}
