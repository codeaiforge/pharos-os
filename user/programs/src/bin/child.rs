//! A child for the `spawn` test kernel (issue #60), started by `spawner`.
//!
//! - Argument 1: handles 1 console, 2 an endpoint (`SEND`, badged by the
//!   parent). Prints a line, sends `hi`, and exits with code 42.
//! - Argument 2: crashes (a stack overflow, so a page fault).
//! - Argument 3: handle 1 an endpoint (`RECEIVE`). Waits for one message,
//!   then exits with code 0 (for the process-limit test).

#![no_std]
#![no_main]

use pharos_user::{debug_write, receive, send};

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
        1 => {
            let _ = debug_write(1, b"child: hello");
            let _ = send(2, b"hi", 0, 0, 0);
            42
        }
        2 => overflow(0),
        3 => {
            let mut buf = [0u8; 8];
            match receive(1, &mut buf) {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }
        _ => 99,
    }
}
