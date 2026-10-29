//! A child for the `spawn` test kernel (issue #60), started by `spawner`.
//!
//! - Argument 1: handles 1 console, 2 an endpoint (`SEND`, badged by the
//!   parent). Prints a line, sends `hi`, and exits with code 42.
//! - Argument 2: crashes (a stack overflow, so a page fault).
//! - Argument 3: handle 1 an endpoint (`RECEIVE`). Waits for one message,
//!   then exits with code 0 (for the process-limit test).
//! - Argument 4: handle 1 an endpoint (`RECEIVE`). A server for one `call`:
//!   answers it, yields so the caller returns, then answers again through
//!   the same reply capability. Exits 0 only if that fails with `REVOKED`
//!   (replies are one-shot; M2.10 security review).

#![no_std]
#![no_main]

use pharos_user::{Error, Received, debug_write, receive, send, try_send, yield_now};

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
        4 => {
            let mut buf = [0u8; 8];
            let Ok(Received::Message { cap, .. }) = receive(1, &mut buf) else {
                return 1;
            };
            if try_send(cap, b"once").is_err() {
                return 2;
            }
            yield_now();
            match try_send(cap, b"twice") {
                Err(Error::Revoked) => 0,
                _ => 3,
            }
        }
        _ => 99,
    }
}
