//! A test service for `init`'s test table (issue #61). Handles: 1 debug
//! console, 2 `init`'s report endpoint (`SEND`, badged) for daemons.
//!
//! - Argument 0: a one-shot service that succeeds (exits with 0).
//! - Argument 1: a daemon: reports ready, then waits forever.
//! - Argument 2: crashes (a stack overflow, so a page fault).
//!
//! For the `supervision` test kernel (#100):
//! - 3: a daemon that never reports ready.
//! - 4: reports ready, then crashes 300 ms later.
//! - 5: handle 2 `SEND` on the storage service: attaches a 4 MiB buffer,
//!   prints `svc: holding`, and exits 0 half a second later.
//! - 6: prints `svc: steady`, reports ready, and waits forever.

#![no_std]
#![no_main]

use pharos_proto::store::{Request, encode};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    debug_write, delete, endpoint_create, mem_map_buffer, mem_share, receive, send, sleep,
};

pharos_user::entry!(main);

/// Recurses until the stack runs out: a page fault in user mode.
fn overflow(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if frame[0] == u64::MAX {
        return 0;
    }
    overflow(depth + 1) + frame[1]
}

/// Waits forever: nothing arrives on a fresh endpoint.
fn idle() -> u64 {
    let mut buf = [0u8; 8];
    match endpoint_create() {
        Ok(idle) => loop {
            let _ = receive(idle, &mut buf);
        },
        Err(_) => 2,
    }
}

fn main(arg: u64) -> u64 {
    match arg {
        0 => 0,
        1 => {
            if send(2, b"ready", 0, 0, 0).is_err() {
                return 1;
            }
            idle()
        }
        2 => overflow(0),
        3 => idle(),
        4 => {
            if send(2, b"ready", 0, 0, 0).is_err() {
                return 1;
            }
            sleep(300_000);
            overflow(0)
        }
        5 => {
            let len = 4 << 20;
            let Ok(buffer) = mem_map_buffer(len) else {
                return 1;
            };
            let Ok(memory) = mem_share(buffer.addr(), len) else {
                return 2;
            };
            let mut msg = [0u8; 16];
            let n = encode(&Request::Attach { len }, &mut msg).unwrap_or(0);
            let sent = send(2, &msg[..n], memory, READ | WRITE, 0);
            let _ = delete(memory);
            if sent.is_err() {
                return 3;
            }
            let _ = debug_write(1, b"svc: holding");
            sleep(500_000);
            0
        }
        6 => {
            let _ = debug_write(1, b"svc: steady");
            if send(2, b"ready", 0, 0, 0).is_err() {
                return 1;
            }
            idle()
        }
        _ => 99,
    }
}
