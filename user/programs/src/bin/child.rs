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
//!
//! For the `process_stop` test kernel (#95), started by `stopper`, which
//! stops each one:
//! - 5: loops forever. 6: handle 1 an endpoint (`RECEIVE`): receives
//!   forever. 7: handle 1 an endpoint (`SEND`) nobody receives on: sends
//!   forever. 8: sleeps forever. 9: maps and touches 1 MiB, then loops.
//! - 10: handle 1 `bin/child`: starts a looping child (5), then loops.
//! - 11: handle 1 an endpoint (`RECEIVE`): takes one call, keeps its reply
//!   capability, and loops.
//! - 12: handle 1 the endpoint of 11 (`SEND`): calls it with a 300 ms
//!   timeout; exits 0 on `TIMED_OUT`.
//! - 13: handle 1 `bin/child`: starts a looping child (5), then exits 0.
//! - 14: handle 1 a process handle with only `WAIT`: exits 0 if stopping
//!   it is `MISSING_RIGHT` and its status still reads.

#![no_std]
#![no_main]

use pharos_user::{
    Error, Received, Status, call_timeout, debug_write, endpoint_create, mem_map_buffer,
    process_status, process_stop, receive, send, sleep, spawn, try_send, yield_now,
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
        5 => spin(),
        6 => {
            let mut buf = [0u8; 8];
            let _ = receive(1, &mut buf);
            1
        }
        7 => {
            let _ = send(1, b"never", 0, 0, 0);
            1
        }
        8 => {
            sleep(u64::MAX);
            1
        }
        9 => match mem_map_buffer(1 << 20) {
            Ok(buffer) => {
                for page in 0..256 {
                    buffer.write_bytes(page * 4096, &[1]);
                }
                spin()
            }
            Err(_) => 1,
        },
        10 => match spawn(1, 5, &[], None) {
            Ok(_) => spin(),
            Err(_) => 1,
        },
        11 => {
            let mut buf = [0u8; 8];
            match receive(1, &mut buf) {
                Ok(Received::Message { .. }) => spin(),
                _ => 1,
            }
        }
        12 => {
            let Ok(reply) = endpoint_create() else {
                return 2;
            };
            let mut buf = [0u8; 8];
            match call_timeout(1, b"q", reply, &mut buf, 300_000) {
                Err(Error::TimedOut) => 0,
                _ => 1,
            }
        }
        13 => match spawn(1, 5, &[], None) {
            Ok(_) => 0,
            Err(_) => 1,
        },
        14 => {
            let refused = process_stop(1) == Err(Error::MissingRight);
            let reads = process_status(1) == Ok(Status::Running);
            if refused && reads { 0 } else { 1 }
        }
        _ => 99,
    }
}

fn spin() -> u64 {
    loop {
        core::hint::spin_loop();
    }
}
