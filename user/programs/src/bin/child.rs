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
//!
//! For the `trust` test kernel (#96): 15, a stand-in agent runtime that
//! hangs. Handles 1 `bin/child`, 2 the trusted service's endpoint (`SEND`,
//! badged as the runtime). Starts a looping agent (5) with no
//! capabilities, registers it with the trusted service as `worker`, and
//! loops forever.
//!
//! For the `spawn` test kernel's classes (#114): 16, started in the agents
//! class, handle 1 `bin/child`. Exits 0 if a child in a higher class
//! (services or trusted) is `TOO_LARGE` and one in its own class starts.
//! 17: handle 1 `bin/child`: starts a 10 (which starts a 5), then loops,
//! for `process_usage`'s descendants.
//!
//! For the `spawn` test kernel's budgets (#115): 18, handle 1 `bin/child`:
//! starts sleeping children (8) until refused; exits with 10 times how
//! many started, plus 1 if the refusal was `TOO_LARGE`. 19, with no
//! handles: creates endpoints until refused; exits with 10 times how many,
//! plus 1 if the refusal was `NO_MEMORY`.

#![no_std]
#![no_main]

use pharos_proto::trust::{self, Request};
use pharos_user::rights::{READ, STOP, WAIT};
use pharos_user::{
    Class, Error, Grant, Limits, Received, Status, call_timeout, debug_write, endpoint_create,
    mem_map, process_status, process_stop, receive, send, sleep, spawn, spawn_with, try_send,
    yield_now,
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
        9 => match mem_map(1 << 20) {
            Ok(buffer) => {
                for page in 0..256 {
                    buffer.write_bytes(page * 4096, &[1]);
                }
                spin()
            }
            Err(_) => 1,
        },
        10 => match spawn_with(1, 5, &[], None, SMALL) {
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
        13 => match spawn_with(1, 5, &[], None, SMALL) {
            Ok(_) => 0,
            Err(_) => 1,
        },
        14 => {
            let refused = process_stop(1) == Err(Error::MissingRight);
            let reads = process_status(1) == Ok(Status::Running);
            if refused && reads { 0 } else { 1 }
        }
        // Two tasks of one agent: both registered as `worker`.
        15 => {
            for slot in 0..2 {
                let Ok(agent) = spawn(1, 5, &[], None) else {
                    return 1;
                };
                let mut msg = [0u8; 64];
                let register = Request::Register {
                    slot,
                    name: b"worker",
                    group: b"",
                };
                let Some(n) = trust::encode(&register, &mut msg) else {
                    return 2;
                };
                if send(2, &msg[..n], agent, STOP | WAIT, 0).is_err() {
                    return 3;
                }
            }
            spin()
        }
        17 => {
            let file = [Grant {
                handle: 1,
                rights: READ,
                badge: 0,
            }];
            let one = Limits {
                processes: 1,
                handles: 8,
                ..Limits::NONE
            };
            match spawn_with(1, 10, &file, None, one) {
                Ok(_) => spin(),
                Err(_) => 1,
            }
        }
        18 => {
            let mut started = 0;
            let refusal = loop {
                match spawn_with(1, 8, &[], None, SMALL) {
                    Ok(_) if started < 8 => started += 1,
                    other => break other.err(),
                }
            };
            started * 10 + u64::from(refusal == Some(Error::TooLarge))
        }
        19 => {
            let mut made = 0;
            let refusal = loop {
                match endpoint_create() {
                    Ok(_) if made < 64 => made += 1,
                    other => break other.err(),
                }
            };
            made * 10 + u64::from(refusal == Some(Error::NoMemory))
        }
        16 => {
            let in_class = |class| spawn_with(1, 1, &[], None, Limits { class, ..SMALL });
            let above = |class| in_class(class) == Err(Error::TooLarge);
            let own = in_class(Class::Agents).is_ok();
            if above(Class::Services) && above(Class::Trusted) && own {
                0
            } else {
                1
            }
        }
        _ => 99,
    }
}

/// What these children give theirs: 4 handles, since a child's default
/// budget is one full table (D-022, #115) and must keep room for its own.
const SMALL: Limits = Limits {
    handles: 4,
    ..Limits::NONE
};

fn spin() -> u64 {
    loop {
        core::hint::spin_loop();
    }
}
