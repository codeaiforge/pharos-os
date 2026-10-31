//! Waits with timeouts for the `timeouts` test kernel (issue #76,
//! user-environment.md). The argument picks one case; the kernel times
//! each process and checks its exit code.
//!
//! - 0: exits at once (the kernel's baseline for start-up time).
//! - 1: handle 1 an endpoint (`RECEIVE`) nobody sends on. `receive` with
//!   timeout 0, then 200 ms: both `TIMED_OUT`. Exits 0 if so.
//! - 2: handle 1 an endpoint (`SEND`) nobody receives on, handle 2 a reply
//!   endpoint. `call` with a 100 ms timeout: `TIMED_OUT`. Exits 0 if so.
//! - 3: `sleep(0)`, then `sleep` for 100 ms. Exits 0 if `uptime` (#88)
//!   advanced by at least 100 ms across it.
//! - 4: the client of a race: handles 1 the server's endpoint (`SEND`), 2 a
//!   reply endpoint. For k = 1..=[`ROUNDS`], calls with request `k` and a
//!   40 ms timeout, then sleeps 200 ms. Exits with bit k set for each reply.
//! - 5: the server: handle 1 its endpoint (`RECEIVE`). For each request k,
//!   sleeps 10·k ms and answers. Exits with bit k set for each answer
//!   delivered (a late answer gets `REVOKED`).
//!
//! Any other outcome exits with [`BAD`].

#![no_std]
#![no_main]

use pharos_user::{
    Error, Received, call_timeout, delete, receive, receive_timeout, send, sleep, uptime,
};

pharos_user::entry!(main);

/// Rounds in the race.
pub const ROUNDS: u64 = 8;
/// Exit code for an unexpected result.
pub const BAD: u64 = 0xbad;

fn client() -> u64 {
    let mut bits = 0;
    for k in 1..=ROUNDS {
        let mut buf = [0u8; 8];
        match call_timeout(1, &[k as u8], 2, &mut buf, 40_000) {
            Ok(Received::Message { len: 1, .. }) if buf[0] == b'r' => bits |= 1 << k,
            Err(Error::TimedOut) => {}
            _ => return BAD,
        }
        sleep(200_000);
    }
    bits
}

fn server() -> u64 {
    let mut bits = 0;
    for _ in 1..=ROUNDS {
        let mut buf = [0u8; 8];
        let Ok(Received::Message { len: 1, cap, .. }) = receive(1, &mut buf) else {
            return BAD;
        };
        let k = u64::from(buf[0]);
        sleep(10_000 * k);
        match send(cap, b"r", 0, 0, 0) {
            Ok(_) => bits |= 1 << k,
            Err(Error::Revoked) => {}
            Err(_) => return BAD,
        }
        let _ = delete(cap);
    }
    bits
}

fn main(arg: u64) -> u64 {
    let mut buf = [0u8; 8];
    let ok = match arg {
        0 => true,
        1 => {
            receive_timeout(1, &mut buf, 0) == Err(Error::TimedOut)
                && receive_timeout(1, &mut buf, 200_000) == Err(Error::TimedOut)
        }
        2 => call_timeout(1, b"x", 2, &mut buf, 100_000) == Err(Error::TimedOut),
        3 => {
            sleep(0);
            let start = uptime();
            sleep(100_000);
            start > 0 && uptime() - start >= 100_000
        }
        4 => return client(),
        5 => return server(),
        _ => false,
    };
    if ok { 0 } else { BAD }
}
