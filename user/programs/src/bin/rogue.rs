//! A stand-in for a failed or compromised AI service (M4.6, D-031,
//! services.md "AI services"). `init` starts it from a test table in
//! place of `infer` or the agent runtime, with exactly that service's
//! manifest, so it holds only what the shipped service holds. Handle 3 is
//! `init`'s report endpoint in both manifests.
//!
//! - Argument 3 (as `infer`): reports `ready`, then never receives on the
//!   inference endpoint: a hung service.

#![no_std]
#![no_main]

use pharos_user::{debug_write, endpoint_create, receive, send};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const REPORT: u64 = 3;

fn main(arg: u64) -> u64 {
    match arg {
        3 => {
            if send(REPORT, b"ready", 0, 0, 0).is_err() {
                return 1;
            }
            let _ = debug_write(CONSOLE, b"rogue: ready, never receiving");
            // Nothing ever arrives on a fresh endpoint.
            let mut buf = [0u8; 8];
            let Ok(idle) = endpoint_create() else {
                return 2;
            };
            loop {
                let _ = receive(idle, &mut buf);
            }
        }
        _ => 9,
    }
}
