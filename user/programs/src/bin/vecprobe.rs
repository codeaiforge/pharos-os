//! Vector-state probe for the `vector_state` test kernels (issue #74,
//! D-016). Handle 1 is a debug console. By argument:
//!
//! - 1, 2: a worker. Ten rounds of putting values from its seed in every
//!   vector register, spinning long enough to be preempted, and checking
//!   the values are unchanged; then the floating-point checksum must match
//!   the host's. Two workers run at once, so each is preempted by the other.
//! - 3: fills every register with a marker value, spins (so the scheduler
//!   switches to other threads while its registers hold the marker), then
//!   crashes (`ud2`).
//! - 4: started while 3 spins: no register may hold the marker, and
//!   `MXCSR` must be the clean value. Being switched in straight from 3,
//!   it would see the marker if a new thread did not get clean state.
//!
//! Each step prints `ok <step>` or `FAIL <step>`; the exit code is the
//! number of failures. Every run also prints `avx: yes` or `avx: no`.

#![no_std]
#![no_main]

use pharos_programs::fp;
use pharos_user::vector;
use pharos_user::{debug_write, yield_now};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
/// Marker left in the registers of the crashing process (arg 3).
const MARKER: u64 = 0xa5a5_5a5a_dead_beef;
/// Spins per round: long enough to span timer ticks, even under TCG.
const SPINS: u64 = 20_000_000;

fn say(text: &str) {
    let _ = debug_write(CONSOLE, text.as_bytes());
}

fn report(failures: &mut u64, step: &str, ok: bool) {
    let mut line = [0u8; 96];
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let n = (prefix.len() + step.len()).min(line.len());
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..n].copy_from_slice(&step.as_bytes()[..n - prefix.len()]);
    let _ = debug_write(CONSOLE, &line[..n]);
    if !ok {
        *failures += 1;
    }
}

fn main(arg: u64) -> u64 {
    let avx = vector::avx_enabled();
    say(if avx { "avx: yes" } else { "avx: no" });
    let mut f = 0;
    match arg {
        1 | 2 => {
            let survived = (0..10).all(|round| {
                let ok = vector::registers_survive(arg * 100 + round, SPINS, avx);
                yield_now();
                ok
            });
            let step = if arg == 1 {
                "worker 1: registers survived 10 rounds of preemption"
            } else {
                "worker 2: registers survived 10 rounds of preemption"
            };
            report(&mut f, step, survived);
            let step = if arg == 1 {
                "worker 1: floating-point checksum matches the host"
            } else {
                "worker 2: floating-point checksum matches the host"
            };
            report(&mut f, step, fp::checksum() == fp::EXPECTED);
            f
        }
        3 => vector::crash_holding(MARKER, 3 * SPINS, avx),
        4 => {
            report(
                &mut f,
                "fresh process: no register holds another process's values",
                !vector::registers_contain(MARKER, avx),
            );
            report(
                &mut f,
                "fresh process: MXCSR is clean (0x1F80)",
                vector::mxcsr() == 0x1f80,
            );
            f
        }
        _ => 99,
    }
}
