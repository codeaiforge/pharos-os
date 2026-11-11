//! Maps memory for the `user_memory` test kernel (issue #75,
//! user-environment.md).
//!
//! - Argument 0: started with a limit of [`LIMIT`] pages and handles 1 the
//!   debug console (`WRITE | GRANT`), 2 the file `bin/memprobe` (`READ`).
//!   Each step prints `ok <step>` or `FAIL <step>`; the exit code is the
//!   number of failures.
//! - Argument 1: a child given half the limit: maps all of it, then one
//!   page more. Exits 0 if the first works and the second fails.
//! - Argument 2: a child given no limit. Exits 0 if it cannot map a page.
//! - Argument 3: a child given half the limit: maps it, holds it for
//!   300 ms, and exits 0 (#115: meanwhile its parent cannot map that half).
//! - Argument 6 (the `user_memory` kernel, #120): maps and unmaps 64 MiB
//!   in a loop until stopped, so a stop lands while it maps however fast
//!   the machine is (under KVM one mapping takes less than the kernel's
//!   30 ms wait).
//! - Argument 7 (the `user_memory` kernel, #198): maps 16 GiB in one call,
//!   more than any matrix cell has; exits 0 if it is refused (`NO_MEMORY`),
//!   after the kernel has mapped what it could and rolled it back.
//! - Argument 5 (the `shared_memory` kernel, #122): see
//!   [`revoked_while_mapping`].
//! - Argument 4 (the `exhaustion` kernel, #120, #122): maps 64 MiB and
//!   unmaps it, maps 128 MiB, shares it, and maps the share, then maps 64
//!   MiB more, each in one call, and holds them until stopped; exits with
//!   the failed step's number otherwise.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use pharos_user::rights::WRITE;
use pharos_user::{
    Error, Grant, Received, Status, debug_write, endpoint_create, mem_map, mem_map_cap, mem_share,
    mem_unmap, process_status, receive, sleep, spawn, spawn_limited,
};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const SELF: u64 = 2;
/// The page limit the test kernel starts this program with: 32 MiB.
pub const LIMIT: u32 = 8192;
/// Half of it, for children (#115).
const HALF: u32 = LIMIT / 2;
const MIB: u64 = 1024 * 1024;
const REGION: u64 = 0x0000_1000_0000_0000;

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

/// Starts this program with `arg` and `limit` and waits for its exit code.
fn child(arg: u64, limit: Option<u32>) -> Option<u64> {
    let events = endpoint_create().ok()?;
    let caps = [Grant {
        handle: CONSOLE,
        rights: WRITE,
        badge: 0,
    }];
    let notify = Some((events, 0));
    let process = match limit {
        Some(limit) => spawn_limited(SELF, arg, &caps, notify, limit),
        None => spawn(SELF, arg, &caps, notify),
    }
    .ok()?;
    let mut buf = [0u8; 8];
    receive(events, &mut buf)
        .ok()
        .filter(|r| *r == Received::Notification(1))?;
    match process_status(process) {
        Ok(Status::Exited(code)) => Some(code),
        _ => None,
    }
}

/// Argument 5: shares 64 MiB holding a marker (its handle 1), then maps
/// handle 2, which the kernel derives from it and revokes while the map
/// runs. Exits 0 if the map is refused (`REVOKED`) or its pages read zeros
/// once revoked, 9 if they still show the marker, other codes on errors.
fn revoked_while_mapping() -> u64 {
    let Ok(buffer) = pharos_user::mem_map_buffer(64 * MIB) else {
        return 1;
    };
    buffer.write_bytes(0, &[0xab]);
    if mem_share(buffer.addr(), 64 * MIB).is_err() {
        return 2;
    }
    let mapped = loop {
        match mem_map_cap(2, false, 64 * MIB) {
            Err(Error::InvalidHandle) => sleep(1_000),
            other => break other,
        }
    };
    match mapped {
        Err(Error::Revoked) => 0,
        Ok(view) => {
            sleep(300_000);
            let mut byte = [0u8];
            view.read_bytes(0, &mut byte);
            if byte[0] == 0 { 0 } else { 9 }
        }
        Err(_) => 5,
    }
}

fn main(arg: u64) -> u64 {
    let all = u64::from(LIMIT) * 4096;
    match arg {
        1 => {
            let half = u64::from(HALF) * 4096;
            return u64::from(mem_map(half).is_err() || mem_map(4096) != Err(Error::NoMemory));
        }
        3 => {
            let held = mem_map(u64::from(HALF) * 4096).is_ok();
            sleep(300_000);
            return u64::from(!held);
        }
        2 => return u64::from(mem_map(4096) != Err(Error::NoMemory)),
        7 => return u64::from(mem_map(16 * 1024 * MIB) != Err(Error::NoMemory)),
        5 => return revoked_while_mapping(),
        6 => loop {
            let Ok(a) = mem_map(64 * MIB) else { return 1 };
            if mem_unmap(a, 64 * MIB).is_err() {
                return 2;
            }
        },
        4 => {
            let Ok(a) = mem_map(64 * MIB) else { return 1 };
            if mem_unmap(a, 64 * MIB).is_err() {
                return 2;
            }
            let Ok(b) = mem_map(128 * MIB) else { return 3 };
            let Ok(memory) = mem_share(b, 128 * MIB) else {
                return 4;
            };
            if mem_map_cap(memory, true, 128 * MIB).is_err() {
                return 5;
            }
            // Its own, freed as it ends.
            if mem_map(64 * MIB).is_err() {
                return 6;
            }
            loop {
                sleep(1_000_000);
            }
        }
        _ => {}
    }
    let mut f = 0;
    let (a, b) = (mem_map(16 * MIB), mem_map(16 * MIB));
    report(&mut f, "mem_map up to the limit", a.is_ok() && b.is_ok());
    let (a, b) = (a.unwrap_or(0), b.unwrap_or(0));
    report(
        &mut f,
        "one page past the limit: NO_MEMORY",
        mem_map(4096) == Err(Error::NoMemory),
    );
    report(
        &mut f,
        "mappings are placed in the map region",
        a == REGION && b == REGION + 16 * MIB,
    );
    report(
        &mut f,
        "length 0: TOO_LARGE",
        mem_map(0) == Err(Error::TooLarge),
    );
    report(
        &mut f,
        "part of a mapping: BAD_ADDRESS",
        mem_unmap(a, 4096) == Err(Error::BadAddress)
            && mem_unmap(a + 4096, 16 * MIB - 4096) == Err(Error::BadAddress),
    );
    report(
        &mut f,
        "no mapping there: BAD_ADDRESS",
        mem_unmap(REGION + 1024 * MIB, 4096) == Err(Error::BadAddress)
            && mem_unmap(0x40_0000, 4096) == Err(Error::BadAddress),
    );
    report(
        &mut f,
        "unmapping (length rounded up) returns the limit",
        mem_unmap(a, 16 * MIB).is_ok()
            && mem_unmap(b, 16 * MIB - 100).is_ok()
            && mem_map(all).and_then(|c| mem_unmap(c, all)).is_ok(),
    );
    report(
        &mut f,
        "a refused unmap changed nothing",
        mem_unmap(a, 16 * MIB) == Err(Error::BadAddress),
    );
    // 16 x 32 MiB is twice the machine's 256 MiB: frames must come back.
    let rounds = (0..16).all(|_| mem_map(all).and_then(|c| mem_unmap(c, all)).is_ok());
    report(&mut f, "16 rounds of 32 MiB: frames are freed", rounds);

    // The allocator: 8 MiB vectors are their own mapping, freed each round.
    let large = (0..16u8).all(|round| {
        let v = vec![round; 8 * MIB as usize];
        v.iter().all(|&x| x == round)
    });
    report(&mut f, "allocator: 16 large vectors of 8 MiB", large);
    // 100 x 640 KiB of small blocks is twice the limit: blocks are reused.
    let small = (0..100u64).all(|round| {
        let blocks: Vec<Box<[u64; 8]>> = (0..10_000).map(|i| Box::new([round ^ i; 8])).collect();
        blocks
            .iter()
            .enumerate()
            .all(|(i, b)| b[7] == round ^ i as u64)
    });
    report(&mut f, "allocator: small blocks are reused", small);

    report(
        &mut f,
        "spawn with a limit above its own: TOO_LARGE",
        spawn_limited(SELF, 1, &[], None, LIMIT + 1) == Err(Error::TooLarge),
    );
    // Carved (D-022, #115): a child's pages come out of this process's.
    let held = mem_map(4096);
    report(
        &mut f,
        "a child may not get more pages than are left: TOO_LARGE",
        held.is_ok() && spawn_limited(SELF, 1, &[], None, LIMIT) == Err(Error::TooLarge),
    );
    let _ = held.and_then(|h| mem_unmap(h, 4096));
    report(
        &mut f,
        "a child given half the limit maps it all, and no more",
        child(1, Some(HALF)) == Some(0),
    );
    report(
        &mut f,
        "the half returns when it ends: a second child gets it too",
        child(1, Some(HALF)) == Some(0),
    );
    let holder = spawn_limited(SELF, 3, &[], None, HALF);
    sleep(100_000);
    let blocked = mem_map(u64::from(HALF) * 4096) == Err(Error::NoMemory);
    let mut done = false;
    for _ in 0..100 {
        done = holder.and_then(process_status) == Ok(Status::Exited(0));
        if done {
            break;
        }
        sleep(10_000);
    }
    report(
        &mut f,
        "while a child holds half, this process cannot map it",
        holder.is_ok() && blocked && done,
    );
    report(
        &mut f,
        "a child without a limit cannot map",
        child(2, None) == Some(0),
    );
    f
}
