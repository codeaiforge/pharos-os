//! Shares memory for the `shared_memory` test kernel (issue #80,
//! user-environment.md). Two processes, A (the sharer) and B (the
//! receiver), started twice by the kernel:
//!
//! - Run 1, A ends first: A is argument 1, B argument 2.
//! - Run 2, B ends first: A is argument 3, B argument 4.
//!
//! A's handles: 1 the console, 2 an endpoint to B (`SEND`), 3 one from B
//! (`RECEIVE`); limit 3 pages (2 for the buffer, 1 charged for the kernel's
//! bookkeeping of sharing it, #115). B's: 1 the console, 2 the endpoint from A
//! (`RECEIVE`), 3 the one to A (`SEND`); limit 4 pages. Each step prints
//! `ok <step>` or `FAIL <step>`; the exit code is the number of failures.
//! In run 1, A revokes both grants while B maps them: B's mappings turn
//! into zeroed private pages with the same access (#104), and B ends by
//! writing to its read-only one (a page fault).

#![no_std]
#![no_main]

use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Error, Mapped, Received, debug_write, delete, mem_map, mem_map_cap, mem_share, mem_unmap,
    receive, revoke, send, sleep,
};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
// A's handles.
const OUT: u64 = 2;
const IN: u64 = 3;
// B's handles.
const FROM_A: u64 = 2;
const TO_A: u64 = 3;
const LEN: u64 = 8192;

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

fn holds(m: &Mapped, offset: usize, text: &[u8]) -> bool {
    let mut buf = [0u8; 16];
    m.read_bytes(offset, &mut buf[..text.len()]);
    &buf[..text.len()] == text
}

/// The next message on `endpoint`: its text and capability.
fn next(endpoint: u64) -> ([u8; 16], u64) {
    let mut buf = [0u8; 16];
    match receive(endpoint, &mut buf) {
        Ok(Received::Message { cap, .. }) => (buf, cap),
        _ => ([0; 16], 0),
    }
}

fn sharer(b_ends_first: bool) -> u64 {
    let mut f = 0;
    let Ok(buf) = mem_map(LEN) else {
        report(&mut f, "A: map a two-page buffer", false);
        return f;
    };
    buf.write_bytes(0, b"from A");
    let shared = mem_share(&buf);
    report(&mut f, "A: share the buffer", shared.is_ok());
    report(
        &mut f,
        "A: sharing took its last page for bookkeeping",
        mem_map(4096) == Err(Error::NoMemory),
    );
    let h = shared.unwrap_or(0);
    report(
        &mut f,
        "A: send a writable and a read-only grant",
        send(OUT, b"rw", h, READ | WRITE, 0).is_ok() && send(OUT, b"ro", h, READ, 0).is_ok(),
    );
    let (msg, _) = next(IN);
    report(&mut f, "A: B is done", msg.starts_with(b"done"));
    report(&mut f, "A: sees B's write", holds(&buf, 100, b"from B"));
    if b_ends_first {
        // The kernel checks the object lives on while A maps it.
        sleep(300_000);
        report(
            &mut f,
            "A: buffer intact after B ended",
            holds(&buf, 100, b"from B"),
        );
        return f;
    }
    report(&mut f, "A: revoke both grants", revoke(h) == Ok(2));
    report(
        &mut f,
        "A: unmap while B still maps it",
        mem_unmap(buf).is_ok(),
    );
    let _ = send(OUT, b"revoked", 0, 0, 0);
    f
}

fn receiver(ends_first: bool) -> u64 {
    let mut f = 0;
    let ((_, rw), (_, ro)) = (next(FROM_A), next(FROM_A));
    let m1 = mem_map_cap(rw, true, LEN);
    report(&mut f, "B: map the writable grant", m1.is_ok());
    let Ok(m1) = m1 else { return f };
    report(&mut f, "B: sees A's write", holds(&m1, 0, b"from A"));
    m1.write_bytes(100, b"from B");
    report(
        &mut f,
        "B: a read-only grant cannot be mapped writable",
        mem_map_cap(ro, true, LEN).err() == Some(Error::MissingRight),
    );
    report(
        &mut f,
        "B: a wrong length is refused",
        mem_map_cap(ro, false, 4096).err() == Some(Error::TooLarge),
    );
    report(
        &mut f,
        "B: a received mapping cannot be shared again",
        mem_share(&m1).err() == Some(Error::BadAddress),
    );
    let m2 = mem_map_cap(ro, false, LEN);
    report(
        &mut f,
        "B: map the read-only grant",
        m2.as_ref().is_ok_and(|m| holds(m, 0, b"from A")),
    );
    report(
        &mut f,
        "B: the receiver's limit applies",
        mem_map_cap(rw, false, LEN).err() == Some(Error::NoMemory),
    );
    let _ = send(TO_A, b"done", 0, 0, 0);
    if ends_first {
        return f;
    }
    let (msg, _) = next(FROM_A);
    report(
        &mut f,
        "B: A revoked and unmapped",
        msg.starts_with(b"revoked"),
    );
    report(
        &mut f,
        "B: revoked grants map nothing new",
        mem_map_cap(rw, false, LEN).err() == Some(Error::Revoked),
    );
    // The revoked mappings no longer hold the object; the kernel checks
    // it is gone once B's revoked grants are deleted too.
    report(
        &mut f,
        "B: dropped its grants",
        delete(rw).is_ok() && delete(ro).is_ok(),
    );
    sleep(300_000);
    report(
        &mut f,
        "B: revoked, its mappings read zeros",
        holds(&m1, 0, &[0; 6]) && holds(&m1, 100, &[0; 6]),
    );
    m1.write_bytes(200, b"mine");
    report(
        &mut f,
        "B: its writes stay in its own pages",
        holds(&m1, 200, b"mine"),
    );
    if let Ok(m2) = m2 {
        let _ = debug_write(CONSOLE, b"B: writing the read-only mapping");
        m2.write8(0, 1);
    }
    f
}

fn main(arg: u64) -> u64 {
    match arg {
        1 => sharer(false),
        2 => receiver(false),
        3 => sharer(true),
        4 => receiver(true),
        _ => 0xbad,
    }
}
