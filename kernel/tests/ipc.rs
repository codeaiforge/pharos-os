//! Test kernel: IPC between user processes over endpoints, capability
//! passing, revocation, and rights (issue #41). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use pharos_kernel::arch::x86_64::paging::{self, Flags};
use pharos_kernel::arch::x86_64::user_programs::TestProgram;
use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{self, Capability, Object};
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::process::{self, USER_BASE};
use pharos_kernel::sched::TaskId;
use pharos_kernel::syscall::{Error, MAX_MESSAGE, number::*};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm, sched, time};

pharos_kernel::test_kernel!(run);

/// Ping-pong round trips: 1000, or `PHAROS_IPC_ROUND_TRIPS` at build time
/// (`cargo xtask bench-ipc` builds with 100,000).
const ROUND_TRIPS: u64 = match option_env!("PHAROS_IPC_ROUND_TRIPS") {
    Some(n) => decimal(n),
    None => 1000,
};

/// A positive decimal number, at compile time.
const fn decimal(s: &str) -> u64 {
    let b = s.as_bytes();
    assert!(!b.is_empty(), "PHAROS_IPC_ROUND_TRIPS is empty");
    let mut i = 0;
    let mut v = 0u64;
    while i < b.len() {
        assert!(
            b[i].is_ascii_digit(),
            "PHAROS_IPC_ROUND_TRIPS must be a number"
        );
        v = v * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    assert!(v > 0, "PHAROS_IPC_ROUND_TRIPS must be positive");
    v
}
/// Each table process: entries from the start, strings at +0x800, receive
/// buffers at +0xc00 (all in its own page at this address).
const TABLE: u64 = 0x6000_0000;
const STRINGS: u64 = TABLE + 0x800;
const BUFFERS: u64 = TABLE + 0xc00;
const ENTRY_WORDS: usize = 10;

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

fn endpoint_cap(endpoint: &Arc<Endpoint>, rights: u32) -> Arc<Capability> {
    Capability::new(Object::Endpoint(endpoint.clone()), rights)
}

/// One table entry: number, five arguments, expected status and value.
struct Call(&'static str, u64, [u64; 5], Result<u64, Error>);

/// Builds a table page: entries, then `strings` at their offsets.
fn table_page(calls: &[Call], strings: &[(u64, &[u8])]) -> Vec<u8> {
    let mut page = vec![0u8; 4096];
    let mut put = |word: usize, value: u64| {
        page[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(0, calls.len() as u64);
    for (i, Call(_, number, args, _)) in calls.iter().enumerate() {
        put(1 + i * ENTRY_WORDS, *number);
        for (j, &arg) in args.iter().enumerate() {
            // Arguments go to rdi, rsi, rdx, r10, r8 (r9 stays 0).
            put(1 + i * ENTRY_WORDS + 1 + j, arg);
        }
    }
    for &(addr, bytes) in strings {
        let at = (addr - TABLE) as usize;
        page[at..at + bytes.len()].copy_from_slice(bytes);
    }
    page
}

/// Loads the table program with `page` at [`TABLE`] and starts it.
fn start_table(page: &[u8], caps: Vec<Arc<Capability>>) -> Option<(TaskId, u64)> {
    let mut space = process::load(TestProgram::SyscallTable.bytes()).ok()?;
    let phys = mm::frames().as_mut().and_then(|frames| {
        space
            .map_new_page(TABLE, Flags::USER_DATA, page, frames)
            .ok()
    })?;
    let id = process::start(space, 0, TABLE, caps).ok()?;
    Some((id, phys))
}

/// Checks every entry's result; returns true if all match and all
/// registers survived.
fn check_table(t: &mut TestRun, who: &str, phys: u64, calls: &[Call]) -> bool {
    let word = |w: usize| paging::read_phys_u64(phys + w as u64 * 8).unwrap_or(u64::MAX);
    let mut all = true;
    for (i, Call(what, _, _, expected)) in calls.iter().enumerate() {
        let base = 1 + i * ENTRY_WORDS;
        let got = (word(base + 7), word(base + 8));
        let want = match expected {
            Ok(value) => (0, *value),
            Err(error) => (*error as u64, 0),
        };
        if got != want {
            kprintln!("{who} {what}: got {got:?}, expected {want:?}");
        }
        all &= got == want && word(base + 9) == 1;
        t.check(what, got == want);
    }
    all
}

fn read_bytes(phys: u64, len: usize) -> Vec<u8> {
    (0..len.div_ceil(8))
        .flat_map(|i| {
            paging::read_phys_u64(phys + i as u64 * 8)
                .unwrap_or(0)
                .to_le_bytes()
        })
        .take(len)
        .collect()
}

fn wait_for_exits(ids: &[TaskId]) {
    for _ in 0..500 {
        let exits = process::exits();
        if ids.iter().all(|id| exits.iter().any(|e| e.task == *id)) {
            return;
        }
        sched::sleep(Duration::from_millis(10));
    }
}

/// Waits up to a second for `done`: a process may still be on its way to
/// the state checked next (preempted in user mode, or not reaped yet).
fn settle(done: impl Fn() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        sched::sleep(Duration::from_millis(10));
    }
}

fn exit_code(id: TaskId) -> Option<u64> {
    process::exits()
        .iter()
        .find(|e| e.task == id)
        .map(|e| e.code)
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    let ready = memory
        && mm::init_heap().is_ok()
        && requests::HHDM
            .response()
            .is_some_and(|hhdm| apic::init(hhdm.offset).is_ok())
        && time::init().is_ok()
        && sched::init().is_ok();
    t.check("memory, heap, APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    process::init();
    t.check("preemption enabled", sched::enable_preemption().is_ok());

    // Part 1: ping-pong, ordering checked by the programs themselves.
    let (to_pong, to_ping) = (Endpoint::new(), Endpoint::new());
    let pong = process::spawn(
        TestProgram::Pong.bytes(),
        0,
        0,
        vec![
            endpoint_cap(&to_pong, cap::RECEIVE),
            endpoint_cap(&to_ping, cap::SEND),
        ],
    );
    let start = time::uptime();
    let ping = process::spawn(
        TestProgram::Ping.bytes(),
        0,
        ROUND_TRIPS,
        vec![
            endpoint_cap(&to_pong, cap::SEND),
            endpoint_cap(&to_ping, cap::RECEIVE),
        ],
    );
    t.check(
        "ping and pong processes started",
        ping.is_ok() && pong.is_ok(),
    );
    let (Ok(ping), Ok(_)) = (ping, pong) else {
        return;
    };
    wait_for_exits(&[ping]);
    // From starting ping to its exit (recorded when it exits), so the
    // polling above does not count. Includes starting ping once.
    let elapsed = process::exits()
        .iter()
        .find(|e| e.task == ping)
        .map_or(Duration::ZERO, |e| e.at - start);
    kprintln!(
        "IPC round trip: {} ns ({ROUND_TRIPS} round trips in {} us; TCG timing is not hardware timing)",
        elapsed.as_nanos() / u128::from(ROUND_TRIPS),
        elapsed.as_micros()
    );
    settle(|| to_pong.waiting() == (0, 1));
    t.check(
        "every round trip's reply is the request plus one, in order",
        exit_code(ping) == Some(0),
    );
    t.check(
        "pong waits for the next message; nobody else waits",
        to_pong.waiting() == (0, 1) && to_ping.waiting() == (0, 0),
    );

    // Part 2: passing, using, and revoking a capability; rights checks.
    let before = free_frames();
    let (requests, acks) = (Endpoint::new(), Endpoint::new());
    let s = |offset: u64| STRINGS + offset;
    let b = |offset: u64| BUFFERS + offset;
    let granter = [
        Call(
            "granter: send the console capability (WRITE only)",
            SEND,
            [1, s(0), 9, 3, u64::from(cap::WRITE)],
            Ok(0),
        ),
        Call(
            "granter: receive the first ack",
            RECEIVE,
            [2, b(0), 256, u64::MAX, 0],
            Ok(4),
        ),
        Call(
            "granter: revoke what it granted",
            REVOKE,
            [3, 0, 0, 0, 0],
            Ok(1),
        ),
        Call("granter: send 'revoked'", SEND, [1, s(16), 7, 0, 0], Ok(0)),
        Call(
            "granter: receive the second ack",
            RECEIVE,
            [2, b(0x100), 256, u64::MAX, 0],
            Ok(4),
        ),
        Call(
            "granter: send a 10-byte message",
            SEND,
            [1, s(32), 10, 0, 0],
            Ok(0),
        ),
        Call(
            "granter: still writes with its own capability",
            DEBUG_WRITE,
            [3, s(48), 6, 0, 0],
            Ok(6),
        ),
    ];
    let receiver = [
        Call(
            "receiver: receive message and capability (handle 3)",
            RECEIVE,
            [1, b(0), 256, u64::MAX, 0],
            Ok(9 | 3 << 32),
        ),
        Call(
            "receiver: write with the granted capability",
            DEBUG_WRITE,
            [3, b(0), 9, 0, 0],
            Ok(9),
        ),
        Call(
            "receiver: cannot pass it on (no GRANT)",
            SEND,
            [2, b(0), 4, 3, u64::from(cap::WRITE)],
            Err(Error::MissingRight),
        ),
        Call(
            "receiver: send the first ack",
            SEND,
            [2, s(0), 4, 0, 0],
            Ok(0),
        ),
        Call(
            "receiver: receive 'revoked'",
            RECEIVE,
            [1, b(0x100), 256, u64::MAX, 0],
            Ok(7),
        ),
        Call(
            "receiver: the granted capability is revoked",
            DEBUG_WRITE,
            [3, b(0), 4, 0, 0],
            Err(Error::Revoked),
        ),
        Call(
            "receiver: send the second ack",
            SEND,
            [2, s(16), 4, 0, 0],
            Ok(0),
        ),
        Call(
            "receiver: a 4-byte buffer gets 4 bytes, the value the full 10",
            RECEIVE,
            [1, b(0x200), 4, u64::MAX, 0],
            Ok(10),
        ),
        Call(
            "receiver: delete the revoked handle",
            DELETE,
            [3, 0, 0, 0, 0],
            Ok(0),
        ),
        Call(
            "receiver: no SEND on a receive-only endpoint",
            SEND,
            [1, s(0), 4, 0, 0],
            Err(Error::MissingRight),
        ),
        Call(
            "receiver: no RECEIVE on a send-only endpoint",
            RECEIVE,
            [2, b(0), 16, u64::MAX, 0],
            Err(Error::MissingRight),
        ),
        Call(
            "receiver: no passing a capability without GRANT",
            SEND,
            [2, s(0), 4, 1, u64::from(cap::SEND)],
            Err(Error::MissingRight),
        ),
        Call(
            "receiver: kernel receive buffer",
            RECEIVE,
            [1, 0xffff_8000_0000_0000, 16, u64::MAX, 0],
            Err(Error::BadAddress),
        ),
        Call(
            "receiver: read-only receive buffer",
            RECEIVE,
            [1, USER_BASE, 16, u64::MAX, 0],
            Err(Error::BadAddress),
        ),
        Call(
            "receiver: unknown handle",
            RECEIVE,
            [5, b(0), 16, u64::MAX, 0],
            Err(Error::InvalidHandle),
        ),
    ];
    let granter_page = table_page(
        &granter,
        &[
            (s(0), b"take this"),
            (s(16), b"revoked"),
            (s(32), b"truncated!"),
            (s(48), b"still!"),
        ],
    );
    let receiver_page = table_page(&receiver, &[(s(0), b"ack1"), (s(16), b"ack2")]);
    let console = Capability::new(Object::DebugConsole, cap::WRITE | cap::GRANT);
    let a = start_table(
        &granter_page,
        vec![
            endpoint_cap(&requests, cap::SEND),
            endpoint_cap(&acks, cap::RECEIVE),
            console,
        ],
    );
    let r = start_table(
        &receiver_page,
        vec![
            endpoint_cap(&requests, cap::RECEIVE),
            endpoint_cap(&acks, cap::SEND),
        ],
    );
    t.check("granter and receiver started", a.is_some() && r.is_some());
    let (Some((a_id, a_phys)), Some((r_id, r_phys))) = (a, r) else {
        return;
    };
    wait_for_exits(&[a_id, r_id]);
    settle(|| free_frames() == before);
    t.check(
        "both exited normally",
        exit_code(a_id) == Some(0x600d) && exit_code(r_id) == Some(0x600d),
    );
    let granter_ok = check_table(t, "granter", a_phys, &granter);
    let receiver_ok = check_table(t, "receiver", r_phys, &receiver);
    t.check("registers survived every call", granter_ok && receiver_ok);
    let r_buf = r_phys + (BUFFERS - TABLE);
    let a_buf = a_phys + (BUFFERS - TABLE);
    t.check(
        "messages arrived intact and in order",
        read_bytes(r_buf, 9) == b"take this"
            && read_bytes(r_buf + 0x100, 7) == b"revoked"
            && read_bytes(a_buf, 4) == b"ack1"
            && read_bytes(a_buf + 0x100, 4) == b"ack2",
    );
    t.check(
        "a cut message fills only the buffer",
        read_bytes(r_buf + 0x200, 8) == b"trun\0\0\0\0",
    );
    let output = process::debug_output();
    t.check(
        "the receiver wrote with the granted capability before revocation only",
        output.contains(&(r_id, b"take this".to_vec()))
            && output.iter().filter(|(id, _)| *id == r_id).count() == 1,
    );
    t.check(
        "no process waits; their frames are back",
        requests.waiting() == (0, 0) && acks.waiting() == (0, 0) && free_frames() == before,
    );

    reply_wakes_a_caller_first(t);
}

/// #204: a `call` woken by an event on its reply endpoint, before any server
/// took its request, withdraws the request, so a caller cannot leave
/// requests queued on a server that does not receive.
fn reply_wakes_a_caller_first(t: &mut TestRun) {
    static RETURNED: AtomicUsize = AtomicUsize::new(0);
    let server = Arc::new(Endpoint::new());
    let mut withdrawn = true;
    for round in 0..3 {
        let queued = server.waiting().0;
        let reply = Arc::new(Endpoint::new());
        let (to, back) = (server.clone(), reply.clone());
        let caller = sched::spawn(move || {
            let message = Message {
                data: [0; MAX_MESSAGE],
                len: 1,
                cap: None,
                badge: 0,
            };
            let _ = ipc::call(&to, message, &back, None);
            RETURNED.fetch_add(1, Ordering::Relaxed);
        });
        if caller.is_err() {
            withdrawn = false;
            break;
        }
        // The caller has queued its request and waits.
        settle(|| server.waiting().0 == queued + 1);
        ipc::notify(&reply, 1);
        settle(|| RETURNED.load(Ordering::Relaxed) == round + 1);
        let (returned, waiting) = (RETURNED.load(Ordering::Relaxed), server.waiting());
        if returned != round + 1 || waiting != (0, 0) {
            kprintln!("round {round}: {returned} calls returned, server queues {waiting:?}");
        }
        withdrawn &= returned == round + 1 && waiting == (0, 0);
    }
    t.check(
        "a caller woken by its reply endpoint withdraws its request (3 rounds)",
        withdrawn,
    );
}
