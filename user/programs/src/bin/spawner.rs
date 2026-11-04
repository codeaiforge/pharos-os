//! Starts processes for the `spawn` test kernel (issue #60,
//! services.md).
//!
//! Handles: 1 debug console (`WRITE | GRANT`), 2 the `programs` filesystem
//! (`READ | GRANT`), 3 a file capability without `READ`, 4 an endpoint
//! with `SEND` only. Each step prints `ok <step>` or `FAIL <step>`, then
//! `limit <n>` (children started before the process limit); the exit code
//! is the number of failures.

#![no_std]
#![no_main]

use pharos_user::rights::{GRANT, READ, RECEIVE, SEND, WRITE};
use pharos_user::{
    Class, Error, Grant, Limits, Received, Status, Usage, call_reply, debug_write, endpoint_create,
    open, process_status, process_stop, process_usage, receive, send, sleep, spawn, spawn_limited,
    spawn_with,
};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const FS: u64 = 2;
const NO_READ: u64 = 3;
const SEND_ONLY: u64 = 4;

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

fn main(_: u64) -> u64 {
    let mut f = 0;
    let (Ok(events), Ok(child)) = (endpoint_create(), open(FS, b"bin/child")) else {
        report(&mut f, "endpoint_create and open bin/child", false);
        return f;
    };
    report(&mut f, "endpoint_create and open bin/child", true);

    // A child with two capabilities, one badged; its end sets bit 3.
    let caps = [
        Grant {
            handle: CONSOLE,
            rights: WRITE,
            badge: 0,
        },
        Grant {
            handle: events,
            rights: SEND,
            badge: 7,
        },
    ];
    let first = spawn(child, 1, &caps, Some((events, 3)));
    report(&mut f, "spawn a child with two capabilities", first.is_ok());
    let mut buf = [0u8; 16];
    let got = receive(events, &mut buf);
    report(
        &mut f,
        "the child's message carries badge 7",
        got == Ok(Received::Message {
            len: 2,
            cap: 0,
            badge: 7,
        }) && buf.starts_with(b"hi"),
    );
    report(
        &mut f,
        "its end arrives as notification bit 3",
        receive(events, &mut buf) == Ok(Received::Notification(1 << 3)),
    );
    report(
        &mut f,
        "process_status: exited with 42",
        first.and_then(process_status) == Ok(Status::Exited(42)),
    );

    let crash = spawn(child, 2, &[], Some((events, 4)));
    let note = receive(events, &mut buf);
    report(
        &mut f,
        "a crashing child is reported killed by a page fault",
        note == Ok(Received::Notification(1 << 4))
            && crash.and_then(process_status) == Ok(Status::Killed(14)),
    );

    // A child serves one call, then answers again through the same reply
    // capability: that must fail, since replies are one-shot.
    let (Ok(server), Ok(reply)) = (endpoint_create(), endpoint_create()) else {
        report(&mut f, "endpoints for the call test", false);
        return f;
    };
    let serve = [Grant {
        handle: server,
        rights: RECEIVE,
        badge: 0,
    }];
    let served = spawn(child, 4, &serve, Some((events, 5)));
    let answer = call_reply(server, b"q", reply, &mut buf);
    report(
        &mut f,
        "call: the server's answer arrives",
        matches!(answer, Ok(Received::Message { len: 4, .. })) && buf.starts_with(b"once"),
    );
    report(
        &mut f,
        "call: a second answer on the reply capability is REVOKED",
        receive(events, &mut buf) == Ok(Received::Notification(1 << 5))
            && served.and_then(process_status) == Ok(Status::Exited(0)),
    );

    report(
        &mut f,
        "file without READ: MISSING_RIGHT",
        spawn(NO_READ, 1, &[], None) == Err(Error::MissingRight),
    );
    let ungrantable = [Grant {
        handle: SEND_ONLY,
        rights: SEND,
        badge: 0,
    }];
    report(
        &mut f,
        "capability without GRANT: MISSING_RIGHT",
        spawn(child, 1, &ungrantable, None) == Err(Error::MissingRight),
    );
    report(
        &mut f,
        "notify endpoint without RECEIVE: MISSING_RIGHT",
        spawn(child, 1, &[], Some((SEND_ONLY, 0))) == Err(Error::MissingRight),
    );
    report(
        &mut f,
        "send with a 25-bit badge: TOO_LARGE",
        send(events, b"x", CONSOLE, WRITE, 1 << 24) == Err(Error::TooLarge),
    );
    let nine = [caps[0]; 9];
    report(
        &mut f,
        "9 capabilities: TOO_LARGE",
        spawn(child, 1, &nine, None) == Err(Error::TooLarge),
    );
    let mut bad = true;
    for path in [&b"bad/magic"[..], b"bad/wx", b"bad/truncated", b"bad/empty"] {
        bad &= open(FS, path).and_then(|file| spawn(file, 1, &[], None)) == Err(Error::BadProgram);
    }
    report(&mut f, "malformed programs: BAD_PROGRAM", bad);

    // A child in the agents class cannot start one above it (D-022).
    let file = [Grant {
        handle: child,
        rights: READ | GRANT,
        badge: 0,
    }];
    let low = spawn_with(
        child,
        16,
        &file,
        None,
        Limits {
            class: Class::Agents,
            processes: 1,
            ..Limits::NONE
        },
    );
    let mut status = Ok(Status::Running);
    for _ in 0..200 {
        status = low.and_then(process_status);
        if status != Ok(Status::Running) {
            break;
        }
        sleep(10_000);
    }
    report(
        &mut f,
        "a child in the agents class: a higher class is TOO_LARGE",
        status == Ok(Status::Exited(0)),
    );

    // process_usage (#114): a looping child that maps 1 MiB is charged CPU
    // time and its pages; once stopped, its CPU time is kept and its pages
    // are 0. A child whose child starts a looping child has two
    // descendants.
    let mapper = spawn_limited(child, 9, &[], None, 256);
    sleep(100_000);
    let cpu = mapper.and_then(|p| process_usage(p, Usage::CpuMicros));
    let pages = mapper.and_then(|p| process_usage(p, Usage::Pages));
    let _ = mapper.and_then(process_stop);
    let mut ended = false;
    for _ in 0..100 {
        ended = mapper.and_then(process_status) == Ok(Status::Stopped);
        if ended {
            break;
        }
        sleep(10_000);
    }
    let kept = mapper.and_then(|p| process_usage(p, Usage::CpuMicros));
    let after = mapper.and_then(|p| process_usage(p, Usage::Pages));
    report(
        &mut f,
        "process_usage: CPU time and pages while running, CPU time kept once stopped",
        cpu.is_ok_and(|c| c >= 20_000)
            && pages == Ok(256)
            && ended
            && kept.is_ok_and(|k| k >= cpu.unwrap_or(u64::MAX))
            && after == Ok(0),
    );
    let two = Limits {
        processes: 2,
        ..Limits::NONE
    };
    let parent = spawn_with(child, 17, &file, None, two);
    sleep(100_000);
    let descendants = parent.and_then(|p| process_usage(p, Usage::Descendants));
    let _ = parent.and_then(process_stop);
    report(
        &mut f,
        "process_usage: a child whose child started a child has two descendants",
        descendants == Ok(2),
    );

    // Budgets carved from this process's (D-022, #115).
    let budget = |processes, handles| Limits {
        processes,
        handles,
        ..Limits::NONE
    };
    let exit_code = |p: Result<u64, Error>| {
        for _ in 0..200 {
            match p.and_then(process_status) {
                Ok(Status::Running) => sleep(10_000),
                Ok(Status::Exited(code)) => return Some(code),
                _ => return None,
            }
        }
        None
    };
    report(
        &mut f,
        "a child given 2 descendants starts 2, then TOO_LARGE",
        exit_code(spawn_with(child, 18, &file, None, budget(2, 0))) == Some(21),
    );
    report(
        &mut f,
        "a child given 8 handles holds 8, then NO_MEMORY",
        exit_code(spawn_with(child, 19, &[], None, budget(0, 8))) == Some(81),
    );
    report(
        &mut f,
        "more descendants or handles than this process has: TOO_LARGE",
        spawn_with(child, 1, &[], None, budget(255, 0)) == Err(Error::TooLarge)
            && spawn_with(child, 1, &[], None, budget(0, 4095)) == Err(Error::TooLarge),
    );
    report(
        &mut f,
        "a child given fewer handles than its capabilities: TOO_LARGE",
        spawn_with(child, 1, &caps, None, budget(0, 1)) == Err(Error::TooLarge),
    );

    // Start waiting children until the process limit (which needs every
    // budget above returned).
    let Ok(gate) = endpoint_create() else {
        report(&mut f, "endpoint for waiting children", false);
        return f;
    };
    let waiting = [Grant {
        handle: gate,
        rights: RECEIVE,
        badge: 0,
    }];
    let mut started = 0u64;
    let last = loop {
        match spawn(child, 3, &waiting, None) {
            Ok(_) if started < 64 => started += 1,
            other => break other.err(),
        }
    };
    report(
        &mut f,
        "the process limit: NO_MEMORY",
        last == Some(Error::NoMemory),
    );
    let mut line = *b"limit 00";
    line[6] = b'0' + (started / 10) as u8;
    line[7] = b'0' + (started % 10) as u8;
    let _ = debug_write(CONSOLE, &line);
    let mut released = true;
    for _ in 0..started {
        released &= send(gate, b"go", 0, 0, 0).is_ok();
    }
    report(&mut f, "released the waiting children", released);
    f
}
