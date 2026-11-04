//! Stops processes for the `process_stop` test kernel (#95, agents.md).
//!
//! Handles: 1 debug console (`WRITE | GRANT`), 2 the `programs`
//! filesystem (`READ | GRANT`). It starts `child` in each of its stop
//! modes (5–14) and checks each ends as stopped, and what it leaves
//! behind. Each step prints `ok <step>` or `FAIL <step>`; the exit code is
//! the number of failures.

#![no_std]
#![no_main]

use pharos_user::rights::{GRANT, READ, RECEIVE, SEND, WAIT};
use pharos_user::{
    Error, Grant, Handle, Limits, Received, Status, debug_write, endpoint_create, open,
    process_status, process_stop, receive_timeout, sleep, spawn, spawn_with, try_send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const FS: Handle = 2;

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

/// The process's status once it is no longer running, or `Running` after
/// 1 s.
fn ended(process: Result<Handle, Error>) -> Status {
    let Ok(process) = process else {
        return Status::Exited(u64::MAX);
    };
    for _ in 0..100 {
        match process_status(process) {
            Ok(Status::Running) => sleep(10_000),
            Ok(status) => return status,
            Err(_) => return Status::Exited(u64::MAX),
        }
    }
    Status::Running
}

/// Starts `child` in `mode`, lets it reach its wait, stops it, and returns
/// how it ended.
fn stopped(child: Handle, mode: u64, caps: &[Grant], limit: u32) -> Status {
    // One descendant, for the modes that start a child.
    let limits = Limits {
        pages: limit,
        processes: 1,
        ..Limits::NONE
    };
    let Ok(process) = spawn_with(child, mode, caps, None, limits) else {
        return Status::Exited(u64::MAX);
    };
    sleep(50_000);
    if process_stop(process).is_err() {
        return Status::Exited(u64::MAX);
    }
    ended(Ok(process))
}

/// No pages, one descendant (D-022).
const ONE_CHILD: Limits = Limits {
    processes: 1,
    ..Limits::NONE
};

fn main(_: u64) -> u64 {
    let mut f = 0;
    let (Ok(child), Ok(events)) = (open(FS, b"bin/child"), endpoint_create()) else {
        report(&mut f, "open bin/child and create an endpoint", false);
        return f;
    };
    let file = Grant {
        handle: child,
        rights: READ | GRANT,
        badge: 0,
    };

    // A looping child, with its end as a notification.
    let looping = spawn(child, 5, &[], Some((events, 0)));
    sleep(50_000);
    let stop = looping.and_then(process_stop);
    let mut buf = [0u8; 8];
    let note = receive_timeout(events, &mut buf, 1_000_000);
    report(
        &mut f,
        "a looping process: stopped, and its end notified",
        stop.is_ok() && note == Ok(Received::Notification(1)) && ended(looping) == Status::Stopped,
    );
    report(
        &mut f,
        "stopping it again: OK",
        looping.and_then(process_stop).is_ok(),
    );

    let (Ok(inbox), Ok(outbox)) = (endpoint_create(), endpoint_create()) else {
        report(&mut f, "endpoints for the waiting children", false);
        return f;
    };
    let receiver = [Grant {
        handle: inbox,
        rights: RECEIVE,
        badge: 0,
    }];
    report(
        &mut f,
        "a process waiting in receive: stopped, and no longer queued",
        stopped(child, 6, &receiver, 0) == Status::Stopped
            && try_send(inbox, b"x") == Err(Error::WouldBlock),
    );
    let sender = [Grant {
        handle: outbox,
        rights: SEND,
        badge: 0,
    }];
    report(
        &mut f,
        "a process waiting in send: stopped, and its message withdrawn",
        stopped(child, 7, &sender, 0) == Status::Stopped
            && receive_timeout(outbox, &mut buf, 100_000) == Err(Error::TimedOut),
    );
    report(
        &mut f,
        "a sleeping process: stopped",
        stopped(child, 8, &[], 0) == Status::Stopped,
    );
    report(
        &mut f,
        "a process holding 1 MiB: stopped",
        stopped(child, 9, &[], 512) == Status::Stopped,
    );
    report(
        &mut f,
        "a process with a looping child: stopped",
        stopped(child, 10, &[file], 0) == Status::Stopped,
    );

    // A server takes a call and is stopped while its client waits.
    let Ok(server) = endpoint_create() else {
        report(&mut f, "an endpoint for the server", false);
        return f;
    };
    let serving = spawn(
        child,
        11,
        &[Grant {
            handle: server,
            rights: RECEIVE,
            badge: 0,
        }],
        None,
    );
    let client = spawn(
        child,
        12,
        &[Grant {
            handle: server,
            rights: SEND,
            badge: 0,
        }],
        None,
    );
    sleep(50_000);
    let stop = serving.and_then(process_stop);
    report(
        &mut f,
        "a server stopped during a call: its client gets TIMED_OUT",
        stop.is_ok() && ended(serving) == Status::Stopped && ended(client) == Status::Exited(0),
    );

    report(
        &mut f,
        "a process that starts a child and exits: exited",
        ended(spawn_with(child, 13, &[file], None, ONE_CHILD)) == Status::Exited(0),
    );

    let target = spawn(child, 5, &[], None);
    let checker = target.and_then(|target| {
        spawn(
            child,
            14,
            &[Grant {
                handle: target,
                rights: WAIT,
                badge: 0,
            }],
            None,
        )
    });
    report(
        &mut f,
        "a handle without STOP: MISSING_RIGHT",
        ended(checker) == Status::Exited(0),
    );
    report(
        &mut f,
        "the target then stops",
        target.and_then(process_stop).is_ok() && ended(target) == Status::Stopped,
    );
    report(
        &mut f,
        "process_stop on a console: MISSING_RIGHT",
        process_stop(CONSOLE) == Err(Error::MissingRight),
    );
    f
}
