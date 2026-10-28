//! The service manager (issue #61, services.md): the first user process.
//!
//! The kernel gives it handles 1 debug console, 2 the root filesystem
//! (`READ | GRANT`), 3 the kernel's report endpoint (`SEND`), and from 4
//! each supported device (`MAP | CONFIG | IRQ | GRANT`). The argument
//! selects a service table (0: boot; 1: the `services` test kernel).
//! Services start one after another; each gets only what its entry lists.
//! A one-shot service succeeds by exiting with 0, a daemon by sending
//! `ready`. Every event is printed; after the last service `init` sends
//! the kernel `[ready, failed]` and keeps reporting daemons that end.

#![no_std]
#![no_main]

use pharos_user::rights::{CONFIG, IRQ, MAP, SEND, WRITE};
use pharos_user::{
    Error, Grant, Handle, Received, Status, config_read, debug_write, endpoint_create, open,
    process_status, receive, send, spawn,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const ROOT: Handle = 2;
const REPORT: Handle = 3;
const FIRST_DEVICE: Handle = 4;

const VIRTIO_BLK: u32 = 0x1042_1af4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Succeeds by exiting with code 0.
    OneShot,
    /// Succeeds by sending `ready`; must not end.
    Daemon,
}

/// A capability a service gets, in handle order.
#[derive(Clone, Copy)]
enum Cap {
    Console,
    /// The device with this PCI vendor and device ID.
    Device(u32),
    /// `init`'s endpoint, badged with the service's number (daemons).
    Report,
}

struct Service {
    name: &'static str,
    path: &'static [u8],
    arg: u64,
    kind: Kind,
    caps: &'static [Cap],
    /// Indexes of services that must have succeeded first.
    after: &'static [usize],
}

const BOOT: &[Service] = &[Service {
    name: "virtio-blk",
    path: b"bin/virtio-blk",
    arg: 0,
    kind: Kind::OneShot,
    caps: &[Cap::Console, Cap::Device(VIRTIO_BLK)],
    after: &[],
}];

const TEST: &[Service] = &[
    Service {
        name: "first",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
    },
    Service {
        name: "daemon",
        path: b"bin/svc",
        arg: 1,
        kind: Kind::Daemon,
        caps: &[Cap::Console, Cap::Report],
        after: &[0],
    },
    Service {
        name: "crasher",
        path: b"bin/svc",
        arg: 2,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
    },
    Service {
        name: "after-crasher",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[2],
    },
    Service {
        name: "independent",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
    },
    Service {
        name: "missing",
        path: b"bin/no-such-program",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
    },
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console, Cap::Device(VIRTIO_BLK)],
        after: &[],
    },
];

/// Most services in a table (one notification bit each).
const MAX_SERVICES: usize = 32;

/// Prints `init: <name> <what>[ <number>]`.
fn say(name: &str, what: &str, number: Option<u64>) {
    let mut line = [0u8; 96];
    let mut n = 0;
    let mut put = |bytes: &[u8]| {
        let take = bytes.len().min(line.len() - n);
        line[n..n + take].copy_from_slice(&bytes[..take]);
        n += take;
    };
    put(b"init: ");
    put(name.as_bytes());
    put(b" ");
    put(what.as_bytes());
    if let Some(mut v) = number {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        put(b" ");
        put(&digits[i..]);
    }
    let _ = debug_write(CONSOLE, &line[..n]);
}

/// The devices the kernel passed: `(handle, vendor and device ID)`.
fn devices() -> ([(Handle, u32); 8], usize) {
    let mut found = [(0, 0); 8];
    let mut count = 0;
    for handle in FIRST_DEVICE..FIRST_DEVICE + 8 {
        match config_read(handle, 0, 4) {
            Ok(id) => {
                found[count] = (handle, id);
                count += 1;
            }
            Err(Error::InvalidHandle) => break,
            Err(_) => {}
        }
    }
    (found, count)
}

/// What became of a service.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Running(Handle),
    Ok(Handle),
    Failed,
}

/// Reports how service `i` ended (its notification bit was set).
fn ended(service: &Service, process: Handle) -> bool {
    match process_status(process) {
        Ok(Status::Exited(0)) if service.kind == Kind::OneShot => {
            say(service.name, "done", None);
            true
        }
        Ok(Status::Exited(code)) => {
            say(service.name, "exited", Some(code));
            false
        }
        Ok(Status::Killed(vector)) => {
            say(service.name, "killed", Some(vector));
            false
        }
        _ => false,
    }
}

fn main(arg: u64) -> u64 {
    let table = match arg {
        0 => BOOT,
        1 => TEST,
        _ => &[],
    };
    let Ok(events) = endpoint_create() else {
        let _ = debug_write(CONSOLE, b"init: cannot create an endpoint");
        return 1;
    };
    let (devices, device_count) = devices();
    let mut state = [State::Pending; MAX_SERVICES];
    let mut buf = [0u8; 16];

    for (i, service) in table.iter().enumerate().take(MAX_SERVICES) {
        if service
            .after
            .iter()
            .any(|&a| !matches!(state[a], State::Ok(_)))
        {
            say(service.name, "skipped", None);
            state[i] = State::Failed;
            continue;
        }
        let Ok(file) = open(ROOT, service.path) else {
            say(service.name, "missing program", None);
            state[i] = State::Failed;
            continue;
        };
        let mut grants = [Grant {
            handle: 0,
            rights: 0,
            badge: 0,
        }; 8];
        let mut missing = false;
        for (grant, cap) in grants.iter_mut().zip(service.caps) {
            *grant = match cap {
                Cap::Console => Grant {
                    handle: CONSOLE,
                    rights: WRITE,
                    badge: 0,
                },
                Cap::Report => Grant {
                    handle: events,
                    rights: SEND,
                    badge: i as u32 + 1,
                },
                Cap::Device(id) => match devices[..device_count].iter().find(|d| d.1 == *id) {
                    Some(&(handle, _)) => Grant {
                        handle,
                        rights: MAP | CONFIG | IRQ,
                        badge: 0,
                    },
                    None => {
                        missing = true;
                        break;
                    }
                },
            };
        }
        if missing {
            say(service.name, "no device", None);
            state[i] = State::Failed;
            continue;
        }
        let caps = &grants[..service.caps.len().min(8)];
        let process = match spawn(file, service.arg, caps, Some((events, i as u32))) {
            Ok(process) => process,
            Err(e) => {
                say(service.name, "spawn failed, error", Some(e.code()));
                state[i] = State::Failed;
                continue;
            }
        };
        let _ = pharos_user::delete(file);
        say(service.name, "started", None);
        state[i] = State::Running(process);

        // Wait until this service succeeds or fails.
        while state[i] == State::Running(process) {
            match receive(events, &mut buf) {
                Ok(Received::Message { badge, .. }) if badge == i as u32 + 1 => {
                    if service.kind == Kind::Daemon {
                        say(service.name, "ready", None);
                        state[i] = State::Ok(process);
                    }
                }
                Ok(Received::Notification(bits)) => {
                    for (j, other) in table.iter().enumerate().take(i + 1) {
                        if bits & 1 << j == 0 {
                            continue;
                        }
                        if let State::Running(p) | State::Ok(p) = state[j] {
                            let ok = ended(other, p);
                            state[j] = if ok && j == i {
                                State::Ok(p)
                            } else {
                                State::Failed
                            };
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let ready = state.iter().filter(|s| matches!(s, State::Ok(_))).count();
    let failed = table.len().min(MAX_SERVICES) - ready;
    let _ = send(REPORT, &[ready as u8, failed as u8], 0, 0, 0);

    // Keep reporting daemons that end.
    loop {
        if let Ok(Received::Notification(bits)) = receive(events, &mut buf) {
            for (j, service) in table.iter().enumerate().take(MAX_SERVICES) {
                if bits & 1 << j != 0 {
                    if let State::Ok(p) = state[j] {
                        ended(service, p);
                        state[j] = State::Failed;
                    }
                }
            }
        }
    }
}
