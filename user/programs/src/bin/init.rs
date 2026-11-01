//! The service manager (issue #61, services.md): the first user process.
//!
//! The kernel gives it handles 1 debug console, 2 the root filesystem
//! (`READ | GRANT`), 3 the kernel's report endpoint (`SEND`), and from 4
//! each supported device (`MAP | CONFIG | IRQ | GRANT`). The argument
//! selects a service table (0: boot; 1: the `services` test kernel; 2: the
//! `network` test kernel).
//! Services start one after another; each gets only what its entry lists.
//! A one-shot service succeeds by exiting with 0, a daemon by sending
//! `ready`. Every event is printed; after the last service `init` sends
//! the kernel `[ready, failed]` and keeps reporting daemons that end.

#![no_std]
#![no_main]

use pharos_user::rights::{CONFIG, IRQ, MAP, RECEIVE, SEND, WRITE};
use pharos_user::{
    Error, Grant, Handle, Received, Status, config_read, debug_write, endpoint_create, open,
    process_status, receive, send, spawn_limited,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const ROOT: Handle = 2;
const REPORT: Handle = 3;
const FIRST_DEVICE: Handle = 4;

const VIRTIO_BLK: u32 = 0x1042_1af4;
const VIRTIO_NET: u32 = 0x1041_1af4;
const VIRTIO_CONSOLE: u32 = 0x1043_1af4;

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
    /// The second device with this ID (the writable store disk comes after
    /// the read-only one).
    SecondDevice(u32),
    /// The storage service's endpoint, to receive on (the service itself).
    StoreService,
    /// `init`'s endpoint, badged with the service's number (daemons).
    Report,
    /// The network service's endpoint, to receive on (the service itself).
    NetService,
    /// A network capability: `SEND` on the service endpoint, badged with
    /// this UDP port (0: an unbadged capability, which the service refuses).
    Network(u16),
    /// A storage capability: `SEND` on the storage service, badged with a
    /// namespace and the read-only bit (`pharos_proto::store`).
    Storage(u32),
    /// The inference service's endpoint, to receive on (the service).
    InferService,
    /// The trusted service's endpoint, to receive on (the service).
    TrustService,
}

struct Service {
    name: &'static str,
    path: &'static [u8],
    arg: u64,
    kind: Kind,
    caps: &'static [Cap],
    /// Indexes of services that must have succeeded first.
    after: &'static [usize],
    /// Pages it may `mem_map` (0: none).
    limit: u32,
}

const NET: Service = Service {
    name: "net",
    path: b"bin/net",
    arg: 0,
    kind: Kind::Daemon,
    caps: &[
        Cap::Console,
        Cap::Device(VIRTIO_NET),
        Cap::NetService,
        Cap::Report,
    ],
    after: &[],
    limit: 0,
};

/// 1 GiB: up to 16 clients' buffers of at most 32 MiB each, and the heap.
const STORE_LIMIT: u32 = 1 << 18;
/// 1 GiB (D-011): one S1 model, its 16 MiB read window, cache, and heap.
const INFER_LIMIT: u32 = 1 << 18;
/// Namespace 3, `models`, read-only (`pharos_proto::store`).
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;

const BOOT: &[Service] = &[
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console, Cap::Device(VIRTIO_BLK)],
        after: &[],
        limit: 0,
    },
    NET,
    Service {
        name: "store",
        path: b"bin/store",
        arg: 0,
        kind: Kind::Daemon,
        caps: &[
            Cap::Console,
            Cap::SecondDevice(VIRTIO_BLK),
            Cap::StoreService,
            Cap::Report,
        ],
        after: &[],
        limit: STORE_LIMIT,
    },
    // The inference service (#88): only `models`, read-only. It reports
    // ready without loading a model. Clients get no capability from `init`
    // in M3.2.
    Service {
        name: "infer",
        path: b"bin/infer",
        arg: 0,
        kind: Kind::Daemon,
        caps: &[
            Cap::Console,
            Cap::InferService,
            Cap::Report,
            Cap::Storage(MODELS_READ_ONLY),
        ],
        after: &[2],
        limit: INFER_LIMIT,
    },
    // The trusted service (#96, D-018): the trusted path's device and its
    // endpoint, nothing else. The agent runtime (#98) starts after it and
    // `init` sends it the runtime's `STOP` capability.
    Service {
        name: "trust",
        path: b"bin/trust",
        arg: 0,
        kind: Kind::Daemon,
        caps: &[Cap::Device(VIRTIO_CONSOLE), Cap::TrustService, Cap::Report],
        after: &[],
        limit: 0,
    },
];

const NETWORK: &[Service] = &[
    NET,
    Service {
        name: "echoer",
        path: b"bin/netclient",
        arg: 2,
        kind: Kind::Daemon,
        caps: &[Cap::Console, Cap::Network(40001), Cap::Report],
        after: &[0],
        limit: 0,
    },
    Service {
        name: "sender",
        path: b"bin/netclient",
        arg: 1,
        kind: Kind::OneShot,
        caps: &[Cap::Console, Cap::Network(40000)],
        after: &[1],
        limit: 0,
    },
    Service {
        name: "unbadged",
        path: b"bin/netclient",
        arg: 3,
        kind: Kind::OneShot,
        caps: &[Cap::Console, Cap::Network(0)],
        after: &[0],
        limit: 0,
    },
];

const TEST: &[Service] = &[
    Service {
        name: "first",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "daemon",
        path: b"bin/svc",
        arg: 1,
        kind: Kind::Daemon,
        caps: &[Cap::Console, Cap::Report],
        after: &[0],
        limit: 0,
    },
    Service {
        name: "crasher",
        path: b"bin/svc",
        arg: 2,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "after-crasher",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[2],
        limit: 0,
    },
    Service {
        name: "independent",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "missing",
        path: b"bin/no-such-program",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        caps: &[Cap::Console, Cap::Device(VIRTIO_BLK)],
        after: &[],
        limit: 0,
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
        2 => NETWORK,
        _ => &[],
    };
    let endpoints = (
        endpoint_create(),
        endpoint_create(),
        endpoint_create(),
        endpoint_create(),
        endpoint_create(),
    );
    let (Ok(events), Ok(net_service), Ok(store_service), Ok(infer_service), Ok(trust_service)) =
        endpoints
    else {
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
                Cap::NetService => Grant {
                    handle: net_service,
                    rights: RECEIVE,
                    badge: 0,
                },
                Cap::StoreService => Grant {
                    handle: store_service,
                    rights: RECEIVE,
                    badge: 0,
                },
                Cap::Storage(badge) => Grant {
                    handle: store_service,
                    rights: SEND,
                    badge: *badge,
                },
                Cap::InferService => Grant {
                    handle: infer_service,
                    rights: RECEIVE,
                    badge: 0,
                },
                Cap::TrustService => Grant {
                    handle: trust_service,
                    rights: RECEIVE,
                    badge: 0,
                },
                Cap::Network(port) => Grant {
                    handle: net_service,
                    rights: SEND,
                    badge: u32::from(*port),
                },
                Cap::Device(id) | Cap::SecondDevice(id) => match devices[..device_count]
                    .iter()
                    .filter(|d| d.1 == *id)
                    .nth(usize::from(matches!(cap, Cap::SecondDevice(_))))
                {
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
        let notify = Some((events, i as u32));
        let process = match spawn_limited(file, service.arg, caps, notify, service.limit) {
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
