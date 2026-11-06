//! The service manager (issue #61, services.md): the first user process.
//!
//! The kernel gives it handles 1 debug console, 2 the root filesystem
//! (`READ | GRANT`), 3 the kernel's report endpoint (`SEND`), and from 4
//! each supported device (`MAP | CONFIG | IRQ | GRANT`). The argument
//! selects a service table (0: boot; 1: the `services` test kernel; 2: the
//! `network` test kernel; 3: the `supervision` test kernel).
//! Services start one after another; each gets only what its entry lists.
//! A one-shot service succeeds by exiting with 0, a daemon by sending
//! `ready` within 10 s (else it is stopped). Every event is printed; after
//! the last service `init` sends the kernel `[ready, failed]` and keeps
//! supervising (#100): a daemon that crashes or exits is restarted, at
//! most 3 times, with the same capabilities on the same endpoints, so its
//! clients reach the new one; one that was stopped is never restarted.
//! When any service ends, `init` sends the storage and inference services
//! `RELEASE` for the badges it gave it, so they free its slots.
//! Each time the network service reports ready, `init` sends it every
//! network client's destinations (`ALLOW`, #109), on its own unbadged
//! capability: a client can send only where its entry lists.

#![no_std]
#![no_main]

extern crate alloc;

use pharos_programs::supervise::{self, Restart};
use pharos_proto::audit;
use pharos_proto::infer::{self, Request as InferRequest};
use pharos_proto::net::{self, Allowed, Dest, Request as NetRequest};
use pharos_proto::store::{self, Request as StoreRequest};
use pharos_proto::trust::{self, Event, Names};
use pharos_user::rights::{CONFIG, GRANT, IRQ, MAP, READ, RECEIVE, SEND, STOP, WAIT, WRITE};
use pharos_user::{
    Class, Error, Grant, Handle, Limits, MAX_SPAWN_CAPS, Received, Status, call_timeout,
    config_read, debug_write, endpoint_create, open, process_status, receive_timeout, send,
    spawn_with, try_send, uptime,
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
    /// this UDP port, and the destinations it may send to (#109). Never
    /// badge 0: that is `init`'s own, which may send `ALLOW`.
    Network(u32, &'static [Dest]),
    /// A storage capability: `SEND` on the storage service, badged with a
    /// namespace and the read-only bit (`pharos_proto::store`).
    Storage(u32),
    /// The inference service's endpoint, to receive on (the service).
    InferService,
    /// The trusted service's endpoint, to receive on (the service).
    TrustService,
    /// The agent runtime's endpoint: `RECEIVE`, and `SEND` with `GRANT`
    /// so it can hand each agent a badged `SEND` (the runtime itself).
    AgentsService,
    /// The root filesystem, read-only.
    Root,
    /// `SEND` on the inference service, badged as this client number.
    Inference(u32),
    /// `SEND` on the trusted service, badged as the agent runtime.
    TrustRuntime,
    /// The audit service's endpoint, to receive on (the service, #107).
    AuditService,
    /// `SEND` on the audit service, badged as this client
    /// (`pharos_proto::audit::client`).
    Audit(u32),
    /// The knowledge service's endpoint, to receive on (the service, #144).
    KnowledgeService,
    /// `SEND` on the knowledge service, badged as this client
    /// (`pharos_proto::knowledge::client`).
    Knowledge(u32),
}

struct Service {
    name: &'static str,
    path: &'static [u8],
    arg: u64,
    kind: Kind,
    /// What happens when it crashes, exits, or sends no `ready` in time
    /// (#150, D-026).
    restart: Restart,
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
    restart: Restart::Up(3),
    caps: &[
        Cap::Console,
        Cap::Device(VIRTIO_NET),
        Cap::NetService,
        Cap::Report,
    ],
    after: &[],
    limit: 0,
};

/// The agent runtime's handles: a full table for itself, and 16 for each
/// of its 16 agents.
const RUNTIME_HANDLES: u16 = 64 + 16 * 16;

/// 1 GiB: up to 16 clients' buffers of at most 32 MiB each, and the heap.
const STORE_LIMIT: u32 = 1 << 18;
/// 1 GiB (D-011): one S1 model, its 16 MiB read window, cache, and heap.
const INFER_LIMIT: u32 = 1 << 18;
/// The knowledge service (#144): its heap (each key's version index) and
/// up to 4 clients' buffers of at most 64 KiB each.
const KNOWLEDGE_LIMIT: u32 = 1024;
/// The agent runtime (#98): its own heap and buffers; agents' limits come
/// from its policy table, each at most this.
const AGENTS_LIMIT: u32 = 1 << 14;
/// The program `init` registers with `trust` as the agent runtime.
const RUNTIME_PATH: &[u8] = b"bin/agents";
/// `pharos_proto::trust`: `RUNTIME`, sent through `init`'s own unbadged
/// handle (badge 0, `trust::INIT`).
const TRUST_RUNTIME: [u8; 2] = [1, 1];
const TRUST_RUNTIME_BADGE: u32 = 2;
/// Namespace 5, `agents`, read-write: the runtime's tasks (#99).
const AGENTS_TASKS: u32 = 5;
/// Namespace 3, `models`, read-only (`pharos_proto::store`).
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
/// Namespace 6, `audit`, read-write: the audit trail (#107).
const AUDIT_TRAIL: u32 = 6;
/// Namespace 7, `files`, read-only: the files the user gives agents (#127).
const FILES_READ_ONLY: u32 = 7 | 1 << 16;
/// Namespace 8, `knowledge`, read-write: shared knowledge (#144).
const KNOWLEDGE_STORE: u32 = 8;
/// The knowledge service's client numbers
/// (`pharos_proto::knowledge::client`).
const KNOWLEDGE_RUNTIME: u32 = 1;
const KNOWLEDGE_TRUST: u32 = 2;
/// The audit service's client numbers (`pharos_proto::audit::client`).
const AUDIT_TRUST: u32 = 2;
const AUDIT_RUNTIME: u32 = 3;
/// The runtime's UDP port, for its agents' datagrams (#109).
const RUNTIME_PORT: u32 = 40_100;
/// The slirp gateway, where `cargo xtask` runs the host echo server.
const HOST_ECHO: Dest = ([10, 0, 2, 2], 47_000);
const OUR_IP: [u8; 4] = [10, 0, 2, 15];

const BOOT: &[Service] = &[
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
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
        restart: Restart::Up(3),
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
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::InferService,
            Cap::Report,
            Cap::Storage(MODELS_READ_ONLY),
        ],
        after: &[2],
        limit: INFER_LIMIT,
    },
    // The audit service (#107): the only writer of the audit trail, in
    // namespace `audit`; before every service that writes records.
    Service {
        name: "audit",
        path: b"bin/audit",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::AuditService,
            Cap::Report,
            Cap::Storage(AUDIT_TRAIL),
        ],
        after: &[2],
        limit: 0,
    },
    // The knowledge service (#144): the only writer of namespace
    // `knowledge`; before `trust` and the runtime, its two clients.
    Service {
        name: "knowledge",
        path: b"bin/knowledge",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::KnowledgeService,
            Cap::Report,
            Cap::Storage(KNOWLEDGE_STORE),
        ],
        after: &[2],
        limit: KNOWLEDGE_LIMIT,
    },
    // The trusted service (#96, D-018): the trusted path's device and its
    // endpoint, the audit service, whose chain head it shows (#107), and
    // the knowledge service, to mark versions verified (#144).
    Service {
        name: "trust",
        path: b"bin/trust",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Device(VIRTIO_CONSOLE),
            Cap::TrustService,
            Cap::Report,
            Cap::Audit(AUDIT_TRUST),
            Cap::Knowledge(KNOWLEDGE_TRUST),
        ],
        after: &[4, 5],
        limit: 0,
    },
    // The agent runtime (#98), after `trust`, which `init` then sends its
    // `STOP` capability: the runtime never decides whether it can be
    // stopped. Inference client 1. Its boot policy table is empty.
    Service {
        name: "agents",
        path: RUNTIME_PATH,
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::AgentsService,
            Cap::Report,
            Cap::Root,
            Cap::Inference(1),
            Cap::TrustRuntime,
            Cap::Storage(AGENTS_TASKS),
            Cap::Audit(AUDIT_RUNTIME),
            // The union of its policy table's destinations: none.
            Cap::Network(RUNTIME_PORT, &[]),
            Cap::Storage(FILES_READ_ONLY),
            Cap::Knowledge(KNOWLEDGE_RUNTIME),
        ],
        after: &[2, 3, 5, 6],
        limit: AGENTS_LIMIT,
    },
];

const NETWORK: &[Service] = &[
    NET,
    Service {
        name: "echoer",
        path: b"bin/netclient",
        arg: 2,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::Network(40001, &[(OUR_IP, 40000)]),
            Cap::Report,
        ],
        after: &[0],
        limit: 0,
    },
    Service {
        name: "sender",
        path: b"bin/netclient",
        arg: 1,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[
            Cap::Console,
            Cap::Network(40000, &[HOST_ECHO, (OUR_IP, 40001), (OUR_IP, 40999)]),
        ],
        after: &[1],
        limit: 0,
    },
    // A badge over 16 bits is no port.
    Service {
        name: "unported",
        path: b"bin/netclient",
        arg: 3,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console, Cap::Network(1 << 16, &[HOST_ECHO])],
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
        restart: Restart::Never,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "daemon",
        path: b"bin/svc",
        arg: 1,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[Cap::Console, Cap::Report],
        after: &[0],
        limit: 0,
    },
    Service {
        name: "crasher",
        path: b"bin/svc",
        arg: 2,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "after-crasher",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console],
        after: &[2],
        limit: 0,
    },
    Service {
        name: "independent",
        path: b"bin/svc",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "missing",
        path: b"bin/no-such-program",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console],
        after: &[],
        limit: 0,
    },
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console, Cap::Device(VIRTIO_BLK)],
        after: &[],
        limit: 0,
    },
];

/// The `supervision` test kernel's table (#100): the storage and inference
/// services, a daemon that never reports ready (restarted once), one
/// that crashes after each start (restarted 3 times, with growing
/// delays), one that crashes and is never restarted, one the kernel stops, an inference client the kernel
/// kills services under, and a one-shot that holds a storage buffer and
/// exits.
const SUPERVISE: &[Service] = &[
    Service {
        name: "store",
        path: b"bin/store",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::SecondDevice(VIRTIO_BLK),
            Cap::StoreService,
            Cap::Report,
        ],
        after: &[],
        limit: STORE_LIMIT,
    },
    Service {
        name: "infer",
        path: b"bin/infer",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            Cap::Console,
            Cap::InferService,
            Cap::Report,
            Cap::Storage(MODELS_READ_ONLY),
        ],
        after: &[0],
        limit: INFER_LIMIT,
    },
    Service {
        name: "silent",
        path: b"bin/svc",
        arg: 3,
        kind: Kind::Daemon,
        // One restart: no `ready` in 10 s counts as a crash (#150).
        restart: Restart::Up(1),
        caps: &[Cap::Console, Cap::Report],
        after: &[],
        limit: 0,
    },
    Service {
        name: "flaky",
        path: b"bin/svc",
        arg: 4,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[Cap::Console, Cap::Report],
        after: &[],
        limit: 0,
    },
    // Crashes as `flaky` does, and is never restarted (#150).
    Service {
        name: "brittle",
        path: b"bin/svc",
        arg: 4,
        kind: Kind::Daemon,
        restart: Restart::Never,
        caps: &[Cap::Console, Cap::Report],
        after: &[],
        limit: 0,
    },
    Service {
        name: "steady",
        path: b"bin/svc",
        arg: 6,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[Cap::Console, Cap::Report],
        after: &[],
        limit: 0,
    },
    // Inference client 2; `models` read-write, to put the model in place.
    Service {
        name: "client",
        path: b"bin/inferclient",
        arg: 4,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console, Cap::Inference(2), Cap::Storage(3)],
        after: &[0, 1],
        limit: 1024,
    },
    // Namespace 1, `test`, read-write. Last, so nothing else attaches to
    // the store while the kernel measures it.
    Service {
        name: "holder",
        path: b"bin/svc",
        arg: 5,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[Cap::Console, Cap::Storage(1)],
        after: &[0],
        limit: 2048,
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

fn decimal(mut v: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    loop {
        at -= 1;
        out[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &out[at..];
        }
    }
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
    /// Started; a daemon has not sent `ready` yet.
    Running(Handle),
    /// A daemon that sent `ready`.
    Ok(Handle),
    /// Waiting to be started again at this `uptime` (#150).
    Restarting(u64),
    /// A one-shot service that exited with 0.
    Done,
    Failed,
}

/// How long a daemon may take to send `ready` (#100).
const READY_US: u64 = 10_000_000;
/// How long `init` waits for an audit record.
const AUDIT_US: u64 = 1_000_000;
/// How long a service may take to answer `RELEASE`.
const RELEASE_US: u64 = 1_000_000;

struct Init {
    table: &'static [Service],
    events: Handle,
    reply: Handle,
    net: Handle,
    store: Handle,
    infer: Handle,
    trust: Handle,
    agents: Handle,
    audit: Handle,
    knowledge: Handle,
    devices: [(Handle, u32); 8],
    device_count: usize,
    state: [State; MAX_SERVICES],
    /// When each running daemon must have sent `ready`.
    deadline: [u64; MAX_SERVICES],
    restarts: [u8; MAX_SERVICES],
    /// Whether each start is in the audit trail yet (#108).
    recorded: [bool; MAX_SERVICES],
}

impl Init {
    /// The capability `cap` for service `i`, if `init` has it.
    fn grant(&self, i: usize, cap: &Cap) -> Option<Grant> {
        let g = |handle, rights, badge| {
            Some(Grant {
                handle,
                rights,
                badge,
            })
        };
        match cap {
            Cap::Console => g(CONSOLE, WRITE, 0),
            Cap::Report => g(self.events, SEND, i as u32 + 1),
            Cap::NetService => g(self.net, RECEIVE, 0),
            Cap::StoreService => g(self.store, RECEIVE, 0),
            Cap::Storage(badge) => g(self.store, SEND, *badge),
            Cap::InferService => g(self.infer, RECEIVE, 0),
            Cap::TrustService => g(self.trust, RECEIVE, 0),
            Cap::AgentsService => g(self.agents, RECEIVE | SEND | GRANT, 0),
            Cap::Root => g(ROOT, READ, 0),
            Cap::Inference(badge) => g(self.infer, SEND, *badge),
            Cap::TrustRuntime => g(self.trust, SEND, TRUST_RUNTIME_BADGE),
            Cap::AuditService => g(self.audit, RECEIVE, 0),
            Cap::Audit(badge) => g(self.audit, SEND, *badge),
            Cap::KnowledgeService => g(self.knowledge, RECEIVE, 0),
            Cap::Knowledge(badge) => g(self.knowledge, SEND, *badge),
            Cap::Network(0, _) => None,
            Cap::Network(port, _) => g(self.net, SEND, *port),
            Cap::Device(id) | Cap::SecondDevice(id) => {
                let nth = usize::from(matches!(cap, Cap::SecondDevice(_)));
                let &(handle, _) = self.devices[..self.device_count]
                    .iter()
                    .filter(|d| d.1 == *id)
                    .nth(nth)?;
                g(handle, MAP | CONFIG | IRQ, 0)
            }
        }
    }

    /// Starts service `i` with exactly what its entry lists.
    fn start(&mut self, i: usize) {
        let service = &self.table[i];
        self.state[i] = State::Failed;
        let Ok(file) = open(ROOT, service.path) else {
            say(service.name, "missing program", None);
            return;
        };
        let mut grants = [Grant {
            handle: 0,
            rights: 0,
            badge: 0,
        }; MAX_SPAWN_CAPS];
        for (grant, cap) in grants.iter_mut().zip(service.caps) {
            match self.grant(i, cap) {
                Some(g) => *grant = g,
                None => {
                    let _ = pharos_user::delete(file);
                    say(service.name, "no device", None);
                    return;
                }
            }
        }
        let caps = &grants[..service.caps.len().min(MAX_SPAWN_CAPS)];
        let notify = Some((self.events, i as u32));
        // D-022: `trust` keeps `init`'s class, so the emergency stop runs
        // ahead of everything else; every other service is below it.
        // ponytail: chosen by name; a table field if a second one is trusted.
        let class = if service.name == "trust" {
            Class::Same
        } else {
            Class::Services
        };
        // The runtime starts up to 16 agents of 16 handles each (D-022);
        // every other service gets a full table and no descendants.
        let (processes, handles) = if service.path == RUNTIME_PATH {
            (16, RUNTIME_HANDLES)
        } else {
            (0, 0)
        };
        let limits = Limits {
            pages: service.limit,
            class,
            processes,
            handles,
        };
        let spawned = spawn_with(file, service.arg, caps, notify, limits);
        let _ = pharos_user::delete(file);
        let process = match spawned {
            Ok(process) => process,
            Err(e) => {
                say(service.name, "spawn failed, error", Some(e.code()));
                return;
            }
        };
        say(service.name, "started", None);
        // `trust` gets the runtime's STOP before the runtime can start any
        // agent; a failed send leaves the runtime unstoppable, so stop it.
        if service.path == RUNTIME_PATH {
            let sent = send(self.trust, &TRUST_RUNTIME, process, STOP | WAIT, 0);
            if sent.is_err() {
                let _ = pharos_user::process_stop(process);
                say(service.name, "not registered with trust", None);
            }
        }
        self.state[i] = State::Running(process);
        self.deadline[i] = uptime().saturating_add(READY_US);
        self.recorded[i] = false;
    }

    /// Records every start not yet in the audit trail (#108): a `start`
    /// event per service, with how many capabilities its entry lists.
    /// Starts before the audit service was ready are recorded once it is;
    /// a record that fails is not tried again.
    fn record_starts(&mut self) {
        let ready = self
            .table
            .iter()
            .position(|s| s.path == b"bin/audit")
            .is_some_and(|a| matches!(self.state[a], State::Ok(_)));
        if !ready {
            return;
        }
        for i in 0..self.table.len().min(MAX_SERVICES) {
            let started = matches!(
                self.state[i],
                State::Running(_) | State::Ok(_) | State::Done
            );
            if !started || self.recorded[i] {
                continue;
            }
            self.recorded[i] = true;
            let service = &self.table[i];
            let mut d = [0u8; 20];
            let mut detail = [0u8; 40];
            let count = decimal(service.caps.len() as u64, &mut d);
            let k = count.len();
            detail[..k].copy_from_slice(count);
            detail[k..k + 13].copy_from_slice(b" capabilities");
            let entry = audit::Entry {
                kind: audit::Kind::Event,
                refers: 0,
                actor: service.name.as_bytes(),
                task: 0,
                attempt: 0,
                action: audit::action::START,
                permission: None,
                service: b"init",
                outcome: audit::outcome::OK,
                detail: &detail[..k + 13],
            };
            let mut msg = [0u8; 256];
            if let Some(n) = audit::encode(&audit::Request::Append(entry), &mut msg) {
                // The request is sent from this buffer too.
                let mut out = [0u8; 256];
                // No badge: the audit service knows `init` by that.
                let _ = call_timeout(self.audit, &msg[..n], self.reply, &mut out, AUDIT_US);
            }
        }
    }

    /// True if the entry running `path` has succeeded.
    fn up(&self, path: &[u8]) -> bool {
        (self.table.iter())
            .position(|s| s.path == path)
            .is_some_and(|i| matches!(self.state[i], State::Ok(_)))
    }

    /// A `service` event in the audit trail (#151), once the audit service
    /// is ready (before then only the services it needs can fail).
    fn record(&self, actor: &[u8], detail: &[u8]) {
        if !self.up(b"bin/audit") {
            return;
        }
        let entry = audit::Entry {
            kind: audit::Kind::Event,
            refers: 0,
            actor,
            task: 0,
            attempt: 0,
            action: audit::action::SERVICE,
            permission: None,
            service: b"init",
            outcome: audit::outcome::OK,
            detail: &detail[..detail.len().min(audit::MAX_DETAIL)],
        };
        let mut msg = [0u8; 256];
        if let Some(n) = audit::encode(&audit::Request::Append(entry), &mut msg) {
            let mut out = [0u8; 256];
            let _ = call_timeout(self.audit, &msg[..n], self.reply, &mut out, AUDIT_US);
        }
    }

    /// Tells `trust` (#151), if it runs, trying for at most 100 ms: it
    /// waits in `receive` almost always, and `init` never waits on it.
    fn tell_trust(&self, req: &trust::Request<'_>) {
        let mut msg = [0u8; 256];
        let Some(n) = trust::encode(req, &mut msg).filter(|_| self.up(b"bin/trust")) else {
            return;
        };
        for _ in 0..10 {
            if try_send(self.trust, &msg[..n]).is_ok() {
                return;
            }
            pharos_user::sleep(10_000);
        }
    }

    /// The system's state after the boot sequence (#151): ready if every
    /// entry succeeded, else what failed; to the trail and `trust`. The
    /// kernel gets its `[ready, failed]` as before.
    fn report_ready(&self, ready: usize) {
        let failed: alloc::vec::Vec<&[u8]> = (self.table.iter().zip(&self.state))
            .filter(|(_, s)| !matches!(s, State::Ok(_) | State::Done))
            .map(|(t, _)| t.name.as_bytes())
            .collect();
        let mut d = [0u8; 20];
        let detail = if failed.is_empty() {
            [&b"ready "[..], decimal(ready as u64, &mut d), b" services"].concat()
        } else {
            let mut v = [
                &b"not ready "[..],
                decimal(failed.len() as u64, &mut d),
                b" failed: ",
            ]
            .concat();
            v.extend_from_slice(&failed.join(&b", "[..]));
            v
        };
        self.record(b"init", &detail);
        let mut wire = [0u8; 200];
        let shown = &failed[..failed.len().min(trust::MAX_NAMES)];
        let (event, count) = match failed.len() {
            0 => (Event::Ready, ready),
            n => (Event::NotReady, n),
        };
        self.tell_trust(&trust::Request::Service {
            event,
            name: b"",
            numbers: [count as u32, 0, 0],
            names: Names::build(shown, &mut wire).unwrap_or_default(),
        });
    }

    /// Tells the storage and inference services that service `i`'s
    /// capabilities on them are gone, so they free its slots (#100).
    fn release(&self, i: usize) {
        for cap in self.table[i].caps {
            let (endpoint, client, msg) = match cap {
                Cap::Storage(badge) => {
                    let mut msg = [0u8; 16];
                    let n = store::encode(&StoreRequest::Release { client: *badge }, &mut msg);
                    (self.store, *badge, n.map(|n| (msg, n)))
                }
                Cap::Inference(badge) => {
                    let mut msg = [0u8; 16];
                    let n = infer::encode(&InferRequest::Release { client: *badge }, &mut msg);
                    (self.infer, *badge, n.map(|n| (msg, n)))
                }
                _ => continue,
            };
            let Some((msg, n)) = msg else { continue };
            let mut buf = [0u8; 16];
            let answered = call_timeout(endpoint, &msg[..n], self.reply, &mut buf, RELEASE_US)
                .is_ok_and(|r| matches!(r, Received::Message { len, .. } if len >= 1))
                && buf[0] == 0;
            if !answered {
                say(
                    self.table[i].name,
                    "slot not released, badge",
                    Some(u64::from(client)),
                );
            }
        }
    }

    /// Sends the network service every client's destinations (#109).
    fn allow(&self) {
        for (service, cap) in self
            .table
            .iter()
            .flat_map(|s| s.caps.iter().map(move |c| (s, c)))
        {
            let Cap::Network(port, dests) = *cap else {
                continue;
            };
            let req = Allowed::new(dests)
                .zip(u16::try_from(port).ok())
                .map(|(dests, client)| NetRequest::Allow { client, dests });
            let mut msg = [0u8; 64];
            let Some(n) = req.and_then(|r| net::encode(&r, &mut msg)) else {
                continue;
            };
            // The request is sent from this buffer too.
            let mut buf = [0u8; 64];
            let answered = call_timeout(self.net, &msg[..n], self.reply, &mut buf, RELEASE_US)
                .is_ok_and(|r| matches!(r, Received::Message { len, .. } if len >= 1))
                && buf[0] == net::OK;
            if !answered {
                say(
                    service.name,
                    "destinations not sent, port",
                    Some(port.into()),
                );
            }
        }
    }

    /// Service `j`'s process ended (its notification bit was set).
    fn ended(&mut self, j: usize) {
        let (State::Running(p) | State::Ok(p)) = self.state[j] else {
            return;
        };
        let service = &self.table[j];
        let status = process_status(p);
        if status == Ok(Status::Running) {
            return;
        }
        let _ = pharos_user::delete(p);
        self.release(j);
        let crashed = match status {
            Ok(Status::Exited(0)) if service.kind == Kind::OneShot => {
                say(service.name, "done", None);
                self.state[j] = State::Done;
                return;
            }
            Ok(Status::Exited(code)) => {
                say(service.name, "exited", Some(code));
                true
            }
            Ok(Status::Killed(vector)) => {
                say(service.name, "killed", Some(vector));
                true
            }
            Ok(Status::Stopped) => {
                say(service.name, "stopped; not restarted", None);
                false
            }
            _ => false,
        };
        self.state[j] = State::Failed;
        if crashed {
            self.crashed(j);
        }
    }

    /// Service `j` crashed, exited, or sent no `ready` in time: restarted
    /// after its policy's delay, or left (#150). One the user stopped
    /// never comes here: the trusted path's safe mode.
    fn crashed(&mut self, j: usize) {
        let service = &self.table[j];
        let Some(wait) = supervise::delay(service.restart, self.restarts[j]) else {
            let why = match service.restart {
                Restart::Never => "not restarted: restart policy never",
                Restart::Up(_) => "not restarted: restarts used up",
            };
            say(service.name, why, None);
            return;
        };
        self.restarts[j] += 1;
        self.state[j] = State::Restarting(uptime().saturating_add(wait));
        let mut d = [[0u8; 20]; 3];
        let [a, b, c] = &mut d;
        let mut line = [
            &b"init: "[..],
            service.name.as_bytes(),
            b" restarting ",
            decimal(u64::from(self.restarts[j]), a),
            b" of ",
            decimal(u64::from(service.restart.limit()), b),
            b" in ",
            decimal(wait / 1000, c),
            b" ms",
        ]
        .concat();
        let after: alloc::vec::Vec<&[usize]> = self.table.iter().map(|s| s.after).collect();
        for (k, d) in supervise::dependents(&after, j).into_iter().enumerate() {
            line.extend_from_slice(if k == 0 { b"; used by " } else { b", " });
            line.extend_from_slice(self.table[d].name.as_bytes());
        }
        let _ = debug_write(CONSOLE, &line);
    }

    /// Starts services whose restart delay has passed, and stops daemons
    /// that did not send `ready` in time. Returns how long until the next
    /// deadline.
    fn check_ready(&mut self) -> u64 {
        let now = uptime();
        let mut wait = u64::MAX;
        for j in 0..self.table.len().min(MAX_SERVICES) {
            if let State::Restarting(at) = self.state[j] {
                if now >= at {
                    self.start(j);
                } else {
                    wait = wait.min(at - now);
                    continue;
                }
            }
            let State::Running(p) = self.state[j] else {
                continue;
            };
            if self.table[j].kind != Kind::Daemon {
                continue;
            }
            if now >= self.deadline[j] {
                say(self.table[j].name, "no ready within 10 s; stopped", None);
                let _ = pharos_user::process_stop(p);
                let _ = pharos_user::delete(p);
                self.release(j);
                self.state[j] = State::Failed;
                // Counted as a crash (D-026 design, #149).
                self.crashed(j);
                if let State::Restarting(at) = self.state[j] {
                    wait = wait.min(at.saturating_sub(now));
                }
            } else {
                wait = wait.min(self.deadline[j] - now);
            }
        }
        wait
    }

    /// Waits for one event (a `ready`, an end, or a deadline) and handles it.
    fn step(&mut self) {
        self.record_starts();
        let wait = self.check_ready();
        let mut buf = [0u8; 16];
        match receive_timeout(self.events, &mut buf, wait) {
            Ok(Received::Message { badge, cap, .. }) => {
                if cap != 0 {
                    let _ = pharos_user::delete(cap);
                }
                let i = (badge as usize).wrapping_sub(1);
                if let (Some(service), Some(State::Running(p))) =
                    (self.table.get(i), self.state.get(i).copied())
                {
                    if service.kind == Kind::Daemon {
                        say(service.name, "ready", None);
                        self.state[i] = State::Ok(p);
                        if service.path == b"bin/net" {
                            self.allow();
                        }
                    }
                }
            }
            Ok(Received::Notification(bits)) => {
                for j in 0..self.table.len().min(MAX_SERVICES) {
                    if bits & 1 << j != 0 {
                        self.ended(j);
                    }
                }
            }
            _ => {}
        }
    }
}

fn main(arg: u64) -> u64 {
    let table = match arg {
        0 => BOOT,
        1 => TEST,
        2 => NETWORK,
        3 => SUPERVISE,
        _ => &[],
    };
    let mut handles = [0; 9];
    for h in handles.iter_mut() {
        match endpoint_create() {
            Ok(e) => *h = e,
            Err(_) => {
                let _ = debug_write(CONSOLE, b"init: cannot create an endpoint");
                return 1;
            }
        }
    }
    let [
        events,
        reply,
        net,
        store,
        infer,
        trust,
        agents,
        audit,
        knowledge,
    ] = handles;
    let (devices, device_count) = devices();
    let mut init = Init {
        table,
        events,
        reply,
        net,
        store,
        infer,
        trust,
        agents,
        audit,
        knowledge,
        devices,
        device_count,
        state: [State::Pending; MAX_SERVICES],
        deadline: [0; MAX_SERVICES],
        restarts: [0; MAX_SERVICES],
        recorded: [false; MAX_SERVICES],
    };
    for (i, service) in table.iter().enumerate().take(MAX_SERVICES) {
        let met = service
            .after
            .iter()
            .all(|&a| matches!(init.state[a], State::Ok(_) | State::Done));
        if !met {
            say(service.name, "skipped", None);
            init.state[i] = State::Failed;
            continue;
        }
        init.start(i);
        // Until this service succeeds or fails; others' events too.
        while matches!(init.state[i], State::Running(_) | State::Restarting(_)) {
            init.step();
        }
    }
    let ready = init
        .state
        .iter()
        .filter(|s| matches!(s, State::Ok(_) | State::Done))
        .count();
    let failed = table.len().min(MAX_SERVICES) - ready;
    // The trail and `trust` first: the kernel may end the boot check
    // once it has the summary.
    init.report_ready(ready);
    let _ = send(REPORT, &[ready as u8, failed as u8], 0, 0, 0);

    // Keep supervising: restarts, and `ready` from restarted daemons.
    loop {
        init.step();
    }
}
