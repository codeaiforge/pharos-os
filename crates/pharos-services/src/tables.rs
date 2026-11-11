//! The tables: argument 0 boot, 1 the `services` test kernel, 2 the
//! `network` test kernel, 3 the `supervision` test kernel, 4 the
//! `health` test kernel, 5 `aifail`, 6 `compromised`, 7 `soak`
//! ([`table`]).

use crate::rights::{GRANT, RECEIVE, SEND};
use crate::{
    Badge, CONSOLE, Dest, Ep, Gain, Give, Kind, Object, REPORT, ROOT, Restart, Service, arrived,
    device, give, receive, send,
};

pub const VIRTIO_BLK: u32 = 0x1042_1af4;
pub const VIRTIO_NET: u32 = 0x1041_1af4;
pub const VIRTIO_CONSOLE: u32 = 0x1043_1af4;

/// The program `init` registers with `trust` as the agent runtime.
pub const RUNTIME_PATH: &[u8] = b"bin/agents";
/// The agent runtime's handles: a full table for itself, and 16 for each
/// of its 16 agents.
pub const RUNTIME_HANDLES: u16 = 64 + 16 * 16;
/// `trust`'s badge for the agent runtime (`pharos_proto::trust::RUNTIME`).
pub const TRUST_RUNTIME_BADGE: u32 = 2;

/// 1 GiB: up to 16 clients' buffers of at most 32 MiB each, and the heap.
pub const STORE_LIMIT: u32 = 1 << 18;
/// 1 GiB (D-011): one S1 model, its 16 MiB read window, cache, and heap.
pub const INFER_LIMIT: u32 = 1 << 18;
/// The knowledge service (#144): its heap (each key's version index) and
/// up to 4 clients' buffers of at most 64 KiB each.
pub const KNOWLEDGE_LIMIT: u32 = 1024;
/// The agent runtime (#98): its own heap and buffers; agents' limits come
/// from its policy table, each at most this.
pub const AGENTS_LIMIT: u32 = 1 << 14;

/// Storage badges: a namespace, and bit 16 for read-only
/// (`pharos_proto::store`).
pub const AGENTS_TASKS: u32 = 5;
pub const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
pub const AUDIT_TRAIL: u32 = 6;
pub const KNOWLEDGE_STORE: u32 = 8;
/// `trust`'s knowledge client (`pharos_proto::knowledge::client`).
pub const KNOWLEDGE_TRUST: u32 = 2;
/// Audit clients (`pharos_proto::audit::client`).
pub const AUDIT_TRUST: u32 = 2;
pub const AUDIT_RUNTIME: u32 = 3;
/// The slirp gateway, where `cargo xtask` runs the host echo server.
pub const HOST_ECHO: Dest = ([10, 0, 2, 2], 47_000);
pub const OUR_IP: [u8; 4] = [10, 0, 2, 15];

/// The table `init` runs for its argument.
pub fn table(arg: u64) -> &'static [Service] {
    match arg {
        0 => BOOT,
        1 => TEST,
        2 => NETWORK,
        3 => SUPERVISE,
        4 => HEALTH,
        5 => AIFAIL,
        6 => COMPROMISED,
        7 => SOAK,
        _ => &[],
    }
}

const NET: Service = Service {
    name: "net",
    path: b"bin/net",
    arg: 0,
    kind: Kind::Daemon,
    restart: Restart::Up(3),
    caps: &[CONSOLE, device(VIRTIO_NET, 0), receive(Ep::Net), REPORT],
    net: &[],
    after: &[],
    limit: 0,
    gains: &[],
};

const STORE: Service = Service {
    name: "store",
    path: b"bin/store",
    arg: 0,
    kind: Kind::Daemon,
    restart: Restart::Up(3),
    // The writable disk comes after the read-only one.
    caps: &[CONSOLE, device(VIRTIO_BLK, 1), receive(Ep::Store), REPORT],
    net: &[],
    after: &[],
    limit: STORE_LIMIT,
    gains: &[],
};

const INFER_CAPS: &[Give] = &[
    CONSOLE,
    receive(Ep::Infer),
    REPORT,
    send(Ep::Store, MODELS_READ_ONLY),
];

/// The inference service, after the store at `store`.
const fn infer(store: usize) -> Service {
    Service {
        name: "infer",
        path: b"bin/infer",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: INFER_CAPS,
        net: &[],
        after: match store {
            0 => &[0],
            _ => &[2],
        },
        limit: INFER_LIMIT,
        gains: &[],
    }
}

const AUDIT_CAPS: &[Give] = &[
    CONSOLE,
    receive(Ep::Audit),
    REPORT,
    send(Ep::Store, AUDIT_TRAIL),
];

/// The audit service, after the store at `store`.
const fn audit(store: usize) -> Service {
    Service {
        name: "audit",
        path: b"bin/audit",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: AUDIT_CAPS,
        net: &[],
        after: match store {
            0 => &[0],
            _ => &[2],
        },
        limit: 0,
        gains: &[],
    }
}

/// A test service: `bin/svc` in mode `arg`.
const fn svc(
    name: &'static str,
    arg: u64,
    kind: Kind,
    restart: Restart,
    caps: &'static [Give],
    after: &'static [usize],
) -> Service {
    Service {
        name,
        path: b"bin/svc",
        arg,
        kind,
        restart,
        caps,
        net: &[],
        after,
        limit: 0,
        gains: &[],
    }
}

pub const BOOT: &[Service] = &BOOT_ENTRIES;

const BOOT_ENTRIES: [Service; 9] = [
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, device(VIRTIO_BLK, 0)],
        net: &[],
        after: &[],
        limit: 0,
        gains: &[],
    },
    NET,
    STORE,
    // The inference service (#88): only `models`, read-only. It reports
    // ready without loading a model.
    infer(2),
    // The audit service (#107): the only writer of the audit trail, in
    // namespace `audit`; before every service that writes records.
    audit(2),
    // The knowledge service (#144): the only writer of namespace
    // `knowledge`; before `trust` and the runtime, its two clients.
    Service {
        name: "knowledge",
        path: b"bin/knowledge",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            CONSOLE,
            receive(Ep::Knowledge),
            REPORT,
            send(Ep::Store, KNOWLEDGE_STORE),
        ],
        net: &[],
        after: &[2],
        limit: KNOWLEDGE_LIMIT,
        gains: &[],
    },
    // The trusted service (#96, D-018): the trusted path's device and its
    // endpoint, the audit service, whose chain head it shows (#107), and
    // the knowledge service, to mark versions verified (#144). It keeps
    // the runtime's and each agent's process capability, and its channel
    // to the runtime.
    Service {
        name: "trust",
        path: b"bin/trust",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            device(VIRTIO_CONSOLE, 0),
            receive(Ep::Trust),
            REPORT,
            send(Ep::Audit, AUDIT_TRUST),
            send(Ep::Knowledge, KNOWLEDGE_TRUST),
        ],
        net: &[],
        after: &[4, 5],
        limit: 0,
        gains: &[Gain::Processes, Gain::RuntimeChannel],
    },
    // The agent runtime (#98), after `trust`, which `init` then sends its
    // `STOP` capability: the runtime never decides whether it can be
    // stopped. `SEND` with `GRANT` on its own endpoint, to hand each agent
    // a badged `SEND`. Inference client 1 (it attaches its prompt buffer
    // at start). Its boot policy table is empty, so it gets no network,
    // files, or knowledge capability (handles 9 to 11, which it treats as
    // optional; M4.2 narrowing, #157): an entry needing one adds it here.
    Service {
        name: "agents",
        path: RUNTIME_PATH,
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            CONSOLE,
            give(
                Object::Endpoint(Ep::Agents),
                RECEIVE | SEND | GRANT,
                Badge::None,
            ),
            REPORT,
            ROOT,
            send(Ep::Infer, 1),
            send(Ep::Trust, TRUST_RUNTIME_BADGE),
            send(Ep::Store, AGENTS_TASKS),
            send(Ep::Audit, AUDIT_RUNTIME),
        ],
        net: &[],
        after: &[2, 3, 6],
        limit: AGENTS_LIMIT,
        gains: &[Gain::Processes],
    },
    // A virtio-blk disk added to a hotplug slot (M4.4, #171): started when
    // one arrives, never at boot, and stopped before its slot powers off.
    // Argument 2: it mounts the disk's image, says what it found, sends
    // `ready`, and keeps the device until stopped.
    Service {
        name: "disk",
        path: b"bin/virtio-blk",
        arg: 2,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[CONSOLE, arrived(VIRTIO_BLK), REPORT],
        net: &[],
        after: &[],
        limit: 0,
        gains: &[],
    },
];

pub const NETWORK: &[Service] = &[
    NET,
    Service {
        name: "echoer",
        path: b"bin/netclient",
        arg: 2,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[CONSOLE, send(Ep::Net, 40001), REPORT],
        net: &[(OUR_IP, 40000)],
        after: &[0],
        limit: 0,
        gains: &[],
    },
    Service {
        name: "sender",
        path: b"bin/netclient",
        arg: 1,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Net, 40000)],
        net: &[HOST_ECHO, (OUR_IP, 40001), (OUR_IP, 40999)],
        after: &[1],
        limit: 0,
        gains: &[],
    },
    // A badge over 16 bits is no port.
    Service {
        name: "unported",
        path: b"bin/netclient",
        arg: 3,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Net, 1 << 16)],
        net: &[HOST_ECHO],
        after: &[0],
        limit: 0,
        gains: &[],
    },
];

/// The `health` test kernel's table (M4.5): a daemon named `net` that
/// `table` with entry `i` running `bin/rogue` with `arg`, every other
/// field as shipped (M4.6, D-031): the AI services' failure and
/// hostile-service kernels.
const fn rogue(mut table: [Service; 9], i: usize, arg: u64) -> [Service; 9] {
    table[i].path = b"bin/rogue";
    table[i].arg = arg;
    table
}

/// The boot table's indexes of the inference service and the runtime.
pub const INFER: usize = 3;
pub const AGENTS: usize = 7;

/// The `aifail` kernel (M4.6, #182): `infer` is `rogue` 3, which sends
/// `ready` and never receives, so the runtime must start without it.
pub const AIFAIL: &[Service] = &rogue(BOOT_ENTRIES, INFER, 3);

/// The `compromised` kernel (M4.6, #183): `infer` is `rogue` 1 and the
/// runtime `rogue` 2, each probing what its exact manifest refuses.
pub const COMPROMISED: &[Service] = &rogue(rogue(BOOT_ENTRIES, INFER, 1), AGENTS, 2);

/// The runtime's first control client's badge (`pharos_proto::agents::CONTROL`).
const AGENTS_CONTROL: u32 = 0x100;

/// The `soak` kernel (M5.1, #189, testing.md): the boot table with the
/// runtime on its test policy table (argument 1, which has `worker`), and
/// `soaker`, `agentclient` 15, which runs one `worker` task after another
/// until the machine stops.
pub const SOAK: &[Service] = &soak(BOOT_ENTRIES);

const SOAKER_CAPS: &[Give] = &[CONSOLE, send(Ep::Agents, AGENTS_CONTROL), REPORT];

const fn soak(boot: [Service; 9]) -> [Service; 10] {
    let mut table = [
        boot[0], boot[1], boot[2], boot[3], boot[4], boot[5], boot[6], boot[7], boot[8], boot[8],
    ];
    table[AGENTS].arg = 1;
    table[9] = Service {
        name: "soaker",
        path: b"bin/agentclient",
        arg: 15,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: SOAKER_CAPS,
        net: &[],
        after: &[AGENTS],
        limit: 64,
        gains: &[],
    };
    table
}

/// sends `ready` and never receives on the network endpoint `init` checks
/// it on, so it answers no health check (restarted once, then given up),
/// and one whose name no endpoint has, which is never checked.
pub const HEALTH: &[Service] = &[
    svc(
        "net",
        1,
        Kind::Daemon,
        Restart::Up(1),
        &[CONSOLE, REPORT],
        &[],
    ),
    svc(
        "steady",
        6,
        Kind::Daemon,
        Restart::Up(1),
        &[CONSOLE, REPORT],
        &[],
    ),
];

pub const TEST: &[Service] = &[
    svc("first", 0, Kind::OneShot, Restart::Never, &[CONSOLE], &[]),
    svc(
        "daemon",
        1,
        Kind::Daemon,
        Restart::Up(3),
        &[CONSOLE, REPORT],
        &[0],
    ),
    svc("crasher", 2, Kind::OneShot, Restart::Never, &[CONSOLE], &[]),
    svc(
        "after-crasher",
        0,
        Kind::OneShot,
        Restart::Never,
        &[CONSOLE],
        &[2],
    ),
    svc(
        "independent",
        0,
        Kind::OneShot,
        Restart::Never,
        &[CONSOLE],
        &[],
    ),
    Service {
        name: "missing",
        path: b"bin/no-such-program",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE],
        net: &[],
        after: &[],
        limit: 0,
        gains: &[],
    },
    Service {
        name: "virtio-blk",
        path: b"bin/virtio-blk",
        arg: 0,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, device(VIRTIO_BLK, 0)],
        net: &[],
        after: &[],
        limit: 0,
        gains: &[],
    },
];

/// The `supervision` test kernel's table (#100): the storage, audit,
/// trusted (#152), and inference services, a daemon that never reports
/// ready (restarted once), one that crashes after each start (restarted 3
/// times, with growing delays), one that crashes and is never restarted,
/// one the kernel stops, an inference client the kernel kills services
/// under, and a one-shot that holds a storage buffer and exits.
pub const SUPERVISE: &[Service] = &[
    STORE,
    // Every later event is an audit record and a `trust` line (#152).
    audit(0),
    Service {
        name: "trust",
        path: b"bin/trust",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            device(VIRTIO_CONSOLE, 0),
            receive(Ep::Trust),
            REPORT,
            send(Ep::Audit, AUDIT_TRUST),
        ],
        net: &[],
        after: &[1],
        limit: 0,
        gains: &[Gain::Processes, Gain::RuntimeChannel],
    },
    infer(0),
    // One restart: no `ready` in 10 s counts as a crash (#150).
    svc(
        "silent",
        3,
        Kind::Daemon,
        Restart::Up(1),
        &[CONSOLE, REPORT],
        &[],
    ),
    svc(
        "flaky",
        4,
        Kind::Daemon,
        Restart::Up(3),
        &[CONSOLE, REPORT],
        &[],
    ),
    // Crashes as `flaky` does, and is never restarted (#150).
    svc(
        "brittle",
        4,
        Kind::Daemon,
        Restart::Never,
        &[CONSOLE, REPORT],
        &[],
    ),
    svc(
        "steady",
        6,
        Kind::Daemon,
        Restart::Up(3),
        &[CONSOLE, REPORT],
        &[],
    ),
    // Inference client 2; `models` read-write, to put the model in place.
    Service {
        name: "client",
        path: b"bin/inferclient",
        arg: 4,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Infer, 2), send(Ep::Store, 3)],
        net: &[],
        after: &[0, 3],
        limit: 1024,
        gains: &[],
    },
    // Namespace 1, `test`, read-write. Last, so nothing else attaches to
    // the store while the kernel measures it.
    Service {
        name: "holder",
        path: b"bin/svc",
        arg: 5,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Store, 1)],
        net: &[],
        after: &[0],
        limit: 2048,
        gains: &[],
    },
];
