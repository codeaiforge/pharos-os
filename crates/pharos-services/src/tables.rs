//! The tables: argument 0 boot, 1 the `services` test kernel, 2 the
//! `network` test kernel, 3 the `supervision` test kernel, 4 the
//! `health` test kernel, 5 `aifail`, 6 `compromised`, 7 `soak`, 8 `tls`,
//! 9 `tls_norandom`, 10 `secrets`, 11 `vault`, 12 `bridge` ([`table`]); each table's
//! routes ([`routes`]).

use crate::rights::{GRANT, READ, RECEIVE, SEND};
use crate::{
    Approve, Badge, CONSOLE, Dest, Ep, Gain, Give, Kind, Object, REPORT, ROOT, Restart, Route,
    Service, arrived, device, give, receive, send,
};

pub const VIRTIO_BLK: u32 = 0x1042_1af4;
pub const VIRTIO_NET: u32 = 0x1041_1af4;
pub const VIRTIO_CONSOLE: u32 = 0x1043_1af4;
pub const VIRTIO_RNG: u32 = 0x1044_1af4;

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
/// `trust`'s badge at the store: the `identity` namespace, read-write
/// (#310, identity.md); no one else holds it.
pub const IDENTITY_STORE: u32 = 10;
/// `trust`'s pages (#310): its identity store buffer and its heap.
pub const TRUST_LIMIT: u32 = 32;
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
        8 => TLS,
        9 => TLS_NORANDOM,
        10 => SECRETS,
        11 => VAULT,
        12 => BRIDGE,
        _ => &[],
    }
}

/// The routes of the table `init` runs for its argument (D-035): the
/// vault's and the gateway's, which get the table's number as theirs.
pub fn routes(arg: u64) -> &'static [Route] {
    match arg {
        10 => &SECRETS_ROUTES,
        11 | 12 => &VAULT_ROUTES,
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
    tcp: &[],
    tls: &[],
    after: &[],
    // smoltcp's sockets and the clients' TCP buffers (tls.md): 2 MiB.
    limit: 512,
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
    tcp: &[],
    tls: &[],
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
        tcp: &[],
        tls: &[],
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
    // Handle 5: signs the chain head (D-047, #256).
    give(Object::AuditAnchor, READ, Badge::None),
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
        tcp: &[],
        tls: &[],
        after: match store {
            0 => &[0],
            1 => &[1],
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
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
            send(Ep::Store, IDENTITY_STORE),
        ],
        net: &[],
        tcp: &[],
        tls: &[],
        after: &[4, 5],
        limit: TRUST_LIMIT,
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
        after: &[],
        limit: 0,
        gains: &[],
    },
];

/// The TLS service's capabilities (tls.md): its device, its endpoint, the
/// root filesystem for its roots, the network service, then the audit
/// service when the table has one.
const TLS_CAPS: [Give; 6] = [
    CONSOLE,
    device(VIRTIO_RNG, 0),
    receive(Ep::Tls),
    REPORT,
    ROOT,
    send(Ep::Net, TLS_NET_PORT),
];
/// The TLS service's client port at the network service.
pub const TLS_NET_PORT: u32 = 40_443;
/// The TLS service's pages (tls.md, budgets): 4 MiB.
pub const TLS_LIMIT: u32 = 1024;

const TLS_NO_AUDIT: Service = Service {
    name: "tls",
    path: b"bin/tls",
    arg: 0,
    kind: Kind::Daemon,
    restart: Restart::Up(3),
    caps: &TLS_CAPS,
    net: &[],
    tcp: &[([10, 0, 2, 2], 47_443)],
    tls: &[],
    after: &[0],
    limit: TLS_LIMIT,
    gains: &[],
};

/// The TLS service's audit client (`pharos_proto::audit::client::TLS`).
pub const AUDIT_TLS: u32 = 4;
/// The name every `tls` kernel destination is checked against.
pub const TLS_TEST_NAME: &[u8] = b"pharos-test.local";
/// The host's `openssl s_server`s for the `tls` kernel (#273, run by
/// `cargo xtask`): a good certificate, an expired one, one for another
/// name, and one from an authority that is not pinned; then a listener
/// that accepts and never answers, so a handshake with it never ends
/// (review F4, #274).
pub const TLS_SERVERS: [Dest; 5] = [
    ([10, 0, 2, 2], 47_443),
    ([10, 0, 2, 2], 47_444),
    ([10, 0, 2, 2], 47_445),
    ([10, 0, 2, 2], 47_446),
    ([10, 0, 2, 2], 47_447),
];

const TLS_AUDITED_CAPS: [Give; 7] = [
    TLS_CAPS[0],
    TLS_CAPS[1],
    TLS_CAPS[2],
    TLS_CAPS[3],
    TLS_CAPS[4],
    TLS_CAPS[5],
    send(Ep::Audit, AUDIT_TLS),
];

/// The destination `proxy` fakes, so its `TCP_POLL` counts are its own
/// (#277): nothing listens there.
pub const TLS_ROGUE: Dest = ([10, 0, 2, 2], 47_448);
/// The TLS service's idle limit in the `tls` kernel, in seconds (its
/// argument; #277): 60 elsewhere.
pub const TLS_TEST_IDLE: u64 = 3;

/// The `tls` kernel (#273, tls.md): the network, storage, and audit
/// services, `proxy` in front of the network and audit services (#277),
/// the TLS service with its audit trail through it and a 3 s idle limit,
/// and `tlsclient` (`netclient` 6), whose destinations 0 to 4 are
/// [`TLS_SERVERS`], 5 the good server again (its success is refused by
/// `proxy`), and 6 [`TLS_ROGUE`].
pub const TLS: &[Service] = &[
    NET,
    STORE,
    audit(1),
    Service {
        name: "proxy",
        path: b"bin/proxy",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Never,
        caps: &[
            CONSOLE,
            receive(Ep::Proxy),
            REPORT,
            send(Ep::Net, TLS_NET_PORT),
            send(Ep::Audit, AUDIT_TLS),
        ],
        net: &[],
        tcp: &TLS_SERVERS,
        tls: &[],
        after: &[0, 2],
        // Its copy of the TLS service's 64 KiB network buffer, and that one.
        limit: 64,
        gains: &[],
    },
    Service {
        name: "tls",
        path: b"bin/tls",
        arg: TLS_TEST_IDLE,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            TLS_CAPS[0],
            TLS_CAPS[1],
            TLS_CAPS[2],
            TLS_CAPS[3],
            TLS_CAPS[4],
            send(Ep::Proxy, 1),
            send(Ep::Proxy, 2),
        ],
        net: &[],
        tcp: &[],
        tls: &[],
        after: &[3],
        limit: TLS_LIMIT,
        gains: &[],
    },
    Service {
        name: "tlsclient",
        path: b"bin/netclient",
        arg: 6,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Tls, 1)],
        net: &[],
        tcp: &[],
        tls: &[
            (TLS_SERVERS[0].0, TLS_SERVERS[0].1, TLS_TEST_NAME),
            (TLS_SERVERS[1].0, TLS_SERVERS[1].1, TLS_TEST_NAME),
            (TLS_SERVERS[2].0, TLS_SERVERS[2].1, TLS_TEST_NAME),
            (TLS_SERVERS[3].0, TLS_SERVERS[3].1, TLS_TEST_NAME),
            (TLS_SERVERS[4].0, TLS_SERVERS[4].1, TLS_TEST_NAME),
            (TLS_SERVERS[0].0, TLS_SERVERS[0].1, TLS_TEST_NAME),
            (TLS_ROGUE.0, TLS_ROGUE.1, TLS_TEST_NAME),
        ],
        after: &[4],
        // Its 16 KiB buffer for the request and the reply.
        limit: 8,
        gains: &[],
    },
];

/// The `tls_norandom` kernel (#273): the TLS service with no virtio-rng.
/// Its handle 2 is the console instead, so the handles after it stay where
/// the service expects them; every `OPEN` must be `NO_RANDOM`.
pub const TLS_NORANDOM: &[Service] = &[
    NET,
    Service {
        name: "tls",
        path: b"bin/tls",
        arg: 0,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &[
            CONSOLE,
            CONSOLE,
            TLS_CAPS[2],
            TLS_CAPS[3],
            TLS_CAPS[4],
            TLS_CAPS[5],
        ],
        net: &[],
        tcp: &[TLS_SERVERS[0]],
        tls: &[],
        after: &[0],
        limit: TLS_LIMIT,
        gains: &[],
    },
    Service {
        name: "tlsclient",
        path: b"bin/netclient",
        arg: 7,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Tls, 1)],
        net: &[],
        tcp: &[],
        tls: &[(TLS_SERVERS[0].0, TLS_SERVERS[0].1, TLS_TEST_NAME)],
        after: &[1],
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
        after: &[1],
        limit: 0,
        gains: &[],
    },
    // TCP (#270): the host echo server, and a port nothing listens on.
    Service {
        name: "tcper",
        path: b"bin/netclient",
        arg: 4,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Net, 40002)],
        net: &[],
        tcp: &[HOST_ECHO, ([10, 0, 2, 2], 47_002)],
        tls: &[],
        after: &[0],
        limit: 4,
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
        tcp: &[],
        tls: &[],
        after: &[0],
        limit: 0,
        gains: &[],
    },
    // The TLS service (#271): no audit trail in this table, so its OPEN
    // must be refused before anything is sent; no roots in the image.
    TLS_NO_AUDIT,
    Service {
        name: "tlser",
        path: b"bin/netclient",
        arg: 5,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Tls, 1)],
        net: &[],
        tcp: &[],
        tls: &[([10, 0, 2, 2], 47_443, b"pharos-test.local")],
        after: &[5],
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
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
            // No knowledge service here: handle 6 stays the store's.
            CONSOLE,
            send(Ep::Store, IDENTITY_STORE),
        ],
        net: &[],
        tcp: &[],
        tls: &[],
        after: &[1],
        limit: TRUST_LIMIT,
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
        tcp: &[],
        tls: &[],
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
        tcp: &[],
        tls: &[],
        after: &[0],
        limit: 2048,
        gains: &[],
    },
];

/// The vault's audit client (`pharos_proto::audit::client::VAULT`).
pub const AUDIT_VAULT: u32 = 5;
/// The vault's handles (gateway.md): console, its endpoint, the report
/// endpoint, the secrets file, and the audit service as client 5.
const VAULT_CAPS: [Give; 5] = [
    CONSOLE,
    receive(Ep::Vault),
    REPORT,
    give(Object::Secrets, READ, Badge::None),
    send(Ep::Audit, AUDIT_VAULT),
];

/// The vault for table `arg`, after the audit service at `audit`.
const fn vault(arg: u64, audit: &'static [usize]) -> Service {
    Service {
        name: "vault",
        path: b"bin/vault",
        arg,
        kind: Kind::Daemon,
        restart: Restart::Up(3),
        caps: &VAULT_CAPS,
        net: &[],
        tcp: &[],
        tls: &[],
        after: audit,
        // 16 secrets of at most 1 KiB and its 4 KiB file: 64 KiB.
        limit: 16,
        gains: &[],
    }
}

/// The secret the `secrets` kernel's host file holds (`cargo xtask`
/// writes it); no other table names it.
pub const TEST_SECRET_NAME: &str = "test-token";
/// Its value: a test value, not a credential. The runner checks it never
/// reaches the console or the audit trail.
pub const TEST_SECRET_VALUE: &str = "pharos-test-secret-7Hq2vN";

/// The person `cargo xtask` seeds into test and `run` stores (#310,
/// identity.md), with a known passphrase; no release store holds them.
/// A low iteration count keeps logins quick under TCG: `person add` on
/// the console always uses `identity::ITERATIONS`.
pub const TEST_PERSON: &str = "admin";
pub const TEST_PASSPHRASE: &str = "pharos-test-passphrase";
pub const TEST_ITERATIONS: u32 = 1000;

/// The `secrets` kernel's routes (#281): one whose secret the file holds,
/// one whose secret it lacks, and one with none.
const SECRETS_ROUTES: [Route; 3] = [
    Route {
        name: "with-secret",
        dest: 0,
        method: "GET",
        path: "/items",
        query: false,
        secret: Some(TEST_SECRET_NAME),
        header: ("Authorization", "Bearer "),
        headers: &[],
        max_body: 0,
        max_answer: 4096,
        clients: &[1],
        approve: Approve::None,
    },
    Route {
        name: "missing",
        dest: 0,
        method: "GET",
        path: "/items",
        query: false,
        secret: Some("absent"),
        header: ("x-api-key", ""),
        headers: &[],
        max_body: 0,
        max_answer: 4096,
        clients: &[1],
        approve: Approve::None,
    },
    Route {
        name: "open",
        dest: 0,
        method: "GET",
        path: "/public",
        query: false,
        secret: None,
        header: ("", ""),
        headers: &[],
        max_body: 0,
        max_answer: 4096,
        clients: &[1],
        approve: Approve::None,
    },
];

/// The `secrets` kernel (#281): the store and audit service, the vault,
/// and `vaulter`, which holds the gateway's capability (badge 1) and a
/// second one with badge 2, which the vault must refuse.
pub const SECRETS: &[Service] = &[
    STORE,
    audit(0),
    vault(10, &[1]),
    Service {
        name: "vaulter",
        path: b"bin/netclient",
        arg: 8,
        kind: Kind::OneShot,
        restart: Restart::Never,
        caps: &[CONSOLE, send(Ep::Vault, 1), send(Ep::Vault, 2)],
        net: &[],
        tcp: &[],
        tls: &[],
        after: &[2],
        // Its 4 KiB buffer at the vault.
        limit: 4,
        gains: &[],
    },
];

/// The bridge's badge at the runtime (`pharos_proto::agents::BRIDGE`).
pub const AGENTS_BRIDGE: u32 = 0x81;

/// The `bridge` test kernel's table (#300, bridge.md): the `vault`
/// table's services up to the runtime (the TLS service, the vault, and the
/// gateway on the `vault` kernel's routes, table 12's), the runtime on its
/// `guest` policy table (4) with the gateway as handle 12, the bridge
/// holding the second virtio-console (the Tier 3 channel's Pharos end,
/// which `cargo xtask` joins to the guest's port through one host socket)
/// with argument 1, so each `BIND` follows one whose reply no one takes
/// (#302), and `guestclient`, which runs the guest agent's tasks.
pub const BRIDGE: &[Service] = &bridge_table(BOOT_ENTRIES);

const BRIDGE_CAPS: [Give; 4] = [
    CONSOLE,
    device(VIRTIO_CONSOLE, 1),
    REPORT,
    send(Ep::Agents, AGENTS_BRIDGE),
];
const GUESTCLIENT_CAPS: [Give; 2] = [CONSOLE, send(Ep::Agents, AGENTS_CONTROL)];

const fn bridge_table(boot: [Service; 9]) -> [Service; 13] {
    let v = vault_table(boot);
    let (mut vault, mut gateway, mut runtime) = (v[8], v[9], v[10]);
    vault.arg = 12;
    gateway.arg = 12;
    runtime.arg = 4;
    [
        v[0],
        v[1],
        v[2],
        v[3],
        v[4],
        v[5],
        v[6],
        v[7],
        vault,
        gateway,
        runtime,
        Service {
            name: "bridge",
            path: b"bin/bridge",
            // Each `BIND` after one whose reply no one takes (#302).
            arg: 1,
            kind: Kind::Daemon,
            restart: Restart::Up(3),
            caps: &BRIDGE_CAPS,
            net: &[],
            tcp: &[],
            tls: &[],
            after: &[10],
            // Its receive and transmit buffers, its agent buffer, and one
            // frame (bridge.md): 512 KiB.
            limit: 128,
            gains: &[],
        },
        Service {
            name: "guestclient",
            path: b"bin/agentclient",
            arg: 18,
            kind: Kind::OneShot,
            restart: Restart::Never,
            caps: &GUESTCLIENT_CAPS,
            net: &[],
            tcp: &[],
            tls: &[],
            after: &[11],
            limit: 64,
            gains: &[],
        },
    ]
}

/// The gateway's audit client (`pharos_proto::audit::client::GATEWAY`).
pub const AUDIT_GATEWAY: u32 = 6;
/// The `vault` kernel's HTTPS test server (#284, run by `cargo xtask`):
/// Python's `http.server` with the `tls` kernel's good certificate.
pub const VAULT_SERVER: Dest = ([10, 0, 2, 2], 47_450);

/// A route of the `vault` kernel carrying the test secret as a bearer
/// token.
const fn bearer(name: &'static str, method: &'static str, path: &'static str) -> Route {
    Route {
        name,
        dest: 0,
        method,
        path,
        query: false,
        secret: Some(TEST_SECRET_NAME),
        header: ("Authorization", "Bearer "),
        headers: &[],
        max_body: 0,
        max_answer: 4096,
        clients: &[1],
        approve: Approve::None,
    }
}

/// The `vault` kernel's routes (#284): `items` (the server checks the
/// header), `echo` (the server sends the header back), `post`, `missing`
/// (a secret the file lacks), `other`, which `fetcher` is not granted, and
/// `approved` (#325), marked for one approver, which the gateway refuses
/// without an approval from `trust`.
const VAULT_ROUTES: [Route; 6] = [
    bearer("items", "GET", "/items"),
    bearer("echo", "GET", "/echo"),
    Route {
        max_body: 1024,
        headers: &[("Content-Type", "application/json")],
        ..bearer("post", "POST", "/items")
    },
    Route {
        secret: Some("absent"),
        header: ("x-api-key", ""),
        ..bearer("missing", "GET", "/items")
    },
    bearer("other", "GET", "/items"),
    Route {
        max_body: 1024,
        approve: Approve::One,
        ..bearer("approved", "POST", "/items")
    },
];

/// The `vault` kernel (#284): the boot table's services up to `trust`, the
/// TLS service, the vault, the gateway, the runtime on its `vault` policy
/// table (3, `fetcher`) with the gateway as handle 12 (handles 9 to 11 are
/// the console: no network, files, or knowledge), and `agentclient` 17.
pub const VAULT: &[Service] = &vault_table(BOOT_ENTRIES);

const VAULT_RUNTIME_CAPS: [Give; 12] = [
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
    CONSOLE,
    CONSOLE,
    CONSOLE,
    send(Ep::Gateway, 1),
];

const GATEWAY_CAPS: [Give; 6] = [
    CONSOLE,
    receive(Ep::Gateway),
    REPORT,
    send(Ep::Vault, 1),
    send(Ep::Tls, 1),
    send(Ep::Audit, AUDIT_GATEWAY),
];
const GATEWAY_DESTS: [crate::TlsDest; 1] = [(VAULT_SERVER.0, VAULT_SERVER.1, TLS_TEST_NAME)];
const FETCHCLIENT_CAPS: [Give; 2] = [CONSOLE, send(Ep::Agents, AGENTS_CONTROL)];

/// `trust` with `SEND` on the gateway (#325), for its approvals.
const TRUST_GATEWAY_CAPS: [Give; 7] = [
    device(VIRTIO_CONSOLE, 0),
    receive(Ep::Trust),
    REPORT,
    send(Ep::Audit, AUDIT_TRUST),
    send(Ep::Knowledge, KNOWLEDGE_TRUST),
    send(Ep::Store, IDENTITY_STORE),
    send(Ep::Gateway, crate::GATEWAY_TRUST as u32),
];

const fn vault_table(boot: [Service; 9]) -> [Service; 12] {
    let mut trust = boot[6];
    trust.caps = &TRUST_GATEWAY_CAPS;
    let mut runtime = boot[AGENTS];
    runtime.arg = 3;
    runtime.caps = &VAULT_RUNTIME_CAPS;
    runtime.after = &[2, 3, 6, 9];
    [
        boot[0],
        boot[1],
        boot[2],
        boot[3],
        boot[4],
        boot[5],
        trust,
        Service {
            name: "tls",
            path: b"bin/tls",
            arg: 0,
            kind: Kind::Daemon,
            restart: Restart::Up(3),
            caps: &TLS_AUDITED_CAPS,
            net: &[],
            tcp: &[VAULT_SERVER],
            tls: &[],
            after: &[1, 4],
            limit: TLS_LIMIT,
            gains: &[],
        },
        vault(11, &[4]),
        Service {
            name: "gateway",
            path: b"bin/gateway",
            arg: 11,
            kind: Kind::Daemon,
            restart: Restart::Up(3),
            caps: &GATEWAY_CAPS,
            net: &[],
            tcp: &[],
            tls: &GATEWAY_DESTS,
            after: &[7, 8],
            // Its buffers and an answer in parsing (gateway.md): 512 KiB.
            limit: 128,
            gains: &[],
        },
        runtime,
        Service {
            name: "fetchclient",
            path: b"bin/agentclient",
            arg: 17,
            kind: Kind::OneShot,
            restart: Restart::Never,
            caps: &FETCHCLIENT_CAPS,
            net: &[],
            tcp: &[],
            tls: &[],
            after: &[10],
            limit: 64,
            gains: &[],
        },
    ]
}
