//! What the `agents`, `agents_crash`, `agents_store`, `permissions`, and
//! `agents_net` test kernels share (#98, #99, #109):
//! starting `store`, `infer`, `audit`, `knowledge` (#144), `trust`, and
//! the agent runtime with the capabilities `init` gives them, replacing
//! the runtime, and starting the control client.

// Each kernel uses only part of it.
#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::cap::{
    CONFIG, Capability, GRANT, IRQ, MAP, MAX_HANDLES, Object, READ, RECEIVE, SEND, STOP, WAIT,
    WRITE,
};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::process;
use pharos_kernel::sched::{self, TaskId};
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::TestRun;
use pharos_kernel::{fs, pci};

/// Namespace 3 (`models`), read-only (`pharos_proto::store`).
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
/// Namespace 5, `agents`, read-write (`pharos_proto::store`).
const AGENTS_TASKS: u32 = 5;
/// Namespace 6, `audit`, read-write, and the audit clients `init` gives
/// `trust` and the runtime (#107, #108).
const AUDIT_TRAIL: u32 = 6;
const AUDIT_TRUST: u32 = 2;
const AUDIT_RUNTIME: u32 = 3;
/// Namespace 7, `files`, read-only (#127): the runtime's handle 10, given
/// after the network service's handle 9.
const FILES_READ_ONLY: u32 = 7 | 1 << 16;
/// Namespace 9, `system/incoming`, read-write (#165): the runtime's handle
/// 12, after `knowledge`, for `PROPOSE`.
pub const INCOMING: u32 = 9;
/// Namespace 8, `knowledge`, read-write, and the knowledge service's
/// clients (#144): the runtime's handle 11, after `files`, and `trust`'s 5.
const KNOWLEDGE_STORE: u32 = 8;
const KNOWLEDGE_RUNTIME: u32 = 1;
const KNOWLEDGE_TRUST: u32 = 2;
/// `pharos_proto::trust`: `RUNTIME`, under `init`'s (no) badge, and the
/// runtime's badge.
const TRUST_RUNTIME: [u8; 2] = [1, 1];
const INIT_BADGE: u32 = 0;
const RUNTIME_BADGE: u32 = 2;
/// The runtime's badge at the inference service, as `init` gives it.
const INFER_CLIENT: u32 = 1;
/// `pharos_proto::agents::CONTROL`.
const CONTROL: u32 = 0x100;
/// As `init` gives the storage service.
const STORE_PAGES: u64 = 10_240;
/// As `init` gives the runtime.
const RUNTIME_PAGES: u64 = 1 << 14;
/// The runtime's UDP port, and the union of its test table's
/// destinations (`net` and `ask_net`), as `init` would list them (#109).
const RUNTIME_PORT: u32 = 40_100;
const RUNTIME_DESTINATIONS: [([u8; 4], u16); 2] =
    [([10, 0, 2, 2], 47_000), ([10, 0, 2, 2], 47_001)];

pub struct Services {
    pub programs: Arc<fs::Fs>,
    pub runtime_ep: Arc<Endpoint>,
    pub report: Arc<Endpoint>,
    pub infer: Arc<Endpoint>,
    pub trust_ep: Arc<Endpoint>,
    pub store: Arc<Endpoint>,
    pub trust: TaskId,
    /// The storage service and its capabilities, to start it again.
    pub store_id: TaskId,
    store_caps: Vec<Arc<Capability>>,
    /// The audit service (#108), for tests that kill it.
    pub audit: Arc<Endpoint>,
    pub audit_id: TaskId,
    /// The knowledge service (#144).
    pub knowledge: Arc<Endpoint>,
    /// The network service, if [`start_net`] started it: the runtime then
    /// gets handle 9 on it.
    pub net: Option<Arc<Endpoint>>,
    pub net_id: TaskId,
}

/// The capabilities of `id`.
pub fn caps_of(id: TaskId) -> Vec<Arc<Capability>> {
    process::by_id(id).map_or(Vec::new(), |p| {
        let mut caps = p.caps.lock();
        (1..=MAX_HANDLES as u64)
            .filter_map(|h| caps.get(h, 0).ok())
            .collect()
    })
}

pub fn endpoint(c: &Capability) -> Option<&Arc<Endpoint>> {
    match c.object() {
        Object::Endpoint(e) => Some(e),
        _ => None,
    }
}

/// Starts `path` and waits for its `ready` on `report`.
fn start(
    t: &mut TestRun,
    programs: &fs::Fs,
    path: &[u8],
    arg: u64,
    caps: Vec<Arc<Capability>>,
    report: &Arc<Endpoint>,
    pages: u64,
) -> Option<TaskId> {
    let id = process::spawn_elf_limited(programs, path, arg, caps, pages).ok();
    let ready = ipc::poll(report, Duration::from_secs(10)).is_some_and(|m| m.bytes() == b"ready");
    let name = core::str::from_utf8(path).unwrap_or("?");
    t.check(
        &alloc::format!("{name} started and reported ready"),
        id.is_some() && ready,
    );
    id.filter(|_| ready)
}

/// Starts `store` (on the second virtio-blk disk), `infer`, `audit` (#108),
/// `knowledge` (#144), and `trust` (on the virtio-console), as `init` does. The scheduler and processes must be set up.
pub fn setup(t: &mut TestRun) -> Option<Services> {
    pci::enumerate();
    let devices = pci::devices();
    let disk = devices
        .iter()
        .filter(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .nth(1)
        .cloned();
    let console = devices
        .iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1043))
        .cloned();
    let (Some(disk), Some(console), Ok(programs)) = (disk, console, fs::mount("programs")) else {
        t.check(
            "the store disk, the console, and the programs are found",
            false,
        );
        return None;
    };
    let (Some(disk), Some(console)) = (DeviceHandle::grant(disk), DeviceHandle::grant(console))
    else {
        t.check("the devices are granted", false);
        return None;
    };
    let (store, report) = (Endpoint::new(), Endpoint::new());
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(disk), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(store.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
    ];
    let store_caps = caps.clone();
    let store_id = start(t, &programs, b"bin/store", 0, caps, &report, STORE_PAGES)?;
    let store_send = Capability::new(Object::Endpoint(store.clone()), SEND);
    let infer = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Endpoint(infer.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
        store_send.derive_badged(SEND, MODELS_READ_ONLY),
    ];
    start(t, &programs, b"bin/infer", 0, caps, &report, 1 << 18)?;
    let audit = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Endpoint(audit.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
        store_send.derive_badged(SEND, AUDIT_TRAIL),
    ];
    let audit_id = start(t, &programs, b"bin/audit", 0, caps, &report, 0)?;
    let audit_send = Capability::new(Object::Endpoint(audit.clone()), SEND);
    let knowledge = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Endpoint(knowledge.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
        store_send.derive_badged(SEND, KNOWLEDGE_STORE),
    ];
    start(t, &programs, b"bin/knowledge", 0, caps, &report, 1024)?;
    let knowledge_send = Capability::new(Object::Endpoint(knowledge.clone()), SEND);
    let trust_ep = Endpoint::new();
    let caps = vec![
        Capability::new(Object::Device(console), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(trust_ep.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
        audit_send.derive_badged(SEND, AUDIT_TRUST),
        knowledge_send.derive_badged(SEND, KNOWLEDGE_TRUST),
    ];
    let trust = start(t, &programs, b"bin/trust", 0, caps, &report, 0)?;
    Some(Services {
        programs,
        runtime_ep: Endpoint::new(),
        report,
        infer,
        trust_ep,
        store,
        trust,
        store_id,
        store_caps,
        audit,
        audit_id,
        knowledge,
        net: None,
        net_id: 0,
    })
}

/// Starts the network service on the virtio-net device and, as `init`
/// does once it is ready, lists the runtime's destinations (`ALLOW` under
/// `init`'s badge, 0).
pub fn start_net(t: &mut TestRun, s: &mut Services) -> bool {
    let nic = pci::devices()
        .into_iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1041))
        .and_then(DeviceHandle::grant);
    let Some(nic) = nic else {
        t.check("the network card is found", false);
        return false;
    };
    let net = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(nic), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(net.clone()), RECEIVE),
        Capability::new(Object::Endpoint(s.report.clone()), SEND),
    ];
    let Some(id) = start(t, &s.programs, b"bin/net", 0, caps, &s.report, 0) else {
        return false;
    };
    s.net_id = id;
    // `pharos_proto::net`'s `ALLOW`: version, op, port, count, then each
    // address and port.
    let mut data = [0u8; MAX_MESSAGE];
    let port = (RUNTIME_PORT as u16).to_le_bytes();
    data[..5].copy_from_slice(&[1, 5, port[0], port[1], RUNTIME_DESTINATIONS.len() as u8]);
    let mut len = 5;
    for (addr, port) in RUNTIME_DESTINATIONS {
        data[len..len + 4].copy_from_slice(&addr);
        data[len + 4..len + 6].copy_from_slice(&port.to_le_bytes());
        len += 6;
    }
    // The service answers with a non-blocking send, which cannot reach a
    // kernel thread; `send` returns once it took the request, before any
    // later one. If the list did not take, every agent send is refused.
    let answers = Endpoint::new();
    ipc::send(
        &net,
        Message {
            data,
            len,
            cap: Some(Capability::new(Object::Endpoint(answers), SEND)),
            badge: INIT_BADGE,
        },
    );
    s.net = Some(net);
    true
}

/// Starts the storage service again on its endpoint and disk, as `init`
/// restarts it (#100).
pub fn restart_store(t: &mut TestRun, s: &Services) -> Option<TaskId> {
    let caps = s.store_caps.clone();
    start(
        t,
        &s.programs,
        b"bin/store",
        0,
        caps,
        &s.report,
        STORE_PAGES,
    )
}

/// Starts the runtime as `init` does and registers it with `trust`.
pub fn start_runtime(t: &mut TestRun, s: &Services) -> Option<TaskId> {
    start_runtime_table(t, s, 1)
}

/// [`start_runtime`] with the runtime's policy table `table` (1 the test
/// table, 2 the `budgets` kernel's).
pub fn start_runtime_table(t: &mut TestRun, s: &Services, table: u64) -> Option<TaskId> {
    let infer_send = Capability::new(Object::Endpoint(s.infer.clone()), SEND);
    let trust_send = Capability::new(Object::Endpoint(s.trust_ep.clone()), SEND);
    let store_send = Capability::new(Object::Endpoint(s.store.clone()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(
            Object::Endpoint(s.runtime_ep.clone()),
            RECEIVE | SEND | GRANT,
        ),
        Capability::new(Object::Endpoint(s.report.clone()), SEND),
        Capability::new(Object::Filesystem(s.programs.clone()), READ),
        infer_send.derive_badged(SEND, INFER_CLIENT),
        trust_send.derive_badged(SEND, RUNTIME_BADGE),
        store_send.derive_badged(SEND, AGENTS_TASKS),
        Capability::new(Object::Endpoint(s.audit.clone()), SEND).derive_badged(SEND, AUDIT_RUNTIME),
    ];
    let mut caps = caps;
    if let Some(net) = &s.net {
        caps.push(
            Capability::new(Object::Endpoint(net.clone()), SEND).derive_badged(SEND, RUNTIME_PORT),
        );
        caps.push(store_send.derive_badged(SEND, FILES_READ_ONLY));
        caps.push(
            Capability::new(Object::Endpoint(s.knowledge.clone()), SEND)
                .derive_badged(SEND, KNOWLEDGE_RUNTIME),
        );
        caps.push(store_send.derive_badged(SEND, INCOMING));
    }
    let runtime = start(
        t,
        &s.programs,
        b"bin/agents",
        table,
        caps,
        &s.report,
        RUNTIME_PAGES,
    )?;
    let record = process::by_id(runtime).map(|p| p.record.clone())?;
    let mut data = [0u8; MAX_MESSAGE];
    data[..2].copy_from_slice(&TRUST_RUNTIME);
    ipc::send(
        &s.trust_ep,
        Message {
            data,
            len: 2,
            cap: Some(Capability::new(Object::Process(record), STOP | WAIT)),
            badge: INIT_BADGE,
        },
    );
    Some(runtime)
}

/// Stops `old` (and so its agents) and starts a new runtime.
pub fn replace_runtime(t: &mut TestRun, s: &Services, old: TaskId) -> Option<TaskId> {
    let record = process::by_id(old).map(|p| p.record.clone())?;
    let children: Vec<TaskId> = (old + 1..old + 400)
        .filter(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(old)))
        .collect();
    process::stop(old);
    for _ in 0..100 {
        if record.end().is_some() && children.iter().all(|&c| process::by_id(c).is_none()) {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    t.check(
        "stopping the runtime stopped it and its running agent",
        record.end() == Some(process::End::Stopped)
            && !children.is_empty()
            && children.iter().all(|&c| process::by_id(c).is_none()),
    );
    start_runtime(t, s)
}

/// Starts `agentclient` in mode `arg`; its steps arrive on the endpoint.
pub fn client(t: &mut TestRun, s: &Services, arg: u64) -> (TaskId, Arc<Endpoint>) {
    let steps = Endpoint::new();
    let runtime_send = Capability::new(Object::Endpoint(s.runtime_ep.clone()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        runtime_send.derive_badged(SEND, CONTROL),
        Capability::new(Object::Endpoint(steps.clone()), SEND),
    ];
    let client = process::spawn_elf_limited(&s.programs, b"bin/agentclient", arg, caps, 64);
    t.check("the control client started", client.is_ok());
    (client.unwrap_or(u64::MAX), steps)
}
