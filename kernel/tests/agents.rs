//! Test kernel: the agent runtime (#98, agents.md). `cargo xtask` boots it
//! with the inference test's store (the service's test model, manifest
//! model 2) and the programs image, which holds `agents/worker.manifest`,
//! `agents/greedy.manifest` (asks for more pages than its policy entry),
//! and `agents/noentry.manifest` (no entry). The kernel starts `store`,
//! `infer`, `trust`, and `agents` with the capabilities `init` gives them,
//! registers the runtime with `trust` as `init` does, then runs
//! `agentclient`, which submits `bin/testagent` tasks for each case and
//! reports each passed step. While four agents wait, the kernel checks
//! what each holds. Last, the runtime's events and `trust`'s registrations.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{
    CONFIG, Capability, GRANT, IRQ, MAP, MAX_HANDLES, Object, READ, RECEIVE, SEND, STOP, WAIT,
    WRITE,
};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::process;
use pharos_kernel::sched::TaskId;
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// Namespace 3 (`models`), read-only (`pharos_proto::store`).
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
/// `pharos_proto::trust`: `RUNTIME` and the badges.
const TRUST_RUNTIME: [u8; 2] = [1, 1];
const INIT_BADGE: u32 = 0;
const RUNTIME_BADGE: u32 = 2;
/// The runtime's badge at the inference service, as `init` gives it.
const INFER_CLIENT: u32 = 1;
/// `pharos_proto::agents::CONTROL`.
const CONTROL: u32 = 0x100;
/// As `init` gives the runtime.
const RUNTIME_PAGES: u64 = 1 << 14;

/// The capabilities of `id`.
fn caps_of(id: TaskId) -> Vec<Arc<Capability>> {
    process::by_id(id).map_or(Vec::new(), |p| {
        let mut caps = p.caps.lock();
        (1..=MAX_HANDLES as u64)
            .filter_map(|h| caps.get(h, 0).ok())
            .collect()
    })
}

fn endpoint(c: &Capability) -> Option<&Arc<Endpoint>> {
    match c.object() {
        Object::Endpoint(e) => Some(e),
        _ => None,
    }
}

/// Starts `path` and waits for its `ready` on a new report endpoint.
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

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    let Some(hhdm) = requests::HHDM.response() else {
        return;
    };
    if memory {
        storage::record_modules(requests::MODULES.response(), hhdm.offset);
    }
    let ready = memory
        && mm::init_heap().is_ok()
        && apic::init(hhdm.offset).is_ok()
        && time::init().is_ok()
        && sched::init().is_ok();
    t.check("memory, heap, APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    process::init();
    t.check("preemption enabled", sched::enable_preemption().is_ok());
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
        return;
    };
    let (Some(disk), Some(console)) = (DeviceHandle::grant(disk), DeviceHandle::grant(console))
    else {
        t.check("the devices are granted", false);
        return;
    };

    let (store, report) = (Endpoint::new(), Endpoint::new());
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(disk), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(store.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
    ];
    let Some(_) = start(t, &programs, b"bin/store", 0, caps, &report, 10_240) else {
        return;
    };
    let store_send = Capability::new(Object::Endpoint(store.clone()), SEND);
    let infer = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Endpoint(infer.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
        store_send.derive_badged(SEND, MODELS_READ_ONLY),
    ];
    let Some(_) = start(t, &programs, b"bin/infer", 0, caps, &report, 1 << 18) else {
        return;
    };
    let trust_ep = Endpoint::new();
    let caps = vec![
        Capability::new(Object::Device(console), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(trust_ep.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
    ];
    let Some(trust) = start(t, &programs, b"bin/trust", 0, caps, &report, 0) else {
        return;
    };

    // The runtime, with what `init` gives it.
    let runtime_ep = Endpoint::new();
    let infer_send = Capability::new(Object::Endpoint(infer.clone()), SEND);
    let trust_send = Capability::new(Object::Endpoint(trust_ep.clone()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Endpoint(runtime_ep.clone()), RECEIVE | SEND | GRANT),
        Capability::new(Object::Endpoint(report.clone()), SEND),
        Capability::new(Object::Filesystem(programs.clone()), READ),
        infer_send.derive_badged(SEND, INFER_CLIENT),
        trust_send.derive_badged(SEND, RUNTIME_BADGE),
    ];
    let Some(runtime) = start(t, &programs, b"bin/agents", 1, caps, &report, RUNTIME_PAGES) else {
        return;
    };
    let Some(record) = process::by_id(runtime).map(|p| p.record.clone()) else {
        return;
    };
    let mut data = [0u8; MAX_MESSAGE];
    data[..2].copy_from_slice(&TRUST_RUNTIME);
    ipc::send(
        &trust_ep,
        Message {
            data,
            len: 2,
            cap: Some(Capability::new(Object::Process(record), STOP | WAIT)),
            badge: INIT_BADGE,
        },
    );

    // The control client; its steps arrive on `steps`.
    let steps = Endpoint::new();
    let runtime_send = Capability::new(Object::Endpoint(runtime_ep.clone()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        runtime_send.derive_badged(SEND, CONTROL),
        Capability::new(Object::Endpoint(steps.clone()), SEND),
    ];
    let client = process::spawn_elf_limited(&programs, b"bin/agentclient", 0, caps, 64);
    t.check("the control client started", client.is_ok());
    let client = client.unwrap_or(u64::MAX);

    let mut passed: Vec<Vec<u8>> = Vec::new();
    let mut events: Vec<Vec<u8>> = Vec::new();
    let mut checked = None;
    let start = time::uptime();
    // Up to 180 s; about 30 s on the reference host.
    while time::uptime() - start < Duration::from_secs(180) {
        for (id, line) in process::debug_output() {
            if id == runtime && !events.contains(&line) {
                events.push(line);
            }
        }
        let Some(m) = ipc::poll(&steps, Duration::from_millis(50)) else {
            continue;
        };
        match m.bytes() {
            b"done" => break,
            b"check" => {
                let services = [&store, &infer, &trust_ep, &report, &steps];
                checked = Some(check_agents(runtime, &runtime_ep, &services));
            }
            step => {
                kprintln!("  {}", core::str::from_utf8(step).unwrap_or("?"));
                passed.push(step.to_vec());
            }
        }
    }
    for (id, line) in process::debug_output() {
        if id == runtime && !events.contains(&line) {
            events.push(line);
        }
    }
    for step in [
        "INFO: interface agents, one agent accepted, none running",
        "agents with a refused, missing, or unlisted manifest are not found",
        "agent requests from a control client are refused",
        "an unknown task is not found",
        "a task completes on its first attempt",
        "a crashed agent is restarted and completes",
        "an agent that always crashes fails after 3 attempts",
        "an agent that exits without a result fails after 3 attempts",
        "a hung agent is stopped and fails after 3 attempts",
        "an agent's FAIL ends its task with its reason",
        "inference through the runtime, only from the manifest's models",
        "an agent's control requests are refused",
        "at most four agents run at once",
        "cancelling running and pending tasks stops their agents",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    // It exits just after its `done`.
    let mut exit = None;
    for _ in 0..40 {
        exit = process::exits().into_iter().find(|e| e.task == client);
        if exit.is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    t.check(
        "the client exited with no failed step",
        exit.is_some_and(|e| e.code == 0),
    );
    t.check(
        "each running agent held only its runtime endpoint and its own endpoints",
        checked == Some(true),
    );

    let has = |text: &str| {
        events
            .iter()
            .any(|l| l.windows(text.len()).any(|w| w == text.as_bytes()))
    };
    for (what, text) in [
        ("an accepted manifest", "agents: worker manifest accepted"),
        (
            "a manifest over its policy entry refused",
            "agents: greedy manifest refused: asks for more than its policy entry",
        ),
        (
            "a missing manifest refused",
            "agents: absent manifest refused: no manifest",
        ),
        ("a start", " started"),
        ("a completion", " completed"),
        ("a crash with its vector", " crashed 14"),
        ("an exit with its code", " exited 3"),
        ("a hang", " hung"),
        ("a restart", " restarting 2/3"),
        ("a failure", " failed"),
        ("a cancellation", " cancelled"),
        ("an agent's log line", "agents: worker: working"),
    ] {
        t.check(&alloc::format!("the runtime reported {what}"), has(text));
    }
    for e in &events {
        kprintln!("  runtime: {}", core::str::from_utf8(e).unwrap_or("?"));
    }
    // The runtime, then every agent, registered with `trust`.
    let processes = caps_of(trust)
        .iter()
        .filter(|c| matches!(c.object(), Object::Process(_)))
        .count();
    t.check(
        "trust holds the runtime and the agents' process capabilities",
        processes >= 2,
    );
    t.check(
        "the runtime still runs",
        process::by_id(runtime).is_some_and(|p| p.record.end().is_none()),
    );
}

/// Every process the runtime started holds `SEND` on the runtime with an
/// agent badge (1 to 16), and otherwise only endpoints it made itself
/// (none of `services`), and nothing but endpoints.
fn check_agents(runtime: TaskId, runtime_ep: &Arc<Endpoint>, services: &[&Arc<Endpoint>]) -> bool {
    let agents: Vec<TaskId> = (runtime + 1..runtime + 200)
        .filter(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(runtime)))
        .collect();
    kprintln!("  checking {} running agents", agents.len());
    agents.len() == 4
        && agents.iter().all(|&id| {
            let caps = caps_of(id);
            let to_runtime: Vec<_> = caps
                .iter()
                .filter(|c| endpoint(c).is_some_and(|e| Arc::ptr_eq(e, runtime_ep)))
                .collect();
            let only_own = caps.iter().all(|c| match endpoint(c) {
                Some(e) => !services.iter().any(|s| Arc::ptr_eq(e, s)),
                None => false,
            });
            to_runtime.len() == 1
                && to_runtime[0].rights() == SEND
                && (1..=16).contains(&to_runtime[0].badge())
                && only_own
        })
}
