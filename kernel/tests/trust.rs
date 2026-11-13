//! Test kernel: the trusted path and the emergency stop (#96, D-018,
//! agents.md). The kernel starts `trust` with the virtio-console device,
//! its endpoint, and a report endpoint, as `init` does. A stand-in agent
//! runtime (`child` mode 15) starts two agents, registers both with
//! `trust` as `worker`, and then spins: a hung runtime. The kernel waits
//! for both registrations, then registers that process as
//! the runtime under `init`'s badge, and sends an impostor agent under the
//! wrong badge, which `trust` must drop. `cargo xtask runner` types on the
//! trusted console (`TRUST_SCRIPT`): `list`, `stop worker`, a bad command,
//! `list`, `stop all`. The kernel checks both agents end while the runtime
//! spins, then the runtime ends, and what each process holds. Last, an
//! approval left open ends with a new runtime's `CHANNEL` (#206). Runs
//! under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{
    CONFIG, Capability, IRQ, MAP, MAX_HANDLES, Object, READ, RECEIVE, SEND, STOP, WAIT,
};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::process::{self, End};
use pharos_kernel::sched::TaskId;
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, pci, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `pharos_proto::trust`: version 1, its operations and badges.
const VERSION: u8 = 1;
const RUNTIME_OP: u8 = 1;
const REGISTER_OP: u8 = 2;
const CHANNEL_OP: u8 = 3;
const APPROVE_OP: u8 = 5;
/// `pharos_proto::permission`: the kind of `model <n>`.
const MODEL: u8 = 1;
const INIT_BADGE: u32 = 0;
const RUNTIME_BADGE: u32 = 2;

/// Sends `bytes` to `trust` from the kernel, with `cap` and `badge`.
fn send(to: &Endpoint, bytes: &[u8], cap: Arc<Capability>, badge: u32) {
    let mut data = [0u8; MAX_MESSAGE];
    data[..bytes.len()].copy_from_slice(bytes);
    ipc::send(
        to,
        Message {
            data,
            len: bytes.len(),
            cap: Some(cap),
            badge,
        },
    );
}

/// How the process behind `record` ended, waiting up to `secs` seconds.
fn end_of(record: &process::ProcessRecord, secs: u64) -> Option<End> {
    for _ in 0..secs * 20 {
        if let Some(end) = record.end() {
            return Some(end);
        }
        sched::sleep(Duration::from_millis(50));
    }
    record.end()
}

/// The objects in `id`'s capability table.
fn holds(id: TaskId, f: impl Fn(&Object) -> bool) -> usize {
    process::by_id(id).map_or(0, |p| {
        let mut caps = p.caps.lock();
        (1..=MAX_HANDLES as u64)
            .filter_map(|h| caps.get(h, 0).ok())
            .filter(|c| f(c.object()))
            .count()
    })
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
        && mm_ready()
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
    let console = pci::devices()
        .into_iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1043));
    let (Some(console), Ok(programs)) = (console, fs::mount("programs")) else {
        t.check("the virtio-console and the programs are found", false);
        return;
    };
    let Some(device) = DeviceHandle::grant(console) else {
        t.check("the virtio-console is granted", false);
        return;
    };
    let (endpoint, report) = (Endpoint::new(), Endpoint::new());
    let caps = vec![
        Capability::new(Object::Device(device), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(endpoint.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
    ];
    let trust = process::spawn_elf(&programs, b"bin/trust", 0, caps);
    t.check("trust started", trust.is_ok());
    let ready = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "it set up its console and reported ready",
        ready.is_some_and(|m| m.bytes() == b"ready"),
    );
    let trust = trust.unwrap_or(u64::MAX);

    // The stand-in runtime: `bin/child` to start its agent, and `SEND` on
    // `trust` badged as the runtime.
    let Ok(child) = programs.lookup(b"bin/child") else {
        t.check("bin/child in the programs image", false);
        return;
    };
    let root = Capability::new(Object::Endpoint(endpoint.clone()), SEND);
    let caps = vec![
        Capability::new(
            Object::File {
                fs: programs.clone(),
                file: child,
            },
            READ,
        ),
        root.derive_badged(SEND, RUNTIME_BADGE),
    ];
    let runtime = process::spawn_elf(&programs, b"bin/child", 15, caps);
    t.check("the stand-in runtime started", runtime.is_ok());
    let runtime = runtime.unwrap_or(u64::MAX);
    let Some(record) = process::by_id(runtime).map(|p| p.record.clone()) else {
        t.check("the runtime's record", false);
        return;
    };
    let process = || Capability::new(Object::Process(record.clone()), STOP | WAIT);

    // The two agents the runtime started (its only children), both
    // registered as `worker`.
    let mut agents: Vec<TaskId> = Vec::new();
    for _ in 0..40 {
        agents = (runtime + 1..runtime + 6)
            .filter(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(runtime)))
            .collect();
        if agents.len() == 2 {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    t.check("the runtime started its two agents", agents.len() == 2);
    t.check(
        "the agents hold no capability",
        agents.iter().all(|&a| holds(a, |_| true) == 0),
    );
    let records: Vec<_> = agents
        .iter()
        .filter_map(|&a| process::by_id(a).map(|p| p.record.clone()))
        .collect();
    if agents.len() != 2 || records.len() != 2 {
        return;
    }
    // Only now the runtime's registration, which the runner waits for
    // before it types anything; an impostor first, an agent registration
    // under `init`'s badge.
    // Both agents are registered first, so the runner's `list` shows them.
    for _ in 0..40 {
        if holds(trust, |o| matches!(o, Object::Process(_))) == 2 {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    let mut impostor = vec![VERSION, REGISTER_OP, 1, 8];
    impostor.extend_from_slice(b"impostor");
    send(&endpoint, &impostor, process(), INIT_BADGE);
    send(&endpoint, &[VERSION, RUNTIME_OP], process(), INIT_BADGE);
    t.check(
        "the runtime holds no device, and no console",
        holds(runtime, |o| {
            matches!(o, Object::Device(_) | Object::DebugConsole)
        }) == 0,
    );

    // The runner types `stop worker`: both agents end while the runtime
    // spins. (That the runtime still ran then, the runner checks: the
    // next `list` says `runtime running`, then `worker stopped` twice.)
    t.check(
        "`stop worker` on the trusted path stopped both agents of that name",
        records.iter().all(|r| end_of(r, 60) == Some(End::Stopped)),
    );
    t.check(
        "trust kept the runtime and both agents, and dropped the impostor",
        holds(trust, |o| matches!(o, Object::Process(_))) == 3,
    );
    t.check(
        "trust holds no console and no other device",
        holds(trust, |o| matches!(o, Object::DebugConsole)) == 0
            && holds(trust, |o| matches!(o, Object::Device(_))) == 1,
    );
    // Then `stop all`: the hung runtime ends.
    t.check(
        "`stop all` stopped the hung runtime",
        end_of(&record, 60) == Some(End::Stopped),
    );
    t.check(
        "trust still runs",
        process::by_id(trust).is_some_and(|p| p.record.end().is_none()),
    );

    // #206: an approval left open, then a new runtime's `CHANNEL`. The
    // runner must see `approve #1: the runtime ended`, and `yes 1` must
    // then be `no request #1`.
    let mut approve = vec![VERSION, APPROVE_OP, 1, 0, 6];
    approve.extend_from_slice(b"tester");
    approve.extend_from_slice(&[1, 0, 0, 0, MODEL, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    send(&endpoint, &approve, process(), RUNTIME_BADGE);
    let channel = Capability::new(Object::Endpoint(Endpoint::new()), SEND);
    send(&endpoint, &[VERSION, CHANNEL_OP], channel, RUNTIME_BADGE);
    // Let the runner type and read the last answer before QEMU exits.
    sched::sleep(Duration::from_secs(2));
}

fn mm_ready() -> bool {
    pharos_kernel::mm::init_heap().is_ok()
}
