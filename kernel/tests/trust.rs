//! Test kernel: the trusted path and the emergency stop (#96, D-018,
//! agents.md). The kernel starts `trust` with the virtio-console device,
//! its endpoint, and a report endpoint, as `init` does. A stand-in agent
//! runtime (`child` mode 15) starts an agent, registers it with `trust`,
//! and then spins: a hung runtime. The kernel registers that process as
//! the runtime under `init`'s badge, and sends an impostor agent under the
//! wrong badge, which `trust` must drop. `cargo xtask runner` types on the
//! trusted console (`TRUST_SCRIPT`): `list`, `stop worker`, a bad command,
//! `list`, `stop all`. The kernel checks the agent ends while the runtime
//! spins, then the runtime ends, and what each process holds. Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
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
const INIT_BADGE: u32 = 1;
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

    // The agent the runtime started (its only child).
    let mut agent = None;
    for _ in 0..40 {
        agent = (runtime + 1..runtime + 4)
            .find(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(runtime)));
        if agent.is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    let Some(agent) = agent else {
        t.check("the runtime started its agent", false);
        return;
    };
    t.check("the runtime started its agent", true);
    t.check("the agent holds no capability", holds(agent, |_| true) == 0);
    let Some(agent_record) = process::by_id(agent).map(|p| p.record.clone()) else {
        t.check("the agent's record", false);
        return;
    };
    // Only now the runtime's registration, which the runner waits for
    // before it types anything; an impostor first, an agent registration
    // under `init`'s badge.
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

    // The runner types `stop worker`: the agent ends while the runtime
    // spins. (That the runtime still ran then, the runner checks: the
    // next `list` says `runtime running`, then `worker stopped`.)
    t.check(
        "`stop worker` on the trusted path stopped the agent",
        end_of(&agent_record, 60) == Some(End::Stopped),
    );
    t.check(
        "trust kept the runtime and the agent, and dropped the impostor",
        holds(trust, |o| matches!(o, Object::Process(_))) == 2,
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
    // Let the runner read the last answer before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}

fn mm_ready() -> bool {
    pharos_kernel::mm::init_heap().is_ok()
}
