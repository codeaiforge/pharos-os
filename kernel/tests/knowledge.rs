//! Test kernel: the knowledge service (#143, knowledge.md). `cargo xtask
//! runner` gives it a fresh store. The kernel starts `store` and
//! `knowledge` (namespace `knowledge`), then `knowledgeclient` in mode 0:
//! versions put, corrected, in conflict, and retracted, evidence the
//! reader cannot read, a query, a history, and a mark, with refusals by
//! badge. Then it kills the service (`process::kill`), starts it again on
//! the same endpoint and store, and runs `knowledgeclient` in mode 1: every
//! version, status, and mark survived, and numbering goes on. Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{CONFIG, Capability, IRQ, MAP, Object, RECEIVE, SEND, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// Namespace 8, `knowledge`, read-write (`pharos_proto::store`).
const KNOWLEDGE: u32 = 8;
/// Badges (`pharos_proto::knowledge::client`), and one the service knows
/// nothing of.
const RUNTIME: u32 = 1;
const TRUST: u32 = 2;
const OTHER: u32 = 3;
const KILLED: u64 = 13;

/// Starts `path` and waits for its `ready` on `report`.
fn start(
    t: &mut TestRun,
    programs: &fs::Fs,
    path: &[u8],
    caps: Vec<Arc<Capability>>,
    report: &Arc<Endpoint>,
    pages: u64,
) -> Option<TaskId> {
    let id = process::spawn_elf_limited(programs, path, 0, caps, pages).ok();
    let ready = ipc::poll(report, Duration::from_secs(20)).is_some_and(|m| m.bytes() == b"ready");
    let name = core::str::from_utf8(path).unwrap_or("?");
    t.check(
        &alloc::format!("{name} started and reported ready"),
        id.is_some() && ready,
    );
    id.filter(|_| ready)
}

/// Runs `knowledgeclient` in `mode` until it says `done`; its passed steps.
fn client(programs: &fs::Fs, service: &Arc<Endpoint>, mode: u64) -> (Option<TaskId>, Vec<Vec<u8>>) {
    let steps = Endpoint::new();
    let send = Capability::new(Object::Endpoint(service.clone()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        send.derive_badged(SEND, RUNTIME),
        send.derive_badged(SEND, TRUST),
        send.derive_badged(SEND, OTHER),
        Capability::new(Object::Endpoint(steps.clone()), SEND),
    ];
    let id = process::spawn_elf_limited(programs, b"bin/knowledgeclient", mode, caps, 256).ok();
    let mut passed = Vec::new();
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(40) {
        match ipc::poll(&steps, Duration::from_millis(100)) {
            Some(m) if m.bytes() == b"done" => break,
            Some(m) => {
                kprintln!("  {}", core::str::from_utf8(m.bytes()).unwrap_or("?"));
                passed.push(m.bytes().to_vec());
            }
            None => {}
        }
    }
    (id, passed)
}

fn exited_ok(id: Option<TaskId>) -> bool {
    (0..40).any(|_| {
        let ok = process::exits()
            .into_iter()
            .any(|e| Some(e.task) == id && e.code == 0);
        if !ok {
            sched::sleep(Duration::from_millis(50));
        }
        ok
    })
}

fn said(text: &str) -> bool {
    process::debug_output()
        .iter()
        .any(|(_, l)| l == text.as_bytes())
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
    let disk = pci::devices()
        .iter()
        .filter(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .nth(1)
        .cloned()
        .and_then(DeviceHandle::grant);
    let (Some(disk), Ok(programs)) = (disk, fs::mount("programs")) else {
        t.check("the store disk and the programs", false);
        return;
    };
    let (store, report, service) = (Endpoint::new(), Endpoint::new(), Endpoint::new());
    let ep = |e: &Arc<Endpoint>, rights| Capability::new(Object::Endpoint(e.clone()), rights);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(disk), MAP | CONFIG | IRQ),
        ep(&store, RECEIVE),
        ep(&report, SEND),
    ];
    if start(t, &programs, b"bin/store", caps, &report, 10_240).is_none() {
        return;
    }
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        ep(&service, RECEIVE),
        ep(&report, SEND),
        ep(&store, SEND).derive_badged(SEND, KNOWLEDGE),
    ];
    let Some(first) = start(t, &programs, b"bin/knowledge", caps.clone(), &report, 1024) else {
        return;
    };
    let (id, passed) = client(&programs, &service, 0);
    for step in [
        "INFO answers; a request before ATTACH is NO_BUFFER",
        "versions put and corrected, numbered by the service",
        "a conflict, then a retraction; every version kept with its status",
        "a wrong replaces, the user as author, and other badges are refused",
        "what cites an unreadable scope is as missing as nothing",
        "a query leaves out budget; the history has every version",
        "only trust verifies, with the right hash prefix",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the first client exited with no failed step", exited_ok(id));
    t.check(
        "the kernel killed the knowledge service",
        process::kill(first, KILLED),
    );
    sched::sleep(Duration::from_millis(200));
    if start(t, &programs, b"bin/knowledge", caps, &report, 1024).is_none() {
        return;
    }
    let (id, passed) = client(&programs, &service, 1);
    for step in [
        "after the restart: every version and status is still there",
        "the next version is numbered on, and the old head is stale",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "the second client exited with no failed step",
        exited_ok(id),
    );
    t.check(
        "each start said what it loaded",
        said("knowledge: start 1, 0 versions, 0 marks, 0 unreadable")
            && said("knowledge: start 2, 6 versions, 1 marks, 0 unreadable"),
    );
    sched::sleep(Duration::from_millis(500));
}
