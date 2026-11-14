//! Test kernel: the audit service (#107, capabilities.md). `cargo xtask
//! runner` gives it a tiny fresh store (16 blocks). The kernel starts
//! `store`, `audit` (namespace `audit`), and `trust` with an audit
//! capability, as `init` does, then `auditclient` in mode 0: records from
//! two clients, an intent and its outcome, malformed entries refused. Then
//! it kills the audit service (`process::kill`) and the storage service,
//! starts the audit service again on the same endpoint while the store is
//! down (it must open no stream, #214), then the store, and runs
//! `auditclient` in mode 1: a new stream, opened once the store answers,
//! then the store fills and `APPEND` answers `UNWRITABLE` while `HEAD`
//! still answers. The runner types `audit` on the trusted console, and
//! afterwards checks the image with `cargo xtask store audit`'s code and
//! that the chain head `trust` showed at start is the image's. Runs under
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

/// Namespace 6, `audit`, read-write (`pharos_proto::store`).
const AUDIT_TRAIL: u32 = 6;
const TRUST_CLIENT: u32 = 2;
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

/// Runs `auditclient` in `mode` until it says `done`; its passed steps.
fn client(programs: &fs::Fs, audit: &Arc<Endpoint>, mode: u64) -> (Option<TaskId>, Vec<Vec<u8>>) {
    let steps = Endpoint::new();
    let send = Capability::new(Object::Endpoint(audit.clone()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        send.derive_badged(SEND, 4),
        send.derive_badged(SEND, 5),
        Capability::new(Object::Endpoint(steps.clone()), SEND),
    ];
    let id = process::spawn_elf_limited(programs, b"bin/auditclient", mode, caps, 64).ok();
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
    let devices = pci::devices();
    let disk = devices
        .iter()
        .filter(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .nth(1)
        .cloned()
        .and_then(DeviceHandle::grant);
    let console = devices
        .iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1043))
        .cloned()
        .and_then(DeviceHandle::grant);
    let (Some(disk), Some(console), Ok(programs)) = (disk, console, fs::mount("programs")) else {
        t.check("the store disk, the console, and the programs", false);
        return;
    };
    let (store, report, audit, trust) = (
        Endpoint::new(),
        Endpoint::new(),
        Endpoint::new(),
        Endpoint::new(),
    );
    let ep = |e: &Arc<Endpoint>, rights| Capability::new(Object::Endpoint(e.clone()), rights);
    let store_caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(disk), MAP | CONFIG | IRQ),
        ep(&store, RECEIVE),
        ep(&report, SEND),
    ];
    let Some(store_id) = start(
        t,
        &programs,
        b"bin/store",
        store_caps.clone(),
        &report,
        10_240,
    ) else {
        return;
    };
    let audit_caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        ep(&audit, RECEIVE),
        ep(&report, SEND),
        ep(&store, SEND).derive_badged(SEND, AUDIT_TRAIL),
    ];
    let Some(first) = start(t, &programs, b"bin/audit", audit_caps.clone(), &report, 0) else {
        return;
    };
    let caps = vec![
        Capability::new(Object::Device(console), MAP | CONFIG | IRQ),
        ep(&trust, RECEIVE),
        ep(&report, SEND),
        ep(&audit, SEND).derive_badged(SEND, TRUST_CLIENT),
    ];
    if start(t, &programs, b"bin/trust", caps, &report, 0).is_none() {
        return;
    }
    // Answer `trust`'s `RUNTIME` request (#170) as `init` does with no
    // runtime: `NOT_FOUND`, so it reads its console at once, and later
    // waits for `ready` on this endpoint do not take it instead.
    if let Some(Object::Endpoint(reply)) = ipc::poll(&report, Duration::from_secs(2))
        .and_then(|m| m.cap)
        .map(|c| c.object().clone())
    {
        let mut data = [0; pharos_kernel::syscall::MAX_MESSAGE];
        data[0] = 7; // status::NOT_FOUND
        let answer = ipc::Message {
            data,
            len: 1,
            cap: None,
            badge: 0,
        };
        let _ = ipc::try_send(&reply, answer);
    }

    let (id, passed) = client(&programs, &audit, 0);
    for step in [
        "HEAD: boot 1, its boot record only",
        "entries from two clients get consecutive sequence numbers",
        "an intent, then its outcome referring to it",
        "malformed entries are refused and not stored",
        "HEAD: 6 records and a chain head",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the first client exited with no failed step", exited_ok(id));

    t.check(
        "the kernel killed the audit service",
        process::kill(first, KILLED),
    );
    // #214: the store too, and the audit service started while it is
    // down (its look-up times out after 10 s), then the store again. Its
    // stream must be a new one, opened once the store answers.
    t.check(
        "the kernel killed the storage service",
        process::kill(store_id, KILLED),
    );
    sched::sleep(Duration::from_millis(200));
    if start(t, &programs, b"bin/audit", audit_caps, &report, 0).is_none() {
        return;
    }
    t.check(
        "with no store, the audit service opened no stream",
        said("audit: the store does not take records; not yet a stream"),
    );
    if start(t, &programs, b"bin/store", store_caps, &report, 10_240).is_none() {
        return;
    }
    let (id, passed) = client(&programs, &audit, 1);
    for step in [
        "after the restart: boot 2, a new stream",
        "the store fills: APPEND answers UNWRITABLE",
        "and keeps answering it",
        "HEAD still answers, counting only stored records",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "the second client exited with no failed step",
        exited_ok(id),
    );
    t.check(
        "each start said its boot and stream",
        said("audit: boot 1, log/1") && said("audit: boot 2, log/2"),
    );
    // Let the runner read the last answer before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
