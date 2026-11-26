//! Test kernel: rotating the audit trail (#217, D-048). `cargo xtask
//! runner` gives it a fresh store. The kernel starts `store`, `audit` with
//! its `AuditAnchor` key, and `trust`, as `init` does, then `auditclient`
//! in mode 2, which also holds the service badged as `trust`. The client
//! writes boot 1's records and asks the kernel to restart the service
//! (boot 2); then a rotation from another client is refused, one with a
//! code no export gave is refused, the one the client computes from boot
//! 1's count and head frees it, and a second finds nothing to free. The
//! runner types `audit rotate` with a made-up code on the trusted console
//! (refused), and afterwards checks that only boot 2's stream is left,
//! with its signed heads and a `rotate` record naming the code.

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

fn said(prefix: &str) -> bool {
    process::debug_output()
        .iter()
        .any(|(_, l)| l.starts_with(prefix.as_bytes()))
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
    pharos_kernel::testing::init_iommu(crate::requests::RSDP.response());
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
    if start(t, &programs, b"bin/store", store_caps, &report, 10_240).is_none() {
        return;
    }
    pharos_kernel::testing::init_key();
    pharos_kernel::key::measure(core::iter::once((&b"kernel"[..], &b"rotate test"[..])));
    let audit_caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        ep(&audit, RECEIVE),
        ep(&report, SEND),
        ep(&store, SEND).derive_badged(SEND, AUDIT_TRAIL),
        Capability::new(
            Object::Key(pharos_kernel::key::Purpose::AuditAnchor),
            pharos_kernel::cap::READ,
        ),
    ];
    let Some(first) = start(t, &programs, b"bin/audit", audit_caps.clone(), &report, 0) else {
        return;
    };
    let caps = vec![
        Capability::new(Object::Device(console), MAP | CONFIG | IRQ),
        ep(&trust, RECEIVE),
        ep(&report, SEND),
        ep(&audit, SEND).derive_badged(SEND, TRUST_CLIENT),
        // No knowledge service here (no rights: a call fails at once), then
        // its people (#310); the runner seeds the test person.
        Capability::new(Object::Endpoint(Endpoint::new()), 0),
        ep(&store, SEND).derive_badged(SEND, pharos_services::IDENTITY_STORE),
    ];
    let pages = u64::from(pharos_services::TRUST_LIMIT);
    if start(t, &programs, b"bin/trust", caps, &report, pages).is_none() {
        return;
    }
    // `trust`'s `RUNTIME` request (#170), answered as `init` does with no
    // runtime, so later waits for `ready` do not take it.
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

    let steps = Endpoint::new();
    let send = ep(&audit, SEND);
    let client_caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        send.derive_badged(SEND, 4),
        send.derive_badged(SEND, 5),
        ep(&steps, SEND),
        send.derive_badged(SEND, TRUST_CLIENT),
    ];
    let id = process::spawn_elf_limited(&programs, b"bin/auditclient", 2, client_caps, 64).ok();
    let mut passed = Vec::new();
    let begin = time::uptime();
    let mut restarted = false;
    while time::uptime() - begin < Duration::from_secs(60) {
        match ipc::poll(&steps, Duration::from_millis(100)) {
            Some(m) if m.bytes() == b"done" => break,
            // Boot 2: the service killed and started again.
            Some(m) if m.bytes() == b"restart" && !restarted => {
                restarted = true;
                t.check(
                    "the kernel killed the audit service",
                    process::kill(first, KILLED),
                );
                sched::sleep(Duration::from_millis(200));
                let again = start(t, &programs, b"bin/audit", audit_caps.clone(), &report, 0);
                if again.is_none() {
                    return;
                }
            }
            Some(m) => {
                kprintln!("  {}", core::str::from_utf8(m.bytes()).unwrap_or("?"));
                passed.push(m.bytes().to_vec());
            }
            None => {}
        }
    }
    for step in [
        "boot 1: three records",
        "after the restart: boot 2",
        "ROTATE from a client that is not trust: NO_ACCESS",
        "ROTATE with a code no export gave: NO_EXPORT, nothing freed",
        "ROTATE with boot 1's code: boot 1 freed",
        "a second ROTATE: nothing to free",
        "HEAD: boot 2 holds its boot record and the rotate record",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the client exited with no failed step", {
        (0..40).any(|_| {
            let ok = process::exits()
                .into_iter()
                .any(|e| Some(e.task) == id && e.code == 0);
            if !ok {
                sched::sleep(Duration::from_millis(50));
            }
            ok
        })
    });
    t.check(
        "the service logged the rotation",
        said("audit: rotated: export ") && said("audit: boot 2, log/2"),
    );
    // Let the runner read the trusted console before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
