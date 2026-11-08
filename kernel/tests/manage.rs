//! Test kernel: the user starts, stops, and restarts services from the
//! trusted console (#170, services.md, D-029). `cargo xtask runner` boots
//! it with the boot image's modules and disks, as for `system`, and types
//! the commands (`MANAGE_SCRIPT` in xtask): `stop service net` (twice),
//! `start net` (twice), `stop service store` (protected), `start nosuch`,
//! `restart knowledge`, `stop service knowledge`, `restart trust` (needs
//! knowledge), `start knowledge`, `restart trust`, `services`, and `stop
//! all`. The kernel waits for the runtime's stop, which shows the new
//! `trust` holds the emergency stop, then checks `init`'s lines and the
//! capability audit. First, at ready, it sends `init` `STOP agents` and
//! `RESTART audit` itself (services the script never manages) under the
//! knowledge service's badge and an unknown one: `init` answers
//! management only on `trust`'s badge, so no answer may come and neither
//! may happen. The runner checks the trusted console and the trail.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, MAX_HANDLES, Object, SEND};
use pharos_kernel::ipc::{Endpoint, Message};
use pharos_kernel::sched::TaskId;
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};
use pharos_services::Ep;

#[path = "common/manifests.rs"]
mod manifests;

pharos_kernel::test_kernel!(run);

/// The boot table's 8 entries, all succeeded, from the factory image.
const SUMMARY: [u8; 4] = [8, 0, 0, 0];
const VIRTIO_NET: u16 = 0x1041;
/// The knowledge service's report badge (entry 5 + 1), and one nobody has.
const FORGED_BADGES: [u32; 2] = [6, 99];

/// Sends `init`'s report endpoint `[version, op, length, name]` under
/// `badge`. (An answer cannot be seen: `init` answers without waiting, and
/// the kernel does not wait in `receive`; what `init` does is checked.)
fn forged(events: &Endpoint, badge: u32, op: u8, name: &[u8]) {
    let mut data = [0; MAX_MESSAGE];
    let request = [&[1, op, name.len() as u8][..], name].concat();
    data[..request.len()].copy_from_slice(&request);
    let message = Message {
        data,
        len: request.len(),
        cap: Some(Capability::new(Object::Endpoint(Endpoint::new()), SEND)),
        badge,
    };
    ipc::send(events, message);
}

/// The last line: the new `trust`'s `stop all` reached the runtime.
const LAST: &str = "init: agents stopped; not restarted";

fn net_of(init: TaskId) -> Option<TaskId> {
    (init + 1..init + 400).find(|&id| {
        process::by_id(id).is_some_and(|p| {
            let mut caps = p.caps.lock();
            p.parent == Some(init)
                && (1..=MAX_HANDLES as u64).any(|h| {
                    caps.get(h, 0).is_ok_and(
                        |c| matches!(c.object(), Object::Device(d) if d.pci.device == VIRTIO_NET),
                    )
                })
        })
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
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let init = process::spawn_elf_limited(&root, b"bin/init", 0, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the boot table", init.is_ok());
    let Ok(init) = init else {
        return;
    };

    let mut lines: Vec<(TaskId, Vec<u8>)> = Vec::new();
    let has =
        |lines: &[(TaskId, Vec<u8>)], text: &str| lines.iter().any(|(_, l)| l == text.as_bytes());
    let mut summary = None;
    let mut audit = None;
    let mut net_before = None;
    let start = time::uptime();
    // About 10 s needed; under the runner's 60 s limit.
    while time::uptime() - start < Duration::from_secs(50) {
        for l in process::debug_output() {
            if !lines.contains(&l) {
                kprintln!("  {}: {}", l.0, core::str::from_utf8(&l.1).unwrap_or("?"));
                lines.push(l);
            }
        }
        if summary.is_none() {
            summary = ipc::poll(&report, Duration::from_millis(1)).map(|m| m.bytes().to_vec());
            if summary.is_some() {
                match manifests::Audit::new(init, &report, pharos_services::BOOT) {
                    Ok(a) => audit = Some(a),
                    Err(why) => kprintln!("  audit: {why}"),
                }
                net_before = net_of(init);
                let events = audit.as_ref().and_then(|a| a.endpoint_of(Ep::Events));
                for (e, &badge) in events
                    .iter()
                    .flat_map(|e| FORGED_BADGES.iter().map(move |b| (e, b)))
                {
                    forged(e, badge, 8, b"agents");
                    forged(e, badge, 9, b"audit");
                }
                t.check(
                    "init's report endpoint found, and STOP and RESTART sent on it not as trust",
                    events.is_some(),
                );
            }
        }
        if has(&lines, LAST) {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    sched::sleep(Duration::from_millis(500));

    t.check(
        "init reported every boot service ready: [8, 0, 0, 0]",
        summary.as_deref() == Some(&SUMMARY[..]),
    );
    for (what, line) in [
        ("the user's stop", "init: net stopped by the user"),
        ("the user's start", "init: net started by the user"),
        ("and the started service is ready", "init: net ready"),
        (
            "a protected service is not stopped",
            "init: store stop refused: protected",
        ),
        (
            "a restart names the dependents",
            "init: knowledge restarted by the user; used by trust, agents",
        ),
        (
            "a stop names them too",
            "init: knowledge stopped by the user; used by trust, agents",
        ),
        (
            "and a start after it",
            "init: knowledge started by the user",
        ),
        (
            "trust restarted",
            "init: trust restarted by the user; used by agents",
        ),
        ("the new trust stopped the runtime", LAST),
    ] {
        t.check(&alloc::format!("{what}: {line}"), has(&lines, line));
    }
    let count = |text: &str| lines.iter().filter(|(_, l)| l == text.as_bytes()).count();
    t.check(
        "each action happened once (net stopped once, forged and refused requests did nothing)",
        count("init: net stopped by the user") == 1
            && count("init: net started by the user") == 1
            && count("init: knowledge restarted by the user; used by trust, agents") == 1,
    );
    t.check(
        "no service was restarted by its policy",
        !lines
            .iter()
            .any(|(_, l)| l.windows(12).any(|w| w == b" restarting ")),
    );
    t.check(
        "trust was not restarted while knowledge was stopped",
        count("init: trust restarted by the user; used by agents") == 1,
    );
    t.check(
        "the forged requests did nothing: agents not stopped, audit not restarted by them",
        !has(&lines, "init: agents stopped by the user")
            && !lines
                .iter()
                .any(|(_, l)| l.starts_with(b"init: audit restarted")),
    );
    let net_now = net_of(init);
    t.check(
        "a new network service runs",
        net_now.is_some() && net_now != net_before,
    );
    let Some(audit) = audit.as_ref() else {
        t.check("the audit learned init's endpoints", false);
        return;
    };
    let (findings, report_lines) = audit.check();
    for line in report_lines.iter().chain(&findings) {
        kprintln!("  audit: {line}");
    }
    t.check(
        "every service started by the user holds exactly its manifest",
        findings.is_empty(),
    );
}
