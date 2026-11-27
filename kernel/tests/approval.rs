//! Test kernel: payload approval end to end (#328, M6.4, approval.md,
//! D-037). `cargo xtask runner` boots it as it does `vault` (the boot
//! image, the secrets file, `scripts/vault-test-server.py`), with three
//! people in the store (`admin`, who owns `fetcher`, `bob`, and `carol`)
//! and `APPROVAL_SCRIPT` on the trusted console. The kernel starts `init`
//! with the `approval` table (13): the `vault` table's services and
//! routes, the runtime on policy table 5 (`fetcher`, short approval
//! timeouts), and `agentclient` 20. Each of `fetcher`'s requests on a
//! marked route ends as the runner answers it: one approver, sent; two,
//! the requester refused, a person the requester just added refused
//! (M6.4 review F1), then `bob` and `carol`; two, unanswered,
//! refused at the deadline; one shown while no one was logged in, approved
//! only after `show`; one approved, then changed, and the change refused.
//! Then the client, as gateway client 2, finds the changed body refused
//! and the approved one sent once. Then the kernel kills `trust` at the
//! client's cue; `init` restarts it, and an ask approved there is denied,
//! as the restarted `trust` cannot tell the runtime. The runner checks
//! the server received exactly the approved bodies, and the trail. Runs
//! under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{MAX_HANDLES, Object};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

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
    t.check(
        "the date at boot is kept, for the TLS service's certificate checks",
        time::set_boot_date(requests::DATE_AT_BOOT.response().map(|d| d.timestamp)),
    );
    t.check("preemption enabled", sched::enable_preemption().is_ok());
    testing::init_iommu(crate::requests::RSDP.response());
    pci::enumerate();
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = ipc::Endpoint::new();
    testing::init_key();
    t.check(
        "the host's secrets file was read",
        pharos_kernel::key::secrets_init().is_ok_and(|n| n > 0),
    );
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let id = process::spawn_elf_limited(&root, b"bin/init", 13, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the approval table", id.is_ok());

    // Every entry, the one-shot client last: it ends with its tasks. Each
    // line the client prints to name a kill is acted on as it comes.
    let Ok(init) = id else {
        return;
    };
    let mut seen = 0;
    let mut killed = Vec::new();
    let start = time::uptime();
    let summary = loop {
        if let Some(m) = ipc::poll(&report, Duration::from_millis(100)) {
            break Some(m);
        }
        if time::uptime() - start > Duration::from_secs(230) {
            break None;
        }
        let (now, new) = process::debug_output_since(seen);
        seen = now;
        for (_, line) in new.unwrap_or_default() {
            let names: &[&str] = match line.as_slice() {
                b"approval: kill trust" => &["trust"],
                _ => &[],
            };
            for name in names {
                let found = child(init, name);
                if found.is_some_and(|id| process::kill(id, KILLED)) {
                    killed.push(*name);
                }
            }
        }
    };
    t.check("trust found and killed at the cue", killed == ["trust"]);
    let entries = pharos_services::APPROVAL.len() as u8;
    t.check(
        "every service and the client succeeded",
        summary.is_some_and(|m| m.bytes() == [entries, 0, 0, 0]),
    );
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .map(|(_, l)| l)
        .collect();
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let has = |want: &[u8]| lines.iter().any(|l| l == want);
    for step in [
        "every ask ended as the trusted console answered it",
        "the gateway sends only approved bytes, once",
    ] {
        t.check(step, has(alloc::format!("ok approval: {step}").as_bytes()));
    }
    // The restart came between the cue and the denied ask.
    let in_order = |want: &[&[u8]]| {
        let mut rest = lines.iter();
        want.iter().all(|w| rest.any(|l| l == w))
    };
    t.check(
        "after trust restarted, its approval is denied",
        in_order(&[
            b"approval: kill trust",
            b"init: trust ready",
            b"ok approval: after trust restarted, its approval is denied",
        ]),
    );
    t.check(
        "no client reported a failure",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
}

/// The vector a killed service's end reports.
const KILLED: u64 = 13;

/// The one live child of `init` holding what only `name` holds in the
/// `approval` table: for `trust`, the store's `identity` badge and its
/// audit badge. None if not exactly one.
fn child(init: TaskId, name: &str) -> Option<TaskId> {
    let wanted: &[u32] = match name {
        "trust" => &[
            pharos_services::IDENTITY_STORE,
            pharos_services::AUDIT_TRUST,
        ],
        _ => &[],
    };
    let found: Vec<TaskId> = (process::ids().into_iter())
        .filter(|&id| {
            process::by_id(id).is_some_and(|p| {
                let mut caps = p.caps.lock();
                let held: Vec<_> = (1..=MAX_HANDLES as u64)
                    .filter_map(|h| caps.get(h, 0).ok())
                    .collect();
                let badges: Vec<u32> = (held.iter())
                    .filter(|c| matches!(c.object(), Object::Endpoint(_)))
                    .map(|c| c.badge())
                    .collect();
                p.parent == Some(init)
                    && !wanted.is_empty()
                    && wanted.iter().all(|b| badges.contains(b))
            })
        })
        .collect();
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}
