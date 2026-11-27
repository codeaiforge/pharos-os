//! Test kernel: the credential vault and the egress gateway end to end
//! (#284, M6.2, gateway.md, D-035). `cargo xtask runner` boots it with
//! the boot image's modules and disks, the test authority as the image's
//! root, a secrets file holding the test secret through `fw_cfg`, and
//! `scripts/vault-test-server.py` on the host. The kernel starts `init`
//! with the `vault` table (argument 11): the boot services up to `trust`,
//! the TLS service, the vault, the gateway, the runtime with `fetcher`,
//! and `agentclient` 17, which runs one `fetcher` task. The agent checks
//! that a granted request succeeds, that the echoed header comes back as
//! `[secret]`, that a route not granted, a path
//! the pattern refuses, a body on `GET`, and a route whose secret is
//! missing are each refused, and that its buffer never holds the secret.
//! The runner then checks the server saw the header, the trail has each
//! record, and the secret is in neither the trail, the console, nor the
//! server's log. Then (M6.2 review) the kernel kills the vault and the TLS
//! service, and later the gateway, when the client names them; `init`
//! restarts each, and an `again` task must still get its secret injected
//! and stripped, so each re-attaches its buffers. Runs under UEFI (D-009).

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
    let id = process::spawn_elf_limited(&root, b"bin/init", 11, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the vault table", id.is_ok());

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
                b"vault: kill vault and tls" => &["vault", "tls"],
                b"vault: kill gateway" => &["gateway"],
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
    t.check(
        "the vault, the TLS service, and the gateway each found and killed",
        killed == ["vault", "tls", "gateway"],
    );
    let entries = pharos_services::VAULT.len() as u8;
    t.check(
        "every service and the client succeeded: 12 ready, 0 failed",
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
    t.check("the vault holds one secret", has(b"vault: secrets: 1"));
    t.check(
        "the fetcher's requests and refusals all checked",
        has(b"ok vault: the fetcher's requests and refusals all checked"),
    );
    t.check(
        "the gateway refuses a marked route's request with no approval, from any client",
        has(b"ok vault: the gateway refuses a marked route's request with no approval"),
    );
    // Each restart after its kill and before the request that needed it.
    let in_order = |want: &[&[u8]]| {
        let mut rest = lines.iter();
        want.iter().all(|w| rest.any(|l| l == w))
    };
    let done = b"ok vault: after the vault and the TLS service restarted, a request works";
    t.check(
        "after the vault and the TLS service restarted, a request works",
        in_order(&[b"vault: kill vault and tls", b"init: vault ready", done])
            && in_order(&[b"vault: kill vault and tls", b"init: tls ready", done]),
    );
    t.check(
        "after the gateway restarted, a request works",
        in_order(&[
            b"vault: kill gateway",
            b"init: gateway ready",
            b"ok vault: after the gateway restarted, a request works",
        ]),
    );
    t.check(
        "no client reported a failure",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
    t.check("nothing was killed", process::kills().is_empty());
}

/// The vector a killed service's end reports.
const KILLED: u64 = 13;

/// The one live child of `init` holding what only `name` holds in the
/// `vault` table: the secrets file (the vault), the TLS service's port and
/// audit badges, or the gateway's audit badge and its badge 1 at the vault
/// and the TLS service. None if not exactly one.
fn child(init: TaskId, name: &str) -> Option<TaskId> {
    let wanted: &[u32] = match name {
        "tls" => &[pharos_services::TLS_NET_PORT, pharos_services::AUDIT_TLS],
        "gateway" => &[pharos_services::AUDIT_GATEWAY, 1],
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
                    && match name {
                        "vault" => held.iter().any(|c| matches!(c.object(), Object::Secrets)),
                        _ => wanted.iter().all(|b| badges.contains(b)),
                    }
            })
        })
        .collect();
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}
