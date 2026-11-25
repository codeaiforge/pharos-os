//! Test kernel: the Tier 3 bridge between two booted VMs, and the
//! hostile-guest suite (#297, #298, #300, M6.3, bridge.md, D-036). `cargo
//! xtask runner` boots it as it boots `vault` (the test authority as the
//! image's root, the test secret through `fw_cfg`, and
//! `scripts/vault-test-server.py` on the host), plus a second
//! `virtio-serial-pci` whose port 0 is a host unix socket's server end,
//! and, once the bridge holds that device, the guest image (`cargo xtask
//! guest`) as a second VM whose one `virtserialport` is the client end,
//! with no relay between them. The launch tool checks the guest's command
//! line before it starts, and both VMs' devices through QMP.
//!
//! The kernel starts `init` with the `bridge` table (argument 12): the
//! boot services up to `trust`, the TLS service, the vault, the gateway,
//! the runtime with the `guest` policy table, the bridge, and
//! `guestclient`, which runs one `guest` task per case: the LangGraph
//! agent (a log, a granted HTTPS request through the gateway, a
//! checkpoint, the answer); the guest's refusals; each hostile frame,
//! which must fail its task with the bridge's reason; then one more task,
//! so Pharos still binds; then `hold`, during whose first attempt the
//! kernel kills the bridge: `init` restarts it, its `BIND` ends that
//! attempt (`bridge restarted`), and the second attempt completes; then
//! `restart`, during whose first attempt the kernel kills the runtime: the
//! guest's next request, through the capability the killed runtime
//! minted, is refused by the new one, and the retried attempt completes
//! with its checkpoint and no earlier bytes in its buffer (M6.3 review). The runner checks the guest's serial log (what
//! it can reach: no network, disk, shared mount, or second port) and the
//! audit trail. Runs under UEFI (D-009), in the `kvm` matrix cell only
//! (bridge.md, decided open question 4).

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

/// The hostile cases, each a task the bridge must fail.
const HOSTILE: [&str; 9] = [
    "magic",
    "version",
    "kind",
    "length",
    "message",
    "data",
    "notpassed",
    "early",
    "flood",
];

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
    let id = process::spawn_elf_limited(&root, b"bin/init", 12, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the bridge table", id.is_ok());
    let Ok(init) = id else {
        return;
    };
    // The guest boots beside us once the bridge is ready. Each line is
    // kept as it comes: the cases write more than the kernel's log holds.
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut seen = 0;
    let mut lost = false;
    let mut killed = false;
    let mut runtime_killed = false;
    // Each new line kept; the bridge killed once `hold` says it holds, the
    // runtime once `restart` does.
    let mut keep = |lines: &mut Vec<Vec<u8>>| {
        let (now, new) = process::debug_output_since(seen);
        seen = now;
        let Some(new) = new else {
            lost = true;
            return;
        };
        for (_, line) in new {
            if line == b"agents: guest: holding" && !killed {
                let bridge = child(init, &[pharos_services::AGENTS_BRIDGE]);
                killed = bridge.is_some_and(|b| process::kill(b, KILLED));
            }
            if line == b"agents: guest: restart holding" && !runtime_killed {
                let runtime = child(init, RUNTIME_BADGES);
                runtime_killed = runtime.is_some_and(|r| process::kill(r, KILLED));
            }
            lines.push(line);
        }
    };
    let start = time::uptime();
    let summary = loop {
        if let Some(m) = ipc::poll(&report, Duration::from_millis(100)) {
            break Some(m.bytes().to_vec());
        }
        keep(&mut lines);
        // Within the runner's 60 s, so a hung case shows as its checks.
        if time::uptime() - start > Duration::from_secs(50) {
            break None;
        }
    };
    keep(&mut lines);
    t.check("no console line was lost", !lost);
    t.check("the bridge was found and killed during hold", killed);
    t.check(
        "the runtime was found and killed during restart",
        runtime_killed,
    );
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let has = |want: &[u8]| lines.iter().any(|l| l == want);
    let count = |want: &[u8]| lines.iter().filter(|l| *l == want).count();
    let case = |name: &str| has(&[b"ok bridge: ", name.as_bytes()].concat());
    t.check(
        "the bridge holds the channel's device",
        has(b"bridge: ready"),
    );
    t.check(
        "a control client's BIND is refused",
        has(b"ok bridge: a control client's BIND is refused"),
    );
    t.check(
        "the guest's log line reached the runtime as the agent's",
        has(b"agents: guest: hello from the guest's log"),
    );
    t.check(
        "the LangGraph agent's task completed through the bridge",
        case("agent"),
    );
    t.check(
        "the guest's refused requests left its attempt running",
        case("refusals"),
    );
    for name in HOSTILE {
        t.check(name, case(name));
    }
    t.check(
        "each hostile case failed its attempt at the bridge",
        count(b"bridge: attempt failed") == HOSTILE.len(),
    );
    t.check(
        "after the hostile cases, the next attempt is bound and completes",
        case("again"),
    );
    t.check(
        "the restarted bridge bound hold's second attempt, which completed",
        case("hold") && count(b"init: bridge ready") >= 2,
    );
    // #301 (M6.3 review R-1, R-2): the request through the capability
    // the killed runtime minted reaches no attempt of the new one.
    t.check(
        "after the runtime restarted, a request through its capability is refused",
        !has(b"agents: guest: stale") && case("restart") && count(b"init: agents ready") >= 2,
    );
    t.check(
        "the bridge ended the attempt the restarted runtime refused",
        count(b"bridge: refused by the runtime") == 1,
    );
    // One bind and one revocation per attempt, but the killed bridge's
    // last, which its successor's BIND ended, and the killed runtime's,
    // which the next refused.
    let attempts = HOSTILE.len() + 7;
    t.check(
        "every attempt bound, and its capability revoked as it ended",
        count(b"bridge: bound") == attempts && count(b"bridge: unbound") == attempts - 2,
    );
    t.check(
        "every case ended as it should",
        has(b"ok bridge: every case ended as it should"),
    );
    let entries = pharos_services::BRIDGE.len() as u8;
    t.check(
        "every service and the client succeeded",
        summary.as_deref() == Some(&[entries, 0, 0, 0][..]),
    );
    t.check(
        "no client reported a failure",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
    t.check("nothing was killed", process::kills().is_empty());
}

/// The vector a killed service's end reports.
const KILLED: u64 = 13;

/// What only the runtime holds in the `bridge` table: its audit badge,
/// its badge at `trust`, and badge 1 at the inference service and the
/// gateway.
const RUNTIME_BADGES: &[u32] = &[
    pharos_services::AUDIT_RUNTIME,
    pharos_services::TRUST_RUNTIME_BADGE,
    1,
];

/// The one live child of `init` holding an endpoint with each of
/// `badges`: the bridge for `AGENTS_BRIDGE`, the runtime for
/// [`RUNTIME_BADGES`]. None if not exactly one.
fn child(init: TaskId, badges: &[u32]) -> Option<TaskId> {
    let found: Vec<TaskId> = (process::ids().into_iter())
        .filter(|&id| {
            process::by_id(id).is_some_and(|p| {
                let mut caps = p.caps.lock();
                let held: Vec<u32> = (1..=MAX_HANDLES as u64)
                    .filter_map(|h| caps.get(h, 0).ok())
                    .filter(|c| matches!(c.object(), Object::Endpoint(_)))
                    .map(|c| c.badge())
                    .collect();
                p.parent == Some(init) && badges.iter().all(|b| held.contains(b))
            })
        })
        .collect();
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}
