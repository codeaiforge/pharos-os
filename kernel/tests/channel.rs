//! Test kernel: the Tier 3 channel and bridge between two booted VMs
//! (#297, #298, M6.3, bridge.md, D-036). `cargo xtask runner` boots it with
//! a second `virtio-serial-pci` whose port 0 is a host unix socket's server
//! end, and, once the bridge holds that device, the guest image (`cargo
//! xtask guest`) as a second VM whose one `virtserialport` is the client
//! end, with no relay between them. The launch tool checks the guest's
//! command line before it starts, and both VMs' devices through QMP. The
//! kernel starts `init` with the `channel` table (argument 12): the boot
//! services up to `trust`, the runtime with the `guest` policy table, the
//! bridge, and `guestclient`, which submits a task for `guest`. The guest
//! speaks frames: it answers the bridge's `HELLO`, takes its task, logs,
//! and completes it; the runner checks the guest's serial log too. Runs
//! under UEFI (D-009), in the `kvm` matrix cell only (bridge.md, decided
//! open question 4).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
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
    t.check("preemption enabled", sched::enable_preemption().is_ok());
    testing::init_iommu(crate::requests::RSDP.response());
    pci::enumerate();
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = ipc::Endpoint::new();
    testing::init_key();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let id = process::spawn_elf_limited(&root, b"bin/init", 12, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the channel table", id.is_ok());
    // The guest boots beside us once the bridge is ready.
    let summary = ipc::poll(&report, Duration::from_secs(200)).map(|m| m.bytes().to_vec());
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .map(|(_, l)| l)
        .collect();
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let has = |want: &[u8]| lines.iter().any(|l| l == want);
    t.check(
        "the bridge holds the channel's device",
        has(b"bridge: ready"),
    );
    t.check(
        "the bridge bound the guest's attempt",
        has(b"bridge: bound"),
    );
    t.check(
        "a control client's BIND is refused",
        has(b"ok channel: a control client's BIND is refused"),
    );
    t.check(
        "the guest's log line reached the runtime as the agent's",
        has(b"agents: guest: hello from the guest's log"),
    );
    t.check(
        "the attempt's capability was revoked as it ended",
        has(b"bridge: unbound"),
    );
    t.check(
        "the guest's task ran through the bridge",
        has(b"ok channel: the guest's task ran through the bridge"),
    );
    let entries = pharos_services::CHANNEL.len() as u8;
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
