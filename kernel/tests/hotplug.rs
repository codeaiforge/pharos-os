//! Test kernel: devices added to and removed from a hotplug slot (#171,
//! drivers.md, D-029). `cargo xtask runner` boots it with the boot image's
//! modules and disks, as for `system`, with two PCIe root ports, a QMP
//! channel, and a spare drive. Its script (`HOTPLUG_SCRIPT` in xtask) adds
//! a virtio-blk disk to slot 1, removes it once the `disk` driver is
//! ready, adds it again, stops the driver from the console, and removes
//! it. The kernel checks the slot was found, each arrival got BARs and its
//! driver, each removal stopped the driver before the slot powered off,
//! the capability audit while the driver runs, and that afterwards no
//! process holds a capability on a device behind the slot. The runner
//! checks the trusted console and the trail. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{MAX_HANDLES, Object};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

#[path = "common/manifests.rs"]
mod manifests;

pharos_kernel::test_kernel!(run);

/// The boot table's 8 boot entries ready; the driver entry waits.
const SUMMARY: [u8; 4] = [8, 0, 0, 0];
const ADDED: &str = "init: slot 1 added 1af4:1042; driver disk";
const REMOVED: &str = "init: slot 1 removed 1af4:1042; driver disk";
/// The last line: `services` after the second removal (the runner types it
/// once QEMU has deleted the second device).
const LAST: &str = "init: services listed for trust";

/// Live capabilities, in any process, on a device off bus 0 (behind a
/// slot).
fn slot_device_caps() -> usize {
    (1..400)
        .filter_map(process::by_id)
        .map(|p| {
            let mut caps = p.caps.lock();
            (1..=MAX_HANDLES as u64)
                .filter(|&h| {
                    caps.get(h, 0).is_ok_and(
                        |c| matches!(c.object(), Object::Device(d) if d.pci.address.bus != 0),
                    )
                })
                .count()
        })
        .sum()
}

/// The `disk` driver's report badge: entry 8 + 1.
const DISK_BADGE: u32 = 9;

/// The buses of the devices the running `disk` driver holds.
fn driver_device_buses(init: TaskId) -> Vec<u8> {
    let Some(p) = (init + 1..init + 400)
        .filter_map(process::by_id)
        .find(|p| p.parent == Some(init) && holds_disk_badge(p))
    else {
        return Vec::new();
    };
    let mut caps = p.caps.lock();
    (1..=MAX_HANDLES as u64)
        .filter_map(|h| caps.get(h, 0).ok())
        .filter_map(|c| match c.object() {
            Object::Device(d) => Some(d.pci.address.bus),
            _ => None,
        })
        .collect()
}

fn holds_disk_badge(p: &process::Process) -> bool {
    let mut caps = p.caps.lock();
    (1..=MAX_HANDLES as u64).any(|h| {
        caps.get(h, 0)
            .is_ok_and(|c| matches!(c.object(), Object::Endpoint(_)) && c.badge() == DISK_BADGE)
    })
}

/// Live children of `init` holding the driver entry's report capability.
fn drivers(init: TaskId) -> usize {
    (init + 1..init + 400)
        .filter_map(process::by_id)
        .filter(|p| {
            let mut caps = p.caps.lock();
            p.parent == Some(init)
                && (1..=MAX_HANDLES as u64).any(|h| {
                    caps.get(h, 0).is_ok_and(|c| {
                        matches!(c.object(), Object::Endpoint(_)) && c.badge() == DISK_BADGE
                    })
                })
        })
        .count()
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
    t.check(
        "the kernel found the two root ports' slots, empty",
        pharos_kernel::hotplug::slots() == [1, 2],
    );
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
    let count = |lines: &[(TaskId, Vec<u8>)], text: &str| {
        lines.iter().filter(|(_, l)| l == text.as_bytes()).count()
    };
    let mut summary = None;
    let mut audit = None;
    let mut running_audit = None;
    let mut driver_devices = Vec::new();
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
            }
        }
        // Once the first driver is ready: its manifest, and its device. The
        // runner removes it only after the marker below (review F2).
        if running_audit.is_none() && count(&lines, "init: disk ready") == 1 {
            running_audit = audit.as_ref().map(|a| a.check());
            driver_devices = driver_device_buses(init);
            kprintln!("hotplug test: audited the running driver");
        }
        if count(&lines, "init: disk stopped by the user") >= 1 && count(&lines, LAST) >= 1 {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    sched::sleep(Duration::from_millis(500));

    t.check(
        "init reported every boot service ready, the driver waiting: [8, 0, 0, 0]",
        summary.as_deref() == Some(&SUMMARY[..]),
    );
    // The same line from `init` twice is one entry here (the log keeps
    // distinct lines); the runner counts each add and remove in the trail.
    for (what, line) in [
        ("an arrival was given to init", ADDED),
        ("and its driver started", "init: disk started"),
        ("and became ready", "init: disk ready"),
        ("a removal was reported", REMOVED),
        (
            "the user stopped the driver",
            "init: disk stopped by the user",
        ),
    ] {
        t.check(&alloc::format!("{what}: {line}"), count(&lines, line) >= 1);
    }
    // Mounting needs the device's registers and buffers, so this shows each
    // driver held its device. (Sampling its capabilities is not reliable:
    // a driver lives tens of milliseconds, while this thread may not run.)
    t.check(
        "two driver processes and the boot one-shot mounted the image",
        lines
            .iter()
            .filter(|(_, l)| l.as_slice() == b"ok mounted")
            .count()
            >= 3,
    );
    if let Some((findings, report_lines)) = &running_audit {
        for line in report_lines.iter().chain(findings) {
            kprintln!("  audit: {line}");
        }
    }
    t.check(
        "the running driver held one device, behind the slot (bus 1), and no boot device",
        driver_devices == [1],
    );
    t.check(
        "while the driver ran, every service held exactly its manifest",
        running_audit
            .as_ref()
            .is_some_and(|(findings, _)| findings.is_empty()),
    );
    t.check(
        "afterwards no process holds a capability on a device behind a slot",
        slot_device_caps() == 0,
    );
    t.check(
        "no driver runs: each was stopped when its device left or by the user",
        drivers(init) == 0,
    );
    t.check(
        "and the kernel forgot the device",
        pci::devices().iter().all(|d| d.address.bus == 0),
    );
}
