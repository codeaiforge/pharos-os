//! Test kernel: the virtio-blk driver runs as a user process with only its
//! device and a console (issue #56). It reads the disk built by xtask,
//! mounts the `pharos-fs` image on it, and reports a file. A driver that
//! crashes with a request in flight is killed alone, and its device is
//! stopped and its memory freed; given the wrong device, the driver
//! refuses it. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt, pci as hw};
use pharos_kernel::cap::{CONFIG, Capability, IRQ, MAP, Object, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, irq, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

fn output_of(task: u64) -> Vec<Vec<u8>> {
    process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == task)
        .map(|(_, line)| line)
        .collect()
}

/// How a driver run ended.
enum End {
    Exited(u64),
    Killed(u64),
    Running,
}

/// Starts the driver on `device` with `arg` and waits up to 3 s for it to
/// end. Returns its task ID, how it ended, and its output.
fn run_driver(programs: &fs::Fs, device: Arc<pci::Device>, arg: u64) -> (u64, End, Vec<Vec<u8>>) {
    let Some(handle) = DeviceHandle::grant(device) else {
        return (u64::MAX, End::Running, Vec::new());
    };
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(handle), MAP | CONFIG | IRQ),
    ];
    let Ok(id) = process::spawn_elf(programs, b"bin/virtio-blk", arg, caps) else {
        return (u64::MAX, End::Running, Vec::new());
    };
    let mut end = End::Running;
    for _ in 0..60 {
        sched::sleep(Duration::from_millis(50));
        if let Some(e) = process::exits().iter().find(|e| e.task == id) {
            end = End::Exited(e.code);
            break;
        }
        if let Some(k) = process::kills().iter().find(|k| k.task == id) {
            end = End::Killed(k.vector);
            break;
        }
    }
    let lines = output_of(id);
    for line in &lines {
        kprintln!(
            "  driver {id}: {}",
            core::str::from_utf8(line).unwrap_or("?")
        );
    }
    (id, end, lines)
}

fn said(lines: &[Vec<u8>], text: &[u8]) -> bool {
    lines.iter().any(|l| l == text)
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
    let Some(blk) = devices
        .iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .cloned()
    else {
        t.check("virtio-blk found", false);
        return;
    };
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    // Map the MSI-X table page once (the kernel keeps it), so frame counts
    // below see only what drivers use.
    let table = blk
        .msix
        .and_then(|m| match blk.bars.get(usize::from(m.table_bar)) {
            Some(Some(pci::Bar::Memory { base, .. })) => Some(base + u64::from(m.table_offset)),
            _ => None,
        });
    t.check(
        "MSI-X entry 0 starts masked",
        table.is_some_and(hw::msix_entry_masked),
    );
    let _ = sched::spawn(|| {});
    sched::sleep(Duration::from_millis(20));
    let before = free_frames();

    // 1. The driver serves the disk.
    let (_, end, lines) = run_driver(&programs, blk.clone(), 0);
    t.check("driver exited with code 0", matches!(end, End::Exited(0)));
    t.check(
        "known blocks: sector 0 holds the image header",
        said(&lines, b"ok sector 0"),
    );
    t.check(
        "the pharos-fs image on the disk mounts in the driver",
        said(&lines, b"ok mounted"),
    );
    t.check(
        "the driver reports hello.txt from the disk",
        said(&lines, b"Hello from the Pharos filesystem."),
    );
    t.check(
        "a file spread over several sectors reads back exactly",
        said(&lines, b"ok dir/big.bin"),
    );
    let stats = irq::stats();
    t.check(
        "reads completed on interrupts, none spurious",
        stats.delivered > 0 && stats.spurious == 0,
    );
    let stopped = |t: &mut TestRun, when: &str| {
        t.check(
            &alloc::format!("{when}: bus mastering and decoding off"),
            hw::enabled_bits(blk.address) == (false, false),
        );
        t.check(
            &alloc::format!("{when}: vector freed"),
            irq::stats().in_use == 0,
        );
        // With decoding off the table reads as 0; turn it on to look.
        hw::set_enabled(blk.address, true);
        let masked = table.is_some_and(hw::msix_entry_masked);
        hw::set_enabled(blk.address, false);
        t.check(&alloc::format!("{when}: MSI-X entry masked"), masked);
        t.check(
            &alloc::format!("{when}: every frame returned"),
            free_frames() == before,
        );
    };
    stopped(t, "after the driver exits");

    // 2. The driver crashes with a read in flight.
    let (_, end, _) = run_driver(&programs, blk.clone(), 1);
    t.check(
        "a crashing driver is killed (page fault), the kernel keeps running",
        matches!(end, End::Killed(14)),
    );
    stopped(t, "after the driver is killed");

    // 3. The wrong device: anything but virtio or a bridge.
    let other = devices
        .iter()
        .find(|d| d.vendor != 0x1af4 && d.class[0] != 0x06)
        .cloned();
    t.check("a non-virtio device exists", other.is_some());
    if let Some(other) = other {
        let (_, end, lines) = run_driver(&programs, other, 0);
        t.check(
            "given the wrong device, the driver refuses it (code 1)",
            matches!(end, End::Exited(1)) && said(&lines, b"not a virtio-blk device"),
        );
    }
    t.check(
        "after all three runs: every frame returned",
        free_frames() == before,
    );
}
