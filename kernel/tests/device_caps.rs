//! Test kernel: a driver process reaches its device only through a Device
//! capability: configuration reads, MMIO mappings of its own BARs (never the
//! MSI-X table), and DMA buffers whose frames outlive every mapping and are
//! freed only after bus mastering is off (issue #55). The `devprobe`
//! program does the user side. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt, paging, pci as hw};
use pharos_kernel::cap::{CONFIG, Capability, GRANT, MAP, Object, RECEIVE, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::pci::{self, CAP_VENDOR};
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Steps `devprobe` must report as passed.
const STEPS: [&str; 21] = [
    "config_read vendor and device",
    "config_read a byte",
    "mmio_map the common configuration",
    "one queue",
    "status reset",
    "status write reaches the device",
    "mapping the same address again: IN_USE",
    "BAR 6: NOT_FOUND",
    "past the BAR: BAD_ADDRESS",
    "MSI-X table page: BAD_ADDRESS",
    "no MAP right: MISSING_RIGHT",
    "no CONFIG right: MISSING_RIGHT",
    "256 register pages in all, then NO_MEMORY",
    "dma_alloc 2 pages",
    "DMA buffer starts zeroed",
    "17 pages: TOO_LARGE",
    "DMA over an existing mapping: IN_USE",
    "50 DMA pages in all",
    "past 64 pages: NO_MEMORY",
    "delete both device handles",
    "released by the kernel",
];

fn output_of(task: u64) -> Vec<Vec<u8>> {
    process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == task)
        .map(|(_, line)| line)
        .collect()
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
    let Some(blk) = pci::devices()
        .into_iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
    else {
        t.check("virtio-blk found", false);
        return;
    };
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    // The virtio common configuration: vendor capability with cfg_type 1.
    let common = blk.capabilities.iter().find_map(|c| {
        let header = hw::read32(blk.address, c.offset);
        let cfg_type = (header >> 24) as u8;
        (c.id == CAP_VENDOR && cfg_type == 1).then(|| {
            let bar = hw::read32(blk.address, c.offset + 4) as u8;
            let offset = hw::read32(blk.address, c.offset + 8);
            u64::from(bar) | u64::from(offset) << 8
        })
    });
    t.check("virtio common configuration located", common.is_some());
    let _ = sched::spawn(|| {});
    sched::sleep(Duration::from_millis(20));
    let before = free_frames();
    // Firmware may leave the device enabled; granting sets a known state.

    let Some(device) = DeviceHandle::grant(blk.clone()) else {
        t.check("virtio-blk granted", false);
        return;
    };
    t.check(
        "a granted device cannot be granted again",
        DeviceHandle::grant(blk.clone()).is_none(),
    );
    t.check(
        "granting turns on memory decoding and bus mastering",
        hw::enabled_bits(blk.address) == (true, true),
    );
    let wait = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(device.clone()), MAP | CONFIG),
        Capability::new(Object::Endpoint(wait.clone()), RECEIVE),
        Capability::new(Object::Device(device.clone()), GRANT),
    ];
    let id = process::spawn_elf(&programs, b"bin/devprobe", common.unwrap_or(0), caps);
    t.check("devprobe started", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    sched::sleep(Duration::from_millis(150));

    let lines = output_of(id);
    for line in &lines {
        kprintln!("  devprobe: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in &STEPS[..STEPS.len() - 1] {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    let phys = lines
        .iter()
        .find_map(|l| l.strip_prefix(b"dma "))
        .and_then(|hex| core::str::from_utf8(hex).ok())
        .and_then(|hex| u64::from_str_radix(hex, 16).ok());
    t.check(
        "the reported physical address holds what the process wrote, on both pages",
        phys.is_some_and(|p| {
            paging::read_phys_u64(p) == Some(0x1122_3344_5566_7788)
                && paging::read_phys_u64(p + 4096) == Some(0x99aa_bbcc_ddee_ff00)
        }),
    );
    t.check("the device holds 50 DMA pages", device.dma_pages() == 50);

    // The kernel lets go of its reference; the process deleted both of its
    // handles, but its DMA mappings pin the device.
    drop(device);
    t.check(
        "pinned by the process: still enabled after every handle is gone",
        hw::enabled_bits(blk.address) == (true, true),
    );

    // Release the process; when it ends, the device stops, then its
    // buffers are freed.
    ipc::send(
        &wait,
        Message {
            data: [0; MAX_MESSAGE],
            len: 1,
            cap: None,
            badge: 0,
        },
    );
    sched::sleep(Duration::from_millis(100));
    let lines = output_of(id);
    t.check(
        STEPS[STEPS.len() - 1],
        lines.iter().any(|l| l == b"ok released by the kernel"),
    );
    t.check(
        "devprobe exited with no failures",
        process::exits().iter().any(|e| e.task == id && e.code == 0) && process::kills().is_empty(),
    );
    t.check(
        "after the driver ends: memory decoding and bus mastering off",
        hw::enabled_bits(blk.address) == (false, false),
    );
    let msix_masked = blk.msix.is_some_and(|m| {
        let control = hw::read32(blk.address, m.offset) >> 16;
        control & (1 << 14) != 0 && control & (1 << 15) == 0
    });
    t.check(
        "after the driver ends: MSI-X disabled and masked",
        msix_masked,
    );
    t.check(
        "every frame returned (DMA buffers, mappings, process)",
        free_frames() == before,
    );

    // A register mapping alone pins the device too (security review F2).
    let Some(device) = DeviceHandle::grant(blk.clone()) else {
        t.check("granted again once the driver is gone", false);
        return;
    };
    t.check("granted again once the driver is gone", true);
    let wait = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(device.clone()), MAP | CONFIG),
        Capability::new(Object::Endpoint(wait.clone()), RECEIVE),
        Capability::new(Object::Device(device), GRANT),
    ];
    let arg = common.unwrap_or(0) | 1 << 63;
    let id = process::spawn_elf(&programs, b"bin/devprobe", arg, caps).unwrap_or(u64::MAX);
    sched::sleep(Duration::from_millis(100));
    let lines = output_of(id);
    t.check(
        "registers mapped, then both handles deleted",
        lines.iter().any(|l| l == b"ok mmio_map only")
            && lines.iter().any(|l| l == b"ok delete both device handles"),
    );
    t.check(
        "pinned by the register mapping: still enabled, cannot be granted",
        hw::enabled_bits(blk.address) == (true, true) && DeviceHandle::grant(blk.clone()).is_none(),
    );
    ipc::send(
        &wait,
        Message {
            data: [0; MAX_MESSAGE],
            len: 1,
            cap: None,
            badge: 0,
        },
    );
    sched::sleep(Duration::from_millis(100));
    t.check(
        "after it ends: stopped, and every frame returned",
        process::exits().iter().any(|e| e.task == id && e.code == 0)
            && hw::enabled_bits(blk.address) == (false, false)
            && free_frames() == before,
    );
}
