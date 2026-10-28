//! Test kernel: a driver process gets its device's interrupts only through
//! an `Interrupt` capability created from its `Device` capability (issue
//! #54). The `irqprobe` program routes MSI-X entry 0, reads a sector from
//! the virtio-blk disk, and wakes in `irq_wait` on the completion
//! interrupt; revoking the device revokes the interrupt, and deleting it
//! masks the entry and frees the vector. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt, pci as hw};
use pharos_kernel::cap::{CONFIG, Capability, GRANT, IRQ, MAP, Object, RECEIVE, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint, Message};
use pharos_kernel::pci::{self, Bar};
use pharos_kernel::syscall::MAX_MESSAGE;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, irq, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Steps `irqprobe` must report as passed.
const STEPS: [&str; 13] = [
    "no IRQ right: MISSING_RIGHT",
    "entry past the table: NOT_FOUND",
    "irq_create entry 0",
    "entry taken: IN_USE",
    "waiting on a device handle: MISSING_RIGHT",
    "virtio-blk set up",
    "irq_wait wakes on the completion interrupt",
    "read completed",
    "sector 0 starts with the filesystem magic",
    "revoking the device revokes the interrupt",
    "revoked interrupt: REVOKED",
    "delete the interrupt",
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
    // MSI-X table entry 0, which irqprobe routes.
    let entry0 = blk
        .msix
        .and_then(|m| match blk.bars.get(usize::from(m.table_bar)) {
            Some(Some(Bar::Memory { base, .. })) => Some(base + u64::from(m.table_offset)),
            _ => None,
        });
    t.check(
        "virtio-blk has an MSI-X table with 2 entries",
        entry0.is_some() && blk.msix.is_some_and(|m| m.table_size == 2),
    );
    let entry0 = entry0.unwrap_or(0);
    // Also maps the table page into the kernel (kept, with its page
    // tables), so the frame count below sees only what the driver uses.
    t.check("MSI-X entry 0 starts masked", hw::msix_entry_masked(entry0));
    let _ = sched::spawn(|| {});
    sched::sleep(Duration::from_millis(20));
    let before = free_frames();
    let start = irq::stats();
    t.check("no device vectors in use yet", start.in_use == 0);

    let device = DeviceHandle::grant(blk.clone());
    let wait = Endpoint::new();
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(device.clone()), MAP | CONFIG | IRQ | GRANT),
        Capability::new(Object::Endpoint(wait.clone()), RECEIVE),
        Capability::new(Object::Device(device.clone()), MAP | CONFIG),
    ];
    drop(device);
    let id = process::spawn_elf(&programs, b"bin/irqprobe", 0, caps);
    t.check("irqprobe started", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    sched::sleep(Duration::from_millis(200));

    let lines = output_of(id);
    for line in &lines {
        kprintln!("  irqprobe: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in &STEPS[..STEPS.len() - 1] {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    let now = irq::stats();
    t.check(
        "the interrupt woke the blocked thread",
        now.delivered > start.delivered && now.woken > start.woken,
    );
    t.check(
        "no spurious device-vector interrupts",
        now.spurious == start.spurious,
    );
    t.check(
        "deleted interrupt: vector freed and MSI-X entry masked",
        now.in_use == 0 && hw::msix_entry_masked(entry0),
    );

    ipc::send(
        &wait,
        Message {
            data: [0; MAX_MESSAGE],
            len: 1,
            cap: None,
        },
    );
    sched::sleep(Duration::from_millis(100));
    let lines = output_of(id);
    t.check(
        STEPS[STEPS.len() - 1],
        lines.iter().any(|l| l == b"ok released by the kernel"),
    );
    t.check(
        "irqprobe exited with no failures",
        process::exits().iter().any(|e| e.task == id && e.code == 0) && process::kills().is_empty(),
    );
    t.check(
        "after the driver ends: bus mastering off",
        hw::enabled_bits(blk.address) == (false, false),
    );
    t.check(
        "every frame returned (DMA page, mappings, process)",
        free_frames() == before,
    );
}
