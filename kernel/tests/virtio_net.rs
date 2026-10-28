//! Test kernel: the virtio-net driver runs as a user process with only its
//! device, a console, and a send-only endpoint (issue #62). `netprobe` binds the interrupt to an
//! endpoint (`irq_notify`), reads the MAC, resolves the slirp gateway with
//! ARP, and pings it. A driver that crashes right after sending is killed
//! alone, with its device stopped and its memory freed. Runs under UEFI
//! (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt, pci as hw};
use pharos_kernel::cap::{CONFIG, Capability, IRQ, MAP, Object, SEND, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, irq, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Steps `netprobe` must report as passed.
const STEPS: [&str; 9] = [
    "irq_notify needs RECEIVE: MISSING_RIGHT",
    "irq_notify binds the interrupt",
    "a bound interrupt: irq_wait IN_USE",
    "bound once: IN_USE",
    "virtio-net set up",
    "send an ARP request",
    "ARP reply from the gateway 10.0.2.2",
    "send a ping to the gateway",
    "ping reply from the gateway",
];

/// How a driver run ended.
enum End {
    Exited(u64),
    Killed(u64),
    Running,
}

/// Starts `netprobe` on `device` with `arg` and waits up to 3 s for it to
/// end. Returns how it ended and its output.
fn run_probe(programs: &fs::Fs, device: Arc<pci::Device>, arg: u64) -> (End, Vec<Vec<u8>>) {
    let Some(handle) = DeviceHandle::grant(device) else {
        return (End::Running, Vec::new());
    };
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(handle), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(Endpoint::new()), SEND),
    ];
    let Ok(id) = process::spawn_elf(programs, b"bin/netprobe", arg, caps) else {
        return (End::Running, Vec::new());
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
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, line)| line)
        .collect();
    for line in &lines {
        kprintln!("  netprobe: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    (end, lines)
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
    let Some(nic) = pci::devices()
        .into_iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1041))
    else {
        t.check("virtio-net found", false);
        return;
    };
    t.check("virtio-net found, with MSI-X", nic.msix.is_some());
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    // Map the MSI-X table page once (the kernel keeps it), so frame counts
    // below see only what the driver uses.
    let table = nic
        .msix
        .and_then(|m| match nic.bars.get(usize::from(m.table_bar)) {
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

    let (end, lines) = run_probe(&programs, nic.clone(), 0);
    for step in STEPS {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "the MAC is QEMU's default, 52:54:00:12:34:56",
        lines.iter().any(|l| l == b"mac 52:54:00:12:34:56"),
    );
    t.check(
        "netprobe exited with no failures",
        matches!(end, End::Exited(0)),
    );
    t.check(
        "the interrupts arrived as notifications, none spurious",
        irq::stats().delivered > 0 && irq::stats().spurious == 0,
    );
    let stopped = |t: &mut TestRun, when: &str| {
        t.check(
            &alloc::format!("{when}: bus mastering and decoding off, vector freed"),
            hw::enabled_bits(nic.address) == (false, false) && irq::stats().in_use == 0,
        );
        hw::set_enabled(nic.address, true);
        let masked = table.is_some_and(hw::msix_entry_masked);
        hw::set_enabled(nic.address, false);
        t.check(&alloc::format!("{when}: MSI-X entry masked"), masked);
        t.check(
            &alloc::format!("{when}: every frame returned"),
            free_frames() == before,
        );
    };
    stopped(t, "after the driver exits");

    let (end, _) = run_probe(&programs, nic.clone(), 1);
    t.check(
        "a driver crashing with a frame in flight is killed (page fault)",
        matches!(end, End::Killed(14)),
    );
    stopped(t, "after the driver is killed");
}
