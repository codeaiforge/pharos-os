//! Test kernel: DMA isolation with VT-d (iommu.md). Booted with QEMU's
//! `intel-iommu` (every boot is). First (#242): through `iommu::init`, as
//! the boot does, the unit's capabilities, translation on with every
//! device blocked, the invalidations, and no fault while nothing does DMA.
//! Then the attack (#244): `dmaprobe`, a driver holding the virtio-blk
//! disk, asks its device to read sector 0 into a kernel canary frame. The
//! canary must be unchanged, the unit must record the blocked write for
//! that device and page, the driver's read into its own buffer must still
//! work, and once it has ended its buffers must be unmapped. Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::acpi::{self, DirectMap};
use pharos_kernel::arch::x86_64::iommu::Unit;
use pharos_kernel::arch::x86_64::{apic, gdt, idt, paging};
use pharos_kernel::cap::{CONFIG, Capability, IRQ, MAP, Object, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, iommu, kprintln, mm, pci, process, sched, storage, time};

/// The canary's byte; sector 0 begins `PHAROSFS`.
const CANARY: u8 = 0xa5;

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let hhdm = requests::HHDM.response();
    let ready = testing::init_memory(
        hhdm,
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    ) && mm::init_heap().is_ok();
    t.check("memory and heap set up", ready);
    let (true, Some(hhdm)) = (ready, hhdm) else {
        return;
    };
    let dmar = requests::RSDP
        .response()
        .and_then(|r| r.address.checked_sub(hhdm.offset))
        .and_then(|rsdp| acpi::find(&DirectMap, rsdp, b"DMAR").ok().flatten())
        .and_then(|table| acpi::parse_dmar(&table).ok());
    t.check("a DMAR table", dmar.is_some());
    let Some(dmar) = dmar else {
        return;
    };

    let unit = Unit::new(dmar.units[0].base);
    if let Ok(u) = &unit {
        kprintln!("  CAP {:#018x} ECAP {:#018x}", u.cap(), u.ecap());
    }
    t.check(
        "translation off at handoff (Limine turns it off)",
        unit.as_ref().is_ok_and(|u| !u.translating()),
    );

    let caps = iommu::init(&dmar);
    kprintln!("  {caps:?}");
    t.check(
        "iommu::init: 3-level tables, 65536 domains, faults recorded",
        caps.as_ref()
            .is_ok_and(|c| c.levels == 3 && c.domains == 65536 && c.fault_registers >= 1),
    );
    let on = iommu::translating();
    t.check(
        "every unit translates, from the kernel's root table",
        on.is_some_and(|(on, _)| on),
    );
    t.check(
        "no context entry present: no device reaches memory",
        on.is_some_and(|(_, root)| {
            let bus0 = paging::read_phys_u64(root).unwrap_or(0);
            (1..512).all(|i| paging::read_phys_u64(root + i * 8) == Some(0))
                && bus0 & 1 == 1
                && (0..512).all(|i| paging::read_phys_u64((bus0 & !0xfff) + i * 8) == Some(0))
        }),
    );
    t.check(
        "a second init is refused",
        matches!(iommu::init(&dmar), Err(iommu::InitError::AlreadyStarted)),
    );
    t.check(
        "the invalidations complete",
        unit.as_ref()
            .is_ok_and(|u| u.invalidate_context().is_ok() && u.invalidate_iotlb().is_ok()),
    );
    let faults = iommu::take_faults();
    kprintln!("  faults: {faults:?}");
    t.check("no fault recorded", faults.is_empty());

    attack(t, hhdm.offset);
}

/// The DMA attack (#244).
fn attack(t: &mut TestRun, hhdm: u64) {
    storage::record_modules(requests::MODULES.response(), hhdm);
    let ready = apic::init(hhdm).is_ok() && time::init().is_ok() && sched::init().is_ok();
    t.check("APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    process::init();
    t.check("preemption enabled", sched::enable_preemption().is_ok());
    pci::enumerate();
    let blk = pci::devices()
        .iter()
        .find(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .cloned();
    let (Some(blk), Ok(programs)) = (blk, fs::mount("programs")) else {
        t.check("virtio-blk found and programs mounted", false);
        return;
    };
    let canary = mm::frames().as_mut().and_then(|f| f.alloc().ok());
    let Some(canary) = canary.filter(|&f| paging::fill_frame_for_test(f, CANARY)) else {
        t.check("a canary frame", false);
        return;
    };
    let canary_intact = || {
        (0..512).all(|i| {
            paging::read_phys_u64(canary.addr() + i * 8) == Some(u64::from_ne_bytes([CANARY; 8]))
        })
    };

    let Some(handle) = DeviceHandle::grant(blk.clone()) else {
        t.check("the disk is granted", false);
        return;
    };
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(handle), MAP | CONFIG | IRQ),
    ];
    let id = process::spawn_elf(&programs, b"bin/dmaprobe", canary.addr(), caps);
    t.check("dmaprobe started", id.is_ok());
    let Ok(id) = id else {
        return;
    };
    let mut code = None;
    for _ in 0..100 {
        sched::sleep(Duration::from_millis(50));
        if let Some(e) = process::exits().iter().find(|e| e.task == id) {
            code = Some(e.code);
            break;
        }
    }
    let lines: Vec<_> = process::debug_output()
        .into_iter()
        .filter(|(task, _)| *task == id)
        .map(|(_, line)| line)
        .collect();
    for line in &lines {
        kprintln!("  dmaprobe: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    let said = |text: &[u8]| lines.iter().any(|l| l == text);
    t.check("dmaprobe submitted the attack", said(b"attack submitted"));
    t.check("the canary is unchanged", canary_intact());
    let faults = iommu::take_faults();
    kprintln!("  faults: {faults:?}");
    let a = blk.address;
    t.check(
        "a blocked write recorded for the disk and the canary's page",
        faults.iter().any(|f| {
            f.source == iommu::requester(a.bus, a.device, a.function)
                && f.page == canary.addr()
                && f.write
        }),
    );
    t.check(
        "the driver's own read still worked",
        said(b"ok own read") && code == Some(0),
    );
    // Its buffers, once it has ended: unmapped, so a stale descriptor
    // reaches nothing.
    let buffers: Vec<u64> = lines
        .iter()
        .filter_map(|l| l.strip_prefix(b"dma "))
        .filter_map(|h| u64::from_str_radix(core::str::from_utf8(h).ok()?, 16).ok())
        .collect();
    t.check(
        "after it ends: both of its buffers unmapped from the disk's domain",
        buffers.len() == 2
            && buffers
                .iter()
                .all(|&b| (0..2).all(|p| iommu::translate(a, b + p * 4096).is_none())),
    );
}
