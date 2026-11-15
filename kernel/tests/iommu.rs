//! Test kernel: VT-d translation on with nothing attached (#242,
//! iommu.md), through `iommu::init`, as the boot does. Booted with QEMU's
//! `intel-iommu` (every boot is). Checks the unit's capabilities, that
//! translation is on from an empty root table, that the invalidations
//! complete, and that no fault is recorded while nothing does DMA. #244
//! adds a device that tries. Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::acpi::{self, DirectMap};
use pharos_kernel::arch::x86_64::iommu::Unit;
use pharos_kernel::arch::x86_64::{gdt, idt, paging};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{iommu, kprintln, mm};

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
        "the root table is empty: no device reaches memory",
        on.is_some_and(|(_, root)| {
            (0..512).all(|i| paging::read_phys_u64(root + i * 8) == Some(0))
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
}
