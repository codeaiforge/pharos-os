//! Test kernel: the ACPI walk and the DMAR parser on QEMU's own tables
//! (#241, iommu.md). Booted with `-device intel-iommu,intremap=off`, so
//! the tables hold a DMAR: one unit at 0xfed9_0000 with 39-bit addresses
//! (QEMU's defaults). QEMU 8.2 does not set INCLUDE_PCI_ALL; it names each
//! function on bus 0 in a device scope, so the check is that every function
//! the kernel enumerates there is named. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use pharos_kernel::acpi::{self, DirectMap, INCLUDE_PCI_ALL};
use pharos_kernel::arch::x86_64::{gdt, idt};
use pharos_kernel::pci;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm};

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

    let rsdp = requests::RSDP
        .response()
        .and_then(|r| r.address.checked_sub(hhdm.offset));
    t.check("the bootloader gave the RSDP", rsdp.is_some());
    let Some(rsdp) = rsdp else {
        return;
    };
    let tables = acpi::tables(&DirectMap, rsdp);
    if let Ok(tables) = &tables {
        for e in tables {
            kprintln!(
                "  {} at {:#x}",
                core::str::from_utf8(&e.signature).unwrap_or("????"),
                e.phys
            );
        }
    }
    t.check(
        "the root table lists QEMU's tables, every one checked",
        tables.as_ref().is_ok_and(|ts| {
            ts.iter().any(|e| &e.signature == b"FACP")
                && ts.iter().any(|e| &e.signature == b"APIC")
                && ts.iter().all(|e| acpi::table(&DirectMap, e.phys).is_ok())
        }),
    );

    let dmar = acpi::find(&DirectMap, rsdp, b"DMAR");
    t.check(
        "a DMAR table, checksum verified",
        matches!(dmar, Ok(Some(_))),
    );
    let Ok(Some(dmar)) = dmar else {
        return;
    };
    let dmar = acpi::parse_dmar(&dmar);
    kprintln!("  {dmar:?}");
    t.check(
        "DMAR: 39-bit addresses, no reserved regions",
        dmar.as_ref()
            .is_ok_and(|d| d.address_width == 39 && d.reserved_regions == 0),
    );
    t.check(
        "one unit at 0xfed9_0000 on segment 0",
        dmar.as_ref().is_ok_and(|d| {
            d.units.len() == 1 && d.units[0].base == 0xfed9_0000 && d.units[0].segment == 0
        }),
    );
    pci::enumerate();
    let unnamed: alloc::vec::Vec<_> = pci::devices()
        .iter()
        .map(|d| d.address)
        .filter(|a| a.bus == 0)
        .filter(|a| {
            !dmar.as_ref().is_ok_and(|d| {
                d.units.iter().any(|u| {
                    u.flags & INCLUDE_PCI_ALL != 0
                        || u.scopes.iter().any(|s| {
                            s.start_bus == 0 && s.path.first() == Some(&(a.device, a.function))
                        })
                })
            })
        })
        .collect();
    kprintln!("  bus-0 functions no unit names: {unnamed:?}");
    t.check(
        "every function on bus 0 is in a unit's device scope",
        unnamed.is_empty(),
    );
}
