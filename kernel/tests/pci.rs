//! Test kernel: PCI enumeration finds QEMU's host bridge and the virtio-blk
//! disk that `cargo xtask` attaches, with the expected IDs, BARs, and MSI-X
//! capability (issue #53). Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::arch::x86_64::{gdt, idt};
use pharos_kernel::pci::{self, Bar, CAP_MSIX, CAP_VENDOR};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm};

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let ready = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    ) && mm::init_heap().is_ok();
    t.check("memory and heap set up", ready);
    if !ready {
        return;
    }

    let count = pci::enumerate();
    let devices = pci::devices();
    for d in &devices {
        kprintln!(
            "  {:02x}:{:02x}.{} {:04x}:{:04x} {} bars {:?} caps {:?} msix {:?}",
            d.address.bus,
            d.address.device,
            d.address.function,
            d.vendor,
            d.device,
            d.name(),
            d.bars,
            d.capabilities,
            d.msix
        );
    }
    t.check(
        "functions found and recorded",
        count >= 2 && devices.len() == count,
    );
    t.check(
        "no capability list was malformed",
        devices.iter().all(|d| d.capability_error.is_none()),
    );
    t.check(
        "host bridge at 00:00.0 (Intel Q35, class 06.00)",
        devices.iter().any(|d| {
            d.address.bus == 0
                && d.address.device == 0
                && d.address.function == 0
                && (d.vendor, d.device, d.class[0], d.class[1]) == (0x8086, 0x29c0, 0x06, 0x00)
        }),
    );
    t.check(
        "exactly one network card: modern virtio-net (1af4:1041, class 02.00)",
        devices
            .iter()
            .filter(|d| d.class[0] == 0x02)
            .map(|d| (d.vendor, d.device, d.class[1]))
            .eq([(0x1af4, 0x1041, 0x00)]),
    );

    let blk = devices
        .iter()
        .find(|d| (d.vendor, d.device, d.class[0], d.class[1]) == (0x1af4, 0x1042, 0x01, 0x00));
    let Some(blk) = blk else {
        t.check("virtio-blk found (1af4:1042, class 01.00)", false);
        return;
    };
    t.check("virtio-blk found (1af4:1042, class 01.00)", true);
    let memory_bars: usize = blk
        .bars
        .iter()
        .flatten()
        .filter(|b| matches!(b, Bar::Memory { size, base, .. } if *size >= 4096 && size.is_power_of_two() && base % size == 0))
        .count();
    t.check(
        "virtio-blk: memory BARs, power-of-two sized and aligned",
        memory_bars >= 2,
    );
    t.check(
        "virtio-blk: a 64-bit BAR for the virtio registers",
        blk.bars
            .iter()
            .flatten()
            .any(|b| matches!(b, Bar::Memory { wide: true, .. })),
    );
    t.check(
        "virtio-blk: at least four virtio (vendor-specific) capabilities",
        blk.capabilities
            .iter()
            .filter(|c| c.id == CAP_VENDOR)
            .count()
            >= 4,
    );
    let msix_listed = blk.capabilities.iter().any(|c| c.id == CAP_MSIX);
    let msix_fits = blk.msix.is_some_and(|m| {
        let in_bar = |bar: u8, offset: u32, len: u64| {
            matches!(blk.bars.get(bar as usize), Some(Some(Bar::Memory { size, .. })) if u64::from(offset) + len <= *size)
        };
        m.table_size >= 2
            && in_bar(m.table_bar, m.table_offset, u64::from(m.table_size) * 16)
            && in_bar(m.pba_bar, m.pba_offset, u64::from(m.table_size).div_ceil(64) * 8)
    });
    t.check(
        "virtio-blk: MSI-X listed, table and PBA inside a memory BAR",
        msix_listed && msix_fits,
    );
    t.check(
        "enumerating again finds the same devices (probing restored the BARs)",
        pci::enumerate() == count
            && pci::devices()
                .iter()
                .map(|d| &**d)
                .eq(devices.iter().map(|d| &**d)),
    );
}
