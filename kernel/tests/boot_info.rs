//! Test kernel: the boot information Limine hands over is present and
//! plausible. Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_kernel::boot_info::summarize;
use pharos_kernel::testing::TestRun;

pharos_kernel::test_kernel!(run);

/// Start of the canonical higher half on x86-64 (4-level paging).
const HIGHER_HALF: u64 = 0xffff_8000_0000_0000;
/// Lowest address Limine loads the kernel at (`linker.ld`).
const KERNEL_BASE: usize = 0xffff_ffff_8000_0000;
/// Limine firmware type for 64-bit UEFI.
const FIRMWARE_UEFI64: u64 = 2;

fn run(t: &mut TestRun) {
    t.check(
        "bootloader accepted base revision",
        requests::BASE_REVISION_TAG.is_supported(),
    );

    let memmap = requests::MEMMAP.response();
    t.check("memory map present", memmap.is_some());
    if let Some(map) = memmap {
        let memory = summarize(map.entries().map(|e| (e.kind, e.length)));
        t.check("memory map has entries", memory.entries > 0);
        t.check("usable memory reported", memory.usable_bytes > 0);
        t.check("kernel image listed in memory map", memory.kernel_bytes > 0);
    }

    t.check(
        "HHDM offset in the higher half",
        requests::HHDM
            .response()
            .is_some_and(|hhdm| hhdm.offset >= HIGHER_HALF),
    );
    t.check(
        "bootloader reports itself as Limine",
        requests::BOOTLOADER_INFO
            .response()
            .and_then(|info| info.name())
            == Some("Limine"),
    );
    t.check(
        "firmware is 64-bit UEFI",
        requests::FIRMWARE_TYPE
            .response()
            .is_some_and(|fw| fw.firmware_type == FIRMWARE_UEFI64),
    );
    t.check(
        "test kernel runs at the linked higher-half address",
        run as *const () as usize >= KERNEL_BASE,
    );
}
