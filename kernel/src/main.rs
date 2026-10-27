//! Pharos OS kernel entry point (M2.2).
//!
//! Limine loads this binary at `0xffffffff80000000` and jumps to [`kmain`] in
//! 64-bit mode (see `docs/architecture/boot.md`). The kernel reports what the
//! bootloader handed over on COM1, signals the result to QEMU (only when
//! running under a hypervisor), then halts.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use pharos_kernel::arch::x86_64::{_print_panic, QemuExit, gdt, halt, qemu_exit};
use pharos_kernel::boot_info::{firmware_name, mib, summarize};
use pharos_kernel::kprintln;
use pharos_kernel::limine::BASE_REVISION;

pharos_kernel::limine_requests!();

/// Entry point named in `linker.ld`.
#[allow(unsafe_code)] // `no_mangle` exports the symbol; the function is safe Rust.
#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
    gdt::init();
    kprintln!("Pharos OS {} kernel", env!("CARGO_PKG_VERSION"));

    if !requests::BASE_REVISION_TAG.is_supported() {
        fail(format_args!(
            "bootloader did not accept Limine base revision {BASE_REVISION}"
        ));
    }

    let Some(memmap) = requests::MEMMAP.response() else {
        fail(format_args!("no memory map from the bootloader"));
    };
    let Some(hhdm) = requests::HHDM.response() else {
        fail(format_args!(
            "no higher-half direct map from the bootloader"
        ));
    };

    if let Some(info) = requests::BOOTLOADER_INFO.response() {
        kprintln!(
            "  bootloader: {} {}",
            info.name().unwrap_or("?"),
            info.version().unwrap_or("?")
        );
    }
    if let Some(firmware) = requests::FIRMWARE_TYPE.response() {
        kprintln!("  firmware:   {}", firmware_name(firmware.firmware_type));
    }
    let entry = kmain as *const () as usize;
    kprintln!("  entry:      {entry:#x}");
    kprintln!("  HHDM:       {:#x}", hhdm.offset);

    let memory = summarize(memmap.entries().map(|e| (e.kind, e.length)));
    kprintln!(
        "  memory:     {} entries; {} MiB usable in {} regions; {} MiB bootloader-reclaimable",
        memory.entries,
        mib(memory.usable_bytes),
        memory.usable_regions,
        mib(memory.reclaimable_bytes)
    );

    kprintln!("PHAROS: boot ok");
    qemu_exit(QemuExit::Success);
    halt()
}

/// Reports a fatal boot error and halts.
fn fail(message: core::fmt::Arguments<'_>) -> ! {
    kprintln!("PHAROS: boot failed: {message}");
    qemu_exit(QemuExit::Failure);
    halt()
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    _print_panic(format_args!("PHAROS: panic: {info}\n"));
    qemu_exit(QemuExit::Failure);
    halt()
}
