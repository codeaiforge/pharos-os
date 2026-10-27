//! Pharos OS kernel entry point (M2.2).
//!
//! Limine loads this binary at `0xffffffff80000000` and jumps to [`kmain`] in
//! 64-bit mode (see `docs/architecture/boot.md`). The kernel reports what the
//! bootloader handed over on COM1, signals the result to QEMU (only when
//! running under a hypervisor), then halts.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use pharos_kernel::arch::x86_64::{_print_panic, QemuExit, halt, qemu_exit};
use pharos_kernel::boot_info::{firmware_name, mib, summarize};
use pharos_kernel::kprintln;
use pharos_kernel::limine::BASE_REVISION;

/// Limine requests, placed between the start and end markers in the
/// `.limine_requests*` sections (kept by `linker.ld`).
///
/// This module uses only `unsafe` *attributes* (`link_section`), which choose
/// where data is placed; it contains no unsafe code.
#[allow(unsafe_code)]
mod requests {
    use pharos_kernel::limine::{
        BaseRevisionTag, BootloaderInfoResponse, FirmwareTypeResponse, HhdmResponse,
        MemmapResponse, REQUESTS_END_MARKER, REQUESTS_START_MARKER, Request,
        bootloader_info_request, firmware_type_request, hhdm_request, memmap_request,
    };

    #[used]
    #[unsafe(link_section = ".limine_requests_start")]
    static START: [u64; 4] = REQUESTS_START_MARKER;

    #[used]
    #[unsafe(link_section = ".limine_requests")]
    pub static BASE_REVISION_TAG: BaseRevisionTag = BaseRevisionTag::new();

    #[used]
    #[unsafe(link_section = ".limine_requests")]
    pub static BOOTLOADER_INFO: Request<BootloaderInfoResponse> = bootloader_info_request();

    #[used]
    #[unsafe(link_section = ".limine_requests")]
    pub static FIRMWARE_TYPE: Request<FirmwareTypeResponse> = firmware_type_request();

    #[used]
    #[unsafe(link_section = ".limine_requests")]
    pub static HHDM: Request<HhdmResponse> = hhdm_request();

    #[used]
    #[unsafe(link_section = ".limine_requests")]
    pub static MEMMAP: Request<MemmapResponse> = memmap_request();

    #[used]
    #[unsafe(link_section = ".limine_requests_end")]
    static END: [u64; 2] = REQUESTS_END_MARKER;
}

/// Entry point named in `linker.ld`.
#[allow(unsafe_code)] // `no_mangle` exports the symbol; the function is safe Rust.
#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
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
