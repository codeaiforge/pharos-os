//! Pharos OS kernel entry point (M2.2).
//!
//! Limine loads this binary at `0xffffffff80000000` and jumps to [`kmain`] in
//! 64-bit mode (see `docs/architecture/boot.md`). The kernel reports what the
//! bootloader handed over on COM1, signals the result to QEMU (only when
//! running under a hypervisor), then halts.

#![no_std]
#![no_main]

use core::fmt::Write;
use core::panic::PanicInfo;

use pharos_kernel::arch::x86_64::{QemuExit, Serial, halt, qemu_exit};
use pharos_kernel::boot_info::{firmware_name, mib, summarize};
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
    let mut serial = Serial::com1();
    // Serial writes cannot fail; results are ignored throughout.
    let _ = writeln!(serial, "Pharos OS {} kernel", env!("CARGO_PKG_VERSION"));

    if !requests::BASE_REVISION_TAG.is_supported() {
        fail(
            &mut serial,
            format_args!("bootloader did not accept Limine base revision {BASE_REVISION}"),
        );
    }

    let Some(memmap) = requests::MEMMAP.response() else {
        fail(
            &mut serial,
            format_args!("no memory map from the bootloader"),
        );
    };
    let Some(hhdm) = requests::HHDM.response() else {
        fail(
            &mut serial,
            format_args!("no higher-half direct map from the bootloader"),
        );
    };

    if let Some(info) = requests::BOOTLOADER_INFO.response() {
        let _ = writeln!(
            serial,
            "  bootloader: {} {}",
            info.name().unwrap_or("?"),
            info.version().unwrap_or("?")
        );
    }
    if let Some(firmware) = requests::FIRMWARE_TYPE.response() {
        let _ = writeln!(
            serial,
            "  firmware:   {}",
            firmware_name(firmware.firmware_type)
        );
    }
    let entry = kmain as *const () as usize;
    let _ = writeln!(serial, "  entry:      {entry:#x}");
    let _ = writeln!(serial, "  HHDM:       {:#x}", hhdm.offset);

    let memory = summarize(memmap.entries().map(|e| (e.kind, e.length)));
    let _ = writeln!(
        serial,
        "  memory:     {} entries; {} MiB usable in {} regions; {} MiB bootloader-reclaimable",
        memory.entries,
        mib(memory.usable_bytes),
        memory.usable_regions,
        mib(memory.reclaimable_bytes)
    );

    let _ = writeln!(serial, "PHAROS: boot ok");
    qemu_exit(QemuExit::Success);
    halt()
}

/// Reports a fatal boot error and halts.
fn fail(serial: &mut Serial, message: core::fmt::Arguments<'_>) -> ! {
    let _ = writeln!(serial, "PHAROS: boot failed: {message}");
    qemu_exit(QemuExit::Failure);
    halt()
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let mut serial = Serial::com1();
    let _ = writeln!(serial, "PHAROS: panic: {info}");
    qemu_exit(QemuExit::Failure);
    halt()
}
