//! Pharos OS kernel entry point.
//!
//! Limine loads this binary at `0xffffffff80000000` and jumps to [`kmain`] in
//! 64-bit mode (see `docs/architecture/boot.md`). The kernel reports what the
//! bootloader handed over on COM1, signals the result to QEMU (only when
//! running under a hypervisor), then halts.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use pharos_kernel::arch::x86_64::{
    _print_panic, QemuExit, apic, gdt, halt, idt, paging, qemu_exit, run_on_kernel_stack,
};
use pharos_kernel::boot_info::{firmware_name, mib, summarize};
use pharos_kernel::kprintln;
use pharos_kernel::limine::BASE_REVISION;
use pharos_kernel::mm;

pharos_kernel::limine_requests!();

/// Entry point named in `linker.ld`.
#[allow(unsafe_code)] // `no_mangle` exports the symbol; the function is safe Rust.
#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
    run_on_kernel_stack(kernel_main)
}

/// The kernel proper, on the kernel stack (with its guard page).
extern "C" fn kernel_main() -> ! {
    gdt::init();
    idt::init();
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

    match mm::init_frames(
        hhdm.offset,
        memmap.entries().map(|e| (e.base, e.length, e.kind)),
    ) {
        Ok(stats) => kprintln!(
            "  frames:     {} free of {} ({} MiB free)",
            stats.free,
            stats.total,
            mib(stats.free as u64 * mm::frame::FRAME_SIZE)
        ),
        Err(error) => fail(format_args!("frame allocator setup failed: {error}")),
    }

    let Some(image) = requests::EXECUTABLE_ADDRESS.response() else {
        fail(format_args!("no executable address from the bootloader"));
    };
    let image = paging::KernelImage {
        physical_base: image.physical_base,
        virtual_base: image.virtual_base,
    };
    match mm::init_paging(
        hhdm.offset,
        memmap.entries().map(|e| (e.base, e.length, e.kind)),
        image,
    ) {
        Ok(tables) => kprintln!("  paging:     kernel page tables active ({tables} table frames)"),
        Err(error) => fail(format_args!("paging setup failed: {error}")),
    }

    if let Err(error) = apic::init(hhdm.offset) {
        fail(format_args!("local APIC setup failed: {error}"));
    }
    kprintln!(
        "  local APIC: id {}, version {:#x}",
        apic::id(),
        apic::version() & 0xff
    );

    // Last step that may touch bootloader memory is done: `memmap`, `hhdm`,
    // and the other Limine responses must not be used after this.
    match mm::reclaim_bootloader_memory() {
        Ok(frames) => {
            let free = mm::frames().as_ref().map_or(0, |f| f.stats().free);
            kprintln!(
                "  reclaimed:  {} MiB of bootloader memory ({frames} frames); {} MiB free",
                mib(frames as u64 * mm::frame::FRAME_SIZE),
                mib(free as u64 * mm::frame::FRAME_SIZE)
            );
        }
        Err(error) => fail(format_args!("reclaiming bootloader memory failed: {error}")),
    }

    match mm::init_heap() {
        Ok(stats) => kprintln!(
            "  heap:       {} MiB at {:#x}",
            mib(stats.size as u64),
            mm::heap::HEAP_BASE
        ),
        Err(error) => fail(format_args!("heap setup failed: {error}")),
    }
    // Smoke test: `alloc` works in the kernel.
    let numbers: alloc::vec::Vec<u64> = (1..=100).collect();
    if numbers.iter().sum::<u64>() != 5050 || mm::heap_stats().used == 0 {
        fail(format_args!("heap smoke test failed"));
    }
    drop(numbers);

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
