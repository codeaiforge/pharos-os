//! Pharos OS kernel entry point.
//!
//! Limine loads this binary at `0xffffffff80000000` and jumps to [`kmain`] in
//! 64-bit mode (see `docs/architecture/boot.md`). The kernel reports what the
//! bootloader handed over on COM1, then starts `init` (services.md), which
//! starts the services and reports. Boot succeeds only if every service
//! did; the result goes to QEMU (only when running under a hypervisor).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use pharos_kernel::arch::x86_64::{
    _print_panic, QemuExit, apic, gdt, halt, idt, paging, qemu_exit, run_on_kernel_stack,
};
use pharos_kernel::boot_info::{firmware_name, mib, summarize};
use pharos_kernel::limine::BASE_REVISION;
use pharos_kernel::mm;
use pharos_kernel::storage;
use pharos_kernel::time;
use pharos_kernel::{fs, ipc, kprintln, pci, process, sched};

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
    // The CPU setup that switched page tables also enabled floating point
    // for processes (D-016).
    {
        use pharos_kernel::arch::x86_64::fpu::{Mode, mode};
        kprintln!(
            "  vectors:    {}",
            match mode() {
                Mode::Fxsave => "x87 and SSE, saved with FXSAVE",
                Mode::XsaveAvx => "x87, SSE, and AVX, saved with XSAVE",
                Mode::Off => "not enabled",
            }
        );
    }

    if let Err(error) = apic::init(hhdm.offset) {
        fail(format_args!("local APIC setup failed: {error}"));
    }
    kprintln!(
        "  local APIC: id {}, version {:#x}",
        apic::id(),
        apic::version() & 0xff
    );
    match time::init() {
        Ok(c) => kprintln!(
            "  timer:      APIC {} kHz (divided by 16), TSC {} MHz, tick {} Hz",
            c.apic_per_ms,
            c.tsc_per_ms / 1_000,
            time::TICK_HZ
        ),
        Err(error) => fail(format_args!("timer calibration failed: {error}")),
    }

    // Module records live in kernel memory; Limine's list does not survive
    // the reclaim below.
    let (modules, skipped) = storage::record_modules(requests::MODULES.response(), hhdm.offset);

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
    match storage::ram_disk("root") {
        Some(disk) => kprintln!(
            "  storage:    RAM disk 'root', {} bytes ({modules} modules, {skipped} skipped)",
            disk.len()
        ),
        None => kprintln!("  storage:    none ({modules} modules, {skipped} skipped)"),
    }
    // A bad or missing image is reported; the kernel runs on without it.
    match fs::mount_root() {
        Ok(files) => kprintln!("  filesystem: root mounted, files: {files}"),
        Err(error) => kprintln!("  filesystem: root not mounted: {error}"),
    }

    let functions = pci::enumerate();
    kprintln!("  pci:        {functions} functions");
    for d in pci::devices() {
        let a = d.address;
        kprintln!(
            "    {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}.{:02x} {}{}",
            a.bus,
            a.device,
            a.function,
            d.vendor,
            d.device,
            d.class[0],
            d.class[1],
            d.name(),
            if d.msix.is_some() { " (MSI-X)" } else { "" }
        );
    }

    // Smoke test: `alloc` works in the kernel.
    let numbers: alloc::vec::Vec<u64> = (1..=100).collect();
    if numbers.iter().sum::<u64>() != 5050 || mm::heap_stats().used == 0 {
        fail(format_args!("heap smoke test failed"));
    }
    drop(numbers);

    // User space: `init` starts the services and reports (services.md).
    process::init();
    if let Err(error) = sched::init().and_then(|()| sched::enable_preemption()) {
        fail(format_args!("scheduler setup failed: {error}"));
    }
    let Some(root) = fs::root() else {
        fail(format_args!("no root filesystem, so init cannot start"));
    };
    let report = ipc::Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    match process::spawn_elf_limited(&root, b"bin/init", 0, caps, process::INIT_MEMORY_LIMIT) {
        Ok(id) => kprintln!("  init:       started (process {id})"),
        Err(error) => fail(format_args!("cannot start init: {error}")),
    }
    // Enough for two slots that are not ready in 20 s and the factory
    // image (boot.md section 8, #163).
    match ipc::poll(&report, core::time::Duration::from_secs(75)) {
        Some(m) if m.len == 3 => {
            let (ready, failed) = (m.data[0], m.data[1]);
            let image = match m.data[2] {
                0 => "the factory image",
                1 => "slot A",
                2 => "slot B",
                _ => "an unknown image",
            };
            kprintln!("  services:   {ready} ready, {failed} failed, from {image}");
            if failed != 0 {
                fail(format_args!(
                    "{failed} service(s) failed (see init's lines above)"
                ));
            }
        }
        Some(_) => fail(format_args!("init sent a malformed report")),
        None => fail(format_args!("init did not report within 75 s")),
    }

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
