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
    _print_panic, QemuExit, apic, cpu_identity, fw_cfg_file, gdt, halt, idt, paging, qemu_exit,
    run_on_kernel_stack,
};
use pharos_kernel::boot_info::{BootMode, boot_mode, firmware_name, mib, summarize};
use pharos_kernel::limine::{BASE_REVISION, BootMemory};
use pharos_kernel::mm;
use pharos_kernel::storage;
use pharos_kernel::time;
use pharos_kernel::{acpi, cpu, fs, iommu, ipc, kprintln, pci, process, sched};

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

    // Before anything else runs: on a CPU affected by Meltdown or MDS, any
    // process could read all memory through the kernel half (D-044).
    match cpu::check(&cpu_identity()) {
        Ok(allowed) => kprintln!("  cpu:        not affected by Meltdown or MDS ({allowed:?})"),
        Err(refused) => fail(format_args!(
            "this CPU may leak kernel memory to processes (D-044): {}",
            refused.reason()
        )),
    }

    if !requests::BASE_REVISION_TAG.is_supported() {
        fail(format_args!(
            "bootloader did not accept Limine base revision {BASE_REVISION}"
        ));
    }

    // Limine's responses are borrowed from `boot`, which the reclaim below
    // consumes, so none can be used after it (#223).
    let Some(boot) = BootMemory::take() else {
        fail(format_args!("bootloader memory already claimed"));
    };
    let Some(memmap) = requests::MEMMAP.get(&boot) else {
        fail(format_args!("no memory map from the bootloader"));
    };
    let Some(hhdm) = requests::HHDM.get(&boot) else {
        fail(format_args!(
            "no higher-half direct map from the bootloader"
        ));
    };

    if let Some(info) = requests::BOOTLOADER_INFO.get(&boot) {
        kprintln!(
            "  bootloader: {} {}",
            info.name().unwrap_or("?"),
            info.version().unwrap_or("?")
        );
    }
    if let Some(firmware) = requests::FIRMWARE_TYPE.get(&boot) {
        kprintln!("  firmware:   {}", firmware_name(firmware.firmware_type));
    }
    let date = requests::DATE_AT_BOOT.get(&boot).map(|d| d.timestamp);
    // The floor is the build's `SOURCE_DATE_EPOCH`; the boot check reads it (#276).
    let floor = pharos_kernel::time::DATE_FLOOR;
    if pharos_kernel::time::set_boot_date(date) {
        let date = date.unwrap_or(0);
        kprintln!("  date:       {date} (Unix seconds; floor {floor})");
    } else {
        kprintln!("  date:       none, or one before the floor {floor}: TLS refuses (NO_CLOCK)");
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

    let Some(image) = requests::EXECUTABLE_ADDRESS.get(&boot) else {
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

    // The Limine entry's mode (#164): read now, while its string exists.
    let mut mode = match boot_mode(requests::CMDLINE.get(&boot).and_then(|r| r.cmdline())) {
        Ok(mode) => mode,
        Err(other) => {
            kprintln!("  mode:       command line \"{other}\" not known; normal mode");
            BootMode::Normal
        }
    };
    if mode != BootMode::Normal {
        kprintln!("  mode:       {} (from the command line)", mode.name());
    }

    // Module records live in kernel memory; Limine's list does not survive
    // the reclaim below.
    let (modules, skipped) = storage::record_modules(requests::MODULES.get(&boot), hhdm.offset);
    // Measured boot (D-047 item 2): the kernel's file, then each module in
    // configuration order, before their bootloader copies can go.
    let Some(kernel_file) = requests::EXECUTABLE_FILE.get(&boot) else {
        fail(format_args!(
            "no executable file from the bootloader; the boot cannot be measured"
        ));
    };
    let files = core::iter::once((&b"kernel"[..], kernel_file.file().bytes())).chain(
        requests::MODULES
            .get(&boot)
            .into_iter()
            .flat_map(|r| r.modules())
            .map(|f| (f.string().unwrap_or("").as_bytes(), f.bytes())),
    );
    let digest = pharos_kernel::key::measure(files);
    kprintln!(
        "  measured:   boot {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}…",
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
        digest[5],
        digest[6],
        digest[7]
    );

    // Last step that may touch bootloader memory is done. Consuming `boot`
    // ends every borrowed Limine response; using one below does not compile.
    // The RSDP's physical address, kept as a number: the response lives in
    // bootloader memory, the tables themselves in firmware memory.
    let rsdp = requests::RSDP
        .get(&boot)
        .and_then(|r| r.address.checked_sub(hhdm.offset));
    match mm::reclaim_bootloader_memory(boot) {
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
    // A bad `root` falls back to its copy `recovery`, in recovery mode
    // (#164); if both fail, it is reported and `init` cannot start.
    match fs::mount_root() {
        Ok((files, None)) => kprintln!("  filesystem: root mounted, files: {files}"),
        Ok((files, Some(why))) => {
            kprintln!(
                "  filesystem: root not mounted: {why}; recovery copy mounted, files: {files}"
            );
            mode = BootMode::RecoveryCopy;
        }
        Err(error) => kprintln!("  filesystem: root not mounted: {error}"),
    }

    // DMA isolation (iommu.md): translation on, every device blocked,
    // before any driver runs. Without an IOMMU no driver can be isolated,
    // so the boot stops (D-044, #242).
    let dmar = match rsdp.map(|rsdp| acpi::find(&acpi::DirectMap, rsdp, b"DMAR")) {
        Some(Ok(Some(table))) => acpi::parse_dmar(&table)
            .unwrap_or_else(|e| fail(format_args!("the DMAR table is malformed: {e:?}"))),
        Some(Err(error)) => fail(format_args!("ACPI tables unreadable: {error:?}")),
        None => fail(format_args!(
            "no RSDP from the bootloader; the IOMMU cannot be found"
        )),
        Some(Ok(None)) => fail(format_args!(
            "no IOMMU (DMAR) found; drivers cannot be isolated (D-044)"
        )),
    };
    match iommu::init(&dmar) {
        Ok(caps) => kprintln!(
            "  iommu:      {} unit(s) translating, {}-level tables, nothing attached",
            dmar.units.len(),
            caps.levels
        ),
        Err(error) => fail(format_args!(
            "the IOMMU cannot isolate drivers (D-044): {error}"
        )),
    }
    // The device secret (D-047): without it the audit trail and the slot
    // record cannot be authenticated, so the boot stops.
    match pharos_kernel::key::init() {
        Ok(()) => kprintln!("  key:        device key read"),
        Err(error) => fail(format_args!("{error}")),
    }
    // The vault's secrets (D-035): optional; the kernel never parses them.
    match pharos_kernel::key::secrets_init() {
        Ok(0) => kprintln!("  secrets:    none"),
        Ok(n) => kprintln!("  secrets:    {n} bytes"),
        Err(n) => kprintln!("  secrets:    {n} bytes is over 4 KiB; ignored"),
    }
    // D-049: a boot check (the host passes this `fw_cfg` file) ends after
    // `boot ok`; otherwise the system runs until the VM is stopped. Read
    // now: the `fw_cfg` selector is shared, and no other task runs yet.
    let boot_check = fw_cfg_file(BOOT_CHECK, &mut []).is_some();
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
    match process::spawn_elf_limited(
        &root,
        b"bin/init",
        mode.init_arg(),
        caps,
        process::INIT_MEMORY_LIMIT,
    ) {
        Ok(id) => kprintln!("  init:       started (process {id})"),
        Err(error) => fail(format_args!("cannot start init: {error}")),
    }
    // Enough for two slots that are not ready in 20 s and the factory
    // image (boot.md section 8, #163).
    match ipc::poll(&report, core::time::Duration::from_secs(75)) {
        Some(m) if m.len == 4 => {
            let (ready, failed) = (m.data[0], m.data[1]);
            let image = match m.data[2] {
                0 => "the factory image",
                1 => "slot A",
                2 => "slot B",
                3 => "the recovery copy",
                _ => "an unknown image",
            };
            let mode = match m.data[3] {
                0 => "",
                1 => ", safe mode",
                _ => ", recovery mode",
            };
            kprintln!("  services:   {ready} ready, {failed} failed, from {image}{mode}");
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
    if boot_check {
        qemu_exit(QemuExit::Success);
        halt()
    }
    kprintln!("  running:    until the VM is stopped");
    // Nothing wakes this task: the services run, and the idle task when
    // none is ready. The loop guards against a stray wake.
    loop {
        sched::block_current();
    }
}

/// The `fw_cfg` file that makes this boot a boot check (D-049).
const BOOT_CHECK: &[u8] = b"opt/org.pharos/boot-check";

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
