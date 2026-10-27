# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, any release may contain breaking changes.

## [Unreleased]

### Added

- Reclaiming bootloader memory (D-005, #28): the memory map is copied into kernel memory, the frame allocator holds bootloader-reclaimable regions reserved from the start, and `mm::reclaim_bootloader_memory` frees them once the kernel's own page tables are active, after retiring Limine's responses (`response()` returns `None` afterwards). `kmain` reclaims as its last step (41 MiB under UEFI in QEMU). New test kernel `reclaim` (12 checks), verified to fail if the responses are not retired.
- The kernel's own page tables (D-005, #27): `arch::x86_64::paging` with an `AddressSpace` (map, unmap, translate; 4 KiB and 2 MiB pages) and a kernel address space with the direct map at Limine's offset, per-segment permissions (text read+execute, rodata read-only, data no-execute, no writable alias of the kernel image), and unmapped guard pages below both kernel stacks; the double-fault stack moved to its own linker segment. `kmain` switches CR3 to it, and the local APIC now maps through it (the M2.4 stopgap is gone). New Limine executable-address request. New test kernels `paging` (20 checks), `write_protect` (4), and `no_execute` (5); `apic_timer` and `double_fault` now run on the kernel's own tables. Each new check was verified to fail when its property is broken. New design document `docs/architecture/memory.md`.
- Physical frame allocator (D-005, #26): `mm::bitmap` (range allocator shared with the future heap) and `mm::frame` (one bitmap per usable region at or above 1 MiB), both safe and host-tested; `mm::raw` adds `IrqMutex` and the direct-map bitmap storage. `kmain` prints the free frame count. New test kernel `frames` (19 checks), verified to fail if the bitmap storage is not reserved.
- Accepted decision D-005 (memory management): one bitmap per memory region for frames, the kernel's own 4-level page tables with an address-space object, Limine's direct-map offset kept with 2 MiB pages, per-section permissions and guard pages for both kernel stacks, reclaim after copying Limine responses, and an own bitmap heap (4 MiB, no crate). `unsafe` is also allowed in a new `mm::raw` module (AGENTS.md updated). Prototype evidence: fragmented memory maps (up to 32 entries), no 1 GiB pages in QEMU's default CPU, and allocation failure reaching the panic handler.
- `cargo xtask run --kernel <ELF>` boots a given kernel, for example a test kernel, so it can be debugged with GDB at source level. The debugging guide now covers exception reports, a verified GDB session on the page-fault path, and diagnosing triple faults with `-d int,cpu_reset`. The threat model notes the kernel's fault handling.
- Local APIC timer interrupts (D-006, #23): `arch::x86_64::apic` maps the APIC register page uncached into Limine's page tables using page-table pages reserved in the kernel image, enables the APIC, and runs its periodic timer on vector 32 with a spurious vector of 255; the legacy PICs stay masked. `kmain` sets up the APIC and prints its ID and version (checked under UEFI and BIOS). New test kernel `apic_timer` (5 checks; also run once by hand under BIOS), verified to hang and fail without EOI. New design document `docs/architecture/interrupts.md`.
- Double faults run on their own stack (TSS IST1), and the kernel runs on a 64 KiB kernel stack with an unmapped guard page below it (#22). `kmain` and test kernels leave Limine's boot stack first. A stack overflow is now reported as a double fault instead of a triple-fault reboot. New test kernel `double_fault` (5 checks), verified to fail without the IST stack or without the guard gap.
- IDT and CPU exception handlers (#21): `global_asm!` entry stubs for vectors 0–31 (stable Rust, minimum version unchanged) and one Rust dispatcher. Breakpoints are reported and execution continues; other exceptions print the vector, decoded error code, CR2, and registers, then fail the run. Test kernels can install a fatal hook; `TestRun` handles now share one count. New test kernel `exceptions` (8 checks) and host unit tests for gates, frame layout, and reports.
- The kernel loads its own GDT (null, kernel code, kernel data, TSS) and TSS at the start of `kmain` (#20), so it no longer depends on Limine's GDT in reclaimable memory. The TSS provides a 16 KiB double-fault stack (IST1, no guard page until M2.5). New test kernel `gdt` (9 checks) and host unit tests for descriptor encoding. `unsafe` is now allowed in submodules of `arch::x86_64` too (AGENTS.md updated).
- Accepted decision D-006 (controller part): local APIC in xAPIC mode, with the local APIC timer as the first hardware interrupt; the legacy PICs stay masked; M2.4 maps the APIC register page into Limine's page tables until M2.5. Prototypes showed that QEMU under TCG cannot provide x2APIC and that PIC interrupts cannot get past Limine's masked LINT0. The timer choice stays open until M2.6.
- Interrupt-safe kernel console (#19): `interrupts_enabled`, `enable_interrupts`, `disable_interrupts`, and `without_interrupts` in the hardware layer; `kprint!`/`kprintln!` hold the console lock with interrupts disabled and restore the previous state. Fatal exception handlers will use the panic handler's print path. New test kernel `interrupt_state` (9 checks).
- Kernel tests inside QEMU (D-009): test kernels in `kernel/tests/` (first: `boot_info`, 9 checks), the `test_kernel!` and `limine_requests!` macros, and `TestRun`. `cargo xtask runner` boots each test kernel under UEFI as Cargo's runner; `cargo xtask test` runs them after the boot check, so CI runs them too. Kernel Clippy now covers test kernels.
- Kernel logging: `kprint!` and `kprintln!` write to one COM1 console behind a new `SpinLock` (no `unsafe`, unit-tested with threads). The panic handler releases the lock first, so a panic during printing is still reported. Not interrupt-safe yet (M2.4).
- CI `qemu` job (Ubuntu 24.04): installs QEMU, OVMF, and xorriso on the runner, runs `cargo xtask test` (boot check under UEFI and BIOS), and checks that two image builds are byte-identical. No new actions, no artifacts. Verified on GitHub: passes on `main` (44 s) with the same image hash as a local build, and fails on a kernel that reports a boot failure.
- `cargo xtask test [--timeout <SECS>]`: headless boot check under UEFI and BIOS. A boot passes only with QEMU exit status 33 and the `PHAROS: boot ok` line within the limit (60 s by default); hung boots are stopped. Serial logs go to `target/xtask/logs/`, and their end is printed on failure.
- Accepted decision D-009 (QEMU automation): pass = QEMU status 33 and a serial marker, 60-second timeout, logs printed on failure, boot check on UEFI and BIOS, test kernels on stable Rust through Cargo's runner and `cargo xtask test`, ISO reproducibility check in CI. Prototyped before acceptance.
- `cargo xtask run [--bios] [--gdb]`: builds the kernel and image and boots it in QEMU (OVMF or SeaBIOS) with serial on the terminal; succeeds only when the kernel signals success (QEMU exit status 33). `--gdb` waits for GDB on `localhost:1234`.
- The kernel signals success or failure (boot errors, panics) through QEMU's `isa-debug-exit` device, only when CPUID reports a hypervisor.
- GDB workflow for breaking into the kernel, verified and documented in `docs/development/debugging.md`.
- Minimal `no_std` kernel (`pharos-kernel`): Limine boots it on UEFI and BIOS (verified in QEMU with `cargo xtask run`, including from a clean checkout); it checks base revision 6, reads the memory map, direct-map offset, bootloader info, and firmware type, reports them on COM1, and halts. Limine protocol structures are written in the project; all hardware `unsafe` code is in `arch::x86_64`.
- Kernel lint rules: `unsafe` denied except in the hardware layer and the Limine protocol module; every `unsafe` block needs a `// SAFETY:` comment (Clippy `undocumented_unsafe_blocks`).
- `cargo xtask` build tool (`xtask/`, no third-party crates): `build` compiles the kernel for `x86_64-unknown-none`; `image` downloads the pinned Limine 12.9.4 release, verifies its SHA-256, and assembles a reproducible hybrid BIOS/UEFI ISO that includes Limine's license notice.
- `scripts/check.sh`: runs the same checks as CI's `check` job, in order.
- Initial direction for D-004: capability-based microkernel with `unsafe` confined to a small hardware layer, plus constraints on early kernel code. Final decision due before M2.7.
- Boot design (`docs/architecture/boot.md`): accepted boot flow, Limine entry contract, image layout, and `xtask` build plan. Nothing boots on `main` yet.
- Accepted decisions D-001 (Limine, own protocol structures), D-002 (UEFI primary, BIOS secondary), and D-003 (`x86_64-unknown-none` on stable, linker script, `xtask`, ISO images, kernel as workspace member).
- Boot evaluation for D-001 to D-003 (`docs/architecture/boot-evaluation.md`), with proposed recommendations: Limine, UEFI primary with BIOS secondary, `x86_64-unknown-none` with an `xtask` build tool. Not accepted yet.
- Prototype evidence for D-001 to D-003 in the boot evaluation: Limine booted a prototype kernel under UEFI and BIOS in QEMU, with reproducible kernel and ISO builds.

### Changed

- M2.4 (exceptions, interrupts, debugging) is done: CI runs six test kernels covering breakpoints, page faults, stack-overflow double faults, and the local APIC timer, and a deliberately broken double-fault stack failed CI. M2.5 (memory management) is current. `pharos info` shows the new stage and lists exception handling and timer interrupts as implemented.
- M2.3 (QEMU boot validation) is done: CI boots the kernel and runs kernel tests on every push; the CI image hash matched a local build. M2.4 (exceptions and interrupts) is current. `pharos info` shows the new stage.
- `pharos info` reports the minimal kernel and `cargo xtask` as implemented and CI boot tests as planned; the stage is Phase 2 (M2.2). `pharos doctor` points to `cargo xtask run` for the QEMU check.
- M2.2 (minimal bootable kernel) is done; M2.3 (automated QEMU boot tests) is current.
- rust-analyzer's on-save check runs `scripts/ra-check.sh`, which checks host crates and the kernel separately, removing false editor errors in `kernel/src/main.rs`. The kernel's hardware layer now compiles on any x86-64 build so editors can resolve it.
- Prepared the workspace for a bare-metal kernel (D-003): `default-members` excludes `pharos-kernel`; host checks use `--exclude pharos-kernel`; the kernel is linted for `x86_64-unknown-none` and its library tests run on the host; `rust-toolchain.toml` adds the `x86_64-unknown-none` target; `.cargo/config.toml` sets `relocation-model=static` for that target only.
- `pharos-kernel` is now `no_std` outside tests. It is still a placeholder and does not boot.
- Contributor docs, the PR template, and CI use the new commands.

### Security

- Pin `actions/checkout` in CI to the signed v5.1.0 release commit SHA instead of the movable `v5` tag.

## [0.1.0] - 2026-10-26

Initial scaffold, completing Phase 1 (Foundation). Pharos OS is not bootable; this release contains host-side tooling and documentation only.

### Added

- Cargo workspace (edition 2024, resolver 3, stable toolchain via `rust-toolchain.toml`) with `Cargo.lock`.
- `pharos-kernel`: host-side placeholder library. It does not boot and implements no operating-system functionality.
- `pharos-cli`: the `pharos` host-side CLI with `help`, `version`, `info`, and `doctor` commands, defined exit codes, unit tests, and end-to-end tests of the binary.
- Workspace lint `unsafe_code = "forbid"`; Clippy warnings are errors in CI. Minimum supported Rust 1.85 (`rust-version`), verified in CI.
- GitHub Actions CI (format, Clippy, build, test, rustdoc, Markdown link check, Rust 1.85 build and test) with read-only permissions and job timeouts.
- `scripts/check-links.py`: read-only checker for relative Markdown links and anchors.
- Project documentation: vision, architecture (proposed), implementation roadmap, decision log, glossary, threat model, and development guides.
- Repository policy files: `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Apache-2.0 `LICENSE`, and `NOTICE`.
- Private vulnerability reporting through GitHub, documented in `SECURITY.md`.
- Issue and pull-request templates, editor configuration, and optional VS Code recommendations.

[Unreleased]: https://github.com/codeaiforge/pharos-os/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/codeaiforge/pharos-os/releases/tag/v0.1.0
