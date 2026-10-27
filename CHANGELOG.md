# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, any release may contain breaking changes.

## [Unreleased]

### Added

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
