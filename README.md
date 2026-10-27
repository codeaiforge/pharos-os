# Pharos OS

Pharos OS by CodeAIForge is an experimental project to build a local-first AI agent platform, and eventually a standalone operating system, in Rust.

> [!WARNING]
> Pharos OS is **not** a usable or production-ready operating system. The kernel only boots in QEMU, prints what the bootloader handed over, and halts. Do not use it for anything security-critical, and do not boot it on real hardware.

## Status

**Phase 2 — Core System.** M2.2 to M2.7 are done: a minimal kernel boots in QEMU on UEFI and BIOS with one command (`cargo xtask run`), reports CPU exceptions (including stack overflows) over serial, receives local APIC timer interrupts, and manages memory (a frame allocator, its own page tables with write protection, no-execute, and guard pages, reclaimed bootloader memory, and a heap for `alloc`), schedules kernel tasks preemptively on a calibrated 100 Hz timer, and runs user processes in ring 3, each in its own address space, with a small system-call interface and synchronous IPC that passes capabilities; CI boots it and runs kernel tests inside QEMU on every push. The current milestone is M2.8: storage and a filesystem. See the [implementation roadmap](docs/project/implementation-roadmap.md), the [boot design](docs/architecture/boot.md), [exceptions and interrupts](docs/architecture/interrupts.md), [memory management](docs/architecture/memory.md), [scheduling](docs/architecture/scheduling.md), and [system calls and IPC](docs/architecture/syscalls-ipc.md).

| Area | Status |
| --- | --- |
| Rust workspace, formatting, linting, tests, CI config | Implemented |
| `pharos` host-side CLI (`help`, `version`, `info`, `doctor`) | Implemented |
| `cargo xtask` (kernel build, reproducible boot image, QEMU run) | Implemented |
| Minimal x86-64 kernel: boots via Limine in QEMU (UEFI and BIOS), reports boot information over serial, halts | Implemented |
| Automated QEMU boot check in CI (UEFI and BIOS, reproducible image) | Implemented |
| Kernel tests inside QEMU (test kernels, run locally and in CI) | Implemented |
| Memory management, interrupts, scheduling, processes, IPC | Planned |
| Storage, drivers, networking | Planned |
| Local AI inference and agent platform | Planned |

## Vision

Pharos OS aims to run AI agents locally under an operating-system design where agents are untrusted by default: they get explicit, least-privilege capabilities, inference runs isolated from privileged code, and model output is never trusted as instructions to the kernel. The project favors correctness, security, reproducibility, and small verifiable milestones over feature count. Read more in [vision](docs/project/vision.md) and [architecture](docs/project/architecture.md).

## Development environment

| | Initial target |
| --- | --- |
| Host | Linux Mint (other x86-64 Linux distributions should work) |
| Language | Rust, stable channel, edition 2024 (minimum Rust 1.85) |
| Architecture | x86-64 |
| Emulator | QEMU with OVMF (UEFI) and SeaBIOS (BIOS) |

## Prerequisites

- [rustup](https://rustup.rs/) with a stable Rust toolchain. `rust-toolchain.toml` selects `stable` with `rustfmt` and `clippy`, and rustup installs them on first use.
- A C linker (`cc`). On Linux Mint/Ubuntu: `sudo apt install build-essential`.

QEMU and cross-compilation tools are **not** required yet. See [setup](docs/development/setup.md).

## Build and run

```sh
cargo build
cargo run -p pharos-cli -- help
```

## Boot the kernel in QEMU

Needs `qemu-system-x86`, `ovmf`, and `xorriso` (see [setup](docs/development/setup.md)). One command builds the kernel and the image and boots it:

```sh
cargo xtask run          # UEFI (OVMF)
cargo xtask run --bios   # BIOS (SeaBIOS)
```

The serial output ends with `PHAROS: boot ok`, and the command exits 0 only when the kernel reports success. `cargo xtask test` runs the same boot headless under both firmwares, with a time limit, and reports pass or fail for each; CI runs it on every push to `main`.

## CLI usage

```console
$ cargo run -q -p pharos-cli -- version
pharos 0.1.0

$ cargo run -q -p pharos-cli -- info
Pharos OS 0.1.0
Project of: CodeAIForge
Stage:      Phase 2 - Core System (M2.7 complete, M2.8 next)
...

$ cargo run -q -p pharos-cli -- doctor
pharos doctor (read-only checks)
  [PASS] host OS             linux (supported: linux)
  [PASS] host architecture   x86_64 (supported: x86_64)
  ...
```

Exit status: `0` success, `1` the command reported a problem (for example, `doctor` warnings), `2` invalid usage.

## Test, format, lint

```sh
scripts/check.sh
```

This runs the same checks as CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)): formatting, Clippy with warnings as errors, build, tests, rustdoc, and Markdown links. The kernel is checked for its bare-metal target, separately from the host crates. CI also builds and tests the host crates on Rust 1.85. The individual commands are in [testing.md](docs/development/testing.md#quality-gates).

## Repository layout

| Path | Purpose |
| --- | --- |
| `kernel/` | The minimal `no_std` kernel ([kernel/README.md](kernel/README.md)) |
| `tools/pharos-cli/` | The `pharos` host-side development CLI |
| `xtask/` | `cargo xtask`: builds the kernel and boot image ([boot design](docs/architecture/boot.md#build-tool-xtask)) |
| `docs/` | Project, development, architecture, and security docs ([index](docs/README.md)) |
| `tests/` | Future cross-crate and QEMU integration tests ([tests/README.md](tests/README.md)) |
| `scripts/` | Future helper scripts ([scripts/README.md](scripts/README.md)) |

## Documentation

- [Implementation roadmap](docs/project/implementation-roadmap.md)
- [Architecture](docs/project/architecture.md)
- [Development setup](docs/development/setup.md) and [workflow](docs/development/workflow.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md) and [threat model](docs/security/threat-model.md)
- [Changelog](CHANGELOG.md)
- [Agent and contributor rules](AGENTS.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See also [NOTICE](NOTICE).
