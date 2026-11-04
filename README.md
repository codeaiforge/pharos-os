# Pharos OS

Pharos OS by CodeAIForge is an experimental project to build a local-first AI agent platform, and eventually a standalone operating system, in Rust.

> [!WARNING]
> Pharos OS is **not** a usable or production-ready operating system. The kernel only boots in QEMU, prints what the bootloader handed over, and starts a few test services. Do not use it for anything security-critical, and do not boot it on real hardware.

## Status

**Phase 2 — Core System is done (v0.2.0).** a minimal kernel boots in QEMU on UEFI and BIOS with one command (`cargo xtask run`), reports CPU exceptions (including stack overflows) over serial, receives local APIC timer interrupts, and manages memory (a frame allocator, its own page tables with write protection, no-execute, and guard pages, reclaimed bootloader memory, and a heap for `alloc`), schedules kernel tasks preemptively on a calibrated 100 Hz timer, and runs user processes in ring 3, each in its own address space, with a small system-call interface and synchronous IPC that passes capabilities, lets processes read files from a checked, read-only filesystem image on a boot RAM disk through capabilities, and runs drivers in user space: a Rust virtio-blk driver reaches its device only through capabilities (registers, DMA memory, MSI-X interrupts) and mounts the filesystem image on the disk; at boot `init` starts the services, among them a user-space network service with its own small stack (Ethernet, ARP, IPv4, ICMP, UDP) that processes reach only through badged capabilities; CI boots it and runs 55 test kernels inside QEMU on every push. Phase 3 (AI agent platform) has started: M3.1 chose our own `no_std` inference engine and the first model ([evaluation](docs/project/inference-evaluation.md)); M3.0 gave Pharos what running it needs (SIMD in user programs, user memory, timeouts, shared memory, and crash-consistent writable storage that serves a 676 MB model file into one process); M3.2 runs local inference as an unprivileged service on Pharos (S1 under KVM: first token in 6.35 s, 14.2 tokens/s); M3.3 runs agents under a runtime that restarts them after crashes and hangs, keeps their tasks durable across restarts, and can always be stopped from a trusted console that no agent can reach; M3.4 gives agents only the permissions their policy entry or the user grants, revocable at once, with default-deny networking and every grant and consequential action in an audit trail; the current milestone is M3.5, resource accounting and limits. See the [implementation roadmap](docs/project/implementation-roadmap.md), the [boot design](docs/architecture/boot.md), [exceptions and interrupts](docs/architecture/interrupts.md), [memory management](docs/architecture/memory.md), [scheduling](docs/architecture/scheduling.md), [system calls and IPC](docs/architecture/syscalls-ipc.md), [storage](docs/architecture/storage.md), and [drivers](docs/architecture/drivers.md), [services](docs/architecture/services.md), [networking](docs/architecture/networking.md), [local inference](docs/architecture/inference.md), and [agents](docs/architecture/agents.md), and [capabilities](docs/architecture/capabilities.md).

| Area | Status |
| --- | --- |
| Rust workspace, formatting, linting, tests, CI config | Implemented |
| `pharos` host-side CLI (`help`, `version`, `info`, `doctor`) | Implemented |
| `cargo xtask` (kernel build, reproducible boot image, QEMU run, filesystem images) | Implemented |
| Minimal x86-64 kernel: boots via Limine in QEMU (UEFI and BIOS), reports boot information over serial, starts `init` and its services | Implemented |
| Automated QEMU boot check in CI (UEFI and BIOS, reproducible image) | Implemented |
| Kernel tests inside QEMU (test kernels, run locally and in CI) | Implemented |
| Memory management, exceptions and timer interrupts, preemptive scheduling, user processes, system calls, IPC with capabilities | Implemented |
| Filesystem image format and host tool (`crates/pharos-fs`, `cargo xtask fs`) | Implemented |
| Read-only storage in the kernel (RAM disk, filesystem, file capabilities) | Implemented |
| Rust user programs loaded from the filesystem (ELF loader, system-call library) | Implemented |
| PCI discovery, device capabilities (MMIO, DMA, MSI-X interrupts), user-space virtio-blk driver | Implemented |
| Service manager (`init`), user-space network service (UDP, ICMP) with badged network capabilities | Implemented |
| Crash-consistent writable storage service (`bin/store`) | Implemented |
| TCP, more drivers | Planned |
| Inference engine (`crates/pharos-infer`: GGUF Q8_0 Qwen2 models, Qwen2's tokenizer, batched prompts; `no_std`, safe Rust) | Implemented |
| Local inference service on Pharos (`bin/infer`: unprivileged, models pinned by SHA-256, read-only model storage; interface `inference` 1) | Implemented |
| Agent runtime (`bin/agents`: manifests, durable tasks, crash and hang restarts), trusted console with the emergency stop (`bin/trust`), service supervision in `init` | Implemented |
| Agent permissions (policy table, approval on the trusted console, revocation), default-deny agent networking, audit service (`bin/audit`) | Implemented |
| Resource accounting and limits for agents | Planned |

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

The serial output shows `init` starting the services, then ends with `PHAROS: boot ok`, and the command exits 0 only when the kernel reports success. `cargo xtask test` runs the same boot headless under both firmwares, with a time limit, and reports pass or fail for each; CI runs it on every push to `main`.

## CLI usage

```console
$ cargo run -q -p pharos-cli -- version
pharos 0.2.0

$ cargo run -q -p pharos-cli -- info
Pharos OS 0.2.0
Project of: CodeAIForge
Stage:      Phase 3 - AI Agent Platform (M3.4 complete, M3.5 next)
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
| `crates/pharos-elf/` | Program format: a validating parser for static ELF64 user programs ([driver design](docs/architecture/drivers.md)) |
| `user/` | User space: `pharos-user` (system-call library) and `programs/` (Rust user programs, built for the bare-metal target and stored in the boot filesystem) |
| `crates/pharos-fs/` | Filesystem image format: builder, validating parser, block-device trait, shared by the kernel and `cargo xtask` ([storage design](docs/architecture/storage.md)) |
| `crates/pharos-store/` | Writable store format: copy-on-write commits with two superblock roots, crash recovery, SHA-256-chained streams, shared by the storage service and `cargo xtask` ([storage design](docs/architecture/storage.md#8-the-writable-store-m30)) |
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
