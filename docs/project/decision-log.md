# Decision log

This log records significant technical decisions. An entry with status **Open** is a question, not a decision. Do not treat open entries as settled, and do not implement against them until they are accepted.

## Statuses

- **Open** — needs evaluation; no choice made.
- **Proposed** — a choice is recommended and awaiting review.
- **Accepted** — approved; implementation may rely on it.
- **Superseded** — replaced by a later entry (link it).

## Template

Copy this block for each new decision. Use the next free ID.

```markdown
### D-NNN: <title>

- **Status:** Open | Proposed | Accepted | Superseded by D-MMM
- **Needed by:** <roadmap milestone>
- **Date accepted:** <YYYY-MM-DD, when accepted>

**Context.** The problem, constraints, and why a decision is needed.

**Options.** Each option with its pros and cons.

**Evaluation criteria.** What the choice is judged on.

**Decision.** The chosen option (empty while Open).

**Consequences.** What this enables, costs, or rules out; follow-up work.

**Evidence.** Prototypes, measurements, or references supporting the choice.
```

## Accepted decisions (Phase 1 scaffold)

These were chosen during the repository bootstrap, reviewed and accepted by the maintainer, and cover only the host-side workspace.

### P-001: Host toolchain and workspace layout

- **Status:** Accepted (Phase 1 scope). The minimum Rust version (1.85) is conditional on the first passing run of the `msrv` CI job; if it fails, fix the code or raise `rust-version`.
- **Needed by:** M1.1
- **Date accepted:** 2026-10-26

**Decision.** Stable Rust tracked via `rust-toolchain.toml` (`channel = "stable"`, not a fixed patch release); edition 2024 with `rust-version = "1.85"` (the edition's minimum, checked by the `msrv` CI job); Cargo resolver 3; a virtual workspace with `kernel` and `tools/pharos-cli`; `Cargo.lock` committed; `unsafe_code = "forbid"` workspace-wide.

**Rationale.** Edition 2024 is the newest stable edition and is supported by the installed toolchain (Rust 1.99.1 at bootstrap). Tracking `stable` avoids a pin that goes stale; `Cargo.lock` plus `--locked` in CI keeps dependency resolution reproducible. A virtual root keeps package boundaries explicit.

**Consequences.** Contributors on older toolchains must update (`rustup update stable`). A new stable release may introduce new Clippy lints that fail CI; fix them or pin a specific version via a new decision if this becomes disruptive. The kernel will need its own target and may need nightly features — that is decision D-003 and must not be assumed. This decision covers host-side crates only; accepting it does not constrain D-003.

**Revisit when.** New stable releases repeatedly break CI through new lints (consider pinning a version), or D-003 requires a different toolchain for the kernel. The workspace-wide `unsafe_code = "forbid"` is expected to be relaxed for the kernel crate only at M2.2.

### P-002: CLI uses only the standard library

- **Status:** Accepted (Phase 1 scope)
- **Needed by:** M1.3
- **Date accepted:** 2026-10-26

**Decision.** The `pharos` CLI parses arguments by hand with `std`; no argument-parsing crate.

**Rationale.** Four commands without options do not justify a dependency.

**Revisit when.** The first CLI command needs options or flags. Candidates then: `lexopt` (tiny, no dependencies) or `clap` (de facto standard, much larger); choose by the CLI's size at that time. If D-003 places kernel build tasks in a separate `xtask` crate, the CLI may never need this.

## Open and proposed decisions

Each entry lists the milestone by which it must be decided. **Proposed** entries carry a recommendation but are not decisions until accepted. Decisions may be made earlier if evidence is available.

### D-001: Bootloader and boot protocol

- **Status:** Proposed (2026-10-26; awaiting prototype evidence in #3 and acceptance in #4)
- **Needed by:** M2.1

**Context.** The kernel needs a defined entry state and boot information (memory map, framebuffer, command line).

**Options to evaluate.** Limine protocol; Multiboot2 (e.g. via GRUB); the Rust `bootloader` crate ecosystem; a custom UEFI loader.

**Evaluation criteria.** Maturity and maintenance; license compatibility with Apache-2.0; BIOS/UEFI coverage; QEMU support; amount of code added to the TCB; quality of Rust integration; reproducible image creation without root privileges.

**Proposal.** Limine bootloader with the Limine boot protocol: it enters the kernel in 64-bit mode in the higher half with a memory map and direct map, so no mode-switch trampoline is needed; it supports BIOS and UEFI; it is BSD-2-Clause (protocol 0BSD); and it builds images on stable Rust without root. Fallback: Multiboot2. The `bootloader` crate is not recommended because it needs nightly Rust to build images; a custom UEFI loader is not recommended now because of its size and maintenance cost. Note the `limine` crate's change of repository (supply-chain note). Full scoring and sources: [boot evaluation](../architecture/boot-evaluation.md#d-001--bootloader-and-boot-protocol).

### D-002: BIOS and/or UEFI support

- **Status:** Proposed (2026-10-26; awaiting prototype evidence in #3 and acceptance in #4)
- **Needed by:** M2.1

**Context.** Determines firmware interfaces, image format, and testing matrix.

**Options.** UEFI only; BIOS only; both.

**Evaluation criteria.** Relevance to modern hardware; QEMU firmware availability (e.g. OVMF for UEFI); testing cost; Secure Boot implications for later phases.

**Proposal.** UEFI is the primary, required path (tested with OVMF). BIOS is supported as a secondary path (tested with SeaBIOS) while it needs no kernel-side code, which holds with Limine. Revisit at M5.2. Details: [boot evaluation](../architecture/boot-evaluation.md#d-002--bios-andor-uefi).

### D-003: Rust target, linker, and build strategy

- **Status:** Proposed (2026-10-26; awaiting prototype evidence in #3 and acceptance in #4)
- **Needed by:** M2.1

**Context.** A bootable kernel needs a bare-metal target, linker configuration, and a way to build a bootable image.

**Options.** Built-in target (e.g. `x86_64-unknown-none`) on stable versus a custom target JSON (requires nightly `build-std`); linker script versus bootloader-provided layout; `cargo` aliases versus an `xtask` crate versus scripts for image building.

**Evaluation criteria.** Works on stable Rust if possible; reproducibility; no root needed; keeps `cargo test --workspace` working for host crates; clarity for contributors.

**Proposal.** Built-in `x86_64-unknown-none` on stable Rust (Tier 2; `kernel` code model, no red zone, soft-float by default); a small linker script for the higher-half layout; an `xtask` crate to build images and run QEMU, keeping the `pharos` CLI read-only. The kernel stays a workspace member, excluded from host commands (`--exclude pharos-kernel`) and checked separately with `--target x86_64-unknown-none`; target-independent logic goes in a host-testable `no_std` library. Details: [boot evaluation](../architecture/boot-evaluation.md#d-003--rust-target-linker-and-build-strategy).

### D-004: Kernel architecture and privilege boundaries

- **Status:** Open
- **Needed by:** initial direction at M2.1; final before M2.7

**Options.** Microkernel; hybrid; monolithic with strict internal module boundaries.

**Evaluation criteria.** TCB size; isolation of drivers and AI services; IPC performance; implementation complexity for a small team; testability in QEMU.

### D-005: Memory-management strategy

- **Status:** Open
- **Needed by:** M2.5

**Options.** Physical frame allocator design (bitmap, free list, buddy); page-table management approach; kernel heap allocator; address-space layout; use of KASLR later.

**Evaluation criteria.** Correctness and testability; fragmentation; amount of `unsafe`; support for later isolation of agents and large model memory.

### D-006: Interrupt controller and timer design

- **Status:** Open
- **Needed by:** M2.4 (controller), M2.6 (timer)

**Options.** Legacy 8259 PIC versus local APIC/IOAPIC (x2APIC later); PIT, HPET, APIC timer, or TSC-deadline.

**Evaluation criteria.** QEMU and real-hardware support; SMP readiness; precision needed by the scheduler.

### D-007: Filesystem and persistent storage

- **Status:** Open
- **Needed by:** M2.8

**Options.** Read-only initial RAM disk first; existing format (e.g. FAT for interoperability, ext2 for simplicity) versus a custom design; user-space versus kernel filesystem.

**Evaluation criteria.** Crash consistency; simplicity; tooling to build images on the host; fit with capability-based access control.

### D-008: Driver strategy

- **Status:** Open
- **Needed by:** M2.9

**Options.** In-kernel drivers versus user-space drivers; initial device set limited to QEMU devices (serial, virtio-blk, virtio-net, framebuffer) before real hardware.

**Evaluation criteria.** TCB size; DMA isolation (IOMMU availability); performance; effort.

### D-009: QEMU automation and debugging approach

- **Status:** Open
- **Needed by:** M2.3

**Options.** Test runner via Cargo `runner` configuration, an `xtask` harness, or scripts; exit signalling via QEMU `isa-debug-exit` or serial markers; GDB via QEMU's `-s -S` stub.

**Evaluation criteria.** Deterministic pass/fail; timeouts; works headless in CI; no root privileges; clear failure output.

### D-010: AI inference runtime, model formats, and licensing

- **Status:** Open
- **Needed by:** M3.1

**Context.** The inference runtime is large and complex; where and how it runs dominates the security design.

**Options to evaluate.** Rust-native runtimes versus bindings to established C/C++ runtimes; candidate model formats (e.g. GGUF, ONNX, safetensors). Initially this runs on the Linux host; running on Pharos itself depends on Phase 2 services.

**Evaluation criteria.** Runtime license and model licenses (including use restrictions); memory safety and attack surface; CPU performance; portability to Pharos; supply-chain verifiability of model files.

### D-011: CPU/GPU support and memory/VRAM constraints

- **Status:** Open
- **Needed by:** M3.1 (requirements), M3.2 (implementation)

**Context.** GPU acceleration on a custom OS requires drivers that may not exist; CPU-only inference limits model size.

**Evaluation criteria.** Minimum and recommended RAM/VRAM; CPU-only viability for target models; driver availability and licensing; isolation of GPU memory between agents.

### D-012: Agent sandboxing, tool permissions, and network isolation

- **Status:** Open
- **Needed by:** direction by M2.7 (so syscalls/IPC support it); final at M3.4

**Options.** Kernel-enforced capabilities; user-space policy service; combination. Permission prompts versus pre-declared manifests. Default-deny networking with per-destination grants.

**Evaluation criteria.** No ambient authority; revocation; auditability; usability of permission prompts; resistance to prompt injection leading to privilege escalation.
