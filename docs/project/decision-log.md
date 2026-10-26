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

## Accepted decisions (M2.1)

Accepted by the maintainer on 2026-10-26, based on the [boot evaluation](../architecture/boot-evaluation.md) and its [prototype evidence](../architecture/boot-evaluation.md#prototype-evidence-3). The resulting design is in the [boot design](../architecture/boot.md).

### D-001: Bootloader and boot protocol

- **Status:** Accepted
- **Needed by:** M2.1
- **Date accepted:** 2026-10-26

**Context.** The kernel needs a defined entry state and boot information (memory map, framebuffer, command line).

**Options.** Limine protocol; Multiboot2 (e.g. via GRUB); the Rust `bootloader` crate; a custom UEFI loader.

**Evaluation criteria.** Maturity and maintenance; license compatibility with Apache-2.0; BIOS/UEFI coverage; QEMU support; amount of code added to the TCB; quality of Rust integration; reproducible image creation without root privileges.

**Decision.** Use the **Limine** bootloader and the **Limine boot protocol** (base revision 6). The kernel reads boot information through **protocol structures written in the project** from the 0BSD specification; it does **not** depend on the `limine` crate. Limine binaries come from a **pinned official release**, verified by a committed SHA-256 (and the maintainer's GPG signature when the pin is updated).

**Consequences.** The kernel starts in 64-bit mode in the higher half with a memory map and direct map, so no mode-switch trampoline is needed. The project maintains its own protocol structures and updates them when adopting a new base revision. Limine (BSD-2-Clause) binaries are distributed in boot images, so their license must be reproduced in image notices. Multiboot2 remains the fallback if the Limine protocol becomes unsuitable.

**Evidence.** The prototype booted on UEFI and BIOS in QEMU, got all requested responses, and was rejected as expected when requesting an unsupported revision. Rejected: the `bootloader` crate (needs nightly Rust for images), a custom UEFI loader (largest code and maintenance cost, UEFI only, needs Rust 1.91), and GRUB as the primary loader (32-bit entry needs a trampoline; GPL-3.0 adds distribution obligations). Details: [boot evaluation](../architecture/boot-evaluation.md#d-001--bootloader-and-boot-protocol).

### D-002: BIOS and/or UEFI support

- **Status:** Accepted
- **Needed by:** M2.1
- **Date accepted:** 2026-10-26

**Context.** Determines firmware interfaces, image format, and testing matrix.

**Options.** UEFI only; BIOS only; both.

**Evaluation criteria.** Relevance to modern hardware; QEMU firmware availability (e.g. OVMF for UEFI); testing cost; Secure Boot implications for later phases.

**Decision.** **UEFI is the primary, required path**, tested with OVMF. **BIOS is a secondary path**, tested with SeaBIOS, supported only while it needs no kernel-side code.

**Consequences.** Every boot test runs twice (about one second each). Kernel code must not depend on BIOS-only or UEFI-only facilities without a new decision. Secure Boot stays possible (Limine supports it) and is planned for M4.3. Revisit at M5.2 (hardware compatibility).

**Evidence.** The same kernel and hybrid ISO booted on OVMF and SeaBIOS in the prototype, with the firmware type correctly reported. Details: [boot evaluation](../architecture/boot-evaluation.md#d-002--bios-andor-uefi).

### D-003: Rust target, linker, and build strategy

- **Status:** Accepted
- **Needed by:** M2.1
- **Date accepted:** 2026-10-26

**Context.** A bootable kernel needs a bare-metal target, linker configuration, and a way to build a bootable image.

**Options.** Built-in target (`x86_64-unknown-none`) on stable versus a custom target JSON (nightly `build-std`); linker script versus bootloader-provided layout; Cargo aliases versus an `xtask` crate versus scripts for image building; kernel as a workspace member versus a separate workspace.

**Evaluation criteria.** Works on stable Rust if possible; reproducibility; no root needed; keeps host checks working; clarity for contributors.

**Decision.**

- Target: built-in **`x86_64-unknown-none`** on **stable** Rust, with `-C relocation-model=static` set under `[target.x86_64-unknown-none]` in `.cargo/config.toml`.
- Linker: a project **linker script** placing the kernel at `0xffffffff80000000` and keeping the Limine request sections.
- Build: an **`xtask`** crate (`cargo xtask ...`) builds the kernel, assembles a hybrid BIOS/UEFI **ISO** with `xorriso` and `limine bios-install` (file timestamps pinned for reproducibility), and runs QEMU. The `pharos` CLI stays read-only.
- Layout: the kernel is a **workspace member**, excluded from host commands via `default-members` and `--exclude pharos-kernel`, and checked separately with `--target x86_64-unknown-none`. Target-independent kernel logic goes in a host-testable `no_std` library when there is some.

**Consequences.** CI and the documented host commands gain `--exclude pharos-kernel` when the kernel becomes `no_std` (M2.2). `rust-toolchain.toml` gains `targets = ["x86_64-unknown-none"]` at that point. The workspace `unsafe_code = "forbid"` lint is relaxed for the kernel crate only, as planned in P-001. If rust-analyzer handles the member poorly, fall back to a separate workspace through a new decision.

**Evidence.** The prototype built on stable Rust; kernel ELF and ISO were byte-identical across clean builds; with the kernel as a member, `--exclude` and `default-members` kept all host commands passing, while plain `--workspace` failed as predicted. Not yet tested: rust-analyzer behaviour. Details: [boot evaluation](../architecture/boot-evaluation.md#d-003--rust-target-linker-and-build-strategy).

## Open and proposed decisions

Each entry lists the milestone by which it must be decided. **Proposed** entries carry a recommendation but are not decisions until accepted. Decisions may be made earlier if evidence is available.

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
