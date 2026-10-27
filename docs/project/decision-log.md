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

**Consequences.** CI and the documented host commands gain `--exclude pharos-kernel` when the kernel becomes `no_std` (M2.2). `rust-toolchain.toml` gains `targets = ["x86_64-unknown-none"]` at that point. The workspace `unsafe_code = "forbid"` lint is relaxed for the kernel crate only, as planned in P-001. Editors need the same split: rust-analyzer's on-save check runs `scripts/ra-check.sh` (configured in `.vscode/settings.json`), because a plain `cargo clippy --workspace` builds the kernel for the host and reports false errors. If editor support degrades further, fall back to a separate workspace through a new decision.

**Evidence.** The prototype built on stable Rust; kernel ELF and ISO were byte-identical across clean builds; with the kernel as a member, `--exclude` and `default-members` kept all host commands passing, while plain `--workspace` failed as predicted. rust-analyzer, checked on 2026-10-27 (#9): with its default on-save check it showed two false errors in `kernel/src/main.rs` (duplicate `panic_impl`; unresolved `arch`); with `scripts/ra-check.sh` and the hardware layer compiled on any x86-64 build, the file is clean. Details: [boot evaluation](../architecture/boot-evaluation.md#d-003--rust-target-linker-and-build-strategy).

## Accepted decisions (M2.3)

### D-009: QEMU automation and debugging approach

- **Status:** Accepted
- **Needed by:** M2.3
- **Date accepted:** 2026-10-27

**Context.** M2.2 gave a manual boot check (`cargo xtask run`, success = QEMU exit status 33 through `isa-debug-exit`). M2.3 needs boots and kernel tests that run unattended, locally and in CI, with deterministic results.

**Options.** Test runner via Cargo `runner` configuration, an `xtask` harness, or scripts; exit signalling via QEMU `isa-debug-exit`, serial markers, or both; nightly `custom_test_frameworks` versus stable alternatives for in-kernel tests; GDB via QEMU's `-s -S` stub.

**Evaluation criteria.** Deterministic pass/fail; timeouts; works headless in CI; no root privileges; clear failure output; stable Rust; no new crates.

**Decision.**

1. **Pass rule:** a run passes only if QEMU exits with status 33 **and** the serial log contains an exact marker: `PHAROS: boot ok` for the boot check, `PHAROS: tests ok` for test kernels. Status 35, any other status, a missing marker, or a timeout fails.
2. **Timeout:** 60 seconds per boot under TCG (no KVM). A timeout kills QEMU and fails the run. No automatic retries.
3. **Logs:** serial output goes to `target/xtask/logs/<name>-<firmware>.log`. On failure the harness prints the end of the log, so CI shows it in the job output; no artifacts are uploaded.
4. **Firmware:** the boot check runs under UEFI (OVMF) and BIOS (SeaBIOS) on every run; test kernels run under UEFI only (the primary path, D-002).
5. **Kernel tests on stable Rust:** test kernels are `harness = false` test targets in `kernel/tests/`. `[target.x86_64-unknown-none] runner` in `.cargo/config.toml` points at `cargo xtask runner`, which wraps each binary in its own image and boots it headless. The linker script also applies to test targets (`rustc-link-arg-tests`). Limine request declarations are shared through a macro in the kernel library. `custom_test_frameworks` (nightly) is not used.
6. **One command:** `cargo xtask test` runs the boot check and all test kernels (`cargo test -p pharos-kernel --target x86_64-unknown-none --test '*'`; `--test '*'` keeps Cargo from building the library's unit tests for bare metal).
7. **Reproducibility:** CI builds the ISO twice and compares SHA-256 hashes.
8. **Scope of `scripts/check.sh`:** stays host-only and fast; QEMU tests run through `cargo xtask test` and their own CI job. GDB debugging stays as documented for `cargo xtask run --gdb`.

**Consequences.** Kernel tests need QEMU, OVMF, and xorriso locally and in CI. Each test kernel boots separately (about one second each under TCG locally), so test kernels should group related checks. BIOS-specific behaviour is covered only by the boot check until a test needs BIOS; revisit then. The 60-second timeout may need tuning once CI timings are known.

**Evidence.** Prototype on 2026-10-27 in a throwaway copy of `main` (not committed): a `harness = false` test kernel run with `cargo test -p pharos-kernel --target x86_64-unknown-none --test '*'` through a runner script that called `cargo xtask image --kernel <elf>` and booted QEMU headless.

- The nested `cargo xtask` call did not deadlock; Cargo releases its build lock before running test binaries. The test passed in about 1.3 seconds.
- A test kernel reporting failure produced QEMU status 35 and Cargo's `test failed` error (exit 1).
- A hung test kernel was stopped by the timeout and reported as a failure.

## Accepted decisions (M2.4)

### D-006: Interrupt controller and timer design

- **Status:** Accepted (controller part). The timer part stays Open until M2.6.
- **Needed by:** M2.4 (controller), M2.6 (timer)
- **Date accepted:** 2026-10-27

**Context.** M2.4 must receive one hardware interrupt, tested in QEMU under TCG (CI has no KVM). Limine (base revision 6) leaves the legacy PICs fully masked and the local APIC enabled in xAPIC mode with LINT0, LINT1, and the timer masked. Its higher-half direct map (HHDM) covers only memory-map regions, so the local APIC registers at `0xfee00000` are not mapped.

**Options.** Legacy 8259 PIC versus local APIC/IOAPIC (xAPIC or x2APIC); PIT, HPET, APIC timer, or TSC-deadline.

**Evaluation criteria.** Works in QEMU under TCG on UEFI and BIOS; SMP readiness; amount of code; precision needed by the scheduler.

**Decision (controller).**

1. Use the **local APIC in xAPIC mode** (memory-mapped registers). The first hardware interrupt is the **local APIC timer**, which needs no IOAPIC and no input.
2. Keep the legacy PICs masked (as Limine leaves them) and never use them.
3. Before M2.5 replaces Limine's page tables, M2.4 maps the single local APIC register page (uncached, no-execute) into Limine's page tables at `HHDM + 0xfee00000`, using page-table pages reserved statically in the kernel image (no frame allocator). M2.5 takes over this mapping.
4. x2APIC is not used for now: QEMU 8.2 under TCG cannot provide it. Revisit with SMP or a newer QEMU in CI.
5. The IOAPIC (device interrupts such as the keyboard) comes later and needs ACPI MADT parsing; it is not part of M2.4.

**Timer direction (Open, for M2.6).** Lean: local APIC timer, calibrated against the PIT (channel 2, polled, no interrupts) or the HPET; TSC-deadline where available.

**Consequences.** M2.4 gains a small page-mapping helper in the hardware layer (page-table writes are `unsafe` and stay in `arch::x86_64`). Interrupt handlers send EOI through the mapped register page. No legacy PIC code. SMP later needs per-CPU local APIC setup and the IOAPIC.

**Evidence.** Prototype test kernels on 2026-10-27 (not committed), booted in QEMU 8.2.2 (TCG, `-M q35`, default `qemu64` CPU):

- **x2APIC:** CPUID reports no x2APIC on the default CPU. `-cpu qemu64,+x2apic` prints "TCG doesn't support requested feature: CPUID.01H:ECX.x2apic", and `-cpu max` does not report it either. Ruled out for TCG.
- **PIC + PIT, local APIC as Limine left it:** the PIT fires (PIC IRR bit 0 set) but no interrupt reaches the CPU, matching the masked LINT0 (`0x10700` read back later: ExtINT, masked).
- **PIC + PIT, local APIC globally disabled through `IA32_APIC_BASE`:** still no interrupt; the run hung until the 60-second timeout. In QEMU, PIC interrupts still pass through the masked LINT0 entry. So the PIC needs local APIC register access as well and offers no shortcut.
- **xAPIC timer with a self-made mapping:** mapping the register page into Limine's page tables (1–2 new page-table pages) made the registers readable (version `0x50014`); the periodic timer delivered 50 interrupts to a handler, with 0 spurious ones, under **UEFI (PASS) and BIOS (QEMU status 33)**.

## Open and proposed decisions

Each entry lists the milestone by which it must be decided. **Proposed** entries carry a recommendation but are not decisions until accepted. Decisions may be made earlier if evidence is available.

### D-004: Kernel architecture and privilege boundaries

- **Status:** Open — initial direction recorded 2026-10-26 (M2.1). The final decision is due before M2.7.
- **Needed by:** initial direction at M2.1; final before M2.7

**Options.**

- **Microkernel** (reference point: seL4). The kernel provides only address spaces, threads and scheduling, IPC, capabilities, and interrupt delivery. Drivers, filesystems, networking, and AI services run as user-space processes.
- **Hybrid.** A microkernel structure with selected services (for example a filesystem or network stack) moved into the kernel for performance.
- **Monolithic with strict internal module boundaries.** One privileged address space. Isolation comes from module interfaces and Rust's type system. A variant confines all `unsafe` code to a small core and writes the rest of the kernel in safe Rust (reference point: the Asterinas "framekernel").

**Evaluation criteria.** TCB size; isolation of drivers and AI services; IPC performance; implementation complexity for a small team; testability in QEMU.

**Initial direction: capability-based microkernel, with `unsafe` confined to a small hardware layer inside it.**

Rationale:

- **Security goals match.** The project's core requirements are untrusted agents, inference isolated from privileged code, and no ambient authority. A microkernel enforces these with hardware address-space isolation, not just module discipline: a bug in a driver, filesystem, or inference service does not compromise the kernel.
- **Capabilities must be kernel-enforced anyway.** D-012 needs unforgeable, revocable access rights. A capability-based IPC kernel provides that as its central mechanism instead of adding it later.
- **Smallest TCB to review.** A small team can realistically review a small kernel, and all of the kernel's `unsafe` code.
- **Safe/unsafe split inside the kernel.** Borrowing the framekernel idea, hardware access (`asm`, port I/O, page tables, CPU tables) lives in one small module layer with safe interfaces, keeping the reviewed `unsafe` surface minimal.
- **Low cost now.** M2.2 to M2.6 (boot, interrupts, memory, timers, scheduling) are needed by every option. The direction mainly shapes how that code is structured, so committing to it early costs little.

Known costs: IPC overhead on hot paths (notably moving large model data to and from the inference service, which will need shared-memory capabilities, not message copies); more user-space infrastructure before the system is useful; harder debugging across processes.

**Evidence that would change the direction** (to be gathered by M2.7):

- IPC round-trip or shared-memory setup costs, measured in QEMU against a budget set in the M2.7 design document, that cannot be met for the planned inference data paths;
- user-space driver support (IRQ forwarding, I/O port and MMIO grants, DMA restrictions) proving too complex for the team at M2.9 scale. That would argue for a hybrid with specific, documented in-kernel drivers;
- a capability model that cannot express the agent permissions in D-012 without large in-kernel policy.

**Constraints on M2.2–M2.6 code**, so that the final decision is not boxed in:

1. Keep architecture-specific and `unsafe` code in a small hardware layer (for example `arch::x86_64`: port I/O, GDT/IDT, page tables, interrupt entry) with safe interfaces. Other kernel modules use those interfaces.
2. In-kernel drivers are limited to what the kernel itself needs: serial (debug output), interrupt controller, and timer. No storage, network, or display drivers in the kernel before D-004 is final.
3. Model address spaces as first-class objects from M2.5 (no single-global-address-space assumptions), and design the frame allocator so memory regions can later be granted and revoked (future memory capabilities).
4. Route interrupts through a dispatch layer so that IRQs can later be forwarded to user-space drivers.
5. Keep the scheduler generic over threads; do not assume all threads run in the kernel.
6. Avoid kernel-wide mutable global state, except documented singletons in the hardware layer; pass explicit handles where practical.
7. No filesystem, network-stack, or agent-related code in the kernel before D-004 is final.

### D-005: Memory-management strategy

- **Status:** Open
- **Needed by:** M2.5

**Options.** Physical frame allocator design (bitmap, free list, buddy); page-table management approach; kernel heap allocator; address-space layout; use of KASLR later.

**Evaluation criteria.** Correctness and testability; fragmentation; amount of `unsafe`; support for later isolation of agents and large model memory.

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
