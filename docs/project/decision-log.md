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

- **Status:** Accepted (controller part in M2.4, timer part in M2.6)
- **Needed by:** M2.4 (controller), M2.6 (timer)
- **Date accepted:** 2026-10-27 (both parts)

**Context.** M2.4 must receive one hardware interrupt, tested in QEMU under TCG (CI has no KVM). Limine (base revision 6) leaves the legacy PICs fully masked and the local APIC enabled in xAPIC mode with LINT0, LINT1, and the timer masked. Its higher-half direct map (HHDM) covers only memory-map regions, so the local APIC registers at `0xfee00000` are not mapped.

**Options.** Legacy 8259 PIC versus local APIC/IOAPIC (xAPIC or x2APIC); PIT, HPET, APIC timer, or TSC-deadline.

**Evaluation criteria.** Works in QEMU under TCG on UEFI and BIOS; SMP readiness; amount of code; precision needed by the scheduler.

**Decision (controller).**

1. Use the **local APIC in xAPIC mode** (memory-mapped registers). The first hardware interrupt is the **local APIC timer**, which needs no IOAPIC and no input.
2. Keep the legacy PICs masked (as Limine leaves them) and never use them.
3. Before M2.5 replaces Limine's page tables, M2.4 maps the single local APIC register page (uncached, no-execute) into Limine's page tables at `HHDM + 0xfee00000`, using page-table pages reserved statically in the kernel image (no frame allocator). M2.5 takes over this mapping.
4. x2APIC is not used for now: QEMU 8.2 under TCG cannot provide it. Revisit with SMP or a newer QEMU in CI.
5. The IOAPIC (device interrupts such as the keyboard) comes later and needs ACPI MADT parsing; it is not part of M2.4.

**Decision (timer, M2.6).**

1. **Scheduler tick: the local APIC timer, periodic, 100 Hz** (10 ms). Tickless and one-shot modes wait until a need appears. 1000 Hz lost ticks under host load in the prototype (below) and costs more emulation time under TCG.
2. **Calibration against PIT channel 2, polled** (gate on, speaker off, mode 0, no PIT interrupts), at boot with interrupts disabled. Five 10 ms runs; the **smallest** result counts, because a delay while the emulated CPU is descheduled can only inflate a run. The same runs calibrate the TSC.
3. **Uptime clock: the TSC**, converted with the calibrated rate (nanosecond resolution). Counting ticks drifts when ticks are lost; the TSC kept real time in every run. Timer-driven deadlines (sleep, time slices) have tick resolution (10 ms).
4. **Not used for now:** TSC-deadline mode and invariant-TSC checks (QEMU's default CPU under TCG reports neither), the HPET (needs ACPI table parsing, M2.9 or later). Real hardware without an invariant TSC may drift with CPU frequency changes; revisit with real-hardware testing.
5. **Tests** expect timing only within wide bounds (for example a 100 ms sleep takes at least 100 ms and less than 1 s) and check ordering, not exact durations. No automatic retries.

**Consequences.** M2.4 gains a small page-mapping helper in the hardware layer (page-table writes are `unsafe` and stay in `arch::x86_64`). Interrupt handlers send EOI through the mapped register page. No legacy PIC code. SMP later needs per-CPU local APIC setup and the IOAPIC.

**Evidence.** Prototype test kernels on 2026-10-27 (not committed), booted in QEMU 8.2.2 (TCG, `-M q35`, default `qemu64` CPU):

- **x2APIC:** CPUID reports no x2APIC on the default CPU. `-cpu qemu64,+x2apic` prints "TCG doesn't support requested feature: CPUID.01H:ECX.x2apic", and `-cpu max` does not report it either. Ruled out for TCG.
- **PIC + PIT, local APIC as Limine left it:** the PIT fires (PIC IRR bit 0 set) but no interrupt reaches the CPU, matching the masked LINT0 (`0x10700` read back later: ExtINT, masked).
- **PIC + PIT, local APIC globally disabled through `IA32_APIC_BASE`:** still no interrupt; the run hung until the 60-second timeout. In QEMU, PIC interrupts still pass through the masked LINT0 entry. So the PIC needs local APIC register access as well and offers no shortcut.
- **xAPIC timer with a self-made mapping:** mapping the register page into Limine's page tables (1–2 new page-table pages) made the registers readable (version `0x50014`); the periodic timer delivered 50 interrupts to a handler, with 0 spurious ones, under **UEFI (PASS) and BIOS (QEMU status 33)**.

Timer prototype on 2026-10-27 (not committed), same QEMU, under UEFI and BIOS with matching results:

- **CPUID** (default CPU, TCG): TSC present; no TSC-deadline, no invariant TSC; maximum leaf `0xd`, so no CPUID frequency leaves (`0x15`, `0x16`).
- **Idle host:** eight 10 ms PIT calibrations gave 62,518–62,583 APIC ticks (divided by 16) per ms after a first warm-up run of 63,085: QEMU's 1 GHz APIC timer clock, spread under 1%. TSC about 3.696 GHz. Periodic timer at the calibrated rate: 100 ticks at 100 Hz took 1,000 ms by the TSC, 1,000 ticks at 1000 Hz took 1,000–1,002 ms; twenty 50 ms PIT waits took 1,000 ms.
- **Host loaded** (40 busy loops on 20 cores): single calibrations read up to 29% high (80,495), the smallest of eight was correct (62,511). At 1000 Hz, 1,000 ticks took 1,216 ms by the TSC (ticks lost); at 100 Hz, 100 ticks took 1,000 ms; PIT waits stayed accurate (1,004 ms for 1 s).

## Accepted decisions (M2.5)

### D-005: Memory-management strategy

- **Status:** Accepted
- **Needed by:** M2.5
- **Date accepted:** 2026-10-27

**Context.** After M2.4 the kernel runs on Limine's page tables (in bootloader-reclaimable memory) plus one mapping of its own (the local APIC page, D-006). Its stack has a linker-made guard gap; the double-fault stack has none. There is no allocator. D-004 constraint 3 asks for address spaces as first-class objects and a frame allocator whose regions can later be granted and revoked.

**Options.** Frame allocator: bitmap, free list, or buddy. Page tables: keep extending Limine's, or build our own. Heap: own allocator or a crate. Layout: keep Limine's HHDM or choose our own; 4 KiB, 2 MiB, or 1 GiB pages for the direct map; KASLR now or later.

**Evaluation criteria.** Correctness and testability; fragmentation; amount of `unsafe`; support for later isolation of agents and large model memory.

**Decision.**

1. **Frame allocator: one bitmap per region** (one bit per 4 KiB frame), only over usable regions and, after reclaim, bootloader-reclaimable ones. The bitmaps live in frames taken from the largest usable region at boot. Single frames use a next-fit search; contiguous ranges a linear scan. Double frees and frees of unknown frames are errors. A bitmap makes it easy to hand out and take back exact ranges (future memory capabilities, D-004).
2. **One range allocator for both frames and heap.** The bitmap code finds `n` free units with a given alignment. It is plain safe Rust over slices, unit-tested on the host.
3. **Page tables: the kernel builds its own and switches CR3.** 4-level paging. An `AddressSpace` object owns a root table; the kernel half (PML4 entries 256–511) will be shared by later address spaces. Page-table frames come from the frame allocator and are reached through the direct map.
4. **Kernel layout:**
   - **Direct map:** keep Limine's HHDM offset, so addresses computed so far stay valid. Map usable, bootloader-reclaimable, executable, ACPI, and framebuffer regions; 2 MiB pages where both ends are aligned, 4 KiB at the edges; writable and no-execute.
   - **Kernel image:** at its link address, with text read+execute, rodata read-only+no-execute, and data/bss writable+no-execute, using linker symbols. Its physical base comes from Limine's executable-address request.
   - **Stacks:** the kernel stack and the double-fault stack each get an unmapped guard page (the double-fault stack moves to its own linker section after a gap, like the kernel stack).
   - **MMIO:** the local APIC stays at `HHDM + physical address`, uncached, now mapped through the mapper; the M2.4 stopgap tables go.
   - **Heap:** a fixed virtual window at `0xffff_c000_0000_0000`, above any direct map the kernel accepts (physical memory must stay below 64 TiB; checked at boot).
   - KASLR is deferred.
5. **Reclaim:** copy everything the kernel still needs from Limine responses (memory map, HHDM offset, bootloader and firmware info, executable address) into kernel memory early in boot, switch to the kernel's own tables, then add the bootloader-reclaimable regions to the frame allocator. Limine responses are not used after that point.
6. **Heap: own allocator, no crate.** A bitmap over 16-byte units in a fixed 4 MiB heap at first (growth later), using the shared range allocator; sizes come from `Layout` on free, so the heap keeps no headers in allocated memory. Its lock disables interrupts while held, like the console.
7. **`unsafe` boundaries:** page-table and CR3 code stays in `arch::x86_64`. One new module, `mm::raw`, may use `unsafe` for raw memory: turning direct-map ranges into slices, the `GlobalAlloc` implementation, and the lock cell that guards allocator state. Allocator logic stays safe Rust. This adds `mm::raw` to the AGENTS.md list (a reviewed design change, made by this decision).
8. **Out of memory:** the frame allocator returns an error. Heap exhaustion returns null to Rust's allocation machinery, which on stable `no_std` calls the panic handler with `memory allocation of N bytes failed`; acceptable for now (verified in the prototype).
9. **Testing:** allocator and range logic host-tested (Miri optional, local only, since it needs nightly); test kernels for frames, mappings, permissions, guard pages, reclaim, and heap.

**Consequences.** Every kernel memory structure (bitmaps, page tables, heap) is reached through the direct map, so physical memory beyond what the direct map covers cannot be used; fine for now. Bitmap scans are linear; acceptable at today's sizes and replaceable behind the same interface. The heap's fixed size caps kernel allocations until growth is added. A second module joins the `unsafe` list.

**Evidence.** Prototype test kernel on 2026-10-27 (not committed), QEMU 8.2.2, TCG, `-m 256M`, default CPU:

- **Memory map:** 32 entries under UEFI (10 usable regions, the largest 135 MiB) and 20 under BIOS; reserved regions reach up to 1 TiB (`0x0100_0000_0000`). A single bitmap over the whole physical range would need 32 MiB; per-region bitmaps for about 250 MiB of usable and reclaimable memory need about 8 KiB.
- **Limine responses** are in bootloader-reclaimable memory (the memory-map response was at `HHDM + 0xa011000`, inside a reclaimable region), so they must be copied before reclaim.
- **CPU:** no 1 GiB pages (CPUID `0x80000001` EDX bit 26 clear); NX supported and enabled (`EFER = 0xd00`). Hence 2 MiB pages for the direct map.
- **Out of memory:** with a global allocator that always fails, `Vec::with_capacity(64)` reached the kernel's panic handler with `memory allocation of 64 bytes failed` (QEMU status 35).
- **HHDM offset** was `0xffff_8000_0000_0000` under UEFI and BIOS.

## Accepted decisions (M2.6)

### D-013: Scheduling model

- **Status:** Accepted
- **Needed by:** M2.6
- **Date accepted:** 2026-10-27

**Context.** M2.6 needs several kernel tasks running interleaved, preemptively, with a test that a busy task cannot starve others. The kernel has one CPU in use, a heap, a frame allocator, its own page tables, interrupt-safe locks (`IrqMutex`), and a periodic timer (D-006). D-004 constraint 5 asks that the scheduler stay generic over threads and not assume every thread runs in the kernel; constraint 6 limits global mutable state to documented singletons.

**Options.** Cooperative only; preemptive round-robin; priority or fair-share scheduling. Context switch in `global_asm!` or with naked functions (stable since Rust 1.88, above the 1.85 minimum). Switching inside the interrupt handler or by deferring to a return path.

**Evaluation criteria.** Meets the M2.6 acceptance criteria; little code and little `unsafe`; testable in QEMU under TCG; does not block user threads (M2.7) or SMP later.

**Decision.**

1. **Preemptive round-robin, one CPU, fixed time slice of one tick** (10 ms at 100 Hz). One ready queue, first in first out. No priorities until a need appears.
2. **Task = kernel thread:** an ID, a state (ready, running, sleeping, exited), a saved stack pointer, and its own kernel stack. Stacks are 16 KiB in a dedicated virtual window (`0xffff_c800_0000_0000`), each with an unmapped guard page below, built from frame-allocator frames and returned on reap. The scheduler sees only the saved kernel context. A user thread (M2.7) will also run on its own kernel stack when it enters the kernel, so it fits without scheduler changes; address-space switching joins then.
3. **Context switch:** a `global_asm!` routine in `arch::x86_64` pushes the callee-saved registers (`rbx`, `rbp`, `r12`–`r15`), stores the stack pointer, loads the next one, pops, and returns. The kernel is soft-float, so there is no FPU or SSE state. A new task starts in a small trampoline that enables interrupts, calls its entry function, and exits when it returns.
4. **Preemption:** the timer handler sends EOI and then, when the slice is used up, switches tasks from inside the handler. The interrupted task's interrupt frame stays on its own stack until it is switched back in and returns with `iretq`. `yield_now`, `sleep`, and exit switch the same way with interrupts disabled.
5. **Locking rules:** switches happen with interrupts disabled and **no lock held**. The scheduler takes its ready-queue lock (`IrqMutex`) to pick the next task, releases it, then switches. A debug check counts held `IrqMutex` guards and fails a switch while any is held. Interrupts stay disabled only inside lock sections and the switch itself.
6. **Idle task:** runs only when nothing else is ready; it halts with interrupts enabled (`sti; hlt`).
7. **Exit:** an exited task cannot free the stack it runs on; the next switch reaps it (stack frames back to the frame allocator, guard mapping removed).
8. **Sleep:** a deadline in ticks; the timer tick moves due sleepers back to the ready queue (10 ms resolution).
9. **The scheduler is a documented singleton** (one CPU) behind `IrqMutex`, allowed by D-004 constraint 6. Queue logic is safe Rust and host-tested; only the switch routine and stack mapping use `unsafe`, in the existing hardware layer.

**Consequences.** Every task costs 16 KiB plus a 4 KiB virtual guard page. A task that disables interrupts for long blocks preemption; documented as a rule, not enforced. Holding a lock across a switch is caught only in debug builds. SMP needs per-CPU queues and a decision of its own. M2.7 adds address-space switching and the TSS ring-0 stack per task.

**Evidence.** The D-006 timer prototype (100 Hz periodic ticks arrive at the calibrated rate even with the host loaded). The context-switch routine follows the System V AMD64 calling convention (callee-saved registers), so the switch is an ordinary function call on both sides.

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
