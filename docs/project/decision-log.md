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
2. **Task = kernel thread:** an ID, a state (ready, running, sleeping, exited), a saved stack pointer, and its own kernel stack. Stacks are 16 KiB *(32 KiB since 2026-10-28, #63: amended with maintainer approval after debug builds of the M2.10 `call` path overflowed 16 KiB; the guard area grew with them)* in a dedicated virtual window (`0xffff_c800_0000_0000`), each with an unmapped guard page below, built from frame-allocator frames and returned on reap. The scheduler sees only the saved kernel context. A user thread (M2.7) will also run on its own kernel stack when it enters the kernel, so it fits without scheduler changes; address-space switching joins then.
3. **Context switch:** a `global_asm!` routine in `arch::x86_64` pushes the callee-saved registers (`rbx`, `rbp`, `r12`–`r15`), stores the stack pointer, loads the next one, pops, and returns. The kernel is soft-float, so there is no FPU or SSE state. A new task starts in a small trampoline that enables interrupts, calls its entry function, and exits when it returns.
4. **Preemption:** the timer handler sends EOI and then, when the slice is used up, switches tasks from inside the handler. The interrupted task's interrupt frame stays on its own stack until it is switched back in and returns with `iretq`. `yield_now`, `sleep`, and exit switch the same way with interrupts disabled.
5. **Locking rules:** switches happen with interrupts disabled and **no lock held**. The scheduler takes its ready-queue lock (`IrqMutex`) to pick the next task, releases it, then switches. A debug check counts held `IrqMutex` guards and fails a switch while any is held. Interrupts stay disabled only inside lock sections and the switch itself.
6. **Idle task:** runs only when nothing else is ready; it halts with interrupts enabled (`sti; hlt`).
7. **Exit:** an exited task cannot free the stack it runs on; the next switch reaps it (stack frames back to the frame allocator, guard mapping removed).
8. **Sleep:** a deadline in ticks; the timer tick moves due sleepers back to the ready queue (10 ms resolution).
9. **The scheduler is a documented singleton** (one CPU) behind `IrqMutex`, allowed by D-004 constraint 6. Queue logic is safe Rust and host-tested; only the switch routine and stack mapping use `unsafe`, in the existing hardware layer.

**Consequences.** Every task costs 16 KiB (32 KiB since #63) plus a virtual guard area. A task that disables interrupts for long blocks preemption; documented as a rule, not enforced. Holding a lock across a switch is caught only in debug builds. SMP needs per-CPU queues and a decision of its own. M2.7 adds address-space switching and the TSS ring-0 stack per task.

**Evidence.** The D-006 timer prototype (100 Hz periodic ticks arrive at the calibrated rate even with the host loaded). The context-switch routine follows the System V AMD64 calling convention (callee-saved registers), so the switch is an ordinary function call on both sides.

## Accepted decisions (M2.7)

### D-004: Kernel architecture and privilege boundaries

- **Status:** Accepted (final decision, issue #36); initial direction recorded 2026-10-26 (M2.1)
- **Needed by:** initial direction at M2.1; final before M2.7
- **Date accepted:** 2026-10-27

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

**Decision (final, M2.7).** Confirm the direction: **a capability-based microkernel, with `unsafe` confined to a small hardware layer inside it.**

1. **In the kernel:**
   - address spaces;
   - threads and scheduling (D-013);
   - IPC;
   - capabilities;
   - interrupt delivery (to user-space drivers from M2.9);
   - the timer (D-006);
   - the interrupt controller;
   - the serial debug console.

   Nothing else: drivers, filesystems, networking, inference, and agents run as user processes (constraints 2 and 7 stay in force).
2. **`unsafe` boundary:** only `arch::x86_64`, `limine`, and `mm::raw` may use `unsafe` (AGENTS.md). User-mode entry, system calls, and page-table changes for processes join the hardware layer; process, IPC, and capability logic is safe Rust.
3. **IPC budget**, judged on the development machine with QEMU and KVM (`-cpu host`), release build. QEMU under TCG is for correctness only: its timings do not reflect hardware.
   - **Message round trip:** call and reply between two user processes with a small message must take **at most 2 µs**.
   - **Shared memory:** granting a 1 MiB region to another process must take **at most 100 µs**.
   - M2.7 (#41) measures the message round trip. The shared-memory path is measured when it exists (inference, M3.x).
   - Missing either budget is the evidence that reopens this decision (see above).
4. **Still open by design:** the user-space driver model (D-008, M2.9) remains the other trigger for revisiting.

**Consequences.** M2.7 builds processes, system calls, and IPC as the main kernel interface and designs them in `syscalls-ipc.md` (#37). Large data (models, buffers) must move through shared-memory capabilities, not message copies. Debugging spans processes. Constraints 1–7 now apply as rules for all kernel code, not only M2.2–M2.6.

**Evidence (final decision).** Prototype test kernel on 2026-10-27 (not committed). It added user segments, user pages, `syscall`/`sysret` and `int 0x80` entry, and ring 3 entry, and ran in QEMU 8.2.2 on an Intel Core i9-10900K. Round trips are averages over 100,000 calls; the task switch over 20,000 round trips:

| Measurement | KVM, `-cpu host`, release | TCG, default CPU, release |
| --- | --- | --- |
| `syscall`/`sysret`, empty handler | 18 ns | 74 ns |
| `syscall`/`sysret` with stack switch, caller-saved registers saved, Rust call | 21 ns | 134 ns |
| `int 0x80`/`iretq` | 138 ns | 397 ns |
| Kernel task switch round trip (two `yield_now`) | 145 ns | 1,275 ns |

Estimate for one IPC round trip:
- two system calls (about 40 ns);
- two task switches (about 150 ns);
- two address-space switches, unmeasured: a CR3 write without PCID flushes the TLB, assumed a few hundred ns each;
- copying a small message.

That is under 1 µs, half the budget.

- **User data access:** a ring 3 read of kernel data faulted with error code `0x5` (user mode, protection violation) and `CS = 0x33`, and the kernel continued into its fault handler. UEFI and BIOS behaved the same.
- **SMEP and SMAP:** QEMU's default CPU under TCG (used by CI) reports neither. `-cpu max` under TCG and `-cpu host` under KVM report both. Limine leaves CR4 at `0x20`, so neither is enabled.
- **Timing under TCG is noisy:** the debug build's empty `syscall` measured faster (43 ns) than the release build.

**Measured against the budget (M2.7, #41, 2026-10-27).** The implemented IPC (synchronous endpoints, D-014) was measured between two user processes, as call and reply with 8-byte messages: ping sends and receives, pong receives and sends.
- **Steady state:** 1.97–2.00 µs per round trip under KVM, release build, i9-10900K (three runs of 100,000 round trips). This meets the 2 µs budget, with no margin.
- **Global kernel pages (added for this):** without them, the 1,000-round-trip test took 2.9 µs per trip; with them, 2.65 µs (both figures include starting the process).
- **If later work pushes it over:** see `syscalls-ipc.md` (open questions).
- **Measured again (#81, 2026-10-31):** it had risen to 2.29–2.32 µs by M3.0. One locked instruction fewer per lock and unlock brought it to medians of 1.87–1.92 µs, every run at or under 2.00 µs; `cargo xtask bench-ipc` now measures it with one command. The budget stands.

### D-014: IPC model and system-call mechanism

- **Status:** Accepted
- **Needed by:** M2.7
- **Date accepted:** 2026-10-27

**Context.** D-004 makes IPC and capabilities the kernel's main interface, with an IPC round trip of at most 2 µs under KVM. D-012 asks for capabilities that move only over IPC. M2.7 needs a system-call entry and one IPC primitive that untrusted processes cannot use to exhaust kernel memory. Design details are in [syscalls-ipc.md](../architecture/syscalls-ipc.md).

**Options.**
- **System-call entry:** `syscall`/`sysret` or a software interrupt (`int 0x80`).
- **IPC:**
  - synchronous endpoints, where sender and receiver meet;
  - asynchronous queues, where the kernel buffers messages;
  - shared-memory rings set up through the kernel.

**Evaluation criteria.** Bounded kernel memory under untrusted use; round-trip cost against the D-004 budget; amount of code and `unsafe`; room for capability passing and a later shared-memory path.

**Decision.**

1. **`syscall`/`sysret`.** Arguments go in registers. The status returns in `rax` and the value in `rdx`. The entry switches to the thread's kernel stack through a scratch slot (one CPU). The stub checks that the return address is canonical before `sysret` (falling back to `iretq`), and the last user page is never mapped (CVE-2012-0217).
2. **Synchronous endpoints.**
   - A message is at most 256 bytes plus one capability.
   - `send` copies the message into a per-thread kernel buffer and blocks until a receiver takes it; `receive` blocks until a message arrives.
   - Queues are first in first out per endpoint. Each thread waits on at most one endpoint, so kernel memory for IPC is bounded by the number of threads.
3. **Large data uses shared-memory capabilities later,** not bigger messages.
4. **No combined `call`/reply in M2.7.** Add it if round-trip measurements need fewer system calls.

**Consequences.**
- Senders block, so a server that never receives stalls its clients. Timeouts or non-blocking variants come when a service needs them.
- Two system calls per direction (send and receive) until `call` exists.
- SMP will need per-CPU entry state (`swapgs`).

**Evidence.** The D-004 prototype (2026-10-27, KVM, release build, i9-10900K):
- `syscall`/`sysret` with a stack switch, register save, and Rust call: 21 ns;
- `int 0x80`/`iretq`: 138 ns;
- task switch round trip: 145 ns.

Two system calls per direction plus two task switches and two address-space switches leave the estimated round trip well under 2 µs.

## Accepted decisions (M2.8)

### D-007: Filesystem and persistent storage

- **Status:** Accepted
- **Needed by:** M2.8
- **Date accepted:** 2026-10-27

**Context.**
- The kernel is a capability-based microkernel (D-004). Processes get kernel objects only through capabilities (D-012 direction), and IPC carries 256 bytes plus one capability (D-014).
- There is no program loader and no shared memory yet, so a user-space filesystem server could not be loaded from storage.
- There are no device drivers yet; device interrupts and PCI come with M2.9 (D-008).
- Limine can load files from the boot image as modules. The kernel already maps module memory read-only and no-execute in the direct map, and never gives it to the frame allocator (memory type "executable and modules").
- A storage image is untrusted input to the kernel.

**Options.**
- **Storage source:** a Limine module used as a read-only RAM disk; or virtio-blk, which needs PCI, interrupts or polling, and DMA.
- **Format:**
  - FAT: interoperable, but large, hard to validate, and without checksums;
  - ext2: simpler, but built for writing and without checksums;
  - a small custom read-only format with checksums.
- **Placement:** the filesystem in the kernel for now; or a user-space server from the start, which needs program loading, shared memory, and bulk IPC first.
- **Writes:** none in M2.8; or now, which needs a journal or copy-on-write.

**Evaluation criteria.** Crash consistency; simplicity; tooling to build images on the host; fit with capability-based access control; how safely the kernel can parse an untrusted image.

**Decision.**

1. **A Limine module is the first block device:** a read-only RAM disk behind a block-device trait. virtio-blk implements the same trait in M2.9.
2. **A small custom read-only format:**
   - a header, a directory table, and file data;
   - CRC-32 checksums on the header, the directory, and each file;
   - fixed limits (entries, name length, sizes);
   - a version field.

   CRC-32 detects corruption; it does not prove where an image came from. Authenticating images belongs with secure boot, later.
3. **One parser for the kernel and the host:** a new `no_std` crate with `unsafe` forbidden and no dependencies. It builds and validates images. It is used by the kernel and by the host tool (`cargo xtask`), and fuzzed on the host. Every check runs before any data is used.
4. **The filesystem runs in the kernel for M2.8,** behind the block-device trait. It moves to a user-space server once program loading and shared memory exist.
5. **Processes reach files only through capabilities:** a filesystem capability opens files; a file capability carries a `READ` right. Both pass over IPC and can be revoked like endpoints.
6. **Read-only in M2.8.** The direction for writes is copy-on-write: new blocks are written first, then the root is switched in one step. The design comes before any write code.

**Consequences.**
- Images need our own host tool and inspector, since no existing tool reads the format.
- The parser joins the kernel's trusted computing base until it moves to a server. Safe Rust, fixed limits, and fuzzing keep that risk small.
- Files are limited to what fits in the boot image and in memory until virtio-blk.
- Moving the filesystem out of the kernel later changes the kernel side only; the capability interface processes use stays the same.

## Accepted decisions (M2.9)

### D-008: Driver strategy

- **Status:** Accepted
- **Needed by:** M2.9
- **Date accepted:** 2026-10-27

**Context.**
- D-004 puts drivers in user processes. The kernel provides address spaces, threads, IPC, capabilities, and interrupt delivery. D-004 names user-space driver support proving too complex as the trigger for a documented hybrid.
- The kernel has ring 3 processes with capabilities and IPC (M2.7), and a read-only filesystem in the kernel (M2.8, a D-007 exception until program loading exists). User programs are small assembly test programs; there is no program loader.
- QEMU 8.2 (local and CI) has modern virtio-blk with MSI-X and an emulated Intel IOMMU (`intel-iommu`).

**Options.**
- **Where drivers run:** in user space, per D-004; in the kernel for now; or a documented hybrid.
- **Device set:** virtio-blk only, or also virtio-net, a framebuffer, or a keyboard.
- **Discovery:** legacy PCI configuration through ports `0xCF8`/`0xCFC`, or PCIe ECAM through the ACPI MCFG table.
- **Device interrupts:** MSI-X (devices write to the local APIC), or the IOAPIC with ACPI routing.
- **DMA isolation:** an IOMMU now, or kernel-allocated pinned buffers with the IOMMU as a tracked limit.

**Evaluation criteria.** TCB size; DMA isolation (IOMMU availability); performance; effort.

**Decision.**

1. **Drivers run in user space.** The kernel adds only what drivers need, each as a capability:
   - a device (one PCI function);
   - its interrupts;
   - mappings of its MMIO BARs;
   - DMA buffers.
2. **virtio-blk is the only driver in M2.9:** the modern PCI transport over MMIO, read-only. Its gate test reads a disk image built on the host and mounts a `pharos-fs` image in user space with the same parser the kernel uses.
3. **Rust user programs:** a `no_std` user crate and system-call library, and a kernel loader for static ELF64 executables, loaded from the boot filesystem. The ELF parser is safe Rust and fuzzed.
4. **Discovery through PCI configuration ports** `0xCF8`/`0xCFC`, in the hardware layer. ECAM can follow when a device needs extended configuration space.
5. **Device interrupts through MSI-X.** The interrupt handler only records the interrupt and wakes the driver's thread; driver code never runs in the handler. The IOAPIC waits for a device that needs it.
6. **DMA through kernel-allocated, pinned buffers.** The driver learns their physical addresses. **No IOMMU in M2.9:** a driver can program its device to reach any physical memory. This is a recorded limit, to be evaluated before real-hardware use.

**Consequences.**
- The kernel gains a program loader, PCI enumeration, MSI-X, and new capability types and system calls. These are its new trusted code and attack surface; the M2.9 security review covers them.
- Until there is an IOMMU, a driver process is effectively trusted with all memory through its device. Drivers stay small, and only the kernel starts them.
- Rust user programs unlock moving the M2.8 filesystem out of the kernel later.
- If user programs or device capabilities prove too large for M2.9, D-004's hybrid fallback applies: a documented, reviewed in-kernel driver.

### D-015: Network stack and service model

- **Status:** Accepted
- **Needed by:** M2.10
- **Date accepted:** 2026-10-28

**Context.**
- D-004 keeps networking out of the kernel. M2.9 gave user-space drivers their devices through capabilities and a shared virtio transport (`pharos_programs::virtio`).
- Missing for M2.10:
  - a network driver and stack;
  - a way for a process to start processes (only the kernel does today);
  - a service manager that starts services in order and reports failures.
- IPC is synchronous, with 256-byte messages plus one capability, and carries no sender identity.
- QEMU user-mode networking (slirp) needs no host privileges, so it runs in CI. It provides the guest address `10.0.2.15` and the gateway (and host) `10.0.2.2`.
- `smoltcp` (0BSD) is the usual `no_std` stack. Its releases 0.13 and 0.14 need Rust 1.91; only 0.12 builds on the project's minimum, 1.85 (checked with `cargo info`, 2026-10-28).

**Options.**
- **Stack:**
  - our own minimal stack: Ethernet, ARP, IPv4, ICMP echo, and UDP;
  - `smoltcp` 0.12, which includes TCP but pins an old release or raises the minimum Rust.
- **Placement:** the stack in the virtio-net driver's process, or in a separate process. The second needs shared memory (a new kernel feature) or many messages per frame.
- **Client identity:** one endpoint per client, or IPC badges (a kernel and IPC change).
- **Addresses:** static slirp addresses, or DHCP.
- **Service start:** the kernel starts `init`, which starts the rest; or the kernel starts each service from a fixed list.

**Evaluation criteria.** TCB size (nothing new in the kernel beyond process creation); attack surface; dependency cost and the minimum Rust; effort; whether TCP is needed before Phase 3.

**Decision.**

1. **Our own minimal stack:** Ethernet II, ARP with a bounded cache, IPv4 without fragments, ICMP echo, and UDP. **No TCP in M2.10.** Every parser is safe `no_std` Rust and fuzzed on the host. `smoltcp` is re-evaluated when TCP is needed, together with the minimum Rust.
2. **One network service:** the stack runs in the virtio-net driver's process, so frames never cross IPC. Clients exchange datagrams of at most one IPC message with it.
3. **Network access is a capability:** each client holds a `SEND` capability on the network service's one endpoint, with a **badge** set by `init` that names the UDP port it may use. The kernel delivers the sender's badge with every message, so the service tells clients apart without trusting message contents. *(Amended 2026-10-28, #59, approved by the maintainer. Originally one endpoint per client with no badges. The design found that this needs a call that waits on several endpoints at once, a larger and more race-prone kernel change than a badge field. Interrupts and child exits reach the same blocking point as endpoint notification bits; see [services.md](../architecture/services.md).)*
4. **Static slirp addresses:** `10.0.2.15/24`, gateway `10.0.2.2`. There is no DHCP.
5. **The kernel starts `init`:** `bin/init` from the root filesystem, with the boot capabilities. `init` starts the services in a fixed order, each with only the capabilities it needs, and reports every failure. This needs new system calls to start a process and wait for it; the program file is passed as a file capability.
6. **The test endpoint is on the host:** `cargo xtask` runs a UDP echo server bound to localhost and reached through slirp, and the tests also ping the slirp gateway. No root and no TAP devices.

**Consequences.**
- The kernel gains process creation from user space, its only new trusted code in M2.10; the M2.10 security review covers it.
- The network service is a single point of trust for networking. A bug in it affects only networking, not the kernel or other processes.
- Without TCP, Phase 2 networking is datagrams only. Phase 3 needs (for example model downloads, if any) decide whether TCP or `smoltcp` comes next.
- Badges, endpoint notifications, `call`, and a non-blocking `send` extend the D-014 IPC model ([services.md](../architecture/services.md), [networking.md](../architecture/networking.md)). Each service waits at one blocking point.

## Accepted decisions (M3.0)

### D-016: User execution environment: SIMD state, user memory, and timeouts

- **Status:** Accepted
- **Needed by:** M3.0
- **Date accepted:** 2026-10-29 (issue #71)

**Context.** Phase 2 user programs cannot use x87, SSE, or AVX (`CR0.EM` makes them fault, because the kernel saves no vector state), get a 256 KiB bump heap that never frees, and have no timeouts on IPC or interrupt waits. An inference runtime needs all three.

**Options to evaluate.** Vector state: eager save and restore on every switch, or lazy (on first use after a switch); `XSAVE`/`XSAVEOPT` or `FXSAVE`; which instruction sets to expose (SSE2 baseline, AVX2 if present). User memory: an anonymous-memory map/unmap system call with a per-process page limit, or memory capabilities that a parent grants. Timeouts: a deadline argument on `receive`, `call`, and `irq_wait`, or a separate timer object that sends a notification.

**Evaluation criteria.** No register state visible across processes (including after a kill); context-switch cost measured; every limit checked before allocation; timeouts that cannot leave a half-delivered message; the smallest change to the M2.7 boundary.

**Evidence (2026-10-29, rustc 1.99.1).**

- Building for `x86_64-unknown-none` with `-C target-feature=+sse,+sse2` compiles, but the engine's inner loops still call software routines (`__mulsf3`, `__addsf3`: 24 calls, no SSE instructions): the target also enables LLVM's `soft-float`. Adding `-soft-float` produces SSE code (63 SSE float and 28 integer SIMD instructions, no software calls) but the compiler warns that disabling `soft-float` "will become a hard error in a future release".
- A `no_std`, `no_main` program built for `x86_64-unknown-linux-gnu` and linked with `-nostartfiles -nostdlib -static` and our own linker script is a static ELF with no dynamic section, uses SSE float and integer SIMD instructions, and needs only `memcpy` (and the other memory functions) and a `rust_eh_personality` symbol from us; nothing else from a C library.
- `libm` 0.2.16: MIT, in `rust-lang/compiler-builtins`, no runtime dependencies, minimum Rust 1.63.

**Decision.**

1. **User programs are built for `x86_64-unknown-linux-gnu` as `no_std` static programs** (hard-float calling convention, SSE2 baseline): `-C relocation-model=static` and `-nostartfiles -nostdlib -static -T user.ld`, set by `cargo xtask`. `pharos-user` supplies `memcpy`, `memmove`, `memset`, `memcmp`, and `bcmp` (with `rep movsb`/`rep stosb`, so the compiler cannot turn them into calls to themselves) and an empty `rust_eh_personality`, all in its `syscall` module. No C library is linked, so any accidental libc reference fails at link time. The kernel stays on `x86_64-unknown-none` (soft-float). Rejected: SSE flags on `x86_64-unknown-none` (no effect while `soft-float` is forced, and disabling it is being phased out); a custom target or `x86_64-unknown-linux-none` (both need nightly `build-std`); the UEFI target (PE files, not ELF).
2. **Vector state is saved eagerly on every thread switch**, never lazily: lazy switching (`CR0.TS` and a fault on first use) leaked state between processes on affected CPUs (LazyFP, CVE-2018-3665) and adds a fault path. `XSAVE` with `XCR0` = x87, SSE, and AVX when the CPU has `XSAVE` and AVX; `FXSAVE` otherwise. AVX-512 is not enabled. One save area per thread, 64-byte aligned, sized from CPUID leaf 0xD (refused above 4 KiB). A new process starts from a clean image (`FNINIT` state, `MXCSR` 0x1F80 with all exceptions masked, zero registers). The kernel never uses vector registers, so system calls and interrupts save nothing. SIMD floating-point exceptions (vector 19) and x87 errors kill the process. `CR0.EM` cleared, `CR0.MP` and `NE` set; `CR4.OSFXSR`, `OSXMMEXCPT`, and `OSXSAVE` when used. Tested on QEMU's default CPU (the `FXSAVE` path) and `-cpu max` (`XSAVE` with AVX).
3. **User memory: `mem_map(len)` and `mem_unmap(addr, len)`**: anonymous, zeroed, writable, non-executable, page-granular memory at an address the kernel chooses in a per-process region; unmap only of whole earlier mappings. Frames are allocated when mapped (no demand paging, so no new page-fault path). **A per-process page limit**, set by the creator at `spawn` and at most the creator's own; checked before any frame is allocated. Limits are not carved out of the creator's (that is M3.5, as the M2.10 review recorded). `pharos-user`'s allocator: power-of-two size classes up to 32 KiB from 64 KiB chunks, and larger allocations mapped directly and unmapped when freed, so large buffers (a model file, the key/value cache) return to the kernel. It replaces the bump heap. Rejected: memory capabilities granted by a parent (more objects now; revisit with M3.5 quotas).
4. **Timeouts are an argument**, relative, in microseconds (`u64::MAX`: wait forever; 0: do not block), on `receive`, `call`, and `irq_wait`; a new error `TIMED_OUT`; a `sleep` system call. Resolution is one timer tick, rounded up, so no wait ends early. Expiry removes the waiter with interrupts off, so a message delivered before expiry is returned and one arriving after stays queued; a reply to a timed-out `call` meets the revoked one-shot reply capability (`REVOKED` at the server). Rejected: timer objects (another object type; can be added for periodic timers later).
5. **Math functions from `libm`** (MIT), in user space only, behind `pharos-infer`'s `Math` trait; the dependency is reviewed under AGENTS.md section 6 in #74. Its results are compared with the host's through `pharos-infer`'s output. Rejected: our own implementations (more code and tests for accuracy `libm` already provides).

### D-017: Writable persistent storage and audit integrity

- **Status:** Accepted
- **Needed by:** M3.0 (storage), M3.4 (audit records)
- **Date accepted:** 2026-10-29 (issue #72)

**Context.** D-007 chose a read-only RAM disk and named copy-on-write as the future write strategy. Durable tasks (M3.3), the audit trail (M3.4), the knowledge service (M3.8), and model files need writable storage that survives crashes.

**Options to evaluate.** Extending the `pharos-fs` format with copy-on-write, or a separate log-structured store for records; a storage service in user space over the virtio-blk driver, or in the kernel; append-only audit records with a hash chain, or with periodic signed checkpoints.

**Evaluation criteria.** Crash consistency proven by fault injection; checksums on everything read; one safe parser shared with the host tool; tamper evidence for audit records; defined behaviour when storage is full or failing (consequential actions refused rather than unaudited); capability-only access.

**Findings that shape the choice.**

- **Bulk data does not fit IPC.** A 676 MB model file in 256-byte messages is about 2.6 million messages: seconds under KVM, minutes under the emulation CI uses. Giving the inference service its own disk device instead would hand DMA, and with no IOMMU all of memory, to the process that parses untrusted model files. A way to share memory between processes is needed.
- **Precedent:** D-015 put the network stack in the virtio-net driver's process, so one process owns the device and parses what comes from it; the same shape fits storage.
- **Media are untrusted** (D-007): a disk can be corrupted, swapped, or edited offline, so every block read is checked, and the parser is shared with the host tool and fuzzed.

**Decision.**

1. **A new store, `pharos-store`, separate from `pharos-fs`.** `pharos-fs` stays the packed read-only image for boot modules. The store is a `no_std`, safe-Rust crate (no dependencies) used by the storage service and by `cargo xtask` to build and inspect images.
2. **Format: copy-on-write with two roots.**
   - 4 KiB blocks. Blocks 0 and 1 are superblock slots, each with a magic value, the format version, a generation number, the location and checksum of the index, and its own checksum.
   - Live data is never overwritten: a commit writes new data blocks, then a new index (every object with its extents, length, and checksum), then the superblock in the older slot with the next generation.
   - Blocks referenced by either of the two newest generations stay intact, so the store can always fall back one generation; all other blocks are free and reused.
   - Limits fixed in the format (for example 4,096 objects, paths of at most 104 bytes as in `pharos-fs`).
3. **Objects:** named files written whole (create or replace atomically, any size; model files are stored this way, normally by the host tool when the image is built), and **append-only streams** of records (audit, task logs).
4. **Crash consistency:** write data, flush (virtio-blk `FLUSH`), write the index, flush, write the superblock, flush. On mount, the newest superblock whose index and checksums verify wins; otherwise the previous one. Every block read is checksummed (CRC-32, as `pharos-fs`). Proven two ways: a **host test** that cuts the write sequence at every point (including torn blocks) and mounts, expecting the old or the new state and never a mix; and a **QEMU fault-injection test** that kills QEMU at random points while writing, reboots, and checks the same.
5. **Audit records:** each stream record carries a SHA-256 hash chained to the previous one (our own SHA-256, checked against the FIPS 180-4 test vectors). This makes changes detectable relative to a known chain head. Anchoring the head (keeping it where an attacker with the disk cannot rewrite it, or signing it) is M3.4 work. When the store is full or failing, writes return errors, and M3.4 refuses consequential actions then.
6. **Where it runs: in the virtio-blk driver's process** (a storage service, as D-015 did for networking). Clients get a `SEND` capability on its endpoint, badged by `init` with a namespace (a path prefix) and read-only or read-write; a client sees only its namespace.
7. **Bulk data: shared-memory capabilities** (a kernel addition beside D-016's memory calls): `mem_share` turns a whole `mem_map` mapping into a `Memory` capability (rights: read, write, grant), passed over IPC like any capability; `mem_map_cap` maps it in the receiver, read-only or read-write within its rights. Frames are freed when the last mapping and capability are gone; mapped pages count against the mapper's limit; revocation stops new mappings but does not unmap existing ones, the same limit as device memory. A client reads a file by sharing a buffer with the storage service, which copies blocks into it from its DMA buffers.
8. **QEMU:** a second, writable virtio-blk disk (a fresh image under `target/` for each run, built by `cargo xtask`), so existing tests keep their read-only disk.

**Rejected:** a storage service in the kernel (trusted code for parsing untrusted media); copy-on-write inside `pharos-fs` (a packed image with a different purpose); a log-structured store with a segment cleaner (more code for the same guarantees at M3.0 sizes); signed checkpoints (need key management, M3.4 or later); file data over IPC messages (millions of messages for a model); a disk device granted to the inference service (DMA to all memory for the process parsing untrusted models).

**Limits (accepted):** one commit at a time; the index is rewritten on every commit, which is fine for thousands of objects but not millions; no encryption at rest; the hash chain is not anchored until M3.4.

## Accepted decisions (M3.1)

### D-020: Where Phase 3 runs first

- **Status:** Accepted
- **Needed by:** M3.1
- **Date accepted:** 2026-10-29 (issue #67)

**Context.** The roadmap allows Phase 3 prototypes on the Linux host. Choosing per milestone what runs on the host and what must run on Pharos decides how much the M3.1 evaluation transfers and when M3.0 must be finished.

**Options to evaluate.** Host-first for inference and the agent runtime, then port behind the same interfaces; Pharos-first, with M3.0 on the critical path; a split, for example inference evaluated on the host while the enforcement milestones (M3.4, M3.5) are built only on Pharos.

**Evaluation criteria.** Enforcement claims are tested where enforcement happens (on Pharos, not on Linux); interfaces stay identical across host and Pharos; host results are labelled as such and never presented as running on Pharos; M3.0's scope follows from what must run on Pharos.

**Decision (split, one codebase).**

1. **One codebase, no parallel Linux prototype.** Agent and inference logic is written as `no_std` crates, as Phase 2 did for `pharos-fs`, `pharos-elf`, and `pharos_programs::net`. They are unit-tested and fuzzed on the Linux host, and the same code runs on Pharos as user programs. A Linux-only service that would later be rewritten is not built.
2. **Measurement on the host.** Runtime evaluation, benchmarks, and output comparison against established engines (llama.cpp) run on the host, and their results are labelled as host results.
3. **Enforcement on Pharos only.** Anything that claims to enforce something (the emergency stop, capabilities, audit, budgets, tool-call refusal, channel isolation) counts as done only when a QEMU test on Pharos shows it. A host test of the same logic is supporting evidence, never the proof.
4. **Per milestone:**

   | Milestone | Host (Linux) | Pharos (QEMU) |
   | --- | --- | --- |
   | M3.0 | Host tests of on-disk formats and pure logic | Everything it delivers |
   | M3.1 | All of it (evaluation) | — |
   | M3.2 | The engine crate: unit tests, fuzzing of the model parser, output comparison with llama.cpp; the service interface's codecs | The inference service as a user program, with tier T in CI and tier S under KVM |
   | M3.3 | Task-state and manifest logic (host tests) | Lifecycle, restart recovery, emergency stop |
   | M3.4 | Audit-record format and checks (host tests) | Capabilities, sandbox, audit trail |
   | M3.5 | Accounting logic (host tests) | Budgets, reservations, exhaustion tests |
   | M3.6 | Tool-call validator (host tests, fuzzing, injection corpus) | Tool calls with capability checks and confirmation |
   | M3.7 | Message codecs and group-state logic (host tests) | Channels, groups, isolation |
   | M3.8 | Data model and provenance logic (host tests) | Access control on stored knowledge |

5. **Consequence for M3.0:** it is on the critical path from M3.2 onward. M3.2's engine crate can be built and host-tested in parallel with M3.0, but nothing in M3.2–M3.8 is done until it runs on Pharos.

### D-010: AI inference runtime, model formats, and licensing

- **Status:** Accepted
- **Needed by:** M3.1
- **Date accepted:** 2026-10-29 (issue #70)

**Context.** The inference runtime is large and complex; where and how it runs dominates the security design.

**Options to evaluate.** Rust-native runtimes versus bindings to established C/C++ runtimes; candidate model formats (e.g. GGUF, ONNX, safetensors). Initially this runs on the Linux host; running on Pharos itself depends on M3.0. Established engines such as llama.cpp need a C library, threads, `mmap`, and a C++ runtime, which Pharos does not plan to provide (M3.0 excludes a POSIX layer). The leading option to test is therefore a small native `no_std` Rust engine on Pharos (safe Rust, fuzzable model parser, single-threaded at first), with existing engines used on the host behind the same provider interface (D-019). Correctness is shown by comparing outputs against an established engine on the same open-weight model, not by training a model.

**Evaluation criteria.** Runtime license and model licenses (including use restrictions); memory safety and attack surface; CPU performance; portability to Pharos and its effort; deterministic output (replayable inference records); supply-chain verifiability of model files.

**Evidence.** [inference-evaluation.md](inference-evaluation.md) (#69): llama.cpp `b11609` measured on four GGUF models; the native spike `pharos-infer` byte-identical to llama2.c `run.c` on `stories15M`, and on Qwen2.5-0.5B-Instruct q8_0 identical to llama.cpp under one of its two attention settings for each of four prompts, at 13.7–14.6 generated tokens/s on one thread against llama.cpp's 22–23; candle dropped (it needs a full standard library, and system OpenSSL to build its examples).

**Decision.**

1. **Engine on Pharos: our own** (`pharos-infer`, grown in M3.2): `no_std` safe Rust, no dependencies, checked and fuzzed parsers, single-threaded, weights borrowed from the model file. It is the only candidate that runs on Pharos without a C library, threads, `mmap`, or a C++ runtime, and its whole code is reviewable.
2. **Format: GGUF**, one file with weights, metadata, and the tokenizer; read by our checked parser. **Weights: Q8_0** first (the measured speed meets S1 with margin; the scale model fits the M3.0 memory target). Further quantization types only when memory requires them.
3. **Models:**
   - **Tier S (S1 on Pharos): Qwen2.5-0.5B-Instruct q8_0** (Apache-2.0, license text shipped with the model; 676 MB; SHA-256 `ca59ca7f…44e`, pinned by repository revision).
   - **Tier T (correctness and CI):** generated tiny models in the tests, and `stories15M` (MIT) against `run.c`.
   - **Tier H (host reference only):** Qwen2.5-1.5B-Instruct q4_k_m.
4. **Host reference: llama.cpp** (MIT, pinned build) for output comparison and benchmarks, on the host only; never shipped or ported.
5. **Determinism is a requirement:** the same model, prompt token IDs, and settings give the same tokens, so inference records in the audit trail (M3.4) can be replayed.
6. **Rejected:** llama.cpp on Pharos (C/C++ trusted code and a POSIX-like environment that M3.0 excludes); candle (needs a full standard library); Llama 3.2 (use restrictions in its license); ONNX and safetensors as the primary format (GGUF already carries quantized weights and the tokenizer in one checked file).
7. **Left to M3.2:** a GGUF tokenizer (Qwen2's byte-level BPE; prompts come as token IDs until then), batched prompt processing (needed for the 10 s first-token target: token by token, the S1 prompt takes about 16 s), and SIMD kernels. Where `exp`, `sin`, `cos`, `powf`, and `sqrt` come from on Pharos is decided with D-016.

## Accepted decisions (M3.2)

### D-019: Service interfaces and versioning

- **Status:** Accepted
- **Needed by:** M3.2 (inference interface), M3.3 (agent runtime)
- **Date accepted:** 2026-10-31 (issue #82)

**Context.** Today's IPC carries untyped 256-byte messages, and each service hand-encodes its requests (for example the network service in M2.10). Agents and services that discover and compose each other need typed, versioned contracts.

**Options to evaluate.** A small interface description with generated Rust encoders and decoders, or hand-written codecs with shared host-tested types; a service registry, or capabilities handed out by a manager; how versions are negotiated; how large payloads travel (shared memory capabilities or chunked messages).

**Evaluation criteria.** Every message checked by generated or shared code, fuzzed on the host; finding a service grants no permission; incompatible versions refused with a clear error; structured errors, timeouts, and cancellation in every contract; no new dependency without the AGENTS.md review.

**Evidence (2026-10-31, the two services Pharos has):**
- **The storage service (#77)** uses one shared module, `store_proto`: `parse` and `encode` for every request, used by the service and its clients, with round-trip tests, truncation and trailing-byte tests, and 100,000 random messages. Its reviews found no codec bug.
- **The network service (M2.10)** parses requests inline, at fixed offsets in the service's loop. Its client encodes them in separate functions. Neither side is fuzzed, and its status codes differ from the store's (2 is `TOO_LARGE` there, `NOT_FOUND` in the store).
- Neither service carries a version, so a client built against another layout gets wrong answers instead of a refusal.
- **Cost of a request:** an IPC round trip is about 1.9 µs under KVM (#81). Generating one token of the S1 model takes about 70 ms on the host (#69), so even one round trip per token costs under 0.01 %.
- **Large data:** both services already move bulk data outside messages. The store has one shared buffer per client, attached once (#77), and large files are read through a window (#78).
- **Discovery:** `init` hands every service and client the capabilities its reviewed table lists, badged per client (M2.10). Nothing finds services by name.

**Decision.**

1. **Hand-written codecs in one shared crate, not an interface description.** A new `no_std` crate, `crates/pharos-proto`, with no dependencies and `unsafe` forbidden, holds:
   - a checked reader and writer;
   - the common header, status codes, and common operations (below);
   - one module per service interface, in the style of `store_proto`: a `Request` and a `Reply` type with `parse` and `encode`.

   The service and its clients use the same module. Each module has round-trip tests, truncation and trailing-byte tests, and a fuzz test, and a parser never panics. An interface description language with a generator would add a build tool to review and a second language to read. It pays off only with many interfaces or clients written in other languages, neither of which Pharos has (three interfaces planned by M3.3). Reconsider it then.
2. **Every message starts with two bytes: interface version, then operation.** One endpoint serves one interface, so the endpoint names it. Pharos IPC has no connections, so each request carries its version. A server refuses a version it does not support with status `VERSION` and the range it supports (lowest and highest). A change that changes the meaning of existing bytes needs a new version; a new operation does not.
3. **Common status codes, the same in every interface:** 0 `OK`, 1 `BAD_REQUEST`, 2 `VERSION`, 3 `NO_ACCESS`, 4 `BUSY`, 5 `TOO_LARGE`, 6 `NO_BUFFER`, 7 `NOT_FOUND`, 8 `CANCELLED`, 9 `INTERNAL`. Codes 32 and up are the interface's own. Every reply starts with its status.
4. **Common operations** (codes 0xF0 and up, the same in every interface):
   - `INFO`: the interface name, its supported versions, and a list of the service's capabilities (for inference: models, context lengths, limits). This is model capability discovery (M3.2). It reveals only what the caller's endpoint capability already reaches.
   - `ATTACH`: a `send` carrying a `Memory` capability and its size, the client's buffer for bulk data, as in the store (#77). Large data never travels in messages.
5. **Discovery stays capability-based (D-018).** There is no registry. `init` (later the agent runtime) hands each client the badged endpoint capabilities its table lists, and finding a service grants nothing. A registry, if one comes, returns only capabilities its caller was granted.
6. **Timeouts and cancellation are part of every contract.**
   - Each interface documents a timeout for each operation. Clients always use `call` with a timeout (#76), and servers reply with non-blocking `send`s, never waiting on a client.
   - Long results are pulled. A long operation such as generation returns a session number with its first piece; the client then calls `NEXT` for each further piece, or `CANCEL`. A server drops a session that sees no call within its documented idle time, so a client that dies or stops asking costs nothing for long.
   - Pulling also gives back-pressure: the server produces only what the client asks for.
7. **Existing services move to `pharos-proto` in M3.2 (#92):** the network service's codec is extracted, shared with its client, and fuzzed, and `store_proto` moves into the crate. Both adopt the common header and status codes (a new version 1 of each interface). `init`, the test programs, and the docs change with them.

### D-021: A clock for user programs

- **Status:** Accepted
- **Needed by:** M3.2 (the inference service's result record), M3.4 (audit times)
- **Date accepted:** 2026-10-31 (issue #88, the maintainer's choice)

**Context.** The inference design (#83) puts prompt and generation times in every `RESULT` record. User programs had no way to read a clock: they could only wait (timeouts and `sleep`, #76).

**Options considered.** A system call returning the time since boot; leaving times out of the record and measuring from outside (the test kernel or `cargo xtask` watching the serial log); or reading the CPU's time-stamp counter in `pharos-user`'s `unsafe` module, which gives ticks of a frequency user space does not know.

**Decision.** System call 24 `uptime`: no arguments, returns microseconds since boot from the kernel's calibrated clock (`time::uptime`). It needs no capability. It adds no authority: timeouts already let any program measure time to the 10 ms tick, and a finer clock does not reach anything a program could not reach before. Wall-clock time (a date) is not part of it; there is no real-time clock driver yet.

**Consequences.** `pharos_user::uptime`. A finer clock makes timing side channels easier to measure; Pharos runs one CPU and does not claim protection from them (threat model). Revisit if it does.

## Open and proposed decisions

Each entry lists the milestone by which it must be decided. **Proposed** entries carry a recommendation but are not decisions until accepted. Decisions may be made earlier if evidence is available.

### D-011: CPU/GPU support and memory/VRAM constraints

- **Status:** Requirements part accepted 2026-10-29 (issue #70); implementation part accepted 2026-11-01 (M3.2 gate, #91)
- **Needed by:** M3.1 (requirements), M3.2 (implementation)

**Context.** GPU acceleration on a custom OS requires drivers that may not exist; CPU-only inference limits model size. The reference host's GPU (NVIDIA GTX 1060, 6 GB) has no realistic driver path on Pharos (NVIDIA's drivers are proprietary), so the expected outcome is CPU-only on Pharos for the foreseeable future, with the GPU used for host measurements only.

**Evaluation criteria.** Minimum and recommended RAM/VRAM; CPU-only viability for target models; driver availability and licensing; isolation of GPU memory between agents.

**Decision (requirements part, accepted 2026-10-29).**

1. **CPU only on Pharos.** No GPU support is planned; the GPU is used for host measurements only. Reconsider only if a GPU with an open, documented interface becomes a target.
2. **CPU: x86-64 with SSE2 required, AVX2 and FMA used when present** (per the Phase 3 requirements). One CPU, as Pharos runs today.
3. **Memory for tier S:** the model file in memory (676 MB; weights borrowed from it), a key/value cache of 24 KiB per token (24 layers × 2 × 128 values × 4 bytes; 48 MiB for 2,048 tokens), and small activations. Measured peak on the host: 662 MiB for a 233-token prompt and 128 generated tokens. **Limit for the inference service: 1 GiB; guest memory for inference runs: 2 GiB.**
4. **Threads:** none needed (one CPU); the engine stays single-threaded, which also keeps its output deterministic.

**Decision (implementation part, accepted 2026-11-01, M3.2 gate #91).** What M3.2 measured on Pharos under KVM (#90, [inference-evaluation.md](inference-evaluation.md)):

1. **CPU only, confirmed.** S1 runs on one CPU: first token 6.35 s after the request (target 10 s), 14.2 tokens/s (target 5), text identical to the host's.
2. **SSE2 only; AVX2 and FMA are not used** (amends item 2 of the requirements part). The compiler-vectorized SSE2 build meets both targets, so M3.2 has no hand-written SIMD and no second build (#86). One build on every CPU keeps output identical everywhere (D-010 item 5). A second build for `x86-64-v3` stays the option if a later model misses a target.
3. **Memory, confirmed:** the service's peak was 686 MiB of its 1 GiB limit (model file 676 MB, cache, 16 MiB store window); 2 GiB of guest memory sufficed. The first-token target counts from a loaded model; the first request after boot also loads it (6.7 s; #86).
4. **No threads**, as in the requirements part.

### D-012: Agent sandboxing, tool permissions, and network isolation

- **Status:** Open — direction recorded 2026-10-27 (M2.7, issue #36); final at M3.4
- **Needed by:** direction by M2.7 (so syscalls/IPC support it); final at M3.4

**Options.** Kernel-enforced capabilities; user-space policy service; combination. Permission prompts versus pre-declared manifests. Default-deny networking with per-destination grants.

**Evaluation criteria.** No ambient authority; revocation; auditability; usability of permission prompts; resistance to prompt injection leading to privilege escalation.

**Direction (recorded 2026-10-27, M2.7).** The kernel enforces capabilities; user space decides policy.

1. **Mechanism in the kernel:**
   - Each process has a capability table, and user code names capabilities by handle (an index into its own table, meaningless in another process).
   - A capability is a reference to a kernel object (at first an IPC endpoint; later memory regions, processes, interrupts) plus a set of rights (for example send, receive, map, grant).
   - Every system call that touches an object takes a handle and checks its rights.
2. **No ambient authority:** a process starts with only the capabilities its creator gives it. There are no global names or default access.
3. **Delegation:** capabilities move between processes only inside IPC messages, and only with the grant right. The sender can pass on the same or fewer rights.
4. **Revocation:** the holder of the original capability can revoke everything derived from it. M2.7 (#37) chooses how: a derivation tree as in seL4, or revocable indirection objects. Revocation must not depend on the receivers' cooperation.
5. **Policy in user space:** a policy service (the agent runtime, M3.x) decides what each agent gets and records an audit log. Permission prompts versus manifests, and network rules, are decided at M3.4.
6. **M2.7 implements:**
   - capability tables;
   - endpoint capabilities with send and receive rights;
   - passing a capability in a message;
   - deleting a handle;
   - revocation as designed in #37.

   Memory, process, and interrupt capabilities follow with their milestones.

### D-018: Authority model: capabilities, identity, and human control

- **Status:** Proposed
- **Needed by:** M3.3 (final with D-012 at M3.4)

**Context.** Agent platforms often authorize by identity ("this agent may do X"). In a capability system that brings back ambient authority and confused-deputy bugs. Agents, models, tools, and users also need identities for attribution. And the user needs controls that work when every agent is wrong or compromised; Pharos is headless today, so no trusted path to a human exists.

**Recommendation.**

1. **Authority comes only from capabilities.** A request is allowed because the caller holds a capability with the right, never because of who it claims to be. Badges (M2.10) identify a client to a server, as granted by whoever handed out the capability.
2. **Identity is for attribution.** Agent, model, tool, and user identities are recorded in audit records and task state, and are kept separate from each other; they never grant access by themselves.
3. **Delegation only narrows** rights (as `GRANT` does today), may carry an expiry, and is revocable through the derivation tree.
4. **Failure to establish authority means denial.** There is no fallback to broader access.
5. **A trusted path for the user:** a console or device that only the kernel and a small trusted service read, with commands to stop an agent or group, revoke its capabilities, deny a release, and enter safe mode. It works without any agent or model cooperating, and agents cannot reach it.
6. **Human approval** is required for: granting capabilities beyond an agent's manifest, applying system updates (M4.3), and anything a policy marks sensitive.

**Evaluation criteria.** No ambient authority; revocation independent of the holder; attribution of every consequential action; emergency controls that survive a hung agent runtime; usability of approvals.
