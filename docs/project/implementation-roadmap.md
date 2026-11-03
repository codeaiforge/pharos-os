# Implementation roadmap

This is the authoritative plan for Pharos OS. It is ordered by dependency, not by calendar: it contains no dates or effort estimates, because no real project plan supports them yet.

**Phase 1 — Foundation (v0.1.0) and Phase 2 — Core System (v0.2.0) are done. Current milestone: M3.4 — Permissions, sandboxing, auditability, and isolation.** Everything in Phases 3–5 is **planned, not implemented**.

## How to read this roadmap

- Work is split into five phases, each made of milestones (`M<phase>.<n>`).
- Each milestone lists: objective and scope, deliverables, prerequisites, acceptance criteria, validation, risks, out-of-scope items, definition of done, and a gate.
- A **gate** states what must pass before work that depends on this milestone starts.
- Status labels: **Current**, **Planned**, **Done** (only after its gate passed).

### Standard definition of done

Every milestone's definition of done includes the following, plus any milestone-specific items:

1. All acceptance criteria are met and demonstrated by the listed validation.
2. `scripts/check.sh` passes locally, and CI passes.
3. Documentation (README, relevant `docs/` pages, `CHANGELOG.md`) reflects the new state honestly.
4. Any `unsafe` code, new dependency, or privilege change has been reviewed per [AGENTS.md](../../AGENTS.md).
5. Related decision-log entries are Accepted, and the [threat model](../security/threat-model.md) is updated if trust boundaries changed.
6. The change has been reviewed and merged by a maintainer.

## Cross-cutting tracks (start early, never "finished")

The phases are not strictly sequential. These tracks run through every phase:

| Track | Starts | What it means |
| --- | --- | --- |
| Testing | M1.4 | Every milestone adds automated tests. QEMU regression tests start at M2.3 and grow with each kernel milestone, long before Phase 5. |
| Security | M1.1 | Threat model updated at every phase gate. Privilege boundaries designed at M2.1, before code depends on them. Agent permissions designed before agents get tools. |
| Documentation | M1.5 | Docs updated in the same change as code. |
| Architecture decisions | M2.1 | Decisions recorded before the milestone that depends on them (see [Open decisions](#open-decisions)). |
| Governed development | M1.1 | Agent-assisted development of this repository follows [AGENTS.md](../../AGENTS.md): focused changes, tests and CI as evidence (an agent's claim that a change works is not evidence), maintainer approval, and no agent commits to shared history, tags, pushes, or publishes without explicit authorization. This is separate from a running Pharos system updating itself, which is M4.3. |
| Host-side prototyping | Phase 3 | Inference and agent-runtime prototypes can run on the Linux host before the kernel can host them, so Phase 3 evaluation may overlap Phase 2. Prototypes must not be presented as running on Pharos. D-020 (accepted): one codebase of `no_std` crates, host-tested and fuzzed on Linux and run unchanged on Pharos; measurements on the host; enforcement counts only when shown on Pharos. |

## Phase overview

| Phase | Name | Status |
| --- | --- | --- |
| 1 | Foundation | Done (v0.1.0) |
| 2 | Core System | Done (v0.2.0) |
| 3 | AI Agent Platform | **Current** (M3.4; M3.1, M3.0, M3.2, and M3.3 done) |
| 4 | Full Operating System | Planned |
| 5 | Deployment and Release | Planned |

---

## Phase 1 — Foundation

**Status: Done** — gate passed 2026-10-26 (CI green on `main` at commit `38cc424`; maintainer approved the release). Follow-up: the manual fresh-machine run of setup.md has not been performed yet.

- **Objective and scope:** A clean, reproducible host-side Rust workspace with a placeholder kernel crate, a minimal CLI, quality gates, CI, and documentation that lets later work proceed safely.
- **Deliverables:** M1.1–M1.5 below.
- **Prerequisites:** Rust stable toolchain on Linux x86-64.
- **Acceptance criteria:** The workspace builds and all checks pass from a clean clone with only the documented prerequisites.
- **Validation:** Automated: CI on a hosted repository. Manual: a second machine or fresh user account follows [setup.md](../development/setup.md) end to end.
- **Risks and mitigations:** Over-engineering the scaffold → keep std-only, minimal files. Docs drifting from code → honest status labels and review.
- **Out of scope:** Bootable code, `no_std`, targets, QEMU, inference.
- **Definition of done:** Standard, plus every M1.x milestone done.
- **Gate:** CI passes on the hosted repository for the committed scaffold; the maintainer has reviewed the docs and the roadmap.

### M1.1 — Repository and Rust workspace

**Status: Done.**

- **Objective and scope:** Conventional repository layout; Cargo virtual workspace; toolchain and formatting configuration.
- **Deliverables:** Root `Cargo.toml` (resolver 3, shared package metadata, lints), `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`, `.gitignore`, `.editorconfig`, `.gitattributes`, `LICENSE`, `NOTICE`.
- **Prerequisites:** None.
- **Acceptance criteria:** `cargo check --workspace` succeeds on stable Rust with no warnings; `LICENSE` is the verbatim Apache-2.0 text.
- **Validation:** Automated: CI build. Manual: compare `LICENSE` SHA-256 against the canonical text.
- **Risks and mitigations:** New stable release adds lints that break CI → fix promptly, or record a decision to pin a version.
- **Out of scope:** Kernel targets, cross-compilation.
- **Definition of done:** Standard.
- **Gate:** Workspace builds from a clean clone.

### M1.2 — Host-side kernel placeholder

**Status: Done.**

- **Objective and scope:** Reserve `kernel/` as a host-buildable library that clearly states it is not a kernel.
- **Deliverables:** `kernel/Cargo.toml`, `kernel/src/lib.rs`, `kernel/README.md`.
- **Prerequisites:** M1.1.
- **Acceptance criteria:** Builds and tests on the host; documentation explicitly says it does not boot or manage hardware; no `unsafe`, `no_std`, or target configuration.
- **Validation:** Automated: `cargo test -p pharos-kernel`. Manual: doc review for unsupported claims.
- **Risks and mitigations:** Placeholder mistaken for real functionality → explicit status in code, README, and CLI `info` output.
- **Out of scope:** Any OS functionality.
- **Definition of done:** Standard.
- **Gate:** Placeholder status is clear in every place it is mentioned.

### M1.3 — Initial CLI

**Status: Done.**

- **Objective and scope:** A small, deterministic `pharos` CLI with `help`, `version`, `info`, `doctor`.
- **Deliverables:** `tools/pharos-cli` with unit tests; usage in README.
- **Prerequisites:** M1.1.
- **Acceptance criteria:** Version comes from Cargo metadata; end-to-end tests run the real binary; unknown commands and extra arguments exit with status 2 and a message on stderr; `doctor` is read-only and reports unbuilt capabilities as "not checked"; tests cover parsing, output, unknown commands, and exit codes.
- **Validation:** Automated: `cargo test -p pharos-cli`. Manual: run each command and check output and `echo $?`.
- **Risks and mitigations:** CLI growing into a framework → std-only, no plugin system (decision P-002).
- **Out of scope:** Building kernel images, launching QEMU, agent features.
- **Definition of done:** Standard.
- **Gate:** All CLI tests pass; `doctor` makes no unverified claims.

### M1.4 — Formatting, linting, tests, and CI

**Status: Done** — both CI jobs green on `main`. Deliberate-failure check passed on 2026-10-26: CI failed at "Check formatting" on a branch with planted errors ([run 40382690825](https://github.com/codeaiforge/pharos-os/actions/runs/40382690825)).

- **Objective and scope:** Enforce formatting, Clippy with warnings as errors, build, and tests on every push and pull request.
- **Deliverables:** `.github/workflows/ci.yml` with read-only permissions; workspace lint configuration.
- **Prerequisites:** M1.1–M1.3.
- **Acceptance criteria:** CI runs fmt, Clippy (`-D warnings`), build, test, rustdoc, and the link check with `--locked`, plus build and test on the minimum supported Rust (1.85); uses only `actions/checkout`; has `contents: read` permission; does not publish, deploy, or upload artifacts.
- **Validation:** Automated: the CI run itself. Manual: introduce a deliberate formatting error on a throwaway branch and confirm CI fails.
- **Risks and mitigations:** Third-party action compromise → minimal actions, pinned by commit SHA.
- **Out of scope:** QEMU in CI (starts at M2.3), release automation.
- **Definition of done:** Standard, plus one green CI run on the hosted repository.
- **Gate:** CI green on the default branch.

### M1.5 — Project documentation and development workflow

**Status: Done.**

- **Objective and scope:** Documentation that explains the vision, proposed architecture, roadmap, security posture, and how to develop.
- **Deliverables:** README, AGENTS.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, CHANGELOG.md, and `docs/` (project, development, architecture, security).
- **Prerequisites:** M1.1.
- **Acceptance criteria:** All internal links resolve; no document claims unimplemented functionality; README, roadmap, architecture, and AGENTS.md agree.
- **Validation:** Automated: `python3 scripts/check-links.py` (runs in CI). Manual: maintainer read-through.
- **Risks and mitigations:** Generic boilerplate → content specific to Pharos; invented contacts or legal details → none included, gaps stated.
- **Out of scope:** Detailed subsystem designs (written per milestone in Phase 2+).
- **Definition of done:** Standard.
- **Gate:** Maintainer approves documentation.

---

## Phase 2 — Core System

**Status: Done** — gate passed 2026-10-29 with the M2.10 gate: every M2.x gate passed, and the threat model was updated for everything Phase 2 built, with its open limits carried into Phases 3 and 4 ([threat model](../security/threat-model.md#open-limits-carried-out-of-phase-2)). Prepared for release as v0.2.0.

- **Objective and scope:** A minimal x86-64 kernel that boots in QEMU and grows, milestone by milestone, into a system with memory management, scheduling, isolated processes, IPC, storage, drivers, and networking.
- **Deliverables:** M2.1–M2.10.
- **Prerequisites:** Phase 1 gate.
- **Acceptance criteria:** Each milestone's criteria, verified by automated QEMU tests that run in CI.
- **Validation:** Automated: QEMU test harness from M2.3 onward. Manual: GDB-assisted inspection; occasional real-hardware boot only when authorized.
- **Risks and mitigations:** `unsafe` and hardware complexity → small abstractions, `SAFETY:` comments, review; scope creep → strict gates.
- **Out of scope:** AI agents inside the OS; real-hardware support beyond experiments.
- **Definition of done:** Standard, plus a QEMU test suite covering every Phase 2 milestone.
- **Gate:** All M2.x gates passed; threat model updated for kernel/user boundary.

### M2.1 — Architecture and boot-protocol decisions

**Status: Done** — gate passed 2026-10-26: D-001, D-002, D-003 Accepted (design in [boot.md](../architecture/boot.md)); initial D-004 direction recorded (capability-based microkernel, final decision before M2.7).

- **Objective and scope:** Decide how the kernel boots and is built, and set an initial direction for kernel architecture, before writing kernel code.
- **Deliverables:** Accepted decision records D-001, D-002, D-003; initial direction for D-004; `docs/architecture/boot.md`; a throwaway prototype if needed to gather evidence.
- **Prerequisites:** Phase 1 gate.
- **Acceptance criteria:** Each decision lists options, criteria, evidence, and consequences; the chosen build strategy keeps `cargo test --workspace` working for host crates.
- **Validation:** Manual: review of decision records; prototype demonstrates the chosen boot path in QEMU.
- **Risks and mitigations:** Choosing a boot path that limits later work → evaluate licenses, UEFI/BIOS coverage, and maintenance before committing.
- **Out of scope:** Production kernel code.
- **Definition of done:** Standard.
- **Gate:** D-001, D-002, D-003 Accepted.

### M2.2 — Minimal bootable x86-64 kernel

**Status: Done** — gate passed 2026-10-27. From a clean checkout, `cargo xtask run` built a byte-identical image and booted it to the kernel's success signal (QEMU exit status 33) on UEFI and BIOS; boot failures and panics exit with status 35; the GDB breakpoint on `kmain` was verified. The automated, timed boot test in CI moves to M2.3 together with decision D-009.

- **Objective and scope:** Convert the `kernel` crate into a `no_std` kernel that boots via Limine and reaches its entry point in QEMU and halts cleanly, following [boot.md](../architecture/boot.md) and the D-004 constraints on early kernel code.
- **Deliverables:** Kernel entry point; panic handler; build configuration; reproducible bootable image creation without root privileges.
- **Prerequisites:** M2.1.
- **Acceptance criteria:** A single documented command builds the image; QEMU reaches the kernel entry point and halts or exits with a known status; host crates still build and test normally.
- **Validation:** Automated: QEMU boots with a timeout and checks exit status (exit signalling per D-009). Manual: GDB breakpoint on the entry point.
- **Risks and mitigations:** Toolchain or target needs nightly → only if D-003 accepts it; document why.
- **Out of scope:** Interrupts, memory management, output beyond what the gate needs.
- **Definition of done:** Standard, plus `unsafe` blocks each carry `SAFETY:` comments.
- **Gate:** Image builds reproducibly and boots in QEMU on a clean checkout.

### M2.3 — Early serial output and QEMU boot validation

**Status: Done** — gate passed 2026-10-27: the CI `qemu` job passed on `main` with the boot check (UEFI and BIOS) and the `boot_info` test kernel (9 checks), and the CI image hash matched a local build (`f4fc294`, [run 40476613340](https://github.com/codeaiforge/pharos-os/actions/runs/40476613340)). Delivered: D-009 (#13), `cargo xtask test` (#14), logging macros (#15), kernel tests inside QEMU (#16), CI job (#17). A hung boot fails within the time limit; failing, panicking, and empty test kernels fail the run.

- **Objective and scope:** Serial (COM1) output and an automated QEMU test harness that runs in CI.
- **Deliverables:** Serial driver; logging macros; QEMU harness (per D-009) with timeout and serial capture; CI job running it headless.
- **Prerequisites:** M2.2; D-009 Accepted.
- **Acceptance criteria:** Booting prints a known marker (for example `PHAROS: boot ok`) on serial; the harness reports pass/fail deterministically; a hung boot fails within the timeout; kernel tests can report results over serial.
- **Validation:** Automated: CI QEMU job. Manual: run QEMU interactively and read serial output.
- **Risks and mitigations:** Flaky CI from emulator timing → generous timeouts, retries disallowed for real failures, logs saved on failure.
- **Out of scope:** Framebuffer graphics.
- **Definition of done:** Standard, plus the QEMU job required in CI.
- **Gate:** QEMU job green in CI on the default branch. This is the first measurable kernel milestone.

### M2.4 — Exceptions, interrupts, and debugging

**Status: Done** — gate passed 2026-10-27: the CI `qemu` job passed on `main` with the exception tests (`6f1ad22`, [run 40507039495](https://github.com/codeaiforge/pharos-os/actions/runs/40507039495)): six test kernels, 41 checks, including breakpoint, page fault, double fault from a stack overflow, and the local APIC timer. A deliberately broken double-fault stack failed CI on a throwaway branch ([run 40507832079](https://github.com/codeaiforge/pharos-os/actions/runs/40507832079)). Delivered: D-006 (#18), interrupt-safe console (#19), GDT and TSS (#20), IDT and exception handlers (#21), double fault on IST1 with a guarded kernel stack (#22), local APIC timer (#23), debugging docs and CI gate (#24). Design: [interrupts.md](../architecture/interrupts.md).

- **Objective and scope:** IDT, CPU exception handlers, double-fault handling on a separate stack, interrupt controller setup (per D-006), and debugging support.
- **Deliverables:** Exception handlers that log diagnostic state over serial; interrupt controller driver; GDB workflow in [debugging.md](../development/debugging.md).
- **Prerequisites:** M2.3; D-006 (controller) Accepted.
- **Acceptance criteria:** Tests trigger breakpoint, page-fault, and double-fault paths and observe correct handling; a stack overflow causes a reported double fault, not a triple-fault reboot; a hardware interrupt (for example the timer or keyboard) is received.
- **Validation:** Automated: QEMU tests per exception. Manual: GDB session following the documented steps.
- **Risks and mitigations:** Silent triple faults → QEMU `-d int` logging and `-no-reboot` in debugging docs.
- **Out of scope:** Scheduling, SMP.
- **Definition of done:** Standard.
- **Gate:** Exception tests pass in CI.

### M2.5 — Physical and virtual memory management

**Status: Done** — gate passed 2026-10-27: the CI `qemu` job passed on `main` with the memory tests (`850c165`, [run 40516480215](https://github.com/codeaiforge/pharos-os/actions/runs/40516480215)): 13 test kernels, including frames, paging, write protection, no-execute, reclaim, heap, and heap exhaustion; the maintainer reviewed and approved [memory.md](../architecture/memory.md). Read-only data deliberately mapped writable failed CI on a throwaway branch ([run 40516617148](https://github.com/codeaiforge/pharos-os/actions/runs/40516617148)). Delivered: D-005 (#25), frame allocator (#26), the kernel's own page tables with guard pages (#27), reclaim of bootloader memory (#28), kernel heap and `alloc` (#29), page-table debugging docs and CI gate (#30).

- **Objective and scope:** Physical frame allocation from the boot memory map, page-table management, and a kernel heap.
- **Deliverables:** Frame allocator; page mapper; heap allocator enabling `alloc`; `docs/architecture/memory.md`.
- **Prerequisites:** M2.4; D-005 Accepted.
- **Acceptance criteria:** Allocator unit tests (host-run where the logic is target-independent) and QEMU tests pass; mapping and unmapping are verified; out-of-memory is reported, not undefined behavior; `alloc` collections work in the kernel.
- **Validation:** Automated: host unit tests plus QEMU stress tests (many allocations, fragmentation). Manual: inspect page tables in GDB.
- **Risks and mitigations:** Memory corruption from `unsafe` → keep `unsafe` in small, reviewed modules; test-heavy; consider Miri for host-testable logic.
- **Out of scope:** User address spaces (M2.7), swapping.
- **Definition of done:** Standard.
- **Gate:** Memory tests pass in CI; design document reviewed.

### M2.6 — Timers and scheduling

**Status: Done** — gate passed 2026-10-27: the CI `qemu` job passed on `main` with the scheduling tests (`31ff346`, tested as `6d6eee2` before a commit-message rewrite that left the files unchanged, [run 40530704211](https://github.com/codeaiforge/pharos-os/actions/runs/40530704211)). That run had 16 test kernels, among them `timer`, `tasks`, `task_overflow`, and `preemption`; the last shows that a task spinning forever cannot starve the others. Every M2.6 commit passed CI on its first run, with no retries. A scheduler with preemption deliberately removed failed CI on a throwaway branch ([run 40532363163](https://github.com/codeaiforge/pharos-os/actions/runs/40532363163)): its host unit tests failed, and the `preemption` test kernel hung until the time limit. Delivered: D-006 timer part and D-013 (#31), timer calibration and kernel clock (#32), tasks and context switching (#33), preemption, idle task, and sleep (#34), tracing docs and CI gate (#35). Design: [scheduling.md](../architecture/scheduling.md).

- **Objective and scope:** A periodic or one-shot timer (per D-006) and a scheduler for kernel tasks.
- **Deliverables:** Timer driver; task abstraction; context switching; scheduler.
- **Prerequisites:** M2.5.
- **Acceptance criteria:** Multiple kernel tasks run interleaved; the scheduler is preemptive (or the chosen model is documented); a test shows a busy task cannot starve others.
- **Validation:** Automated: QEMU tests with multiple tasks and checked ordering markers. Manual: trace switching via serial logs.
- **Risks and mitigations:** Race conditions → document locking rules; disable interrupts only in minimal sections.
- **Out of scope:** SMP scheduling (later decision), user processes.
- **Definition of done:** Standard.
- **Gate:** Scheduling tests pass in CI.

### M2.7 — Processes, privilege boundaries, system calls, and IPC

**Status: Done** — gate passed 2026-10-27: the CI `qemu` job passed on `main` at `a7e806b` ([run 40564446336](https://github.com/codeaiforge/pharos-os/actions/runs/40564446336)) with 22 test kernels, among them the isolation kernels `address_spaces`, `user_mode`, `syscalls`, `ipc`, and `hardening`: user processes that try to read, write, or jump into kernel memory or another process's memory are killed, invalid system-call arguments are rejected (and `syscall::decode` is fuzzed with 200,000 random calls), and two processes exchange messages and capabilities over IPC. A kernel that made every page user-accessible failed CI on a throwaway branch ([run 40566069746](https://github.com/codeaiforge/pharos-os/actions/runs/40566069746)): the host unit test `paging::tests::leaf_entries` failed, and so did two `address_spaces` checks in QEMU. The maintainer approved the [security review](../security/review-m2.7-kernel-user-boundary.md) of the kernel/user boundary; its findings F1–F5 are fixed. The minimum supported Rust (1.85) build broke on four commits during M2.7 (let chains) and was fixed in `12cc012`. Delivered: D-004 final and D-012 direction (#36), D-014 and the syscalls-ipc design (#37), per-process address spaces (#38), ring 3 execution (#39), system calls and capabilities (#40), IPC with capability passing and revocation (#41), security review and CI gate (#42). Design: [syscalls-ipc.md](../architecture/syscalls-ipc.md).

- **Objective and scope:** User-mode processes in separate address spaces, a minimal system-call interface, and IPC. This is the foundation for isolating services and agents.
- **Deliverables:** Ring 3 execution; per-process address spaces; syscall entry; IPC primitive; `docs/architecture/syscalls-ipc.md`; capability direction from D-012 reflected in the interface.
- **Prerequisites:** M2.6; D-004 Accepted; D-012 direction recorded.
- **Acceptance criteria:** A user process cannot read or write kernel memory or another process's memory (tests attempt it and are stopped); invalid syscall arguments are rejected safely; two processes exchange messages through IPC.
- **Validation:** Automated: QEMU isolation tests; fuzzing of syscall argument handling where practical. Manual: security review of the syscall surface.
- **Risks and mitigations:** Large or ambiguous syscall surface → start minimal; every syscall documented with its capability requirement.
- **Out of scope:** POSIX compatibility.
- **Definition of done:** Standard, plus threat model updated for the kernel/user boundary.
- **Gate:** Isolation tests pass in CI; security review complete.

### M2.8 — Storage abstractions and filesystem

**Status: Done** — gate passed 2026-10-27: the CI `qemu` job passed on `main` at `6ead5e8` ([run 40576869275](https://github.com/codeaiforge/pharos-os/actions/runs/40576869275)) with 25 test kernels, among them the storage kernels `ramdisk`, `fs`, and `files`: files built on the host are read back from a boot RAM disk, each of 12 corrupted images is rejected with its own error while the kernel keeps running, and processes read files only through capabilities. The image parser is fuzzed on the host with 100,000 mutated images. A parser that skipped the file checksum failed CI on a throwaway branch ([run 40577075436](https://github.com/codeaiforge/pharos-os/actions/runs/40577075436)): the `pharos-fs` host tests failed (also on Rust 1.85), and the `fs` test kernel failed at `fs-file-crc`. Every M2.8 commit passed CI on its first run, including the minimum supported Rust. Delivered: D-007 (#43), storage design (#44), image format crate and host tool (#45), RAM disk from Limine modules (#46), kernel filesystem (#47), file capabilities with `open` and `read` (#48), CI gate (#49). Writes stay out of scope (copy-on-write direction in D-007). Design: [storage.md](../architecture/storage.md).

- **Objective and scope:** A block-device abstraction and a filesystem (per D-007), starting read-only.
- **Deliverables:** Block device interface; initial RAM disk or virtio-blk support; filesystem implementation; host tool to build images.
- **Prerequisites:** M2.7; D-007 Accepted.
- **Acceptance criteria:** Files are read from an image built on the host; if writable, data survives a clean reboot in QEMU; corrupt images are rejected without crashing the kernel.
- **Validation:** Automated: QEMU tests with known images, including corrupted ones. Manual: inspect images with host tools.
- **Risks and mitigations:** Data corruption → read-only first; checksums; crash-consistency design before writes.
- **Out of scope:** Full permission model on files beyond capability checks.
- **Definition of done:** Standard.
- **Gate:** Storage tests pass in CI.

### M2.9 — Hardware abstraction and selected drivers

**Status: Done** — gate passed 2026-10-28: the CI `qemu` job passed on `main` at `35ec2cd` ([run 40713610670](https://github.com/codeaiforge/pharos-os/actions/runs/40713610670)) with 31 test kernels, among them the driver kernels `user_elf`, `pci`, `device_caps`, `device_irq`, and `virtio_blk`. A Rust virtio-blk driver runs as a user process with only its device and a console, reads the disk on MSI-X interrupts, and mounts the `pharos-fs` image on it with the kernel's parser. A driver killed mid-request leaves the kernel running and its device stopped, and a wrong device is refused. An MMIO grant that reached past the device's BAR failed CI on a throwaway branch ([run 40713691815](https://github.com/codeaiforge/pharos-os/actions/runs/40713691815)): the kernel's host tests failed (also on Rust 1.85), and the `device_caps` kernel failed at "past the BAR". Every M2.9 commit passed CI on its first run. The security review ([review-m2.9-drivers.md](../security/review-m2.9-drivers.md)) found and fixed four issues and was approved by the maintainer on 2026-10-28. Delivered: D-008 (#50), driver design (#51), Rust user programs and the ELF loader (#52), PCI discovery (#53), device interrupts (#54), device capabilities with MMIO and DMA (#55), the virtio-blk driver (#56), CI gate and security review (#57). Per D-008, virtio-net, a framebuffer, and a keyboard were left out; the IOMMU is a tracked limit. Design: [drivers.md](../architecture/drivers.md).

- **Objective and scope:** A driver model (per D-008) and drivers for a small set of QEMU devices.
- **Deliverables:** Device discovery (PCI/ACPI as needed); drivers such as virtio-blk, virtio-net, and a framebuffer or keyboard.
- **Prerequisites:** M2.7; D-008 Accepted.
- **Acceptance criteria:** Each driver has QEMU tests; a misbehaving device or driver error does not crash the kernel when drivers run in user space (if that option is chosen).
- **Validation:** Automated: QEMU device tests. Manual: optional authorized real-hardware boot.
- **Risks and mitigations:** DMA attacks → IOMMU evaluation; limited device set.
- **Out of scope:** Broad real-hardware support, GPU drivers.
- **Definition of done:** Standard.
- **Gate:** Driver tests pass in CI.

### M2.10 — Networking and basic system services

**Status: Done** — gate passed 2026-10-29: the CI `qemu` job passed on `main` at `ed4d1cb` ([run 40835736689](https://github.com/codeaiforge/pharos-os/actions/runs/40835736689)) with 34 test kernels, among them `spawn`, `services`, `virtio_net`, and `network`, whose client exchanges a UDP datagram with the host echo server at `10.0.2.2:47000`. At boot the kernel starts `init`, which starts the virtio-blk driver and the network service in order and reports each start and failure; the boot passes only if every service succeeded. A UDP parser that accepted headers shorter than 8 bytes failed CI on a throwaway branch ([run 40835882010](https://github.com/codeaiforge/pharos-os/actions/runs/40835882010)): the host tests failed, also on Rust 1.85, while the QEMU job passed, since QEMU never sends such a segment. Every CI run on `main` during M2.10 passed on its first attempt. The security review ([review-m2.10-services-networking.md](../security/review-m2.10-services-networking.md)) found and fixed one issue (reply capabilities now one-shot), recorded a test gap the broken-branch check exposed, and was approved by the maintainer on 2026-10-29. Delivered: D-015 (#58), services and networking design (#59), `spawn` with badges and notifications (#60), `init` (#61), the virtio-net driver (#62), the network service (#63), the host test endpoint (#64), CI gate and security review (#65). Design: [services.md](../architecture/services.md), [networking.md](../architecture/networking.md).

- **Objective and scope:** A minimal network stack and basic user-space services (for example a service manager and logging).
- **Deliverables:** Network stack (implementation or library choice recorded as a decision); basic services.
- **Prerequisites:** M2.9.
- **Acceptance criteria:** QEMU guest exchanges packets with the host over user-mode networking; network access is mediated so it can later be granted as a capability; services start in a defined order and report failures.
- **Validation:** Automated: QEMU network tests against a host-side test endpoint. Manual: packet capture inspection.
- **Risks and mitigations:** Large attack surface → default-deny; minimal protocols first.
- **Out of scope:** TLS and full Internet services.
- **Definition of done:** Standard.
- **Gate:** Phase 2 gate.

---

## Phase 3 — AI Agent Platform

**Status: Current** (M3.4; M3.1, M3.0, M3.2, and M3.3 done).

Ordering notes:

- **M3.0 comes before anything runs on Pharos.** Phase 2 left Pharos unable to host an inference runtime or an agent: user programs cannot use SIMD, have a 256 KiB heap that never frees, no writable storage, and no timeouts. M3.1 runs on the Linux host alongside M3.0 and sets its targets (model sizes, memory, instruction sets).
- **Permissions and resource limits (M3.4, M3.5) come before tool integration, agent communication, and the knowledge service (M3.6–M3.8)**, so that no agent gets tools, channels, or shared knowledge without enforcement already in place.
- **One agent before many:** groups of agents (M3.7) come only after a single agent is enforced, audited, budgeted, and stoppable (M3.3–M3.5).
- **The control plane proposes; the execution plane decides.** Agents, plans, and model output are untrusted proposals. The kernel and trusted services enforce capabilities, quotas, and audit, and keep working when every agent or model is unavailable or wrong. No agent can gain authority by changing a plan, delegating, writing to shared knowledge, or composing services.

- **Objective and scope:** Local inference and an agent runtime in which agents are untrusted, isolated, resource-limited, and use only granted capabilities. Early milestones may be prototyped on the Linux host.
- **Deliverables:** M3.0–M3.8.
- **Prerequisites:** Phase 2 gate. M3.1 runs on the Linux host; running anything on Pharos requires M3.0.
- **Acceptance criteria:** Each milestone's criteria; agent isolation verified by adversarial tests.
- **Validation:** Automated: unit and integration tests; QEMU tests once on Pharos; prompt-injection test suite. Manual: security review.
- **Risks and mitigations:** AI dominates the TCB → inference stays unprivileged; model output untrusted.
- **Out of scope:** Training or fine-tuning models (a separate research track; correctness of inference engines is shown against open-weight models); cloud or remote inference providers (they need TLS and an outbound network policy, and they open an exfiltration path; reconsider after M3.4 with D-012's per-destination grants); remote agents and federation; agents changing a running Pharos system (M4.3).
- **Definition of done:** Standard, plus threat model updated for agents and inference.
- **Gate:** All M3.x gates; agent isolation security review complete.

### M3.0 — Platform prerequisites for hosting agents

**Status: Done** — gate passed 2026-10-30: the CI `qemu` job passed on `main` at `e1d9694` ([run 41016521842](https://github.com/codeaiforge/pharos-os/actions/runs/41016521842), #107) with 42 test kernels, among them `vector_state`, `vector_state_avx`, `user_memory`, `timeouts`, `shared_memory`, `store`, `store_crash` (20 QEMU kills while writing, the store consistent after each), and `large_file` (a 676 MB GGUF read into one process under 2 GiB, in 49 s). Letting `mem_share` re-share a received mapping failed CI on a throwaway branch ([run 41016950143](https://github.com/codeaiforge/pharos-os/actions/runs/41016950143), #108): the QEMU job failed at `shared_memory`, while the host tests and the Rust 1.85 job passed. Every CI run on `main` during M3.0 passed. The security review ([review-m3.0-platform.md](../security/review-m3.0-platform.md)) found and fixed two issues: a receiver could mint a shared-memory capability its sharer's `revoke` could not reach, and one storage client could take the service's whole limit. The maintainer approved it on 2026-10-30. Delivered: D-016 (#71), D-017 (#72), the design (#73), vector state (#74), user memory (#75), timeouts (#76), the writable store and storage service (#77), shared memory (#80), large files (#78), and the gate (#79). Carried: the IPC round trip over D-004's budget (#81), and the limits in the [threat model](../security/threat-model.md#open-limits-carried-out-of-phase-2).

- **Where it runs (D-020):** Pharos; host tests for on-disk formats and pure logic.
- **Objective and scope:** Give Pharos what an inference runtime and an agent runtime need from the OS, without which no later Phase 3 milestone can run on Pharos.
- **Deliverables:**
  - SIMD for user programs: the kernel saves and restores FPU, SSE, and AVX state per thread (XSAVE where available), with state leaks between processes tested (D-016);
  - user memory: map and unmap anonymous memory under a per-process limit, and a freeing user allocator in place of the bump heap (D-016);
  - timeouts and cancellation: `receive`, `call`, and `irq_wait` with a deadline, and a user-space sleep (D-016);
  - writable persistent storage: virtio-blk writes and a crash-consistent store for durable state, large files (model files), and append-only records (D-017);
  - shared-memory capabilities (`mem_share`, `mem_map_cap`) so large files move between processes without IPC copies (D-017);
  - QEMU runs with enough memory for the M3.1 target model.
  - **Targets set by M3.1 (#70, D-010, D-011):**
    - guest memory 2 GiB for inference runs (other test kernels keep 256 MiB);
    - user programs built for a target with SSE2 enabled (today's `x86_64-unknown-none` has no SSE, so floating point runs in software), and the kernel saving SSE state, and AVX state when AVX2 is used (D-016);
    - a process may hold up to 1 GiB (the inference service; measured peak 662 MiB on the host);
    - a 700 MB model file (Qwen2.5-0.5B-Instruct q8_0, 676 MB) read from disk into one process;
    - no threads and no `mmap`: the engine is single-threaded and borrows weights from the file in memory;
    - the math functions the engine needs (`sqrt`, `exp`, `sin`, `cos`, `powf`) provided in user space (D-016).
- **Prerequisites:** Phase 2 gate; D-016 and D-017 Accepted.
- **Acceptance criteria:**
  - a user program uses SIMD, and a test shows another process never sees its register state;
  - a process maps memory up to its limit and is refused beyond it, and freed memory returns to the kernel;
  - a `call` to a server that never answers returns a timeout error;
  - data written to the store survives a QEMU kill at random points (fault injection) without corruption: either the old or the new state is read back, checked;
  - a model file of the M3.1 target size is read from disk into a process.
- **Validation:** Automated: QEMU test kernels, fault-injection runs, host tests and fuzzing for the store's on-disk format.
- **Risks and mitigations:** Saving vector state adds context-switch cost and a new leak path → measure, test for leaks, keep the save in the hardware layer; storage corruption → checksums, copy-on-write (per D-007), and fault injection in CI.
- **Out of scope:** Multiple CPUs, user threads (one CPU makes them useless for throughput; reconsider with SMP), GPU drivers (D-011), a general POSIX layer.
- **Definition of done:** Standard, plus a security review of the new kernel paths and the threat model updated.
- **Gate:** Prerequisite tests pass in CI; security review approved.

### M3.1 — Requirements and inference-runtime evaluation

**Status: Done** — gate passed 2026-10-29: D-010 accepted. The requirements ([phase3-requirements.md](phase3-requirements.md), #66) set scenario S1 (summarize a granted file) and its targets; D-020 (#67) put enforcement on Pharos and measurement on the host; the benchmark harness (#68) and the evaluation ([inference-evaluation.md](inference-evaluation.md), #69) measured llama.cpp and our own engine, which matched llama.cpp's output on Qwen2.5-0.5B-Instruct q8_0 at 13.7–14.6 tokens/s on one thread; D-010 and D-011's requirements part (#70) chose our own `no_std` engine, GGUF with Q8_0, and that model, and set the M3.0 targets. CI was green on `main` through the last code change, `49ecb68` ([run 40866848930](https://github.com/codeaiforge/pharos-os/actions/runs/40866848930)). candle was dropped with the maintainer's agreement. Open for M3.2: a tokenizer, batched prompt processing (the S1 prompt takes about 16 s token by token, over the 10 s target), and SIMD.

- **Where it runs (D-020):** Host only (evaluation).
- **Objective and scope:** Define target use cases, hardware requirements, and choose an inference runtime and model formats.
- **Deliverables:** Requirements document ([phase3-requirements.md](phase3-requirements.md): target use cases, the first agent scenario, target model sizes; approved 2026-10-29, #66); benchmark results on the reference host; accepted D-010, D-011 (requirements part), and D-020 (accepted 2026-10-29, #67); the memory and instruction-set targets for M3.0.
- **Prerequisites:** Phase 1 gate (can overlap Phase 2).
- **Acceptance criteria:** At least two runtimes evaluated against the D-010 criteria with measurements (tokens/s, memory use) on documented hardware; license review of runtime and candidate models complete.
- **Validation:** Manual: reproducible benchmark scripts reviewed.
- **Risks and mitigations:** Licenses with use restrictions → explicit license review before adoption.
- **Out of scope:** Integration into Pharos.
- **Definition of done:** Standard.
- **Gate:** D-010 Accepted.

### M3.2 — Model compatibility and local inference

**Status: Done** — gate passed 2026-11-01: the CI jobs passed on `main` at `403c5c7` ([run 41316810311](https://github.com/codeaiforge/pharos-os/actions/runs/41316810311)) with 44 test kernels, among them `inference_tiny` (a tiny Qwen2 model on Pharos, identical to the host) and `inference` (the service as `init` starts it: generation identical to the host, `CONTEXT`, `BUSY`, cancel, the idle drop, a changed and a truncated model refused, a stopped service's `TIMED_OUT`, and exactly its granted handles). Removing the model's SHA-256 check failed CI on a throwaway branch ([run 41316879215](https://github.com/codeaiforge/pharos-os/actions/runs/41316879215)): the host tests and the Rust 1.85 job failed at `each_load_check_refuses_its_file`, and the QEMU job at `inference`, where the changed model was accepted. Every CI run on `main` during M3.2 passed. Scenario S1 on Pharos under KVM (`cargo xtask bench-infer`, #90): first token 6.35 s after the request (target 10 s, counted from a loaded model, #86), 14.2 tokens/s (target 5), 686 MiB peak, text identical to the host's. The IPC round trip was re-measured at a 1938 ns median, within D-004's budget. The security review ([review-m3.2-inference.md](../security/review-m3.2-inference.md)) found and fixed one issue: one client could erase another's `RESULT` record. The maintainer approved it, and D-011's implementation part, on 2026-11-01. Delivered: D-019 (#82), the design (#83), `pharos-proto` (#92), the tokenizer (#84), batched prompts (#85), no hand-written SIMD (#86), first inference on Pharos (#87), the inference service (#88), failure tests (#89), S1 under KVM (#90), and the gate (#91). Carried: the limits in the [threat model](../security/threat-model.md#open-limits-carried-out-of-phase-2), and faster model loading (6.7 s on the first request after boot; not profiled).

- **Where it runs (D-020):** Engine crate host-tested, fuzzed, and compared with llama.cpp on the host, in parallel with M3.0; done only when the service runs on Pharos.
- **Objective and scope:** Run inference locally as an unprivileged service (host prototype first, then on Pharos, per D-020).
- **Deliverables:** Inference service behind a stable provider interface (D-019), so the agent runtime is not bound to one runtime or model; model capability discovery; model and runtime versions recorded with every result; model loading with integrity verification (checksums).
- **Prerequisites:** M3.1; for Pharos: M3.0 (the engine crate can start before M3.0 is done).
- **Acceptance criteria:** A supported model produces output through the service; an unsupported model or configuration is refused with a clear error; a model file failing integrity checks is refused; memory use stays within a configured limit; the service has no privileges beyond its granted capabilities; when the service is down, callers get an error, not a hang.
- **Validation:** Automated: integration tests with a small test model; malformed-model tests. Manual: resource monitoring.
- **Risks and mitigations:** Parser exploits in model loaders → sandbox the service; fuzz loaders where possible.
- **Out of scope:** GPU acceleration unless D-011 supports it.
- **Definition of done:** Standard.
- **Gate:** Inference integration tests pass.

### M3.3 — Agent lifecycle and orchestration

**Status: Done** — gate passed 2026-11-03: the CI jobs passed on `main` at `f5968e1` ([run 41483828684](https://github.com/codeaiforge/pharos-os/actions/runs/41483828684)) with 50 test kernels, among them `process_stop` (the `STOP` right, children stopped with their parent), `trust` (the emergency stop from typed commands while the runtime spins, two agents of one name stopped by name), `agents` (start, crash, hang, exit, and restart up to the attempt limit, inference through the runtime, idempotency keys, checkpoints, and a runtime replaced mid-task), `agents_crash` (QEMU killed 6 times while a task counts), `agents_store` (a task stranded by a storage crash restarts once the store is back), and `supervision` (ready timeouts, bounded restarts, a stopped daemon left stopped, the storage and inference services killed and restarted). Making `BEGIN` stop recording its idempotency key failed CI on a throwaway branch ([run 41519185407](https://github.com/codeaiforge/pharos-os/actions/runs/41519185407)): the host tests and the Rust 1.85 job failed at `keys_answer_go_done_unknown` and `every_store_write_cut`, and the QEMU job at `agents`. Every CI run on `main` during M3.3 passed. The IPC round trip was re-measured at a 1989 ns median, within D-004's budget (11 ns of margin). The security review ([review-m3.3-agents.md](../security/review-m3.3-agents.md)) found and fixed one issue: `stop <agent>` stopped only the first process registered under the name. The maintainer approved it on 2026-11-03. Delivered: D-018 (#93), the design (#94), the `STOP` right (#95), the trusted path (#96), manifests (#97), the agent runtime (#98), durable tasks (#99), supervision (#100), and the gate (#101). Carried: the limits in the [threat model](../security/threat-model.md#open-limits-carried-out-of-phase-2).

- **Where it runs (D-020):** Pharos; task-state and manifest logic host-tested.
- **Objective and scope:** Start, stop, supervise, and restart agents, and keep their work durable across restarts.
- **Deliverables:**
  - agent runtime; agent manifest format (D-019); lifecycle states and events;
  - durable tasks: task state, dependencies, checkpoints, and bounded retries kept in the M3.0 store, with idempotency keys for consequential operations (no exactly-once promise);
  - timeouts and cancellation for every agent request;
  - emergency stop: the user stops an agent and revokes its capabilities through the trusted path (D-018), which works without any agent or model cooperating.
- **Prerequisites:** M3.0 for Pharos; M3.2; D-018 and D-019 Accepted; permission-model design (M3.4) started.
- **Acceptance criteria:** Agents can be started and stopped deterministically; a crashed or hung agent is detected and handled per policy; agents start with zero capabilities; after an agent or runtime restart, task state is recovered and a consequential operation is not repeated (its idempotency key is checked); a stopped agent leaves no running work behind; the emergency stop works while the agent runtime itself is hung.
- **Validation:** Automated: lifecycle tests including crash, hang, and restart cases; fault injection during task checkpoints.
- **Risks and mitigations:** Runaway agents → hard stop always available to the user, outside the agent runtime.
- **Out of scope:** Tool use.
- **Definition of done:** Standard.
- **Gate:** Lifecycle tests pass.

### M3.4 — Permissions, sandboxing, auditability, and isolation

**Status: Current.** M3.3 gives it agents that start with one capability and can always be stopped from the trusted path. D-012 accepted (#102): permissions from the policy table, and beyond it only by approval on the trusted path for one task; revocation per permission and at once, memory unmapped by the kernel; expiry on runtime grants only; default-deny networking per destination. Design: [capabilities.md](../architecture/capabilities.md) (#103), approved 2026-11-03. Next: kernel revocation of mapped memory (#104).

- **Where it runs (D-020):** Pharos; audit-record format host-tested.
- **Objective and scope:** Enforce explicit, least-privilege capabilities for agents, sandbox them, and record grants and sensitive actions in a protected audit trail.
- **Deliverables:**
  - capability grant and revoke mechanism (per D-012 and D-018): authority comes only from capabilities; identities (agent, model, tool, user) are recorded for attribution and never grant access by themselves; delegation only narrows rights;
  - sandbox;
  - audit as a trusted service: append-only, integrity-checked records in the M3.0 store (D-017), linking each consequential action to who initiated it, the capability used, the services invoked, and the outcome; consequential actions are refused while the audit trail cannot be written;
  - `docs/architecture/capabilities.md`.
- **Prerequisites:** M3.3; M2.7 (for kernel enforcement on Pharos); D-017 and D-018 Accepted.
- **Acceptance criteria:** Adversarial tests show an agent cannot access files, processes, devices, or network endpoints without a capability, whatever it claims to be; revocation takes effect immediately; every grant and revocation appears in the audit log; tampering with an audit record is detected; an investigator can reconstruct a consequential operation from the audit trail alone.
- **Validation:** Automated: adversarial test suite. Manual: security review.
- **Risks and mitigations:** Permission fatigue → sensible grouped grants; clear prompts.
- **Out of scope:** Multi-user policy.
- **Definition of done:** Standard, plus threat model updated.
- **Gate:** D-012 Accepted; adversarial tests pass; security review complete.

### M3.5 — Resource accounting and limits

**Status: Planned.**

- **Where it runs (D-020):** Pharos; accounting logic host-tested.
- **Objective and scope:** Per-agent and per-group limits on CPU, memory, storage, network, and inference usage, with resources reserved for essential system functions.
- **Deliverables:** Accounting attributed to each agent and group; enforcement; admission control for inference requests; reservations for the kernel, trusted services, and the emergency-stop path; limit configuration; usage reporting.
- **Prerequisites:** M3.4.
- **Acceptance criteria:** An agent or group exceeding a limit is throttled or stopped per policy without affecting other agents or the system; under full load the emergency stop and trusted services still respond; every unit of usage is attributed to an agent or a system component.
- **Validation:** Automated: resource-exhaustion tests.
- **Risks and mitigations:** Accounting overhead → measure and document.
- **Out of scope:** Billing.
- **Definition of done:** Standard.
- **Gate:** Exhaustion tests pass.

### M3.6 — Controlled tool integration

**Status: Planned.**

- **Where it runs (D-020):** Pharos; the tool-call validator host-tested and fuzzed.
- **Objective and scope:** Let agents invoke defined tools only through capability checks.
- **Deliverables:** Tool interface; initial tool set (for example read a granted file); validation of model-generated tool calls.
- **Prerequisites:** M3.4, M3.5.
- **Acceptance criteria:** Tool calls without a capability are refused and logged; malformed or injected tool calls are rejected; sensitive tools require user confirmation.
- **Validation:** Automated: prompt-injection and malformed-call test suite. Manual: review of each tool's permission requirements.
- **Risks and mitigations:** Prompt injection → model output never trusted; least-privilege tools.
- **Out of scope:** Arbitrary shell execution tools.
- **Definition of done:** Standard.
- **Gate:** Injection test suite passes.

### M3.7 — Agent communication and coordination

**Status: Planned.**

- **Where it runs (D-020):** Pharos; codecs and group-state logic host-tested.
- **Objective and scope:** Agents communicate only through granted channels, and groups of agents work toward a shared goal under explicit authority and budgets.
- **Deliverables:** Message channels built on IPC with typed messages (D-019); coordination patterns (for example supervisor and worker); agent groups with a goal, completion criteria, tasks, delegation, and a group budget, built on M3.3 durable tasks.
- **Prerequisites:** M3.4, M3.5, M3.6.
- **Acceptance criteria:** Agents without a shared channel cannot communicate; messages are logged per policy; a compromised agent cannot gain another agent's capabilities through messaging; joining a group grants nothing, and delegation only narrows authority; a group stays within its budget; a failed or timed-out worker is handled, and stopping a group leaves no running work; results are checked by a non-agent verifier before they count as done.
- **Validation:** Automated: isolation and confused-deputy tests.
- **Risks and mitigations:** Capability leakage via messages → capabilities are not transferable unless explicitly allowed.
- **Out of scope:** Cross-machine agents.
- **Definition of done:** Standard.
- **Gate:** Coordination and isolation tests pass.

### M3.8 — Knowledge service

**Status: Planned.**

- **Where it runs (D-020):** Pharos; data model and provenance logic host-tested.
- **Objective and scope:** A shared, permission-aware knowledge service with provenance, separate from each agent's private memory.
- **Deliverables:** A small, versioned data model and stable interface (D-019) on the M3.0 store; provenance on every entry (source, author, time, version and scope, verification status); private agent memory kept separate, with promotion to shared knowledge explicit and policy-checked; history kept, so corrections never rewrite the evidence behind earlier decisions.
- **Prerequisites:** M3.4, M3.5; M3.0 for Pharos.
- **Acceptance criteria:** Reads and writes need capabilities, and a query or summary never returns content whose evidence the caller cannot read; verified facts, unverified claims, stale entries, and conflicting entries remain distinguishable; stored content is never treated as instructions or policy (prompt-injection tests); an update is attributable and audited.
- **Validation:** Automated: access-control, provenance, staleness, and injection tests. Manual: security review.
- **Risks and mitigations:** Poisoned knowledge → provenance and verification status on every entry, and no authority from content; premature technology choices → no graph database or semantic search until real queries justify one, recorded in a decision.
- **Out of scope:** Distributed or federated knowledge; semantic retrieval unless justified by measured needs.
- **Definition of done:** Standard, plus threat model updated.
- **Gate:** Phase 3 gate.

---

## Phase 4 — Full Operating System

**Status: Planned.**

- **Objective and scope:** Integrate the kernel, user-space services, and AI platform into a coherent, configurable, recoverable system.
- **Deliverables:** M4.1–M4.6.
- **Prerequisites:** Phase 2 and Phase 3 gates.
- **Acceptance criteria:** A full system boots in QEMU, starts services and the agent platform, and survives defined failure scenarios.
- **Validation:** Automated: end-to-end QEMU scenarios. Manual: exploratory testing; security review.
- **Risks and mitigations:** Integration complexity → integrate one service at a time with tests.
- **Out of scope:** Broad hardware support (Phase 5).
- **Definition of done:** Standard.
- **Gate:** All M4.x gates; full threat-model review.

### M4.1 — Integration of kernel and user-space services

- **Objective and scope:** Boot into a complete user space with services started by a service manager. **Status: Planned** (partly delivered: M2.10's `init` starts services in a fixed order and reports each failure).
- **Deliverables:** Service manager with declared dependencies and restart policies, building on `init`; integrated system image.
- **Prerequisites:** Phase 2 gate.
- **Acceptance criteria:** System reaches a defined "ready" state in QEMU; each service failure is reported.
- **Validation:** Automated: end-to-end boot test to ready state.
- **Risks and mitigations:** Startup ordering bugs → explicit dependencies.
- **Out of scope:** Graphical user interface.
- **Definition of done:** Standard.
- **Gate:** Ready-state test passes in CI.

### M4.2 — Security model and privilege separation

- **Objective and scope:** Apply the security model system-wide: each service runs with minimal capabilities. **Status: Planned.**
- **Deliverables:** Per-service capability manifests; privilege-separation review.
- **Prerequisites:** M4.1, M3.4.
- **Acceptance criteria:** No user-space service holds capabilities beyond its manifest; tests confirm.
- **Validation:** Automated: capability audit test. Manual: security review.
- **Risks and mitigations:** Over-broad manifests → review each manifest.
- **Out of scope:** Formal verification.
- **Definition of done:** Standard, plus threat model updated.
- **Gate:** Security review complete.

### M4.3 — Reliable boot and recovery

- **Objective and scope:** Detect failed boots and updates and recover to a known-good state. Agents may diagnose and propose repairs, but recovery never depends on them. **Status: Planned.**
- **Deliverables:** Recovery mode and safe mode reachable through the trusted path (D-018); known-good image fallback (for example A/B images); signed system updates with rollback; detection of restart and repair loops; Secure Boot evaluation.
- **Prerequisites:** M4.1; M3.0 (writable storage).
- **Acceptance criteria:** Simulated corrupted system image leads to recovery, not an unbootable system; a rejected or failing update is rolled back; an update proposed by an agent cannot be applied without the required approval; a malfunctioning agent cannot disable recovery or the emergency stop.
- **Validation:** Automated: fault-injection boot tests.
- **Risks and mitigations:** Recovery path untested → test it in CI.
- **Out of scope:** Over-the-air updates.
- **Definition of done:** Standard.
- **Gate:** Recovery tests pass.

### M4.4 — Device and service management

- **Objective and scope:** Manage devices and services at runtime (start, stop, restart, status). **Status: Planned.**
- **Deliverables:** Management interface and CLI.
- **Prerequisites:** M4.1, M2.9.
- **Acceptance criteria:** Services can be restarted without reboot; device add/remove (where QEMU supports it) is handled.
- **Validation:** Automated: QEMU tests.
- **Risks and mitigations:** Management interface as attack surface → capability-protected.
- **Out of scope:** Remote management.
- **Definition of done:** Standard.
- **Gate:** Management tests pass.

### M4.5 — System configuration and diagnostics

- **Objective and scope:** Declarative configuration and diagnostics (logs, health checks). **Status: Planned.**
- **Deliverables:** Configuration format and validation; diagnostics tooling.
- **Prerequisites:** M4.4.
- **Acceptance criteria:** Invalid configuration is rejected with a clear error before it is applied; diagnostics report service and agent health.
- **Validation:** Automated: configuration validation tests.
- **Risks and mitigations:** Misconfiguration widening privileges → validation against policy.
- **Out of scope:** Telemetry to external servers.
- **Definition of done:** Standard.
- **Gate:** Configuration tests pass.

### M4.6 — Integration of AI services without unrestricted kernel access

- **Objective and scope:** Run inference and the agent runtime as integrated system services with no privileged access. **Status: Planned.**
- **Deliverables:** AI services under the service manager with capability manifests.
- **Prerequisites:** M4.2, Phase 3 gate.
- **Acceptance criteria:** AI services run unprivileged; adversarial tests show they cannot access kernel memory or resources outside their capabilities; the system remains usable if AI services fail.
- **Validation:** Automated: adversarial and failure tests. Manual: security review.
- **Risks and mitigations:** Pressure to grant broad access for convenience → requires a decision record and security review.
- **Out of scope:** Kernel-resident inference.
- **Definition of done:** Standard, plus threat model updated.
- **Gate:** Phase 4 gate.

---

## Phase 5 — Deployment and Release

**Status: Planned.**

- **Objective and scope:** Make the system releasable: broad testing, hardware compatibility, performance, security review, and reproducible artifacts.
- **Deliverables:** M5.1–M5.5.
- **Prerequisites:** Phase 4 gate (automated QEMU regression testing has run since M2.3).
- **Acceptance criteria:** Documented release criteria are met.
- **Validation:** Automated: full regression suite. Manual: hardware testing; external security review if available.
- **Risks and mitigations:** Release pressure overriding quality → release criteria are a hard gate.
- **Out of scope:** Commercial support commitments.
- **Definition of done:** Standard.
- **Gate:** Release criteria met and approved by maintainers.

### M5.1 — QEMU regression and release testing

- **Objective and scope:** Broaden the QEMU regression suite (running since M2.3) into a release test matrix. **Status: Planned.**
- **Deliverables:** Test matrix (firmware, memory sizes, CPU models); long-running stability tests.
- **Prerequisites:** Phase 4 gate.
- **Acceptance criteria:** Full matrix passes; no known crash bugs open.
- **Validation:** Automated: matrix in CI or scheduled runs.
- **Risks and mitigations:** CI cost → scheduled runs for long tests.
- **Out of scope:** Real hardware (M5.2).
- **Definition of done:** Standard.
- **Gate:** Matrix green.

### M5.2 — Hardware compatibility testing

- **Objective and scope:** Validate on a documented set of real machines, with explicit authorization for each test. **Status: Planned.**
- **Deliverables:** Hardware compatibility list; test reports.
- **Prerequisites:** M5.1.
- **Acceptance criteria:** Boots and passes the smoke suite on each listed machine.
- **Validation:** Manual: documented test procedure per machine.
- **Risks and mitigations:** Bricking or data loss → test on dedicated hardware only; never on a machine with important data.
- **Out of scope:** Exhaustive hardware coverage.
- **Definition of done:** Standard.
- **Gate:** Compatibility list published.

### M5.3 — Performance, reliability, and resource optimization

- **Objective and scope:** Measure and improve boot time, inference throughput, memory use, and stability. **Status: Planned.**
- **Deliverables:** Benchmarks; performance budget; fixes.
- **Prerequisites:** M5.1.
- **Acceptance criteria:** Performance budget met on reference hardware; no regressions beyond thresholds.
- **Validation:** Automated: benchmark tracking.
- **Risks and mitigations:** Optimizations weakening security → security review of performance changes.
- **Out of scope:** Micro-optimizations without measurements.
- **Definition of done:** Standard.
- **Gate:** Budget met.

### M5.4 — Security review and threat-model update

- **Objective and scope:** Full security review before release. **Status: Planned.**
- **Deliverables:** Updated threat model; review report; fixes; security reporting process reviewed.
- **Prerequisites:** M5.1.
- **Acceptance criteria:** No open critical or high findings; every `unsafe` block reviewed; dependencies audited.
- **Validation:** Manual: review; external audit if resources allow.
- **Risks and mitigations:** Limited reviewer capacity → prioritize TCB and agent isolation.
- **Out of scope:** Certification.
- **Definition of done:** Standard.
- **Gate:** Review sign-off.

### M5.5 — Reproducible builds, release artifacts, documentation, and release criteria

- **Objective and scope:** Produce verifiable releases. **Status: Planned.**
- **Deliverables:** Reproducible build procedure; signed artifacts; user documentation; written release criteria.
- **Prerequisites:** M5.2, M5.3, M5.4.
- **Acceptance criteria:** Two independent builds produce bit-identical artifacts; release criteria documented and met.
- **Validation:** Automated: reproducibility check. Manual: maintainer approval.
- **Risks and mitigations:** Non-determinism in toolchains → pin toolchain for release builds; document environment.
- **Out of scope:** App stores, package-manager distribution.
- **Definition of done:** Standard.
- **Gate:** Phase 5 gate; maintainer approves release.

---

## Open decisions

Full entries are in the [decision log](decision-log.md). D-001 to D-003 were accepted on 2026-10-26; D-009, D-006, D-005, D-013, D-004, D-014, D-007, and D-008 on 2026-10-27; D-015 on 2026-10-28; D-020, D-010, D-011 (requirements part), D-016, and D-017 on 2026-10-29; D-019 and D-021 on 2026-10-31; D-011's implementation part and D-018 on 2026-11-01; D-012 (final, with D-018) on 2026-11-03; the rest are open.

| ID | Decision | Needed by | Key evaluation criteria |
| --- | --- | --- | --- |
| D-001 | Bootloader and boot protocol | M2.1 | **Accepted:** Limine, Limine protocol, own protocol structures |
| D-002 | BIOS and/or UEFI | M2.1 | **Accepted:** UEFI primary, BIOS secondary |
| D-003 | Rust target, linker, build strategy | M2.1 | **Accepted:** `x86_64-unknown-none` on stable, linker script, `xtask`, ISO, kernel as workspace member |
| D-004 | Kernel architecture and privilege boundaries | M2.1 (direction), M2.7 | **Accepted:** capability-based microkernel, `unsafe` in a small hardware layer; IPC round trip ≤ 2 µs (KVM) |
| D-005 | Memory-management strategy | M2.5 | **Accepted:** bitmap frame allocator per region, own page tables, Limine's HHDM with 2 MiB pages, own bitmap heap, `unsafe` in `mm::raw` |
| D-006 | Interrupt controller and timer | M2.4, M2.6 | **Accepted:** local APIC (xAPIC), PICs masked; APIC timer at 100 Hz calibrated against the PIT, TSC uptime clock |
| D-007 | Filesystem and persistent storage | M2.8 | **Accepted:** read-only RAM disk from a Limine module; small custom format with CRC-32 checksums, one safe `no_std` parser for kernel and host; in the kernel for now, files through capabilities only |
| D-008 | Driver strategy | M2.9 | **Accepted:** user-space drivers with device, interrupt, MMIO, and DMA capabilities; virtio-blk only in M2.9; PCI through config ports, MSI-X; no IOMMU yet (tracked limit) |
| D-009 | QEMU automation and debugging | M2.3 | **Accepted:** status 33 + serial marker, 60 s timeout, test kernels via Cargo runner and `cargo xtask test` |
| D-010 | Inference runtime, model formats, licensing | M3.1 | **Accepted:** our own `no_std` engine on Pharos; GGUF with Q8_0; Qwen2.5-0.5B-Instruct q8_0 for S1; llama.cpp host-only reference; deterministic output required |
| D-011 | CPU/GPU support, memory/VRAM | M3.1, M3.2 | **Requirements accepted:** CPU only; SSE2 required, AVX2 used when present; 1 GiB for the inference service, 2 GiB guest; no threads. **Implementation part accepted (#91):** SSE2 only, no AVX2 or FMA (both S1 targets met); 686 MiB peak within 1 GiB |
| D-015 | Network stack and service model | M2.10 | **Accepted:** own minimal stack (Ethernet, ARP, IPv4, ICMP echo, UDP; no TCP) inside the virtio-net driver's process; badged capabilities as network capabilities (amended, #59); static slirp addresses; the kernel starts `init`, which starts services |
| D-014 | IPC model and system-call mechanism | M2.7 | **Accepted:** `syscall`/`sysret`; synchronous endpoints, 256-byte messages plus one capability, bounded per-thread buffers |
| D-012 | Agent sandboxing, tool permissions, network isolation | M2.7 (direction), M3.4 | **Accepted** (final, #102): kernel-enforced capabilities, policy in the agent runtime; permissions from the policy table, beyond it only by approval on the trusted path for one task; revocation per permission and at once, memory unmapped by the kernel; expiry on runtime grants only; default-deny networking per destination, checked by the runtime and the network service; every consequential action audited, and refused while the trail cannot be written |
| D-016 | User execution environment: SIMD state, user memory, timeouts | M3.0 | **Accepted:** user programs built for `x86_64-unknown-linux-gnu` as `no_std` static programs; eager XSAVE/FXSAVE per thread; `mem_map`/`mem_unmap` with a per-process limit; timeout argument and `TIMED_OUT`; `libm` in user space |
| D-017 | Writable persistent storage and audit integrity | M3.0, M3.4 | **Accepted:** new `pharos-store` crate; copy-on-write with two superblock roots; whole-file objects and append-only streams; SHA-256-chained audit records; storage service in the virtio-blk driver's process; shared-memory capabilities for bulk data |
| D-018 | Authority model: capabilities, identity, human control | M3.3 | **Accepted** (final with D-012, #102): authority only from capabilities; identity for attribution and audit; delegation narrows; a trusted path for emergency stop and revocation that needs no agent or model, on a virtio-console device owned by a trusted service; a `STOP` right that also stops a process's children, held by the agent runtime and by the trusted service; M3.3 grants only from a reviewed table |
| D-019 | Service interfaces and versioning | M3.2, M3.3 | **Accepted:** hand-written codecs in a shared `no_std` crate `pharos-proto` (no interface language); every message starts with interface version and operation, `VERSION` refused with the supported range; common status codes and the common operations `INFO` (discovery) and `ATTACH` (bulk data through shared memory); capabilities handed out by `init`, no registry; per-operation timeouts, long results pulled with `NEXT`/`CANCEL`; network and storage move to it in M3.2 (#92) |
| D-020 | Where Phase 3 runs first | M3.1 | **Accepted:** one codebase of `no_std` crates tested on the host and run on Pharos; measurements on the host; enforcement shown only on Pharos; M3.0 on the critical path from M3.2 |
| D-013 | Scheduling model | M2.6 | **Accepted:** preemptive round-robin on one CPU, 10 ms slice, kernel threads on guarded stacks, no lock held across a switch |

## Next milestone

Phase 1 passed its gate and was released as v0.1.0. M2.1 passed its gate on 2026-10-26, and M2.2 and M2.3 on 2026-10-27. M2.4, M2.5, M2.6, M2.7, and M2.8 passed their gates on 2026-10-27, M2.9 on 2026-10-28, and M2.10 on 2026-10-29, which closed Phase 2 (prepared for release as v0.2.0). M3.1 passed its gate on 2026-10-29 with D-010 accepted, M3.0 (platform prerequisites) on 2026-10-30, M3.2 (local inference) on 2026-11-01, and M3.3 (agent lifecycle) on 2026-11-03. The current milestone is **M3.4 — Permissions, sandboxing, auditability, and isolation**. D-004 (final: capability-based microkernel) was accepted and the D-012 direction (kernel-enforced capabilities) recorded on 2026-10-27.
