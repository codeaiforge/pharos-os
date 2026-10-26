# Implementation roadmap

This is the authoritative plan for Pharos OS. It is ordered by dependency, not by calendar: it contains no dates or effort estimates, because no real project plan supports them yet.

**Phase 1 — Foundation is done (released as v0.1.0). Current milestone: M2.2 — Minimal bootable x86-64 kernel.** Everything in Phases 2–5 is **planned, not implemented**.

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
| Host-side prototyping | Phase 3 | Inference and agent-runtime prototypes can run on the Linux host before the kernel can host them, so Phase 3 evaluation may overlap Phase 2. Prototypes must not be presented as running on Pharos. |

## Phase overview

| Phase | Name | Status |
| --- | --- | --- |
| 1 | Foundation | Done (v0.1.0) |
| 2 | Core System | **Current** (M2.2) |
| 3 | AI Agent Platform | Planned |
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

**Status: Current.**

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

**Status: Current.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

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

**Status: Planned.**

Ordering note: within this phase, **permissions and resource limits (M3.4, M3.5) come before tool integration and agent communication (M3.6, M3.7)**, so that no agent gets tools or channels without enforcement already in place.

- **Objective and scope:** Local inference and an agent runtime in which agents are untrusted, isolated, resource-limited, and use only granted capabilities. Early milestones may be prototyped on the Linux host.
- **Deliverables:** M3.1–M3.7.
- **Prerequisites:** M3.1 can start during Phase 2. Running on Pharos requires the Phase 2 gate.
- **Acceptance criteria:** Each milestone's criteria; agent isolation verified by adversarial tests.
- **Validation:** Automated: unit and integration tests; QEMU tests once on Pharos; prompt-injection test suite. Manual: security review.
- **Risks and mitigations:** AI dominates the TCB → inference stays unprivileged; model output untrusted.
- **Out of scope:** Training models; cloud inference as a requirement.
- **Definition of done:** Standard, plus threat model updated for agents and inference.
- **Gate:** All M3.x gates; agent isolation security review complete.

### M3.1 — Requirements and inference-runtime evaluation

**Status: Planned.**

- **Objective and scope:** Define target use cases, hardware requirements, and choose an inference runtime and model formats.
- **Deliverables:** Requirements document; benchmark results on the reference host; accepted D-010 and D-011 (requirements part).
- **Prerequisites:** Phase 1 gate (can overlap Phase 2).
- **Acceptance criteria:** At least two runtimes evaluated against the D-010 criteria with measurements (tokens/s, memory use) on documented hardware; license review of runtime and candidate models complete.
- **Validation:** Manual: reproducible benchmark scripts reviewed.
- **Risks and mitigations:** Licenses with use restrictions → explicit license review before adoption.
- **Out of scope:** Integration into Pharos.
- **Definition of done:** Standard.
- **Gate:** D-010 Accepted.

### M3.2 — Model compatibility and local inference

**Status: Planned.**

- **Objective and scope:** Run inference locally as an unprivileged service (host prototype first, then on Pharos).
- **Deliverables:** Inference service with a defined request/response interface; model loading with integrity verification (checksums).
- **Prerequisites:** M3.1; for Pharos: M2.7, M2.8.
- **Acceptance criteria:** A supported model produces output through the service; a model file failing integrity checks is refused; memory use stays within a configured limit; the service has no privileges beyond its granted capabilities.
- **Validation:** Automated: integration tests with a small test model; malformed-model tests. Manual: resource monitoring.
- **Risks and mitigations:** Parser exploits in model loaders → sandbox the service; fuzz loaders where possible.
- **Out of scope:** GPU acceleration unless D-011 supports it.
- **Definition of done:** Standard.
- **Gate:** Inference integration tests pass.

### M3.3 — Agent lifecycle and orchestration

**Status: Planned.**

- **Objective and scope:** Start, stop, supervise, and restart agents.
- **Deliverables:** Agent runtime; agent manifest format; lifecycle states and events.
- **Prerequisites:** M3.2; permission-model design (M3.4) started.
- **Acceptance criteria:** Agents can be started and stopped deterministically; a crashed agent is detected and handled per policy; agents start with zero capabilities.
- **Validation:** Automated: lifecycle tests including crash and hang cases.
- **Risks and mitigations:** Runaway agents → hard stop always available to the user.
- **Out of scope:** Tool use.
- **Definition of done:** Standard.
- **Gate:** Lifecycle tests pass.

### M3.4 — Permissions, sandboxing, auditability, and isolation

**Status: Planned.**

- **Objective and scope:** Enforce explicit, least-privilege capabilities for agents, sandbox them, and log grants and sensitive actions.
- **Deliverables:** Capability grant and revoke mechanism (per D-012); sandbox; audit log; `docs/architecture/capabilities.md`.
- **Prerequisites:** M3.3; M2.7 (for kernel enforcement on Pharos).
- **Acceptance criteria:** Adversarial tests show an agent cannot access files, processes, devices, or network endpoints without a capability; revocation takes effect immediately; every grant and revocation appears in the audit log.
- **Validation:** Automated: adversarial test suite. Manual: security review.
- **Risks and mitigations:** Permission fatigue → sensible grouped grants; clear prompts.
- **Out of scope:** Multi-user policy.
- **Definition of done:** Standard, plus threat model updated.
- **Gate:** D-012 Accepted; adversarial tests pass; security review complete.

### M3.5 — Resource accounting and limits

**Status: Planned.**

- **Objective and scope:** Per-agent limits on CPU, memory, storage, network, and inference usage.
- **Deliverables:** Accounting and enforcement; limit configuration; usage reporting.
- **Prerequisites:** M3.4.
- **Acceptance criteria:** An agent exceeding a limit is throttled or stopped per policy without affecting other agents or the system.
- **Validation:** Automated: resource-exhaustion tests.
- **Risks and mitigations:** Accounting overhead → measure and document.
- **Out of scope:** Billing.
- **Definition of done:** Standard.
- **Gate:** Exhaustion tests pass.

### M3.6 — Controlled tool integration

**Status: Planned.**

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

- **Objective and scope:** Agents communicate only through granted channels.
- **Deliverables:** Message channels built on IPC; coordination patterns (for example supervisor and worker).
- **Prerequisites:** M3.4, M3.6.
- **Acceptance criteria:** Agents without a shared channel cannot communicate; messages are logged per policy; a compromised agent cannot gain another agent's capabilities through messaging.
- **Validation:** Automated: isolation and confused-deputy tests.
- **Risks and mitigations:** Capability leakage via messages → capabilities are not transferable unless explicitly allowed.
- **Out of scope:** Cross-machine agents.
- **Definition of done:** Standard.
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

- **Objective and scope:** Boot into a complete user space with services started by a service manager. **Status: Planned.**
- **Deliverables:** Init and service manager; integrated system image.
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

- **Objective and scope:** Detect failed boots and recover to a known-good state. **Status: Planned.**
- **Deliverables:** Recovery mode; known-good image fallback; Secure Boot evaluation.
- **Prerequisites:** M4.1.
- **Acceptance criteria:** Simulated corrupted system image leads to recovery, not an unbootable system.
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

Full entries are in the [decision log](decision-log.md). D-001 to D-003 were accepted on 2026-10-26; the rest are open.

| ID | Decision | Needed by | Key evaluation criteria |
| --- | --- | --- | --- |
| D-001 | Bootloader and boot protocol | M2.1 | **Accepted:** Limine, Limine protocol, own protocol structures |
| D-002 | BIOS and/or UEFI | M2.1 | **Accepted:** UEFI primary, BIOS secondary |
| D-003 | Rust target, linker, build strategy | M2.1 | **Accepted:** `x86_64-unknown-none` on stable, linker script, `xtask`, ISO, kernel as workspace member |
| D-004 | Kernel architecture and privilege boundaries | M2.1 (direction), M2.7 | **Direction:** capability-based microkernel; final decision open |
| D-005 | Memory-management strategy | M2.5 | Correctness, fragmentation, `unsafe` surface |
| D-006 | Interrupt controller and timer | M2.4, M2.6 | QEMU/hardware support, SMP readiness |
| D-007 | Filesystem and persistent storage | M2.8 | Crash consistency, simplicity, host tooling |
| D-008 | Driver strategy | M2.9 | TCB size, DMA isolation, effort |
| D-009 | QEMU automation and debugging | M2.3 | Deterministic results, headless CI, no root |
| D-010 | Inference runtime, model formats, licensing | M3.1 | Licenses, memory safety, performance, portability |
| D-011 | CPU/GPU support, memory/VRAM | M3.1, M3.2 | Hardware requirements, driver availability |
| D-012 | Agent sandboxing, tool permissions, network isolation | M2.7 (direction), M3.4 | No ambient authority, revocation, auditability |

## Next milestone

Phase 1 passed its gate and was released as v0.1.0. M2.1 passed its gate on 2026-10-26. The current milestone is **M2.2 — Minimal bootable x86-64 kernel**; the first measurable kernel result follows at M2.3 (reproducible QEMU boot with observable serial output, tested in CI).
