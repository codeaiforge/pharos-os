# Architecture

This document has two parts: what is **implemented** today, and the **proposed** architecture. The proposed architecture is a direction, not an approved design; the decisions it depends on are open in the [decision log](decision-log.md).

## Implemented architecture

```text
Cargo workspace (stable Rust, edition 2024)
├── tools/pharos-cli   binary `pharos` (host): read-only development CLI, std only
├── xtask              binary `xtask` (host): builds the kernel and the boot ISO, std only
└── kernel             `pharos-kernel` for x86_64-unknown-none:
                       ├── library (no_std): Limine protocol structures, boot-info logic,
                       │                     SpinLock, x86-64 hardware layer (console, halt)
                       └── binary (no_main): entry point, Limine requests
```

- **Kernel (M2.2–M2.6, minimal):**
  - Limine boots it on UEFI and BIOS. It checks the protocol revision and reports boot information over COM1.
  - It handles CPU exceptions and local APIC timer interrupts ([interrupts.md](../architecture/interrupts.md)).
  - It manages physical memory, runs on its own page tables, and has a heap ([memory.md](../architecture/memory.md)).
  - It calibrates a 100 Hz timer and schedules kernel tasks preemptively ([scheduling.md](../architecture/scheduling.md)).
  - It has no user processes, system calls, IPC, or drivers beyond serial, the interrupt controller, and the timer.
  - CI boots it and runs its test kernels in QEMU on every push.
- `unsafe` is forbidden in host crates. In the kernel it is denied by default and allowed only in the hardware layer and the Limine protocol module, each block documented (enforced by lints).
- No package has third-party dependencies. The CLI and `xtask` do not depend on the kernel crate.

## Proposed architecture (planned)

### Layers

```text
┌──────────────────────────────────────────────────────────────┐
│ Agents (untrusted)            each in its own sandbox        │
├──────────────────────────────────────────────────────────────┤
│ Agent runtime & policy        lifecycle, capability grants,  │
│                               resource limits, audit log     │
├──────────────────────────────────────────────────────────────┤
│ Inference service             model loading and execution,   │
│ (unprivileged)                bounded CPU/GPU/memory         │
├──────────────────────────────────────────────────────────────┤
│ System services (user space)  storage, filesystem, network,  │
│                               device drivers where feasible  │
├────────────────────── privilege boundary ────────────────────┤
│ Kernel (privileged, minimal)  memory, scheduling, interrupts,│
│                               isolation, IPC, capabilities   │
├──────────────────────────────────────────────────────────────┤
│ Boot (bootloader / firmware interface)                       │
└──────────────────────────────────────────────────────────────┘
Host tooling (outside the OS): pharos CLI, build, QEMU test harness
```

### Boundaries

| Boundary | Rule |
| --- | --- |
| Kernel ↔ user space | Only the kernel runs privileged. User space reaches it through a small, documented system-call interface. |
| Services ↔ agents | Agents reach services only through IPC endpoints granted to them as capabilities. |
| Inference ↔ everything privileged | Inference is an unprivileged service. Its output is data, never commands, until checked by policy. |
| Agent ↔ agent | No shared state by default; communication only through granted channels. |
| Host tooling ↔ OS | Host tools build, launch, and inspect the OS in QEMU; they are not part of the OS trust base. |

### Capability model (direction)

Agents start with no authority. The user or a policy grants specific capabilities (for example: read one directory, call one tool, reach one network host). Grants are logged, can be limited by time and resources, and can be revoked. The exact mechanism (kernel-level capabilities versus a user-space policy service, or both) is an open decision.

### Kernel style

The kernel style is decided (decision D-004, accepted 2026-10-27): a **capability-based microkernel**. The kernel keeps address spaces, threads and scheduling, IPC, capabilities, and interrupt delivery, while drivers, filesystems, networking, and AI services run in user space. Inside the kernel, `unsafe` code is confined to a small hardware layer. The decision, its IPC budget, the evidence that would reopen it, and the constraints it places on kernel code are in the [decision log](decision-log.md#d-004-kernel-architecture-and-privilege-boundaries).

## Keeping this document accurate

- Move an item from "proposed" to "implemented" only when it exists and is tested.
- Detailed designs go in [docs/architecture/](../architecture/README.md); this file stays a short overview.
