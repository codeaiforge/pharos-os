# Architecture

This document has two parts: what is **implemented** today, and the **proposed** architecture. The proposed architecture is a direction, not an approved design; the decisions it depends on are open in the [decision log](decision-log.md).

## Implemented architecture (Phase 1)

```text
Cargo workspace (host, stable Rust, edition 2024)
├── tools/pharos-cli   binary `pharos` — host-side CLI, std only, no dependencies
└── kernel             library `pharos_kernel` — host-side placeholder, std, no OS functionality
```

- The two packages are independent; the CLI does not depend on the kernel crate. A host tool should not link the future `no_std` kernel.
- Neither package uses `unsafe` (forbidden by workspace lints) or third-party dependencies.
- Nothing boots. There is no kernel, no target configuration, and no QEMU integration.

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

The final kernel style is **not decided** (decision D-004, due before M2.7). The **initial direction** (recorded at M2.1) is a **capability-based microkernel**: the kernel keeps address spaces, threads and scheduling, IPC, capabilities, and interrupt delivery, while drivers, filesystems, networking, and AI services run in user space. Inside the kernel, `unsafe` code is confined to a small hardware layer. The direction, the evidence that would change it, and the constraints it places on early kernel code are in the [decision log](decision-log.md#d-004-kernel-architecture-and-privilege-boundaries).

## Keeping this document accurate

- Move an item from "proposed" to "implemented" only when it exists and is tested.
- Detailed designs go in [docs/architecture/](../architecture/README.md); this file stays a short overview.
