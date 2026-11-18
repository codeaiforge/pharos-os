# Architecture documents

This directory holds the detailed design documents, one per subsystem. **Start with [how Pharos works](overview.md)**: diagrams of the layers, what each process holds, the boot, an agent task end to end, and the trust zones, with links into the documents below. The short overview stays in [docs/project/architecture.md](../project/architecture.md); decisions are recorded in [docs/project/decision-log.md](../project/decision-log.md).

Each document's own Status section says what is **implemented**, **placeholder**, or **planned**.

**Overview**

- [How Pharos works](overview.md) — how the components interact, in diagrams; the place to start.

**Kernel**

- [Boot design](boot.md) — boot flow, kernel entry contract, image layout, the build tool, and recovery and signed updates (M2.2, M2.3, M4.3; D-028).
- [Memory management](memory.md) — frame allocator, the kernel's own page tables, and the kernel address space (M2.5, D-005).
- [Exceptions and interrupts](interrupts.md) — IDT, exception handling, the interrupt stacks, and the local APIC timer (M2.4, D-006).
- [Scheduling](scheduling.md) — kernel tasks, their stacks, the context switch, scheduling classes, and locking rules (M2.6, D-013).
- [System calls and IPC](syscalls-ipc.md) — processes, the system-call interface, capabilities, and IPC (M2.7, D-004, D-012, D-014).
- [The user execution environment](user-environment.md) — vector state, user memory, timeouts, and shared memory for user programs (M3.0, D-016).
- [DMA isolation](iommu.md) — a VT-d driver for QEMU's `intel-iommu`: one domain per device, blocked by default (M5.2, D-044; implemented).
- [Release integrity](release-integrity.md) — the per-VM device secret, the signed audit head, the slot record's MAC, Secure Boot, and signed release artifacts (M5.5, D-047; design approved, implementation planned).

**System services**

- [Storage and the filesystem](storage.md) — block devices, the read-only image format, the writable copy-on-write store, and file capabilities (M2.8, M3.0; D-007, D-017).
- [Drivers and device access](drivers.md) — Rust user programs and the ELF loader, PCI discovery, device interrupts, MMIO and DMA capabilities, virtio drivers, and hotplug (M2.9, M4.4; D-008).
- [Processes and system services](services.md) — process creation from user space, badges, notifications, `init`, supervision, manifests, configuration, and health (M2.10, M4.1–M4.6; D-015, D-026 to D-031).
- [Networking](networking.md) — the virtio-net driver, the minimal network stack, network capabilities, and the host test endpoint (M2.10, D-015).

**AI and agents**

- [Local inference](inference.md) — the `no_std` engine, the inference service, its model manifest, and its interface (M3.2; D-010, D-011).
- [Agents](agents.md) — the runtime, manifests, the agent lifecycle, durable tasks, and the emergency stop on the trusted console (M3.3, D-018).
- [Capabilities](capabilities.md) — agent permissions, revocation, approval on the trusted path, agent networking, and the audit service (M3.4, D-012).
- [Resources](resources.md) — CPU accounting, limits, budgets, and reservations (M3.5, D-022).
- [Tools](tools.md) — validated tool calls, granted files, and per-call confirmation (M3.6).
- [Coordination](coordination.md) — channels, groups, delegation, and verification (M3.7, D-024).
- [Knowledge](knowledge.md) — shared entries with provenance (M3.8).

**Evaluations**

- [Boot evaluation](boot-evaluation.md) — options and prototype evidence behind D-001 to D-003.

## When to write one

Write a design document before implementing a subsystem that:

- crosses a privilege or trust boundary (system calls, IPC, agent sandboxing);
- defines an interface other components depend on (boot information, memory map, capability format);
- is hard to change later (on-disk format, ABI).

## Naming and layout

One file per subsystem, named after it, for example:

```text
docs/architecture/
├── README.md          this guide
├── boot.md            boot flow and boot protocol usage
├── memory.md          physical/virtual memory management
├── interrupts.md      exceptions, interrupts, timers
├── scheduling.md      tasks, context switching, scheduler
├── syscalls-ipc.md    system-call interface and IPC
├── capabilities.md    capability model and agent permissions
└── inference.md       inference service and its isolation
```

These names are suggestions; create files only when there is content for them.

## Template

Each document should contain:

1. **Status** — draft, accepted, or superseded; and implementation status (implemented / planned).
2. **Context** — the problem and constraints; links to the roadmap milestone and decision records.
3. **Design** — components, data structures, interfaces, and invariants.
4. **Security** — trust boundaries, privileges required, how untrusted input is handled.
5. **Testing** — how the design is validated (unit, QEMU, manual).
6. **Alternatives** — options considered and why they were not chosen.
7. **Open questions.**

Keep documents in sync with the code: update them in the same change that alters the design, and update the diagrams in [overview.md](overview.md) when a change alters what they show. Draw diagrams in Mermaid, using the colour classes defined there, so they diff as text and render on GitHub.
