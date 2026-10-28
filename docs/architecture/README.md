# Architecture documents

This directory will hold detailed design documents for individual subsystems. The high-level overview stays in [docs/project/architecture.md](../project/architecture.md); decisions are recorded in [docs/project/decision-log.md](../project/decision-log.md).

Current documents:

- [Boot design](boot.md) — accepted boot flow, kernel entry contract, image layout, and build tool (implemented in M2.2 and M2.3).
- [Memory management](memory.md) — frame allocator, the kernel's own page tables, and the kernel address space (M2.5, D-005).
- [Exceptions and interrupts](interrupts.md) — IDT, exception handling, the double-fault stack, and the local APIC timer (M2.4, D-006).
- [Scheduling](scheduling.md) — kernel tasks, their stacks, the context switch, and locking rules (M2.6, D-013).
- [System calls and IPC](syscalls-ipc.md) — processes, the system-call interface, capabilities, and IPC (M2.7, D-004, D-012, D-014).
- [Storage and the filesystem](storage.md) — block devices, the read-only image format, its validation, and file capabilities (M2.8, D-007).
- [Drivers and device access](drivers.md) — Rust user programs and the ELF loader, PCI discovery, device interrupts, MMIO and DMA capabilities, and the virtio-blk driver (M2.9, D-008).
- [Processes and system services](services.md) — process creation from user space, badges, endpoint notifications, and the `init` service manager (M2.10, D-015).
- [Networking](networking.md) — the virtio-net driver, the minimal network stack, network capabilities, and the host test endpoint (M2.10, D-015).
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

Keep documents in sync with the code: update them in the same change that alters the design.
