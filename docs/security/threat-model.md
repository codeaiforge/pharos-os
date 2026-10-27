# Threat model

**Status:** updated at the M2.7 gate (2026-10-27). It covers what exists today, the host workspace and a kernel with isolated user processes, and the planned system. It must be updated at each phase gate (see the [roadmap](../project/implementation-roadmap.md)).

## Security principles

1. **Least privilege.** Every component and agent receives only the access it needs.
2. **Minimal trusted computing base.** Keep the kernel and other privileged code small; keep drivers, services, and AI out of it where practical.
3. **Explicit agent permissions.** Agents have no ambient authority. Access to files, processes, devices, networks, and tools requires granted, revocable, auditable capabilities.
4. **Isolation between inference and privileged code.** Inference runs as an unprivileged, resource-limited service.
5. **Untrusted model output.** Model output is data. It is validated and policy-checked before it can cause any action, and it is never executed directly.
6. **Controlled resource access.** Files, processes, devices, and network endpoints are reachable only through mediated interfaces.
7. **Safe Rust by default.** `unsafe` is minimal, justified, documented, and reviewed.

## Part 1 — Current scope (implemented)

### Assets

- Source code and its integrity.
- The developer's host machine and its data.
- Any credentials in the developer's environment (for example, Git hosting tokens).

### Trust boundaries

- Developer host ↔ the repository's code and scripts.
- Repository ↔ CI runners (if the repository is hosted).
- Workspace ↔ third-party crates (none today).

### Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| A dependency is malicious or compromised | No third-party dependencies; `Cargo.lock` committed; CI uses `--locked`; dependency policy in AGENTS.md. |
| CI workflow is abused to write to the repository or leak tokens | `permissions: contents: read`; `persist-credentials: false`; `actions/checkout` pinned to a verified commit SHA; no secrets used; no publish or deploy steps. The QEMU job installs Ubuntu packages on the disposable runner only. |
| Tooling damages the host | The CLI is read-only: no external commands, no privileges, no file writes. `xtask` runs build tools and QEMU without privileges and writes only under `target/`. Scripts policy forbids `sudo` and device writes. |
| Vulnerabilities disclosed publicly before a fix | GitHub private vulnerability reporting is enabled; [SECURITY.md](../../SECURITY.md) directs reporters to it. |
| A tampered Limine download ends up in boot images | `xtask` downloads a pinned release over HTTPS, checks a SHA-256 committed in the repository, and deletes any download that does not match; whoever updates the pin also verifies the maintainer's GPG signature ([boot.md](../architecture/boot.md#updating-the-limine-pin)). |
| The QEMU exit signal reaches real hardware | The kernel writes to the debug-exit port only when CPUID reports a hypervisor. AGENTS.md forbids real-hardware boots without authorization. |
| A kernel fault silently corrupts state or reboots the machine without a trace | Every CPU exception is reported over serial and halts the kernel (only breakpoints continue); the double fault runs on its own stack, and the kernel stack has an unmapped guard page, so a stack overflow is reported instead of overwriting memory or triple-faulting ([interrupts.md](../architecture/interrupts.md)). The kernel runs on its own page tables with write protection and no-execute: code is read-only, data and the direct map are not executable, and the kernel image has no writable alias ([memory.md](../architecture/memory.md)). Both kernel stacks have unmapped guard pages. Each path has a QEMU test. |
| An allocator bug corrupts kernel memory | Frame, heap, and range allocation logic is safe Rust, unit-tested on the host and stress-tested in QEMU; `unsafe` for raw memory is confined to `mm::raw` and `arch::x86_64::paging`. Double frees are detected (an error for frames, a panic for the heap), allocated heap memory holds no headers to overwrite, and out of memory is reported instead of being undefined behaviour ([memory.md](../architecture/memory.md)). |
| A kernel task starves the others, overflows its stack, or corrupts another task's state | A one-tick time slice preempts a task that never yields; a QEMU test runs a task that spins forever and checks that the others keep making progress. Each task has its own stack above an unmapped 16 KiB guard area, so an overflow is reported as a double fault instead of running into a neighbouring stack. The context switch saves every callee-saved register (tested), refuses to switch while an `IrqMutex` is held, and checks its preconditions before using raw stack pointers; scheduler logic is safe Rust ([scheduling.md](../architecture/scheduling.md)). Limits: all tasks are fully privileged kernel code, and a task that disables interrupts cannot be preempted. |
| Secrets committed by mistake | `.gitignore` covers `.env`, `*.pem`, `*.key`; AGENTS.md forbids secrets; PR template asks for confirmation. |
| An AI assistant performs unwanted Git or system changes | AGENTS.md forbids commits, pushes, history rewrites, and privileged commands without explicit authorization. |

### Kernel/user boundary (M2.7)

User processes run in ring 3 since M2.7. Design: [syscalls-ipc.md](../architecture/syscalls-ipc.md) and [D-014](../project/decision-log.md#d-014-ipc-model-and-system-call-mechanism). Review: [M2.7 security review](review-m2.7-kernel-user-boundary.md). Every mitigation below is implemented and covered by QEMU test kernels, except where marked as a limit.

| Threat | Mitigation |
| --- | --- |
| A process reads or writes kernel memory | Kernel pages never have the user bit; SMEP/SMAP are on where available. `user_mode` has processes read and write kernel data and jump into kernel code; each is killed with the expected page fault |
| A process reaches another process's memory | Separate user halves per process; the kernel decides all user mappings. A process reading a page only another process maps is killed |
| A malicious system-call argument corrupts the kernel | Every argument is checked, and the kernel never dereferences user addresses: it copies through the direct map after validating range, mapping, and access. `syscalls` passes bad buffers, numbers, and handles. `syscall::decode` is fuzzed on the host with 200,000 random calls |
| `sysret` to a non-canonical address faults in ring 0 (CVE-2012-0217) | The last user page is never mapped, and the return address is checked before `sysret`. Tested under TCG, and under KVM on an Intel CPU |
| A process uses an object it was not given | Capabilities only: per-process handle tables, and rights checked on every call. Delegation only with `GRANT`, narrowing rights; revocation through the derivation tree (`ipc`) |
| A process exhausts kernel memory | IPC uses one 256-byte message and one wait per thread; process creation is kernel-only; kernel logs keep their newest 64 entries (review F2, `hardening`). Limit: a server that never receives blocks its clients forever (no timeouts yet) |
| A process crashes the kernel with a fault or a privileged instruction | Exceptions from user mode kill only the process. `cli`, `hlt`, `mov cr3`, port I/O, and `int n` (all gates are DPL 0) are killed with general-protection faults (`user_mode`, `hardening`) |
| User flags leak into the kernel (DF, AC) | Interrupt entry clears DF and AC (review F1); `syscall` clears them through `SFMASK`. Debug builds assert both are clear in every dispatcher (`hardening`) |
| FPU state leaks between processes | `CR0.EM` makes x87/MMX instructions fault, and SSE/AVX are off, so no process can use registers the kernel does not save (review F3, `hardening`) |
| A stale TLB entry keeps a freed kernel page reachable | Kernel-space unmaps always flush, even while a process space is active (review F4, `address_spaces`) |
| Speculative execution leaks kernel memory (Meltdown class) | **Limit:** not mitigated (no KPTI); revisit before real-hardware use |
| Timing side channels | **Limit:** `rdtsc` is available in user mode |

### Storage images (M2.8, planned)

Design: [storage.md](../architecture/storage.md) and [D-007](../project/decision-log.md#d-007-filesystem-and-persistent-storage). The first two rows are **implemented** (#45–#48) and covered by host tests and the `fs` and `files` test kernels.

| Threat | Mitigation |
| --- | --- |
| A corrupt or hostile filesystem image crashes or corrupts the kernel | The image is untrusted input. One safe `no_std` parser (`unsafe` forbidden) checks every offset, size, path, and CRC-32 before use, with fixed limits; it is fuzzed on the host, and a QEMU test boots one corrupted image per check. A bad image fails to mount and the kernel keeps running |
| A process reads files it was not given | Files only through capabilities: a filesystem capability with `READ` opens files, file capabilities narrow rights, pass over IPC only with `GRANT`, and are revoked through the derivation tree |
| An image is replaced or tampered with | **Limit:** CRC-32 detects corruption only; images are not authenticated until secure boot |

### Drivers and devices (M2.9, planned)

Design: [drivers.md](../architecture/drivers.md) and [D-008](../project/decision-log.md#d-008-driver-strategy). The first row is **implemented** (#52), and so are the second and fourth (#55: device capabilities, MMIO limits, and stopping a device before its DMA buffers are freed, all tested in `device_caps`). The other rows are **planned** (#54, #56).

| Threat | Planned mitigation |
| --- | --- |
| A malformed program file corrupts the kernel | One safe `no_std` ELF parser checks every header and segment before anything is allocated, and is fuzzed on the host |
| A driver reaches memory or devices it was not given | Device capabilities only: MMIO mappings limited to its device's BARs, never RAM, other devices, or the MSI-X table; no configuration-space writes |
| A driver injects interrupts | The kernel programs MSI-X; the table's pages are never mapped to drivers; handlers do no driver work |
| A device DMAs into freed memory after its driver dies | Bus mastering is disabled and MSI-X masked when the device capability goes, before the driver's frames are freed |
| A driver programs DMA to arbitrary memory | **Limit:** no IOMMU in M2.9; a driver is trusted with all memory through its device. Only the kernel starts drivers; the IOMMU is evaluated before real hardware |
| A device returns bad values | The driver checks every ring index, descriptor ID, length, and status; the kernel bounds its capability-list walk |

### Known limitations

- No automated secret scanning or dependency auditing is configured yet (nothing to audit today).
- User processes are isolated from the kernel and from each other (see the kernel/user boundary above). Inside the kernel, the protections guard against kernel bugs: one stack frame larger than a guard page could skip it, and all kernel memory is reachable through the writable direct map.
- One CPU only: the kernel/user boundary's reasoning about system calls and TLB flushes assumes it.

## Part 2 — Planned system (Phases 2–5)

Everything below is **planned**; none of it is implemented.

### Assets

- Kernel integrity and confidentiality of kernel memory.
- User data on persistent storage.
- Capability grants and the policy that issues them.
- Audit logs.
- Model files (integrity and license compliance).
- Compute resources: CPU, memory, GPU/VRAM, storage, network bandwidth.

### Trust boundaries

```text
 untrusted            │ partially trusted          │ trusted (TCB)
──────────────────────┼────────────────────────────┼──────────────────
 agents               │ agent runtime & policy     │ kernel
 model output         │ system services            │ boot chain
 model files          │ inference service          │
 network peers        │ drivers (if user space)    │
 external input/files │                            │
```

### Threat actors

- **Malicious or manipulated agent** — for example, via prompt injection from a web page, file, or tool result.
- **Malicious model file** — crafted to exploit parser bugs in the inference runtime, or containing hidden behaviors.
- **Network attacker** — reaches exposed services or intercepts traffic.
- **Malicious local input** — crafted disk images, files, or devices.
- **Supply-chain attacker** — compromises a dependency, toolchain, or build artifact.
- **Physical attacker** — access to the machine (largely out of scope initially).

### Threats and planned mitigations

| Threat | Planned mitigation | Milestone |
| --- | --- | --- |
| Agent escalates privileges or escapes its sandbox | Kernel-enforced isolation; capability-only access; no ambient authority | M2.7, M3.4 |
| Prompt injection causes harmful tool use | Model output treated as untrusted; per-tool capabilities; user confirmation for sensitive actions; audit log | M3.4, M3.6 |
| Inference runtime exploit via model file | Runtime runs unprivileged and sandboxed; model integrity checks; memory limits | M3.2, M3.4 |
| Resource exhaustion by an agent | Per-agent CPU, memory, storage, and network quotas | M3.5 |
| Agent data exfiltration over network | Default-deny networking; per-destination grants; logging | M3.4 |
| Kernel memory-safety bug | Safe Rust by default; reviewed `unsafe`; fuzzing of syscall interfaces | M2.2 onward |
| Malicious DMA from devices | IOMMU use where available; limited device set | M2.9 |
| Tampered boot chain | Reproducible builds; Secure Boot evaluation | M4.3, M5.5 |
| Compromised dependency or artifact | Minimal dependencies; license and audit review; reproducible builds | ongoing, M5.5 |

### Known limitations of the plan

- Many mitigations depend on open decisions (D-004, D-008, D-012).
- Side channels (timing, cache) are not yet addressed.
- Physical attacks and firmware compromise are out of scope for now.
