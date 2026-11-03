# Threat model

**Status:** updated at the M2.10 gate, which closes Phase 2 (2026-10-29). It covers what exists today (the host workspace, and a kernel with isolated user processes, a read-only RAM-disk filesystem, user-space drivers, a service manager, and a user-space network service) and the planned system. It must be updated at each phase gate (see the [roadmap](../project/implementation-roadmap.md)).

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
- Workspace ↔ third-party crates: one, `libm` (user programs only, D-016).
- QEMU guest ↔ host network: slirp user-mode networking in tests only; the host side is the `cargo xtask` echo server on localhost.

### Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| A dependency is malicious or compromised | One third-party crate, `libm` 0.2.16 (MIT, no dependencies of its own, maintained by the Rust project), used only by user programs, never the kernel; reviewed under AGENTS.md section 6 (#74); `Cargo.lock` committed with its checksum; CI uses `--locked`; dependency policy in AGENTS.md. |
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
| A process exhausts kernel memory | IPC uses one 256-byte message and one wait per thread; processes start processes only within the limits in the processes and services section below; kernel logs keep their newest 64 entries (review F2, `hardening`). Limit: a server that never receives blocks its clients forever (no timeouts yet) |
| A process crashes the kernel with a fault or a privileged instruction | Exceptions from user mode kill only the process. `cli`, `hlt`, `mov cr3`, port I/O, and `int n` (all gates are DPL 0) are killed with general-protection faults (`user_mode`, `hardening`) |
| User flags leak into the kernel (DF, AC) | Interrupt entry clears DF and AC (review F1); `syscall` clears them through `SFMASK`. Debug builds assert both are clear in every dispatcher (`hardening`) |
| FPU state leaks between processes | Since M3.0 (D-016) processes use x87, SSE, and AVX, and every thread switch saves and restores them eagerly (`FXSAVE`, or `XSAVE` with AVX), with a clean state for new threads (`vector_state`, `vector_state_avx`). Until then `CR0.EM` made x87 fault (review F3) |
| A stale TLB entry keeps a freed kernel page reachable | Kernel-space unmaps always flush, even while a process space is active (review F4, `address_spaces`) |
| Speculative execution leaks kernel memory (Meltdown class) | **Limit:** not mitigated (no KPTI); revisit before real-hardware use |
| Timing side channels | **Limit:** `rdtsc` is available in user mode |

### Storage images (M2.8)

Design: [storage.md](../architecture/storage.md) and [D-007](../project/decision-log.md#d-007-filesystem-and-persistent-storage). The first two rows are **implemented** (#45–#48) and covered by host tests and the `fs` and `files` test kernels. Since M2.9 the virtio-blk driver runs the same parser in user space on the disk's image (`virtio_blk`).

| Threat | Mitigation |
| --- | --- |
| A corrupt or hostile filesystem image crashes or corrupts the kernel | The image is untrusted input. One safe `no_std` parser (`unsafe` forbidden) checks every offset, size, path, and CRC-32 before use, with fixed limits; it is fuzzed on the host, and a QEMU test boots one corrupted image per check. A bad image fails to mount and the kernel keeps running |
| A process reads files it was not given | Files only through capabilities: a filesystem capability with `READ` opens files, file capabilities narrow rights, pass over IPC only with `GRANT`, and are revoked through the derivation tree |
| An image is replaced or tampered with | **Limit:** CRC-32 detects corruption only; images are not authenticated until secure boot |

### Drivers and devices (M2.9)

Design: [drivers.md](../architecture/drivers.md) and [D-008](../project/decision-log.md#d-008-driver-strategy). Every mitigation below is **implemented** (#52–#56) and was reviewed at the M2.9 gate: [review-m2.9-drivers.md](review-m2.9-drivers.md) (findings F1–F4 fixed). Tests: host tests, and the `user_elf`, `pci`, `device_caps`, `device_irq`, and `virtio_blk` test kernels.

| Threat | Mitigation |
| --- | --- |
| A malformed program file corrupts the kernel | One safe `no_std` ELF parser checks every header and segment before anything is allocated, and is fuzzed on the host |
| A driver reaches memory or devices it was not given | Device capabilities only: MMIO mappings limited to its device's memory BARs, never the MSI-X table; no configuration-space writes. BARs that overlap the memory map are ignored, so a hostile device cannot expose RAM (F1). A device is granted to one driver at a time, and stays with it while any of its pages are mapped (F2) |
| A driver injects interrupts | The kernel programs MSI-X; the table's pages are never mapped to drivers; handlers do no driver work |
| A device DMAs into freed memory after its driver dies | Bus mastering is disabled and MSI-X masked when the device's last reference goes (handles and pins), before its DMA frames are freed; checked after exit and after a kill |
| A driver exhausts kernel resources | At most 64 DMA pages per device, 256 register pages per process (F4), 4 interrupt vectors per device (F3), 16 in all |
| A driver programs DMA to arbitrary memory | **Limit:** no IOMMU in M2.9; a driver is trusted with all memory through its device. Only the kernel starts drivers; the IOMMU is evaluated before real hardware |
| A revoked driver keeps device access | **Limit:** revocation stops new calls, but existing mappings stay until the process ends; ending the process is the full revocation |
| A device returns bad values | The driver checks every ring index, descriptor ID, length, and status (host-tested); the kernel bounds its capability-list walk and checks BARs |

### Processes and services (M2.10)

Design: [services.md](../architecture/services.md) and [D-015](../project/decision-log.md#d-015-network-stack-and-service-model). Every mitigation below is **implemented** (#60, #61, #63) and was reviewed at the M2.10 gate: [review-m2.10-services-networking.md](review-m2.10-services-networking.md) (finding F1 fixed). Rows marked **Limit** are accepted. Tests: `spawn` and `services`.

| Threat | Mitigation |
| --- | --- |
| A process starts programs or passes capabilities it should not | `spawn` takes the program as a file capability (`READ`) and passes only listed capabilities, each derived from one the caller holds with `GRANT`, rights only narrowed; revocation reaches children |
| A client forges its identity | Badges are set once by the capability's grantor and delivered by the kernel; holders cannot change them |
| A process exhausts kernel memory by spawning or signalling | 32 live processes, 8 capabilities per spawn, notifications are a fixed word per endpoint; limits checked before allocation |
| A server keeps a reply capability and answers a later call meant for another server | Replies are one-shot: the kernel revokes the server's reply capability when the call returns, and `call` refuses a reply endpoint with a queued message (review F1, `spawn`) |
| `init` misuses its authority | `init` holds every boot capability; it is small, its service table is reviewed code, and it passes each service only what the table lists |
| A stuck service hangs the boot | **Limit:** no timeouts; the kernel's 30 s wait turns a stuck `init` into a boot failure instead of a pass |
| One process takes every process slot | **Limit:** no per-process quotas; the 32-process limit is global (M3.5) |

### Networking (M2.10)

Design: [networking.md](../architecture/networking.md). The first four rows are **implemented** (#62–#64: the parser is fuzzed on the host; `network` checks badges, the refused unbadged client, the counters, and a round trip to the host echo server) and were reviewed at the M2.10 gate; the fifth is **implemented** (#109); the rest are accepted limits.

| Threat | Mitigation |
| --- | --- |
| A malformed or hostile packet crashes or corrupts the network service | Every layer is parsed by safe, allocation-free code with checked lengths and checksums, fuzzed on the host; bad frames are dropped and counted |
| A process uses the network without permission | Network access only through a badged `SEND` capability on the service's endpoint; a badge that is no port is refused; badge 0 is `init`'s, which may only list destinations (`ALLOW`); revocable |
| A client impersonates another client or spoofs addresses | Identity is the kernel-delivered badge (one UDP port per client); the service builds every header itself |
| A client blocks or floods the service | Replies are non-blocking sends; per-client queues and outstanding requests are bounded; drops are counted |
| A client reaches arbitrary hosts | Each client sends only to the destinations `init`'s table lists for it, and pings only their addresses; a client with no list sends nowhere; only `init` can set a list (**implemented, #109**: the `network` kernel checks an unlisted destination, an unlisted ping address, and a client's own `ALLOW` are refused; mutation-checked). Before #109: any destination |
| A virtio-net device DMAs anywhere | **Limit:** no IOMMU (D-008) |
| A forged ARP message redirects traffic | **Limit:** ARP is believed, as in any ARP; on slirp the only other host is the gateway |
| A guest program reaches beyond the host in tests | **Limit:** slirp's NAT is not restricted (`restrict=on` would also block the echo server); nothing in the guest sends anywhere but `10.0.2.2` |

### User environment and storage (M3.0)

Design: [user-environment.md](../architecture/user-environment.md) and [storage.md part 8](../architecture/storage.md#8-the-writable-store-m30), from D-016 and D-017. Rows are marked implemented as their issues land (#74–#78, #80); all are reviewed at the M3.0 gate.

| Threat | Planned mitigation |
| --- | --- |
| A process reads another's floating-point or vector registers | **Implemented (#74):** eager save and restore on every switch, a clean image for new threads, no lazy switching (LazyFP); `vector_state` and `vector_state_avx` check values survive preemption, a new process switched in from one holding a marker never sees it, and `MXCSR` is clean; mutation-checked |
| A malformed save area crashes the kernel (`XRSTOR` fault) | Only the kernel writes save areas; user code cannot reach them |
| A process exhausts memory | **Implemented (#75):** a page limit per process, set at `spawn` and at most the creator's (`TOO_LARGE`), checked before any frame is allocated; at most 1,024 mappings; no demand paging; unmap and exit free every frame (`user_memory`, mutation-checked). **Limit:** limits are not carved from the creator's until M3.5, and a large `mem_map` holds the CPU with interrupts off while it zeroes its pages |
| Shared memory widens access | **Implemented (#80):** rights only narrow; a writable mapping needs `WRITE`; read-only mappings have no write bit (a write kills the process); mappings are never executable; only whole `mem_map` mappings the process made itself can be shared, so a receiver cannot mint a capability its sharer's `revoke` misses (M3.0 review, F1); frames live until the last mapping and capability, and are never freed twice (`shared_memory`, both end orders; mutation-checked). Revocation turns existing mappings into zeroed private pages (#104). **Limit:** a shared object's frame list costs 8 bytes of kernel heap per page |
| A timeout loses or misdirects a message | **Implemented (#76):** expiry with interrupts off; a message delivered before the waiter runs again is returned, and a waiter leaves the queue only if still in it; an untaken `call` request is withdrawn; a late reply meets a revoked one-shot reply capability (`timeouts` race test: every reply the server delivered reached the client; mutation-checked) |
| A corrupted or edited disk crashes or misleads the storage service | **Implemented (#77):** every superblock, index, extent, and record checked (CRC-32) before use; shared parser fuzzed; crash consistency tested by cutting every write sequence on the host (with lost and reordered unflushed writes) and by killing QEMU 20 times while it writes; mutation-checked |
| Audit records are altered on disk | SHA-256 chain over stream records. **Limit:** the chain head is not anchored until M3.4, so someone holding the disk can rewrite the whole chain |
| A client reads or writes another's files | **Implemented (#77):** namespaces from badges, read-only bit, paths joined to the prefix and checked against escape; file data only in the client's own attached buffer (`store` test: read-only, foreign, unbadged, and unknown clients; mutation-checked) |
| A client exhausts the storage service | **Implemented (M3.0 review, F2):** attached buffers are capped at 32 MiB, at most 16 clients hold one, within the service's 1 GiB limit (`store` test, mutation-checked). A client's buffer is freed when it ends: `init` sends the service `RELEASE` for the badge it gave it, accepted only without a badge (**implemented, #100**: the `supervision` test kernel checks a 4 MiB buffer is freed and a client's `RELEASE` refused; mutation-checked). **Limit:** a client that `init` did not start (a test kernel's) keeps its slot until its badge attaches another |

### Local inference (M3.2)

Design: [inference.md](../architecture/inference.md), from D-010, D-011, and D-019. Every row is **implemented** (#84–#92) and was reviewed at the M3.2 gate: [review-m3.2-inference.md](review-m3.2-inference.md) (finding F1 fixed). Rows marked **Limit** are accepted.

| Threat | Planned mitigation |
| --- | --- |
| A malformed or substituted model file exploits the parser or changes the model's behaviour | Only models in the compiled-in manifest load; size and SHA-256 checked before parsing; configuration checked against the manifest; the GGUF and tokenizer parsers are checked and fuzzed. **Implemented and tested (#88, #89):** a changed and a truncated file in QEMU; malformed files and a wrong configuration on the host |
| A client exhausts the service's memory or holds it forever | Prompt, token, and context limits checked before anything is allocated; one session at a time; idle sessions dropped after 10 s. **Implemented and tested (#89):** `CONTEXT`, `BUSY`, and the idle drop in QEMU. **Limit:** per-agent token and time budgets are M3.5; a prompt near the context limit holds the service for about a minute, and other callers time out meanwhile; at most 8 clients hold a buffer slot, freed by `init`'s `RELEASE` when the client ends (#100) |
| A client changes its prompt while it is being processed | The prompt is copied out of the shared buffer before tokenizing |
| A client hides another's inference from the audit record | **Implemented (M3.2 review, F1):** each client's `RESULT` record is kept with its own slot until its next session ends, so another client's session cannot replace it (`inference` test, mutation-checked). **Limit:** the record is stored by the audit trail only from M3.4 |
| A hung or crashed service hangs its callers | Every operation has a documented timeout and clients always use `call` with it (#76); the service replies with non-blocking sends. **Tested (#89):** a client calling a service that never receives gets `TIMED_OUT`. **Limit:** restarting the service is M3.3 |
| A compromised inference service reaches further | It holds only read-only access to the `models` namespace and its own endpoints: no devices, network, or other storage. **Tested (#89):** the `inference` kernel checks every handle the service holds after its clients ran |
| Model output is acted on | Output is returned as text to the caller only; nothing in the service executes it or passes it to a privileged interface (AGENTS.md section 7) |

### Known limitations

- No automated secret scanning or dependency auditing is configured yet (nothing to audit today).
- User processes are isolated from the kernel and from each other (see the kernel/user boundary above). Inside the kernel, the protections guard against kernel bugs: one stack frame larger than a guard page could skip it, and all kernel memory is reachable through the writable direct map.
- One CPU only: the kernel/user boundary's reasoning about system calls and TLB flushes assumes it.

### Open limits carried out of Phase 2

Phase 2, M3.0 ([review](review-m3.0-platform.md)), M3.2 ([review](review-m3.2-inference.md)), and M3.3 ([review](review-m3.3-agents.md)) close with these limits accepted. Each is carried to the milestone that addresses it; none blocks Phase 3, which runs only in QEMU.

| Limit | Since | Carried to |
| --- | --- | --- |
| No IOMMU: a driver is trusted with all memory through its device's DMA | M2.9 (D-008) | M4.4 (device management); required before real-hardware use (M5.2) |
| No KPTI: the kernel half is mapped in every address space (Meltdown class) | M2.7 | M4.2 (security model); required before real-hardware use (M5.2) |
| One CPU: locking, TLB flushes, and MSI-X routing assume it | from the start | Phase 4; SMP needs a decision record and a re-review of those paths |
| Revocation does not unmap device registers or DMA buffers; ending the process is the full revocation. **Resolved (#104):** revoking a device capability stops the device and turns the driver's register and DMA mappings into zeroed private pages | M2.9 | M3.4 (revocable agent permissions) |
| No timeouts on pings or service start (`receive`, `call`, `irq_wait`, and `sleep` have them since #76). **Resolved (#100):** `init` stops a daemon that sends no `ready` within 10 s, restarts a crashed daemon at most 3 times, and never restarts a stopped one | M2.7 | M3.3 (supervision) |
| No per-process quotas on processes, handles, or network use | M2.10 | M3.5 (resource accounting and limits) |
| No network destination policy. **Resolved (#109):** per-client destination lists from `init`, checked by the network service | M2.10 | M3.4 (D-012) |
| `rdtsc` in user mode (timing side channels) | M2.7 | M4.2 |
| Shared-memory bookkeeping (8 bytes per page) on the fixed 4 MiB kernel heap, which panics when full: up to 1/512 of a process's page limit | M3.0 | M3.5 (resource accounting) |
| Page limits not carved from the creator's; a large `mem_map` zeroes pages with interrupts disabled | M3.0 | M3.5 |
| Revocation does not unmap shared memory already mapped. **Resolved (#104):** revoked mappings become zeroed private pages with the same access, in every process, before `revoke` returns | M3.0 | M3.4 |
| Audit chains not anchored | M3.0 | M3.4 |
| The agent runtime serves one request at a time: a dead storage service holds it 10 s per call, so agents can be counted hung and use up attempts; no rate limit on agent requests | M3.3 | M3.5 (budgets) |
| Control clients can read, cancel, and forget every task; only `init` grants the badge, and only test tables do | M3.3 | M3.6 (who submits tasks) |
| The inference service: a long prompt holds it (callers time out). **Resolved (#100):** a failed model read is not kept (the next `GENERATE` tries again with a new window), and client slots are freed when `init` reports the client ended | M3.2 | M3.5 (budgets) |

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
| Agent escalates privileges or escapes its sandbox | Kernel-enforced isolation; capability-only access; no ambient authority; nothing beyond the policy table without the user's approval on the trusted path, for one task (**planned, decided in D-012**: #105, #106); revocation at once, memory unmapped by the kernel (#104); adversarial tests (#110) | M2.7, M3.4 |
| Prompt injection causes harmful tool use | Model output treated as untrusted; per-tool capabilities; user confirmation for sensitive actions; audit log | M3.4, M3.6 |
| Inference runtime exploit via model file | Runtime runs unprivileged and sandboxed; model integrity checks; memory limits (M3.0). Chosen in M3.1 (D-010): our own engine in safe Rust with no dependencies, whose GGUF parser checks every count, length, offset, and tensor shape before use and is fuzzed (20,000 files, host); models pinned by SHA-256 and repository revision; tokenizer strings and model output treated as untrusted data | M3.2, M3.4 |
| A runaway, hung, or compromised agent (or agent runtime) cannot be stopped | A trusted path (D-018): a virtio-console device owned only by a small trusted service, which no agent or the runtime can reach (**implemented, #96**: `trust`; the `trust` test kernel stops two agents registered under one name and then a spinning stand-in runtime from typed commands, and checks an impostor registration is dropped; mutation-checked; `stop <agent>` stopping only the first of several was F1 of the [M3.3 review](review-m3.3-agents.md), fixed); a kernel `STOP` right that also stops the processes a process spawned (**implemented, #95**: `process_stop`, children stopped whenever their parent ends; `process_stop` test kernel, mutation-checked); the trusted service holds it on the agent runtime and on each agent before the agent is granted anything (**implemented, #98**: `init` sends the runtime's right after starting it, the runtime each agent's before serving it; the `agents` test kernel checks `trust` holds them) | M3.3 |
| An agent manifest asks for more than the agent should get, or exploits its parser | Manifests are untrusted input and only ask (agents.md): the parser refuses unknown, repeated, and missing keys, bytes other than printable ASCII, and values out of range, and never panics (**implemented, #97**: `pharos_proto::manifest`, host-tested, 200,000 fuzzed inputs, mutation-checked); a manifest that names another program or asks for more than its entry in the runtime's reviewed policy table is refused, never narrowed (the check is implemented in #97; the table and its use in #98: the `agents` test kernel checks a manifest over its entry, a missing one, and one with no entry are not runnable); an agent with no entry does not start | M3.3 |
| A compromised agent reaches another agent's task, the store, the inference service, or a device | An agent holds one capability, `SEND` on the agent runtime badged with its slot; every service goes through the runtime, which checks each request against the agent's own task and its manifest's models and copies data out of the agent's buffer before use; control requests from an agent are refused (**implemented, #98**: `bin/agents`; the `agents` test kernel checks what each running agent holds, a model outside the manifest refused, and an agent's control requests refused; mutation-checked). Limit: the runtime is trusted for this, not for the stop | M3.3 |
| A crash of an agent, the runtime, or the machine repeats a consequential operation or loses task state | Tasks are one store file each, rewritten whole in one crash-consistent commit, and every change is stored before it is answered; idempotency keys: `BEGIN` stores the key before it answers `GO`, and after a restart answers `DONE` with the recorded result or `UNKNOWN`, never `GO` again; attempts are counted before an agent starts, so restarts stay bounded; IDs are never reused (**implemented, #99**: `pharos_programs::tasks`, its store writes cut at every point on the host; the `agents` kernel replaces the runtime mid-task and the `agents_crash` kernel is killed 6 times mid-task; the `agents_store` kernel kills the storage service with the agent, and the task restarts only once the store records it; mutation-checked). No exactly-once promise: an operation begun but not ended answers `UNKNOWN`, and the agent must check or give up. The task store is held only by the runtime, which is trusted for it | M3.3 |
| An agent's request is approved because the user was misled by the prompt, or approves without reading | Only permissions listed as askable in the policy entry are asked for; `trust` writes the prompt from structured fields, never agent text; at most 4 wait, each refused after 60 s; approvals hold for one task (**implemented, #106**: the `permissions` kernel answers yes, no, and nothing on the trusted console; mutation-checked), and each approval is given only once recorded (**implemented, #108**) | M3.4 |
| The untrusted side of a shared buffer revokes it to crash the trusted side | A revoked mapping becomes private zeroed pages, not a hole, so the mapper reads zeros instead of faulting (**implemented, #104**: `shared_memory` and `device_caps`, a driver reading zeros from revoked registers and DMA without being killed; mutation-checked) | M3.4 |
| Audit records are changed, removed, or rewritten on the disk | One writer (`audit`) stamping each record with the sending service's badge; the store's SHA-256 chain, checked on mount and by `cargo xtask store audit`; the head and count shown on the trusted console at start and on `audit` for the user to compare (**implemented, #107**: the `audit` kernel checks the stamped badges, the chains, and that the head shown is the image's; host tests detect a changed record, a gap in sequence numbers, and a missing boot record; mutation-checked); consequential actions refused while the trail cannot be written, and every grant, revocation, approval, and start recorded (**implemented, #108**: the `permissions` kernel kills the audit service and its agent gets `NO_AUDIT`, the runner reconstructs a task from the trail, and the boot check finds a start record for every service; mutation-checked). No secret-keyed anchor before M4.3 | M3.4 |
| Resource exhaustion by an agent | Per-agent CPU, memory, storage, and network quotas | M3.5 |
| Agent data exfiltration over network | Default-deny networking; per-destination grants (one IPv4 address and UDP port each, from the manifest within its policy entry or by approval), checked by the agent runtime on every send and again by the network service, which lets the runtime's port reach only the union of the policy table's destinations; every send recorded before it goes out (else `NO_AUDIT`); replies kept only for the agents that sent to that destination and delivered only while the grant holds (**implemented, #109**: the `agents_net` kernel exchanges a datagram with the host echo server, is refused other destinations and one not askable, gets one by the user's `yes`, loses one by `revoke` with its late reply dropped, and checks an agent holding the same grant that sent nothing receives nothing; the runner checks every send's intent and outcome in the trail; mutation-checked). Limit: agents granted the same destination and that both sent to it both get its replies (they share the runtime's port) | M3.4 |
| Kernel memory-safety bug | Safe Rust by default; reviewed `unsafe`; fuzzing of syscall interfaces | M2.2 onward |
| Malicious DMA from devices | IOMMU use where available; limited device set (M2.9 limits the device set; the IOMMU is still open) | M4.4, M5.2 |
| Tampered boot chain | Reproducible builds; Secure Boot evaluation | M4.3, M5.5 |
| Compromised dependency or artifact | Minimal dependencies; license and audit review; reproducible builds | ongoing, M5.5 |

### Known limitations of the plan

- Many mitigations depend on open decisions (D-004, D-008, D-012).
- Side channels (timing, cache) are not yet addressed.
- Physical attacks and firmware compromise are out of scope for now.
