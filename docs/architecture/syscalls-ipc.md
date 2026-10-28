# System calls and IPC

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-27 (M2.7, #37). It follows [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries) (capability-based microkernel), the [D-012 direction](../project/decision-log.md#d-012-agent-sandboxing-tool-permissions-and-network-isolation) (kernel-enforced capabilities), and [D-014](../project/decision-log.md#d-014-ipc-model-and-system-call-mechanism) (IPC model and system-call mechanism).
- **Implementation:** per-process address spaces (#38) and ring 3 execution with user faults killing the process (#39) are **implemented** (`process::load`, `process::start`, `process::spawn`). So are the system-call entry and the calls `exit`, `yield`, `debug_write`, and `delete`, with capability tables (#40). So are IPC endpoints with `send` and `receive`, capability passing, and `revoke` (#41). Every M2.7 interface in this document is now implemented. M2.8 added file capabilities and the calls `open` and `read` (#48; design in [storage.md](storage.md#user-interface-capabilities-and-system-calls)).

## 2. Context

M2.7 must:
- run user processes in their own address spaces;
- give them a minimal system-call interface and IPC;
- prove that a process cannot reach kernel memory or another process's memory;
- reject invalid system-call arguments safely.

D-004 makes IPC and capabilities the kernel's main interface, with an IPC round trip of at most 2 µs under KVM. D-012 asks for no ambient authority: every access goes through a capability.

The kernel today:
- runs on one CPU, in ring 0 only;
- has its own page tables (D-005) and a preemptive scheduler for kernel tasks (D-013);
- has a calibrated 100 Hz tick (D-006).

The prototype for D-004 showed that QEMU's default CPU under TCG, which CI uses, has no SMEP or SMAP.

## 3. Design

### Processes and threads

- A **process** owns:
  - an address space (user half private, kernel half shared);
  - a capability table;
  - in M2.7, exactly **one thread**.
- The thread is a scheduler task (D-013) with a user context.
  - It has its own 16 KiB kernel stack (task stack window, guard area below), used for system calls and for interrupts and exceptions taken in user mode.
  - The scheduler loads that stack into the TSS (`rsp0`) and switches CR3 when it switches to a thread of another process. Kernel tasks run on the kernel root.
- **Creation:** only the kernel creates processes in M2.7. `process::spawn` takes an image (see "Programs"), creates the address space, copies the image, maps a user stack, gives the process its initial capabilities, and queues the thread. There is no spawn system call yet.
- **End:**
  - A process ends when its thread calls `exit` or causes a CPU exception.
  - An exception from user mode (CS bits 0–1 = 3) prints `PHAROS: process <id> killed: <exception report>`; the kernel and other tasks continue. Exceptions in ring 0 stay fatal (D-006).
  - The thread is reaped like an exited kernel task. The process's user pages, page tables, and capability table are freed when the last reference goes.

### Address space layout (per process)

| Range | Contents | Access |
| --- | --- | --- |
| `0x0` – `0x3fffff` | Unmapped (null-pointer guard) | — |
| `0x400000` … | Program image | User, read + execute |
| `0x7fffff000000` – `0x7fffff7fffff` | User stack (64 KiB, mapped at the top of this range; the rest stays unmapped as a guard) | User, read + write, no-execute |
| `0x7ffffffff000` | Never mapped (see "SYSRET hazard") | — |
| PML4 entries 256–511 | Kernel half, shared with the kernel address space | Kernel only |

- User mappings carry the user bit; kernel mappings never do.
- **W^X:** no user page is both writable and executable.
- New user pages are zeroed.

### System-call mechanism (D-014)

- **Instruction:** `syscall`/`sysret`. Setup:
  - `EFER.SCE` on;
  - `STAR`: kernel CS `0x08` / SS `0x10`, user base `0x20`, so `sysret` loads CS `0x33` and SS `0x2b`;
  - `LSTAR` → the entry stub;
  - `SFMASK` clears IF, TF, DF, AC, and NT.
- **New GDT entries:** user data `0x28` (DPL 3) and user code `0x30` (DPL 3), after the TSS.
- **Registers:**
  - Number in `rax`; arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.
  - Results: `rax` = status (0 = success, otherwise an error code below), `rdx` = value.
  - `rcx` and `r11` are destroyed (the CPU uses them); everything else is preserved.
- **Entry stub** (`global_asm!` in `arch::x86_64`), with interrupts disabled:
  1. saves the user RSP in a per-CPU scratch slot (a static, one CPU; SMP will need `swapgs` and per-CPU data);
  2. loads the thread's kernel stack top;
  3. pushes the user registers;
  4. calls one Rust dispatcher with them.
- **Return:**
  - `sysret`, after checking that the saved user RIP is canonical (`iretq` otherwise).
  - Threads that entered through an interrupt or exception always return through `iretq`.
- **Interrupts:** system calls run with interrupts disabled. They are short (a message is at most 256 bytes); a thread that blocks switches through the scheduler, and a pending tick is taken on the way back to user mode. Revisit when a system call can take long.

### User memory access

- The kernel **never dereferences a user virtual address**. A user buffer is validated and then copied through the direct map:
  1. Check `addr + len` without overflow, inside `[0x1000, 0x7ffffffff000)`, and `len` within the call's limit.
  2. Translate each page in the process's address space; the page must be present and user-accessible (and writable for writes into it).
  3. Copy page by page between the frame's direct-map address and a kernel buffer.
- **Implementation:** `AddressSpace::read_user` and `write_user` in the hardware layer. They check the range (`user_range_ok`), then every page (present, user, and writable for writes), before copying anything through the direct map. Host tests cover the range checks, including a randomized test. Stateless argument checks are in `syscall::decode`, fuzzed on the host with 200,000 random calls.
- **Check order:** call number, length, address range (`decode`); then handle and rights (the capability table); then the pages (`read_user`).
- With one CPU and interrupts disabled during system calls, no other thread can change the mappings between the check and the copy. SMP must revisit this.
- **SMEP and SMAP** are enabled at boot when CPUID reports them, as defence in depth: the kernel then cannot execute or touch user pages by accident. The design does not rely on them, because CI's default QEMU CPU lacks them. A local check runs the test kernels with `-cpu max`.

### Capabilities (D-012 direction)

- **Capability:** a reference to a kernel object plus rights. Objects in M2.7:
  - **IPC endpoint**, with rights `SEND`, `RECEIVE`, and `GRANT`;
  - **debug console**, with right `WRITE`;
  - since M2.8, **filesystem** (`READ` opens files) and **file** (`READ` reads it), both also with `GRANT` ([storage.md](storage.md)). `open` derives the file capability from the filesystem capability, so revoking reaches files opened through it.
- **Capability table:** per process; handles are small integers indexing it. Handle 0 is never valid, and handles are meaningless in another process.
- **Delegation:** a message may carry one capability, if the sender holds `GRANT` on it. The receiver gets a new handle with the same or fewer rights (the sender chooses).
- **Revocation: derivation tree with lazy invalidation.**
  - Each capability is a node that records the capabilities derived from it (by granting).
  - `revoke(handle)` marks every descendant revoked; the caller keeps its own capability.
  - Every use checks the mark. A revoked handle returns `REVOKED` and can only be deleted.
  - Revocation needs no cooperation from the holders and costs time proportional to the subtree.
- `delete(handle)` removes a handle from the caller's table. It does not affect derived capabilities; use `revoke` for that.

### IPC (D-014): synchronous endpoints

Implemented in `ipc` (endpoint queues, host-tested) and `syscall` (#41). A blocked thread leaves the ready queue through `sched::block_current` and returns through `sched::wake`. A message handed to a waiting receiver goes into that process's inbox (`process::Process::inbox`). `receive` checks the buffer (writable user pages) and a free handle before it takes a message, so none is lost to a bad buffer.

- **Messages:** at most **256 bytes** of data plus at most one capability. Large data will use shared-memory capabilities (a later memory object), not messages.
- **`send(endpoint, buffer, len, cap, rights)`:**
  - copies the message into a kernel buffer owned by the sending thread;
  - blocks until a receiver takes it, or hands it over at once if a receiver is waiting.
- **`receive(endpoint, buffer, max_len)`:**
  - blocks until a message arrives, then copies it out;
  - returns its length and, if a capability came with it, its new handle (in `rdx` as `len | handle << 32`).
- **Fairness:** senders and receivers queue first in first out per endpoint. Blocking goes through the scheduler (the thread leaves the ready queue until the rendezvous).
- **Memory is bounded:** each thread can wait on one endpoint at a time and has one 256-byte buffer. No queue grows with untrusted input.
- **Not in M2.7:** a combined `call` (send and wait for a reply) and one-shot reply capabilities. They can be added later to save system calls on the round trip if the D-004 budget needs it.

### System calls in M2.7

The entry stub is `arch::x86_64::syscall`; the handler is `syscall::handle`; per-process state (the capability table) is `process::Process`. Process address spaces refuse to map the last user page (`paging::LAST_USER_PAGE`).

| No. | Call | Arguments | Result (`rdx`) | Capability needed |
| --- | --- | --- | --- | --- |
| 0 | `exit` | code | does not return | none |
| 1 | `yield` | — | 0 | none |
| 2 | `debug_write` | handle, buffer, len (≤ 256) | bytes written | debug console, `WRITE` |
| 3 | `send` | handle, buffer, len (≤ 256), cap handle (0 = none), rights mask | 0 | endpoint, `SEND`; passed capability, `GRANT` |
| 4 | `receive` | handle, buffer, max len | `len \| new_handle << 32` | endpoint, `RECEIVE` |
| 5 | `delete` | handle | 0 | none (own handle) |
| 6 | `revoke` | handle | revoked count | none (own handle) |
| 7 | `open` (M2.8) | filesystem handle, path buffer, path len (≤ 104) | new file handle | filesystem, `READ` |
| 8 | `read` (M2.8) | file handle, buffer, len (≤ 4096), file offset | bytes read (0 at end of file) | file, `READ` |
| 9 | `config_read` (M2.9) | device, offset (< 256, aligned), width (1, 2, 4) | the value | device, `CONFIG` |
| 10 | `mmio_map` (M2.9) | device, BAR, offset, length, user address (pages) | 0 | device, `MAP` |
| 11 | `dma_alloc` (M2.9) | device, pages (1–16), user address | physical address | device, `MAP` |
| 12 | `irq_create` (M2.9) | device, MSI-X entry (< table size) | new interrupt handle | device, `IRQ` |
| 13 | `irq_wait` (M2.9) | interrupt handle | interrupts since the last wait (≥ 1) | interrupt, `WAIT` |

Error codes (`rax`):

| Code | Name | Meaning |
| --- | --- | --- |
| 1 | `UNKNOWN_CALL` | No such system call |
| 2 | `INVALID_HANDLE` | Handle not in the caller's table |
| 3 | `REVOKED` | The capability was revoked |
| 4 | `MISSING_RIGHT` | The capability lacks a needed right |
| 5 | `BAD_ADDRESS` | A buffer is outside user space, unmapped, or lacks access |
| 6 | `TOO_LARGE` | A length exceeds the call's limit |
| 7 | `NO_MEMORY` | The kernel could not allocate |
| 8 | `NOT_FOUND` | No file with this path (M2.8), no such BAR, or no such MSI-X entry (M2.9) |
| 9 | `IN_USE` | The user address is already mapped, the MSI-X entry already has an interrupt, or another thread is waiting on it (M2.9) |

### Programs for tests

- M2.7 test programs are small flat binaries written with `global_asm!`: position-independent code with an entry offset, copied to `0x400000`. They need no new build steps, and every instruction is visible in review.
- They live in the hardware layer (`arch::x86_64::user_programs`), not in test kernels: the kernel lints treat `global_asm!` and `unsafe extern` blocks as `unsafe` code, which AGENTS.md allows only there. Test kernels load them as data (`TestProgram::bytes`).
- **Not in M2.7:** a Rust user crate with an ELF loader. It arrived in M2.9 (#52, [drivers.md](drivers.md#user-programs)): `user/pharos-user` wraps every call, and `process::spawn_elf` loads programs from the filesystem.

### Interrupts from user mode

- The timer preempts user threads like kernel threads: the interrupt arrives on the thread's kernel stack (TSS `rsp0`), and the tick may switch tasks.
- The CPU restores the user state with `iretq` when the thread runs again.

## 4. Security

- **Trust boundary:** everything a process passes in is untrusted:
  - registers;
  - buffer contents;
  - its own page tables' effect on validation, since the kernel decides those mappings.

  Every argument is checked before use; unknown numbers and malformed calls return errors and never panic.
- **SYSRET hazard:** on Intel CPUs, `sysret` to a non-canonical RIP faults in ring 0 with the user's stack pointer (CVE-2012-0217).
  - Two defences: the last user page (`0x7ffffffff000`) is never mapped, so no `syscall` instruction can sit where the return address would be non-canonical; and the stub checks RIP before `sysret` (falling back to `iretq`).
- **Kernel memory:**
  - user pages have the user bit and kernel pages never do;
  - the kernel never touches user virtual addresses, and copies through the direct map after validation;
  - SMEP and SMAP are on where the CPU has them.
- **Isolation between processes:** separate user halves. A process names objects only through its own capability table, and capabilities move only with `GRANT`. Revocation can cut off everything derived from a capability.
- **Resource limits:** bounded per-thread IPC memory. Process creation is kernel-only, so a process cannot multiply itself; quotas are M3.5.
- **Limits:**
  - **Meltdown-class leaks:** the kernel half is mapped (supervisor-only) in every address space, so speculative-execution attacks on affected CPUs could read it. KPTI is out of scope for M2.7 (not relevant under TCG; revisit for real hardware).
  - **`rdtsc` stays available in user mode**, so timing side channels are possible.
  - **One CPU only:** the scratch slot and time-of-check reasoning assume a single CPU.
- **`unsafe`:** the entry stub, MSR setup, CR3 and TSS writes, and copying through the direct map stay in `arch::x86_64` and `mm::raw`. Process, capability, IPC, and validation logic is safe Rust.

## 5. Testing

The [M2.7 security review](../security/review-m2.7-kernel-user-boundary.md) covers this interface; its findings are fixed and tested in the `hardening` test kernel.


Planned test kernels (QEMU under TCG, run in CI):

- **Address spaces (#38):** the same user address maps to different frames in two processes; destroying a process returns its frames.
- **Ring 3 (#39):** a user program runs and is preempted. A user program that reads or writes kernel memory, executes a privileged instruction (`cli`, `hlt`, `mov cr3`), jumps into kernel code, or touches another process's addresses is killed, and the kernel continues.
- **System calls (#40):**
  - each call with valid arguments;
  - each with invalid ones: kernel pointers, unmapped or read-only buffers, lengths over the limit, overflowing ranges, unknown numbers, invalid, deleted, or revoked handles, and missing rights;
  - a `syscall` placed just below the never-mapped last page.
  - Host tests cover the validation and the capability logic, including a randomized test.
- **IPC (#41):**
  - two processes exchange messages in a checked order;
  - a capability is passed and then revoked;
  - a process without `SEND` cannot send;
  - the round trip is measured under KVM against the D-004 budget (a manual local run; CI only checks correctness).

## 6. Alternatives

- **`int 0x80` instead of `syscall`:** simpler entry (the CPU switches stacks through the TSS), but 6–7 times slower in the D-004 prototype (138 ns against 21 ns under KVM). See D-014.
- **Asynchronous message queues:** senders never block, but the kernel must buffer messages from untrusted senders, which needs quotas from the start and makes memory use depend on them. See D-014.
- **Accessing user memory directly with SMAP toggling (`stac`/`clac`):** fewer copies, but it relies on SMAP, which CI's CPU lacks, and on fault-tolerant copy routines.
- **Revocation by indirection objects:** a grantor wraps a capability in a revocable forwarder. It needs no tree, but the grantor must plan revocation in advance, and every use pays an extra lookup.
- **ELF loading and a Rust user crate now:** more realistic programs, but a second build target and a loader before anything needs them.

## 7. Open questions

- Multiple threads per process, and a spawn system call (with a process capability).
- Memory capabilities for shared memory (the inference data path; D-004's 100 µs grant budget).
- Interrupt capabilities for user-space drivers (M2.9, D-008).
- **The IPC round trip meets the D-004 budget at the limit:** 1.97–2.00 µs against at most 2 µs (KVM, release build, i9-10900K, 100,000 round trips). Candidates if later work makes it slower:
  - a combined `call`/reply (one system call and one block per side instead of two);
  - PCID, so CR3 switches keep user TLB entries;
  - fewer lock acquisitions on the IPC path.

  Global kernel pages (#41) already cut it from about 2.9 µs to 2.65 µs in the 1,000-round-trip test (which includes starting the process).
- SMP: per-CPU scratch slots (`swapgs`), and locking for mappings during copies.
- KPTI or other mitigations for speculative-execution attacks on real hardware.
