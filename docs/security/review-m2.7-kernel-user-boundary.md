# Security review: M2.7 kernel/user boundary

- **Scope:** everything M2.7 added between user processes and the kernel: the system-call entry and every system call, every path that reads or writes user memory, the ring 3 entry and exit paths, interrupts and exceptions from user mode, capabilities and IPC, and every `unsafe` block added in M2.7 (since commit `8b4aeb4`, the M2.6 gate).
- **Design under review:** [syscalls-ipc.md](../architecture/syscalls-ipc.md), D-004, the D-012 direction, D-014.
- **Date:** 2026-10-27, issue #42. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim; findings fixed in the same issue.
- **Status:** **awaiting maintainer approval.**

## Method

1. Read every changed file under `kernel/src` since the M2.6 gate, and list each `unsafe` block and `global_asm!` routine with the invariant it relies on.
2. For each system call, follow every argument from the register to its last use, and check every error path for state changes.
3. For each way into the kernel from ring 3 (`syscall`, interrupts, exceptions, `int n`), check:
   - which stack it runs on;
   - which flags and registers it can inherit from user mode;
   - which values reach user mode on the way out.
4. Check every kernel structure that a process can make grow.
5. Turn each finding into a test kernel check that fails without the fix (`hardening`, and checks in `syscalls`, `user_mode`, `ipc`, `address_spaces`).

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | Interrupt and exception entry from user mode cleared DF (`cld`) but not AC. A process could set AC and take a tick; the handler then ran with SMAP's checks switched off. Alignment checks do not apply in ring 0, and the kernel never touches user pages, so this is defence in depth. | **Fixed:** the common entry stub clears AC on the saved flags (`pushfq; btr; popfq`, which works without SMAP support). Debug builds assert DF and AC are clear in the interrupt and system-call dispatchers. `hardening` runs a process with DF and AC set through many ticks and checks the flags come back. |
| F2 | Medium | The kernel logs of `debug_write` output, exits, and kills grew without bound, driven by process actions. A process with the debug-console capability could fill the 4 MiB kernel heap and stop the kernel. | **Fixed:** each log keeps only its newest 64 entries (`process::LOG_ENTRIES`). `hardening` has a process write 300 times; the log holds 64 entries and the heap grows 18.5 KiB, where an unbounded log would grow over 75 KiB. |
| F3 | Medium | User code could use the x87 FPU and MMX (`CR0.EM` clear). The kernel is soft-float and never saves FPU state on a task switch, so one process could read and change another's FPU registers: an information leak and corruption across processes. Verified with a probe: `fld1` ran in user mode. | **Fixed:** the kernel sets `CR0.EM` at boot, so x87 and MMX instructions fault and the process is killed (`#NM`). SSE and AVX already fault, because `CR4.OSFXSR` and `OSXSAVE` are clear. `hardening` checks the kill. A per-process FPU context comes when user programs need floating point. |
| F4 | High (found in this review, fixed in #41) | Unmapping a kernel page while a process address space was active did not flush the TLB. For example, a task stack freed from a user thread's system call could stay reachable through a stale entry after its frame was reused. | **Fixed in #41:** kernel-space unmaps always flush. An `address_spaces` check remaps a kernel page while a process space is active. |
| F5 | Build | Two let chains (Rust 1.88) broke the minimum supported Rust (1.85) build on four commits; CI's `msrv` job failed. Not a security issue, but it meant `main` was red. | **Fixed** in `12cc012`. `scripts/check.sh` now repeats the `msrv` checks when Rust 1.85 is installed. |

## System calls

Every call goes through one path:
1. `syscall::decode` checks the number, lengths, and address ranges. It is fuzzed with 200,000 random calls.
2. The handler checks the handle and its rights in the caller's table.
3. User memory is copied only through `AddressSpace::read_user` and `write_user`, which validate every page before copying through the direct map.

| Call | User input | Checks | State changed on error | Verdict |
| --- | --- | --- | --- | --- |
| `exit` | code | none needed | — | OK |
| `yield` | — | — | — | OK |
| `debug_write` | handle, buffer, length | length ≤ 256; range; `WRITE` on a debug-console capability; pages present and user. Output is sanitized: non-printable bytes are printed as `?`, so no terminal escapes get through | none | OK (F2 fixed) |
| `send` | handle, buffer, length, capability, rights | as `debug_write`, plus `SEND` on an endpoint. A passed capability needs `GRANT`; the receiver's rights are the sender's ANDed with the mask. The message is copied before blocking | none: every check happens before queueing | OK |
| `receive` | handle, buffer, maximum length | length ≤ 256; range; `RECEIVE` on an endpoint. The pages must be writable user pages, checked before taking a message, and a free handle must exist. A longer message is cut to the buffer, and the value reports the full length | none: every check happens before taking a message | OK |
| `delete` | handle | the handle exists in the caller's table | — | OK |
| `revoke` | handle | the handle exists and is not revoked; marks descendants only | — | OK |
| unknown numbers | — | `UNKNOWN_CALL` | — | OK |

## User memory paths

- **The kernel never dereferences a user virtual address.** All copies go through `read_user` and `write_user`, which:
  - check the range (`user_range_ok`: at or above `0x1000`, below the never-mapped last user page, no overflow);
  - check every page (present, user, and writable for writes);
  - copy only after all checks pass, through the direct map.
- **At most two pages** per copy (`MAX_COPY_PAGES`); longer requests fail.
- **Time of check against time of use:** one CPU, interrupts disabled in system calls, and one thread per process. Between the check and the copy, nothing can change the mappings. **SMP must revisit this.**

## Ways into the kernel from ring 3

| Path | Stack | Flags from user mode | Out to user mode | Verdict |
| --- | --- | --- | --- | --- |
| `syscall` | Thread's kernel stack, through a scratch slot (one CPU) | `SFMASK` clears TF, IF, DF, NT, AC | `sysret` after the return address is checked against the user half (`iretq` fallback); `rcx`/`r11` as documented, other registers restored | OK |
| Interrupts and exceptions | TSS `rsp0` = thread's kernel stack top, set on every switch | `cld`; AC cleared (F1) | `iretq` with all registers restored from the frame | OK (F1 fixed) |
| `int n`, including `int3` and `int 0x80` | — | — | Every gate has DPL 0, so the process gets `#GP` and is killed (tested) | OK |
| First entry (`enter_user`) | — | `RFLAGS = 0x202` | Every other register cleared; selectors `0x33`/`0x2b` | OK |
| Privileged instructions (`cli`, `hlt`, `mov cr3`, `in`/`out`) | — | — | `#GP`: IOPL 0, no I/O bitmap. Process killed (tested) | OK |
| x87/MMX, SSE/AVX | — | — | `#NM` (`CR0.EM`, F3) and `#UD` (FXSR and XSAVE off). Process killed (tested for x87) | OK (F3 fixed) |

## `unsafe` added in M2.7

All `unsafe` stays in the allowed modules (AGENTS.md) and has a `// SAFETY:` comment (enforced by Clippy).

| Location | What | Invariant | Verdict |
| --- | --- | --- | --- |
| `arch::x86_64::rflags` | `pushfq; pop` | Reads only | OK |
| `context::enter_user` (+ `global_asm!`) | `iretq` to ring 3 | `rip` and `rsp` are checked to be in the user half; user selectors; registers cleared; the abandoned frame is never resumed | OK |
| `context::do_switch` → `paging::load_root` | CR3 write | Only the kernel root or a live process space's root. The context owns the space, and a running context cannot be dropped | OK |
| `gdt::set_kernel_stack`, `gdt::kernel_stack` | TSS `rsp0` write and read | One CPU, interrupts disabled; packed field accessed with unaligned access | OK |
| `idt::user_fault_hook`, `syscall::dispatch` | Transmute of a stored function pointer | Only values stored by the typed setters | OK |
| `idt` common stub | `pushfq/btr/popfq` | Changes only AC in the saved flags | OK (F1) |
| `paging::map_new_page` | Copy into a fresh frame | The frame was just allocated and nothing else references it; the length is checked against one page | OK |
| `paging::read_user`, `write_user` | Copies through the direct map | Pages validated as user pages of this space before any copy | OK |
| `paging` CR4/CR0 writes | PGE, SMEP, SMAP, EM | Only add checks or keep kernel TLB entries; global entries are kernel-half only, and kernel unmaps always flush (F4) | OK |
| `paging::read_phys_u64`, `read_test_page`, `read_user_test_page` | Test helpers: reads | Each checks a mapping before reading | OK |
| `syscall` entry (`global_asm!`), `wrmsr` | System-call entry and MSR setup | See "Ways into the kernel"; MSRs point at the stub and kernel selectors | OK |
| `user_programs` (`global_asm!`, `from_raw_parts`) | Test program bytes in read-only data | Symbols bound each program; never written | OK |

## Accepted limits (tracked)

- **Speculative execution (Meltdown class):** the kernel half is mapped, supervisor-only, in every address space; no KPTI. Not relevant under TCG; revisit before real-hardware use.
- **Timing side channels:** `rdtsc` is available in user mode.
- **IPC blocking:** a server that never receives blocks its clients, and a thread blocked on an endpoint that loses its last capability stays blocked. There are no timeouts yet.
- **Serial output is slow,** so a process with the debug-console capability can slow the kernel down by writing a lot. The capability is the control.
- **SMP:** the scratch slot, the time-of-check reasoning, and TLB flushes all assume one CPU.
- **SMEP and SMAP are not in CI:** QEMU's default CPU lacks them. All test kernels passed locally with `-cpu max`.

## Approval

Pending: the maintainer approves, or asks for changes, as part of the M2.7 gate (#42).
