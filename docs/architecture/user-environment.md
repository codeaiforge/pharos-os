# The user execution environment

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-29 (issue #73). It follows [D-016](../project/decision-log.md#d-016-user-execution-environment-simd-state-user-memory-and-timeouts) and item 7 of [D-017](../project/decision-log.md#d-017-writable-persistent-storage-and-audit-integrity), for [M3.0](../project/implementation-roadmap.md#m30--platform-prerequisites-for-hosting-agents).
- **Implementation:** the user-program build and vector state are **implemented** (#74: `kernel/src/arch/x86_64/fpu.rs`, the context switch, `pharos-user`'s memory functions and probes, `libm`; tested by `vector_state` and `vector_state_avx`). So is user memory (#75: `process::UserMemory`, `mem_map`/`mem_unmap` in `kernel/src/syscall.rs`, the limit in `spawn`, `pharos_user::{mem_map, mem_unmap, spawn_limited}` and the size-class heap; tested by `user_memory` with the `memprobe` program). So are timeouts (#76: `sched::deadline` and `sched::block_until` with expiry in the timer tick, `Endpoint::remove_receiver` and `remove_sender`, `irq::Vectors::cancel`, `sleep`, `pharos_user::{receive_timeout, call_timeout, irq_wait_timeout, sleep}`; tested by `timeouts` with the `timeprobe` program, and in `device_irq`). So is shared memory (#80: `process::SharedMemory`, `cap::Object::Memory`, `AddressSpace::disown`, `mem_share` and `mem_map_cap` in `kernel/src/syscall.rs`, `pharos_user::{mem_map_buffer, mem_share, mem_map_cap}` and `Mapped::read_bytes`/`write_bytes`; tested by `shared_memory` with the `shmprobe` program). So are the storage service (#77, storage.md part 8) and large files in one process (#78: `storeclient`'s large-file mode, the 2 GiB guest in `xtask`; tested by `large_file`).

## 2. Context

M3.1 chose an inference engine that needs, from Pharos: floating point and SIMD in user programs, up to 1 GiB of memory in one process, a 700 MB model file in that memory, and calls that do not block forever (D-010, D-011). Today user programs are built for `x86_64-unknown-none`, which has no SSE; `CR0.EM` makes any x87 or SSE instruction fault; a program has a 256 KiB bump heap that never frees and cannot map memory; and no system call has a timeout.

## 3. Design

### Building user programs

- **Target:** `x86_64-unknown-linux-gnu`, as `#![no_std]`, `#![no_main]` static programs. This target uses hardware floating point and SSE2; no C library and no Linux code is involved, because nothing from `std` is used and nothing from a C library is linked. Any accidental libc reference fails at link time.
- **Flags, set by `cargo xtask` only when it builds `pharos-programs`:** `-C relocation-model=static`, `-C panic=abort` (this target unwinds by default; the bare-metal one aborted), link arguments `-nostartfiles -nostdlib -static -T user/programs/user.ld`, and `--cfg pharos_user` (declared to `check-cfg`). They are **not** put in `.cargo/config.toml`: the host also builds for `x86_64-unknown-linux-gnu`, and host tools and tests must not get them. User programs build into their own target directory (`target/user/`), so host artifacts are never rebuilt with these flags.
- **`cfg(target_os = "none")` becomes `cfg(pharos_user)`** in `pharos-user` and `pharos-programs` for the entry stub, the panic handler, and the global allocator. Host unit tests of both crates keep working without the flag.
- **What `pharos-user` supplies** (in its `syscall` module, the one user-space module allowed `unsafe`, D-008):
  - `memcpy` and `memmove` with `rep movsb` (`memmove` copies backwards with the direction flag when the regions overlap, and clears it again), `memset` with `rep stosb`, and `memcmp` and `bcmp` as byte loops. Inline assembly keeps the compiler from turning these into calls to themselves.
  - An empty `rust_eh_personality`: the prebuilt `core` for this target refers to it, although `panic = "abort"` never unwinds.
- **The build checks itself:** `cargo xtask` runs the kernel's ELF checks (`pharos-elf`) on every built program, so one with a dynamic section, an interpreter, or TLS is rejected before it reaches an image; undefined symbols already fail the static link. The vector-state test kernels check that SSE (and AVX) instructions run.
- **Lints:** `scripts/check.sh` and CI run Clippy on `pharos-programs` for `x86_64-unknown-linux-gnu` with `--cfg pharos_user`, in place of `x86_64-unknown-none`.
- **The kernel does not change target:** it stays on `x86_64-unknown-none` (soft-float), so it never touches vector registers.

### Vector state

- **Enabling:** at boot the kernel clears `CR0.EM`, sets `CR0.MP` and `CR0.NE`, and sets `CR4.OSFXSR` and `CR4.OSXMMEXCPT`. If CPUID reports `XSAVE` and AVX, it also sets `CR4.OSXSAVE` and writes `XCR0` = x87 | SSE | AVX (bits 0–2) with `XSETBV`; AVX-512 and other state components are never enabled. Otherwise it uses `FXSAVE`/`FXRSTOR` (x87 and SSE). The boot log names the mode.
- **Save area:** one per thread, 1 KiB and 64-byte aligned, inside the thread's `Context` (so it is allocated with it, not separately). `FXSAVE` uses 512 bytes; `XSAVE` uses the size CPUID leaf 0xD reports for x87 | SSE | AVX (832 bytes expected). If that size exceeded 1 KiB, the kernel would turn AVX back off and use `FXSAVE`.
- **Clean state for a new thread:** the area is initialized to the state after `FNINIT` (x87 control word 0x037F), `MXCSR` 0x1F80 (all SIMD exceptions masked, round to nearest), and zero registers, and for `XSAVE` an `XSTATE_BV` covering the enabled components so every register is loaded from it. A new process never sees another's registers.
- **Switching (eager, D-016):** the context switch in `arch::x86_64::context` saves the outgoing thread's state into its area and restores the incoming thread's, on every switch between threads. Kernel threads have areas too (holding the clean state), so every switch is the same. System calls and interrupts save nothing: the kernel never uses vector registers, and a thread's registers stay in the CPU until the next switch.
- **Exceptions:** SIMD floating-point exceptions (vector 19, `#XM`) and x87 errors (vector 16, `#MF`) from user mode kill the process, like other exceptions. They can only occur if a program unmasks them in `MXCSR` or the x87 control word.
- **`unsafe`:** the `FXSAVE`, `FXRSTOR`, `XSAVE`, `XRSTOR`, `XSETBV`, and control-register writes are `unsafe` and live in the hardware layer (`arch::x86_64`), each with a `// SAFETY:` comment. `XRSTOR` faults on a malformed area; the kernel builds every area itself and user code never writes one.
- **Cost:** measured under KVM with the IPC round trip (two switches each), recorded in [scheduling.md](scheduling.md): no measurable difference. The measurement also showed the round trip is over D-004's budget, independently of this change ([syscalls-ipc.md](syscalls-ipc.md#7-open-questions)).

### User memory

| # | Call | Arguments | Returns | Needs |
| --- | --- | --- | --- | --- |
| 19 | `mem_map` | length in bytes (rounded up to pages, > 0) | the start address | none (the caller's own limit) |
| 20 | `mem_unmap` | start address, length | 0 | none (the caller's own mapping) |

- **Mappings** are anonymous, zeroed, user, writable, and non-executable, at an address the kernel chooses in the **map region**, `0x0000_1000_0000_0000` to `0x0000_2000_0000_0000` (16 TiB, clear of the program at `USER_BASE` and the stack below `STACK_TOP`). The kernel keeps each process's mappings in a list (at most 1,024 mappings) and places a new one at the first gap that fits.
- **Frames are allocated at `mem_map`** (no demand paging, so no new page-fault path). The page count is checked against the process's limit before any frame is allocated; on failure nothing is mapped and the error is `NO_MEMORY`. Page tables created for a mapping count as kernel overhead, as for program loading.
- **`mem_unmap`** takes exactly one whole earlier mapping (start and length as mapped, after rounding); anything else is `BAD_ADDRESS` and changes nothing. It unmaps, flushes the TLB entries, and frees the frames (or drops the reference for a shared mapping).
- **The limit:** each process has a page limit. `spawn` takes it in bits 32–63 of its `count` argument, in pages (bits 0–31 keep the capability count, at most 8); since M3.5 it is carved out of the creator's (D-022, #115): a creator may give at most its limit less its own mappings, what it has given its live children, and what sharing has charged it (`TOO_LARGE` otherwise), and the pages return when the child ends ([resources.md](resources.md#carved-limits-115)). `mem_map` zeroes a large mapping in batches of 64 pages; between them it lets interrupts in (`sti; nop; cli`, since #120: before, `sti` then `cli` let none in), where a tick or device interrupt switches to a woken task, so it does not hold the CPU; a process told to stop meanwhile gives up, and ends as the call returns (a tick ends a process only when it interrupted user mode). Since #122 `mem_unmap`, `mem_share`, `mem_map_cap`, and the end of a process free, share, and map in the same batches. Processes started by the kernel get their limit from the kernel (`init`: 3 GiB since #115, from which the inference and storage services' 1 GiB each and the runtime's 64 MiB are carved; 1.5 GiB before, when nothing was carved). Mappings from `mem_map_cap` count against the mapping process's limit. Existing programs are unaffected: limit 0 means no mappings, and a program that never calls `mem_map` keeps working.
- **Exit and kill** unmap everything and free every frame, as for program pages today.

### The user allocator

`pharos-user`'s global allocator (in its `syscall` module, replacing the bump heap):

- **Small allocations** (up to 32 KiB, rounded up to a power of two from 16 bytes) come from size-class free lists. Their memory comes first from the existing 256 KiB static area in the program image, then from 64 KiB chunks obtained with `mem_map`; chunks are kept for reuse, not returned.
- **Large allocations** (above 32 KiB) are their own `mem_map` mapping, unmapped when freed, so a model file or a key/value cache returns to the kernel. If `mem_map` refuses (a program started without a limit) while the static area still has room, the block is carved from it and never reused, as with the old bump heap, so programs that never had a limit keep working (#75).
- **Out of memory** (the limit reached) is a null return, which Rust turns into the allocation-error path (a panic, so the process ends with a report).
- **Alignment** up to 4 KiB is honoured; larger alignments are refused (null).
- Host-tested: the size-class logic runs on the host with a fake `mem_map`.

### Timeouts

| # | Call | Change |
| --- | --- | --- |
| 4 | `receive` | new 4th argument: timeout |
| 18 | `call` | new 6th argument: timeout |
| 13 | `irq_wait` | new 2nd argument: timeout |
| 21 | `sleep` | new call: duration in microseconds; returns 0 |

- **Timeout encoding (D-016):** microseconds, relative to the call; `u64::MAX` waits forever; 0 does not block (returns `TIMED_OUT` at once if nothing is ready). **Every `pharos-user` wrapper passes `u64::MAX` unless the caller gives a timeout**, so existing programs keep blocking as before; programs that put other values in unused registers must be updated (the `syscalls` test does, on purpose, and is changed to pass explicit values).
- **New error 12, `TIMED_OUT`.**
- **Resolution:** the deadline is converted to timer ticks (10 ms) and rounded up, plus one tick, so no wait ends early; a timeout that would overflow is treated as forever.
- **No lost messages:** expiry is handled in the timer interrupt with interrupts off. If a message was delivered to the waiting thread before expiry, the call returns it; if not, the thread is removed from the endpoint's queue and gets `TIMED_OUT`, and a message sent later stays queued (or the sender blocks) for the next receiver. A reply to a `call` that timed out meets the one-shot reply capability, already revoked, and the server gets `REVOKED`.
- **`irq_wait`:** a timeout leaves the interrupt's count untouched; the next wait returns it.
- **`sleep`** uses the scheduler's sleeping queue, with the same rounding; `sleep(0)` returns at once.
- **Implementation note (#76):** the timer tick makes an expired waiter ready and marks it timed out; the waiter itself then leaves the endpoint's queue when it runs, still with interrupts off. A message or interrupt that reached it between the deadline and that moment is returned instead of `TIMED_OUT`, so nothing is lost. A `call` whose request no server took is withdrawn from the server's queue (with any capability in it).

### Shared memory (D-017 item 7)

| # | Call | Arguments | Returns | Needs |
| --- | --- | --- | --- | --- |
| 22 | `mem_share` | start address, length (one whole `mem_map` mapping) | a new `Memory` handle with `READ`, `WRITE`, and `GRANT` | none (the caller's own mapping) |
| 23 | `mem_map_cap` | `Memory` handle, writable (0 or 1), length (must equal the object's size, rounded up to pages; added in #80 so the caller knows the mapping's bounds) | the start address in the caller's map region | `READ`; `WRITE` when writable |

- **The `Memory` object** holds the frames of the shared mapping. `mem_share` moves the frames' ownership from the address space to the object; the sharer's mapping stays, now holding a reference. Each mapping and each capability keeps the object alive; the frames are freed when the last of them is gone. The page-table bit M2.9 uses for device memory (`DEVICE`, "not owned by this space") keeps `destroy` and `mem_unmap` from freeing the frames directly; implementing #80 showed no separate `SHARED` bit is needed. `mem_share` on an already shared mapping returns another capability on the same object. A mapping made by `mem_map_cap` cannot be shared (`BAD_ADDRESS`): that would give the receiver a capability outside the sharer's derivation tree, which the sharer's `revoke` could not reach (found by the M3.0 security review; the approved design allowed it).
- **Rights narrow only**, as for every capability: a holder passes on `READ` alone to give read-only access. A read-only mapping is mapped without the write bit, so a write is a page fault that kills the process. Mappings are never executable.
- **Revocation** stops new mappings, and turns existing ones into zeroed private pages with the same access, in every process, before `revoke` returns (#104).
- **Only `mem_map` memory can be shared**, not program pages, the stack, device memory, or DMA buffers.

### Large files in one process

A client reads a 700 MB file from the storage service (storage.md, part 8) into its own memory, a heap `Vec` of the file's size (its own `mem_map` mapping), through a 16 MiB window it shares with the service: each `read` fills the window and the client copies it out. **Implemented (#78)** with one change from the design, which had the service fill a shared buffer of the file's size: the service can write a shared buffer at any time, so Rust code must not borrow it as a plain slice, which the GGUF reader and the engine need (they borrow weights from the file). The copy costs one pass over the file. `cargo xtask` runs `large_file` with 2 GiB of guest memory (`test_qemu_args`; other test kernels keep 256 MiB) and a time limit of at least 300 s.

Implementing #78 also found that a device interrupt arriving while the CPU idled waited for the next 10 ms tick before its driver ran: about 2 ms per 4 KiB block, over 5 minutes for the file. The idle task now runs a task woken by an interrupt at once (scheduling.md); the file takes about 43 s under TCG, about 16 MB/s, with one 4 KiB disk request at a time.

### Math functions

`pharos-programs` depends on `libm` (MIT, no runtime dependencies; reviewed under AGENTS.md section 6 in #74) and implements `pharos-infer`'s `Math` trait with it. The kernel does not use it.

## 4. Security

- **Vector-state leaks:** eager save and restore on every switch, a clean image for new threads, and no lazy switching (LazyFP, CVE-2018-3665). Tested with two processes and after a kill.
- **Malformed save areas:** only the kernel writes them; user code cannot reach them.
- **Memory exhaustion:** per-process page limits checked before allocation, at most 1,024 mappings per process, no demand paging. Since #115 limits are carved from the creator's, so a process and its descendants together stay within its limit; a process can still use its whole limit of frames.
- **Shared memory:** rights only narrow; read-only mappings are not writable; frames live until the last user; revoked mappings become zeroed private pages (#104).
- **Timeouts:** cannot lose or duplicate a message; a late reply cannot reach a later call.
- **New trusted code:** the vector-state instructions in the hardware layer, the memory functions and allocator in `pharos-user`'s `syscall` module, and the `Memory` object in the kernel. AGENTS.md's list of what `pharos-user`'s `syscall` module may contain gains the memory functions and the new allocator.

## 5. Testing

| Test | What it checks |
| --- | --- |
| Host, `pharos-user` | The allocator's size classes, reuse, large-allocation mapping and unmapping (fake `mem_map`), alignment; the new wrappers' argument encoding |
| Host, `syscall` | Decoding of calls 19–23, the timeout arguments, and the limit in `spawn`; the fuzz test covers them |
| QEMU, `vector_state` (default CPU: `FXSAVE`) and `vector_state_avx` (`-cpu max`: `XSAVE` with AVX) | Two processes keep their own SSE (and AVX) values across many preemptions; a process never reads another's values, including after the other is killed; floating-point results match the host's for fixed inputs; a new process starts with clean state |
| QEMU, `user_memory` | Mapping up to the limit and `NO_MEMORY` beyond it; bad or partial unmaps refused; frames reused after unmapping and all returned after exit; the allocator frees and reuses; `spawn` refuses a limit above the creator's |
| QEMU, `shared_memory` | Writes visible both ways; a read-only grant cannot be mapped writable and a write is killed; rights cannot widen; the receiver's limit applies; every frame returns whichever process ends first |
| QEMU, `timeouts` | A `call` to a silent server returns `TIMED_OUT` within the deadline plus one tick; a reply racing the deadline is never lost; a late reply gets `REVOKED`; `irq_wait` and `sleep` |
| QEMU, `large_file` (2 GiB) | A 676 MB file read into one process through a shared window, its SHA-256 checked, parsed by `pharos-infer`'s GGUF reader. The file is a generated GGUF of the target size, or the Qwen2.5-0.5B q8_0 file named by `PHAROS_MODEL` (CI has no model file) |

Each fix and each check is mutation-tested as in earlier milestones.

## 6. Alternatives

Recorded in D-016 and D-017: SSE flags on `x86_64-unknown-none` (no effect while `soft-float` is forced, and disabling it is being phased out), a custom target (nightly), lazy vector switching (LazyFP), memory capabilities instead of a limit (M3.5), timer objects, file data over IPC.

## 7. Open questions

- Context-switch cost with `XSAVE` on real hardware (measured under QEMU first).
- Whether `XSAVEOPT` or `XSAVES` is worth using (only if the measurement shows the save matters).
