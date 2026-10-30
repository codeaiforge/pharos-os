# Security review: M3.0 platform prerequisites

- **Scope:** everything M3.0 added at the boundaries between processes, the storage service, the disk, and the kernel (since commit `dfb4bad`, the approved M3.0 design):
  - vector state: `kernel/src/arch/x86_64/fpu.rs` and the context switch (#74);
  - user memory: `mem_map`, `mem_unmap`, the page limit in `spawn`, and `pharos-user`'s allocator (#75);
  - timeouts on `receive`, `call`, and `irq_wait`, and `sleep` (#76);
  - shared memory: `mem_share`, `mem_map_cap`, and the `Memory` object (#80);
  - the writable store format, the storage service, virtio-blk writes, and the crash test (#77);
  - large files in one process, and the idle task's change (#78);
  - every new `unsafe` block.
- **Design under review:** [user-environment.md](../architecture/user-environment.md), [storage.md part 8](../architecture/storage.md#8-the-writable-store-m30), D-016, D-017.
- **Date:** 2026-10-30, issue #79. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. Both findings were fixed in the same issue.
- **Status:** **approved** by the maintainer on 2026-10-30 (M3.0 gate, #79).

## Method

1. Listed every changed file under `kernel/src`, `user/`, `crates/pharos-store`, and `xtask/` since `dfb4bad`, and searched the diff for new `unsafe` blocks.
2. For each new system call (19–23 and the timeout arguments), followed every argument from the register to its last use. Checked that every limit is checked before any frame is allocated, and that nothing stays mapped or allocated after an error.
3. Followed a `Memory` object through every holder (sharer's mapping, capabilities, receivers' mappings) and every way it ends (unmap, revoke, delete, exit), and checked who can obtain a capability on it.
4. For each value the storage service takes from a client (requests, badges, buffer sizes) or from the disk (superblocks, index, extents, records), found where it is checked.
5. Checked every kernel structure a process can make grow: mappings, `Memory` objects, shared-mapping lists, the deadline queue.
6. Turned each finding into a check that fails without the fix, and mutation-checked it.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | A receiver could escape revocation. `mem_share` on a mapping made by `mem_map_cap` returned a new capability on the same object, as the design allowed. That capability was a new root, outside the sharer's derivation tree, so the sharer's `revoke` could not reach it. A receiver could keep it, or pass it on, and others could map the memory after the sharer revoked every grant. | **Fixed:** only the sharer's own `mem_map` memory can be shared. Each shared mapping records whether it is the process's own, and `mem_share` refuses one made by `mem_map_cap` with `BAD_ADDRESS`. `shared_memory` test: B's `mem_share` on its received mapping must fail. Mutation-checked (allowed again: 6 checks fail). |
| F2 | Low | One client could take the whole storage service's memory. The service maps each client's attached buffer against its own page limit (1 GiB under `init`), and took any size. A single client attaching a 1 GiB buffer would leave every other client unable to attach one (`NO_BUFFER`). | **Fixed:** buffers over 32 MiB (`store_proto::MAX_BUFFER`) are refused and the client's earlier buffer stays; 16 clients' buffers fit in the service's limit. `store` test: a 32 MiB + 4 KiB attach is refused and the 17 MiB buffer stays. Mutation-checked (no cap: the check fails). |

## System calls

- **`mem_map` (19):** the length is rounded up to pages and capped at the map region. The page limit and the 1,024-mapping limit are checked before any frame is allocated. On a failure part-way, every page mapped so far is unmapped and freed, and the reservation is released. Pages are zeroed, writable, user, and never executable.
- **`mem_unmap` (20):** takes only one whole mapping, matched exactly against the process's own list, so no partial or foreign range can be unmapped. A shared mapping's frames are left to the `Memory` object; only owned frames are freed.
- **The limit in `spawn`:** a child's limit cannot exceed its creator's (`TOO_LARGE`). It is not carved out of the creator's (see the limits below).
- **`mem_share` (22):** needs a whole mapping the process made with `mem_map` (see F1). Frame ownership moves to the object page by page with `disown`, which cannot fail part-way on a recorded mapping. The handle table is checked first. The capability has `READ`, `WRITE`, and `GRANT`.
- **`mem_map_cap` (23):** needs `READ`, and `WRITE` for a writable mapping. The expected length must equal the object's size, so the caller knows the mapping's bounds. The mapping is counted against the caller's limit and never executable. Its pages carry the "not owned" bit, so neither `mem_unmap` nor `destroy` frees them. Frames are freed when the last capability and mapping are dropped, never twice (the `shared_memory` test counts double frees).
- **Timeouts and `sleep` (21):** deadlines saturate, so a huge timeout never wraps to an early one. Expiry runs in the tick with interrupts disabled. A waiter that a message or interrupt reached before it ran again gets that message, not `TIMED_OUT`. A `call` request no server took is withdrawn from the queue, and a late reply meets the revoked one-shot reply capability (`REVOKED`). The `timeouts` race test checks that every reply the server delivered reached the client.

## Vector state

- Saved and restored eagerly on every switch (`FXSAVE`, or `XSAVE` with `XCR0` = x87 | SSE | AVX), never lazily (LazyFP). Each thread starts from a clean area, so a new process never sees another's registers (`vector_state`, `vector_state_avx`).
- Save areas are kernel memory that only the kernel writes, so `XRSTOR` never loads a value from user space. A user program can set `MXCSR` only through `LDMXCSR`, which faults on reserved bits in the program itself.

## The storage service

- **The disk is untrusted.** Every superblock, index, extent, and record is checked (CRC-32, bounds, overlaps) before use. The parser is fuzzed with 100,000 images, and every commit was cut at every write on the host, with lost and reordered unflushed writes. `store_crash` kills QEMU 20 times while writing, and every next boot found the old or the new state.
- **Clients are known only by badge.** The namespace comes from the badge's low 16 bits through a reviewed table; badge 0 and unknown namespaces get `NO_ACCESS`. Client paths are joined to the namespace prefix and checked as store paths, so `..` and empty components cannot escape it. Bit 16 makes a client read-only.
- **File data stays in the client's own buffer.** Each `read` and `write` range is checked against that client's attached buffer (`NO_BUFFER`). `NO_SPACE` is decided before anything is written. Buffers are capped at 32 MiB (F2), and at most 16 clients hold one.
- **Shared buffers are never borrowed as slices.** The service may write a client's buffer at any time, so both sides access shared memory only through `Mapped`'s volatile copies. The large-file client copies each window into private memory before the GGUF reader borrows it (#78).

## The idle task

The idle task checks the ready queue with interrupts disabled, then runs `sti; hlt`. `sti` takes effect only after the next instruction, so an interrupt that became pending after the check still wakes the `hlt`. It then yields, so a task woken by an interrupt runs at once (#78).

## `unsafe` added in M3.0

All of it is in the modules AGENTS.md allows, each block with a `// SAFETY:` comment (enforced by Clippy's `undocumented_unsafe_blocks`):

- `kernel/src/arch/x86_64/fpu.rs` (13 lines): `CPUID`, `CR0`/`CR4` writes, `XSETBV`, and `FXSAVE`/`XSAVE`/`FXRSTOR`/`XRSTOR` on a thread's aligned save area.
- `kernel/src/arch/x86_64.rs` (1 block): `sti; hlt` for the idle task.
- `user/pharos-user/src/syscall.rs`: the memory functions the compiler calls (`memcpy`, `memmove`, `memset`, `memcmp`, `bcmp`), vector-register probes for tests, and the size-class heap allocator (free lists threaded through freed blocks, a lock around the heap). Its host tests run it under the standard allocator.

`pharos-store`, `pharos-infer`, and the user programs use none (`pharos-store` and `pharos-infer` forbid it).

## Accepted limits (tracked)

- **Shared-memory bookkeeping uses the kernel heap.** A `Memory` object keeps one 8-byte frame address per page on the fixed 4 MiB kernel heap, and the kernel panics when that heap is exhausted. A process can therefore use up to 1/512 of its page limit in kernel heap: 2 MiB for the 1 GiB inference service. A process sharing all of a 1.5 GiB limit (only `init` has one) would take 3 MiB. `mem_share` itself fails cleanly when the heap is short, but a later kernel allocation might not. Carried to M3.5 (resource accounting): store runs of frames, or count the bookkeeping against the process's limit.
- **Limits are not carved from the creator's** (#75), so several children may each hold their creator's whole limit. Carried to M3.5.
- **A large `mem_map` runs with interrupts disabled** while it zeroes every page (#75). Carried to M3.5, with preemption points.
- **Revocation does not unmap** shared memory a receiver already mapped, as for device memory (M2.9). Ending the process is the full revocation. Carried to M3.4.
- **The storage service forgets no client:** a buffer stays mapped after its client ends, until the same badge attaches another. At most 16 badges hold one. Carried to M3.3, with service restarts.
- **Audit chains are not anchored:** someone holding the disk can rewrite a whole stream with a valid chain. Carried to M3.4.
- **A QEMU kill cannot lose writes QEMU already handed to the host,** so `store_crash` cannot detect a missing flush. The host crash tests cover it.
