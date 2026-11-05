# Security review: M3.5 resource accounting and limits

- **Scope:** everything M3.5 added to the kernel, the agent runtime, `trust`, the inference service, and `init` (since commit `c233cec`, the M3.4 gate):
  - scheduling classes, `preempt`, CPU time per task, and `process_usage` (#114);
  - limits carved from the creator's: `process::Budget`, `Process::give` and `take_back`, the capability table's limit, and `mem_share`'s bookkeeping charge (#115);
  - runtime budgets and groups, `pharos_programs::budgets`, `OVER_LIMIT` (#116);
  - stalled services, the request rate, and one approval request per agent (#117);
  - inference admission, `LIMIT` (#118);
  - usage reporting: `USAGE`, `USED`, `GROUP_USED`, and the `usage` record (#119);
  - the exhaustion tests and `interrupt_window` (#120);
  - batched unmapping, sharing, and freeing: `free_user_part`, `free_current_space`, `with_pauses`, `unmap_batched` (#122);
  - every new `unsafe` block.
- **Design under review:** [resources.md](../architecture/resources.md), D-022, D-013, [scheduling.md](../architecture/scheduling.md), [memory.md](../architecture/memory.md).
- **Date:** 2026-11-04, issue #121. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. All three findings are fixed.
- **Status:** **approved** by the maintainer on 2026-11-05 (M3.5 gate, #121).

## Method

1. Listed every changed file under `kernel/`, `user/`, `crates/`, and `xtask/` since `c233cec`, and searched the diff for new `unsafe` blocks.
2. For each budget (pages, processes, handles), followed where it is taken (`spawn`, `mem_map`, `mem_share`), where it returns (a child ending, a failed `spawn`, `mem_unmap`), and whether a failure part-way leaves it taken or a frame allocated.
3. For each new pause with interrupts on (`mem_map`, `mem_unmap`, `mem_share`, `mem_map_cap`, freeing an ending process's space, freeing a shared object), checked what may change during it: a stop, a revocation, another process's pauses.
4. Followed each new request (`LIMIT`, `USAGE`, `USED`, `GROUP_USED`, `process_usage`) to who may send it and what it reveals or changes.
5. Turned each finding into a check that fails without the fix.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | `with_pauses` restored the mark it found. If two tasks' `with_pauses` overlapped (one ending while another unmaps shared memory, both pausing), the first to finish cleared the second's mark and the second then restored the first's, leaving a live task marked outside `with_pauses`. That task's later drop of a shared object, with interrupts off and no lock held, would then let interrupts in where its caller may rely on them staying off. | **Fixed:** each task clears only its own mark (`process::unmark`, a compare-and-exchange); a task that takes the mark over ends the other's pauses early, which costs latency only. Unit test `overlapping_pauses_leave_no_stale_mark` fails if `unmark` clears whatever mark is there. |
| F2 | Medium | Found during #122, in #120's code: once `mem_map`'s pauses let interrupts in, a tick could end a process told to stop in the middle of the call. What the call held, the process among it, was never dropped, nor every capability it held, so each such stop leaked memory and kept endpoints alive. | **Fixed in `d8f7821`:** the tick ends a process only when it interrupted user mode; the call sees the stop and ends the process on its way out. `user_memory` stops a `memprobe` holding an endpoint while it maps 64 MiB and checks the endpoint is released; it fails without the fix. |
| F3 | Medium | Found during #122: with pauses between `mem_map_cap`'s batches, a capability revoked during the call was swept before the new mapping was recorded, so the sweep missed it and the mapping kept showing the object after `revoke` returned. | **Fixed in `066a9c9`:** `mem_map_cap` checks the capability once mapped and answers `REVOKED`, with nothing switching between that check and recording the mapping. `shared_memory` revokes a capability while `memprobe` maps it and checks the pages read zeros or the call was refused; it fails without the check. |

## Limits carved from the creator's

- **Checked before anything is taken:** `Process::give` checks pages, processes, and handles together and takes nothing unless all fit; a failed load or start returns them (`take_back`), and a child ending returns them to a parent that still runs. Every sum saturates. The creator's own table shrinks to the handles it has not given away, with room for the child's process handle.
- **No class above the creator's:** `spawn` refuses a higher class with `TOO_LARGE` (`spawn` kernel).
- **The kernel's backstops stay:** 32 processes, 64 handles per table, 1,024 mappings, whatever the budgets say.
- **`process_usage` needs `WAIT`** on the process, as `process_status` does: a process sees the usage of what it started, or what it was given a capability on.

## Pauses with interrupts on

- **Each pause holds no lock** and runs with the region already reserved, so nothing else maps there; only the calling process's single thread uses its mapping meanwhile.
- **A stop during a pause** ends the call cleanly (F2): `mem_map` gives back what it mapped, and the others finish and end the process on return.
- **A revocation during a pause** is caught (F3) for `mem_map_cap`. While an ending process frees its space, a revocation may map zeroed pages into it; each batch scans from the start again, and no pause follows the last, so those pages are freed too.
- **Pauses in drops** happen only under `with_pauses`, which only an ending process and `mem_unmap` use, and only with no lock held (F1).

## The runtime, `trust`, and inference

- **Budgets are checked before anything is charged or recorded,** so a refused request costs nothing; groups use the same checks.
- **`LIMIT`** is accepted by the inference service only without a badge (from `init`), for a client other than 0.
- **`USAGE`** is served by the runtime only under `trust`'s badge (`hostile`: refused); **`USED` and `GROUP_USED`** are accepted by `trust` only under the runtime's badge; both carry numbers only, and `trust` writes the text.

## IPC round trip

`cargo xtask bench-ipc` under KVM, 100,000 round trips per run. **At or just over D-004's 2,000 ns budget on this host:**

- 5 runs at `066a9c9`: median 2,010 ns (run medians 1,950 to 2,047).
- Alternating with the M3.4 gate's kernel (`c233cec`), 9 runs each: median 1,979 ns for M3.4 and 2,043 ns now; this kernel was slower in 6 of the 9 pairs. M3.5 added about 30 to 60 ns.
- Alternating with the kernel before #120 (`8201aa9`), 9 runs each: 1,947 against 1,973 ns, within the host's spread. #120 and #122 changed nothing on the round trip's path but a relaxed atomic load of the root table, the same instruction as before.

The cost comes from #114 and #115, each measured within the host's spread at the time: a TSC read and the CPU count on every switch, a class check per wake-up and queue, the `preempt` flag on every system call, and the table's limit check. The run-to-run spread on this host is about 100 ns, as large as the cost.

## `unsafe` added in M3.5

Two blocks, both in the hardware layer where D-005 allows `unsafe`:

- `arch::x86_64::interrupt_window` (#120): `sti; nop; cli`, which only sets and clears the interrupt flag. Not marked `nomem`, since interrupt handlers may change memory the caller reads after. Its callers hold no lock.
- `apic::on_timer`'s handler cast (#122) now converts to `fn(bool)`, matching what `set_tick_handler` stores; the same reasoning as before.

## Accepted limits (tracked)

- **A busy trusted or services-class process holds back lower classes** (D-022 accepted it): classes have no time share.
- **Interrupt and system-call time is charged to the process that was running.**
- **The last reference to a large shared object dropped by deleting its capability** frees the object in one go: the capability table is locked then, so no pause is safe.
- **Freeing a space in one pass instead of 4 page tables at a time** costs about 9 ms at the `exhaustion` kernel's size, below what it can tell apart; the batches stay for larger spaces (the inference service maps several times more).
- **`mem_share`'s bookkeeping charge stays until the sharer ends,** even once the object is freed; an object that outlives its sharer is no longer charged to anyone.
- **A manifest cannot narrow a budget,** and a group's minute is a fixed window (up to twice the rate across a window's edge).
