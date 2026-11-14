# Security review: M5.4 trusted base

- **Scope:** the trusted base, reviewed whole rather than as the changes of one milestone:
  - the kernel's system-call layer: `syscall.rs`, `cap.rs`, `ipc.rs`, `process.rs`, and the user-memory copies in `arch/x86_64/paging.rs`;
  - every kernel `unsafe` module: `arch/x86_64.rs` and its submodules, `limine.rs`, `mm/raw.rs`;
  - `trust`, the agent runtime (`agents` and its `pharos_programs` modules), `init`, `store`, and `audit`, with their `pharos_proto` interfaces and `pharos-fs`.
- **Design under review:** the [threat model](threat-model.md) (Part 1), AGENTS.md sections 5 and 7, and the architecture pages each scope names.
- **Dates:** 2026-11-13 to 2026-11-14, milestone M5.4. The code under review is `main` from `37ab5b7` onward; the fixes are listed below.
- **Status:** **awaiting the maintainer's verdict.** Validity and severity of every finding are the maintainer's to decide. The severities below are the reviewers' proposals, with the main session's opinion where it differs.

## Reviewers and their independence

M5.4 asks for a reviewer independent of the agents that wrote the code: a person, or at least a different model family. Two model reviewers read the code. Neither was given the earlier milestone reviews or the CHANGELOG.

| Reviewer | Family | Independence |
| --- | --- | --- |
| Claude (a separate agent per scope, Claude Code) | Same family as the model that wrote the code | **Not independent.** It may share the code's blind spots, though it saw only the code, the threat model, and the method, not the conclusions of the earlier reviews. |
| gemini-3.8-flash (GitHub Copilot CLI 1.0.103, read-only: shell, write, and network tools denied) | Different family (Google) | **Independent of the authoring model,** as M5.4's minimum asks. It is a lower-cost model, and two of its kernel findings quoted code that does not exist (below). |

Both reviewers followed one written method: attack surface first, then tracing every input, every `unsafe` invariant, object lifetimes, information flow, and denial of service. They had to quote code exactly with `file:line`, give a concrete trigger, and mark a finding unconfirmed without one. A third model, gpt-5.6-luna, reviewed the kernel's `unsafe` code and found nothing. It was not used again.

Every finding below was checked against the code by the main session (Claude Code) before it was filed. The main session wrote neither review, but it is the same family that wrote the code. **No human has reviewed the trusted base.** That is still the M5.4 gate ("sign-off by the independent reviewer and the maintainer"); an external audit stays open if resources allow.

## Findings fixed

Each fix has a test that fails without it. Each fix also has a throwaway branch: the test kept, the fix removed. CI on each such branch must fail at that test and at no other.

| Issue | Proposed severity | Found by | Finding | Fix | Test (fails without the fix) |
| --- | --- | --- | --- | --- | --- |
| #204 | High | Claude | A caller woken by its reply endpoint left its request queued on the server: the kernel heap could grow without bound, with stray wake-ups later | `b3efd30` | `ipc` |
| #202 | High | Claude (both kernel scopes) | Device registers mapped into a process were accepted as system-call buffers; the kernel copied through the direct map, which does not cover them: a kernel page fault from ring 3 | `fcd08a0` | `device_caps` (`devprobe`) |
| #205 | Medium | Claude | A process that could not start (bad entry point, no frame for its kernel stack) leaked its address space | `be34074` | `spawn` |
| #203 | Medium | Claude; Gemini (F-01, F-02) | The revocation sweep took the trusted reserve for any process, and built a 16-byte-per-page list on the fixed kernel heap | `37ab5b7` | `shared_memory` |
| #206 | Medium | Claude (T1); Gemini (F1, F2) | `trust`'s approval slots outlived the runtime that asked: they filled up, and a restarted runtime's `#1` could be answered by a `yes 1` meant for an old prompt | `480e8a2` | `trust` |
| #208 | Medium (Gemini: High; Claude: Low) | Claude (R7); Gemini (SEC-01, SEC-05) | A supervisor could delegate `update propose`, which acts on the worker's own files; the user's `apply` still gated every update | `63176b2` | `groups` unit test |
| #210 | Medium | Claude (R2) | An expired model grant did not end the inference session opened under it | `4653150` | `permissions` |
| #209 | Medium | Claude (R1) | A request sent without a reply capability skipped the agent's rate limit | `8162da1` | `exhaustion` |
| #211 | Medium | Claude (R3) | One agent could hold the only inference session for its whole task time | `a07305f` | `agents` |
| #207 | Medium | Claude (R6) | Revocations and refusals were kept in memory only, so a runtime restart gave a resumed task its revoked permissions back | `edbbb29` | `permissions` |
| #213 | Medium | Claude (S-1) | `init` handed `trust` the runtime's `STOP` with a blocking send, and hung for good when the runtime restarted while `trust` was down | `07e1ec9` | `system` |
| #214 | Medium | Claude (S-3); Gemini (SEC-M54-001) | A restarted audit service that could not reach the store fell back to boot 1 and wrote into an earlier boot's trail | `106bc4e` | `audit` |
| #216 | Low to medium | Claude (S-2) | A store answer lost after a committed append made the next audit record reuse its sequence number | `ddea515` | `sequence` unit test (a lost answer cannot be made on purpose in QEMU) |
| #212 | Medium | Claude (R4, S-4); Gemini (SEC-M54-002) | The store had no limit per namespace: one writer, an agent with empty files among them, could fill it and deny the audit trail. Decided by D-046 | `4be5074` | `pharos-store` unit test; `budgets` |
| #215 | Medium | Claude (S-5) | `init` carried out the user's commands whatever happened to their audit record, and dropped the oldest queued record silently after 32 | `a7ab8f9` | `manage` |

**CI on the throwaway branches:**
- Confirmed to fail at their test only (2026-11-14, the `push` cell):
  - #204: run 43481497823;
  - #202: run 43481504187;
  - #205: run 43481510032;
  - #203: run 43481514964;
  - #206: run 43481521810.
- **Not yet run:** #208, #210, #209, #211, #207, #213, #214, #216, #212, #215. Their branches are local until the maintainer pushes them.

## Corrections to the findings

Checking the findings against the code changed some of them:
- **#203:** the claim that replacement pages are uncharged is wrong for shared mappings, which are already within the mapper's reservation. The real faults were the trusted reserve and the kernel heap.
- **#205:** the `TooManyCapabilities` path is checked by the spawn call before it is reached. The reachable path is the kernel stack allocation under memory pressure.
- **#213:** the trigger was narrower than reported. Killing `trust` and the runtime together did not hang `init`. Killing the runtime and then `trust` within the runtime's 100 ms restart delay did.
- **#208:** the reviewers disagreed on severity (Gemini high, Claude low). The main session proposes medium: the worker gains a permission no one granted it, but nothing runs without the user's `apply`.
- **Gemini SEC-01 and SEC-03 (system calls):** they quote code that is not in the repository, so they were reported as not reproduced. This is the main known weakness of the cross-family reviewer.

## Findings not fixed

### Medium, not yet verified

These were reported in the kernel scopes and were neither verified nor filed. **They must be decided before the M5.4 gate:**
- **Kernel `unsafe` F2:** the MSI-X table address is never checked against its BAR's size. It needs a hostile device, and the trust model has no IOMMU (an accepted limit until M8.1).
- **Kernel `unsafe` F3, and Gemini SEC-05:** several safe kernel functions would be unsound if misused (`gdt`, `paging`, `x86_64.rs`, `mm/raw.rs`, `context.rs`). No current caller misuses them.
- **System calls F5:** a page the revocation sweep cannot replace leaves a hole inside a reservation, which `dma_alloc` might then map.

### Low and informational

For the maintainer to accept or file:

- **Kernel:**
  - `unmap_owned` frees frames marked `DEVICE`; only the callers' ordering prevents it (F4).
  - The system-call exit has no `cli`; it relies on every handler returning with interrupts off, which holds today (F5).
  - NMI and #MC have no IST stack (F6).
  - Limine references stay usable after `retire_responses` (F7; Gemini SEC-02).
  - The data segment selectors are not saved per thread, a possible covert channel (F8).
  - `pci::write_slot` uses `wrapping_add` (F9).
  - Interrupts can be turned on with an `IrqMutex` held if guards are dropped out of order (F10).
  - `module_bytes` could alias the kernel image (F11).
  - `debug_write` holds interrupts off for up to 256 bytes on the serial port (F6, system calls).
  - The revocation sweep runs in one pass with interrupts off: recorded in the threat model, to M6.10.
- **`trust`:**
  - A runtime can show a false `granted` line, but only for a number `trust` has open, and the runtime enforces approvals anyway (Gemini F3).
  - Stale agent slots and channel after a restart: the new `CHANNEL` replaces the channel, and stopping an ended agent does nothing (Gemini F4; Claude T5, a documented limit).
  - Prompts were printed but not recorded when the table was full (T2): moot after #206.
  - Over-long lines lose their terminator (T3).
  - `stop all` always says `stopped all` (T4).
  - No rate limit on lines from the runtime (T6).
  - The start-up `ready` is a blocking send (T7).
- **Agent runtime:**
  - A store failure on the second write of a subtask leaves a parentless task (R5, unconfirmed).
  - A revocation between attempts does not reach the next attempt or the agent's subtasks (R8).
  - A subtask of an ended goal keeps its grants while its cancellation cannot be recorded (R9, unconfirmed).
  - One sender can keep a receiver's 8-message queue full (R10).
  - Knowledge status bits reveal versions the reader cannot read (R11).
  - The approval lists are never pruned (R12; Gemini SEC-04).
  - A confirmed `send` survives revoking its destination (Gemini SEC-02).
  - A budget is charged with no refund when the audit record fails (Gemini SEC-03).
- **`init`, `store`, `audit`:**
  - A 72-byte name in `incoming/` hides later update files from `update` (S-6).
  - Badge bits 17–31 are ignored by `namespace()` but not by the table rules (S-7, not reachable with today's tables).
  - A crash between writing a slot and saving the record can mark the rollback slot bad; no unapplied image boots (S-8).
  - The update buffer is attached with `WRITE` (Gemini SEC-M54-003).
  - Fixed 16-byte audit path buffer (Gemini SEC-M54-004): holds, since `log/` plus 10 digits is 14 bytes.
- **Carried by D-046:** the knowledge service can still fill the non-audit share of the store and deny the runtime's task records (to M6.10). A warning as the audit trail fills, and export then rotation on the user's command, are planned for M5.5 (#217).

## What held up

Neither reviewer found any of these:
- a way for ring 3 to gain kernel privilege or reach another process's memory without a capability;
- a badge check an agent can get past;
- a tool call from model output that skips the manifest's tool list or the permission check;
- an action of the runtime taken before its audit record;
- a runtime panic an agent can reach;
- a way into another store namespace, or a path that escapes one;
- an update booting without the user's `apply`;
- `init` giving a service more than its table entry lists.

These are statements about what two model reviewers did not find, not proofs.

## Coverage

What the reviewers said they did not reach:
- the manifest parser and `models.rs` (runtime scope);
- the start-up and verification parts of `knowledge.rs`;
- the store's index parsing at mount, and the cost of a long stream past 64 extents;
- `trust`'s half of `service.rs`;
- the test modules.

## Acceptance criteria (M5.4)

| Criterion | State |
| --- | --- |
| No open critical or high findings | Both highs (#202, #204) are fixed. Three medium kernel findings are not yet verified (above). |
| Every `unsafe` block reviewed | **Kernel only:** `arch/x86_64.rs` and its submodules, `limine.rs`, and `mm/raw.rs`, by the Claude and Gemini kernel reviews (gpt-5.6-luna found nothing). Whether every block was read is in each reviewer's coverage notes, not checked block by block here. **Not reviewed:** `user/pharos-user/src/syscall.rs`, the only `unsafe` in user space (D-008, D-016). |
| Dependencies audited (`ed25519-compact` 2.6.0, `libm` 0.2.16) | **Not done.** |
| Security reporting process reviewed (SECURITY.md) | **Not done.** |
| The report states the reviewer's independence | Above. |
| Threat model updated | Rows for #203 (the one-pass stall, to M6.10), #212 and D-046, and #215; the other fixes are within existing rows. |
