# Security review: M5.4 trusted base

- **Scope:** the trusted base, reviewed whole rather than as the changes of one milestone:
  - the kernel's system-call layer: `syscall.rs`, `cap.rs`, `ipc.rs`, `process.rs`, and the user-memory copies in `arch/x86_64/paging.rs`;
  - every kernel `unsafe` module: `arch/x86_64.rs` and its submodules, `limine.rs`, `mm/raw.rs`;
  - `trust`, the agent runtime (`agents` and its `pharos_programs` modules), `init`, `store`, and `audit`, with their `pharos_proto` interfaces and `pharos-fs`;
  - user space's only `unsafe` module, `user/pharos-user/src/syscall.rs`, with the wrappers in `lib.rs`;
  - the two registry dependencies, `ed25519-compact` 2.6.0 and `libm` 0.2.16.
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

Every finding below was checked against the code by the main session (Claude Code) before it was filed. The main session wrote neither review, but it is the same family that wrote the code. **Sign-off (the M5.4 gate):** the maintainer signed off on this report and its verdicts on 2026-11-14; the independent review is gemini-3.8-flash's, the minimum M5.4 accepts. An external audit stays open if resources allow.

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
| #218 | Medium | Claude (kernel `unsafe` F2) | The MSI-X table offset comes from the device and was never checked against its BAR's size, so the kernel's 16-byte entry write could land in RAM | `1050f95` | `pci` unit test |
| #219 | Medium | Claude (system calls F5) | `dma_alloc` and `mmio_map` accepted a hole the revocation sweep left in a `mem_map` reservation; `mem_unmap` then freed the DMA frame the device still held | `841db94` | `syscall` decoder unit test (the whole chain needs frames to run out during a sweep) |
| #220 | Medium (Gemini: high) | Claude and Gemini (`pharos-user` F1) | `mem_unmap` took any address and `Mapped` was `Copy`, so safe code could unmap memory live references still pointed into | `db2c59a` | `compile_fail` doctest and `pharos-user` unit test; the change is to types, so there is no throwaway branch: without the fix the doctest compiles |

**CI on the throwaway branches:**
- Confirmed to fail at their test only (2026-11-14, the `push` cell):
  - #204: run 43481497823;
  - #202: run 43481504187;
  - #205: run 43481510032;
  - #203: run 43481514964;
  - #206: run 43481521810;
  - #210: run 43611659904 (`permissions`);
  - #209: run 43611662483 (`exhaustion`);
  - #211: run 43611665410 (`agents`);
  - #207: run 43611668129 (`permissions`);
  - #213: run 43611670918 (`system`);
  - #214: run 43611673550 (`audit`);
  - #212: runs 43611679675 and 43613143640 (`exhaustion` and `budgets`, both through the `spend` agent's file limit; the `pharos-store` unit test passes there, since the branch removes only the store's use of the reserve check);
  - #215: run 43611682311 (`manage`).
- **Unit tests,** which run in the CI workflow rather than the release matrix (the `push` cell passed for both, as expected):
  - #208: run 43613138229 (`groups::tests::only_what_the_supervisor_holds_and_no_longer`);
  - #216: run 43613141112 (`sequence::tests::a_lost_answer_is_not_a_reused_number`).
  - #218: run 43627303835 (`pci::tests::msix_entries_stay_inside_their_bar`);
  - #219: run 43627306518 (`syscall::tests::rejects_bad_arguments`).

## Corrections to the findings

Checking the findings against the code changed some of them:
- **#203:** the claim that replacement pages are uncharged is wrong for shared mappings, which are already within the mapper's reservation. The real faults were the trusted reserve and the kernel heap.
- **#205:** the `TooManyCapabilities` path is checked by the spawn call before it is reached. The reachable path is the kernel stack allocation under memory pressure.
- **#213:** the trigger was narrower than reported. Killing `trust` and the runtime together did not hang `init`. Killing the runtime and then `trust` within the runtime's 100 ms restart delay did.
- **#208:** the reviewers disagreed on severity (Gemini high, Claude low). The main session proposes medium: the worker gains a permission no one granted it, but nothing runs without the user's `apply`.
- **Gemini SEC-01 and SEC-03 (system calls):** they quote code that is not in the repository, so they were reported as not reproduced. This is the main known weakness of the cross-family reviewer.

## Findings not fixed

### Medium, verified, hardened

- **Kernel `unsafe` F3, and Gemini SEC-05:** checked against the code; each function is as described. Safe kernel functions whose `unsafe` block trusts an unchecked argument: `gdt::set_kernel_stack`, `paging::load_root`, `run_on_kernel_stack`, `mm::raw::bitmap_storage`, `paging::fill_frame_for_test` and `write_rodata_probe` (compiled into every kernel), `mmio_write32`/`mmio_read32`, `AddressSpace::map`, and `Context::leave_space`. No current caller passes a bad value, and none is reachable from ring 3. Making them `unsafe fn` would move `unsafe` into callers outside the allowed modules (`kmain` in `main.rs`), so the fix is a design choice: narrower types (`&KernelStack`, a frame the space owns), or the test helpers behind a feature. The main session proposes **low**: hardening, not a reachable defect. The maintainer kept them safe functions; `3753e95` narrows `set_kernel_stack`, `mmio_read32`, `mmio_write32`, and `bitmap_storage` to their callers' module and documents what each caller must guarantee. The test helpers stay public, since the test kernels call them. Revisit if these functions gain callers.

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

### Verdicts on the lows

The main session proposed these, and the maintainer accepted them on 2026-11-14. Filed as #221–#236 (`bug`, no milestone), one per finding, except Gemini SEC-M54-003, which did not hold up when checked: `init` reads update files into that buffer, so the store needs `WRITE` on it.
- **File as low issues:**
  - kernel F4 (skip `DEVICE` frames in `unmap_owned`), F7, F9, F11, and F6 before real hardware;
  - `trust` T3, T4, T6;
  - runtime R8, R11, R12, Gemini SEC-02, and R5 and R9 to confirm first;
  - S-6, S-8.
- **Accept as documented limits:**
  - kernel F5 and F10 (invariants that hold today), F8 (covert channels are outside the threat model), `debug_write`'s 256 bytes;
  - `trust` Gemini F3 (the runtime enforces approvals), Gemini F4 and T5 (documented), T7;
  - runtime R10 (within the sender's budget), Gemini SEC-03 (fails closed);
  - S-7 (not reachable with today's tables).
- **No action:** T2 (moot after #206), Gemini SEC-M54-004 (holds), Gemini SEC-M54-003 (not reproduced), the revocation sweep and D-046 (already scheduled), and the three `pharos-user` lows below (a comment fix for F2 at most).

### `pharos-user` low findings (Gemini)

- F2: `memmove` calls `memcpy` for overlapping ranges, which `memcpy`'s comment forbids. The forward copy is correct there (`dest` at or before `src`), and raw pointers carry no `noalias`; the comment is wrong, not the code.
- F3: `registers_contain` would report a false match for 0 with SSE, from lanes it never writes. Its only caller passes a nonzero marker.
- F4: the vector probes run AVX instructions on the caller's word; without AVX, that is a `#UD` that ends the process, not undefined behaviour.

Checked and sound by both: the entry stub's stack alignment and `ud2` after `pharos_main`; `raw`'s registers and clobbers (it and `call` are private to the crate; every public wrapper takes Rust slices); the direction flag, which the kernel clears on every entry (`SFMASK` for system calls, `cld` for interrupts), so `memmove`'s `std` cannot reach it; `Mapped`'s bounds and alignment checks, with no reference into device memory; the heap's size classes, alignment, overflow, and lock.

## Dependency audit

Both crates are the only registry packages in `Cargo.lock`, checksums pinned. Checked on 2026-11-14 by the main session:

| Crate | Used by | License | Transitive dependencies | Advisories (OSV, which mirrors RustSec) | Notes |
| --- | --- | --- | --- | --- | --- |
| `ed25519-compact` 2.6.0 | `pharos-image` (update signatures: verified on Pharos, signed on the host) | MIT | none (`default-features = false`: no `getrandom`, `ct-codecs`, `ed25519`) | none, any version | No build script. One `unsafe` block (volatile wipe). Verification rejects a non-canonical `s` and checks with the cofactor, so it accepts a few more signatures than a strict check; Pharos's key is fixed and an image is named by its hash, not its signature, so malleability does not matter. 2.6.1 (2026-11-07) rewrote signing's base-point table and fixes nothing for verification: staying on 2.6.0 is the proposal. |
| `libm` 0.2.16 | `pharos-programs` (inference arithmetic), `xtask` | MIT | none | none, any version | Maintained by the Rust project (`compiler-builtins`); newest release. Its build script only reads environment variables. Its runtime FMA detection runs `xgetbv` only when CPUID reports OSXSAVE, which the kernel sets with AVX (`fpu.rs`). |

Not done: a line-by-line read of either crate's arithmetic, and `cargo audit`/`cargo deny`, which are not installed.

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

## The reporting process

Checked on 2026-11-14:
- **Channel:** GitHub private vulnerability reporting is enabled (`private-vulnerability-reporting` API: `enabled: true`), and the advisory link in `SECURITY.md` is the repository's.
- **Supported versions:** "the latest release and `main`" matches the releases (v0.1.0 to v0.4.0).
- **Corrected:** `SECURITY.md` still said Pharos is not bootable. Its scope named only the host workspace, the CLI, CI, and docs, and called the threat model the "planned system". It now lists the kernel, user space, and the signing tools, gives examples of reportable issues taken from the threat model, and says what is not a vulnerability: documented limits, real hardware, model text that crosses no capability boundary, and the generated test key. A leaked release key is reported the same way.
- **Unchanged, the maintainer's policy:** no committed response time, and no disclosure timeline.
- **Settings:** secret scanning, push protection, and Dependabot alerts and security updates were off; at the maintainer's request they were turned on on 2026-11-14, and the repository API confirms them.

## Acceptance criteria (M5.4)

| Criterion | State |
| --- | --- |
| No open critical or high findings | Both highs (#202, #204) are fixed, and so is #220, medium by the main session's proposal and high by Gemini's. |
| Every `unsafe` block reviewed | **Kernel only:** `arch/x86_64.rs` and its submodules, `limine.rs`, and `mm/raw.rs`, by the Claude and Gemini kernel reviews (gpt-5.6-luna found nothing). Whether every block was read is in each reviewer's coverage notes, not checked block by block here. **User space:** `user/pharos-user/src/syscall.rs` (D-008, D-016), by the main session and Gemini, every block; #220 came of it. |
| Dependencies audited (`ed25519-compact` 2.6.0, `libm` 0.2.16) | Done by the main session (above): no advisories, no transitive dependencies, MIT. Not read line by line. |
| Security reporting process reviewed (SECURITY.md) | Done by the main session (see [the reporting process](#the-reporting-process)). Private vulnerability reporting is on; `SECURITY.md`'s status and scope were out of date and are corrected. Secret scanning, push protection, and Dependabot security updates are now on. |
| The report states the reviewer's independence | Above. |
| Gate: sign-off by the independent reviewer and the maintainer | The independent review is gemini-3.8-flash's; the maintainer signed off on 2026-11-14. **Passed.** |
| Threat model updated | Rows for #203 (the one-pass stall, to M6.10), #212 and D-046, and #215; the other fixes are within existing rows. |
