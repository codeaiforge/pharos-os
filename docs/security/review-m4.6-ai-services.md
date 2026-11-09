# Security review: M4.6 AI services, and the Phase 4 threat model

- **Scope:** everything M4.6 added since commit `d0e322a` (the M4.5 gate):
  - D-031 and the design: [services.md, AI services](../architecture/services.md#ai-services-m46-d-031) (#180, #181);
  - the runtime starting beside a hung `infer` (`attach_prompt`, `ATTACH_US`), and the trusted memory reserve (`process::TRUSTED_RESERVE`, `may_take` in `mem_map` and `spawn`; D-022 amended) (#182);
  - `Service::is_runtime` in `init`, `pharos_user::probe`, the test program `rogue`, the `aifail` and `compromised` tables and kernels (#182–#184).
- **Phase 4 gate:** all M4.x gates and a full threat-model review (below).
- **Design under review:** services.md, D-031, D-022, D-027, D-029, [capabilities.md](../architecture/capabilities.md), [threat-model.md](threat-model.md).
- **Date:** 2026-11-09, issue #185. Reviewer: AI-assisted (Claude Code), from reading the code, the `aifail` and `compromised` kernels, and the experiments recorded in services.md (a runaway `infer` stopping `trust`, #182; `trust` losing `system ready`, #183).
- **Status:** **proposed**, awaiting the maintainer. F1 and F2 fixed (2026-11-09) at the maintainer's request; F3 and F4 accepted; F5 carried.

## Method

1. Listed every changed file since `d0e322a` and searched the diff for new `unsafe` blocks and dependencies: none (the kernel's `Cargo.toml` gains two test entries).
2. Read each capability `infer` and the runtime hold against what their code uses, and what each lets a compromised holder do.
3. Followed the trusted reserve through every way a process takes frames: `mem_map`, `spawn`, `mem_share`, `mem_map_cap`, `fs_mount`, `dma_alloc`, page tables.
4. Followed each message between `init`, `trust`, and the runtime for what is lost or replaced when one side is busy, hung, or hostile.
5. Checked each M4.6 acceptance criterion against a test that runs in CI, and each threat-model limit for a milestone that has closed.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | **`init` gives `trust` 100 ms to take each service event, then drops it.** `tell_trust` tries `try_send` 10 times, 10 ms apart. `trust` blocks for longer in several places: its first call to `init` (`RUNTIME`, up to 1 s, unanswered during boot), each audit record (up to 1 s), and messages to the runtime (up to 2 s). An event that arrives meanwhile is lost: `system ready`, a service failing, being given up, or found unresponsive. Shown by `compromised` before `init` found the runtime by its manifest (services.md, "Found"); the audit trail still holds every event, so only the console line is lost. | **Fixed:** `init` never waits on `trust`: an event or update offer `trust` does not take at once is queued (at most 32) and offered again every 10 ms from `init`'s loop, in order, and dropped only after `EVENT_US` (2.5 s), longer than any one wait of `trust`, whose waits are now shared constants in `pharos_proto::trust` (host test `init_outlasts_every_wait_of_trust`). The old `trust` takes what is queued before `restart trust` stops it. The `recovery` round `next-safe` now requires `system ready: 7 services` on the trusted console (safe mode starts nothing after `trust`, so `init` reports ready while `trust` waits on its first call); without the queue it fails. A first attempt, `init` waiting 2.5 s on `trust`, deadlocked `manage`: `trust` waits on `init` too. |
| F2 | Low | **The trusted reserve does not cover every path.** `fs_mount` copies (only `init` mounts) and `dma_alloc` (drivers) do not check it, and `spawn` counts a program's file pages, not its zero-filled ones, so a large `.bss` can dip into the reserve by up to that size. Only reviewed programs are started (the root image is signed, D-028), and no AI service mounts or holds a device. | **Fixed:** `dma_alloc` checks the reserve (the caller's class), and the ELF loader counts every page the program's segments span, zero-filled ones included, for the child's class, in place of the file's size. `fs_mount` needs none: only `init` holds `MOUNT`, and it is trusted. Covered by `may_take`'s host test; no QEMU test drives a driver or a large `.bss` into the reserve. |
| F3 | Info | **A compromised runtime can replace `trust`'s revocation channel:** `CHANNEL` from the runtime's badge with any capability that is not a process becomes the channel. Revocations reach only the runtime's own agents, which it already controls; `stop all` stops the runtime through the process capability `init` gave `trust`, and its agents end with it. | **Accepted:** the runtime is the only sender on that badge, and the channel reaches only what it already controls; there is nothing for a check to protect. |
| F4 | Info | **A runaway service starves its peers.** The reserve keeps `trust` and `init` working; `store`, `audit`, and `knowledge` share the rest with `infer` (D-022 amended, threat model). The user recovers with `stop service infer` (`aifail`). | Accepted (the maintainer's choice, #182). |
| F5 | Low (carried) | **A real model has still not driven an agent on Pharos.** Carried from M3.6 to M4.6 (threat model): the scenario model's tool calls are tested on the host (`tools::tests::the_scenario_models_own_calls`), and agents run inference on Pharos with the test model, but the S1 model (676 MB, a 2 GiB guest) is not in CI and M4.6 did not run it. | **Carried** to Phase 5 (M5.1, QEMU regression and release testing), where the S1 scenario is run end to end: it needs the model file (not in the repository) and a 2 GiB guest, so it cannot run in CI as it is. |

## Who can reach what

- **`infer`** holds its console, its endpoint (`RECEIVE`), its report endpoint, and `models` read-only. A compromised `infer` can lie to its clients (the runtime treats model output as untrusted, D-023) and stop answering (the runtime starts and runs without it, #182). It cannot write the store, reach another namespace, manage a service, or reach a device or another process: 83 attempts in `compromised`, all refused.
- **The runtime** is its agents' reference monitor, so a compromised runtime controls every agent and uses what it holds: inference, its `agents` namespace, audit records stamped as client 3, and approval prompts that only the user answers. It cannot reach another service's data, manage a service, or stop `trust`: 86 attempts, all refused. The only capability it may pass on is its own endpoint (M4.2 F2).
- **Kernel memory:** every system call given a kernel address is refused (`compromised`, `syscalls`); a direct access kills the process (`user_mode`). Side channels are open until M5.2 (no KPTI, `rdtsc`; D-031).
- **Failure:** the trusted console keeps working while `infer` hangs, runs away with memory, or the runtime crashes until given up, and `start` brings both back (`aifail`).

## Acceptance criteria

| Criterion | Shown by (in CI) |
| --- | --- |
| AI services run unprivileged | Both in ring 3 under `init`, with the boot table's manifests checked live by the `system` capability audit (#158) and, as hostile stand-ins, by `compromised` |
| Adversarial tests show they cannot access kernel memory or resources outside their capabilities | `compromised`: 83 and 86 attempts refused, the audit matching, nothing started or stopped; mutation-checked (the store's read-only bit). `user_mode` for direct access |
| The system remains usable if AI services fail | `aifail`: a hung `infer` (runtime still ready), the runtime crashed until given up (`services`, `stop all`), a runaway `infer` (the reserve; `trust` restarts), and recovery from the trusted console; mutation-checked three ways |

## Phase 4: the threat model

Phase 4's gate asks for a full threat-model review. Each M4.x review covered what that milestone added: M4.1 ([services](review-m4.1-services.md)), M4.2 ([privileges](review-m4.2-privileges.md)), M4.3 ([recovery](review-m4.3-recovery.md)), M4.4 ([management](review-m4.4-management.md)), M4.5 ([configuration](review-m4.5-configuration.md)), and this one. Read against the threat model as a whole:

- **Every Part 1 threat has a mitigation that is implemented and tested,** or is listed as a limit. The rows added in Phase 4 (services, privileges, boot and recovery, management, configuration, AI services) each name the test kernels that show them.
- **Limits carried to a milestone that has closed,** each given a new place:
  - one CPU (carried to "Phase 4"): to Phase 5, with SMP needing a decision record and a re-review of locking, TLB flushes, and MSI-X routing; Phase 4 ran on one CPU throughout;
  - shared-memory bookkeeping on the fixed kernel heap (carried to M3.5, partly resolved): the whole 4 MiB heap at 2 GiB of memory; to Phase 5, before guests larger than 2 GiB;
  - control clients reading every task (carried to M3.6): accepted, as only test tables grant the badge;
  - the model driving an agent on Pharos (carried to M4.6): to M5.1 (F5).
- **Rows marked resolved** stay as a record of when and how.
- **Unchanged:** the no-IOMMU, KPTI, `rdtsc`, and audit-anchor limits stay required before real-hardware use (M5.2, M5.5).

## IPC round trip

`cargo xtask bench-ipc`, 2026-11-09: median 1,888 ns (min 1,793, max 1,977) over five runs of 100,000 round trips under KVM, within D-004's 2,000 ns budget (M4.5: 1,894 ns). M4.6 adds a check of the free-frame count to `mem_map` and `spawn`, not to the system-call path of IPC.

## Checks run

- `scripts/check.sh`: passed (the Rust 1.85 step skipped: that toolchain is not installed here).
- `cargo xtask test`: 75 test kernels passed, among them `aifail` and `compromised`.
- CI on `main`: run 42655103116 passed at `863449e` (#183); run 42665044098 at `ccf7d34` (#184) was running when this was written.
- Mutations, each failing its test: the blocking attach (`aifail`), no reserve (`aifail`), no restart reset on `start` (`aifail`), the store's read-only bit ignored (`compromised`).

## `unsafe` added in M4.6

None. `pharos_user::probe` calls the existing system-call wrapper with kernel-half addresses only and needs none.

## Accepted limits (tracked)

- **A runaway service starves its peers** until the user stops it (F4, D-022 amended).
- **A compromised runtime controls its agents and its own revocation channel** (F3; the runtime is their reference monitor, D-012).
- **No direct-access probe as a service:** capabilities do not change the kernel half's mapping, and `user_mode` covers every ring-3 process.
