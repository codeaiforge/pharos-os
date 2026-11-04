# Security review: M3.4 permissions, sandboxing, and audit

- **Scope:** everything M3.4 added at the boundaries between agents, the agent runtime, `trust`, the audit service, the network service, `init`, and the kernel (since commit `0e50720`, the M3.3 gate):
  - kernel revocation of mapped memory and devices (#104);
  - runtime permissions, `pharos_programs::grants`, `pharos_proto::permission`, and `revoke` on the trusted console (#105);
  - approval on the trusted path, `ASK`, `APPROVE`, `ANSWER`, `RESOLVED` (#106);
  - the audit service `bin/audit`, `pharos_proto::audit`, namespace `audit`, and `cargo xtask store audit` (#107);
  - auditing every grant, revocation, and consequential action (#108);
  - agent networking: `SEND_TO`, `RECEIVE_FROM`, the manifest key `net`, and `ALLOW` and `POLL` in the network service (#109);
  - refusal records and the hostile agent (#110);
  - every new `unsafe` block.
- **Design under review:** [capabilities.md](../architecture/capabilities.md), D-012, D-017, D-018, [networking.md](../architecture/networking.md), [agents.md](../architecture/agents.md).
- **Date:** 2026-11-03, issue #111. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. Both findings were fixed in the same issue.
- **Status:** **approved** by the maintainer on 2026-11-04 (M3.4 gate, #111).

## Method

1. Listed every changed file under `kernel/`, `user/`, `crates/`, and `xtask/` since `0e50720`, and searched the diff for new `unsafe` blocks.
2. Followed every field of every new request (`ASK`, `ANSWER`, `REVOKE`, `DATA_PUT`, `DATA_GET`, `SEND_TO`, `RECEIVE_FROM`, `APPEND`, `HEAD`, `ALLOW`, `POLL`) from `receive` to its last use, with the badge it came under.
3. For each permission, followed where it is granted (attempt start, approval), checked (each request), and taken away (revocation, expiry, the attempt ending), and whether each step is recorded before or after it takes effect.
4. For each request that waits on another service, checked who can trigger the wait and how long the runtime, which serves one message at a time, is blocked.
5. Investigated the one CI failure of M3.4 (`trust` hung on `main` at `6798458`).
6. Turned each finding into a check that fails without the fix where one can be built.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | `RECEIVE_FROM` needed no grant. Any agent, granted no destination, could make the runtime poll the network service; with that service stopped or hung, each poll blocks the runtime for up to 1 s, during which no other agent is answered and their progress limits run down. | **Fixed:** `RECEIVE_FROM` answers `NO_ACCESS` unless the agent holds a `net` grant, and polls the service only for an agent that has sent somewhere. `hostile` test: `RECEIVE_FROM` without a grant must be `NO_ACCESS` (fails without the fix: `NOT_FOUND`). An agent with a grant can still stall the runtime as long as the network service takes to answer, as with inference and storage (accepted limit below). |
| F2 | Low | Lost wakeup in kernel-side IPC. `ipc::send`, `call`, and `receive` queue the running thread, then block it. A thread preempted between the two misses its waker's `wake` (which does nothing for a thread not blocked yet) and blocks forever. System calls are safe, since they run with interrupts off (SFMASK); kernel threads, which only the test kernels use, call them with interrupts on. This hung the `trust` test kernel once in CI (`main`, `6798458`, [run 41652628559](https://github.com/codeaiforge/pharos-os/actions/runs/41652628559)) after its console script had finished. | **Fixed:** the three functions turn interrupts off around the queue-then-block; system calls use the new `send_now`, `call_now`, and `receive_now`, which skip the flags read (it measurably cost the round trip, below). No test reproduces the race: its window is a few instructions wide against a 10 ms tick. The full suite passed twice locally, and CI on `main` at `cef4ece` ([run 41708829549](https://github.com/codeaiforge/pharos-os/actions/runs/41708829549)), with the fix. |

## Permissions, revocation, and approvals

- **No permission is a kernel capability.** An agent holds one `SEND` on the runtime, badged with its slot; the `hostile` kernel checks it and that every other handle and every other use of that one fails. A request's permission is looked up from the slot's grants (`Grants::allows`), never from the message.
- **Grants are rebuilt per attempt** from the manifest within the policy entry, plus approvals and minus revocations kept for the task; each grant is recorded before it is given, and none is given if its record fails (`permissions`: `keeper-d`).
- **Revocation takes effect before it is answered:** the next request needing it is refused, an inference session on the model is cancelled, and a reply from a revoked destination is dropped when the agent takes it (`agents_net`). Memory revocation (#104) turns every mapping through the revoked capability, and capabilities derived from it, into zeroed private pages before `revoke` returns, and stops a revoked device first; the `hostile` agent revokes its buffer under the runtime, which reads zeros and runs on.
- **Only `trust` approves.** `ANSWER` and `REVOKE` are served only under the `trust` badge, which only `trust` holds (the runtime sends it with `CHANNEL`); an agent's own `ANSWER` is refused and its request stays pending (`hostile`). The prompt is built by `trust` from structured fields, never agent text; an agent's `LOG` that copies a prompt reaches only the serial console (`hostile`: `approve #9` never appears on the trusted console).
- **Only listed permissions are askable,** at most 4 wait, each 60 s, and an answer for a number not waiting is refused (`permissions`, `hostile`).

## The audit trail

- **One writer,** `audit`, holding namespace 6; it stamps each record with the badge it came under (`audit` kernel). Records are binary, with names checked as agent names are, at most 172 bytes.
- **Write before acting:** inference, `DATA_PUT`, `SEND_TO`, `SUBMIT`, and `CANCEL` are refused with `NO_AUDIT` unless their intent is stored (`permissions`). Stops never depend on the trail.
- **Refusals are bounded** (#110): an agent's refused requests are recorded once per kind per attempt, plus the total when the attempt ends, so a flood (the `hostile` agent's 454 refused requests) costs at most five records and cannot fill the store and so block every agent with `NO_AUDIT`.
- **The anchor** is the chain head `trust` shows at start and on `audit`; `cargo xtask store audit` checks the chains, sequence numbers, and the boot record.

## Networking

- **Two checks.** The runtime checks each send against the agent's grants; the network service checks each client's destinations, which only `init` sets (`ALLOW` is accepted only without a badge, and `init` never grants badge 0). The runtime's list is the union of its policy table's destinations, so a bug in the runtime cannot reach anything nobody listed (`network`: a client's own `ALLOW` and unlisted destinations refused).
- **Replies** are kept only for agents that sent to the source and given only while the grant holds (`agents_net`: an agent with the same grant that sent nothing receives nothing).
- **Every send is recorded first** (`net send`, with the destination; not the payload).

## IPC round trip

`cargo xtask bench-ipc` under KVM, 5 runs of 100,000 round trips: median 1,963 ns (run medians 1,920 to 1,993), within D-004's 2,000 ns budget; M3.3 measured 1,989 ns. The host varied by about 50 ns between runs. With F2's first fix, which read the interrupt flag on every system-call send, call, and receive, alternating runs measured 13 to 78 ns slower than without it; system calls now skip it.

## `unsafe` added in M3.4

None. The kernel's revocation sweep (#104) uses the existing page-table and raw-memory interfaces; `pharos-proto` forbids `unsafe`; the runtime, `trust`, `audit`, the network service, and the test programs use only `pharos-user`'s safe interface.

## Accepted limits (tracked)

- **The runtime blocks on its services.** It serves one message at a time; a granted agent's inference (up to 60 s), store write (10 s), audit record (2 s), or network request (1 s) to a stalled service delays every other agent, whose progress limits keep running. Carried to M3.5 with per-agent budgets.
- **The approval queue is shared.** One agent can keep all 4 places for up to 60 s each, and others' requests are refused meanwhile. Carried to M3.5.
- **Agents granted the same destination share its replies** once both have sent to it: they share the runtime's port.
- **No rate limit on agent requests** (carried from M3.3, to M3.5). Refusal records are bounded; served requests are not.
- **No secret-keyed audit anchor** before signed updates and keys (M4.3); the user compares the head `trust` shows.
- **`trust` and the runtime are trusted to report** what happened; the badge on each record shows which did.
- **Control clients see every task** (carried from M3.3, to M3.6).
