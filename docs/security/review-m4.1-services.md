# Security review: M4.1 service manager

- **Scope:** everything M4.1 added to `init`, `trust`, `pharos-proto`, `pharos-programs`, the kernel's tests, and `xtask` since commit `f230d70` (the M3.8 gate):
  - D-026 and the design, [services.md](../architecture/services.md#supervision-and-readiness-m41-d-026) (#148, #149);
  - restart policies and growing delays: `pharos_programs::supervise`, `init`'s `Restarting` state (#150);
  - the ready state: the audit action `service` (19) and `trust`'s `SERVICE` (op 10) from `init` (#151);
  - failure reporting and `services`: `init`'s single event path, the audit queue, `pharos_proto::service` (`SERVICES` and its reply), and the `services` command (#152);
  - the `supervision` and `system` test kernels and their runner checks (#150–#153), and every new `unsafe` block.
- **Design under review:** [services.md](../architecture/services.md), D-026, D-018, D-019, D-022, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-06, issue #154. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. One finding is fixed, three are recorded.
- **Status:** awaiting the maintainer's approval.

## Method

1. Listed every changed file since `f230d70` and searched the diff for new `unsafe` blocks: none. The kernel changed only in its tests.
2. Followed each event (`exited`, `killed`, no `ready`, skipped, not started, restarting, given up, never, stopped, ready, not ready) from the kernel's process status to the debug console, the audit record, and `trust`'s line, checking where each byte of text comes from.
3. Followed `services` from the typed line to `init` and back: who may ask, what `init` answers, what `trust` trusts in the reply, and how long each side can wait.
4. Followed an audit record through every way its write can end: taken, refused, timed out, the audit service or the store down or restarting.
5. Turned each finding into a check that fails without the fix.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | A restart record could name part of a service. A restart's audit detail lists its dependents and was cut at 64 bytes wherever that fell, so `used by audit, trust, infer, client, holder` could end in `cli` or `tr`: a record naming a service that does not exist. | **Fixed:** `pharos_programs::supervise::cut_list` cuts after the last whole name that fits and adds ` ...`; `init` uses it for every record's detail. The host test `lists_are_cut_after_a_whole_name` fails with a plain cut. The debug line and `trust`'s line (names sent as a list, at most 8) were never cut. |
| F2 | Low | A record can be in the trail twice. `init` sends a record again when the audit service does not confirm it within 1 s; the store may have written it just before it was killed (seen in the `supervision` kernel: `store killed 13` twice). A reader cannot tell the copy from a second event. | **Recorded:** deliberate, at least once (#152): before the queue, the same window lost every record. The copy has the same detail and a later time. A number per record from `init` would let a reader drop it. The `supervision` runner leaves the store's own records out of its exact counts. |
| F3 | Low | A record can be dropped without a trace in the trail. `init` keeps at most 32 records the audit service has not taken and drops the oldest when full. | **Recorded:** the queue fills only while the audit service is down for long: restart policies bound each service's events (a boot daemon about 8: four ends, three restarts, a give-up), and each event is still on the debug console and `trust`'s console. A count of dropped records in the next record would show the gap. |
| F4 | Low | `services` can hold the trusted console for up to 1 s per page. `trust` waits for `init`'s answer in a `call`, and `init` may be in a 1 s wait on the audit service; a `stop all` typed meanwhile runs after it. | **Recorded:** the same bound as `audit` and `verify` (1 s each). The boot table fits one page. `init` answers with a non-blocking send and never waits on `trust` longer than 100 ms, so the two never wait on each other. |

## Who may say what

- **Text only from `init`'s table and numbers:** every event line is built from the service's table name (`valid_name`, checked by `encode` and `parse`), fixed words, and numbers from the kernel's process status. A service chooses only its exit code. Nothing it writes reaches `trust` or the trail.
- **`SERVICE` only from `init`:** `trust` acts on it only with badge `INIT` (0), which no other process holds.
- **`SERVICES` only from `trust`:** `init` answers only the badge of its `bin/trust` entry. Badges are set by `init` and cannot be changed by their holders, so no other service learns the table's state. A daemon's message is still its `ready`, as before.
- **The reply is untrusted input to `trust`:** `Reply::parse` checks every entry's name and state and the exact length. A page with no entries ends the loop, and the index only grows, so a wrong `total` cannot keep `trust` asking.

## Supervision

- **A stopped service is never restarted,** whatever its policy (`supervision`: `steady`; `system`: `net`). It is shown as `stopped`, apart from `failed`.
- **Restarts are bounded and spaced:** at most the policy's limit, each after 100 ms × 4ⁿ (`supervision`: `flaky`'s delays measured; `system`: `infer` given up after 3). A crash loop costs at most one start per delay.
- **Dependents keep running and are named.** They reach the new instance on the same endpoint (`system`: `trust` and the runtime alive after the knowledge service's restart).
- **`init` never waits on `trust` longer than 100 ms per event,** and on the audit service no longer than 1 s per try, with the retry wait doubling to 60 s while it does not answer.

## Kernel

No kernel change outside `kernel/tests/`. `process::kill`, used by the `supervision` and `system` kernels, is the existing test-only fault injection (#100); nothing in user space reaches it.

## Measured

The IPC round trip: 1,856 ns median (1,820–1,971 ns over 5 runs of 100,000, KVM), within D-004's 2 µs budget (M3.8: 1,887 ns).
