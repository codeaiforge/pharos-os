# Security review: M3.3 agent lifecycle

- **Scope:** everything M3.3 added at the boundaries between agents, the agent runtime, the trusted service, `init`, the storage and inference services, and the kernel (since commit `fce1508`, the M3.2 gate):
  - the `STOP` right and system call 25 `process_stop`, children stopped with their parent, and the test-only `process::kill` (#95, #100);
  - the trusted service `bin/trust`, its virtio-console driver, and interface `trust` (#96);
  - agent manifests, `pharos_proto::manifest` (#97);
  - the agent runtime `bin/agents` and interface `agents` version 1 (#98);
  - durable tasks, `pharos_programs::tasks`, in the store's `agents` namespace (#99);
  - supervision in `init`, and `RELEASE` in the storage and inference services (#100);
  - every new `unsafe` block.
- **Design under review:** [agents.md](../architecture/agents.md), D-018, D-019, [services.md](../architecture/services.md).
- **Date:** 2026-11-02, issue #101. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. The finding was fixed in the same issue.
- **Status:** **approved** by the maintainer on 2026-11-03 (M3.3 gate, #101).

## Method

1. Listed every changed file under `kernel/`, `user/`, `crates/`, and `xtask/` since `fce1508`, and searched the diff for new `unsafe` blocks.
2. Followed every value an agent or control client sends (each request field, the badge, the attached buffer and its length, the capability on each message) from `receive` to its last use in `bin/agents`, and every registration from `receive` in `bin/trust`.
3. Followed each stop path: `process_stop`, a parent ending, the trusted console's `stop <agent>` and `stop all`, and `init` seeing a stopped daemon.
4. Checked what a process can still do after another tried to stop it: blocked, sleeping, queued as a sender, or spinning in user mode.
5. Checked task IDs and process IDs are never reused, and what the runtime and the services do with requests sent before a service restarted.
6. Turned the finding into a check that fails without the fix.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | The emergency stop by name missed processes. The runtime registers every running task with `trust` under its agent's name, so two tasks of one agent are two entries with the same name. `stop <agent>` stopped only the first, and said `stopped <agent>`, while the second kept running. `stop all` was not affected. | **Fixed:** `stop <agent>` stops every process registered under the name. `trust` test: the stand-in runtime registers two `worker` agents, and after `stop worker` the trusted console must list both stopped while the runtime still runs, or the runner never types `stop all`. Mutation-checked (stopping only the first: the run never finishes and the time limit fails it). |

## The stop call and the trusted path

- **`process_stop` needs `STOP`** on a process capability. `spawn` returns `WAIT`, `GRANT`, and `STOP` to the parent only; agents get no process capability. The `process_stop` test kernel checks a process without `STOP` is refused.
- **A stopped process cannot keep running.** It is marked, and a blocked or sleeping wait ends at once as timed out; it ends at its next return to user mode, from a system call or a timer interrupt, so a spinning process ends within one tick. A stopped sender takes its message back from the endpoint's queue, so no service later answers a process that has ended.
- **No stale capability stops a new process.** Task IDs only count up (`sched::spawn`), and a process capability names its record, so a capability kept after its process ended stops nothing.
- **No work outlives its starter.** When a process ends for any reason, every process it started is stopped, and in turn their children. Agents cannot spawn (they hold no file capability), so `stop all` (the runtime, then every registered agent) leaves nothing running.
- **`trust`** holds the virtio-console device, its endpoint, and a report capability; no console, storage, network, or inference capability (checked by the `trust` test kernel). Registrations are kept only for a valid request under the badge allowed to send it (`init`'s for `RUNTIME`, the runtime's for `REGISTER`), with a process capability; anything else has its capability deleted. Names are 1 to 32 letters, digits, `-`, or `_`, so a registered name cannot write control sequences to the trusted console. Typed lines are bounded at 64 bytes with control bytes dropped. The driver checks every used-ring ID and length the device reports, and stops serving if the device breaks the queue rules.
- **`init` never restarts a stopped daemon**, so `stop all` is not undone by supervision (`supervision` test: `steady`).
- **`process::kill`** (#100) is a kernel function for test kernels; no system call reaches it.

## The agent runtime

- **Requests** are parsed by `pharos_proto::agents::parse`: version first, exact lengths, no trailing bytes, text without control characters, names checked; host-tested and fuzzed with 100,000 messages. Badges 1 to 16 are agent slots, 0x100 and above control clients, anything else `NO_ACCESS`; agents get `NO_ACCESS` for control requests and control clients for agent requests (`agents` test).
- **Capabilities on messages:** an `ATTACH` capability is mapped (at most 68 KiB) and deleted; a `call`'s reply capability is answered without blocking and deleted.
- **Buffers:** every length (task input, checkpoint at offset 4,096, result, prompt) is checked against the sender's own buffer and the interface's limit before any copy, and the bytes are copied out before they are stored or forwarded, so an agent changing its buffer meanwhile changes nothing already checked.
- **Inference:** a model must be in the agent's accepted manifest (`NO_ACCESS` otherwise, tested); one session at a time across agents (`BUSY`); `NEXT` and `CANCEL_INFER` act only on the calling slot's session.
- **Manifests** only ask: each is checked against its compiled-in policy entry, and anything over it is refused, never narrowed (#97: fuzzed, mutation-checked).
- **Slots:** a slot is reused only after its process has ended (`process_status` not running), so a new agent never gets a badge a live process holds. Each agent's `STOP` is with `trust` before the runtime answers it.
- **Task state:** every change is written before it is answered; a write the store refuses leaves the state as it was. A task whose retry the store refused is retried at least once a second and restarts only once the store records it (`agents_store` test kernel, mutation-checked).

## Supervision and `RELEASE`

- **Only `init` can release.** `RELEASE` is accepted only with no badge, and `init` is the only process with an unbadged capability on either service (`supervision` test: a client's `RELEASE` is refused by both).
- **Requests to a dead service are not replayed.** A sender whose wait times out takes its message back from the endpoint, so a restarted service never acts on a request its caller already counted as failed.
- **Restarts are bounded** (3), and a daemon that sends no `ready` within 10 s is stopped.

## IPC round trip

`cargo xtask bench-ipc` under KVM, 5 runs of 100,000 round trips: median 1,989 ns (1,957 to 2,008), within D-004's 2,000 ns budget. M3.2 measured 1,938 ns. The margin is now 11 ns; which M3.3 change added the 51 ns was not measured. The stop check on every return from a system call (a scheduler lock and a set lookup) is the first candidate.

## `unsafe` added in M3.3

None. `pharos-proto` forbids it; the runtime, `trust`, its driver, and the task logic use only `pharos-user`'s safe interface.

## Accepted limits (tracked)

- **A store outage uses up attempts.** The runtime serves one request at a time, and a call to a storage service that has died waits its full 10 s. Meanwhile no agent is answered, so an agent's 5 s progress limit can pass and its attempt count as hung (seen in the `agents_store` test). Carried to M3.5 with per-agent budgets.
- **No rate limit on agent requests.** An agent can send `LOG` or other requests as fast as the runtime answers them, bounded only by its task's time limit; the kernel keeps only the newest debug lines. Carried to M3.5.
- **`RELEASE` assumes one service per badge.** A storage or inference badge given to two services would let one's end free the other's buffer. Every `init` table gives each badge to one service; nothing enforces it. The reviewed tables are the only source of grants in M3.3 (D-018).
- **`trust` trusts the runtime's registrations.** A compromised runtime can register its agents under wrong names, or not at all; `stop all` still ends it and every process it started.
- **Stopping is the only revocation.** Capabilities are not taken back from a running agent; it ends. Carried to M3.4 (revocable permissions).
- **Control clients see every task.** Any holder of a control badge can read, cancel, or forget any task. Only `init` grants one, and in M3.3 only test tables do. Carried to M3.6 (who submits tasks).
