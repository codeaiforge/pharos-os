# Coordination: channels, groups, delegation, and verification

## 1. Status

**Planned. Design approved by the maintainer on 2026-11-05 (#132),** with messages kept in memory (8 per receiver, `BUSY` when full), one verifier check (`text <max bytes>`, with every subtask done and verified), `stop group` done by `trust` alone, and no delegation by workers. **Implemented:** channels (#133). To be built by: groups and subtasks (#134), delegation (#135), failure and stop handling (#136), the verifier (#137), and the isolation and confused-deputy tests (#138).

## 2. Context

M3.6 gives agents validated tool calls within their grants ([tools.md](tools.md)). M3.7 lets agents talk and work together without giving any of them more authority. D-024 (#131) decides it:

- channels go through the runtime, granted by policy, and carry data only (item 1);
- a group names a supervisor and its workers; the supervisor submits subtasks to them (item 2);
- a supervisor may pass a subset of its own grants to a subtask (item 3);
- a compiled-in verifier checks results before a goal counts as done (item 4);
- a failed worker is reported to its supervisor, and stopping a group ends everything it started (item 5).

What M3.7 builds on:
- **An agent holds one capability,** `SEND` on the runtime, badged with its slot; its buffer (up to 68 KiB) is shared with the runtime ([agents.md](agents.md)).
- **Permissions** are runtime grants per task attempt, from the policy entry and manifest or by approval, each with an optional deadline, revocable at once from the trusted console (`model`, `data`, `net`, `file`; [capabilities.md](capabilities.md)).
- **Tasks** are durable store files with up to 4 dependencies, retried within their attempts, recovered after a restart; only control clients submit them. At most 4 agents run at once (`MAX_RUNNING`).
- **Budget groups** (D-022): entries naming the same group share its totals (`agents`, `pages`, tokens and network bytes per minute) ([resources.md](resources.md)).
- **The trusted path:** `trust` holds `STOP` on every agent it registered, by slot and name; a task whose agent it stops becomes cancelled.

## 3. Design

### Channels (#133)

- **A new permission, `channel <agent>`:** sending messages to one named agent. Wire kind 6, a length and the name (as `file`, at most 32 bytes, agent-name rules). Given at the attempt's start from the policy entry's new `channels` list (the manifest key `channels` may ask for fewer); not askable in M3.7. Revoked like any other: `revoke <agent> channel <to>`.
- **Two new requests:**
  - `MESSAGE_SEND` (24): the receiver's name, a kind byte (the agents' own, never read by the runtime), and up to 1 KiB from the sender's buffer. Needs `channel <receiver>`; else `NO_ACCESS`.
  - `MESSAGE_RECEIVE` (25): the oldest message waiting for the caller into its buffer, with the sender's name, kind, and length; `NOT_FOUND` at once if none (the agent polls, as with `RECEIVE_FROM`).
- **Queues:** the runtime keeps at most 8 messages per receiving agent name, in memory, whether or not it runs; a send to a full queue is `BUSY` (nothing is dropped). They are lost when the runtime restarts (accepted: messages are not durable state; a task's durable state is its checkpoint).
- **A message is data:** the runtime copies its bytes out of the sender's buffer before use and never interprets them; the receiver treats them as untrusted input, as it treats a file or model output. No request carries a permission in a message.
- **Logged:** every message is audited as a consequential action, new action `message` (16): an `INTENT` naming the sender, `channel <receiver>`, and the kind and length (never the content), stored before the message is queued (else `NO_AUDIT`), then its `OUTCOME`.
- **Budgeted:** a new per-attempt budget field, `messages`, and every message counts against `rate`.
- *Implemented (#133):* `Permission::Channel` (wire kind 6, `channel <agent>` typed), the policy entry's `channels` and the optional manifest key `channels` (at most 4 agent names, each in the entry's), `MESSAGE_SEND` (24) and `MESSAGE_RECEIVE` (25) with the `Message` reply (`pharos_proto::agents`, `MAX_MESSAGE` 1 KiB), `pharos_programs::mailbox` (8 waiting per receiving agent name), the budget field `messages` (`OVER_LIMIT`, recorded as `over messages`), and the audit action `message` (16): `Intent message <sender> … channel <receiver> agents … kind <k> len <n>`, then its outcome. The service named in the record is `agents`. A full queue answers `BUSY` before anything is charged or recorded. `MESSAGE_RECEIVE` needs a buffer of at least 1 KiB (`NO_BUFFER`). A receiver gets messages by its agent name, so every running attempt of that agent shares its queue.

### Groups and subtasks (#134)

- **A group in the policy table** (the D-022 group, extended): its budget totals as before, plus a `supervisor` (an agent name, empty for a budget-only group), `workers` (agent names), and a `verifier` (below). Every member's entry must name the group; the runtime refuses a group whose members do not, at start.
- **A goal is the supervisor's task,** submitted by a control client as today.
- **New request `SUBTASK` (26)** from a supervisor: a worker name, the input (up to 4 KiB from its buffer), and up to 4 permissions to delegate (below). The runtime checks the caller is its group's supervisor, the worker is one of its workers, and its own task runs; it stores a new task for the worker with the supervisor's task as its **parent** (a new field in the task record) and returns its ID. At most 8 open subtasks per goal; more are `BUSY`.
- **New request `SUBTASK_STATUS` (27):** a subtask's state, attempts, and result (into the buffer), only for the caller's own subtasks; `NO_SESSION` otherwise.
- **Joining grants nothing:** a worker's subtask runs with its own entry's grants and what is delegated to it; being in a group adds no permission, and a worker cannot submit subtasks or reach its supervisor's task.
- **The group budget** covers every member's attempts (D-022): a subtask that would exceed the group's `agents` or `pages` waits to start, as attempts do.

### Delegation (#135)

- **A supervisor delegates only what it holds:** each permission named in `SUBTASK` must be allowed by the supervisor's grants at that moment; one it does not hold is refused (`NO_ACCESS`), and nothing is submitted.
- **Recorded and durable:** delegated permissions are stored in the subtask's record and recorded as `grant` events with the detail `from <supervisor> task <id>` when each attempt starts. A delegated grant never outlives the supervisor's: it takes the supervisor's deadline, if any.
- **Revoked with its source:** revoking a supervisor's permission (from the trusted console, or by expiry) revokes it from every subtask it delegated it to, at once, and recorded.
- **Ends with the subtask:** a delegated grant exists only in that subtask's attempts.
- **Not passed on:** a worker cannot delegate (it cannot submit subtasks).

### Failure and stop (#136)

- **A failed, crashed, or hung worker** is retried within its entry's attempts (M3.3); then its subtask fails, and the supervisor sees it with `SUBTASK_STATUS` and decides.
- **A goal that ends** (done, failed, or cancelled) cancels its open subtasks, stopping their agents: no work outlives its goal.
- **`stop group <name>`** on the trusted console stops every agent `trust` registered in that group, without the runtime: `REGISTER` gains the agent's group name. The runtime marks each stopped task cancelled (as today), and the supervisor's end cancels any subtask not yet started.

### The verifier (#137)

- **A compiled-in check, named by the group:** `text <max bytes>` (the result is UTF-8 of at most that many bytes, with no control characters but newline and tab, and every subtask of the goal is done and passed the same check). The table of checks is reviewed code; a group with no verifier cannot have a supervisor.
- **Applied at `COMPLETE`:** a supervisor's or worker's `COMPLETE` is checked first; one that fails ends its task failed with `not verified` instead of done, so a refused result never counts. Each decision is recorded, new action `verify` (17), with the outcome.
- **Not an agent:** no model or agent text decides; the check reads the result only as bytes.

## 4. Security

- **No path for authority between agents** but delegation: messages carry data only, a group adds nothing, and a delegated permission is one the supervisor holds, recorded, bounded by its source's deadline, and revoked with it.
- **The confused deputy:** a supervisor acts for a worker only by starting a subtask with the supervisor's own authority, which it chose to pass; a worker cannot ask the runtime to act with the supervisor's grants, and a message cannot name a permission the runtime would use.
- **Messages are untrusted input** to their receiver, like files and model output: injected instructions in a message reach the receiver's model as text, and anything it then does goes through its own grants.
- **The runtime stays the only place agents meet,** so every message, subtask, and delegation is checked, budgeted, audited, and stoppable; `trust` stops a group without it.
- **Carried:** messages are lost on a runtime restart; a supervisor's plan is untrusted and can waste its group's budget on subtasks, within the budget.

## 5. Testing

| Where | What |
| --- | --- |
| Host, `pharos_proto` (#133, #134) | `channel` permissions, `MESSAGE_SEND`, `MESSAGE_RECEIVE`, `SUBTASK`, `SUBTASK_STATUS`, and the new `REGISTER` round-trip, truncated and trailing bytes refused, fuzzed |
| Host, `pharos_programs` | queues (limits, order, a full queue), group membership checks, delegation (a subset only, deadlines, revocation with the source), the parent field in task records and recovery, verifier checks |
| Pharos, `channels` kernel (#133) | two agents with a channel exchange messages; a third without one is refused; a revoked channel stops at once; a full queue is `BUSY`; every message audited, no content in the trail; mutation-checked |
| Pharos, `groups` kernel (#134–#137) | a supervisor and two workers complete a goal within the group budget; a delegated file is read by a worker and a wider delegation refused; revoking the supervisor's grant revokes the worker's; a crashing worker is retried, then reported failed; a bad result is not verified and the goal fails; `stop group` leaves nothing running; mutation-checked |
| Pharos, `deputy` kernel (#138) | agents without a channel try to reach each other; a worker tries to use its supervisor's grants, submit subtasks, read another goal's subtasks, and pass on a delegation; messages with injected instructions and a flood of messages; each refused and recorded once |

## 6. Alternatives

- **Messages that carry a grant,** or **kernel endpoints between agents:** rejected in D-024 item 1.
- **Durable message queues in the store:** survive a runtime restart, but each message would be a store commit; a task's checkpoint is its durable state.
- **Fixed pipelines in policy:** rejected in D-024 item 2.
- **The user verifying results** or **a verifier service:** rejected in D-024 item 4.
- **Workers delegating further:** longer chains to record and revoke, for no current need.

## 7. Open questions

- None yet; the review (#139) may add some.
