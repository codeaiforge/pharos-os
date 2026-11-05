# Security review: M3.7 agent communication and coordination

- **Scope:** everything M3.7 added to `pharos-proto`, the agent runtime, `trust`, and the task store since commit `64e85ee` (the M3.6 gate):
  - D-024 and the design, [coordination.md](../architecture/coordination.md) (#131, #132);
  - channels: `channel <agent>`, `MESSAGE_SEND`, `MESSAGE_RECEIVE`, the mailboxes, and the `messages` budget (#133);
  - groups and subtasks: `Group`'s supervisor, workers, and verifier, `SUBTASK`, `SUBTASK_STATUS`, and task records format 2 (#134);
  - delegation: `groups::delegable` and `given`, and revocation with the source (#135);
  - failure and stop: `Tasks::orphans`, `REGISTER` with the group, and `stop group` (#136);
  - the verifier: `groups::verify` and the audit action `verify` (#137);
  - the `channels`, `groups`, and `deputy` test kernels (#133–#138), and every new `unsafe` block.
- **Design under review:** [coordination.md](../architecture/coordination.md), D-024, D-012, D-018, D-022, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-05, issue #139. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. Two findings are fixed, one is recorded.
- **Status:** **approved** by the maintainer on 2026-11-05 (M3.7 gate, #139), with F3 recorded.

## Method

1. Listed every changed file since `64e85ee` and searched the diff for new `unsafe` blocks: none.
2. Followed each new request (`MESSAGE_SEND`, `MESSAGE_RECEIVE`, `SUBTASK`, `SUBTASK_STATUS`, `COMPLETE` in a group) from the agent's buffer to the store or a mailbox, checking what is copied, checked, charged, recorded, and returned.
3. For each permission kind, asked what a delegated copy lets a worker reach, and whether that is something its supervisor holds.
4. Followed a delegated grant through every way its source can end: revocation from the console, expiry, the supervisor's attempt ending, a retry, and the goal ending.
5. Counted what an untrusted supervisor can create that outlives its attempt (tasks, messages, store files), and what bounds each.
6. Turned each finding into a check that fails without the fix.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | A supervisor could fill the task table. `SUBTASK` limited a goal to 8 *open* subtasks, but every subtask is a durable task, and ended ones stay until a control client's `FORGET`. A supervisor giving quick subtasks 8 at a time reached `MAX_TASKS` (256), after which no one, a control client included, could submit a task. | **Fixed:** at most 32 subtasks per goal in all (`MAX_GOAL_SUBTASKS`, `Tasks::children`); the 33rd is `OVER_LIMIT`, recorded once as `over subtasks`. Goals are submitted only by control clients, so an agent's share of the table is bounded by what they submit. The `deputy` kernel's third goal gives subtasks until refused and must get exactly 32; without the fix it runs past the 60 s limit. |
| F2 | Low | `data read` and `data write` could be delegated. They name the holder's own files (`data/<agent>/`), so a worker given one by its supervisor got access to *its own* data files, which its policy entry may not grant: not the supervisor's authority, but new authority (and store space) no one granted. | **Fixed:** `groups::delegable` refuses both, held or not, and nothing is submitted (`no grant`). The host test `only_what_the_supervisor_holds_and_no_longer` delegates each and fails without the fix. Delegable kinds are those naming one absolute thing: `model`, `net`, `file`, `channel`. |
| F3 | Low | A revocation does not reach a subtask whose supervisor is not running. `revoke <agent> <permission>` acts on that agent's running attempts, and the cascade (#135) starts from them. Between a supervisor's attempts (a retry, when its entry allows more than one), its running subtasks keep a delegated grant until their deadline or the goal's end. | **Recorded:** the user can `revoke <worker> <permission>` or `stop group`; the test table's supervisor has one attempt, so there is no such window. To be revisited if supervisors get retries. |

Not a security finding, recorded for the gate: CI run 42048789818 (on `0cebbab`) failed once in the `exhaustion` kernel, the trusted task waking 43.4 ms late against its 40 ms bound on the shared runner; the next runs passed, and locally the worst seen is 40.0 ms. The bound is kept.

## Channels

- **Data only, copied before use:** a message is copied out of the sender's buffer before it is queued; the runtime reads only its length and kind, and no request takes a permission from a message.
- **The sender is the runtime's word:** the receiver sees the sender's policy-entry name, never a name the sender wrote (the `deputy` kernel's injected message arrives from `aide`, unchanged, and gains it nothing).
- **Bounded:** 8 messages of at most 1 KiB per receiving name, and names are only those policy entries list as channel targets; a full queue is `BUSY` before anything is charged or recorded, and nothing is dropped.
- **No content in the trail or on the console:** checked by the `channels` and `deputy` runners.

## Groups, subtasks, and the confused deputy

- **Who may assign:** only a group's supervisor, only to its workers, and only in a coordinated group; an entry names one group, so a worker cannot also supervise, and no chain forms.
- **A subtask runs with its worker's authority:** its own entry's grants plus what is delegated; a worker cannot reach its supervisor's grants, task, or subtasks (`deputy`: 74 refused requests from the compromised `helper`, recorded as one record per kind and a total).
- **A supervisor acting for a worker uses only its own grants:** delegation checks the supervisor's grants at `SUBTASK` and again at each attempt's start, with the source's deadline.
- **No work outlives its goal:** the open subtasks of an ended goal are cancelled before any task starts; `stop group` works without the runtime.

## The verifier

- **Compiled-in and byte-level:** UTF-8, a length bound, no control characters but newline and tab, and every subtask done; no model or agent text decides, and a refused result is never retried.
- **Recorded before it counts:** a verify record that cannot be stored refuses the `COMPLETE` (`NO_AUDIT`), so no result is done without its decision in the trail.

## IPC round trip

`cargo xtask bench-ipc`, 2026-11-05: median 1,844 ns (min 1,797, max 1,930) over five runs of 100,000 round trips under KVM, within D-004's 2,000 ns budget.

## `unsafe` added in M3.7

None. The diff since `64e85ee` adds no `unsafe` block.

## Accepted limits (tracked)

- **Messages are lost when the runtime restarts** (the design's choice): a task's durable state is its checkpoint.
- **Revoking from a supervisor takes an overlapping permission from its subtasks even if the worker's own entry gives it,** for the rest of that task: never wider, sometimes narrower (#135).
- **A goal's subtasks keep running between its attempts;** only its end cancels them (#136; see F3).
- **A supervisor's plan is untrusted:** it can spend its group's budget and its goal's 32 subtasks on useless work, within those bounds.
