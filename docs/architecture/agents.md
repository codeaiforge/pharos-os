# Agents: runtime, manifests, durable tasks, and the emergency stop

## 1. Status

**Implemented** (M3.3, gate passed 2026-11-03, #101). Design approved by the maintainer on 2026-11-01 (#94); built by the kernel stop call (#95), the trusted path (#96), the manifest parser (#97), the agent runtime (#98), durable tasks (#99), and supervision in `init` (#100). Permissions, approvals, and audit for agents are in [capabilities.md](capabilities.md) (M3.4); resource limits are in [resources.md](resources.md) (M3.5); tools in [tools.md](tools.md) (M3.6); channels, groups, and delegation, planned, in [coordination.md](coordination.md) (M3.7).

## 2. Context

M3.2 gave Pharos an inference service that clients reach through a badged capability. M3.3 runs **agents**: untrusted programs that do work for the user, can be started, stopped, supervised, and restarted, and whose work survives restarts.

What M3.3 builds on:
- **Authority comes only from capabilities (D-018).** Badges tell a server which client is calling, as granted by whoever handed out the capability. No process can stop another yet (#95).
- **D-018's choices:** the trusted path under QEMU is a virtio-console device owned by a small trusted service. A `STOP` right also stops every process its target spawned. The trusted service holds `STOP` on the agent runtime, and on each agent before that agent is granted anything. M3.3 grants only what a reviewed, compiled-in table allows.
- **Services and interfaces (D-019):** hand-written codecs in `pharos-proto`, a version and operation on every message, `ATTACH` for bulk data, timeouts on every operation, long results pulled with `NEXT`.
- **The writable store (D-017):** a write replaces a whole file in one crash-consistent commit, and clients see only their namespace.
- **IPC** carries 256 bytes and at most one capability per message. `spawn` gives a child up to 12 capabilities (8 until #144) and returns a process handle with `WAIT` and `GRANT`. A process's end can set a bit on an endpoint.

## 3. Design

### Processes and what each holds

`init` starts two new daemons after the storage and inference services: first `trust`, then `agents`. Both are unprivileged user processes.

| Process | Holds | Does not hold |
| --- | --- | --- |
| `trust` (trusted service) | the virtio-console device (PCI `1af4:1043`); its own endpoint; `init`'s report endpoint; `SEND` on the audit service, badged as client 2 (#107); `STOP` on `agents` (sent by `init`); `STOP` on each running agent (sent by `agents`); `SEND` on `agents`, badged as `trust` (sent by `agents`, #105) | storage, inference, network, the serial console |
| `agents` (the agent runtime) | the serial console; its own endpoint; `init`'s report endpoint; the read-only filesystem (agent programs and manifests); storage namespace `agents`, read-write; storage namespace `files`, read-only (handle 10, #127; not yet at boot, tools.md); `SEND` on inference; `SEND` on `trust` (badged); `STOP`, `WAIT`, and `GRANT` on each agent it starts | any device; `trust`'s console |
| an agent | **one capability for its whole life:** `SEND` on `agents`' endpoint, badged with its slot (and what it makes itself: a reply endpoint and a buffer, which reach no other process) | everything else |

- **An agent's only capability is its runtime endpoint.** Every service an agent uses (its task, checkpoints, inference, log lines) goes through the runtime. So the runtime can check, time out, and cancel every request, and stopping an agent cannot leave work running elsewhere. Agents cannot reach each other, the store, or the inference service.
- **Order of grants (D-018):** `agents` spawns the agent with only that capability, sends `STOP` on it to `trust`, and answers the agent's requests only after `trust` acknowledged. An agent the runtime never registered can do nothing, and stopping `agents` ends it too.
- **`init`** sends `trust` a `STOP`-only copy of `agents`' process handle right after starting it. `trust` never depends on `agents` to stop it.

### The kernel: stopping a process (#95)

- **New right `STOP`** on process capabilities. `spawn`'s process handle gets `WAIT | GRANT | STOP`; rights only narrow when the handle is granted.
- **New call 25, `process_stop(handle)`**, needs `STOP`. It ends the process as an exit would: threads leave every queue they wait in, memory and mappings are freed, capabilities are deleted. Its end is recorded as **stopped**, a new outcome that `process_status` returns.
- **Children go with their parent.** The kernel records each process's parent at `spawn`. Stopping a process stops every process it spawned, depth first. **A process's children are also stopped when it ends in any other way** (exit, fault), so no work outlives the process that supervised it. When the runtime crashes, its agents stop, and its next start recovers their tasks from the store.
- **Waiters get errors, not hangs.** A client in `call` to a stopped server gets its own timeout (`TIMED_OUT`); every Pharos client calls with one (D-019). The stopped process's own waits end as timed out, so it leaves every endpoint queue, and a blocked `send` takes its message back. *Implemented (#95).*
- **How it ends (#95):** the stop marks the process and wakes it if it waits. A marked process never waits again, and ends itself at its next return to user mode (after a system call or a timer tick). A process can therefore not run user code after `process_stop` returns and it is next scheduled. Each process that ends stops the processes it started, so a whole tree ends, one level per scheduling round.

### The trusted path (#96)

- `trust` drives the virtio-console device with the shared user-space virtio transport (`pharos_programs::virtio`), as the network service drives its device (D-015). No other process holds the device, so nothing else can read the user's commands or write what looks like `trust`'s answers.
- **Commands**, one per line, each answered on the same console:
  - `list`: the registered agents and whether each is running;
  - `stop <agent>`: `process_stop` on every process registered under that name (one agent may run several tasks at once, one process each);
  - `stop group <group>` (#136, [coordination.md](coordination.md#failure-and-stop-136)): `process_stop` on every process registered in that group, without the runtime: `REGISTER` carries each agent's policy-entry group. The runtime cancels each stopped task, and a goal's end cancels its subtasks not yet stopped, so nothing the group started keeps running; an approval request of a stopped task ends (`the task ended`). Recorded as a `stop` by the user with the detail `group <group>`;
  - `revoke <agent> <permission>` (#105): `model <n>`, `data read`, `data write`, or `net <a.b.c.d>:<port>`, taken from every running task of that agent; `trust` passes it to the runtime and shows the runtime's answer (`revoked …`, `… does not hold …`, `no agent … runs`) ([capabilities.md](capabilities.md));
  - `yes <n>`, `no <n>` (#106): the answer to approval request `<n>`, which `trust` showed as `approve #<n>: <agent> task <id> wants <permission> for this task? (yes <n> / no <n>)` (or `for <ms> ms`);
  - `usage` (#119, [resources.md](resources.md#usage-reporting-119)): `usage: runtime cpu <ms> ms, <pages> pages` from `trust`'s own capability on the runtime, then one line per running attempt and per group that the runtime sends as numbers (`USED`, `GROUP_USED`), which `trust` writes out: `usage: <agent> task <id>: cpu …, … pages, … tokens, … datagrams of … bytes, … requests` and `usage: group <name>: … running, … pages, … tokens and … bytes this minute`;
  - `services` (#152, [services.md](services.md#supervision-and-readiness-m41-d-026)): one line per service, its state, restarts done, and limit, as `init` answers on `trust`'s report capability; `trust` keeps no service state. `init` also sends each service event, which `trust` prints as `service <name> …` from fields only;
  - `stop all`: `process_stop` on `agents`, which ends every agent. This is the emergency stop and safe mode: `init` does not restart a service that was stopped (#100), so everything stays stopped until reboot.
- **"Revoke" in M3.3 is a stop.** An agent's one capability is deleted with its process, and in M3.3 kernel revocation did not unmap memory, so ending the process was the full revocation (M3.4 unmaps it, #104). Revoking one capability while the agent keeps running comes with M3.4.
- **`trust`'s interface** (`pharos_proto::trust`, version 1) has two operations, each carrying a process capability with `STOP` and `WAIT` (`WAIT` so `list` can show whether it runs): `RUNTIME`, accepted only under `init`'s badge (no badge: `init` created the endpoint and is the only holder of an unbadged `SEND` on it, since it gives every other sender a badged copy, which cannot be re-badged; a process cannot badge its own copy, because a send to itself would block), and `REGISTER` (agent slot and name), accepted only under the runtime's badge. Anything else is dropped and its capability deleted. It keeps at most 16 agents, replacing an agent's entry when its slot is reused. There is no reply: the sender's blocking `send` returns once `trust` has the message, and `trust` never refuses a valid one. Neither operation can make `trust` do anything but remember a process.
- *Implemented (#96):* `bin/trust` and `pharos_programs::virtio_console` (`VERSION_1` only, port 0, 16 receive buffers of 64 bytes and 16 transmit buffers of 256; every used element checked; output never waits, so a full console drops a line). Lines are at most 64 bytes; control bytes are dropped. Each stop waits up to 1 s and answers `stopped <name>` or `stopping <name>: still running`. `stop all` stops the runtime, then every registered agent. `trust` holds no serial console: on a setup failure it exits with a code, which `init` reports. `init` starts it after the inference service, then the runtime, and sends `trust` the runtime's `RUNTIME` registration right after starting it (#98); if that send fails, `init` stops the runtime.
- **The host side (QEMU):** `cargo xtask` gives every boot a `virtio-serial-pci` with one `virtconsole` on a pair of FIFOs next to the boot image, `trust.in` (typed) and `trust.out` (answers). `cargo xtask run` prints both paths: `cat` the one and `echo list >` the other.
- **Limit:** under OVMF, the firmware prints its boot messages to the virtio-console too, before Pharos starts; it could also read keys typed there then. The firmware is trusted anyway (boot chain, M4.3).

### Agent manifests (#97)

A manifest describes what an agent needs. It is a small text file in the read-only filesystem image (`agents/<name>.manifest`), at most 4 KiB, one `key = value` per line, `#` comments:

```text
manifest = 1
name = summarize
program = agents/summarize
pages = 2048
models = 1
attempts = 3
progress_ms = 30000
task_ms = 600000
data = read
net =
```

- `data` (#105): `none`, `read`, or `write` (which includes reading), the agent's own files kept by the runtime ([capabilities.md](capabilities.md)).
- `net` (#109): UDP destinations, `address:port`, comma-separated, at most 4, each only once, or empty for none; each must be in the policy entry's `net` ([capabilities.md](capabilities.md)).
- `tools` and `files` (#126, #127) and `channels` (#133), the only optional keys: tool names, granted file names, and agents it may send messages to, comma-separated, at most 4 files and 4 channels, each in the policy entry's ([tools.md](tools.md), [coordination.md](coordination.md)); absent or empty for none.
- `pages`: the agent's page limit. `models`: inference models it may use. `attempts`: tries per task, at most 10. `progress_ms`: how long it may go without a request while it has a task. `task_ms`: how long a task may run.
- **Manifests are untrusted input:** a `no_std` parser in `pharos-proto` with checked bounds. Unknown keys, repeated keys, missing keys, and values out of range are refused. Host tests and 100,000 fuzzed inputs.
- *Implemented (#97):* `pharos_proto::manifest`. Spaces around keys and values are ignored. `models` lists model numbers (1 to 31), comma-separated, or is empty for none. Limits: `pages` 1 to 262,144 (1 GiB), `attempts` 1 to 10, `progress_ms` 1 to one hour and at most `task_ms`, `task_ms` 1 to one day; numbers have no sign or leading zero. `program` is a relative path of at most 64 bytes with no empty, `.`, or `..` part. A refusal names its line. `Manifest::within` is the policy check: no entry for the name, another program, or anything over the entry is refused.
- **The policy table** in the runtime is reviewed code, like `init`'s service table: for each agent name, the program and the most it may get (pages, models, attempts, timeouts). **A manifest asking for more than its entry is refused, not narrowed**, so the agent never runs with settings nobody wrote down. An agent with no entry does not start.

### Lifecycle (#98)

```text
            spawn + trust REGISTER
 starting ───────────────────────────▶ running ──── COMPLETE / FAIL / exit 0 ──▶ stopped
    │                                     │
    │ spawn or REGISTER fails             ├── crash, or no request for progress_ms ──▶ restarting ──▶ starting
    ▼                                     │                                               │
  failed ◀──────────── attempts used up ──┴───────────────────────────────────────────────┘
                                          └── CANCEL, or trust's stop ──▶ stopped
```

- **One process per task attempt.** The runtime starts an agent when one of its tasks can run. The agent asks for its task, works, reports the result, and exits. A restart is a new process for the same task, with the attempt count increased and the last checkpoint handed back.
- **At most 4 agents run at once**, at most 16 slots in all (the notification bits on the runtime's endpoint tell it which agent ended).
- **Crash:** the end notification and `process_status` (exit code or fault vector). **Hang:** no request from the agent for `progress_ms` while it has a task, or the task over `task_ms`. The runtime then stops the agent (`process_stop`) and counts the attempt.
- **Events** are console lines from the runtime: `agents: <name> task <id> started`, `completed`, `crashed <vector>`, `hung`, `restarting <n>/<max>`, `failed`, `cancelled`, `stopped`. Agents' own `LOG` lines are written as `agents: <name>: <text>`.

- *Implemented (#98):* `bin/agents`, started by `init` after `trust` with a 64 MiB limit (handles: console, its endpoint with `RECEIVE`, `SEND`, and `GRANT`, the report endpoint, the root filesystem read-only, inference client 1, `trust` badged as the runtime, storage namespace `agents`, the audit service as client 3, #108, and the network service badged with port 40100, #109). The policy table is selected by its argument: empty at boot, three entries for the `agents` test kernel. At start it reads `agents/<name>.manifest` for each entry and prints `manifest accepted` or `manifest refused: <why>`; only accepted agents can be given tasks. A task attempt opens the entry's program, spawns it with the manifest's page limit, one capability (`SEND` on the runtime, badge slot + 1), and its end bound to notification bit *slot*, then sends `trust` `REGISTER` with `STOP` and `WAIT`; the runtime handles no request from that process until the send returned, since it serves one message at a time. An agent may make its own reply endpoint and buffer: they reach nothing. An attempt that ends without `COMPLETE` or `FAIL` (exit with any code, fault, or hang) counts against `attempts`; after the last, the task fails with `retries exhausted`. The runtime stops the agent after `COMPLETE` or `FAIL`. An agent that `trust` stopped ends its task as cancelled (`stopped`). Tasks are kept in the store (#99).

### The runtime's interface (`agents`, version 1)

Clients are told apart by badge: agent slots, and control clients that `init`'s table lists (tests in M3.3; a user shell later).

| Operation | From | Does | Timeout |
| --- | --- | --- | --- |
| `TASK` | agent | its task: ID, attempt, input and last checkpoint (copied into its attached buffer) | 1 s |
| `CHECKPOINT` | agent | stores up to 64 KiB from its buffer as the task's checkpoint; `OK` only after the store committed | 10 s |
| `BEGIN` | agent | starts a consequential operation with a 16-byte idempotency key: `GO`, `DONE` with the recorded result, or `UNKNOWN` | 10 s |
| `END` | agent | records the operation's result (up to 64 bytes) | 10 s |
| `COMPLETE`, `FAIL` | agent | ends the task with a result (up to 4 KiB) or a reason; in a coordinated group the result is first checked by the group's verifier, and one it refuses ends the task failed with `not verified: text` or `not verified: subtask` (#137, [coordination.md](coordination.md#the-verifier-137)) | 10 s |
| `INFER`, `NEXT`, `CANCEL_INFER` | agent | inference through the runtime: the prompt is copied from the agent's buffer into the runtime's own buffer at the inference service; models only from the agent's manifest | as `inference` |
| `LOG` | agent | one console line, at most 200 bytes, printable characters only | 1 s |
| `DATA_PUT`, `DATA_GET` | agent | writes or reads one of the agent's own files (a name as agent names are, up to 64 KiB, through its buffer), kept by the runtime at `data/<agent>/<name>` in its store namespace; needs `data write` or `data read` (#105) | 10 s |
| `ASK` | agent | asks the user, through `trust`, for a permission its policy entry lists as askable, for some milliseconds or the rest of the task: `GRANTED`, `REFUSED`, or `PENDING` (ask again); see [capabilities.md](capabilities.md) (#106) | 1 s |
| `SEND_TO` | agent | one UDP datagram of up to 248 bytes from its buffer to a destination it holds `net` for, through the runtime's port (#109) | 1 s |
| `RECEIVE_FROM` | agent | the oldest datagram kept for it (only from a destination it sent to and still holds), into its buffer, with its source; `NOT_FOUND` at once if none (#109) | 1 s |
| `TOOL` | agent | a tool call: its text in the agent's buffer (at most 1 KiB) is copied out, parsed, and checked against the agent's tools, grants, and budgets, then audited and run; `read_file` puts a granted file in the buffer, `send` sends a datagram once the user confirms that call (`PENDING` until then, `REFUSED` if not); see [tools.md](tools.md) (#126–#128) | 10 s |
| `MESSAGE_SEND`, `MESSAGE_RECEIVE` | agent | a message of up to 1 KiB and a kind byte to an agent it holds `channel` for, queued in the runtime (8 per receiver, `BUSY` when full) and audited without its content; the oldest message waiting for the caller, with its sender, or `NOT_FOUND`; see [coordination.md](coordination.md) (#133) | 1 s |
| `KNOWLEDGE_PUT`, `KNOWLEDGE_GET`, `KNOWLEDGE_HISTORY`, `KNOWLEDGE_QUERY`, `PROMOTE` (planned, M3.8) | agent | shared knowledge through the `knowledge` service, within `knowledge read` and `knowledge write` grants per scope; each put and promotion audited without its content ([knowledge.md](knowledge.md)) | the service's bounded wait |
| `SUBTASK`, `SUBTASK_STATUS` | supervisor | a subtask for one of its group's workers, input from its buffer (at most 8 open per goal, `BUSY` beyond); one of its own subtasks' state and result, `NO_SESSION` for any other task; see [coordination.md](coordination.md) (#134) | 10 s |
| `ANSWER` | `trust` | the user's `yes` or `no` to an approval request (#106) | none (a plain `send`) |
| `REVOKE` | `trust` | takes a permission from every running task of an agent, for the rest of the task; answered with `trust`'s `REVOKED` (#105) | none (a plain `send`) |
| `SUBMIT` | control | a new task: agent name, up to 4 task IDs it depends on, input from the client's buffer; returns the task ID | 10 s |
| `STATUS` | control | a task's state, attempts, and result | 1 s |
| `CANCEL` | control | stops the task's agent, cancels its inference session, marks it cancelled | 10 s |
| `FORGET` | control | deletes an ended task's record | 10 s |
| `INFO`, `ATTACH` | both | as D-019 | 1 s |

Inference, `DATA_PUT`, `SEND_TO` (#109), `SUBMIT`, and `CANCEL` are audited first (#108): if the audit trail cannot record the intent within 2 s, the request answers `NO_AUDIT` and nothing is done ([capabilities.md](capabilities.md)). An agent's refused requests are recorded once per kind per attempt, with the attempt's total when it ends (#110).

- An agent sees only its own task: the badge gives the slot, the slot the task. A request about another task answers `NO_SESSION`.
- Everything an agent sends is checked and copied out of its buffer before use, as in the inference service. Inference output reaches the agent as data, never interpreted by the runtime.
- *Implemented (#98):* `pharos_proto::agents` with `TASK`, `COMPLETE`, `FAIL`, `INFER`, `NEXT`, `CANCEL_INFER`, `LOG`, `SUBMIT`, `STATUS`, `CANCEL`, `INFO`, and `ATTACH` (buffers up to 64 KiB, mapped read-write by the runtime; input and results up to 4 KiB). `INFER` and `NEXT` answer with the inference service's own replies; one agent at a time may hold a session (`BUSY` otherwise), which is cancelled when the agent ends. Control requests from an agent, and agent requests from a control client, answer `NO_ACCESS`. *Implemented (#99):* `CHECKPOINT`, `BEGIN`/`END` (16-byte keys, results up to 64 bytes, `BEGIN` answering `GO`, `DONE` with the result, or `UNKNOWN`), `FORGET` (only an ended task that no unended task depends on; `BUSY` otherwise), and up to 4 dependencies on `SUBMIT`. An agent's buffer is up to 68 KiB: the input at 0 and the checkpoint at 4096, where `TASK` puts the last one and `CHECKPOINT` takes the new one.

### Durable tasks (#99)

- **Storage:** namespace `agents` (new, read-write, held only by the runtime). One file per task, `tasks/<id>`, rewritten whole on every change, so each change is one crash-consistent commit. It holds the agent name, state, dependencies, attempts, input, checkpoint, idempotency entries, and result. `next-id` is written before a new task's file, so a task ID is never reused, even after a crash. At most 256 task files; `SUBMIT` beyond that answers `TOO_LARGE`.
- **States:** pending, running, done, failed, cancelled. A task runs only when all its dependencies are done. If one fails or is cancelled, the task fails ("dependency failed"). A task can depend only on tasks that already exist, so there are no cycles.
- **Recovery:** when the runtime starts, it reads every task file. A running task becomes pending with one more attempt, or failed if its attempts are used up ("retries exhausted").
- **Idempotency keys** (no exactly-once promise):
  - `BEGIN` writes the key as *begun* and commits before it answers `GO`.
  - `END` writes the result as *done*.
  - After a restart, `BEGIN` with a done key answers `DONE` and the recorded result, so the operation is not repeated. With a key that was begun but never ended it answers `UNKNOWN`: the operation may or may not have happened, and the agent must check or give up. It is never silently repeated.
  - At most 32 keys per task.
- **The task logic** (state changes, recovery, keys, dependencies) is a host-tested `no_std` module, separate from IPC and storage. *Implemented (#99):* `pharos_programs::tasks`. Task files start with `PTSK` and a format byte, and every length and limit is checked when read; a file that is not a task record under its own ID is counted as unreadable and left in place. Each change is made on a copy, written, and kept only once the store took it, so a refused write changes nothing and the request answers `INTERNAL`. A refused retry after a crash or hang would leave the task running with no process; the runtime finds such tasks on every pass of its loop (`Tasks::retry_stranded`) and retries them at least once a second until the store takes the write. An attempt is counted and stored before the agent starts, so a kill during an attempt uses it up. The runtime holds namespace `agents` read-write (`init` grants it as storage badge 5) and a 128 KiB buffer at the storage service; at start it prints `<n> tasks recovered, <m> were running, <k> unreadable`. A task whose dependency was forgotten cannot exist, since `FORGET` refuses it. Fault injection cuts the store's writes at every point on the host. In QEMU, the runtime is stopped during checkpoints, and QEMU is killed during them.

### Timeouts and cancellation

- Every operation above has its timeout, and the runtime uses `call` with a timeout toward the store and the inference service.
- Cancelling a task stops its agent's process and cancels its inference session. Stopping the runtime stops all agents (children go with their parent). The inference service drops the runtime's session after 10 s idle anyway (M3.2).

### Service supervision in `init` (#100)

- `init` waits for each daemon's `ready` with a timeout and reports one that never answers.
- A daemon that crashes is restarted at most 3 times. One that was **stopped** is never restarted (safe mode).
- The storage and inference services release a client's buffer when the client ends (carried from the M3.0 and M3.2 reviews). The inference service tries a model whose read failed again after a restart.
- *Implemented (#100):* the kernel tells no server that a client ended, but `init` knows, because it starts the clients and gives them their badges. When a service ends, `init` sends `RELEASE` with each badge it gave it to the storage and inference services, through its own unbadged capability; they accept it from no one else (as `trust` accepts `RUNTIME` only from `init`). A failed model read is never kept: the inference service drops its read window, and the next `GENERATE` attaches a new one and tries again. The agent runtime and the inference service attach their buffers again when a restarted service answers `NO_BUFFER`. Details in [services.md](services.md#init). For tests, the kernel can end a process as if it crashed (`process::kill`, not reachable from user space).

## 4. Security

- **What must be right for the emergency stop:** the kernel's stop call and `trust` with its virtio-console driver. Neither the runtime nor any agent can delay or prevent a stop: `trust` holds `STOP` on the runtime from `init`, and a stop needs nothing from the process it stops.
- **What the runtime is trusted for:** task integrity, idempotency records, attribution in its events, and granting only what the policy table allows. It is not trusted for the stop.
- **Agents are untrusted:** one capability, every request checked, limits from the manifest within the table, nothing reachable but the runtime. A compromised agent can waste its own budget, but cannot reach another agent's task, the store, or the inference service directly.
- **Attribution:** console lines are prefixed by the kernel with the writing process. `trust`'s console is its own device. Records name the agent, task, and attempt.

## 5. Testing

| Where | What |
| --- | --- |
| Host | Manifest parser: every field, every refusal, 100,000 fuzzed inputs (#97). Task logic: every state change, recovery from every state, retries bounded, keys answering `GO`/`DONE`/`UNKNOWN`, dependencies, and every store write cut (#99). Codecs for `agents` and `trust`: round trips, truncation, fuzzing |
| QEMU, `process_stop` (#95) | Stopping a looping, a blocked, and a memory-holding process; its children stopped with it; children of a process that exits or faults stopped; no frames, handles, or queued messages left; a client of a stopped server gets an error; the `spawn` kernel's process-limit check rechecked, since its parent now takes its children with it |
| QEMU, `trust` (#96) | A `stop` typed on the trusted path ends an agent while a stand-in runtime spins in a loop (no test hooks in the real runtime); `stop all`; an agent holds nothing that reaches `trust` |
| QEMU, `agents` (#98, #99) | Start and stop; crash, hang, and restart; attempts used up; an agent holds exactly one capability it was given (*implemented, #98*: start, a crash then success, crashes, exits, and hangs until attempts are used up, an agent's `FAIL`, inference through the runtime with a model outside the manifest refused, an agent's control requests refused, four of five agents running, cancel, refused and missing manifests); a task's inference through the runtime; recovery after the runtime is stopped mid-task; a repeated key answers `DONE`; checkpoints survive a QEMU kill (*implemented, #99*: keys answering `GO`, `UNKNOWN`, and `DONE`, a checkpoint handed to the next attempt, dependencies waited for, an unknown one refused, a cancelled one failing its dependent, `FORGET`, and the runtime stopped while an agent holds a checkpoint and a done key, then a new runtime on the same store finishing the task on attempt 2 without repeating the operation; the `agents_crash` kernel killed 6 times while a task counts to 30, checking every step's record on every attempt; the `agents_store` kernel killing the storage service with the agent, the task waiting `not stored` without restarting, then restarting and completing once the store is back) |
| QEMU, `init` (#100) | A daemon that never reports `ready`; a killed inference service restarted and serving; a stopped one not restarted; a client's buffer released after it ends (*implemented, #100*: the `supervision` test kernel, also the storage service killed and the model reloaded through the new one, a crashing daemon restarted 3 times and then left, a read failure not kept, and `RELEASE` refused from a client) |

Each check is mutation-tested, as in earlier milestones.

## 6. Alternatives

- **Agents holding inference and storage capabilities directly:** one copy fewer, but the runtime could not cancel, time out, or (in M3.5) budget their requests, and stopping an agent could leave a session running.
- **A spawn that starts the child suspended:** grants the stop capability before the child runs at all, but adds a kernel call. With a single capability that the runtime does not serve until `trust` acknowledged, the agent can do nothing before then anyway.
- **Serial input for the trusted path:** rejected in D-018 (shared with every process's output, needs kernel input code).
- **A journal instead of one file per task:** fewer bytes written, but replay, compaction, and a format of its own. The store already makes a whole-file write atomic.
- **Manifests in the store:** editable at run time, but data an unsigned store cannot vouch for (as for models, M3.2). Reconsidered with signed updates (M4.3).
- **Narrowing a manifest to the table instead of refusing it:** the agent would run with settings different from the ones written.

## 7. Open questions

- The trusted path on real hardware (M5): a local console or keyboard that only `trust` reads.
- Who submits tasks after M3.3 (a user shell, M3.6), and whether one agent process should run several tasks.
- Whether 64 KiB checkpoints are enough for the agents M3.6 brings.
