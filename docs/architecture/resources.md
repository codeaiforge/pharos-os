# Resources: accounting, limits, and reservations

## 1. Status

**Planned. Design approved by the maintainer on 2026-11-04 (#113),** with CPU time counted by one `rdtsc` per switch and a plain load and store, measured within D-004's IPC budget before approval. To be built by: scheduling classes and CPU accounting (#114), carved limits (#115), runtime budgets (#116), not holding the runtime (#117), inference admission (#118), usage reporting (#119), and exhaustion tests (#120). **Implemented:** scheduling classes and CPU time per process (#114), carved limits (#115), runtime budgets (#116), not holding the runtime (#117), inference admission (#118), usage reporting (#119), exhaustion tests (#120).

## 2. Context

M3.4 gives agents only granted permissions, with every consequential action audited ([capabilities.md](capabilities.md)). Nothing limits how much they use. D-022 (#112) decides M3.5:

- three fixed scheduling classes, trusted, services, and agents, a higher class always first (item 1, amending D-013);
- CPU time counted per process by the kernel (item 2);
- pages, processes, and handles carved from the creator's (item 3);
- over a limit refused, requests over the rate throttled, an attempt over its CPU budget stopped, each recorded (item 4);
- groups named in the policy table (item 5);
- the kernel enforces classes, pages, processes, and handles; the runtime enforces CPU per attempt, storage, network, inference, and requests; the inference service admits within each client's budget (item 6).

What M3.5 builds on:
- **The scheduler** has one first-in first-out ready queue and a 10 ms slice ([scheduling.md](scheduling.md)); nothing is counted per task.
- **Processes** get a page limit at `spawn` (bits 32–63 of its `count` argument), at most the creator's but not taken from it ([user-environment.md](user-environment.md)); at most 32 live processes system-wide, 64 handles each.
- **The trusted reserve (#182, M4.6; D-022 amended):** limits are not held against memory, so the kernel keeps 2,048 frames (8 MiB) only the trusted class may take (`process::TRUSTED_RESERVE`, in `mem_map`, `dma_alloc`, `mem_map_cap`, and `spawn`, which counts every page of the program's segments; M4.6 review F2). Each mapping also counts the page tables it may need (`process::tables_for`: one per 512 pages plus 3; #196), since they come from the same frames; `init` can always start or restart `trust`. Other classes share the rest, so a runaway service can starve its peers until the user stops it.
- **The agent runtime** serves one message at a time, calling the store (10 s), inference (`GENERATE` up to 60 s), audit (2 s), and network (1 s) services with `call_timeout`. It already stops agents with no request for `progress_ms` or over `task_ms`, and holds each agent's `STOP` right ([agents.md](agents.md)).
- **The inference service** runs one session at a time and answers `BUSY` to others ([inference.md](inference.md)).

## 3. Design

### Scheduling classes (#114)

- **Three ready queues, one per class: trusted (0), services (1), agents (2).** The scheduler always picks from the highest non-empty class; within a class, round robin with the 10 ms slice as now. A task woken by IPC or an interrupt joins the back of its own class's queue, and preempts the running task at once if its class is higher (not at the next tick), so the emergency stop runs as soon as `trust`'s console interrupt arrives.
- **Who is in which class:** kernel tasks and `init` are trusted. `spawn` takes the child's class in bits 32–33 of its last argument (the notification bit stays in bits 0–31): 0 means the creator's own, and a class above the creator's is `TOO_LARGE`. `init`'s table gives `trust` class 0 and the other services, the audit service among them, class 1; the agent runtime starts agents in class 2. Test kernels' processes keep the creator's class unless they ask.
- **The idle task** stays outside the classes, as now.
- **Starvation is by design:** a lower class runs only when every higher class is blocked (D-022 consequences). The services class spends its time waiting on IPC, except the inference service while it computes, when agents wait on it anyway.

### CPU accounting (#114)

- **The kernel counts each process's CPU time in TSC cycles,** with one `rdtsc` per switch, in `pick_next`, which every switch goes through: the cycles since the leaving task's start time are added to its count, and the arriving task's start time is set. Both fields sit in the task, and the addition is a plain load and store, not an atomic read-modify-write: the scheduler runs with interrupts off on one CPU, and the locked form measured several times slower (below). Cycles are converted to microseconds only when read. Interrupt and system-call time is charged to the process that was running, as the kernel does not split them.
- **A new system call, `process_usage` (26),** returns a process's CPU time in microseconds, its pages in use, and its live descendants, for any holder of its process capability with `WAIT`. The runtime reads it for its agents; `init` for its services.
- **Cost, measured for this design (2026-11-04, `cargo xtask bench-ipc`, KVM, 9 runs each, builds alternated):** without counting, medians 1,921 and 1,915 ns; with it, 1,926 and 1,936 ns, within D-004's 2,000 ns budget. A first version with an atomic `fetch_add` measured 1,961 and 2,046 ns against 1,929 and 1,920 ns, over the budget once; hence the plain load and store. Measured again with #114's code (9 runs each): medians 1,915 and 1,959 ns. Its first version read and cleared the preemption flag with an atomic `swap` on every system call, which measured 1,994 and 1,962 ns; a plain load in the common case replaced it.

### Carved limits (#115)

- **Each process has three budgets: pages, processes, and handles.** Pages as now; processes, how many live descendants it may have; handles, the sum of handles held by itself and its descendants (each table stays at most 64).
- **`spawn` takes the child's budgets out of the creator's** and they return when the child ends (its descendants are stopped with it, so everything returns at once). The pages a creator has given away count as in use: it can map at most its limit minus its mappings minus its children's limits. Over any budget, `spawn` answers `TOO_LARGE`. A creator's own table shrinks to its handle budget less what its children hold (at most 64), keeping room for the new process handle; a call that would add a handle beyond it answers `NO_MEMORY` and takes nothing (`receive` refuses before taking a message, as for a full table today, so no message is lost).
- **`spawn`'s arguments:** pages in bits 32–63 of `count` (as now), processes in bits 40–47 and handles in bits 48–59 of the last argument. 0 processes means none; 0 handles means 64, one full table (services use up to a full table; the agent runtime gives each agent 16). The kernel gives each process it starts, `init` among them, the whole system: 31 processes and 2,048 handles (a full table for each of 32), with its pages.
- *Implemented (#115):* `process::Budget`, `Process::give` and `take_back`, the table's limit (`CapTable::set_limit`), `pharos_user::Limits` with `spawn_with`. `init` gives the agent runtime 16 processes and 320 handles (64, plus 16 for each of 16 agents) and every other service none and a full table; the runtime gives each agent 16 handles and no descendants. The capability table keeps a count of its handles, since `insert` (on every `call`) now checks the limit: counting the slots each time cost the IPC round trip about 60 ns. IPC round trip against #114's kernel, alternately, 9 runs each: 2,012 and 1,935 ns against 1,995 and 2,000 ns. The two differences from the draft above: 0 handles means 64, not 16, and a `receive` over the budget is refused rather than delivering the message without its capability.
- **The system-wide limit stays** (32 processes) as the kernel's own backstop; with carving, only `init` can reach it.
- **Shared memory's bookkeeping** (8 bytes per page of a shared object, on the kernel heap) is charged to the sharing process's page limit, one page per 512 shared pages, rounded up.
- **`mem_map` no longer zeroes with interrupts off.** The pages are reserved against the limit first, then allocated and zeroed in batches of 64 pages (256 KiB) with interrupts on between batches, and mapped at the end; a process stopped meanwhile frees what was allocated.

### Runtime budgets (#116)

- **New fields in a policy entry,** each a limit per attempt unless named otherwise (a manifest may ask for less with the same keys, never more):
  - `cpu_ms`: CPU time;
  - `tokens`: inference tokens, prompt plus generated;
  - `net_sends` and `net_bytes`: datagrams and their payload bytes;
  - `data_kb`: the agent's stored files in total (across attempts and tasks, since they persist);
  - `file_kb`: granted files read with `read_file` (#127, tools.md);
  - `messages`: messages sent to other agents (#133, coordination.md);
  - `rate`: requests per second, with a burst of the same number;
  - `group`: the group's name.
- **Pages are not a runtime budget:** the entry's `pages` already goes to `spawn`, and the kernel now carves it from the runtime's own limit (#115), so all agents together fit in the runtime's.
- **Groups** are a second table in the runtime, `GROUPS`, each with a name and totals over its running agents: `agents` (running at once), `pages` (their page limits together), and `tokens_per_min` and `net_bytes_per_min` (shared by its agents, as rolling one-minute windows). An attempt that would exceed `agents` or `pages` waits to start, as attempts already wait for a free slot; a request over a shared rate is refused.
- **Over a limit:**
  - an inference, `DATA_PUT`, or `SEND_TO` that would exceed the agent's or group's budget is refused with the new common status `OVER_LIMIT` (10), before its `INTENT` is recorded; the agent may carry on without it;
  - an attempt over `cpu_ms` is stopped and counted as a failed attempt (`over cpu`), like a hang; the runtime checks each agent's CPU time with `process_usage` at least every 100 ms while agents run, so an agent overruns by at most about 100 ms plus one slice;
  - a request over `rate` is held (#117).
- **Every limit reached is recorded** in the audit trail once per kind per attempt, as refusals are (#110): `limit` with the resource, the limit, and the use, and counted in the attempt's refusal total.
- **The logic** (budgets, windows, groups) is a host-tested module beside `grants`.
- *Implemented (#116):* `pharos_proto::manifest::{Budget, Group}` (the entry's `budget`, `Budget::UNLIMITED` for none), `pharos_programs::budgets`, `status::OVER_LIMIT`, and in the runtime a `Usage` per attempt and a `GroupUse` per group. Tokens are charged as the prompt's bytes plus the new tokens asked for, before the request goes out (refunded with the real count in #118); `data_kb` is checked against the agent's files listed and sized in the store on each `DATA_PUT`; the runtime reads CPU time at least every 100 ms while an agent with a `cpu_ms` runs. Each limit reached is a refusal record (`over tokens`, `over net sends`, `over net bytes`, `over data`, `over group tokens`, `over group net`, `over cpu`), counted in the attempt's total. The boot policy table has no groups and every entry `Budget::UNLIMITED`; the `budgets` test kernel has its own table. Differences from the draft above: a manifest cannot narrow a budget yet (no agent needs less than its entry), a record names the resource but not the limit and the use, a group's minute is a fixed window from its first use (up to twice the rate across a window's edge), and `rate` came with #117.

### Not holding the runtime (#117)

- **A stalled service fails fast.** The runtime keeps a state per service (store, inference, audit, network). After one call times out, the service is *stalled*: every request that needs it answers `BUSY` at once (for audit, `NO_AUDIT`), without calling it. At most once per second the runtime sends it `INFO` with a 50 ms timeout, and an answer makes it healthy again. A stalled service therefore holds the runtime for one timeout, then at most 50 ms a second, and agents not using it are served meanwhile. Stopping agents never needed a service and is unchanged.
- **Long work stays bounded:** `GENERATE` reads the whole prompt before answering (6.3 s for the S1 prompt); it keeps its 60 s timeout, and admission (#118) bounds how long a prompt may be.
- **Throttling holds the request:** the runtime keeps the request and its reply capability in the agent's slot (one at a time per agent; a second while one is held is refused with `BUSY`) and serves it when the agent's rate allows, from its main loop. The agent's call waits; the request counts as progress when it arrives.
- **The approval queue is shared fairly:** an agent may have at most 1 request waiting, of the 4 places; another is refused without asking, and recorded (closing the M3.4 limit).

- *Implemented (#117):* a `Health` per service (store, inference, audit, network) wraps every call: one that times out stalls the service, agent requests that need it answer `BUSY` (audit `NO_AUDIT`) before anything is recorded, and at most once a second the next call is preceded by an `INFO` with 50 ms, whose answer ends the stall. The policy entry's budget has `rate` (`Budget::UNLIMITED`: none); a request past it is kept with its reply capability in the agent's slot and served from the main loop when the bucket allows, and one more while it is held is `BUSY`. `ASK` is refused without asking while the agent has one request waiting. Not tested: a stall ending (the `fairness` kernel's network service stays stopped).

### Inference admission (#118)

- **A budget per client in the inference service:** tokens (prompt plus generated) per minute and the longest prompt in tokens, set by `init`'s table for direct clients and by the runtime for its own badge with a new operation, `LIMIT` (6), accepted only without a badge, as `RELEASE` is (the runtime's badge gets the sum of its policy groups' `tokens_per_min`).
- **A `GENERATE` over the client's budget** answers `OVER_LIMIT` before any work, so a long prompt cannot hold the service past the client's own limit.
- **Within the runtime**, each agent's `tokens` and its group's rate are charged before the request is sent: the prompt's length in tokens is not known before tokenizing, so the runtime charges its byte length (an upper bound, since every token is at least one byte), then the service's `RESULT` gives the real count and the difference is returned.

- *Implemented (#118):* `LIMIT` (`pharos_proto::infer`, op 6) and `Status::OverLimit`; the service keeps limits by badge for up to 8 clients and charges prompt plus new tokens at `GENERATE` (it gives nothing back; the runtime's own budget does). `init`'s boot table sends none: its runtime's policy has no groups, so the runtime's badge has no limit. The runtime charges an agent the prompt's bytes plus the new tokens, then gives back the bytes beyond the prompt's tokens from the `GENERATE` reply, and the new tokens not generated from the session's `RESULT` when it ends (by `NEXT`, `CANCEL_INFER`, or the agent ending); everything when the request fails or the trail refuses it.

### Usage reporting (#119)

- **Every unit is attributed:** CPU and pages to a process (kernel), and the runtime's own process's use split by agent in the runtime for tokens, network, storage, and requests; anything the runtime does for no agent is its own.
- **`usage` on the trusted console** shows each running agent's attempt (CPU ms, pages, tokens, network sends and bytes, data KB, requests) against its limits, each group's totals, and the services' CPU time and pages, which `trust` asks the runtime and `init` for with non-blocking sends, as for `revoke`.
- **At the end of each attempt** the runtime records its usage in the audit trail (`usage`, beside the refusal total).

- *Implemented (#119):* `usage` on the trusted console, `agents` request `USAGE` (22, served only under `trust`'s badge), `trust` operations `USED` (7) and `GROUP_USED` (8) with numbers only, and audit action `usage` (14): each attempt's record as it ends reads `cpu <ms> tok <n> net <datagrams>/<bytes> req <n>`. Not shown: the other services' CPU time and pages, since `trust` holds no capability on them (it holds the runtime's and each agent's, from `init` and the runtime); `process_usage` attributes every process's CPU time and pages to it in the kernel.

### Exhaustion tests (#120)

An agent per resource that tries to use more than its limit, alone and then all together, beside a well-behaved agent that must complete: spinning (CPU and the emergency stop's latency), mapping (pages), spawning (processes, which agents cannot do anyway), holding capabilities (handles, in a test kernel process), filling its data (storage), flooding sends (network), long prompts and many tokens (inference), and flooding requests (rate). Under all of them at once, `trust`'s `stop` and a trusted service's answer must arrive within a stated bound (to be measured in #114, expected one slice).

- *Implemented (#120):* each kind alone is tested by its issue's kernel (`classes`, `spawn`, `user_memory`, `budgets`, `fairness`, `inference`); the `exhaustion` kernel runs them together. At most 4 agents run at once (`MAX_RUNNING`), so it runs two `spinner`s, `glutton` (pages and handles until refused, 12 requests at 4 a second held and served, then `spender`'s tokens, datagrams, bytes, and files), and `ticker`, which must be served within 400 ms throughout; beside them `memprobe` (services class) maps 64 MiB in one call. **Bounds, stated and checked:** the kernel's own task (trusted class) wakes at most 40 ms after a 20 ms wait (measured 21–29 ms, of which 20 ms is the timeout's rounding to ticks); the trusted console answers `usage` and `stop all` within 200 ms of the runner typing them (measured 1 ms and 17–21 ms), and `stop all` ends the runtime and every agent. **Found and fixed:** `mem_map`'s window between batches (#115) was `sti` then `cli`, which lets no interrupt in (`sti` takes effect after the next instruction), and a woken task waited for the whole mapping anyway: loading the test model (a 26 ms `mem_map` in the inference service) held the kernel's task 33–41 ms. Now `sti; nop; cli`, so a tick or device interrupt between batches switches to the woken task. Found too, and fixed in #122: `mem_unmap`, a process's end (a 64 MiB process ending held the kernel's task 60–74 ms under TCG), `mem_share`, and `mem_map_cap` walked their pages with interrupts off. **Not covered:** a manifest cannot narrow budgets.

- *Implemented (#122):* `mem_unmap`, `mem_share`, and `mem_map_cap` work in batches of 64 pages with interrupts let in between, as `mem_map`. An ending process leaves its address space (it runs on the kernel root from then on) and frees it 4 page tables at a time with pauses, in its own context, instead of the scheduler freeing it whole under its locks when the thread is reaped. A `SharedMemory` object frees its frames in batches, pausing only when its last reference goes with an ending process or `mem_unmap` (`process::with_pauses`: elsewhere a drop may run where something relies on interrupts staying off). `mem_map_cap` answers `REVOKED` when its capability is revoked during one of its pauses: revocation's sweep could not see a mapping not yet recorded, which would otherwise have kept showing the object. The `exhaustion` kernel (now with 1 GiB) has `memprobe` map and unmap 64 MiB, share 128 MiB and map the share, and map 64 MiB more, then stops it, all while the kernel's task is measured (21–30 ms late at most, 20 ms of it the timeout's rounding); before, its teardown alone held the task 9–30 ms past that. The `shared_memory` kernel revokes a capability while `mem_map_cap` maps it. **Not covered:** a large shared object whose last reference goes with `delete` of its capability is freed in one go (the capability table is locked); at 192 MiB, freeing the space whole costs about 9 ms, so the 4-table batches are not shown to matter at this size (they are for spaces like the inference service's).

## 4. Security

- **Trusted for limits:** the kernel (classes, CPU time, pages, processes, handles), the runtime (per-agent and group budgets, rates), and the inference service (per-client admission).
- **Untrusted:** agents, their manifests (which only narrow), and the usage they cause.
- **The reservation** is the classes: nothing an agent does can delay a trusted or services-class process, except by asking a service for work, which that service's own limits and the agent's budgets bound.
- **Carving** makes the runtime's own limits the bound on all agents together, so a runtime bug cannot hand out more than `init` gave it.
- **Risk:** a stuck trusted or services-class process starves every lower class; those are reviewed programs, and `init` already restarts or stops a hung service.

## 5. Testing

- **Host:** the run queue with classes; carving arithmetic (give, return, refuse); budgets, windows, groups, and the stalled-service state; codecs for `process_usage`, `LIMIT`, and the new fields; manifest keys fuzzed.
- **QEMU:**
  - classes: a trusted task runs within one slice while 30 agent-class processes spin; a woken trusted task preempts at once; an agent cannot spawn into a higher class (#114);
  - CPU: `process_usage` of a spinning process grows with uptime, and of a blocked one does not (#114);
  - carving: a child over its creator's pages, processes, or handles is refused; the budgets return when it ends; a capability over the handle budget is not taken (#115);
  - budgets: an agent over each budget is refused or stopped, a group limit holds across two agents, while another agent completes (#116);
  - a killed or stalled store, inference, or audit service delays other agents by at most its first timeout; a flooding agent is held to its rate; one agent cannot fill the approval queue (#117);
  - inference: a client over its tokens or prompt length gets `OVER_LIMIT`, another is served (#118);
  - usage on the trusted console and in the trail matches what was used (#119);
  - exhaustion (#120), as above.
- **Mutations** for each check, as in M3.4.

## 6. Alternatives

- **Tick sampling for CPU time** (charge 10 ms to whoever runs at each tick): free on the switch path, but an agent that blocks just before each tick is never charged.
- **Kernel throttling of CPU budgets:** rejected in D-022 item 1; stopping in the runtime is enough for per-attempt budgets.
- **A thread per service call in the runtime:** would remove blocking entirely, but Pharos processes have one thread, and the stalled-service state bounds the cost with far less.
- **Usage limits per task instead of per attempt:** survives restarts, but every count would have to be stored before it is used; per attempt is bounded by `attempts` times the budget.
- **Handles as a per-process count only:** simpler, but a process could still hold 64 handles in each of its 31 descendants' tables.

## 7. Open questions

- ~~The bound on the emergency stop's latency under full load.~~ Stated and checked in #120: 200 ms from typing `stop all` to its answer (measured 17–21 ms under TCG), and 40 ms for a trusted task's wake-up.
