# Resources: accounting, limits, and reservations

## 1. Status

**Planned. Design approved by the maintainer on 2026-11-04 (#113),** with CPU time counted by one `rdtsc` per switch and a plain load and store, measured within D-004's IPC budget before approval. To be built by: scheduling classes and CPU accounting (#114), carved limits (#115), runtime budgets (#116), not holding the runtime (#117), inference admission (#118), usage reporting (#119), and exhaustion tests (#120). Nothing here is implemented yet.

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
- **Cost, measured for this design (2026-11-04, `cargo xtask bench-ipc`, KVM, 9 runs each, builds alternated):** without counting, medians 1,921 and 1,915 ns; with it, 1,926 and 1,936 ns, within D-004's 2,000 ns budget. A first version with an atomic `fetch_add` measured 1,961 and 2,046 ns against 1,929 and 1,920 ns, over the budget once; hence the plain load and store. #114 measures again with the real code.

### Carved limits (#115)

- **Each process has three budgets: pages, processes, and handles.** Pages as now; processes, how many live descendants it may have; handles, the sum of handles held by itself and its descendants (each table stays at most 64).
- **`spawn` takes the child's budgets out of the creator's** and they return when the child ends (its descendants are stopped with it, so everything returns at once). The pages a creator has given away count as in use: it can map at most its limit minus its mappings minus its children's limits. Over any budget, `spawn` answers `TOO_LARGE`, and a call that would add a handle over the budget (`receive` with a capability, `endpoint_create`, `open`, `mem_share`) answers `NO_MEMORY` and the capability is not taken; a message carrying it is delivered without it.
- **`spawn`'s arguments:** pages in bits 32–63 of `count` (as now), processes in bits 40–47 and handles in bits 48–59 of the last argument. 0 processes means none; 0 handles means 16, enough for a service's start capabilities and replies. The kernel gives `init` the whole system: 31 processes, 2,048 handles, and its 1.5 GiB of pages.
- **The system-wide limit stays** (32 processes) as the kernel's own backstop; with carving, only `init` can reach it.
- **Shared memory's bookkeeping** (8 bytes per page of a shared object, on the kernel heap) is charged to the sharing process's page limit, one page per 512 shared pages, rounded up.
- **`mem_map` no longer zeroes with interrupts off.** The pages are reserved against the limit first, then allocated and zeroed in batches of 64 pages (256 KiB) with interrupts on between batches, and mapped at the end; a process stopped meanwhile frees what was allocated.

### Runtime budgets (#116)

- **New fields in a policy entry,** each a limit per attempt unless named otherwise (a manifest may ask for less with the same keys, never more):
  - `cpu_ms`: CPU time;
  - `tokens`: inference tokens, prompt plus generated;
  - `net_sends` and `net_bytes`: datagrams and their payload bytes;
  - `data_kb`: the agent's stored files in total (across attempts and tasks, since they persist);
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

### Not holding the runtime (#117)

- **A stalled service fails fast.** The runtime keeps a state per service (store, inference, audit, network). After one call times out, the service is *stalled*: every request that needs it answers `BUSY` at once (for audit, `NO_AUDIT`), without calling it. At most once per second the runtime sends it `INFO` with a 50 ms timeout, and an answer makes it healthy again. A stalled service therefore holds the runtime for one timeout, then at most 50 ms a second, and agents not using it are served meanwhile. Stopping agents never needed a service and is unchanged.
- **Long work stays bounded:** `GENERATE` reads the whole prompt before answering (6.3 s for the S1 prompt); it keeps its 60 s timeout, and admission (#118) bounds how long a prompt may be.
- **Throttling holds the request:** the runtime keeps the request and its reply capability in the agent's slot (one at a time per agent; a second while one is held is refused with `BUSY`) and serves it when the agent's rate allows, from its main loop. The agent's call waits; the request counts as progress when it arrives.
- **The approval queue is shared fairly:** an agent may have at most 1 request waiting, of the 4 places; another is refused without asking, and recorded (closing the M3.4 limit).

### Inference admission (#118)

- **A budget per client in the inference service:** tokens (prompt plus generated) per minute and the longest prompt in tokens, set by `init`'s table for direct clients and by the runtime for its own badge with a new operation, `LIMIT` (6), accepted only without a badge, as `RELEASE` is (the runtime's badge gets the sum of its policy groups' `tokens_per_min`).
- **A `GENERATE` over the client's budget** answers `OVER_LIMIT` before any work, so a long prompt cannot hold the service past the client's own limit.
- **Within the runtime**, each agent's `tokens` and its group's rate are charged before the request is sent: the prompt's length in tokens is not known before tokenizing, so the runtime charges its byte length (an upper bound, since every token is at least one byte), then the service's `RESULT` gives the real count and the difference is returned.

### Usage reporting (#119)

- **Every unit is attributed:** CPU and pages to a process (kernel), and the runtime's own process's use split by agent in the runtime for tokens, network, storage, and requests; anything the runtime does for no agent is its own.
- **`usage` on the trusted console** shows each running agent's attempt (CPU ms, pages, tokens, network sends and bytes, data KB, requests) against its limits, each group's totals, and the services' CPU time and pages, which `trust` asks the runtime and `init` for with non-blocking sends, as for `revoke`.
- **At the end of each attempt** the runtime records its usage in the audit trail (`usage`, beside the refusal total).

### Exhaustion tests (#120)

An agent per resource that tries to use more than its limit, alone and then all together, beside a well-behaved agent that must complete: spinning (CPU and the emergency stop's latency), mapping (pages), spawning (processes, which agents cannot do anyway), holding capabilities (handles, in a test kernel process), filling its data (storage), flooding sends (network), long prompts and many tokens (inference), and flooding requests (rate). Under all of them at once, `trust`'s `stop` and a trusted service's answer must arrive within a stated bound (to be measured in #114, expected one slice).

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

- The bound on the emergency stop's latency under full load, to be measured in #114 and stated in the tests.
