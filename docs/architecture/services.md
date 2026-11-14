# Processes and system services

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-28 (M2.10, #59). It follows [D-015](../project/decision-log.md#d-015-network-stack-and-service-model) (as amended on 2026-10-28: badges instead of per-client endpoints), [D-014](../project/decision-log.md#d-014-ipc-model-and-system-call-mechanism) (IPC), and [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries). Networking is in [networking.md](networking.md).
- **M4.6 (D-031):** the AI services as system services below: design **approved** (#181, 2026-11-09); nothing in it is implemented yet.
- **M4.5 (D-030):** system configuration and health checks below: design **approved** (#175, 2026-11-09); the configuration file and its checks **implemented** (#176); health checks, `health`, and `config` **implemented** (#177).
- **M4.4 (D-029):** runtime management below: design **approved** (#169, 2026-11-08); `start`, `stop service`, and `restart` **implemented** (#170); driver entries for hotplug **implemented** (#171, [drivers.md](drivers.md#hotplug-m44-d-029)).
- **M4.3 (D-028):** **implemented (#163):** with the boot table, `init` starts the storage service from the factory image, picks and verifies an image slot, mounts it with `fs_mount`, starts the other services from it (`trust`'s program always from the factory image), and falls back in place to the other slot, then the factory image; it reports `[ready, failed, image]`. **Implemented (#164):** safe mode and recovery: the kernel's mode in `init`'s argument (bits 8 and up), else the slot record's one-shot `next`; the agent runtime `off` in both; recovery on the factory image (or the `recovery` copy), also when the factory image is not ready; the report `[ready, failed, image, mode]`; `trust`'s `system`, `safe`, and `recovery` (`SYSTEM`, `NEXT`). **Implemented (#165):** updates staged from the host: `trust`'s `update` (`UPDATE`, answered at once, then an `OFFER` per file), `apply <n>` and `discard <n>` (`ANSWER`), and `rollback` (`ROLLBACK`); an approved update goes to the slot that is not active and is tried in place, and one that is not ready is bad and the previous slot runs again. An agent with `update propose` only adds a file to `system/incoming` (`PROPOSE`, through the runtime's namespace 9; the boot table gives the runtime no such capability, as no boot entry may propose). Design in [boot.md](boot.md#8-recovery-and-updates-m43-d-028).
- **M4.1 (D-026, #149):** restart policies, the ready state, and failure reporting below are **planned**. Design approved by the maintainer on 2026-11-06 (#149), with a daemon that sends no `ready` in 10 s counted as a crash.
- **Implementation:** `endpoint_create`, `spawn`, `process_status`, badges, and endpoint notifications are **implemented** (#60: `cap::Capability::derive_badged`, `ipc::Endpoint::signal`, `process::ProcessRecord`, `pharos_user::{spawn, Grant, Received, Status}`; tested by the `spawn` test kernel with the `spawner` and `child` programs). So is `init` (#61: `user/programs/src/bin/init.rs`, `process::init_capabilities`, `ipc::poll` for the kernel's wait on the report; the main kernel starts it at boot, and the `services` test kernel runs its test table with the `svc` program). The boot table has `virtio-blk`, the network service (#63), and the storage service on the second virtio-blk disk with a 1 GiB page limit (#77; entries carry a `limit` and `Cap::SecondDevice` picks the second device with an ID), and the inference service with a 1 GiB limit, its endpoint, and a read-only `models` storage capability (#88, `Cap::InferService` and `Cap::Storage`; [inference.md](inference.md)), and the trusted service `trust` with the virtio-console device (`1af4:1043`, now in `process::INIT_DEVICES`), its endpoint, and the report endpoint (#96, `Cap::TrustService`; [agents.md](agents.md#the-trusted-path-96)), and the agent runtime `agents` after it, with a 64 MiB limit, its endpoint with `RECEIVE`, `SEND`, and `GRANT` (so it can give each agent a badged `SEND`), the root filesystem read-only, inference client 1, and `SEND` on `trust` badged as the runtime (#98, `Cap::AgentsService`, `Cap::Root`, `Cap::Inference`, `Cap::TrustRuntime`), and storage namespace `agents` read-write for its tasks (#99, `Cap::Storage(5)`), so it starts after the storage service. Right after starting the runtime, `init` sends `trust` its process capability with `STOP` and `WAIT` through `init`'s own unbadged handle; if that fails, it stops the runtime. So is `irq_notify` (#62: `irq::Vectors::bind`, kernel-side bindings beside the vector table). So are `call` and non-blocking `send` (#63: `ipc::call`, `ipc::try_send`, `Endpoint::offer_now`, `Endpoint::is_idle`).

## 2. Context

M2.10 must start services in a defined order and report failures ([roadmap](../project/implementation-roadmap.md#m210--networking-and-basic-system-services)). Today:

- Only the kernel starts processes (`process::spawn_elf`), and only test kernels do so; the main kernel runs no user code. *(Before M2.10.)*
- IPC is synchronous: 256-byte messages plus one capability. A receiver cannot tell senders apart, and a thread blocks on exactly one thing: one endpoint (`receive`) or one interrupt (`irq_wait`).
- Endpoints are created only by the kernel.

A service manager and a network service each need four things:

- to start processes;
- to learn when a child ends;
- to tell clients apart;
- to wait on messages, interrupts, and child exits at one blocking point.

This document adds the kernel support for these, and defines `init`.

## 3. Design

### Overview

| Addition | What | Issue |
| --- | --- | --- |
| `endpoint_create` | A process makes its own endpoints | #60 |
| Badges | A number on a capability, set once when it is passed on, and delivered with every message sent through it | #60 |
| Notifications | Up to 32 bits on an endpoint, set by the kernel (child exit, interrupt) without blocking or allocating; `receive` returns them | #60 |
| `spawn`, `process_status` | Start a program from a file capability with a chosen set of capabilities; learn how it ended | #60 |
| `init` | The first user process: starts the services in order and reports | #61 |
| `irq_notify` | Deliver an interrupt as a notification instead of to `irq_wait` | #62 |
| `call`, non-blocking `send` | Request and reply without lost replies, and replies that never block a service | #63 |

Nothing here adds `unsafe` code.

**New system calls and errors**, each checked as in [syscalls-ipc.md](syscalls-ipc.md); `syscall::decode` and its fuzz test cover them:

| Number | Name | Arguments | Returns | Needs |
| --- | --- | --- | --- | --- |
| 14 | `endpoint_create` | — | new endpoint handle | none |
| 15 | `spawn` | file, argument, capability array, count (≤ 8; since M3.0 bits 32–63 carry the child's page limit, [user-environment.md](user-environment.md#user-memory)), endpoint (0 = none), bit (since M3.5 bits 32–33 carry the child's scheduling class, [scheduling.md](scheduling.md#classes-d-022-114)) | new process handle | file `READ`; each passed capability `GRANT`; endpoint `RECEIVE` |
| 16 | `process_status` | process | 0 while running, else how it ended | process `WAIT` |
| 17 | `irq_notify` | interrupt, endpoint, bit (0–31) | 0 | interrupt `WAIT`; endpoint `RECEIVE` |
| 18 | `call` | endpoint, buffer, length (≤ 256), reply endpoint, maximum reply length, timeout (since M3.0, [user-environment.md](user-environment.md#timeouts)) | as `receive` | endpoint `SEND`; reply `SEND`, `RECEIVE` |

`send` (3) gains a flags argument (the sixth): bit 0 makes it non-blocking ([networking.md](networking.md#ipc-additions-kernel)).

| Code | Name | Meaning |
| --- | --- | --- |
| 10 | `BAD_PROGRAM` | `spawn`: the file is not a valid program |
| 11 | `WOULD_BLOCK` | Non-blocking `send`: no receiver is waiting; nothing was queued |

### Endpoints and badges

- **`endpoint_create`** returns a handle with `SEND | RECEIVE | GRANT` on a new endpoint. Endpoints count against the caller's 64 handles; no other limit is needed, since an endpoint is freed with its last capability.
- **Badge:** each capability has a 24-bit badge, 0 by default.
  - It is set only when a capability is passed on (by `spawn`, or by `send` with a capability), and only if the capability being passed has badge 0. Otherwise the child keeps the parent's badge.
  - So a badged capability can be narrowed and passed on, but never re-badged.
- **Delivery:** every message carries the badge of the capability it was sent through. `init` hands each client a `SEND` capability on the service's one endpoint, with a badge chosen per client. The service trusts the badge, not the message contents, for identity.

### Notifications

- **Each endpoint has a 32-bit notification word.** The kernel ORs bits into it:
  - when a child ends (`spawn` names the endpoint and bit);
  - when a bound interrupt fires (`irq_notify`).
- **Signalling** never blocks or allocates, so it is safe in an interrupt handler. If a thread waits in `receive` on the endpoint, it is woken.
- **`receive` returns pending notification bits first,** clearing them, before any queued message. The value then has the notification flag set and the bits in the upper half (see the encoding below). Repeated signals of one bit coalesce, so a receiver re-checks the source (`process_status`, its device's used ring) after every notification.
- **Rights:**
  - binding a source to an endpoint needs `RECEIVE` on it. A process directs notifications only to endpoints it receives on;
  - `SEND` holders cannot set bits.
- **`irq_notify`** binds an interrupt to an endpoint bit. From then on each interrupt sets the bit instead of counting for `irq_wait`, which returns `IN_USE`. The binding lasts as long as the interrupt object. It holds the endpoint alive, so a bound endpoint is freed only with the interrupt.

**`receive` value encoding** (status 0). The layout stays compatible with M2.7 for messages with badge 0:

| Bits | Message | Notification |
| --- | --- | --- |
| 0–15 | Length | 0 |
| 16 | 0 | 1 (notification flag) |
| 32–39 | New handle (0 = none) | Notification bits 0–7 |
| 40–63 | Badge | Notification bits 8–31 |

That is, for a notification, bits 32–63 hold the 32 notification bits.

### Starting processes

- **`spawn(file, arg, caps, count, endpoint, bit)`:**
  - `file`: a file capability with `READ` (an ELF program, loaded and checked exactly as in [drivers.md](drivers.md#elf-loader)).
  - `arg`: passed in `rdi`.
  - `caps`: a user array of `count` (at most 8) entries `{ handle: u64, rights: u32, badge: u32 }` (16 bytes each). Entry *i* becomes the child's handle *i* + 1: a capability derived from the caller's, with `GRANT` required on it, rights narrowed to `rights`, and the badge set as described above. So revoking the caller's capability revokes the child's.
  - `endpoint`, `bit`: 0, or an endpoint the caller holds with `RECEIVE`, and a bit (0–31) to signal when the child ends.
  - Returns a **process capability** with `WAIT | GRANT | STOP` (`STOP` since M3.3).
- **`process_status(process)`** (needs `WAIT`) returns:
  - 0 while the child runs;
  - once it has ended: bit 63 set, with bit 62 set if it was killed (low bits: the exception vector), otherwise the exit code in the low 62 bits. Since M3.3, bits 63 and 62 with 256 in the low bits mean it was stopped (exception vectors are below 32).

  The status stays readable as long as the capability exists.
- **Checks, before anything is allocated:**
  - the handles and their rights;
  - the array (range, count ≤ 8);
  - the live-process limit (`MAX_PROCESSES` = 32, kernel-wide).

  Then the ELF checks (`BAD_PROGRAM` on failure). On any failure nothing is created and no frames are lost.
- **Stopping (M3.3, #95, [agents.md](agents.md)):** `process_stop(process)` (call 25, needs `STOP`) tells the process to end. It is woken if it waits: its wait ends as timed out, so it leaves every endpoint queue (a blocked `send` takes its message back), and it never waits again. It ends at its next return to user mode, from a system call or a timer tick, as **stopped**. The call returns at once; `process_status` and the end notification show when the process has ended. **When any process ends** (exit, fault, or stop), every process it started is stopped too, so no work outlives the process that started it. A client in `call` to a stopped server gets its own timeout (`TIMED_OUT`); its reply capability is not signalled.
- **Not yet:**
  - a process outliving its last capability is fine. The process capability only observes; dropping it does not end the child (its parent ending does).

### `init`

- **Supervision (#100, [agents.md](agents.md#service-supervision-in-init-100)):** **implemented.** A daemon must send `ready` within 10 s, else `init` stops it (`no ready within 10 s; stopped`). After its first start, a daemon that exits or is killed is started again with the same capabilities on the same endpoints, so its clients' calls time out and then reach the new one, which they must attach their buffers to again (`NO_BUFFER` tells them). At most 3 restarts (`restarting <n>`, then `not restarted: restarts used up`); one that was stopped, by the trusted path or anyone, is never restarted (`stopped; not restarted`). When any service ends, `init` sends the storage and inference services `RELEASE` for each badge it gave it (operation 9 and 5, accepted only from `init`'s unbadged capability, answered within 1 s), so they free its buffer slot, and the inference service its session and record. Restarting the agent runtime sends `trust` its `RUNTIME` registration again. The `supervision` test table (argument 3) exercises all of it.

- **The main kernel**, after its boot report, enables preemption, mounts `root`, and starts `bin/init` with these capabilities:

  | Handle | Capability | Rights |
  | --- | --- | --- |
  | 1 | Debug console | `WRITE`, `GRANT` |
  | 2 | Root filesystem | `READ`, `GRANT` |
  | 3 | Report endpoint (the kernel receives) | `SEND` |
  | 4, 5, … | Each supported PCI device (virtio-blk, virtio-net), in PCI order | `MAP`, `CONFIG`, `IRQ`, `GRANT` |

  `init` identifies the devices with `config_read`.
- **The service table is compiled into `init`:** name, program, kind, the capabilities to pass, and the services it depends on. The argument selects a table (0: boot; others: test tables for the test kernels).
  - A **one-shot** service succeeds when it exits with code 0 (in M2.10: `virtio-blk`, which mounts the disk's image and exits).
  - A service whose device the kernel did not pass is reported (`no device`) and fails.
  - A **daemon** succeeds when it sends `ready` on its badged report capability (in M2.10: `net`, the network service). It fails if it ends first.
- **Order:** services start one after another in table order. A service starts only after the ones it depends on succeeded; otherwise it is skipped and reported as such.
- **One blocking point:** `init` creates one endpoint. It gives each daemon a `SEND` capability on it badged with the service's index, and binds each child's exit to bit *index*. It then loops on `receive`: messages (ready, by badge) and notifications (exits, then `process_status`).
- **Reports:** a console line per event (`init: <name> started`, `ready`, `exited <code>`, `killed <vector>`, `skipped`, `missing program`). After the last service, it sends one summary message to the kernel: services started and failed.
- **Then `init` keeps running:** it reports any daemon that ends later. No restarts in M2.10.
- **The kernel** polls the report endpoint (a kernel task has no inbox, so it uses `Endpoint::try_take`) for up to 75 s (30 s before #163), and prints the summary, `[ready, failed, image]` since #163 (image 0 factory, 1 slot A, 2 slot B), `[ready, failed, image, mode]` since #164 (image 3 the recovery copy; mode 0 normal, 1 safe, 2 recovery). Under QEMU it then prints `PHAROS: boot ok` and signals success only if no service failed. If no report arrives in 75 s, the boot fails. A boot with a failing service fails the boot check, so CI catches broken services.
- **Limit:** there are no timeouts. A daemon that never reports ready stalls `init`, and the boot check fails at its 60 s limit instead of passing.

### Supervision and readiness (M4.1, D-026)

Builds on M3.3's supervision (#100): a crashed daemon restarted at once, at most 3 times; one that sends no `ready` within 10 s stopped; one the user stopped never restarted. D-026 (#148) changes what follows.

**Restart policies (#150).**
- Each table entry gets `restart`: `Never`, or `Up(n)`, up to `n` restarts. One-shot services and `virtio-blk` are `Never`; every boot daemon is `Up(3)`, as today. The rules are a small host-tested module, `pharos_programs::supervise`: `delay(policy, done)` gives the wait before restart `done + 1`, or none once the restarts are used up.
- **A growing delay:** 100 ms × 4ⁿ (0.1, 0.4, 1.6 s for `Up(3)`). `init` keeps a restart deadline per service beside the `ready` deadlines and starts it when that passes; a crash loop costs at most one start per delay. Meanwhile its clients get timeouts and mark it stalled, as they do now (#117).
- **Unchanged:** a daemon that sends no `ready` within 10 s is stopped and counted as a crash (so its policy applies; today it is never restarted); a service stopped by the user is never restarted, whatever its policy; restarts count per boot (open question below).
- **Dependents** (the entries whose `after` names it, directly or through others) are named in the restart's report and keep running; they reach the new instance on the same endpoint (storage, inference, and knowledge clients attach their buffers again on `NO_BUFFER`).

- *Implemented (#150):* `pharos_programs::supervise` (`Restart`, `delay`, `dependents`) and the `restart` field on every table entry (boot daemons `Up(3)`, one-shots `Never`); `init` waits a restart's delay as a deadline (state `Restarting`), and its line reads `init: <name> restarting <n> of <limit> in <ms> ms; used by <dependents>`, or `not restarted: restart policy never` / `restarts used up`. The `supervision` kernel's `silent` is `Up(1)` and the new `brittle` `Never`.

**The ready state (#151).**
- After the last entry, `init` decides: **ready** if every entry succeeded (a daemon that sent `ready`, a one-shot that exited 0). The agent runtime sends `ready` only after loading its policy table and tasks and giving `trust` its channel, and `trust` only with its console set up, so ready covers the agent platform.
- **Reported three ways:** to the kernel as now (`[ready, failed]`, which the boot check reads); as an audit record (actor `init`, action `service`, detail `ready <n> services` or `not ready <failed> failed`); and to `trust`, which prints `system ready: <n> services` or `system not ready: <names>` (names cut to fit the line).

- *Implemented (#151):* `init` decides after the last entry and sends the trail (`service` 19, actor `init`, `ready <n> services` or `not ready <n> failed: <names>`), then `trust` (`trust::Request::Service` with `Event::Ready` or `NotReady` and up to 8 names, op 10, from `INIT` only; `system ready: <n> services` or `system not ready: <n> failed: <names>`), then the kernel, last, since it may end a boot check once it has the summary. `trust` builds every `SERVICE` line from fixed words, numbers, and `init`'s names, without the heap. The boot check finds the ready record in both boots' trails; the trusted console's line is checked by the `system` kernel (#153).

**Reporting (#152).**
- **Events:** `failed` (exited with a code, killed with a vector, or no `ready` in 10 s), `skipped` (a dependency failed), `restarting` (its number, of how many, and the delay), `given up` (restarts used up), and `stopped` (by the user; not restarted).
- **In the audit trail:** each event is a record with the new action `service` (19): actor the service's table name, detail the event, its numbers, and for a restart the dependents (cut to 64 bytes). Events before the audit service is ready are only on the debug console: only the services the audit service depends on can fail then.
- **On the trusted console:** `init` sends `trust` a new request, `SERVICE` (badge `trust::INIT` only): the service's name from `init`'s table, the event, and its numbers, never text from the service. `trust` prints `service <name> <event> …`. `init` tries for at most 100 ms (`trust` waits in `receive` almost always) and never waits on it longer; a lost line is still in the audit trail and in `services`.
- **`services` on the trusted console:** `trust` asks `init` with a call on the report capability it already holds (badged with its table index; `init` answers only that badge), new operation `SERVICES` (from an index, for paging); `init` answers each service's name, state (`starting`, `ready`, `done`, `restarting`, `failed`, `skipped`, `stopped`), restarts done, and its policy's limit. `trust` prints one line each, or `services: init is not answering` after 2 s (`INIT_US`; 1 s until #201: longer than `init`'s 1 s wait for a service it stops, `INIT_STOP_US`). `init`'s answer is the authoritative state; `trust` keeps none.
- **The interface:** `pharos_proto::service` (D-019): `SERVICE`, `SERVICES`, and its reply, version 1, host-tested and fuzzed like the other interfaces.

- *Implemented (#152):* every event goes through one path in `init`: its debug line (`init: <name> <what>`, as before), an audit record (action `service`, actor the service's table name, detail `<what>` cut to 64 bytes), and `SERVICE` to `trust`. `SERVICE` stayed in `pharos_proto::trust` (#151) and gained `NotStarted` (event 10: missing program, no device, or a spawn error and its code), so a start failure is reported too. `pharos_proto::service` holds only `SERVICES` `[version, op, from]` and its reply `[OK, total, count, entries]`, each entry its name, state (also `pending`, for entries not started yet), restarts done, and limit, as many as fit in one message. `init` answers it only on `trust`'s badge, without waiting; `services` prints `services: <name> <state>, restarts <n> of <limit>` per entry, or `services: init is not answering`. `init`'s states now tell `skipped` and `stopped` from `failed`.
- *Changed from the design (#152):* records are no longer dropped before the audit service is ready or while it cannot write. `init` queues up to 32 (dropping the oldest) and sends them oldest first, retrying after 1 s, doubling to 60 s. Without the queue, the `supervision` kernel lost the events of the 2 s in which the store restarted. Delivery is at least once: a record the store wrote just before it was killed is sent again, so it can be in the trail twice (seen for `store killed 13`).

**The end-to-end test (#153).** A new test kernel, `system`, boots `init` with the boot table and the boot image's disks and devices, and checks ready on the trusted console and in the trail; then kills the knowledge service (restarted after its delay, its dependents named), stops `net` itself (as a stop, never restarted; `trust` stops agents, not services), and kills one service past its restarts (given up); `services` shows each state, and every event is one audit record.

- *Implemented (#153):* `kernel/tests/system.rs`; `cargo xtask runner` gives it the boot image's modules (`root`) instead of the test modules. The service killed past its restarts is `infer` (four kills: restarts 1–3, then given up; `used by agents`). The runner checks the trusted console and the trail with the same check as `supervision` (`event_checks`). About 7 s; two mutations caught (restart policy ignored, no ready report).

### Capability manifests (M4.2, D-027)

**Planned, not implemented.** Design approved (#156, 2026-11-06). D-027 (#155): a service's manifest is its `init` table entry, every capability written out, plus what it may gain while it runs; `init` grants exactly it, and a capability audit checks every live service against it.

**Where the manifests live.** A new crate, `crates/pharos-services` (`no_std`, no dependencies), holds the table types and the tables (boot and test) now in `init`, and `Restart` (from `pharos_programs::supervise`, which keeps `delay` and `dependents`). `init` uses it, and so do the host tests and the audit test kernel, so all three read the same manifests. The kernel uses it only as a dev-dependency of its test kernels: nothing joins the kernel itself.

**A capability, written out.** Each entry's `caps` lists, in handle order, a `Give { object, rights, badge }`:
- `object`: `DebugConsole`, `Root`, `Device(id, nth)` (the `nth` device with that PCI ID), or `Endpoint(e)`, one of `init`'s endpoints: `Events` (its report endpoint), `Net`, `Store`, `Infer`, `Trust`, `Agents`, `Audit`, `Knowledge`;
- `rights`: exactly the rights the service gets (`SEND`, `RECEIVE`, `READ`, `WRITE`, `MAP | CONFIG | IRQ`, `GRANT`), no longer implied by a kind;
- `badge`: `None`, `Fixed(n)`, or `Own` (the entry's index + 1, `init`'s report badge).

For example, the inference service's entry reads `Give(DebugConsole, WRITE, None)`, `Give(Endpoint(Infer), RECEIVE, None)`, `Give(Endpoint(Events), SEND, Own)`, `Give(Endpoint(Store), SEND, Fixed(MODELS_READ_ONLY))`. A network capability's destinations stay a field of the entry (`net`), as `ALLOW` needs them.

**Rules, host-tested on every table** (a table that breaks one does not build its test):
- every `SEND` on an endpoint is badged with a number that is not 0: badge 0 is `init`'s own (`RELEASE`, `ALLOW`, `RUNTIME`, `LIMIT`, and its audit records), and no service may send as `init`;
- one receiver per endpoint, the service named for it;
- a badge appears once per endpoint across a table (two services with one badge would be one client);
- `GRANT` only with `RECEIVE` on the runtime's own endpoint (it hands each agent a badged `SEND`);
- device rights only on devices, each device to one service, `READ` only on `Root`, `WRITE` only on `DebugConsole`;
- every daemon has `Endpoint(Events)` with `Own`, and no one-shot does.

**Declared runtime gains.** Each entry's `gains` lists what the service may hold beyond `caps`:
- `Own` (every service): objects it created itself, an endpoint no other process holds, or an interrupt object of one of its devices;
- `Processes`: process capabilities with `STOP | WAIT`, for `trust` (the runtime and each agent) and for the runtime (its agents). `init` hands `trust` the runtime's without ever blocking (`try_send_cap`, at most 2 s, else it stops the runtime), and restarts the runtime only once `trust` is ready (#213);
- `RuntimeChannel`: `trust`'s `SEND` on `Endpoint(Agents)` badged `agents::TRUST`.

A call's one-shot reply capability is revoked when the call returns, so it needs no entry. The audit tells it apart by taking three snapshots 100 ms apart: a capability counts only if it is in all three. A client's attached buffer is mapped and its capability deleted, so it is no capability; mappings are bounded by each service's page limit.

**`init`.** `grant` becomes a lookup: the object to `init`'s handle, the rights as written, the badge resolved. The kernel already refuses a right `init` does not hold. Two steps:
1. The boot and test tables move to `pharos-services`, written out to give exactly what `init` grants today. This is a refactor with no change in behaviour: every test kernel passes unchanged.
2. Each boot service is narrowed (#157), one capability at a time, each change named in the review. Candidates to examine: the runtime's network capability (no destinations while its boot policy table is empty), its inference and files capabilities under the same table, and the debug console for each service.

**The audit (#158).** `kernel/tests/common/manifests.rs`, used by the `system` kernel at ready and again after its faults (a restarted knowledge service, a stopped network service, a given-up inference service). It:
1. identifies each live child of `init` by its report badge (`Own`) on `init`'s report endpoint, and each of `init`'s endpoints by the service that receives on it;
2. for each service, matches every capability in its table to one `Give` (same object, rights, and badge) or one declared gain, over the three snapshots;
3. fails on anything unmatched, any `Give` missing, and any `Give` held with more rights. It prints each service's table.

A mutation in which `init` grants one service one capability more than its entry must fail it, and one in which a manifest gives `GRANT` must fail a host rule.

- *Implemented (#157, step 1):* `crates/pharos-services` with the types, the four tables written out (`BOOT`, `TEST`, `NETWORK`, `SUPERVISE`, chosen by `table(arg)`), and `check`, the rules above; `Restart` moved there (`pharos_programs::supervise` re-exports it). `Own` gains are implicit, so `gains` lists only `Processes` and `RuntimeChannel`. `init`'s `grant` copies each `Give` and refuses a `SEND` with badge 0 on another service's endpoint (`capability refused`). Every test kernel passed unchanged.
- *Implemented (#157, step 2):* each boot service reviewed against what its code uses:

  | Service | Manifest | Change |
  | --- | --- | --- |
  | `virtio-blk` | console, the read-only disk | none: both used |
  | `net` | console, the network card, its endpoint, report | none |
  | `store` | console, the writable disk, its endpoint, report | none |
  | `infer` | console, its endpoint, report, `models` read-only | none |
  | `audit` | console, its endpoint, report, `audit` | none |
  | `knowledge` | console, its endpoint, report, `knowledge` | none |
  | `trust` | the trusted console, its endpoint, report, audit client 2, knowledge client 2; gains processes and the runtime channel | none: `verify` uses knowledge, the anchor and records audit; it has no debug console |
  | `agents` | console, its endpoint (`RECEIVE`, `SEND`, `GRANT`), report, root, inference client 1, `trust` as the runtime, `agents` tasks, audit client 3; gains processes | **narrowed:** the network capability (no destinations), `files` read-only, and knowledge client 1 removed, as the boot policy table runs no agent; the runtime treats handles 9 to 11 as optional. It no longer waits for the knowledge service (`after`), though it still depends on it through `trust` |

  Kept on purpose: the runtime's inference capability (it attaches its prompt buffer at start, before any agent) and root (agent programs and manifests); every service's debug console (its only log). A policy entry that needs a removed capability adds it to the entry, a reviewed change.

- *Implemented (#158):* `kernel/tests/common/manifests.rs` (`Audit`), run by the `system` kernel at ready (7 services) and after its faults (5: `net` stopped and `infer` given up are gone, `knowledge` is a new process). `Audit::new` learns `init`'s endpoints while every service is up: the report endpoint is the one most services send on, a service is its report badge, and an endpoint is the one its receiver holds with `RECEIVE`. A device's `nth` is its place among devices with its PCI ID in PCI order. "Its own" objects are checked by who else holds them, since the kernel does not record an object's creator: an endpoint or memory object no other process holds. Every service holds own endpoints (for replies), and they carry every right, `GRANT` too, so the `system` kernel no longer finds the runtime by `GRANT`. Each service's table is printed: `trust` holds its 5 manifest capabilities plus its reply endpoint, its console's interrupt, the runtime's process capability, and the runtime channel. Mutation-checked: `init` giving the knowledge service the root filesystem fails both audits.

**Not covered.** `init` itself (the kernel gives it every boot capability; it is reviewed code). Agents (their manifests are D-012's, and the `hostile` and `deputy` kernels test them). Memory mappings, bounded by page limits. Processes the runtime starts that are not agents: there are none.

### Runtime management (M4.4, D-029)

**Implemented: service management (#170) and device hotplug (#171).** Design approved (#169, 2026-11-08). D-029 (#168): the user starts, stops, and restarts services from the trusted console only; `trust`, `audit`, and `store` can be restarted but not stopped; dependents keep running and are reported; only compiled table entries start. Devices added and removed at runtime are in [drivers.md](drivers.md#hotplug-m44-d-029).

**Console commands** (`pharos_proto::trust::command`):

| Command | Meaning |
| --- | --- |
| `start <service>` | Start a stopped, given-up, failed, or skipped service |
| `restart <service>` | Stop it if it runs, then start it |
| `stop service <service>` | Stop it; never restarted by its policy |
| `stop <agent>` | Unchanged: stops an agent (the runtime's registry) |

`start` and `restart` have no agent meaning, so they take a service name directly. `stop` keeps its agent meaning; a service is named after the word `service`, as a group is after `group`. An agent named `service` is stopped with `stop service` alone, as one named `group` is today. A service name is one of `init`'s table names (`valid_name`, at most 32 bytes); `trust` does not check it, `init` does.

**`init` requests** (`pharos_proto::service`, version 1, answered only on `trust`'s badge, like `SERVICES`):

| Op | Request | Reply |
| --- | --- | --- |
| 7 `START` | `[version, 7, len, name…]` | `[status]` |
| 8 `STOP` | `[version, 8, len, name…]` | `[status]` |
| 9 `RESTART` | `[version, 9, len, name…]` | `[status]` |

Statuses: `OK`, `UNKNOWN` (no entry by that name in the running table, so also every entry the mode leaves out, such as `agents` in safe mode), `PROTECTED` (`stop` on `trust`, `audit`, or `store`), `RUNNING` (`start` on a service that runs), `NOT_RUNNING` (`stop` on one that does not), `NEEDS` with the first dependency that does not run (its index in the table), `NO_DEVICE` (a driver entry with no device, [drivers.md](drivers.md#hotplug-m44-d-029)), `BUSY` (`init` is booting, switching images, or in recovery, the same "not now" as `UPDATE`).

**The rules** are a host-tested module, `pharos_programs::manage`: `decide(action, entry, state, deps) -> Result<Plan, Refusal>`, where `Plan` is `Stop`, `Start`, or `StopThenStart`. `init` only carries out a plan.
- **`stop`:** allowed while the service is `starting`, `ready`, or `restarting` (a waiting restart is cancelled). `init` stops the process, marks it `stopped` (never restarted, as for a stop by `trust` today, D-026), and reports its dependents, which keep running.
- **`start`:** allowed from `stopped`, `failed` (given up included), `skipped`, `done` (a one-shot runs again), and `pending`. Every entry in its `after` must be `ready` or `done`, else `NEEDS`. `init` starts it from its table entry with exactly its manifest (D-027) and sets its restart count to 0, so its policy applies afresh. A daemon still has 10 s to send `ready`.
- **`restart`:** allowed while the service runs, protected ones included; a stop then a start, with the count reset. On a service that does not run it is a `start`.
- **Protected services** (`trust`, `audit`, `store`) refuse only `stop`. Restarting `trust` ends the session on the console: `init` answers `OK` before it stops `trust`, and the new `trust` prints its banner. Restarting the agent runtime sends `trust` its `RUNTIME` registration again, as supervision does.
- **One request at a time:** `init` is one thread and answers each request before taking the next, so two commands never interleave.

**Reporting.** Each accepted action goes through `init`'s one event path (debug line, audit record, `SERVICE` line to `trust`, #152):
- new audit action `manage` (21): actor the service's table name, detail `stopped by the user`, `started by the user`, or `restarted by the user`, with `; used by <dependents>` for a stop or restart (cut as F1 of the M4.1 review cuts it);
- `trust` prints `service <name> stopped by the user`, `started by the user`, or `restarted by the user`, then the normal events (`ready`, `failed`, …) as they come; a refusal is one line from `trust` alone (`stop: <name> is protected`, `start: <name> is running`, `start: <name> needs <dependency>`, `start: no service <name>`, `start: not now`), and an audit record only for `PROTECTED` (the only refusal that is an attempt to remove something the user cannot).
- `services` shows the new state; nothing else changes.
- **Recorded before it is done (#215):** `init` stores the `manage` record, after everything queued before it, and only then acts and answers `OK`. If the audit trail does not take it, the action is not done and the answer is `NO_AUDIT` (`trust`: `<command>: not done: the audit trail does not take records`). A start or restart of `audit` or `store` is the exception, so the user can always bring the trail back. `apply`, `discard`, `rollback`, and `safe` or `recovery` are recorded the same way first (`update #<n>: apply asked on the trusted path`, …). Events nobody asked for (a crash, a restart by policy) are queued as before; past 32, the oldest is dropped, and once the trail takes records again one says how many were (`records dropped while the trail was down: <n>`).

**Not in M4.4.** Any service or agent asking `init` to manage a service (D-029 1(b)); starting a program that has no table entry (4(b)); persisting a stop across a reboot.

- *Implemented (#170):* `pharos_proto::service` `START`, `STOP`, `RESTART` (`Request::Manage`, `Action`) and the reply `Managed`; `pharos_proto::trust` commands `Command::Manage` and event `ByUser` (12); audit action `manage` (21); `pharos_programs::manage::decide`; `init`'s `manage`; `trust`'s commands. Tested on the host and by the new `manage` test kernel.
- *Changed from the design (#170):*
  - `NEEDS` carries the dependency's name (`[NEEDS, length, name…]`), not its index, so `trust` can print it: `restart: trust needs knowledge`.
  - No `NO_DEVICE` status: `start` on a driver entry with no device (#171) is `OK`, then `service <name> not started: no device`.
  - The action is reported before it is carried out, so a stop or restart of `trust` is still printed by the `trust` that ends; `init` gives `trust` 100 ms to print it before stopping it.
  - The line `trust` prints for each action is from a new event, `ByUser` (12): `numbers[0]` 0 stopped, 1 started, 2 restarted, and 3 for `service <name> ready` when a daemon the user started sends `ready` (so the user sees when it can be used; without it, `restart trust` right after `start knowledge` was refused, `knowledge` not yet ready).
  - Refusals read `stop: <name> is protected: it can be restarted, not stopped`, `start: <name> is running`, `stop: <name> is not running`, `<action>: <name> needs <dependency>`, `<action>: no service <name>`, and `<action>: not now (booting, updating, or in recovery)`.
  - **A restarted `trust` holds the emergency stop again:** right after its audit line it asks `init` with a new request, `RUNTIME` (op 10), and `init` answers `[OK]` with the running runtime's process capability (`STOP`, `WAIT`) attached, through a new non-blocking `pharos_user::try_send_cap`, or `[NOT_FOUND]` (at boot, when the runtime is registered once it starts). Before, a `trust` restarted after a crash (M4.1) had no runtime capability, so `stop all` did nothing until the runtime restarted. A blocking send from `init` was tried first and deadlocked with `trust`'s own `services` call. Still lost when `trust` restarts: the runtime's channel to `trust` and its agents' registrations (names, groups, open approvals), until the runtime restarts; `stop all` does not need them.
  - The help line became two lines: one console line holds 256 bytes.

### Configuration and health (M4.5, D-030)

**Implemented: configuration (#176); health checks, `health`, and `config` (#177).** Design approved (#175, 2026-11-09). D-030 (#174): configuration holds settings only, each within a ceiling in reviewed code; one file in the signed root image; the manifest format; checked when the image is built, when an update is offered, and at boot, and refused whole, never narrowed; `init` checks each daemon's health; `trust` gains `health` and `config`.

**The file:** `etc/system.conf` in the root image, at most 4 KiB. A missing file means every compiled value (today's behavior). Lines as in agent manifests: `key = value`, `#` comments, blank lines ignored; sections `[service <name>]`. The first line that is not a comment is `config = 1`. Every key is optional and appears at most once per section.

```text
config = 1
[service net]
start = no
[service knowledge]
restarts = 1
delay_ms = 500
```

| Key | Value | Ceiling (compiled) | Refused when |
| --- | --- | --- | --- |
| `start` | `yes` or `no` | — | `no` for `trust`, `audit`, or `store` (`PROTECTED`), for a driver entry, or for a service another entry that starts lists in `after` (the error names it) |
| `restarts` | 0–255 | the entry's `Restart::Up(n)`: at most `n` (`Never`: only 0) | over the ceiling; any value for `trust`, `audit`, or `store` (their compiled values only, M4.5 review F3: a file cannot leave the console or the trail down for long) |
| `delay_ms` | the first restart's delay, 10–60,000 | — (a longer delay grants nothing) | out of range; any value for `trust`, `audit`, or `store` (F3) |

A section for a name not in the table, an unknown key, a repeated section or key, a value out of range, a missing or other `config =` line, a file over 4 KiB, or a line over 128 bytes is an error. The checker reports the first: line number and reason (`line 4: restarts 5 over 3 for knowledge`). A file with an error is refused whole; nothing in it is used.

**Code:** `pharos_services::config`, `no_std`, no dependency: `parse(text, table) -> Result<Config, Error>` and `Config::restart(i)`, `delay(i)`, `starts(i)`. The table is the one `init` runs, so test tables get their own checks. Host-tested on every rule and fuzzed like the manifest parser (`pharos_proto::fuzz`).

**Where it is checked:**
1. *When built:* the image builder (`cargo xtask` building the root, and `cargo xtask image sign`) parses `etc/system.conf` against the boot table and stops with the error, so a bad file never ships.
2. *When offered:* `init`'s `UPDATE` already copies each incoming image into its memory to verify it (`Slots::check`). It then opens the image (`pharos_fs` over the bytes) and checks its `etc/system.conf`. A bad file refuses the offer like a bad signature: `incoming <name> refused: line 4: …` on `trust`, with a new `Refusal::Config`, and the file is never offered, so `apply` cannot reach it.
3. *At boot:* after mounting a slot and before starting anything from it, `init` reads the file from the mounted image. A bad file makes the slot bad with the same refusal, and `init` falls back in place (D-028). The factory image's file is checked by the build; if it is still bad at boot, `init` reports it and runs with the compiled values.

**Which configuration applies:** the file of the image whose services `init` starts (a slot or the factory image). Safe mode and recovery ignore it and use the compiled values, so no file can change what recovery starts. `start`, `restart`, and `stop service` on the console still work on a service the file does not start: the file sets the boot, the user overrides it. Applying a new file means applying its image (D-028); nothing is reloaded in place.

**Agent limits: left out (changed from D-030).** The boot agent policy table is empty (agents.md), so at boot there is nothing for a file to narrow. Its entries live in `bin/agents`, which `init` cannot check against, so an agent section could only be checked when the runtime starts, after the image is applied. Agent sections are left until a boot policy entry exists; until then `[agent …]` is an unknown section.

**Health checks:** every 10 s `init` calls each daemon in state `Ready` with `INFO` (common op `0xf0`) on the endpoint it holds, with a 100 ms timeout, one service at a time. An answer of any status counts. Each entry has a compiled `quiet` window: a service that has answered no check for that long is **unresponsive**:
- 30 s for most services; 600 s for `infer`, which serves one generation at a time and may be busy that long; 180 s for `agents`, which waits for `infer` up to twice `GENERATE_US` (60 s) in one request (M4.5 review F1; host-tested against `pharos_proto::infer::GENERATE_US`); 60 s for `store`, which may be reading a 16 MiB image;
- the window is compiled, not configured;
- a check never blocks `init` for more than 100 ms, so a hung service delays `init` by at most 100 ms every 10 s;
- a daemon is also checked as soon as it is ready (a round at once); until it answers one check, `health` shows `no answer yet` (`quiet_s` `NO_ANSWER`) rather than its ready time (M4.5 review F2). A restarted `trust` first waits on `init` (`RUNTIME`), so it misses that round and answers the next.

An unresponsive service is reported (new service event `Unresponsive` = 15, `service <name> unresponsive for 30 s; restarting`), audited like other service events, stopped, and handled as a crash by its policy (D-026). It is never restarted past its limit. `audit` and `trust` answer no `INFO` today; each gains one (`audit` on `init`'s unbadged capability, `trust` on its service endpoint). Drivers and one-shots are not checked.

**Console commands** (`pharos_proto::trust::command`):

| Command | Meaning |
| --- | --- |
| `health` | Each service: state, restarts used and allowed, uptime, seconds since its last answered check. Then each running agent: name, attempt and attempts allowed, seconds since its last progress report against its `progress_ms` |
| `config` | Where the configuration came from (`slot a version 7`, `factory`, `compiled values (safe mode)`) and each setting that differs from the compiled value |

**`init` requests** (on `trust`'s badge, like `SERVICES`): 11 `HEALTH` (paged like `SERVICES`: `[version, 11, from]`; each entry's state, restarts, uptime, last check), 12 `CONFIG` (`[status, source, version, count, settings…]`). Agent lines come from the runtime: a new runtime op `HEALTH` answered to `trust` (each running agent's name, attempt, and last progress), from what the runtime already keeps.

**Implemented (#177), and what changed from the design:**
- **No `HEALTH` op:** every `SERVICES` entry now ends with its uptime and seconds since its last answered check (`NOT_CHECKED` if it is not checked), so `services` and `health` share one paged request; `health` prints them (`health: net ready, restarts 0 of 3, up 41 s, answered 1 s ago`).
- **`CONFIG` is op 11** (`pharos_proto::service::Settings`): the image the file came from (or `COMPILED`) and each entry that differs, as many as fit in one message (`config: from slot A`, `config: net start = no`, `config: knowledge restarts = 1`).
- **Agent lines come from the kernel, not a runtime op:** `health: agent <name> running` and its CPU time and pages (`process_status`, `process_usage` on the process capabilities `trust` holds), so they show even when the runtime is stuck; attempts and progress stay in `list` and the runtime's own replies.
- **`audit` gains no handler:** it already answers any request it cannot parse, and any answer counts. `trust` answers `INFO` from `init`'s badge with `OK`.
- `init` checks a daemon only if its name is the receiver of one of its endpoints (`Ep::receiver`); `check_health` runs from its main loop every 10 s, during boot too. A late answer cannot reach a later call: the reply capability is one-shot (syscalls-ipc.md).

**Audit:** a configuration refused at offer or boot is a `system` record (action 20), with the image's name, the line, and the reason; the `Unresponsive` event under the existing service action.

**Implemented (#176), and what changed from the design:**
- `pharos_services::config` (`parse`, `Config`, `Error` with `Display` and an allocation-free `text`, since user programs cannot use `alloc::format!`); `pharos_programs::system::image_config` reads the file from an image's bytes; `init`'s `read_config` from a mounted filesystem.
- `Slots::check` returns the image's configuration with its signature, so the offer, `apply`, and the slot boot all check the bytes they verified. A refused slot is bad, as for any refusal.
- A service the file does not start is `off (configuration)` (`State::Configured` = 10); `start <service>` starts it.
- `kernel/root/etc/system.conf` ships, with every compiled value and the format in comments; `cargo xtask` refuses a root or an image to sign whose file fails (`fs_image::check_config`). A test image's own file replaces the directory's (`pack_with`).
- **Changed:** `trust` shows `incoming <name> refused: bad configuration, line N` (the offer's `version` field carries the line), since its lines are written from fields only; the reason is in `init`'s line (`init: system: incoming <name> refused: bad configuration: line 3: audit always starts`) and the audit record. No new audit action: the `system` action holds it. The QEMU checks are rounds of the `update` and `recovery` kernels, not a new `config` kernel; that a restart limit is applied is host-tested (`Config::restart`, `supervise::delay`), as the `update` kernel ends right after the update applies.

**Rejected in the design:** reloading a file without a new image (a second write path, D-030); configuring the `quiet` window (a short one would let a file restart `infer` mid-generation); a health check by `process_usage` CPU time (a busy service and a hung one look the same).

### AI services (M4.6, D-031)

**Planned, not implemented.** Design approved (#181, 2026-11-09). D-031 (#180): `infer` and the agent runtime keep their M4.2 manifests, each capability justified; adversarial tests run hostile programs under their exact manifests; failure tests crash, hang, and exhaust each, then check the rest of the system; KPTI and user-mode `rdtsc` are carried to M5.2.

**Manifests, line by line** (the boot table; checked live by the `system` audit since #158):

| Service | Handle | Capability | What for |
| --- | --- | --- | --- |
| `infer` | 1 | debug console, `WRITE` | its log: model loads, failures, generation times |
| | 2 | its endpoint, `RECEIVE` | serving clients, told apart by badge |
| | 3 | `init`'s report endpoint, `SEND`, its own badge | `ready`; answering health checks |
| | 4 | the store, `models` read-only | loading and verifying model files |
| | — | 1 GiB page limit; no gains | the S1 model, its cache, and clients' buffers (D-011) |
| `agents` | 1 | debug console, `WRITE` | its log, and agents' `LOG` lines (kept off the trusted console on purpose, `hostile`) |
| | 2 | its endpoint, `RECEIVE`, `SEND`, `GRANT` | serving agents and giving each a badged `SEND` (M4.2 review F2) |
| | 3 | `init`'s report endpoint, `SEND`, its own badge | `ready`; health checks |
| | 4 | the root filesystem, `READ` | agent programs and manifests |
| | 5 | `infer`, client 1 | its agents' inference, on its own badge |
| | 6 | `trust`, as the runtime | registering agents, approvals, the revocation channel |
| | 7 | the store, `agents` read-write | durable tasks |
| | 8 | `audit`, client 3 | records before each grant and action (records are stamped with client 3, so it cannot write as `trust` or `init`) |
| | — | 64 MiB page limit; gains its agents' process capabilities | carved for agents (D-022) |

Unchanged since #157: each line is used by the shipped code, so nothing is removed (#182 re-checks this against the code at the time). Nothing else depends on the runtime, and only the runtime depends on `infer`.

**Gaps to close (#182):**
1. **A hung `infer` stops the runtime from starting.** The runtime attaches its prompt buffer with a blocking `send` before it reports `ready` (`attach_prompt`); an `infer` that reported `ready` and then stopped receiving holds it there, so `init` counts the runtime as failed every 10 s and gives it up. Fix: attach with `try_send`, start without the buffer, and treat inference as stalled (`BUSY`, D-022) until an attach succeeds, as after an `infer` restart today.
   - *Implemented (#182):* `attach_prompt` sends with `try_send_cap` for at most 100 ms (`ATTACH_US`), at start and on `NO_BUFFER`; at start a failed attach is logged (`agents: inference service not taking requests; starting without it`) and inference starts stalled, so the first request asks `INFO` (50 ms) and is `BUSY` if unanswered, or attaches on its `NO_BUFFER` if answered. The `aifail` kernel shows the runtime ready beside a hung `infer` (`rogue` 3, the `aifail` table: the boot table with one program changed, host-tested). An inference request from an agent is not exercised there, as the boot policy table runs none; the stalled path is the one `fairness` tests for the network service.
2. **Page limits are not held against memory.** `infer`'s limit (1 GiB) is above the 256 MiB CI guest, so a runaway `infer` can take every free frame. Whether the other services keep working depends on whether they allocate after start. The `exhaust` round measures it; if any service or `trust` fails, the fix is chosen then and recorded (most likely a reserve of frames the kernel keeps for the trusted and services classes), with its own test.
   - *Implemented (#182; the maintainer chose the trusted reserve, D-022 amended):* measured first: `rogue` as `infer` held 185 MiB of the 256 MiB guest, and `trust` could not start (`spawn failed, error 7`). The kernel now keeps 2,048 frames (8 MiB) only the trusted class may take (`process::TRUSTED_RESERVE`; `may_take`, host-tested, in `mem_map` per batch and in `spawn` for the child's class before its program is loaded). The `aifail` kernel tells `rogue` to take all it may and keep taking every freed frame, kills `trust`, and `init` starts it again, ready. Mutation-checked: without the reserve `rogue` leaves 0 frames and `trust`'s restart fails. Not covered: `fs_mount` copies (only `init` mounts) and `dma_alloc` (drivers, not AI services). Services still share what is left, so a runaway `infer` can starve `store`, `audit`, and `knowledge` until the user stops it from `trust`.

**The hostile services (`compromised` kernel, #183).** A test table whose `infer` and `agents` entries are the boot entries with only the path changed, to a new program `rogue` (argument 1: as `infer`; 2: as the runtime); a host test requires every other field equal to the boot entry. Each probe prints its result, and the kernel test checks every one:
- every handle from 1 to 64: `send`, `receive`, `open`, `config_read`, `mmio_map`, `dma_alloc`, `irq_create`, `process_stop`, `spawn` refused unless the manifest grants it;
- system calls given kernel addresses (`debug_write` from, `receive` into, `mem_share` of the kernel half): refused, nothing read or written;
- `mem_map` past its page limit: refused;
- forged requests on every endpoint it holds: `init`'s `START`, `STOP`, `RESTART`, `CONFIG`, `SERVICES`, `RUNTIME`, `ALLOW`, and `RELEASE` (`NO_ACCESS`); the store writing `models` (as `infer`) or reading another namespace; as the runtime, `audit` records with actor `user` (stored with client 3), and to `trust` `RESOLVED` for an approval it never asked and `REGISTER` with a capability that is not a process (both ignored);
- last, a direct read of kernel memory (as `infer`) or a write (as the runtime): the process is killed with a page fault, and `init` restarts it by its policy and gives it up.

The capability audit runs at ready and must match the manifests. `rogue` holds only what `init` gives, so no new kernel code or `unsafe`.

- *Implemented (#183):* the `compromised` table (argument 6, host-tested with `aifail`'s: every field but the program and argument as shipped) and kernel. `rogue` 1 makes 83 attempts as `infer` and `rogue` 2 makes 86 as the runtime, each printing only what succeeds and then its tally; the kernel requires both tallies exact with none allowed, every service ready, the capability audit matching (run once the probes end, so nothing held briefly counts), and no service started, stopped, restarted, or killed. The runner types `services` and refuses `registered rogue` on the trusted console. Mutation-checked: the store ignoring its read-only bit lets `rogue` append to `models` (`ALLOWED store APPEND to models`).
- **Changed from the design:** no direct read or write of kernel memory at the end: it needs `unsafe` in `pharos-user` beyond its reviewed uses, and `user_mode` already shows any ring-3 process killed for it (capabilities do not change the kernel half's mapping). Kernel addresses go through `debug_write` and, as the runtime, `read` into a kernel address (`pharos_user::probe`, which refuses user addresses itself), `mem_share`, and `mem_unmap`. `audit` records with actor `user` are not probed: the service stamps each with the client's badge (`audit.rs`). `init` now finds the runtime by its manifest (`Service::is_runtime`, receiving on its endpoint, host-tested) rather than its program, so `rogue` under the runtime's entry gets its agents' budgets and `trust` its `STOP`, as the runtime does.
- **Found:** a runtime that becomes ready within about 1 s of `trust` lost `system ready`: `trust`'s first call to `init` (`RUNTIME`, 1 s) is unanswered during boot, and `init` gives each event to `trust` only 100 ms (`tell_trust`). With the runtime found by its manifest, `init`'s blocking hand-over of its `STOP` waits for `trust` first; the 100 ms window itself was M4.6 review F1, fixed: `init` queues what `trust` does not take at once and offers it again from its loop, keeping each for 2.5 s (`pharos_proto::trust::EVENT_US`), longer than any one wait of `trust`; it never waits on `trust`. Also: `trust` takes any non-process capability the runtime sends with `CHANNEL` as its revocation channel, so a compromised runtime can replace it; revocations reach only the runtime's own agents, which it already controls.

**Failure (`aifail` kernel, #184).** Booted like `system`, in three rounds:
- `crash`: the kernel kills `infer` and the runtime 4 times each (`process::kill`); both are given up.
- `hang`: a table whose `infer` is `rogue` 3 (`ready`, then never receives): the runtime still reports `ready` (gap 1), and an inference request from it is `BUSY`.
- `exhaust`: `rogue` 4 as `infer` maps pages until refused and holds them (gap 2).

After each, the runner types on the trusted console and checks the answers: `services`, `health`, `audit` (the trail still grows), `stop all`, and a knowledge `verify` (the store and knowledge still answer); then `start infer` and `start agents` (`restart` in `hang`), and both are ready and answer a health check.

- *Implemented (#184), in one boot of the `aifail` kernel (about 15 s), in this order:* the hang (`rogue` 3 as `infer`; the runtime starts without it, #182); the crash (the kernel kills the runtime 4 times, `init` gives it up, and the runner types `services`, which shows `agents failed, restarts 3 of 3`, and `stop all`); the runaway (`rogue` takes every frame it may, #182) with `trust` killed and started again; then, on the new `trust`, `stop service infer` (its memory back), `audit` (the trail still answers), `start infer`, `start agents`, and `health`, where `infer`, `audit`, `knowledge`, and the runtime are ready again with their restarts at 0. Mutation-checked: `init` not resetting the restart count on `start` (`health` shows the runtime's restarts used up).
- **Changed from the design:** one boot instead of three rounds, crash before the runaway (the runtime's restarts would otherwise fail for memory, which the runaway round covers); the crash is the runtime's, since `rogue` stands in for `infer` and the `system` kernel already gives up a killed `infer`; the knowledge service is shown by `health` (ready, answering `init`'s checks) rather than `verify`, which needs an entry; `stop all` runs once the runtime is gone, and `trust` answers at once.

Not covered: a hang longer than `infer`'s 600 s window (the `health` kernel tests the give-up with a 30 s window); side channels (D-031, M5.2).

## 4. Security

- **The trust boundary is unchanged:** every process, `init` included, is untrusted by the kernel. `init` holds the most authority (every device, the root filesystem). It is small, and its service table is reviewed code.
- **Least privilege:** a child gets only the capabilities listed in `spawn`, each narrowed, and only from capabilities the parent holds with `GRANT`. Badges cannot be forged or changed by their holders.
- **Revocation** reaches children through the derivation tree, as before.
- **Kernel resources:**
  - 32 live processes, 12 capabilities per `spawn` (8 until #144);
  - notifications are a fixed word per endpoint;
  - process status records live as long as their capability.

  `spawn` checks all limits before allocating. The process limit also bounds what a spawn loop can take.
- **Notifications** carry no data: a forged or coalesced bit only makes a receiver re-check its source. Only the kernel sets them, and only on endpoints the binder receives on.
- **Untrusted programs:** program files come only through file capabilities, so `init` can start only programs from the filesystems it was given. The ELF loader is unchanged.
- **Runtime management (M4.4, #170):** only `trust`'s badge reaches `START`, `STOP`, and `RESTART`, so an agent or service cannot stop anything; a start uses only a compiled entry's manifest, so it adds no authority the capability audit does not already check; `trust`, `audit`, and `store` cannot be stopped, so no command ends the console or the audit trail.
- **Configuration (M4.5, D-030, implemented, #176):** a file can only lower restart limits, change delays within a range, and not start services nobody needs; it names no capability, program, or manifest, so the capability audit (D-027) is unchanged; `trust`, `audit`, and `store` always start, with their compiled restart limits and delays (review F3); it changes only with a signed image the user applied, and recovery ignores it.
- **Health checks (implemented, #177):** `init` sends only `INFO`, which changes nothing; a service can hide a hang from its callers but not from the check; a check costs `init` at most 100 ms.
- **AI services (M4.6, D-031, planned):** `infer` and the runtime hold only their manifests, checked live; hostile programs under those manifests and the failure rounds above are the evidence (#183, #184). Side channels (no KPTI, `rdtsc`) are open until M5.2.
- The threat model gains a "Processes and services" section (planned).

## 5. Testing

| Layer | Tests |
| --- | --- |
| Host, `cap` | Badge rules: set once, kept when narrowed, never re-badged |
| Host, `ipc` | Notification bits: set, coalesce, returned before messages, cleared |
| Host, `syscall` | Decoding and the fuzz test cover the new calls; the `spawn` array and its limits |
| QEMU, `spawn` | A parent starts a child with two capabilities (one badged); the child uses them; the parent gets the exit notification and code. A killed child reports its vector. Refused, with no frame lost: a file without `READ`, a capability without `GRANT`, a malformed program, more than 12 capabilities (12 accepted, #144), the process limit |
| QEMU, `services` | `init` with a test table: services start in order; a crashing service is reported by name and its dependents skipped, while independent ones still start; a missing program is reported; the summary reaches the kernel |
| Boot check | The main kernel starts `init`, the boot services succeed, and `PHAROS: boot ok` follows the summary; each boot's audit stream has a start record for each of the 8 boot services and `init`'s `ready 8 services` (#151) |
| Host, `pharos_programs::supervise` (#150) | `delay` for `Never` and `Up(n)`: 0.1, 0.4, 1.6 s, then none; dependents through `after`, directly and through others |
| Host, `pharos_proto::service` (#152) | `SERVICE`, `SERVICES`, and the reply round-trip; truncated, trailing, and unknown fields refused; fuzzed |
| QEMU, `supervision` (#150, #152) | each policy: `Never` not restarted, `Up(n)` restarted n times no sooner than each delay, then given up; no `ready` in 10 s counted as a crash; a stopped service never restarted; each event one audit record and one `trust` line; mutation-checked |
| QEMU, `system` (#151, #153) | the boot table to ready (console and trail), a restart with its dependents, a stop, a give-up, `services`; mutation-checked |
| Host, `pharos-services` (#157) | each manifest rule on the boot and test tables; a table breaking each rule refused |
| Host, `pharos_services::config` (#176) | each key and refusal in the table above, with its line and text; restarts over the limit refused, not narrowed; protected services, drivers, and needed services kept on; `restarts` and `delay_ms` refused for protected services (review F3, mutation-checked); fuzzed (random text and mutations of a valid file: never a limit over the compiled one, never a protected service off) |
| Host, `pharos_programs::system` (#176) | `image_config`: no file, a good one, one over a limit, one over 4 KiB, a corrupt image |
| Host, `pharos_programs::supervise` (#176) | a configured first delay, and the longest one saturating |
| Host, `xtask` (#176) | a bad `etc/system.conf` refused by the builder with its line; the shipped root accepted |
| QEMU, `update` (#176) | round `config`: updates whose files turn `audit` off (line 3) or ask 9 restarts of `knowledge` (line 4) refused at offer with their lines, never offered; one with `net` off applied, and `net` not started from it |
| QEMU, `recovery` (#176) | round `bad-config`: slot A whose file turns `audit` off refused at boot and bad, slot B runs; round `next-safe`: slot A's file turns `net` off, and safe mode ignores it |
| Host, `pharos_programs::supervise` (#177) | `unresponsive`: each service's window, an answer after `now`, two checks in every window; the runtime's window above twice `GENERATE_US` and a check (review F1, mutation-checked) |
| Host, `pharos_proto::service` and `trust` (#177) | entries with uptime and last check; `CONFIG` and `Settings` round-trip, cut, bad flags, fuzzed; event 15; `health` and `config` parsed |
| QEMU, `health` (#177) | `init` with its `health` table: `net` (`svc` 1, ready, never receives on the network endpoint) found unresponsive after 30–41 s, stopped, restarted once by its policy, unresponsive again, and given up; `steady`, whose name no endpoint has, never checked or stopped |
| QEMU, `manage` (#177) | no boot service is ever unresponsive over the whole run (21 restarts of `trust`); `health`, before the restarts, shows an answered check for every ready daemon, 7 of them (review F2; mutation-checked: no round at ready, `net` shows `no answer yet`), and the runtime's process; `config` says the factory image's file sets every compiled value |
| QEMU, `system` with the capability audit (#158) | every live service's table against its manifest and gains, at ready and after the faults; mutation-checked (one capability more) |
| Host, `pharos-services` (#183) | the `aifail` and `compromised` tables equal the boot table except `rogue`'s program and argument; `is_runtime` finds only the runtime's entry |
| Host, `pharos-services` (#189) | the `soak` table (argument 7) is the boot table with the runtime's argument 1 and `soaker` after it |
| QEMU, `compromised` (#183) | all 83 and 86 probes refused; the capability audit matches; nothing started, stopped, or restarted; `trust` shows no forged registration; mutation-checked (the store's read-only bit ignored) |
| QEMU, `aifail` (#182) | a hung `infer`: the runtime still starts and is ready; mutation-checked (the blocking attach). A runaway `infer` taking every frame it may: the trusted reserve stays free and `trust` restarts; mutation-checked (no reserve) |
| QEMU, `aifail` (#184) | the runtime crashed until given up, then `services` and `stop all`; after the runaway and `trust`'s restart, `stop service infer`, `audit`, `start infer`, `start agents`, and `health` with both ready again; mutation-checked (no restart reset on `start`) |

## 6. Alternatives

- **A receive-any call over several endpoints** (D-015 as first accepted): it keeps identity in the kernel's endpoint objects. But a thread would wait in several queues at once and be claimed by the first sender, which is harder and more race-prone than a badge field. Replaced by badges (D-015 amendment).
- **Interrupts and exits as queued messages:** these need buffering in the kernel per event. Notification bits are bounded and safe in interrupt handlers.
- **The kernel starts every service from a list:** this needs no `spawn`, but puts service policy in the kernel.
- **A blocking `wait` on a process:** it cannot be combined with waiting for messages; notifications can.

## 7. Open questions

- **Timeouts:** a timer notification source, so `init` can give up on a stuck service.
- **Restart counts per boot** (D-026): a service that crashes once a week gives up after its third crash. Recommended for M4.1: keep per boot, and reset a count once the service has been ready for some time if a real service needs it.
- **Killing a process** through its capability.
- **Loading the service table from a file** instead of compiling it in.
