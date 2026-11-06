# Processes and system services

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-28 (M2.10, #59). It follows [D-015](../project/decision-log.md#d-015-network-stack-and-service-model) (as amended on 2026-10-28: badges instead of per-client endpoints), [D-014](../project/decision-log.md#d-014-ipc-model-and-system-call-mechanism) (IPC), and [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries). Networking is in [networking.md](networking.md).
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
- **The kernel** polls the report endpoint (a kernel task has no inbox, so it uses `Endpoint::try_take`) for up to 30 s, and prints the summary. Under QEMU it then prints `PHAROS: boot ok` and signals success only if no service failed. If no report arrives in 30 s, the boot fails. A boot with a failing service fails the boot check, so CI catches broken services.
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
- **`services` on the trusted console:** `trust` asks `init` with a call on the report capability it already holds (badged with its table index; `init` answers only that badge), new operation `SERVICES` (from an index, for paging); `init` answers each service's name, state (`starting`, `ready`, `done`, `restarting`, `failed`, `skipped`, `stopped`), restarts done, and its policy's limit. `trust` prints one line each, or `services: init is not answering` after 1 s. `init`'s answer is the authoritative state; `trust` keeps none.
- **The interface:** `pharos_proto::service` (D-019): `SERVICE`, `SERVICES`, and its reply, version 1, host-tested and fuzzed like the other interfaces.

- *Implemented (#152):* every event goes through one path in `init`: its debug line (`init: <name> <what>`, as before), an audit record (action `service`, actor the service's table name, detail `<what>` cut to 64 bytes), and `SERVICE` to `trust`. `SERVICE` stayed in `pharos_proto::trust` (#151) and gained `NotStarted` (event 10: missing program, no device, or a spawn error and its code), so a start failure is reported too. `pharos_proto::service` holds only `SERVICES` `[version, op, from]` and its reply `[OK, total, count, entries]`, each entry its name, state (also `pending`, for entries not started yet), restarts done, and limit, as many as fit in one message. `init` answers it only on `trust`'s badge, without waiting; `services` prints `services: <name> <state>, restarts <n> of <limit>` per entry, or `services: init is not answering`. `init`'s states now tell `skipped` and `stopped` from `failed`.
- *Changed from the design (#152):* records are no longer dropped before the audit service is ready or while it cannot write. `init` queues up to 32 (dropping the oldest) and sends them oldest first, retrying after 1 s, doubling to 60 s. Without the queue, the `supervision` kernel lost the events of the 2 s in which the store restarted. Delivery is at least once: a record the store wrote just before it was killed is sent again, so it can be in the trail twice (seen for `store killed 13`).

**The end-to-end test (#153).** A new test kernel, `system`, boots `init` with the boot table and the boot image's disks and devices, and checks ready on the trusted console and in the trail; then kills the knowledge service (restarted after its delay, its dependents named), stops `net` itself (as a stop, never restarted; `trust` stops agents, not services), and kills one service past its restarts (given up); `services` shows each state, and every event is one audit record.

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
