# Processes and system services

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-28 (M2.10, #59). It follows [D-015](../project/decision-log.md#d-015-network-stack-and-service-model) (as amended on 2026-10-28: badges instead of per-client endpoints), [D-014](../project/decision-log.md#d-014-ipc-model-and-system-call-mechanism) (IPC), and [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries). Networking is in [networking.md](networking.md).
- **Implementation:** `endpoint_create`, `spawn`, `process_status`, badges, and endpoint notifications are **implemented** (#60: `cap::Capability::derive_badged`, `ipc::Endpoint::signal`, `process::ProcessRecord`, `pharos_user::{spawn, Grant, Received, Status}`; tested by the `spawn` test kernel with the `spawner` and `child` programs). So is `init` (#61: `user/programs/src/bin/init.rs`, `process::init_capabilities`, `ipc::poll` for the kernel's wait on the report; the main kernel starts it at boot, and the `services` test kernel runs its test table with the `svc` program). The boot table has only `virtio-blk` until the network service exists (#63). So is `irq_notify` (#62: `irq::Vectors::bind`, kernel-side bindings beside the vector table). So are `call` and non-blocking `send` (#63: `ipc::call`, `ipc::try_send`, `Endpoint::offer_now`, `Endpoint::is_idle`).

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
| 15 | `spawn` | file, argument, capability array, count (≤ 8; since M3.0 bits 32–63 carry the child's page limit, [user-environment.md](user-environment.md#user-memory)), endpoint (0 = none), bit | new process handle | file `READ`; each passed capability `GRANT`; endpoint `RECEIVE` |
| 16 | `process_status` | process | 0 while running, else how it ended | process `WAIT` |
| 17 | `irq_notify` | interrupt, endpoint, bit (0–31) | 0 | interrupt `WAIT`; endpoint `RECEIVE` |
| 18 | `call` | endpoint, buffer, length (≤ 256), reply endpoint, maximum reply length | as `receive` | endpoint `SEND`; reply `SEND`, `RECEIVE` |

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
  - Returns a **process capability** with `WAIT | GRANT`.
- **`process_status(process)`** (needs `WAIT`) returns:
  - 0 while the child runs;
  - once it has ended: bit 63 set, with bit 62 set if it was killed (low bits: the exception vector), otherwise the exit code in the low 62 bits.

  The status stays readable as long as the capability exists.
- **Checks, before anything is allocated:**
  - the handles and their rights;
  - the array (range, count ≤ 8);
  - the live-process limit (`MAX_PROCESSES` = 32, kernel-wide).

  Then the ELF checks (`BAD_PROGRAM` on failure). On any failure nothing is created and no frames are lost.
- **Not in M2.10:**
  - killing another process;
  - restarting;
  - passing memory;
  - a process outliving its last capability is fine. The process capability only observes; dropping it does not end the child.

### `init`

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

## 4. Security

- **The trust boundary is unchanged:** every process, `init` included, is untrusted by the kernel. `init` holds the most authority (every device, the root filesystem). It is small, and its service table is reviewed code.
- **Least privilege:** a child gets only the capabilities listed in `spawn`, each narrowed, and only from capabilities the parent holds with `GRANT`. Badges cannot be forged or changed by their holders.
- **Revocation** reaches children through the derivation tree, as before.
- **Kernel resources:**
  - 32 live processes, 8 capabilities per `spawn`;
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
| QEMU, `spawn` | A parent starts a child with two capabilities (one badged); the child uses them; the parent gets the exit notification and code. A killed child reports its vector. Refused, with no frame lost: a file without `READ`, a capability without `GRANT`, a malformed program, more than 8 capabilities, the process limit |
| QEMU, `services` | `init` with a test table: services start in order; a crashing service is reported by name and its dependents skipped, while independent ones still start; a missing program is reported; the summary reaches the kernel |
| Boot check | The main kernel starts `init`, the boot services succeed, and `PHAROS: boot ok` follows the summary |

## 6. Alternatives

- **A receive-any call over several endpoints** (D-015 as first accepted): it keeps identity in the kernel's endpoint objects. But a thread would wait in several queues at once and be claimed by the first sender, which is harder and more race-prone than a badge field. Replaced by badges (D-015 amendment).
- **Interrupts and exits as queued messages:** these need buffering in the kernel per event. Notification bits are bounded and safe in interrupt handlers.
- **The kernel starts every service from a list:** this needs no `spawn`, but puts service policy in the kernel.
- **A blocking `wait` on a process:** it cannot be combined with waiting for messages; notifications can.

## 7. Open questions

- **Timeouts:** a timer notification source, so `init` can give up on a stuck service.
- **Restarts** and a supervision policy.
- **Killing a process** through its capability.
- **Loading the service table from a file** instead of compiling it in.
