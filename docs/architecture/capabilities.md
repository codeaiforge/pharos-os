# Capabilities: agent permissions, revocation, approval, and audit

## 1. Status

**Planned. Design approved by the maintainer on 2026-11-03 (#103),** with zeroed pages on revocation, the trusted console as the audit chain's anchor, and approvals limited to 60 s and 4 waiting. Built by: kernel revocation of mapped memory (#104), runtime permissions (#105), approval on the trusted path (#106), the audit service (#107), auditing every consequential action (#108), agent networking (#109), and adversarial tests (#110). **Implemented:** kernel revocation of mapped memory (#104), runtime permissions with `revoke` on the trusted console (#105), approval on the trusted path (#106), the audit service (#107), auditing every grant, revocation, and consequential action (#108), and agent networking (#109).

## 2. Context

M3.3 runs agents that hold one capability, `SEND` on the agent runtime, and are granted only what a compiled-in policy table allows ([agents.md](agents.md)). They can always be stopped from the trusted console, and stopping is the only revocation. D-012 (final, #102) decides M3.4:

- permissions from the policy table, and beyond it only with the user's approval on the trusted path, for one task (item 7);
- revocation per permission while the agent runs, and memory unmapped by the kernel at once (item 8);
- expiry on runtime grants only (item 9);
- default-deny networking per destination, checked by the runtime and by the network service (item 10);
- every consequential action audited, and refused while the trail cannot be written (item 11).

What M3.4 builds on:
- **Kernel revocation** marks every capability derived from the revoked one, and each fails its next lookup (M2.7). Memory already mapped through a revoked `Memory` or device capability stays mapped (carried from M2.9 and M3.0).
- **The store's streams** are append-only and chain each record with SHA-256, checked on mount (D-017). Nothing writes audit records yet, and the chain's head is not anchored.
- **The network service** gives each client one UDP port (its badge) and lets it send anywhere (carried from M2.10; per-client destinations since #109).

## 3. Design

### Permissions (#105)

- **A permission is a grant in the runtime**, never a kernel capability held by the agent. The agent keeps its one capability; the runtime checks the permission on every request that needs it. Kinds:
  - `model <n>`: inference with manifest model *n* (exists today as the manifest's model mask);
  - `data read` or `data write`: the agent's own files, kept by the runtime under `data/<agent>/` in its store namespace (new; agents have no files today);
  - `net <address>:<port>`: UDP datagrams to one IPv4 destination, and its replies (#109).
- **The policy entry** lists, per agent, what it *gets* (granted at task start, as today) and what it *may ask for* (granted only by approval). Anything in neither list is refused without asking, so an agent cannot flood the user with requests for things nobody planned. The manifest may ask for less than the entry's *gets*, never more; it still cannot widen the entry.
- **Grants are per task attempt**: rebuilt from the entry and the manifest when the attempt starts, plus the approvals given for this task. Nothing is remembered across tasks (D-012 item 7).
- **Expiry:** each grant may carry a deadline in `uptime` microseconds, checked on every request that uses it; past it, the grant is gone as if revoked (D-012 item 9).
- **Revocation** takes a grant away while the agent runs: the next request that needs it answers `NO_ACCESS`, and an inference session or network flow opened with it is ended at once. The agent keeps running and can finish without it.
- **Who revokes:** the user on the trusted console (`revoke <agent> <permission>`), and the runtime itself on expiry. Revocations are audited.
- **The logic** (a task's grants, checks, expiry, revocation) is a host-tested `no_std` module, as the task logic is.
- *Implemented (#105):* `pharos_proto::permission` (the wire and typed forms), `pharos_programs::grants`, the manifest key `data` with the policy entry's `data` field, `DATA_PUT` and `DATA_GET`, and `revoke` on the trusted console. The *may ask for* list and approvals came with #106, network grants with #109. Revoking `data read` or `data write` takes all data access. A revocation also holds when the task's agent restarts (the runtime keeps it by task, in memory). `trust` sends `REVOKE` with a non-blocking send for at most 2 s and says the runtime is not answering if it cannot; the runtime answers `REVOKED` the same way, for at most 1 s.

### Kernel: revoking mapped memory (#104)

- *Implemented (#104):* `process::revoke`, which the `revoke` call uses; `shared_memory` and `device_caps` test it.
- **Revoking a `Memory` or device capability ends every mapping made through it or a capability derived from it, in every process, before `revoke` returns.** Each mapping records the capability it was mapped through, so the kernel finds them by walking the processes' mapping lists; the TLB entries of the current address space are flushed, and others are flushed when the processes are next switched to (no PCID).
- **A revoked mapping becomes private zeroed memory, not a hole.** Its pages are replaced by fresh zeroed frames, already counted against the mapper's page limit, so the mapper reads zeros and its writes go nowhere. Reason: the side that shares a buffer is often the untrusted one. An agent shares its buffer with the runtime, so with plain unmapping it could revoke the buffer while the runtime copies from it and crash the runtime, and with it every agent. If no frames are free, the pages are unmapped instead, and the next access faults.
- **Frames are freed** when the last mapping and capability are gone, as now; the original frames are never reachable again through a revoked capability.
- **Device registers and DMA buffers** are revoked the same way, so `init` can take a device from a driver without stopping it (the zeroed pages reach no device).

### Approval on the trusted path (#106)

- **An agent asks** with a new runtime request, `ASK <permission>`, which answers `GRANTED`, `REFUSED`, or `PENDING`. While `PENDING`, the agent asks again with the same request (each ask counts as progress), so the runtime never waits.
- **The runtime asks `trust`** with a new `trust` operation, `APPROVE` (request number, agent slot, task ID, permission kind and value, optional deadline), all fields structured. `trust` builds the console text itself from them: `approve #3: worker task 12 wants net 10.0.2.2:47000 for this task? (yes 3 / no 3)`. An agent controls only which listed permission it asks for, never the text.
- **The user answers** `yes <n>` or `no <n>`. `trust` sends the answer to the runtime with a non-blocking send on a `SEND` capability badged for answers, which the runtime gives it at start; `trust` never waits on the runtime. **No answer within 60 s, `no`, a full queue, or `trust` unreachable mean no** (D-018 item 4). At most 4 requests wait at once; more are refused without asking.
- **Approvals hold for the task** (or until their deadline) and are audited with the user's answer.
- *Implemented (#106):* `ASK` (`GRANTED`, `REFUSED`, `PENDING`) and `ANSWER` in `agents`, `APPROVE` and `RESOLVED` in `trust`, and the policy entry's `ask_models` and `ask_data` (network destinations became askable with #109: `ask_net`). The runtime decides every outcome, including the timeout (60 s; 5 s with the test policy table, so the test fits the runner's limit), and tells `trust` with `RESOLVED`, which `trust` shows: `granted`, `refused`, `no answer; refused`, or `the task ended`. `trust` keeps the open request numbers only to answer `no request #<n>` for any other. A refusal or an unanswered request holds for the task: asking again is refused without a prompt. An approval also comes back when the task's agent restarts. Auditing comes with #108.

### Agent networking (#109)

- **Agents have no network unless granted** `net <address>:<port>`. Datagrams go through new runtime requests (`SEND_TO`, `RECEIVE_FROM`, payload through the agent's buffer); the runtime checks the grant and forwards to the network service on its own client port.
- **The network service checks destinations too.** `init`'s table gives each network client a list of allowed destinations as well as its port, sent with a new request accepted only under `init`'s badge, as `RELEASE` is. A client sending elsewhere gets `NO_ACCESS`. The runtime's list is the union of the destinations in the policy table, so a runtime bug cannot reach anything nobody listed.
- Replies are delivered only from the granted destination.
- *Implemented (#109):* the manifest key `net` (destinations, comma-separated, at most 4, each in the entry's `net`) and the policy entry's `net` and `ask_net`; `SEND_TO` (14) and `RECEIVE_FROM` (15) in `agents` with the `Datagram` reply; handle 9 of the runtime, `SEND` on the network service badged with its port 40100; `ALLOW` and `POLL` in `net` ([networking.md](networking.md)), with `init` sending every client's list each time the service reports ready (the runtime's boot list is empty, as its boot policy table is). A send needs the grant, at most 248 bytes, and its `INTENT` stored (else `NO_AUDIT`); the network service's own answer (`NO_ACCESS` for a destination it does not list, `BUSY` while one waits for ARP) is passed on. The runtime cannot wait on a deferred `recv` (it serves one message at a time, and the service drops a reply its caller is not waiting for), so `RECEIVE_FROM` polls the service (`POLL`), keeps each datagram for every running agent that sent to its source (at most 4 each, the oldest dropped), and gives one only if the agent still holds that grant, so a revoked or expired destination's replies are dropped. `RECEIVE_FROM` answers `NOT_FOUND` at once when nothing is waiting; the agent polls. Revoking `net` takes only that destination. Limit: two agents granted the same destination that both sent to it both get its replies, since they share the runtime's port.

### The audit service (#107)

- **A new trusted service, `audit`,** started by `init` after the store and before `trust` and the runtime. It holds a new store namespace, `audit` (6, read-write, held only by it), and appends records to one stream per boot, `log/<boot>`. Clients (`init`, `trust`, the runtime) hold `SEND` badged with a client number; the service writes that number into each record, so a client cannot write as another.
- **A record** is binary and fixed in form: sequence number, `uptime`, client, actor (agent name, task, attempt, or the user for `trust`), action, permission or capability, the service used, outcome, and up to 64 bytes of detail. Text fields are checked as names are. The store chains each record's SHA-256 with the previous one and checks the chain on mount (D-017).
- **Write before acting.** A consequential action (D-012 item 11) is preceded by an `INTENT` record and followed by an `OUTCOME` record. The runtime acts only after the `INTENT` was stored; if the service cannot write (store full, failing, or unreachable within its timeout), the action is refused with a new status, `NO_AUDIT`. A missing `OUTCOME` (crash between) shows as an intent without an outcome.
- **The anchor is the trusted console.** At start and on the `audit` command, `trust` prints the newest chain head and record count, which the service reports to it; the user can compare them with what was shown before. A disk edited offline cannot recompute the chain to a head the user already saw, and a truncated stream shows a smaller count. A secret-keyed anchor would need a key outside the store and outside the reproducible boot image; it is left to signed updates and keys (M4.3).
- **Reading** the trail is a host tool: `cargo xtask store audit <store image>` verifies the chain and prints the records; one operation can be reconstructed from its `INTENT` and `OUTCOME` (#108).
- *Implemented (#107):* `bin/audit` and `pharos_proto::audit` (`APPEND`, `HEAD`, the record format, client numbers 1 `init`, 2 `trust`, 3 the runtime), namespace 6 `audit`, `init` starting it after the store and before `trust` (which gets client 2 and shows the anchor at start and on `audit`), and `cargo xtask store audit`, which also checks that sequence numbers run from 0 and record 0 is the service's `boot` event. The new status for refused actions is the service's `UNWRITABLE`; `NO_AUDIT` for agents comes with #108. With no store, the service still runs and answers `UNWRITABLE`; a restarted service starts a new stream. No client writes records yet except the tests (#108). Records stay well under the store's 200-byte inline limit (at most 172 bytes).

### What is audited (#108)

- **Grants and revocations:** `init`'s grants at service start, each task attempt's grants, approvals and refusals, revocations, expiries, and stops from the trusted console.
- **Consequential agent actions** (D-012 item 11): inference, store writes for the agent, network sends, and task submissions and cancellations.
- **Not audited:** reads of the agent's own task, checkpoints, `LOG` lines (on the console), and control requests that change nothing.
- *Implemented (#108):* the runtime (client 3, handle 8) records each grant at the start of an attempt and gives none whose record fails; an approval is given only once recorded (else it is refused); revocations, expiries, and refusals always take effect and are recorded when the trail can be; inference, `DATA_PUT`, `SUBMIT`, and `CANCEL` are each an `INTENT` stored before acting (else `NO_AUDIT`, the new status in `agents`) and an `OUTCOME` after. An audit record may take 2 s before the action is refused. `trust` (client 2) records the user's stops (after stopping), revocations, and answers as actor `user`; `init` (no badge, client 1) records a `start` for each service, also those started before the audit service was ready. Network sends are recorded the same way since #109 (`net send`, with the destination). While the trail is down, `SUBMIT` and `CANCEL` are refused too; stopping agents never depends on it (the trusted console's `stop` works regardless).

### The sandbox

What an agent process can do on Pharos, each a check in the adversarial tests (#110):
- it holds exactly one capability, `SEND` on the runtime with its slot's badge, and cannot get another (no message carries one to it: the runtime's replies carry none);
- it cannot spawn, open files, map devices, or create endpoints, because each needs a capability it lacks;
- its memory is limited by its manifest's page limit within the policy entry;
- every request is checked against its own slot's grants, so another slot's badge, task, session, or buffer is unreachable;
- it cannot reach the trusted console, the audit service, or the store, except through runtime requests that are checked and audited.

CPU time is not limited per agent yet (M3.5).

## 4. Security

- **Trusted for permissions:** the runtime (checks, attribution) and `trust` (approvals, revocations). The kernel enforces that agents hold nothing else.
- **Trusted for the trail:** `audit` and the store. `init`, `trust`, and the runtime are trusted to report what happened; the badge on each record shows which of them did.
- **Untrusted:** agents, their requests, the text they log, and the permissions they ask for.
- **Approval fatigue:** only permissions listed as askable are asked for, at most 4 at once, each with a timeout that means no.

## 5. Testing

- **Host:** the permission logic (grant, narrow, expire, revoke), the `ASK` and `APPROVE` codecs, the audit record format and chain (a changed, removed, reordered, or appended record detected), the destination checks; fuzzed parsers.
- **QEMU:**
  - revocation: a revoked buffer reads zeros in its mapper at once, a revoked device too; an agent revoking its buffer during a copy does not crash the runtime (#104);
  - permissions: an agent loses a model mid-task and is refused, without a restart; an expired grant (#105);
  - approval: the runner answers yes, no, and nothing (#106);
  - audit: a task's operations reconstructed from the trail; an action refused while the store is full; a crash between `INTENT` and `OUTCOME` (#107, #108);
  - networking: a granted destination reaches the host echo endpoint, others are refused by the runtime and, for a direct client, by the network service (#109; `agents_net` and `network`);
  - adversarial: the hostile agent of #110.

## 6. Alternatives

- **Kernel capabilities for each permission, held by the agent:** revocation through the derivation tree, but the runtime could no longer cancel, time out, or (M3.5) budget requests, and the kernel would need a capability kind per service operation.
- **Plain unmapping on revocation:** simpler, but lets the untrusted side of a shared buffer crash the trusted side.
- **Permission text from the agent on the approval prompt:** clearer to read, but lets an agent write what the user sees on the trusted console.
- **Approvals remembered across tasks:** rejected in D-012 item 7.
- **An HMAC-keyed chain with a key in the boot image:** breaks the byte-identical image (D-003), and anyone with the disk has the image too.
- **Audit records written by each service directly to the store:** no single writer, so no one place to refuse when the trail is full.

## 7. Open questions

- What an agent should see when its `data` permission is revoked mid-write (the write is one commit, so it lands whole or not at all).
