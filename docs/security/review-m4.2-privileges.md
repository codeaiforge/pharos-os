# Security review: M4.2 privilege separation

- **Scope:** everything M4.2 added since commit `4e8549f` (the M4.1 gate):
  - D-027 and the design, [services.md](../architecture/services.md#capability-manifests-m42-d-027) (#155, #156);
  - `crates/pharos-services`: the tables written out as manifests, and `check` (#157);
  - `init`'s grants from the manifests, and the narrowed boot runtime (#157);
  - the capability audit, `kernel/tests/common/manifests.rs`, in the `system` kernel (#158);
  - each boot service's manifest, one by one, and every new `unsafe` block.
- **Design under review:** [services.md](../architecture/services.md), D-027, D-015, D-018, D-022, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-06, issue #159. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. One finding is fixed, three are recorded.
- **Status:** **approved** by the maintainer on 2026-11-06 (M4.2 gate, #159), with F2, F3, and F4 recorded.

## Method

1. Listed every changed file since `4e8549f` and searched the diff for new `unsafe` blocks: none. The kernel changed only in its tests, and its one new dependency (`pharos-services`) is a dev-dependency of the test kernels.
2. Read each boot service's code against its manifest: each capability used, and nothing used that is not listed ([services.md](../architecture/services.md#capability-manifests-m42-d-027) has the table).
3. Followed every way a service can come to hold a capability: `spawn` from `init`, a message (`send` and `call`), a call's reply, an object it creates, and `spawn` of its own.
4. Checked what the audit accepts as a gain, against what the kernel actually gives.
5. Turned each finding into a check that fails without the fix.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low (test) | The audit would refuse the runtime's own agents. A process capability from `spawn` carries `STOP`, `WAIT`, and `GRANT`, and the runtime needs `GRANT` to give `trust` each agent's `STOP | WAIT`. The audit allowed process capabilities only up to `STOP | WAIT`, so it would have reported the runtime as soon as an agent ran. The boot table runs none, so no run showed it. | **Fixed:** `GRANT` is allowed on a process capability only if the holder started that process. `trust`'s capability on the runtime, which `init` started, is still held to `STOP | WAIT`, and the `system` kernel checks that live. |
| F2 | Low | The runtime may pass on what it holds with `GRANT`: its own endpoint unbadged (`RECEIVE`, `SEND`, `GRANT`), its own objects, and its agents' process capabilities. An agent given its unbadged `SEND` would be anonymous on the runtime's endpoint. | **Recorded:** the runtime is reviewed code and gives each agent only a badged `SEND`, derived inside `spawn` (D-012); the `hostile` and `deputy` kernels test what an agent can reach. |
| F3 | Low | Mapped memory is not audited. A client's attached buffer stays mapped in the service after the service deletes its capability, until `RELEASE` or a new `ATTACH`. | **Recorded:** mappings are bounded by each service's page limit and freed on `RELEASE` (#100); they are memory, not authority. |
| F4 | Low | Only the boot table is audited live. The `services`, `network`, and `supervision` tables are checked by the host rules only. | **Recorded:** they run test programs; the boot table is what a system runs. |

## Who can hold what

- **A manifest capability cannot be passed on.** Sending a capability in a message needs `GRANT` on it (`syscall.rs`), and no manifest gives `GRANT` except on the runtime's own endpoint (a host rule). The kernel narrows rights on every derivation.
- **`init` gives exactly the entry.** `grant` copies each `Give`, refuses a badge-0 `SEND` on another service's endpoint, and the host rules refuse a table that would need it, gives `GRANT` without `RECEIVE`, gives rights that do not fit the object, or gives a device or a badge twice.
- **Gains are what the kernel gives:** a service's own objects (an endpoint carries every right, `GRANT` too, but no other process holds it), its devices' interrupts, files it opens from its root (`READ`), one-shot replies (revoked when the call returns), and process capabilities for `trust` and the runtime. The `system` kernel's audit prints each service's table: every handle is a manifest entry or one of these.
- **Narrowed:** the boot runtime lost its network, `files`, and knowledge capabilities (#157). The other seven services use everything they hold.

## Kernel

No kernel change outside `kernel/tests/`. `pharos-services` has no dependencies and builds for `x86_64-unknown-none`; it does not join the kernel's trusted computing base.

## Measured

The IPC round trip: 1,850 ns median (1,810–1,979 ns over 5 runs of 100,000, KVM), within D-004's 2 µs budget (M4.1: 1,856 ns).
