# Security review: M2.10 services and networking

- **Scope:** everything M2.10 added at the boundaries between processes, services, the network, and the kernel (since commit `381f367`, the M2.9 gate):
  - process creation from user space (`spawn`, `process_status`, `endpoint_create`);
  - badges, endpoint notifications, `call`, and the non-blocking `send`;
  - `init` and the capabilities it holds;
  - the virtio-net driver and `irq_notify`;
  - the network stack's parsers and the network capability;
  - the host echo server in `cargo xtask`;
  - every new `unsafe` block.
- **Design under review:** [services.md](../architecture/services.md), [networking.md](../architecture/networking.md), D-015, D-013 (amended: 32 KiB task stacks).
- **Date:** 2026-10-29, issue #65. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim; the finding was fixed in the same issue.
- **Status:** awaiting the maintainer's approval (M2.10 and Phase 2 gate, #65).

## Method

1. Read every changed file under `kernel/src`, `user/`, and `xtask/` since the M2.9 gate, and searched the diff for new `unsafe` blocks.
2. For each new system call, followed every argument from the register to its last use, and checked that every handle and limit is checked before anything is allocated or sent.
3. Followed each capability `init` holds to the services it passes it to, with the rights and badge it passes.
4. For each value that comes from the network or the device (frames, used-ring entries), found where it is checked; for each value that comes from a client (requests, badges), found where it is trusted.
5. Checked every kernel structure a process can make grow: processes, handles, endpoints, notification words, kernel logs, derivation-tree children.
6. Followed a `call` from start to end, including what each side holds afterwards.
7. Turned the finding into a check that fails without the fix, and mutation-checked it.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | A reply capability outlived its call. `call` gave the server a `SEND` capability on the caller's reply endpoint, and it stayed valid after the reply. A server could keep it and, during a later `call` from the same client to a *different* server, send first: the client would take that message as the other server's reply, and nothing in it tells them apart. Today the network service is the only server, so no second server existed to impersonate. | **Fixed:** replies are one-shot. The server's capability is a child of one derived just for the call, which the kernel revokes as soon as the call returns; a later send through it fails with `REVOKED`. Until the caller resumes, a second send can only queue a message (the caller no longer waits), and `call` refuses a reply endpoint with a queued message (`IN_USE`), so it is never taken as a reply. `spawn` test: a child serves one call, yields, and answers again; the second answer must fail with `REVOKED`. Mutation-checked (no revoke: the check fails). |

Also fixed: two kernel comments still described 16 KiB task stacks (D-013 now says 32 KiB).

## System calls

- **`spawn` (15):** the program is a file capability with `READ`. Up to 8 capability entries are copied in through the checked user-copy path, and each is derived from a handle the caller holds with `GRANT`. Rights are only narrowed (`rights & mask`). A badge is checked against 24 bits and set only on an unbadged capability; a badged one keeps its badge. The notify endpoint needs `RECEIVE` and the bit is below 32. The handle table and the 32-process limit are checked before the ELF is loaded, and the loader (reviewed at M2.9) checks the whole file. Programs still come only from filesystems the kernel mounted from the boot image.
- **`process_status` (16):** needs `WAIT` on a `Process` capability. It reveals only how the process ended. The process capability carries `WAIT | GRANT`, so the parent decides who else may watch.
- **`endpoint_create` (14):** each endpoint occupies a handle, so a process holds at most 64. Endpoints passed away stay bounded by the other process's table.
- **`send` with a badge and the non-blocking flag:** the badge is checked only when a capability is passed, after the handle checks. With the flag, a send that finds no waiting receiver returns `WOULD_BLOCK` and queues nothing.
- **`call` (18):** every handle, the reply buffer, a free handle slot, and an idle reply endpoint are checked before the request is sent, so no reply is lost to a late error. The caller registers on its reply endpoint before sending, so an instant reply is not lost. See F1 for the reply capability.
- **`irq_notify` (17):** needs `WAIT` on the interrupt and `RECEIVE` on the endpoint, and the bit is below 32. Only interrupts and process ends set notification bits, so a client holding `SEND` on the network service cannot fake a device interrupt.

## `init`

- `init` holds every boot capability: the console, the root filesystem, the report endpoint, and every supported device with `GRANT`. It is part of the trusted computing base: small, with a compiled-in service table that is reviewed code.
- It passes each service only what the table lists:
  - devices with `MAP | CONFIG | IRQ`, never `GRANT`, so a driver cannot hand its device on;
  - network capabilities with `SEND` only, badged with the client's port;
  - the report endpoint with `SEND` and a badge naming the service, so a service can report only as itself. `init` ignores reports with any other badge.
- A service that never reports holds up the services after it (no timeouts). The kernel's own 30 s wait then turns the boot into a failure instead of a pass.

## The network service

- **Frames are untrusted.** One function, `classify`, checks each layer: Ethernet destination and EtherType, ARP format and target, IPv4 version, header length (no options), total length, header checksum, fragments, protocol, and then ICMP checksum and type, UDP length and checksum (0 means none, as RFC 768 allows). Each check has a host test, and 100,000 random and mutated frames never panic or read past the frame.
- **The device is untrusted.** Every used-ring element is checked before use: the index cannot jump past what was posted, each ID must be posted (receive) or in flight (transmit), and receive lengths must fit the buffer and hold a minimal frame (host-tested). On a bad value the service resets the device and exits.
- **Clients are known only by badge.** The UDP source port is the badge, so a client cannot send as another. The service builds every header itself, and badge 0 or a badge above 16 bits gets `NO_PORT`.
- **Clients cannot stall or exhaust it:**
  - replies use non-blocking sends, and the reply capability is deleted after each answer;
  - each client has 4 queued datagrams, one outstanding `recv`, and one outstanding ping (`BUSY` otherwise);
  - at most 8 clients (`NO_ROOM`);
  - payloads over 248 bytes get `TOO_LARGE`;
  - drops are counted.
- **Interrupts:** the service learns of device events only through the notification bit `irq_notify` sets.

## The host echo server

`cargo xtask runner` binds a UDP socket on `127.0.0.1:47000` only for the length of one test-kernel boot. It echoes datagrams to their sender, so it adds no reach beyond loopback. slirp's NAT could reach beyond the host (see the limits below).

## `unsafe` added in M2.10

None. `kernel/src` and `user/` gained no `unsafe` blocks; `pharos_programs::net` and `pharos_programs::virtio_net` are safe Rust, and the network service uses the M2.9 `Mapped` volatile access.

## Accepted limits (tracked)

- **No timeouts:** a server that never answers blocks its caller in `call`, a ping to a silent host stays outstanding, and a stuck service holds up `init`. Carried to Phase 3 (M3.3, agent lifecycle and supervision).
- **No per-process quotas:** one process can start up to the 32-process limit and keep the slots, starving later services. Carried to M3.5 (resource accounting and limits).
- **Clients are never forgotten:** a port stays registered after its client ends, so at most 8 ports ever use the service until it restarts. Carried to M3.3, with service restarts.
- **No destination policy:** a client may send to any address. Per-destination grants come with D-012 (M3.4).
- **ARP is believed:** any ARP request or reply addressed to us updates the 8-entry cache, as in any ARP. On slirp the only other host is the gateway.
- **slirp NAT:** user-mode networking could reach beyond the host (`restrict=on` would also block the echo server at `10.0.2.2`). Nothing in the guest sends anywhere but `10.0.2.2`; revisit before tests run untrusted programs.
- **No IOMMU (D-008):** the virtio-net device, like virtio-blk, can DMA anywhere; its driver is trusted with all memory through it.
- **Revocation does not unmap:** revoking a device stops new calls, but existing mappings stay until the process ends (unchanged from M2.9).

## Approval

Pending: the maintainer approves or requests changes at the M2.10 gate (#65).
