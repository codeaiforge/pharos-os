# Networking

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-28 (M2.10, #59). It follows [D-015](../project/decision-log.md#d-015-network-stack-and-service-model) (as amended on 2026-10-28) and builds on [drivers.md](drivers.md) (device capabilities, the virtio transport) and [services.md](services.md) (badges, notifications, `init`).
- **Implementation:** **planned** (#62, #63, #64).

## 2. Context

The M2.10 acceptance criteria:

- the QEMU guest exchanges packets with the host over user-mode networking;
- network access is mediated, so it can later be granted as a capability.

D-015 chose:

- our own minimal stack with no TCP, running inside the virtio-net driver's process (the **network service**);
- clients identified by capability badges;
- static slirp addresses: guest `10.0.2.15/24`, gateway and host `10.0.2.2`.

## 3. Design

### Components

| Component | Where | `unsafe` |
| --- | --- | --- |
| virtio transport (shared with virtio-blk) | `pharos_programs::virtio`, generalised to several queues | none |
| Frame and packet parsers and builders | `pharos_programs::net` (`no_std`, host-tested and fuzzed) | none |
| Network service | `user/programs/src/bin/net.rs`: driver, stack, client interface | none |
| Client library | `pharos_programs::net::client` (request encoding) | none |
| Kernel IPC additions | `call` and non-blocking `send` (below) | none |
| Host test endpoint | `cargo xtask`: UDP echo server on `127.0.0.1` | none (host code) |

### virtio-net driver (inside the network service)

- **Device:** the driver checks the ID `0x1af4:0x1041`. It negotiates only `VERSION_1` (bit 32) and `MAC` (bit 5); no checksum offload, no segmentation offload, no mergeable buffers, no control queue. It reads the MAC from the device configuration.
- **Queues:** queue 0 receives and queue 1 transmits, each of size min(device maximum, 16). Every frame has the 12-byte virtio-net header, all zero on transmit.
- **Memory:**
  - 16 receive buffers and 16 transmit buffers of 2 KiB each, plus the rings: 18 DMA pages, within the 64-page device limit, in calls of at most 16 pages;
  - receive buffers are posted ahead and reposted after each frame.
- **Interrupts:** both queues use MSI-X entry 0, and the configuration vector is `NO_VECTOR`. The interrupt is bound with `irq_notify` to bit 0 of the service's endpoint, so interrupts and client requests arrive at one `receive`.
- **Device values are untrusted** (as for virtio-blk; checks host-tested):
  - the used index advances by at most the buffers outstanding;
  - descriptor IDs are in range and outstanding;
  - a receive length is at least the header plus 14 bytes, and at most the buffer;
  - transmit completions are only for buffers in flight.

### The stack

All parsing is in `pharos_programs::net`: safe Rust, no allocation per packet, every field checked before use.

| Layer | Accepted | Dropped (each counted) |
| --- | --- | --- |
| Ethernet II | Destination our MAC or broadcast; EtherType ARP or IPv4 | Anything shorter than 14 bytes, other EtherTypes, other destinations |
| ARP | Requests for `10.0.2.15` (answered); replies to our requests (cached) | Non-Ethernet/IPv4 ARP, wrong lengths, gratuitous updates for addresses we did not ask for |
| IPv4 | Version 4, header length 20 (no options), total length within the frame, valid header checksum, no fragments, destination `10.0.2.15`, protocol ICMP or UDP | Everything else (options, fragments, broadcasts, bad checksums) |
| ICMP | Echo request (answered); echo reply matching a client's ping | Other types; bad checksum |
| UDP | Length within the IP payload; checksum valid or zero; a client bound to the destination port | No client on the port (counted, no ICMP error sent) |

- **Routing:** a destination in `10.0.2.0/24` is resolved directly; anything else goes through the gateway `10.0.2.2`.
- **ARP:**
  - a cache of 8 entries, replacing the oldest;
  - a datagram to an unresolved address waits while one ARP request is out, with one waiting datagram per client; a second is dropped.
- **Outgoing packets** are built entirely by the service: source MAC, IP, and port come from the service and the client's badge, never from the client.
- **Limits:**
  - 8 clients;
  - 4 queued datagrams per client, dropping the oldest;
  - one outstanding receive or ping per client;
  - UDP payloads up to 1472 bytes on the wire, up to 248 bytes per client message (one IPC message).

### Network capability and client interface

- **A client's network capability is a `SEND` capability on the service's endpoint,** badged by `init` with the one UDP port the client may use (1–65535). Badge 0, which `init`'s own unbadged capability has, is refused. Revoking the capability ends the client's access. The service binds a port to a client on first use and never lets another badge use it.
- **Requests use `call`** (below). Each request and reply is one message, with little-endian fields:

  | Op | Request | Reply |
  | --- | --- | --- |
  | 1 `send` | `[1, 0, dst_port:u16, dst_ip:[u8;4], payload…]` | `[status]` |
  | 2 `recv` | `[2]` | `[status, 0, src_port:u16, src_ip:[u8;4], payload…]`, deferred until a datagram arrives |
  | 3 `ping` | `[3, 0, seq:u16, dst_ip:[u8;4]]` | `[status, 0, seq:u16]`, deferred until the echo reply |
  | 4 `stats` | `[4]` | `[status, counters…]`: frames received and sent, drops by reason |

  Status codes: 0 OK, 1 bad request, 2 too large, 3 busy (a receive or ping is already outstanding), 4 no port (badge 0).
- **No destination policy in M2.10:** a client may send to any address and port. Per-destination grants come with D-012 (M3.4).

### IPC additions (kernel)

- **`call(endpoint, buffer, length, reply, max)`:**
  1. Registers the caller as a receiver on `reply`, which needs `SEND | RECEIVE`.
  2. Sends the request on `endpoint` (`SEND`), with a `SEND` capability on `reply` derived and attached as the message's capability. It blocks until the service takes it.
  3. Waits for the first event on `reply` and copies it into `buffer` (at most `max` bytes). It returns the same value as `receive`.

  Because the caller is a receiver before the request is delivered, a reply can never arrive too early and be lost.
- **Non-blocking `send`:**
  - flag bit 0 in the sixth argument;
  - if no receiver is waiting, the message is not queued and the call returns the new error **11 `WOULD_BLOCK`**;
  - the service sends every reply this way, so a client that is not waiting cannot block it. The reply is dropped and counted.
- **Deferred replies:** the service keeps the attached reply capability until it answers (at most one per client), then deletes it.

### QEMU and the host endpoint

- **Every QEMU run attaches the network device:** `-netdev user,id=net0 -device virtio-net-pci,netdev=net0,disable-legacy=on`. This uses user-mode networking: no root, no TAP device, and nothing that reaches beyond the host. Existing kernels find their devices by ID, so the extra device changes nothing for them.
- **`cargo xtask test` runs a UDP echo server** on `127.0.0.1:47000` for the run's duration, failing with a clear message if the port is taken. slirp forwards the guest's datagrams to `10.0.2.2` on to the host's loopback, so the guest reaches the server at `10.0.2.2:47000`.
- **Ping target:** the slirp gateway `10.0.2.2`. slirp answers pings to its own address itself; this is confirmed in #62 before tests rely on it.
- **Optional packet capture** for debugging (`-object filter-dump`), written under `target/xtask/logs/`, never committed.

## 4. Security

- **The network service is untrusted** by the kernel and by its clients. It holds the network device and all traffic. A bug in it affects networking only.
- **Packets are untrusted input:** every layer is parsed with checked lengths, and the parsers are fuzzed on the host with random and mutated frames. Malformed frames are dropped and counted, never trusted.
- **Clients:**
  - identity comes from the badge, not the message;
  - a client cannot use another client's port, spoof its source address, or send without a capability;
  - replies never block the service;
  - per-client queues and outstanding requests are bounded.
- **Device:** as in drivers.md; DMA has no IOMMU (D-008 limit).
- **Limits:** no destination policy and no rate limits beyond the queues and the transmit ring; no TCP; the service has no timeouts, so a ping to a silent host stays outstanding until the client gives up or ends.
- The threat model gains a "Networking" section (planned).

## 5. Testing

| Layer | Tests |
| --- | --- |
| Host, `pharos_programs::net` | Each parser against hand-built frames (valid and each refusal), builders round-trip through parsers, checksums against known values, the ARP cache limit; fuzzing with 100,000 random and mutated frames: no panic, nothing past the frame read |
| Host, `pharos_programs::virtio` | Used-ring checks for receive and transmit lengths and IDs |
| Host, `syscall` | `call` and the non-blocking flag decoded; the fuzz test covers them |
| Host, `xtask` | The echo server starts, echoes, stops, and reports a taken port |
| QEMU, `ipc` additions | `call` gets its reply even when the server answers at once; a non-blocking send with no receiver returns `WOULD_BLOCK` and queues nothing |
| QEMU, `virtio_net` | The driver reads the MAC, resolves the gateway with ARP, and sends and receives a frame; a driver killed mid-transfer leaves its device stopped and every frame returned |
| QEMU, `network` | `init` starts the network service and a client with port badge 40000: a UDP datagram to `10.0.2.2:47000` comes back from the host echo server, and a ping to the gateway is answered. Refused: a client with badge 0, and a second client using the first client's port. A datagram to a port with no client is counted. `stats` reports the counts |

## 6. Alternatives

- **`smoltcp`:** a full stack including TCP. Its releases 0.13 and 0.14 need Rust 1.91 (D-015); revisit with TCP.
- **The stack as a separate process from the driver:** this needs shared memory or many messages per frame.
- **DHCP:** slirp offers it, but static addresses are enough for a fixed QEMU network.
- **slirp `guestfwd`:** forwards TCP only, while the test exchange is UDP.

## 7. Open questions

- **TCP:** our own or `smoltcp`, and when.
- **Destination policy and rate limits** for clients (D-012, M3.4).
- **Larger datagrams for clients** (shared memory or several messages).
- **IPv6 and DNS.**
