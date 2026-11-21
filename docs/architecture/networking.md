# Networking

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-28 (M2.10, #59). It follows [D-015](../project/decision-log.md#d-015-network-stack-and-service-model) (as amended on 2026-10-28) and builds on [drivers.md](drivers.md) (device capabilities, the virtio transport) and [services.md](services.md) (badges, notifications, `init`).
- **Implementation:** the virtio-net driver is **implemented** (#62: `pharos_programs::virtio_net` on the shared `virtio::Transport` and `virtio::Queue`, `irq_notify`, a virtio-net card on every QEMU run; tested by `virtio_net` with the `netprobe` program). So are the network service and stack (#63: `pharos_programs::net` with `classify`, the builders, the ARP cache, and the client encoding; `user/programs/src/bin/net.rs`; `call` and non-blocking `send`; started by `init` at boot; tested by `network` with the `netclient` program, and fuzzed on the host). So is the host endpoint (#64: `xtask/src/echo.rs`, started by `cargo xtask runner` around each test-kernel boot; `network` exchanges a datagram with it; `PHAROS_PCAP=1` records the traffic).
- **M6.1 (D-034):** smoltcp in place of this stack's IP layer, and TCP as interface `net` v2: **implemented** (#270), designed in [tls.md](tls.md) (accepted 2026-11-21, #269). The own Ethernet, ARP, IPv4, ICMP, and UDP code described in "The stack" below is retired; that section is kept as the M2.10 record, and "smoltcp (#270)" says what replaced it.

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
| Frame and packet parsers and builders | `pharos_programs::net` (`no_std`, host-tested and fuzzed); **retired in #270**, smoltcp 0.14 since (D-034) | none (smoltcp compiles none here) |
| Network service | `user/programs/src/bin/net.rs`: driver, stack, client interface | none |
| Client library | `pharos_programs::net::client` (request encoding) | none |
| Kernel IPC additions | `call` and non-blocking `send` (below) | none |
| Host test endpoint | `cargo xtask`: UDP and (since #270) TCP echo servers on `127.0.0.1:47000` | none (host code) |

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

- **Routing:** a destination in `10.0.2.0/24` is resolved directly; anything else goes through the gateway `10.0.2.2`. A datagram to our own address `10.0.2.15` is delivered locally to the client on its port, without the device (added in #63, so clients can be tested against each other).
- **ARP:**
  - a cache of 8 entries, replacing the oldest;
  - a datagram to an unresolved address waits while one ARP request is out, with one waiting datagram per client; a second is dropped.
- **Outgoing packets** are built entirely by the service: source MAC, IP, and port come from the service and the client's badge, never from the client.
- **Limits:**
  - 8 clients;
  - 4 queued datagrams per client, dropping the oldest;
  - one outstanding receive or ping per client;
  - UDP payloads up to 1472 bytes on the wire, up to 248 bytes per client message (one IPC message).

### smoltcp (#270, D-034)

- **The network service runs smoltcp 0.14** (features `alloc`, `medium-ethernet`, `proto-ipv4`, `socket-tcp`, `socket-udp`, `socket-icmp`) on the virtio-net driver above, unchanged. Received frames wait in a queue of 32 for smoltcp (more are dropped and counted as `DROPPED`); smoltcp's frames go straight to the transmit ring, and one that finds it full is dropped (TCP sends it again).
- **The same addresses:** `10.0.2.15/24`, default route `10.0.2.2`. smoltcp answers ARP and pings to us itself, and resolves neighbours with its own cache.
- **Each client** gets a UDP socket bound to its port and an ICMP socket bound to its port as echo identifier, made at its first request. Received datagrams move from its socket to its queue of 4 (oldest dropped, `QUEUE_FULL`); a datagram over 248 bytes is dropped (`DROPPED`). A datagram to `10.0.2.15` is still delivered inside the service, without the device, so a datagram to a port no client holds is still counted (`NO_PORT`); from the wire, smoltcp answers such a datagram with ICMP port unreachable, where the own stack sent nothing.
- **A send to a neighbour not yet resolved** waits in the client's UDP socket (4 datagrams) while smoltcp resolves it; a full socket is `BUSY`. Before #270 one datagram per client waited for ARP.
- **TCP** (version 2, below): at most 16 connections, 4 per client, each with 8 KiB windows; the local port is the service's (49152–65535 in turn); connect times out after 5 s (`REFUSED`), an idle connection is aborted after 60 s, and a closed one still saying goodbye after 10 s. TCP's initial sequence numbers come from smoltcp's seed (the boot time and the MAC); they are not a secret, as TLS protects the content (tls.md).
- **Timers:** the service waits for its next message or interrupt only as long as smoltcp's next timer, and at most 100 ms while a connection is open, so retransmissions and deadlines run without traffic.
- **Memory:** smoltcp's sockets and the clients' buffers come from the service's heap and page limit, 512 pages (2 MiB) since #270.

### Network capability and client interface

- **A client's network capability is a `SEND` capability on the service's endpoint,** badged by `init` with the one UDP port the client may use (1–65535). Badge 0, which `init`'s own unbadged capability has, may only send `ALLOW` (#109); anything else under it is refused, and `init` never gives a client badge 0. Revoking the capability ends the client's access. The service binds a port to a client on first use and never lets another badge use it.
- **Requests use `call`** (below). Each request and reply is one message, with little-endian fields. Since #92 this is interface `net`, version 1 (D-019): the codec is `pharos_proto::net`, shared by the service and its clients and fuzzed on the host. Every request starts with the version (1) and the operation; the byte that was padding before #92 now holds the version.

  | Op | Request | Reply |
  | --- | --- | --- |
  | 1 `send` | `[1, 1, dst_port:u16, dst_ip:[u8;4], payload…]` (payload at most 248 bytes) | `[status]` |
  | 2 `recv` | `[1, 2]` | `[status, 0, src_port:u16, src_ip:[u8;4], payload…]`, deferred until a datagram arrives |
  | 3 `ping` | `[1, 3, seq:u16, dst_ip:[u8;4]]` | `[status, 0, seq:u16]`, deferred until the echo reply |
  | 4 `stats` | `[1, 4]` | `[status, 0, 0, 0, counters (u32 each)…]`: frames received and sent, drops by reason |
  | 5 `ALLOW` (#109) | `[1, 5, client_port:u16, count, (ip:[u8;4], port:u16)…]` (at most 8), only without a badge (`init`) | `[status]` |
  | 6 `POLL` (#109) | `[1, 6]` | as `recv`, or `[7]` (not found) at once: never deferred |
  | 0xF0 `INFO` (common) | `[1, 0xF0]` | `[status, 1, 1, 3, "net"]`: versions 1 to 1, no details |

  **Version 2 (#270, tls.md)** adds TCP; the requests above are accepted as version 1 or 2, the ones below only as 2:

  | Op | Request | Reply |
  | --- | --- | --- |
  | 0xF1 `ATTACH` (common, a `send`) | `[2, 0xF1, size:u64]` (at most 64 KiB), with the `Memory` capability | none |
  | 7 `TCP_OPEN` | `[2, 7, dst_port:u16, dst_ip:[u8;4]]` (an address and port `ALLOW_TCP` listed) | `[status, conn]`, deferred until connected or refused (5 s) |
  | 8 `TCP_WRITE` | `[2, 8, conn, offset:u32, len:u32]` (a range of the buffer) | `[status, 0, queued:u32]`, at once; may queue less than asked |
  | 9 `TCP_READ` | `[2, 9, conn, offset:u32, max:u32]` | `[status, 0, read:u32]`, deferred until data, the peer's end (0 bytes), or a reset |
  | 10 `TCP_CLOSE` | `[2, 10, conn]` | `[status]`; a deferred read gets `CLOSED` |
  | 11 `ALLOW_TCP` | as `ALLOW`, only without a badge (`init`) | `[status]` |

  Status codes: the common ones (D-019): 0 OK, 1 bad request (including a malformed request, and a TCP request as version 1), 2 `VERSION` (another version: the reply is `[2, 1, 2]`, the supported range; `[2, 1, 1]` before #270), 3 no access (a destination or ping address not listed for the client, or `ALLOW` from a client), 4 busy (a receive or ping is already outstanding, or a datagram already waits for ARP), 7 not found (`POLL` with nothing waiting); and the interface's own: 32 no port (badge 0 or above 65535), 33 no room (8 clients already known), 34 `REFUSED` (reset, or no answer within 5 s), 35 `CLOSED` (the connection is gone or not this client's), and 6 `NO_BUFFER` (none attached, or a range outside it). Before #92, codes 2–5 were too large, busy, no port, and no room; a payload over 248 bytes cannot arrive in a 256-byte message, so "too large" is gone.
- **Counters** (`stats`): frames received and sent, frames dropped by the parser (malformed or not for us), datagrams for a port no client holds, replies dropped because the client was not waiting, and datagrams dropped from a full queue.
- **Clients are known by port from their first request** and stay known; with 8 ports seen, new ones get `NO_ROOM`. A client registers by making any request (the echoer in the tests asks for `stats` first), so datagrams that arrive before its first `recv` are queued.
- **Destinations (#109, D-012):** a client may send only to the destinations listed for it, and ping only their addresses; anything else is refused with `NO_ACCESS`. A client with no list sends nowhere. The lists come from `init`'s table (each network capability names its port and destinations), sent with `ALLOW` each time the service reports ready, so a restarted service gets them again. `ALLOW` is accepted only without a badge, which only `init` holds; `init` never hands out a network capability with badge 0.
  - *Implemented (#109):* `ALLOW`, `POLL` (for the agent runtime, which serves one message at a time and cannot wait on a deferred `recv`; the service's queue keeps 4 datagrams per client), and the checks. Incoming datagrams are not filtered by source: the runtime delivers an agent only replies from its granted destinations ([capabilities.md](capabilities.md)).
  - *Carried from M2.10:* before #109 a client could send to any address and port.

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
- **Deferred replies:** the service keeps the attached reply capability until it answers (at most one per client), then deletes it. The kernel revokes it anyway once the client's `call` returns (one-shot replies, M2.10 review F1).

### QEMU and the host endpoint

- **Every QEMU run attaches the network device:** `-netdev user,id=net0 -device virtio-net-pci,netdev=net0,disable-legacy=on`. This uses user-mode networking: no root and no TAP device. slirp's NAT could reach beyond the host (`restrict=on` would also block the host endpoint at `10.0.2.2`); nothing in the guest sends anywhere but `10.0.2.2`. Existing kernels find their devices by ID, so the extra device changes nothing for them.
- **`cargo xtask test` runs a UDP echo server, and since #270 a TCP one on the same port,** on `127.0.0.1:47000` (the runner starts it before each test kernel boots and stops it afterwards, so `cargo test --test <name>` gets it too), failing with a clear message if the port is taken. slirp forwards the guest's datagrams to `10.0.2.2` on to the host's loopback, so the guest reaches the server at `10.0.2.2:47000`.
- **Ping target:** the slirp gateway `10.0.2.2`. slirp answers pings to its own address itself (confirmed in #62: `virtio_net` pings it, locally and in CI).
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
- **Destinations:** each client reaches only what `init` listed (#109).
- **Limits:** no rate limits beyond the queues and the transmit ring; a ping to a silent host stays outstanding until the client gives up or ends (TCP has its timeouts since #270); a client's connections and buffer stay until they time out or the service restarts, since `init` does not tell the service that a client ended.
- The threat model gains a "Networking" section (planned).

## 5. Testing

| Layer | Tests |
| --- | --- |
| Host, `pharos_programs::net` | Until #270: each parser against hand-built frames, builders round-trip through parsers, checksums against known values, the ARP cache limit, 100,000 fuzzed frames. Retired with the own stack; smoltcp's receive path is fuzzed in #272 |
| Host, `pharos_programs::virtio` | Used-ring checks for receive and transmit lengths and IDs |
| Host, `syscall` | `call` and the non-blocking flag decoded; the fuzz test covers them |
| Host, `xtask` | The echo server starts, echoes, stops, and reports a taken port |
| QEMU, `ipc` additions | `call` gets its reply even when the server answers at once; a non-blocking send with no receiver returns `WOULD_BLOCK` and queues nothing |
| QEMU, `virtio_net` | The driver reads the MAC, resolves the gateway with ARP, and sends and receives a frame; a driver killed mid-transfer leaves its device stopped and every frame returned |
| QEMU, `network` | `init` starts the network service and clients with port badges 40000 and 40001: a UDP datagram to `10.0.2.2:47000` comes back from the host echo server, a ping to the gateway is answered, and a datagram between the two clients over `10.0.2.15` gets a reply. Refused: a client whose badge is no port (over 16 bits); a destination and a ping address not listed for the client, and its own `ALLOW` (`NO_ACCESS`, #109). `POLL` with nothing waiting answers not found. A datagram to a port with no client is counted. `stats` reports the counts. (Two clients with the same port are not tested: `init` sets every badge, so that would be an `init` bug, not a client's choice.). **Since #270, on smoltcp:** the version check expects `1 to 2`, and a fourth client, `tcper` (port 40002, TCP to `10.0.2.2:47000` and `47002`), attaches a buffer, connects to the host's TCP echo server, writes 14 bytes and reads them back, closes, and is refused: a write on the closed connection (`CLOSED`), a destination not listed for TCP (`NO_ACCESS`), a listed port nothing listens on (`REFUSED`, slirp's reset), and a TCP request as version 1 (`BAD_REQUEST`) |

## 6. Alternatives

- **`smoltcp`:** a full stack including TCP. Its releases 0.13 and 0.14 need Rust 1.91 (D-015). Chosen for TCP by [D-034](../project/decision-log.md#d-034-tcp-and-tls-stack) (2026-11-21): smoltcp 0.14 replaces this stack's IP layer in M6.1 (**planned**).
- **The stack as a separate process from the driver:** this needs shared memory or many messages per frame.
- **DHCP:** slirp offers it, but static addresses are enough for a fixed QEMU network.
- **slirp `guestfwd`:** forwards TCP only, while the test exchange is UDP.

## 7. Open questions

- **TCP:** our own or `smoltcp`, and when.
- **Rate limits** for clients.
- **Larger datagrams for clients** (shared memory or several messages).
- **IPv6 and DNS.**
