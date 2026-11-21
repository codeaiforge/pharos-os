//! The network service (issue #63, networking.md; smoltcp and TCP since
//! #270, tls.md): the virtio-net driver and smoltcp in one process, serving
//! clients over IPC.
//!
//! Handles from `init`: 1 debug console, 2 the virtio-net device
//! (`MAP | CONFIG | IRQ`), 3 the service endpoint (`RECEIVE`), 4 `init`'s
//! report endpoint (`SEND`, badged). Clients hold `SEND` on the service
//! endpoint, badged with the one UDP port they may use; requests come by
//! `call`, and replies go out with non-blocking sends, so a client that is
//! not waiting can never block the service. Interrupts arrive as
//! notification bit 0 on the same endpoint: one blocking point, woken in
//! time for smoltcp's timers.
//!
//! Destinations (#109): each client may send only to the destinations
//! `init` listed for it with `ALLOW` (sent on `init`'s unbadged capability,
//! which no client holds), ping only their addresses, and open TCP only to
//! those `ALLOW_TCP` lists. A client with no list can reach nothing.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use pharos_programs::net::{OUR_IP, STATS, stat};
use pharos_programs::virtio_net::Net;
use pharos_proto::net::{
    Allowed, BAD_REQUEST, BUSY, CLOSED, MAX_BUFFER, MAX_PAYLOAD, NAME, NO_ACCESS, NO_BUFFER,
    NO_PORT, NO_ROOM, NOT_FOUND, OK, REFUSED, Request, TCP_VERSION, VERSION, encode_count,
    encode_datagram, encode_opened, encode_pong, encode_stats, parse,
};
use pharos_proto::{Info, refusal_range};
use pharos_user::{
    Handle, Mapped, Received, debug_write, delete, irq_create, irq_notify, mem_map_cap, mem_unmap,
    receive, receive_timeout, send, try_send, uptime,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
const SERVICE: Handle = 3;
const REPORT: Handle = 4;
const BASE: u64 = 0x1000_0000;
const MAX_CLIENTS: usize = 8;
const QUEUE: usize = 4;
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
/// Frames waiting for smoltcp; more are dropped and counted.
const RX_QUEUE: usize = 32;
/// TCP connections in all, and per client (tls.md).
const MAX_CONNS: usize = 16;
const CONNS_PER_CLIENT: usize = 4;
/// Each connection's receive and send window.
const WINDOW: usize = 8 * 1024;
const CONNECT_US: u64 = 5_000_000;
const IDLE_US: u64 = 60_000_000;
/// A closed connection still finishing its goodbye is aborted after this.
const LINGER_US: u64 = 10_000_000;
/// The longest the service sleeps while a connection is open, so its
/// deadlines are noticed.
const TICK_US: u64 = 100_000;

/// The virtio-net device as smoltcp sees it: received frames wait in `rx`
/// until smoltcp takes them; sent frames go straight to the device.
struct Dev {
    net: Net,
    rx: VecDeque<Vec<u8>>,
    sent: u32,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Net, &'a mut u32);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = [0u8; 1514];
        let len = len.min(frame.len());
        let r = f(&mut frame[..len]);
        // A full transmit ring drops the frame; TCP sends it again.
        if self.0.send(&frame[..len]).is_ok() {
            *self.1 += 1;
        }
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((Rx(frame), Tx(&mut self.net, &mut self.sent)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.net, &mut self.sent))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        caps
    }
}

#[derive(Clone, Copy)]
struct Datagram {
    ip: [u8; 4],
    port: u16,
    len: usize,
    data: [u8; MAX_PAYLOAD],
}

impl Datagram {
    fn new(ip: [u8; 4], port: u16, payload: &[u8]) -> Self {
        let mut d = Self {
            ip,
            port,
            len: payload.len(),
            data: [0; MAX_PAYLOAD],
        };
        d.data[..payload.len()].copy_from_slice(payload);
        d
    }
}

#[derive(Clone, Copy)]
struct Ping {
    reply: Handle,
    seq: u16,
    ip: [u8; 4],
}

/// One client, known by its port (the badge of its capability).
struct Client {
    port: u16,
    queue: VecDeque<Datagram>,
    /// A deferred `recv`: the reply capability to answer on.
    recv: Option<Handle>,
    ping: Option<Ping>,
    /// Where it may send and ping (`ALLOW`); none until `init` says.
    allowed: Allowed,
    /// Where it may open TCP (`ALLOW_TCP`).
    tcp: Allowed,
    udp: SocketHandle,
    icmp: SocketHandle,
    /// The shared buffer for TCP data (`ATTACH`).
    buffer: Option<Mapped>,
}

struct Read {
    reply: Handle,
    offset: u32,
    max: u32,
}

/// One TCP connection, owned by the client on port `owner`.
struct Conn {
    owner: u16,
    socket: SocketHandle,
    /// The deferred `TCP_OPEN` and its deadline.
    opening: Option<(Handle, u64)>,
    read: Option<Read>,
    /// When the client closed it (it is no longer the client's).
    closed: Option<u64>,
    active: u64,
}

struct Service {
    dev: Dev,
    iface: Interface,
    sockets: SocketSet<'static>,
    clients: Vec<Client>,
    conns: [Option<Conn>; MAX_CONNS],
    next_port: u16,
    stats: [u32; STATS],
}

/// Sends `bytes` on the reply capability `reply` without blocking, then
/// lets go of it.
fn answer(stats: &mut [u32; STATS], reply: Handle, bytes: &[u8]) {
    if try_send(reply, bytes).is_err() {
        stats[stat::REPLY_DROPPED] += 1;
    }
    let _ = delete(reply);
}

fn datagram_reply(stats: &mut [u32; STATS], reply: Handle, d: &Datagram) {
    let mut out = [0u8; 256];
    // Datagrams are at most MAX_PAYLOAD bytes (checked on arrival).
    let n = encode_datagram(d.ip, d.port, &d.data[..d.len], &mut out).unwrap_or(0);
    answer(stats, reply, &out[..n]);
}

fn now() -> Instant {
    Instant::from_micros(i64::try_from(uptime()).unwrap_or(i64::MAX))
}

fn v4(ip: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from(ip)
}

/// `buffer[offset..offset + len]`, if it lies inside the buffer.
fn in_buffer(buffer: &Option<Mapped>, offset: u32, len: u32) -> Option<&Mapped> {
    let b = buffer.as_ref()?;
    let end = u64::from(offset) + u64::from(len);
    (end <= b.len() as u64).then_some(b)
}

impl Service {
    fn client(&mut self, port: u16) -> Option<usize> {
        if let Some(i) = self.clients.iter().position(|c| c.port == port) {
            return Some(i);
        }
        if self.clients.len() == MAX_CLIENTS {
            return None;
        }
        let udp = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; QUEUE],
                vec![0; QUEUE * 1472],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; QUEUE],
                vec![0; QUEUE * MAX_PAYLOAD],
            ),
        );
        let icmp = icmp::Socket::new(
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 2], vec![0; 2 * 64]),
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 1], vec![0; 64]),
        );
        let udp = self.sockets.add(udp);
        let icmp = self.sockets.add(icmp);
        let bound = self.sockets.get_mut::<udp::Socket>(udp).bind(port).is_ok()
            && (self.sockets.get_mut::<icmp::Socket>(icmp))
                .bind(icmp::Endpoint::Ident(port))
                .is_ok();
        if !bound {
            self.sockets.remove(udp);
            self.sockets.remove(icmp);
            return None;
        }
        self.clients.push(Client {
            port,
            queue: VecDeque::new(),
            recv: None,
            ping: None,
            allowed: Allowed::NONE,
            tcp: Allowed::NONE,
            udp,
            icmp,
            buffer: None,
        });
        Some(self.clients.len() - 1)
    }

    /// Hands a datagram to the client on `port`, or counts it.
    fn deliver(&mut self, port: u16, d: Datagram) {
        let Some(c) = self.clients.iter_mut().find(|c| c.port == port) else {
            self.stats[stat::NO_PORT] += 1;
            return;
        };
        match c.recv.take() {
            Some(reply) => datagram_reply(&mut self.stats, reply, &d),
            None => {
                if c.queue.len() == QUEUE {
                    c.queue.pop_front();
                    self.stats[stat::QUEUE_FULL] += 1;
                }
                c.queue.push_back(d);
            }
        }
    }

    /// Sends the UDP datagram `d` from client `i`'s port.
    fn send_udp(&mut self, i: usize, d: Datagram) -> u8 {
        let port = self.clients[i].port;
        if d.ip == OUR_IP {
            // Our own address: delivered here, without the device (#63).
            self.deliver(d.port, Datagram::new(OUR_IP, port, &d.data[..d.len]));
            return OK;
        }
        let socket = self.sockets.get_mut::<udp::Socket>(self.clients[i].udp);
        match socket.send_slice(&d.data[..d.len], (v4(d.ip), d.port)) {
            Ok(()) => OK,
            Err(udp::SendError::BufferFull) => BUSY,
            Err(_) => BAD_REQUEST,
        }
    }

    fn send_ping(&mut self, i: usize, ip: [u8; 4], seq: u16) -> bool {
        let c = &self.clients[i];
        let repr = Icmpv4Repr::EchoRequest {
            ident: c.port,
            seq_no: seq,
            data: b"pharos",
        };
        let socket = self.sockets.get_mut::<icmp::Socket>(c.icmp);
        let Ok(buf) = socket.send(repr.buffer_len(), IpAddress::Ipv4(v4(ip))) else {
            return false;
        };
        repr.emit(&mut Icmpv4Packet::new_unchecked(buf), &Default::default());
        true
    }

    /// Moves what smoltcp received to the clients, and answers deferred
    /// requests whose time has come.
    fn serve(&mut self) {
        let mut buf = [0u8; 1472];
        for i in 0..self.clients.len() {
            loop {
                let socket = self.sockets.get_mut::<udp::Socket>(self.clients[i].udp);
                let Ok((n, meta)) = socket.recv_slice(&mut buf) else {
                    break;
                };
                let IpAddress::Ipv4(src) = meta.endpoint.addr;
                if n > MAX_PAYLOAD {
                    self.stats[stat::DROPPED] += 1;
                    continue;
                }
                let d = Datagram::new(src.octets(), meta.endpoint.port, &buf[..n]);
                let port = self.clients[i].port;
                self.deliver(port, d);
            }
            loop {
                let c = &mut self.clients[i];
                let socket = self.sockets.get_mut::<icmp::Socket>(c.icmp);
                let Ok((n, IpAddress::Ipv4(from))) = socket.recv_slice(&mut buf) else {
                    break;
                };
                let echo = Icmpv4Packet::new_checked(&buf[..n])
                    .and_then(|p| Icmpv4Repr::parse(&p, &Default::default()));
                if let (Ok(Icmpv4Repr::EchoReply { ident, seq_no, .. }), Some(p)) = (echo, c.ping)
                    && ident == c.port
                    && seq_no == p.seq
                    && from.octets() == p.ip
                {
                    c.ping = None;
                    answer(&mut self.stats, p.reply, &encode_pong(seq_no));
                }
            }
        }
        let t = uptime();
        for (index, slot) in self.conns.iter_mut().enumerate() {
            let Some(conn) = slot else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.socket);
            let state = socket.state();
            let mut gone = false;
            if let Some(at) = conn.closed {
                if matches!(state, tcp::State::Closed | tcp::State::TimeWait) || t > at + LINGER_US
                {
                    socket.abort();
                    gone = true;
                }
            } else if let Some((reply, deadline)) = conn.opening {
                if state == tcp::State::Established {
                    conn.opening = None;
                    conn.active = t;
                    // At most MAX_CONNS (16) slots.
                    answer(&mut self.stats, reply, &encode_opened(OK, index as u8));
                } else if state == tcp::State::Closed || t > deadline {
                    socket.abort();
                    answer(&mut self.stats, reply, &encode_opened(REFUSED, 0));
                    gone = true;
                }
            } else {
                if let Some(read) = &conn.read {
                    let status = if socket.can_recv() {
                        let owner = self.clients.iter().find(|c| c.port == conn.owner);
                        let buffer =
                            owner.and_then(|c| in_buffer(&c.buffer, read.offset, read.max));
                        let mut data = [0u8; WINDOW];
                        let max = (read.max as usize).min(WINDOW);
                        match (buffer, socket.recv_slice(&mut data[..max])) {
                            (Some(b), Ok(n)) => {
                                b.write_bytes(read.offset as usize, &data[..n]);
                                conn.active = t;
                                Some(encode_count(OK, n as u32))
                            }
                            (None, _) => Some(encode_count(NO_BUFFER, 0)),
                            (_, Err(_)) => Some(encode_count(CLOSED, 0)),
                        }
                    } else if !socket.may_recv() {
                        // The peer's FIN (0 bytes, the end) or a reset.
                        let status = if state == tcp::State::Closed {
                            CLOSED
                        } else {
                            OK
                        };
                        Some(encode_count(status, 0))
                    } else {
                        None
                    };
                    if let Some(out) = status {
                        let reply = read.reply;
                        conn.read = None;
                        answer(&mut self.stats, reply, &out);
                    }
                }
                if t > conn.active + IDLE_US {
                    socket.abort();
                    if let Some(read) = conn.read.take() {
                        answer(&mut self.stats, read.reply, &encode_count(CLOSED, 0));
                    }
                    gone = true;
                }
            }
            if gone {
                self.sockets.remove(conn.socket);
                *slot = None;
            }
        }
    }

    /// The index of `conn` among the connections, for its client.
    fn conn(&mut self, owner: u16, index: u8) -> Option<&mut Conn> {
        self.conns
            .get_mut(usize::from(index))?
            .as_mut()
            .filter(|c| c.owner == owner && c.closed.is_none() && c.opening.is_none())
    }

    fn tcp_open(&mut self, i: usize, ip: [u8; 4], port: u16, reply: Handle) {
        let owner = self.clients[i].port;
        let held = self
            .conns
            .iter()
            .flatten()
            .filter(|c| c.owner == owner)
            .count();
        let free = self.conns.iter().position(Option::is_none);
        let Some(slot) = free.filter(|_| held < CONNS_PER_CLIENT) else {
            return answer(&mut self.stats, reply, &encode_opened(BUSY, 0));
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; WINDOW]),
            tcp::SocketBuffer::new(vec![0; WINDOW]),
        );
        // Local ports 49152-65535, the service's choice, never the client's.
        self.next_port = if self.next_port < 49152 || self.next_port == u16::MAX {
            49152
        } else {
            self.next_port + 1
        };
        if socket
            .connect(self.iface.context(), (v4(ip), port), self.next_port)
            .is_err()
        {
            return answer(&mut self.stats, reply, &encode_opened(BAD_REQUEST, 0));
        }
        let t = uptime();
        let handle = self.sockets.add(socket);
        self.conns[slot] = Some(Conn {
            owner,
            socket: handle,
            opening: Some((reply, t + CONNECT_US)),
            read: None,
            closed: None,
            active: t,
        });
    }

    fn tcp_write(&mut self, owner: u16, conn: u8, offset: u32, len: u32) -> [u8; 6] {
        let Some(i) = self.clients.iter().position(|c| c.port == owner) else {
            return encode_count(CLOSED, 0);
        };
        let Some(buffer) = in_buffer(&self.clients[i].buffer, offset, len) else {
            return encode_count(NO_BUFFER, 0);
        };
        let mut data = [0u8; WINDOW];
        let n = (len as usize).min(WINDOW);
        buffer.read_bytes(offset as usize, &mut data[..n]);
        let Some(c) = self.conn(owner, conn) else {
            return encode_count(CLOSED, 0);
        };
        c.active = uptime();
        let handle = c.socket;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        match socket.send_slice(&data[..n]) {
            Ok(sent) => encode_count(OK, sent as u32),
            Err(_) => encode_count(CLOSED, 0),
        }
    }

    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let i = u16::try_from(badge)
            .ok()
            .filter(|p| *p != 0)
            .and_then(|p| self.client(p));
        let mapped = match i {
            Some(_) if len <= MAX_BUFFER => mem_map_cap(memory, true, len).ok(),
            _ => None,
        };
        let _ = delete(memory);
        if let (Some(i), Some(m)) = (i, mapped)
            && let Some(old) = self.clients[i].buffer.replace(m)
        {
            let _ = mem_unmap(old);
        }
    }

    fn on_request(&mut self, req: &[u8], reply: Handle, badge: u32) {
        let parsed = parse(req);
        if let Ok(Request::Attach { len }) = parsed {
            // A `send`: its capability is the buffer, and nothing answers.
            if reply != 0 {
                self.attach(badge, reply, len);
            }
            return;
        }
        if reply == 0 {
            self.stats[stat::REPLY_DROPPED] += 1;
            return;
        }
        let req = match parsed {
            Ok(req) => req,
            Err(refused) => {
                let mut out = [0u8; 4];
                let n = refusal_range(refused, VERSION, TCP_VERSION, &mut out);
                return answer(&mut self.stats, reply, &out[..n]);
            }
        };
        if let Request::Allow { client, dests } | Request::AllowTcp { client, dests } = req {
            // Only `init`'s capability has no badge.
            let status = if badge != 0 {
                NO_ACCESS
            } else if client == 0 {
                NO_PORT
            } else if let Some(c) = self.client(client) {
                if matches!(req, Request::Allow { .. }) {
                    self.clients[c].allowed = dests;
                } else {
                    self.clients[c].tcp = dests;
                }
                OK
            } else {
                NO_ROOM
            };
            return answer(&mut self.stats, reply, &[status]);
        }
        let Some(port) = u16::try_from(badge).ok().filter(|p| *p != 0) else {
            return answer(&mut self.stats, reply, &[NO_PORT]);
        };
        let Some(i) = self.client(port) else {
            return answer(&mut self.stats, reply, &[NO_ROOM]);
        };
        let (allowed, tcp) = (self.clients[i].allowed, self.clients[i].tcp);
        match req {
            Request::Send { ip, port, .. } if !allowed.sends_to(ip, port) => {
                answer(&mut self.stats, reply, &[NO_ACCESS]);
            }
            Request::Ping { ip, .. } if !allowed.pings(ip) => {
                answer(&mut self.stats, reply, &[NO_ACCESS]);
            }
            Request::TcpOpen { ip, port } if !tcp.sends_to(ip, port) => {
                answer(&mut self.stats, reply, &encode_opened(NO_ACCESS, 0));
            }
            Request::Send { ip, port, payload } => {
                let status = self.send_udp(i, Datagram::new(ip, port, payload));
                answer(&mut self.stats, reply, &[status]);
            }
            Request::Poll => match self.clients[i].queue.pop_front() {
                Some(d) => datagram_reply(&mut self.stats, reply, &d),
                None => answer(&mut self.stats, reply, &[NOT_FOUND]),
            },
            Request::Recv => {
                if self.clients[i].recv.is_some() {
                    return answer(&mut self.stats, reply, &[BUSY]);
                }
                match self.clients[i].queue.pop_front() {
                    Some(d) => datagram_reply(&mut self.stats, reply, &d),
                    None => self.clients[i].recv = Some(reply),
                }
            }
            Request::Ping { ip, seq } => {
                if self.clients[i].ping.is_some() {
                    return answer(&mut self.stats, reply, &[BUSY]);
                }
                if !self.send_ping(i, ip, seq) {
                    return answer(&mut self.stats, reply, &[BUSY]);
                }
                self.clients[i].ping = Some(Ping { reply, seq, ip });
            }
            Request::Stats => {
                self.stats[stat::SENT] = self.dev.sent;
                let mut out = [0u8; 4 + 4 * STATS];
                encode_stats(&self.stats, &mut out);
                answer(&mut self.stats, reply, &out);
            }
            Request::Info => {
                let mut out = [0u8; 16];
                let info = Info {
                    name: NAME,
                    low: VERSION,
                    high: TCP_VERSION,
                    details: &[],
                };
                let n = info.encode(&mut out).unwrap_or(0);
                answer(&mut self.stats, reply, &out[..n]);
            }
            Request::TcpOpen { ip, port } => self.tcp_open(i, ip, port, reply),
            Request::TcpWrite { conn, offset, len } => {
                let out = self.tcp_write(port, conn, offset, len);
                answer(&mut self.stats, reply, &out);
            }
            Request::TcpRead { conn, offset, max } => {
                let buffered = in_buffer(&self.clients[i].buffer, offset, max).is_some() && max > 0;
                let status = match self.conn(port, conn) {
                    None => Some(CLOSED),
                    Some(_) if !buffered => Some(NO_BUFFER),
                    Some(c) if c.read.is_some() => Some(BUSY),
                    Some(c) => {
                        c.read = Some(Read { reply, offset, max });
                        None
                    }
                };
                if let Some(s) = status {
                    answer(&mut self.stats, reply, &encode_count(s, 0));
                }
            }
            Request::TcpClose { conn } => {
                let t = uptime();
                let status = match self.conn(port, conn) {
                    Some(c) => {
                        c.closed = Some(t);
                        let (handle, read) = (c.socket, c.read.take());
                        if let Some(read) = read {
                            answer(&mut self.stats, read.reply, &encode_count(CLOSED, 0));
                        }
                        self.sockets.get_mut::<tcp::Socket>(handle).close();
                        OK
                    }
                    None => CLOSED,
                };
                answer(&mut self.stats, reply, &[status]);
            }
            Request::Allow { .. } | Request::AllowTcp { .. } | Request::Attach { .. } => {}
        }
    }

    /// How long to wait for the next event before smoltcp needs a turn.
    fn wait_us(&mut self) -> Option<u64> {
        let delay = self
            .iface
            .poll_delay(now(), &self.sockets)
            .map(|d| d.total_micros());
        let open = self.conns.iter().any(Option::is_some).then_some(TICK_US);
        match (delay, open) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

fn say(text: &[u8]) {
    let _ = debug_write(CONSOLE, text);
}

fn main(_: u64) -> u64 {
    let Ok(irq) = irq_create(DEVICE, 0) else {
        say(b"net: irq_create failed");
        return 1;
    };
    if irq_notify(irq, SERVICE, 0).is_err() {
        say(b"net: irq_notify failed");
        return 1;
    }
    let net = match Net::init(DEVICE, 0, BASE) {
        Ok(net) => net,
        Err(why) => {
            say(why.as_bytes());
            return 1;
        }
    };
    let mac = net.mac;
    let mut dev = Dev {
        net,
        rx: VecDeque::new(),
        sent: 0,
    };
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    // TCP's initial sequence numbers; not a secret (tls.md: TLS protects
    // the content).
    let m = u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0]);
    config.random_seed = uptime() ^ m.rotate_left(17);
    let mut iface = Interface::new(config, &mut dev, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::Ipv4(v4(OUR_IP)), 24));
    });
    if iface
        .routes_mut()
        .add_default_ipv4_route(v4(GATEWAY))
        .is_err()
    {
        say(b"net: no default route");
        return 1;
    }
    let mut s = Service {
        dev,
        iface,
        sockets: SocketSet::new(vec![]),
        clients: Vec::new(),
        conns: Default::default(),
        next_port: 0,
        stats: [0; STATS],
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let mut msg = [0u8; 256];
    let mut frame = [0u8; 2048];
    loop {
        let event = match s.wait_us() {
            Some(us) => receive_timeout(SERVICE, &mut msg, us.max(1)),
            None => receive(SERVICE, &mut msg),
        };
        match event {
            Ok(Received::Notification(_)) => {
                if s.dev.net.reclaim().is_err() {
                    say(b"net: bad transmit completion; stopping");
                    s.dev.net.reset();
                    return 2;
                }
                loop {
                    match s.dev.net.recv(&mut frame) {
                        Ok(Some(n)) => {
                            s.stats[stat::RECEIVED] += 1;
                            if s.dev.rx.len() < RX_QUEUE {
                                s.dev.rx.push_back(frame[..n].to_vec());
                            } else {
                                s.stats[stat::DROPPED] += 1;
                            }
                        }
                        Ok(None) => break,
                        Err(why) => {
                            say(why.as_bytes());
                            s.dev.net.reset();
                            return 2;
                        }
                    }
                }
            }
            Ok(Received::Message { len, cap, badge }) => {
                s.on_request(&msg[..len.min(msg.len())], cap, badge);
            }
            Err(_) => {}
        }
        s.iface.poll(now(), &mut s.dev, &mut s.sockets);
        s.serve();
        // Replies and data `serve` queued go out now, not at the next event.
        s.iface.poll(now(), &mut s.dev, &mut s.sockets);
    }
}
