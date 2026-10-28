//! The network service (issue #63, networking.md): the virtio-net driver
//! and the minimal stack in one process, serving clients over IPC.
//!
//! Handles from `init`: 1 debug console, 2 the virtio-net device
//! (`MAP | CONFIG | IRQ`), 3 the service endpoint (`RECEIVE`), 4 `init`'s
//! report endpoint (`SEND`, badged). Clients hold `SEND` on the service
//! endpoint, badged with the one UDP port they may use; requests come by
//! `call`, and replies go out with non-blocking sends, so a client that is
//! not waiting can never block the service. Interrupts arrive as
//! notification bit 0 on the same endpoint: one blocking point.

#![no_std]
#![no_main]

use pharos_programs::net::client::{
    BAD_REQUEST, BUSY, MAX_PAYLOAD, NO_PORT, NO_ROOM, OK, OP_PING, OP_RECV, OP_SEND, OP_STATS,
    TOO_LARGE,
};
use pharos_programs::net::{
    ArpCache, OUR_IP, Packet, STATS, arp_frame, classify, echo_frame, next_hop, stat, udp_frame,
};
use pharos_programs::virtio_net::Net;
use pharos_user::{
    Handle, Received, debug_write, delete, irq_create, irq_notify, receive, send, try_send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
const SERVICE: Handle = 3;
const REPORT: Handle = 4;
const BASE: u64 = 0x1000_0000;
const MAX_CLIENTS: usize = 8;
const QUEUE: usize = 4;

#[derive(Clone, Copy)]
struct Datagram {
    ip: [u8; 4],
    port: u16,
    len: usize,
    data: [u8; MAX_PAYLOAD],
}

impl Datagram {
    const EMPTY: Self = Self {
        ip: [0; 4],
        port: 0,
        len: 0,
        data: [0; MAX_PAYLOAD],
    };

    fn new(ip: [u8; 4], port: u16, payload: &[u8]) -> Self {
        let mut d = Self {
            ip,
            port,
            len: payload.len(),
            ..Self::EMPTY
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
    sent: bool,
}

/// One client, known by its port (the badge of its capability).
#[derive(Clone, Copy)]
struct Client {
    port: u16,
    queue: [Datagram; QUEUE],
    head: usize,
    count: usize,
    /// A deferred `recv`: the reply capability to answer on.
    recv: Option<Handle>,
    ping: Option<Ping>,
    /// One datagram waiting for ARP: `(destination, payload)`.
    parked: Option<Datagram>,
}

impl Client {
    const EMPTY: Self = Self {
        port: 0,
        queue: [Datagram::EMPTY; QUEUE],
        head: 0,
        count: 0,
        recv: None,
        ping: None,
        parked: None,
    };

    fn push(&mut self, d: Datagram) -> bool {
        let full = self.count == QUEUE;
        if full {
            self.head = (self.head + 1) % QUEUE;
            self.count -= 1;
        }
        self.queue[(self.head + self.count) % QUEUE] = d;
        self.count += 1;
        !full
    }

    fn pop(&mut self) -> Option<Datagram> {
        if self.count == 0 {
            return None;
        }
        let d = self.queue[self.head];
        self.head = (self.head + 1) % QUEUE;
        self.count -= 1;
        Some(d)
    }
}

struct Service {
    net: Net,
    arp: ArpCache,
    clients: [Client; MAX_CLIENTS],
    used: usize,
    stats: [u32; STATS],
    frame: [u8; 1514],
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
    out[2..4].copy_from_slice(&d.port.to_le_bytes());
    out[4..8].copy_from_slice(&d.ip);
    out[8..8 + d.len].copy_from_slice(&d.data[..d.len]);
    answer(stats, reply, &out[..8 + d.len]);
}

impl Service {
    fn transmit(&mut self, len: usize) {
        if self.net.send(&self.frame[..len]).is_ok() {
            self.stats[stat::SENT] += 1;
        }
    }

    fn client(&mut self, port: u16) -> Option<usize> {
        if let Some(i) = self.clients[..self.used]
            .iter()
            .position(|c| c.port == port)
        {
            return Some(i);
        }
        if self.used == MAX_CLIENTS {
            return None;
        }
        self.clients[self.used] = Client {
            port,
            ..Client::EMPTY
        };
        self.used += 1;
        Some(self.used - 1)
    }

    /// Hands a datagram to the client on `port`, or counts it.
    fn deliver(&mut self, port: u16, d: Datagram) {
        let Some(c) = self.clients[..self.used]
            .iter_mut()
            .find(|c| c.port == port)
        else {
            self.stats[stat::NO_PORT] += 1;
            return;
        };
        match c.recv.take() {
            Some(reply) => datagram_reply(&mut self.stats, reply, &d),
            None => {
                if !c.push(d) {
                    self.stats[stat::QUEUE_FULL] += 1;
                }
            }
        }
    }

    /// Sends the UDP datagram `d` from `port`, or parks it for ARP.
    fn send_udp(&mut self, i: usize, d: Datagram) -> u8 {
        let port = self.clients[i].port;
        if d.ip == OUR_IP {
            self.deliver(d.port, Datagram::new(OUR_IP, port, &d.data[..d.len]));
            return OK;
        }
        let hop = next_hop(d.ip);
        match self.arp.lookup(hop) {
            Some(mac) => {
                let n = udp_frame(
                    &mut self.frame,
                    self.net.mac,
                    mac,
                    d.ip,
                    port,
                    d.port,
                    &d.data[..d.len],
                );
                if let Some(n) = n {
                    self.transmit(n);
                }
                OK
            }
            None if self.clients[i].parked.is_none() => {
                self.clients[i].parked = Some(d);
                self.frame[..42].copy_from_slice(&arp_frame(self.net.mac, false, [0; 6], hop));
                self.transmit(42);
                OK
            }
            None => BUSY,
        }
    }

    fn send_ping(&mut self, i: usize) {
        let Some(mut ping) = self.clients[i].ping else {
            return;
        };
        if ping.sent {
            return;
        }
        let hop = next_hop(ping.ip);
        match self.arp.lookup(hop) {
            Some(mac) => {
                let id = self.clients[i].port;
                if let Some(n) = echo_frame(
                    &mut self.frame,
                    self.net.mac,
                    mac,
                    ping.ip,
                    false,
                    id,
                    ping.seq,
                    b"pharos",
                ) {
                    self.transmit(n);
                }
                ping.sent = true;
                self.clients[i].ping = Some(ping);
            }
            None => {
                self.frame[..42].copy_from_slice(&arp_frame(self.net.mac, false, [0; 6], hop));
                self.transmit(42);
            }
        }
    }

    fn on_frame(&mut self, frame: &[u8]) {
        self.stats[stat::RECEIVED] += 1;
        match classify(frame, self.net.mac) {
            Err(_) => self.stats[stat::DROPPED] += 1,
            Ok(Packet::ArpRequest { mac, ip }) => {
                self.arp.insert(ip, mac);
                self.frame[..42].copy_from_slice(&arp_frame(self.net.mac, true, mac, ip));
                self.transmit(42);
            }
            Ok(Packet::ArpReply { mac, ip }) => {
                self.arp.insert(ip, mac);
                for i in 0..self.used {
                    if let Some(d) = self.clients[i].parked {
                        if next_hop(d.ip) == ip {
                            self.clients[i].parked = None;
                            self.send_udp(i, d);
                        }
                    }
                    self.send_ping(i);
                }
            }
            Ok(Packet::EchoRequest {
                mac,
                ip,
                id,
                seq,
                data,
            }) => {
                let mut copy = [0u8; 1472];
                let len = data.len().min(copy.len());
                copy[..len].copy_from_slice(&data[..len]);
                if let Some(n) = echo_frame(
                    &mut self.frame,
                    self.net.mac,
                    mac,
                    ip,
                    true,
                    id,
                    seq,
                    &copy[..len],
                ) {
                    self.transmit(n);
                }
            }
            Ok(Packet::EchoReply { ip, id, seq }) => {
                let found = self.clients[..self.used].iter_mut().find(|c| {
                    c.port == id && c.ping.is_some_and(|p| p.sent && p.seq == seq && p.ip == ip)
                });
                if let Some(c) = found {
                    if let Some(p) = c.ping.take() {
                        let mut out = [OK, 0, 0, 0];
                        out[2..4].copy_from_slice(&seq.to_le_bytes());
                        answer(&mut self.stats, p.reply, &out);
                    }
                }
            }
            Ok(Packet::Udp {
                ip,
                src_port,
                dst_port,
                payload,
            }) => {
                if payload.len() > MAX_PAYLOAD {
                    self.stats[stat::DROPPED] += 1;
                } else {
                    self.deliver(dst_port, Datagram::new(ip, src_port, payload));
                }
            }
        }
    }

    fn on_request(&mut self, req: &[u8], reply: Handle, badge: u32) {
        if reply == 0 {
            self.stats[stat::REPLY_DROPPED] += 1;
            return;
        }
        let Ok(port) = u16::try_from(badge) else {
            return answer(&mut self.stats, reply, &[NO_PORT]);
        };
        if port == 0 {
            return answer(&mut self.stats, reply, &[NO_PORT]);
        }
        let Some(i) = self.client(port) else {
            return answer(&mut self.stats, reply, &[NO_ROOM]);
        };
        match req.first().copied() {
            Some(OP_SEND) if req.len() >= 8 => {
                let payload = &req[8..];
                if payload.len() > MAX_PAYLOAD {
                    return answer(&mut self.stats, reply, &[TOO_LARGE]);
                }
                let ip = [req[4], req[5], req[6], req[7]];
                let dst_port = u16::from_le_bytes([req[2], req[3]]);
                let status = self.send_udp(i, Datagram::new(ip, dst_port, payload));
                answer(&mut self.stats, reply, &[status]);
            }
            Some(OP_RECV) => {
                if self.clients[i].recv.is_some() {
                    return answer(&mut self.stats, reply, &[BUSY]);
                }
                match self.clients[i].pop() {
                    Some(d) => datagram_reply(&mut self.stats, reply, &d),
                    None => self.clients[i].recv = Some(reply),
                }
            }
            Some(OP_PING) if req.len() >= 8 => {
                if self.clients[i].ping.is_some() {
                    return answer(&mut self.stats, reply, &[BUSY]);
                }
                self.clients[i].ping = Some(Ping {
                    reply,
                    seq: u16::from_le_bytes([req[2], req[3]]),
                    ip: [req[4], req[5], req[6], req[7]],
                    sent: false,
                });
                self.send_ping(i);
            }
            Some(OP_STATS) => {
                let mut out = [0u8; 4 + 4 * STATS];
                for (k, v) in self.stats.iter().enumerate() {
                    out[4 + 4 * k..8 + 4 * k].copy_from_slice(&v.to_le_bytes());
                }
                answer(&mut self.stats, reply, &out);
            }
            _ => answer(&mut self.stats, reply, &[BAD_REQUEST]),
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
    let mut s = Service {
        net,
        arp: ArpCache::default(),
        clients: [Client::EMPTY; MAX_CLIENTS],
        used: 0,
        stats: [0; STATS],
        frame: [0; 1514],
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    let mut msg = [0u8; 256];
    let mut frame = [0u8; 2048];
    loop {
        match receive(SERVICE, &mut msg) {
            Ok(Received::Notification(_)) => {
                if s.net.reclaim().is_err() {
                    say(b"net: bad transmit completion; stopping");
                    s.net.reset();
                    return 2;
                }
                loop {
                    match s.net.recv(&mut frame) {
                        Ok(Some(n)) => s.on_frame(&frame[..n]),
                        Ok(None) => break,
                        Err(why) => {
                            say(why.as_bytes());
                            s.net.reset();
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
    }
}
