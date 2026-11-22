//! Host fuzzing of the TCP the network service runs (#272, D-020): smoltcp
//! with the service's settings (Ethernet, our address, 8 KiB windows, a
//! connection we opened), fed random frames and mutations of a real peer's
//! segments, with the connection open and being used. Nothing may panic.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

use crate::net::{GATEWAY, OUR_IP};

/// Frames fed to our side; CI runs this many on every push.
pub const ROUNDS: usize = 200_000;
const WINDOW: usize = 8 * 1024;
const PORT: u16 = 47_443;

#[derive(Default)]
struct Wire {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let r = f(&mut frame);
        self.0.push(frame);
        r
    }
}

impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((Rx(frame), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        // Unlike the service, checksums are not checked on receipt, so a
        // mutated segment reaches the TCP parser and state machine rather
        // than being dropped at its checksum.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps
    }
}

struct Host {
    wire: Wire,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
}

impl Host {
    fn new(mac: u8, ip: [u8; 4]) -> Self {
        let mut wire = Wire::default();
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress([
            2, 0, 0, 0, 0, mac,
        ])));
        config.random_seed = u64::from(mac);
        let mut iface = Interface::new(config, &mut wire, Instant::ZERO);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), 24));
        });
        let mut sockets = SocketSet::new(vec![]);
        let tcp = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; WINDOW]),
            tcp::SocketBuffer::new(vec![0; WINDOW]),
        ));
        Self {
            wire,
            iface,
            sockets,
            tcp,
        }
    }

    fn poll(&mut self, t: i64) {
        self.iface
            .poll(Instant::from_millis(t), &mut self.wire, &mut self.sockets);
    }

    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.tcp)
    }
}

/// Us connected to a peer at the gateway's address, with data sent both
/// ways; returns the frames the peer sent, as templates for mutation.
fn connected() -> (Host, Vec<Vec<u8>>) {
    let mut us = Host::new(1, OUR_IP);
    let mut peer = Host::new(2, GATEWAY);
    let g = GATEWAY;
    peer.socket().listen(PORT).unwrap();
    let cx = us.iface.context();
    us.sockets
        .get_mut::<tcp::Socket>(us.tcp)
        .connect(cx, (IpAddress::v4(g[0], g[1], g[2], g[3]), PORT), 50_000)
        .unwrap();
    let mut from_peer = Vec::new();
    for t in 0..64 {
        us.poll(t);
        peer.wire.rx.extend(us.wire.tx.drain(..));
        peer.poll(t);
        if peer.socket().can_send() {
            let _ = peer.socket().send_slice(b"from the peer");
        }
        if us.socket().can_send() {
            let _ = us.socket().send_slice(b"from us");
        }
        let mut buf = [0u8; 64];
        let _ = peer.socket().recv_slice(&mut buf);
        from_peer.extend(peer.wire.tx.iter().cloned());
        us.wire.rx.extend(peer.wire.tx.drain(..));
    }
    (us, from_peer)
}

fn next(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

#[test]
fn tcp_never_panics_on_fuzzed_segments() {
    let (mut us, templates) = connected();
    assert!(us.socket().may_recv(), "the connection opened");
    assert!(templates.iter().any(|f| f.len() > 54), "the peer sent data");
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut t = 1_000;
    let mut rebuilt = 0;
    for _ in 0..ROUNDS {
        let mut frame = if next(&mut x).is_multiple_of(8) {
            // Random bytes of a random length, half of them behind our own
            // Ethernet and IPv4 header so they reach TCP.
            let len = (next(&mut x) % 1515) as usize;
            let mut f: Vec<u8> = (0..len).map(|_| next(&mut x) as u8).collect();
            let head = &templates[0];
            if next(&mut x).is_multiple_of(2) && f.len() >= 34 && head.len() >= 34 {
                f[..34].copy_from_slice(&head[..34]);
            }
            f
        } else {
            let mut f = templates[(next(&mut x) as usize) % templates.len()].clone();
            // A few bytes changed, mostly in the IPv4 and TCP headers and
            // options, sometimes the length.
            for _ in 0..1 + next(&mut x) % 6 {
                if f.is_empty() {
                    break;
                }
                let at = if next(&mut x).is_multiple_of(4) {
                    next(&mut x) as usize % f.len()
                } else {
                    14 + next(&mut x) as usize % 46
                };
                if let Some(b) = f.get_mut(at) {
                    *b = next(&mut x) as u8;
                }
            }
            match next(&mut x) % 8 {
                0 => f.truncate(next(&mut x) as usize % (f.len() + 1)),
                1 => f.extend((0..next(&mut x) % 64).map(|_| next(&mut x) as u8)),
                _ => {}
            }
            f
        };
        if frame.len() > 1514 {
            frame.truncate(1514);
        }
        us.wire.rx.push_back(frame);
        t += (next(&mut x) % 400) as i64;
        us.poll(t);
        us.wire.tx.clear();
        let s = us.socket();
        let mut buf = [0u8; 256];
        while s.can_recv() && s.recv_slice(&mut buf).unwrap_or(0) > 0 {}
        if s.can_send() {
            let _ = s.send_slice(b"more from us");
        }
        if !s.is_open() {
            // Reset or closed by a fuzzed segment: start over.
            us = connected().0;
            rebuilt += 1;
        }
    }
    // Some segments must have been accepted far enough to end the
    // connection, or the fuzzing never got past the parser.
    assert!(rebuilt > 0, "no fuzzed segment changed the connection");
}
