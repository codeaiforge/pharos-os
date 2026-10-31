//! The minimal network stack (D-015, networking.md): Ethernet II, ARP,
//! IPv4 (no options, no fragments), ICMP echo, and UDP. Parsing is pure
//! and allocation-free; every length, checksum, and field is checked
//! before use, and [`classify`] is fuzzed on the host. Builders write
//! complete frames, so clients never supply a header.

/// Our IPv4 address on the slirp network.
pub const OUR_IP: [u8; 4] = [10, 0, 2, 15];
/// The slirp gateway (and host).
pub const GATEWAY: [u8; 4] = [10, 0, 2, 2];
/// The broadcast MAC address.
pub const BROADCAST: [u8; 6] = [0xff; 6];

const ETH: usize = 14;
const IP: usize = 20;
const UDP: usize = 8;
/// Largest UDP payload in one Ethernet frame.
pub const MAX_UDP_PAYLOAD: usize = 1500 - IP - UDP;

/// Why a frame was dropped; each reason has a counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Drop {
    Short = 0,
    NotForUs,
    EtherType,
    ArpFormat,
    IpHeader,
    IpChecksum,
    Fragment,
    Protocol,
    IcmpChecksum,
    IcmpType,
    UdpLength,
    UdpChecksum,
}

/// Number of [`Drop`] reasons.
pub const DROP_REASONS: usize = 12;

/// A frame worth acting on.
#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    /// Someone asks for our MAC.
    ArpRequest { mac: [u8; 6], ip: [u8; 4] },
    /// An answer: `ip` is at `mac`.
    ArpReply { mac: [u8; 6], ip: [u8; 4] },
    /// A ping to us.
    EchoRequest {
        mac: [u8; 6],
        ip: [u8; 4],
        id: u16,
        seq: u16,
        data: &'a [u8],
    },
    /// An answer to one of our pings.
    EchoReply { ip: [u8; 4], id: u16, seq: u16 },
    /// A datagram to us.
    Udp {
        ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Adds `bytes` to a one's-complement sum.
fn sum(mut acc: u32, bytes: &[u8]) -> u32 {
    for pair in bytes.chunks(2) {
        acc += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The Internet checksum of `bytes`.
pub fn checksum(bytes: &[u8]) -> u16 {
    fold(sum(0, bytes))
}

/// The UDP checksum over the pseudo header and `segment` (header and
/// payload). 0 is sent as `0xffff`.
fn udp_checksum(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
    let mut acc = sum(0, &src);
    acc = sum(acc, &dst);
    acc += 17 + segment.len() as u32;
    match fold(sum(acc, segment)) {
        0 => 0xffff,
        c => c,
    }
}

/// Parses `frame` as received by `mac` (ours): every check in the stack.
pub fn classify(frame: &[u8], mac: [u8; 6]) -> Result<Packet<'_>, Drop> {
    if frame.len() < ETH {
        return Err(Drop::Short);
    }
    let dst: [u8; 6] = frame[..6].try_into().map_err(|_| Drop::Short)?;
    if dst != mac && dst != BROADCAST {
        return Err(Drop::NotForUs);
    }
    let src: [u8; 6] = frame[6..12].try_into().map_err(|_| Drop::Short)?;
    let body = &frame[ETH..];
    match be16(frame, 12) {
        0x0806 => arp(body),
        0x0800 if dst == mac => ipv4(body, src),
        0x0800 => Err(Drop::NotForUs),
        _ => Err(Drop::EtherType),
    }
}

fn arp(b: &[u8]) -> Result<Packet<'_>, Drop> {
    if b.len() < 28 {
        return Err(Drop::Short);
    }
    // Ethernet hardware, IPv4 protocol, 6- and 4-byte addresses.
    if b[..6] != [0, 1, 0x08, 0x00, 6, 4] {
        return Err(Drop::ArpFormat);
    }
    let mac: [u8; 6] = b[8..14].try_into().map_err(|_| Drop::Short)?;
    let ip: [u8; 4] = b[14..18].try_into().map_err(|_| Drop::Short)?;
    if b[24..28] != OUR_IP {
        return Err(Drop::NotForUs);
    }
    match be16(b, 6) {
        1 => Ok(Packet::ArpRequest { mac, ip }),
        2 => Ok(Packet::ArpReply { mac, ip }),
        _ => Err(Drop::ArpFormat),
    }
}

fn ipv4(b: &[u8], mac: [u8; 6]) -> Result<Packet<'_>, Drop> {
    if b.len() < IP {
        return Err(Drop::Short);
    }
    // Version 4 and a 20-byte header: no options.
    if b[0] != 0x45 {
        return Err(Drop::IpHeader);
    }
    let total = usize::from(be16(b, 2));
    if total < IP || total > b.len() {
        return Err(Drop::IpHeader);
    }
    if checksum(&b[..IP]) != 0 {
        return Err(Drop::IpChecksum);
    }
    // More fragments, or a fragment offset.
    if be16(b, 6) & 0x3fff != 0 {
        return Err(Drop::Fragment);
    }
    if b[16..20] != OUR_IP {
        return Err(Drop::NotForUs);
    }
    let ip: [u8; 4] = b[12..16].try_into().map_err(|_| Drop::Short)?;
    let payload = &b[IP..total];
    match b[9] {
        1 => icmp(payload, mac, ip),
        17 => udp(payload, ip),
        _ => Err(Drop::Protocol),
    }
}

fn icmp(b: &[u8], mac: [u8; 6], ip: [u8; 4]) -> Result<Packet<'_>, Drop> {
    if b.len() < 8 {
        return Err(Drop::Short);
    }
    if checksum(b) != 0 {
        return Err(Drop::IcmpChecksum);
    }
    let (id, seq) = (be16(b, 4), be16(b, 6));
    match (b[0], b[1]) {
        (8, 0) => Ok(Packet::EchoRequest {
            mac,
            ip,
            id,
            seq,
            data: &b[8..],
        }),
        (0, 0) => Ok(Packet::EchoReply { ip, id, seq }),
        _ => Err(Drop::IcmpType),
    }
}

fn udp(b: &[u8], ip: [u8; 4]) -> Result<Packet<'_>, Drop> {
    if b.len() < UDP {
        return Err(Drop::Short);
    }
    let len = usize::from(be16(b, 4));
    if len < UDP || len > b.len() {
        return Err(Drop::UdpLength);
    }
    let segment = &b[..len];
    if be16(b, 6) != 0 {
        let mut acc = sum(0, &ip);
        acc = sum(acc, &OUR_IP);
        acc += 17 + len as u32;
        if fold(sum(acc, segment)) != 0 {
            return Err(Drop::UdpChecksum);
        }
    }
    Ok(Packet::Udp {
        ip,
        src_port: be16(b, 0),
        dst_port: be16(b, 2),
        payload: &segment[UDP..],
    })
}

/// An ARP request or reply from us (`mac`, [`OUR_IP`]) to `to`/`to_ip`
/// (broadcast and zero MAC for a request).
pub fn arp_frame(mac: [u8; 6], reply: bool, to: [u8; 6], to_ip: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(if reply { &to } else { &BROADCAST });
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, if reply { 2 } else { 1 }]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&OUR_IP);
    if reply {
        f[32..38].copy_from_slice(&to);
    }
    f[38..42].copy_from_slice(&to_ip);
    f
}

/// Writes Ethernet and IPv4 headers for `payload_len` bytes of `proto`
/// into `out`; returns the IP payload offset.
fn ip_header(
    out: &mut [u8],
    mac: [u8; 6],
    to: [u8; 6],
    dst: [u8; 4],
    proto: u8,
    payload_len: usize,
) -> usize {
    out[..6].copy_from_slice(&to);
    out[6..12].copy_from_slice(&mac);
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    let total = (IP + payload_len) as u16;
    let h = &mut out[ETH..ETH + IP];
    h.copy_from_slice(&[0; IP]);
    h[0] = 0x45;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[8] = 64;
    h[9] = proto;
    h[12..16].copy_from_slice(&OUR_IP);
    h[16..20].copy_from_slice(&dst);
    let c = checksum(h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    ETH + IP
}

/// A UDP datagram frame into `out` (at least 1514 bytes); returns its
/// length, or `None` if the payload is too large.
#[allow(clippy::too_many_arguments)]
pub fn udp_frame(
    out: &mut [u8],
    mac: [u8; 6],
    to: [u8; 6],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    if payload.len() > MAX_UDP_PAYLOAD || out.len() < ETH + IP + UDP + payload.len() {
        return None;
    }
    let at = ip_header(out, mac, to, dst, 17, UDP + payload.len());
    let len = (UDP + payload.len()) as u16;
    out[at..at + 2].copy_from_slice(&src_port.to_be_bytes());
    out[at + 2..at + 4].copy_from_slice(&dst_port.to_be_bytes());
    out[at + 4..at + 6].copy_from_slice(&len.to_be_bytes());
    out[at + 6..at + 8].copy_from_slice(&[0, 0]);
    out[at + UDP..at + UDP + payload.len()].copy_from_slice(payload);
    let end = at + usize::from(len);
    let c = udp_checksum(OUR_IP, dst, &out[at..end]);
    out[at + 6..at + 8].copy_from_slice(&c.to_be_bytes());
    Some(end)
}

/// An ICMP echo (request, or reply with `reply`) frame into `out`; returns
/// its length, or `None` if `data` is too large.
#[allow(clippy::too_many_arguments)]
pub fn echo_frame(
    out: &mut [u8],
    mac: [u8; 6],
    to: [u8; 6],
    dst: [u8; 4],
    reply: bool,
    id: u16,
    seq: u16,
    data: &[u8],
) -> Option<usize> {
    if data.len() > 1500 - IP - 8 || out.len() < ETH + IP + 8 + data.len() {
        return None;
    }
    let at = ip_header(out, mac, to, dst, 1, 8 + data.len());
    out[at] = if reply { 0 } else { 8 };
    out[at + 1..at + 4].copy_from_slice(&[0, 0, 0]);
    out[at + 4..at + 6].copy_from_slice(&id.to_be_bytes());
    out[at + 6..at + 8].copy_from_slice(&seq.to_be_bytes());
    out[at + 8..at + 8 + data.len()].copy_from_slice(data);
    let end = at + 8 + data.len();
    let c = checksum(&out[at..end]);
    out[at + 2..at + 4].copy_from_slice(&c.to_be_bytes());
    Some(end)
}

/// Where to send a packet for `ip`: itself on our /24, else the gateway.
pub fn next_hop(ip: [u8; 4]) -> [u8; 4] {
    if ip[..3] == OUR_IP[..3] { ip } else { GATEWAY }
}

/// Entries the ARP cache keeps.
pub const ARP_ENTRIES: usize = 8;

/// IP to MAC, at most [`ARP_ENTRIES`], replacing the oldest.
#[derive(Default)]
pub struct ArpCache {
    entries: [Option<([u8; 4], [u8; 6])>; ARP_ENTRIES],
    next: usize,
}

impl ArpCache {
    pub fn lookup(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.0 == ip)
            .map(|e| e.1)
    }

    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        if let Some(e) = self.entries.iter_mut().flatten().find(|e| e.0 == ip) {
            e.1 = mac;
            return;
        }
        self.entries[self.next] = Some((ip, mac));
        self.next = (self.next + 1) % ARP_ENTRIES;
    }
}

/// Client calls (networking.md), over the shared codec in
/// [`pharos_proto::net`] (interface version 1, D-019).
pub mod client {
    use pharos_proto::net::{Request, encode, parse_datagram, parse_stats};
    use pharos_user::{Error, Handle, Received, call_reply};

    pub use pharos_proto::net::{BAD_REQUEST, BUSY, MAX_PAYLOAD, NO_PORT, NO_ROOM, OK};

    /// Sends `req` by `call`; returns the reply's length in `buf`.
    fn call(
        net: Handle,
        reply: Handle,
        req: &Request<'_>,
        buf: &mut [u8; 256],
    ) -> Result<usize, Error> {
        let mut msg = [0u8; 256];
        let n = encode(req, &mut msg).ok_or(Error::TooLarge)?;
        match call_reply(net, &msg[..n], reply, buf)? {
            Received::Message { len, .. } if len >= 1 => Ok(len.min(buf.len())),
            _ => Err(Error::Other(0)),
        }
    }

    /// Sends `payload` to `ip:port`; returns the service's status.
    pub fn send_to(
        net: Handle,
        reply_ep: Handle,
        ip: [u8; 4],
        port: u16,
        payload: &[u8],
    ) -> Result<u8, Error> {
        let mut buf = [0u8; 256];
        call(
            net,
            reply_ep,
            &Request::Send { ip, port, payload },
            &mut buf,
        )?;
        Ok(buf[0])
    }

    /// Waits for a datagram; returns `(status, source ip, source port,
    /// payload length)` with the payload in `out`.
    pub fn recv(
        net: Handle,
        reply_ep: Handle,
        out: &mut [u8],
    ) -> Result<(u8, [u8; 4], u16, usize), Error> {
        let mut buf = [0u8; 256];
        let n = call(net, reply_ep, &Request::Recv, &mut buf)?;
        match parse_datagram(&buf[..n]) {
            Some((ip, port, payload)) => {
                let len = payload.len().min(out.len());
                out[..len].copy_from_slice(&payload[..len]);
                Ok((OK, ip, port, len))
            }
            None => Ok((buf[0], [0; 4], 0, 0)),
        }
    }

    /// Pings `ip` and waits for the reply; returns the status.
    pub fn ping(net: Handle, reply_ep: Handle, ip: [u8; 4], seq: u16) -> Result<u8, Error> {
        let mut buf = [0u8; 256];
        call(net, reply_ep, &Request::Ping { ip, seq }, &mut buf)?;
        Ok(buf[0])
    }

    /// The service's counters, in [`super::stat`] order.
    pub fn stats(net: Handle, reply_ep: Handle) -> Result<(u8, [u32; super::STATS]), Error> {
        let mut buf = [0u8; 256];
        let n = call(net, reply_ep, &Request::Stats, &mut buf)?;
        Ok((buf[0], parse_stats(&buf[..n]).unwrap_or_default()))
    }

    /// Sends raw bytes by `call` (for tests of refusals); returns the reply
    /// and its length.
    pub fn raw(net: Handle, reply_ep: Handle, msg: &[u8]) -> Result<([u8; 256], usize), Error> {
        let mut buf = [0u8; 256];
        match call_reply(net, msg, reply_ep, &mut buf)? {
            Received::Message { len, .. } => Ok((buf, len.min(buf.len()))),
            _ => Err(Error::Other(0)),
        }
    }
}

/// Counters the service reports with `stats`.
pub use pharos_proto::net::STATS;

/// Indexes into the `stats` counters.
pub mod stat {
    pub const RECEIVED: usize = 0;
    pub const SENT: usize = 1;
    /// Frames dropped by [`super::classify`] (malformed, or not for us).
    pub const DROPPED: usize = 2;
    /// Datagrams for a port no client holds.
    pub const NO_PORT: usize = 3;
    /// Replies dropped because the client was not waiting.
    pub const REPLY_DROPPED: usize = 4;
    /// Datagrams dropped from a full client queue.
    pub const QUEUE_FULL: usize = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const PEER: [u8; 6] = [0x52, 0x55, 10, 0, 2, 2];

    fn udp_to_us(payload: &[u8]) -> ([u8; 1514], usize) {
        // Built as the gateway would send it to us: swap the roles.
        let mut out = [0u8; 1514];
        let n = udp_frame(&mut out, PEER, MAC, OUR_IP, 47000, 40000, payload).unwrap();
        // udp_frame writes our IP as source; make it the gateway's.
        out[26..30].copy_from_slice(&GATEWAY);
        out[24..26].copy_from_slice(&[0, 0]);
        let c = checksum(&out[14..34]);
        out[24..26].copy_from_slice(&c.to_be_bytes());
        out[40..42].copy_from_slice(&[0, 0]);
        let c = udp_checksum(GATEWAY, OUR_IP, &out[34..n]);
        out[40..42].copy_from_slice(&c.to_be_bytes());
        (out, n)
    }

    #[test]
    fn checksums_match_known_values() {
        // RFC 1071 example words.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            !0xddf2
        );
        assert_eq!(checksum(&[]), 0xffff);
        assert_eq!(checksum(&[0xff]), !0xff00);
    }

    #[test]
    fn udp_round_trips_and_every_check_bites() {
        let (f, n) = udp_to_us(b"hello");
        assert_eq!(
            classify(&f[..n], MAC),
            Ok(Packet::Udp {
                ip: GATEWAY,
                src_port: 47000,
                dst_port: 40000,
                payload: b"hello"
            })
        );
        let bad = |at: usize, v: u8| {
            let mut g = f;
            g[at] ^= v;
            classify(&g[..n], MAC).err()
        };
        assert_eq!(bad(0, 1), Some(Drop::NotForUs), "another MAC");
        assert_eq!(bad(12, 0x10), Some(Drop::EtherType));
        assert_eq!(bad(14, 0x01), Some(Drop::IpHeader), "options");
        assert_eq!(
            bad(22, 1),
            Some(Drop::IpChecksum),
            "TTL changed, checksum not"
        );
        assert_eq!(bad(33, 1), Some(Drop::IpChecksum), "destination changed");
        assert_eq!(bad(23, 2), Some(Drop::IpChecksum), "protocol changed");
        assert_eq!(bad(43, 1), Some(Drop::UdpChecksum), "payload changed");
        assert_eq!(classify(&f[..20], MAC), Err(Drop::Short));
        assert_eq!(classify(&f[..n - 1], MAC), Err(Drop::IpHeader), "truncated");
        let mut zero = f;
        zero[40..42].copy_from_slice(&[0, 0]);
        assert!(
            matches!(classify(&zero[..n], MAC), Ok(Packet::Udp { .. })),
            "no checksum"
        );
        let mut frag = f;
        frag[20] = 0x20; // more fragments
        let c = {
            frag[24..26].copy_from_slice(&[0, 0]);
            checksum(&frag[14..34])
        };
        frag[24..26].copy_from_slice(&c.to_be_bytes());
        assert_eq!(classify(&frag[..n], MAC), Err(Drop::Fragment));

        // A valid IPv4 header around a UDP segment shorter than its 8-byte
        // header (the fuzzer cannot reach this: it needs the IP checksum).
        let with_total = |total: usize| {
            let mut g = f;
            g[16..18].copy_from_slice(&(total as u16).to_be_bytes());
            g[24..26].copy_from_slice(&[0, 0]);
            let c = checksum(&g[14..34]);
            g[24..26].copy_from_slice(&c.to_be_bytes());
            g
        };
        for short in 0..UDP {
            let g = with_total(IP + short);
            assert_eq!(
                classify(&g[..14 + IP + short], MAC),
                Err(Drop::Short),
                "{short}-byte UDP segment"
            );
        }
        // The UDP length field below its header or past the segment.
        for len in [0u16, 7, 14] {
            let mut g = f;
            g[38..40].copy_from_slice(&len.to_be_bytes());
            assert_eq!(
                classify(&g[..n], MAC),
                Err(Drop::UdpLength),
                "UDP length {len}"
            );
        }
    }

    #[test]
    fn arp_and_echo_round_trip() {
        let req = arp_frame(PEER, false, [0; 6], OUR_IP);
        assert_eq!(
            classify(&req, MAC),
            Ok(Packet::ArpRequest {
                mac: PEER,
                ip: OUR_IP
            })
        );
        let mut wrong = req;
        wrong[41] = 99;
        assert_eq!(
            classify(&wrong, MAC),
            Err(Drop::NotForUs),
            "asks for another IP"
        );
        wrong = req;
        wrong[18] = 8;
        assert_eq!(classify(&wrong, MAC), Err(Drop::ArpFormat));
        let mut out = [0u8; 1514];
        let n = echo_frame(&mut out, PEER, MAC, OUR_IP, false, 7, 9, b"abc").unwrap();
        // Make the gateway the sender.
        out[26..30].copy_from_slice(&GATEWAY);
        out[24..26].copy_from_slice(&[0, 0]);
        let c = checksum(&out[14..34]);
        out[24..26].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            classify(&out[..n], MAC),
            Ok(Packet::EchoRequest {
                mac: PEER,
                ip: GATEWAY,
                id: 7,
                seq: 9,
                data: b"abc"
            })
        );
        out[n - 1] ^= 1;
        assert_eq!(classify(&out[..n], MAC), Err(Drop::IcmpChecksum));
    }

    #[test]
    fn routing_and_the_arp_cache() {
        assert_eq!(next_hop([10, 0, 2, 9]), [10, 0, 2, 9]);
        assert_eq!(next_hop([8, 8, 8, 8]), GATEWAY);
        let mut cache = ArpCache::default();
        for i in 0..9u8 {
            cache.insert([10, 0, 2, i], [i; 6]);
        }
        assert_eq!(cache.lookup([10, 0, 2, 0]), None, "oldest replaced");
        assert_eq!(cache.lookup([10, 0, 2, 8]), Some([8; 6]));
        cache.insert([10, 0, 2, 8], [1; 6]);
        assert_eq!(
            cache.lookup([10, 0, 2, 8]),
            Some([1; 6]),
            "updated in place"
        );
    }

    #[test]
    fn fuzzed_frames_never_panic() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let (udp, n) = udp_to_us(b"payload for mutation");
        let arp = arp_frame(PEER, true, MAC, GATEWAY);
        let mut accepted = 0;
        for i in 0..100_000 {
            let mut f = [0u8; 1600];
            let len = match i % 3 {
                // Mutated valid frames: a few random bytes changed, a random length.
                0 | 1 => {
                    let (src, sn) = if i % 3 == 0 {
                        (&udp[..n], n)
                    } else {
                        (&arp[..], 42)
                    };
                    f[..sn].copy_from_slice(src);
                    for _ in 0..(next() % 4 + 1) {
                        let at = (next() as usize) % sn;
                        f[at] = next() as u8;
                    }
                    (next() as usize) % (sn + 8)
                }
                // Random frames addressed to us.
                _ => {
                    for b in f.iter_mut() {
                        *b = next() as u8;
                    }
                    f[..6].copy_from_slice(&MAC);
                    (next() as usize) % 1600
                }
            };
            if classify(&f[..len], MAC).is_ok() {
                accepted += 1;
            }
        }
        assert!(accepted > 0, "mutations must sometimes stay valid");
    }
}
