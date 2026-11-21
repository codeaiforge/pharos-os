//! Network constants, the client side of the network interface, and the
//! counters' indexes (networking.md). The stack itself is smoltcp in the
//! network service since #270 (D-034, tls.md); the own Ethernet, ARP, IPv4,
//! ICMP, and UDP parsers and builders it replaced are retired with their
//! tests.

/// Our IPv4 address on the slirp network.
pub const OUR_IP: [u8; 4] = [10, 0, 2, 15];
/// The slirp gateway (and host).
pub const GATEWAY: [u8; 4] = [10, 0, 2, 2];

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
    /// Frames dropped before smoltcp saw them (its queue was full), and
    /// datagrams over the interface's payload limit.
    pub const DROPPED: usize = 2;
    /// Datagrams for a port no client holds.
    pub const NO_PORT: usize = 3;
    /// Replies dropped because the client was not waiting.
    pub const REPLY_DROPPED: usize = 4;
    /// Datagrams dropped from a full client queue.
    pub const QUEUE_FULL: usize = 5;
}
