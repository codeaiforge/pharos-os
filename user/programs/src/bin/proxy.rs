//! A compromised network and audit service for the `tls` test kernel
//! (#277, M6.1 review F1 and F5). `init` puts it in front of both: the TLS
//! service's `SEND` on the network service is badged 1 here, and its
//! `SEND` on the audit service badged 2. It passes every request on
//! unchanged, except:
//!
//! - a TCP connection to [`ROGUE`] is its own: connected, every write
//!   taken, and every `TCP_POLL` answered with a count of `u32::MAX`, far
//!   more than was asked for (F1);
//! - the success outcome of an intent naming `dest 5` is refused with
//!   `UNWRITABLE`, as from a full trail (F5).
//!
//! The TLS service shares its buffer without `GRANT`, so the proxy cannot
//! pass it on: it attaches a buffer of its own at the network service and
//! copies a `TCP_WRITE`'s bytes in before passing it on, and a `TCP_POLL`'s
//! out after.
//!
//! Capabilities, in handle order: 1 the debug console, 2 `RECEIVE` on its
//! endpoint, 3 `init`'s report endpoint, 4 `SEND` on the network service
//! with the TLS service's badge and destinations, 5 `SEND` on the audit
//! service as the TLS service's client.

#![no_std]
#![no_main]

use pharos_proto::audit::{self, Kind, outcome};
use pharos_proto::net::{self, Request as NetRequest, encode_count, encode_opened};
use pharos_proto::status;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map,
    mem_map_cap, mem_share, receive, send, try_send,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const NET: Handle = 4;
const AUDIT: Handle = 5;
/// The destination whose connection the proxy fakes (tables.rs).
const ROGUE: ([u8; 4], u16) = ([10, 0, 2, 2], 47_448);
/// The faked connection's number: the network service has 16.
const FAKE: u8 = 200;
const CALL_US: u64 = 1_000_000;

fn main(_: u64) -> u64 {
    let Ok(reply) = endpoint_create() else {
        let _ = debug_write(CONSOLE, b"proxy: cannot create an endpoint");
        return 1;
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 1;
    }
    // The sequence number of the intent whose success is refused.
    let mut refused = None;
    // The TLS service's buffer, and the proxy's at the network service.
    let mut bufs: Option<(Mapped, Mapped)> = None;
    // A message is at most 256 bytes; a larger buffer is refused.
    let mut buf = [0u8; 256];
    loop {
        let Ok(Received::Message { len, cap, badge }) = receive(SERVICE, &mut buf) else {
            let _ = debug_write(CONSOLE, b"proxy: receive failed");
            return 1;
        };
        let msg = &buf[..len.min(buf.len())];
        let own: Option<&[u8]> = match badge {
            1 => match net::parse(msg) {
                // The TLS service's buffer, passed on with the request.
                Ok(NetRequest::Attach { len }) => {
                    let theirs = mem_map_cap(cap, true, len).ok();
                    let ours = mem_map(len).ok().filter(|m| {
                        mem_share(m).is_ok_and(|c| send(NET, msg, c, READ | WRITE, 0).is_ok())
                    });
                    bufs = theirs.zip(ours);
                    continue;
                }
                Ok(NetRequest::TcpConnect { ip, port }) if (ip, port) == ROGUE => {
                    Some(&encode_opened(net::OK, FAKE))
                }
                Ok(NetRequest::TcpPoll { conn: FAKE, .. }) => {
                    Some(&encode_count(net::OK, u32::MAX))
                }
                Ok(NetRequest::TcpWrite {
                    conn: FAKE, len, ..
                }) => Some(&encode_count(net::OK, len)),
                Ok(NetRequest::TcpClose { conn: FAKE }) => Some(&[net::OK]),
                _ => None,
            },
            2 => match audit::parse(msg) {
                Ok(audit::Request::Append(e))
                    if e.kind == Kind::Outcome
                        && e.outcome == outcome::OK
                        && Some(e.refers) == refused =>
                {
                    Some(&[audit::UNWRITABLE])
                }
                _ => None,
            },
            _ => Some(&[status::BAD_REQUEST]),
        };
        let mut out = [0u8; 256];
        let n = match own {
            Some(bytes) => {
                out[..bytes.len()].copy_from_slice(bytes);
                bytes.len()
            }
            None => {
                let to = if badge == 1 { NET } else { AUDIT };
                if let (Ok(NetRequest::TcpWrite { offset, len, .. }), Some((t, o))) =
                    (net::parse(msg), &bufs)
                {
                    copy(t, o, offset as usize, len as usize);
                }
                match call_timeout(to, msg, reply, &mut out, CALL_US) {
                    Ok(Received::Message { len, .. }) => len.min(out.len()),
                    _ => 0,
                }
            }
        };
        if let (Ok(NetRequest::TcpPoll { offset, .. }), Some((t, o)), Some((net::OK, got))) =
            (net::parse(msg), &bufs, net::parse_count(&out[..n]))
            && badge == 1
        {
            copy(o, t, offset as usize, got as usize);
        }
        // Note the intent to refuse once the audit service has stored it.
        if badge == 2
            && n == 9
            && out[0] == status::OK
            && let Ok(audit::Request::Append(e)) = audit::parse(msg)
            && e.kind == Kind::Intent
            && e.detail.windows(6).any(|w| w == b"dest 5")
        {
            refused = out[1..9].try_into().ok().map(u64::from_le_bytes);
        }
        if n > 0 {
            let _ = try_send(cap, &out[..n]);
        }
        let _ = delete(cap);
    }
}

/// Copies `len` bytes at `at` from `from` to `to`, if both hold them.
fn copy(from: &Mapped, to: &Mapped, at: usize, len: usize) {
    let end = at.saturating_add(len);
    if end > from.len() || end > to.len() {
        return;
    }
    let mut chunk = [0u8; 1024];
    let mut i = at;
    while i < end {
        let n = (end - i).min(chunk.len());
        from.read_bytes(i, &mut chunk[..n]);
        to.write_bytes(i, &chunk[..n]);
        i += n;
    }
}
