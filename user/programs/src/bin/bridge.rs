//! The bridge service (#298, bridge.md, D-036): the Tier 3 channel's
//! Pharos end. It holds the second virtio-console, whose port 0 the host
//! joins to the guest's `org.pharos.bridge` port, and speaks for the guest
//! as one agent slot, nothing else.
//!
//! Handles: 1 the console, 2 the device (`device(VIRTIO_CONSOLE, 1)`), 3
//! `init`'s report endpoint, 4 `SEND` on the agent runtime badged as the
//! bridge (`pharos_proto::agents::BRIDGE`), which only `BIND` is served
//! under.
//!
//! It asks the runtime to `BIND` once a second, dropping what the guest
//! sends in between. A bound attempt's
//! capability is `SEND` on the runtime with the guest agent's slot badge:
//! the bridge attaches its buffer through it, sends the guest `HELLO`,
//! and turns each `REQUEST` frame ([`pharos_proto::bridge`]) into that
//! agent's request, one at a time, answering with a `REPLY`. A bad frame,
//! a request sent before the last one's reply, or 60 s of silence ends
//! the attempt: the guest gets `ERROR`, and the runtime the agent's `FAIL`
//! with the reason. When the runtime ends the attempt, it revokes the
//! capability; the bridge's next use fails, the guest gets `ERROR`
//! (`attempt ended`), and the bridge binds again.
//!
//! `bridge: ready` on the console says it holds the device: until then
//! the host keeps the guest off the socket (the firmware drives every
//! virtio-console, bridge.md).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_programs::virtio_console::{Console, Sizes};
use pharos_proto::agents::{self, Bound, MAX_BUFFER, Request};
use pharos_proto::bridge::{self, Bad, Decoder, Hello, MAX_PAYLOAD, Step, kind};
use pharos_proto::status;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Error, Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create,
    irq_create, irq_notify, mem_map, mem_share, receive_timeout, send, sleep, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
const REPORT: Handle = 3;
const RUNTIME: Handle = 4;
const BASE: u64 = 0x1000_0000;
/// Guest silence during an attempt, outside a pending request.
const SILENT_US: u64 = 60_000_000;
/// A request through the runtime: the gateway's 35 s and some.
const CALL_US: u64 = 40_000_000;
const BIND_US: u64 = 2_000_000;
/// Between `BIND`s while none is bound.
const IDLE_US: u64 = 1_000_000;
/// `pass`'s answer when the runtime no longer serves the attempt.
const REFUSED: &[u8] = b"refused by the runtime";
/// A frame to the guest: how long its transmit buffers may stay full.
const WRITE_US: u64 = 10_000_000;

fn say(line: &[u8]) {
    let _ = debug_write(CONSOLE, line);
}

struct Bridge {
    console: Console,
    /// Device interrupts.
    irq_ep: Handle,
    reply: Handle,
    /// The agent buffer, attached at the runtime for each attempt.
    buffer: Mapped,
    frame: Vec<u8>,
    chunk: [u8; Sizes::BRIDGE.rx],
}

/// How an attempt ended on the bridge's side.
enum End {
    /// The runtime ended it (or the guest's `COMPLETE` or `FAIL` did).
    Ended,
    /// The runtime answered `NO_SESSION`: it serves this attempt no more,
    /// though its capability may not be revoked (a restarted runtime).
    Refused,
    /// The guest broke the protocol or went silent: `FAIL` with this.
    Guest(&'static [u8]),
}

impl Bridge {
    /// Writes one frame, waiting while the transmit buffers are full.
    fn write(&mut self, kind: u8, parts: &[&[u8]]) -> bool {
        let len = parts.iter().map(|p| p.len()).sum();
        let Some(head) = bridge::write_header(kind, len) else {
            return false;
        };
        let deadline = uptime() + WRITE_US;
        for part in [&head[..]].into_iter().chain(parts.iter().copied()) {
            for piece in part.chunks(Sizes::BRIDGE.tx) {
                while self.console.send(piece).is_err() {
                    if uptime() >= deadline {
                        return false;
                    }
                    sleep(1_000);
                }
            }
        }
        true
    }

    fn error(&mut self, code: u8, reason: &[u8]) {
        let mut p = [0u8; 256];
        if let Some(n) = bridge::error(code, reason, &mut p) {
            let _ = self.write(kind::ERROR, &[&p[..n]]);
        }
    }

    /// One bound attempt, on `slot`'s capability.
    fn attempt(&mut self, slot: Handle, bound: Bound) -> End {
        let hello = Hello {
            task: bound.task,
            attempt: bound.attempt,
        };
        if !self.write(kind::HELLO, &[&hello.encode()]) {
            return End::Guest(b"guest silent");
        }
        let mut d = Decoder::default();
        let mut deadline = uptime() + SILENT_US;
        loop {
            while let Ok(Some(n)) = self.console.recv(&mut self.chunk) {
                for k in 0..n {
                    let b = self.chunk[k];
                    let (kind, len) = match d.feed(b, &mut self.frame) {
                        Step::More => continue,
                        Step::Silent => return End::Guest(b"guest silent"),
                        Step::Bad(bad) => return End::Guest(bad.reason()),
                        Step::Frame { kind, len } => (kind, len),
                    };
                    if !d.synced() {
                        // An earlier attempt's answer is passed over.
                        if Hello::parse(&self.frame[..len]) == Some(hello) {
                            d.sync();
                            deadline = uptime() + SILENT_US;
                        }
                        continue;
                    }
                    if kind != kind::REQUEST {
                        return End::Guest(Bad::Kind.reason());
                    }
                    // Bytes after the request, before its reply: a second
                    // request sent too soon.
                    if k + 1 < n {
                        return End::Guest(b"guest protocol: request before reply");
                    }
                    match self.request(slot, len) {
                        Ok(true) => deadline = uptime() + SILENT_US,
                        Ok(false) => return End::Ended,
                        Err(REFUSED) => return End::Refused,
                        Err(why) => return End::Guest(why),
                    }
                }
            }
            let now = uptime();
            if now >= deadline {
                return End::Guest(b"guest silent");
            }
            let mut msg = [0u8; 16];
            let _ = receive_timeout(self.irq_ep, &mut msg, deadline - now);
        }
    }

    /// Passes the `REQUEST` frame in the first `len` bytes of the frame
    /// buffer: `Ok(true)` once answered, `Ok(false)` if the attempt is over.
    fn request(&mut self, slot: Handle, len: usize) -> Result<bool, &'static [u8]> {
        let frame = core::mem::take(&mut self.frame);
        let out = self.pass(slot, &frame[..len]);
        self.frame = frame;
        out
    }

    fn pass(&mut self, slot: Handle, payload: &[u8]) -> Result<bool, &'static [u8]> {
        let call = bridge::parse_request(payload).map_err(Bad::reason)?;
        if call.at + call.data.len() > self.buffer.len() {
            return Err(Bad::Data.reason());
        }
        self.buffer.write_bytes(call.at, call.data);
        let mut reply = [0u8; 256];
        reply[..call.msg.len()].copy_from_slice(call.msg);
        let got = call_timeout(slot, call.msg, self.reply, &mut reply, CALL_US);
        let Ok(Received::Message { len, .. }) = got else {
            // Revoked: the runtime ended the attempt.
            self.error(status::CANCELLED, b"attempt ended");
            return Ok(false);
        };
        let reply = &reply[..len.min(256)];
        // The runtime no longer serves this attempt's badge: it ended, or
        // the runtime restarted and never minted it (#301, M6.3 review).
        if reply == [agents::NO_SESSION] {
            self.error(status::CANCELLED, b"attempt ended");
            return Err(REFUSED);
        }
        let n = bridge::reply_len(&call.req, reply).min(self.buffer.len());
        let mut data = alloc::vec![0u8; n];
        self.buffer.read_bytes(0, &mut data);
        let mut head = [0u8; 1 + bridge::MAX_MESSAGE];
        let h = bridge::reply_head(reply, &mut head).ok_or(&b"bad reply"[..])?;
        if !self.write(kind::REPLY, &[&head[..h], &data]) {
            return Err(b"guest silent");
        }
        // The agent's own end of its task.
        let ended = matches!(call.req, Request::Complete { .. } | Request::Fail { .. })
            && reply.first() == Some(&status::OK);
        Ok(!ended)
    }

    /// Nothing bound: for `us`, what the guest says is no attempt's, and
    /// is dropped as it comes (a flood is drained at the device's pace,
    /// #300), so the next attempt's `HELLO` is not behind it.
    fn discard(&mut self, us: u64) {
        let until = uptime() + us;
        loop {
            while let Ok(Some(_)) = self.console.recv(&mut self.chunk) {}
            let now = uptime();
            if now >= until {
                return;
            }
            let mut msg = [0u8; 16];
            let _ = receive_timeout(self.irq_ep, &mut msg, until - now);
        }
    }

    /// Attaches the buffer through the attempt's capability, zeroed first,
    /// so no earlier attempt's bytes reach this one in a reply's gaps
    /// (#301, M6.3 review: `TASK`'s between its input and checkpoint).
    fn attach(&self, slot: Handle) -> bool {
        self.buffer
            .write_bytes(0, &alloc::vec![0u8; self.buffer.len()]);
        let mut msg = [0u8; 16];
        let Some(n) = agents::encode(&Request::Attach { len: MAX_BUFFER }, &mut msg) else {
            return false;
        };
        mem_share(&self.buffer).is_ok_and(|memory| {
            let sent = send(slot, &msg[..n], memory, READ | WRITE, 0).is_ok();
            let _ = delete(memory);
            sent
        })
    }
}

/// `BIND`: a waiting guest attempt's capability, or none.
fn bind(reply: Handle) -> Option<(Handle, Bound)> {
    let mut req = [0u8; 8];
    let n = agents::encode(&Request::Bind, &mut req)?;
    let mut msg = [0u8; 256];
    match call_timeout(RUNTIME, &req[..n], reply, &mut msg, BIND_US) {
        Ok(Received::Message { len, cap, .. }) if cap != 0 => {
            match Bound::parse(&msg[..len.min(256)]) {
                Some(b) => Some((cap, b)),
                None => {
                    let _ = delete(cap);
                    None
                }
            }
        }
        _ => None,
    }
}

fn main(_: u64) -> u64 {
    let Ok(irq_ep) = endpoint_create() else {
        return 1;
    };
    let Ok(reply) = endpoint_create() else {
        return 1;
    };
    let Ok(irq) = irq_create(DEVICE, 0) else {
        return 2;
    };
    if irq_notify(irq, irq_ep, 0).is_err() {
        return 3;
    }
    let Ok(console) = Console::init(DEVICE, 0, BASE, Sizes::BRIDGE) else {
        say(b"bridge: the channel's virtio-console did not start");
        return 4;
    };
    let Ok(buffer) = mem_map(MAX_BUFFER) else {
        return 5;
    };
    let mut b = Bridge {
        console,
        irq_ep,
        reply,
        buffer,
        frame: alloc::vec![0u8; MAX_PAYLOAD],
        chunk: [0u8; Sizes::BRIDGE.rx],
    };
    say(b"bridge: ready");
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 6;
    }
    loop {
        let Some((slot, bound)) = bind(reply) else {
            b.discard(IDLE_US);
            continue;
        };
        say(b"bridge: bound");
        if !b.attach(slot) {
            let _ = delete(slot);
            continue;
        }
        match b.attempt(slot, bound) {
            End::Ended => {}
            End::Refused => {
                // Nothing to probe: the runtime answers it no more (#301).
                say(b"bridge: refused by the runtime");
                let _ = delete(slot);
                continue;
            }
            End::Guest(why) => {
                b.error(status::BAD_REQUEST, why);
                let mut msg = [0u8; 256];
                let n = agents::encode(&Request::Fail { reason: why }, &mut msg).unwrap_or(0);
                let req = msg[..n].to_vec();
                let _ = call_timeout(slot, &req, reply, &mut msg, CALL_US);
                say(b"bridge: attempt failed");
            }
        }
        // The runtime revoked the attempt's capability as it ended it.
        if try_send(slot, b"x") == Err(Error::Revoked) {
            say(b"bridge: unbound");
        } else {
            say(b"bridge: the ended attempt's capability still works");
        }
        let _ = delete(slot);
    }
}
