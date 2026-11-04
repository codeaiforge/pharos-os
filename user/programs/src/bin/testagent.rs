//! A test agent for the `agents` test kernel (#98), started by the agent
//! runtime with one capability: handle 1, `SEND` on the runtime, badged
//! with its slot. It creates a reply endpoint and a buffer of its own,
//! asks for its task, and does what the input says:
//!
//! - `complete`: logs `working`, completes with `done: <input>`;
//! - `crash-once`: crashes on attempt 1, completes after;
//! - `crash`: crashes (a page fault); `exit`: exits with 3; `hang`: spins;
//! - `fail`: fails with `asked to fail`;
//! - `infer`: model 1 (not in its manifest) must be refused, then generates
//!   from model 2 and completes with the text;
//! - `probe`: completes with `probe ok` if control requests are refused;
//! - `wait`: keeps asking `INFO` every 200 ms until stopped;
//! - `keys`: checks `BEGIN` answers `GO`, `UNKNOWN`, and `DONE` (#99);
//! - `resume`: stores checkpoint `half` and crashes; on attempt 2 completes
//!   with `resumed half` if the checkpoint came back;
//! - `durable`: stores checkpoint `step1`, does keyed operation `sent`,
//!   logs `ready to stop`, and waits; on a later attempt (after the runtime
//!   was replaced) completes with `recovered sent` if the checkpoint came
//!   back and the operation answers `DONE`;
//! - `count` (the `agents_crash` kernel): counts to [`COUNT`], one keyed
//!   operation and one checkpoint per step, checking on every attempt that
//!   each step before its checkpoint is recorded as done.
//! - `keeper-a` (the `permissions` kernel, #105): its file `notes` is not
//!   found, then written and read back, and it generates from model 2;
//!   completes with `a ok`;
//! - `keeper-b`: opens a session on model 2, logs `holding a session`,
//!   and polls until `trust` revokes its permissions: reading `notes`
//!   until `NO_ACCESS`, then `INFER` (`BUSY` while its session is open)
//!   until `NO_ACCESS`; then its session must be gone and writing refused,
//!   and it crashes. On attempt 2 both must still be refused (a revocation
//!   holds for the task); completes with `b ok`.
//! - `ask` (agent `asker`, #106): `ASK` for a network destination (not
//!   askable) is refused at once, and model 2 is refused before it asks;
//!   asked for 2 s, model 2 is pending until the user answers `yes`, then
//!   generates, and is refused again once the 2 s are over; `data write`
//!   is refused by the user and refused again without a new prompt; `data
//!   read` is refused when nobody answers in time; completes with `ask ok`.
//! - `keeper-c` (#108): writes its file, logs `audit me` (the kernel then
//!   kills the audit service), and writes until refused with `NO_AUDIT`;
//!   inference is refused the same way, reading still works; completes with
//!   `c ok`;
//! - `keeper-d` (#108): started after the audit service died, so its grants
//!   could not be recorded and it has none: reading its file is refused;
//!   completes with `d ok`.
//! - `net-quiet` (agent `listener`, the `agents_net` kernel, #109): holds
//!   the same grant as `net-talk` but never sends, and must receive nothing
//!   while `net-talk` runs; completes with `quiet ok`.
//! - `net-talk` (agent `netter`): a destination it does not hold is refused, an oversized
//!   datagram too; it exchanges one with the host echo server, sends `late`
//!   there and does not read the echo; asking for a destination not
//!   askable is refused, asking for `10.0.2.2:47001` waits for the user's
//!   `yes`, and then sending there works; once the user revokes
//!   `10.0.2.2:47000`, the `late` echo is never delivered and sending
//!   there is refused; completes with `talk ok`.
//! - `hostile` (agent `hostile`, the `hostile` kernel, #110): logs `check
//!   me` (the kernel inspects what it holds), then tries what it must not
//!   be able to do, each refused as listed in testing.md: every other
//!   handle and every other use of handle 1, memory over its limit, the
//!   network, control and `trust` requests (approving its own request
//!   among them), malformed and out-of-bounds fields and file names
//!   reaching outside its own files, a log line that looks like an
//!   approval prompt, a buffer revoked under the runtime, the approval
//!   queue filled, and a flood of requests; completes with `hostile ok`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_proto::agents::{
    self, Asked, Assigned, Begun, CHECKPOINT_AT, CONTROL, Datagram, Deps, KEY, MAX_BUFFER,
    MAX_DATAGRAM, NO_AUDIT, NO_SESSION, Request, encode,
};
use pharos_proto::infer::{Started, Tokens};
use pharos_proto::permission::Permission;
use pharos_proto::status;
use pharos_user::rights::SEND;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, config_read, debug_write, delete, dma_alloc,
    endpoint_create, irq_create, mem_map, mem_map_buffer, mem_share, mmio_map, open, process_stop,
    receive_timeout, revoke, send, sleep, spawn, try_send, uptime,
};

pharos_user::entry!(main);

const RUNTIME: Handle = 1;
const BUFFER: u64 = MAX_BUFFER;
/// The `count` task's steps.
/// At most `MAX_KEYS` (32): one key per step.
const COUNT: u32 = 30;
const TIMEOUT_US: u64 = 60_000_000;

/// A `BEGIN` answer, owned.
#[derive(PartialEq, Eq)]
enum Got {
    Go,
    Done(Vec<u8>),
    Unknown,
}

struct Agent {
    reply: Handle,
    buffer: Mapped,
}

impl Agent {
    /// A call to the runtime: the reply's status and length.
    fn call(&self, req: &Request<'_>, out: &mut [u8; 256]) -> (u8, usize) {
        let mut msg = [0u8; 256];
        let Some(n) = encode(req, &mut msg) else {
            return (status::BAD_REQUEST, 0);
        };
        match call_timeout(RUNTIME, &msg[..n], self.reply, out, TIMEOUT_US) {
            Ok(Received::Message { len, .. }) if len >= 1 => (out[0], len.min(256)),
            _ => (status::INTERNAL, 0),
        }
    }

    fn complete(&self, result: &[u8]) -> u64 {
        self.buffer.write_bytes(0, result);
        let len = result.len() as u32;
        self.call(&Request::Complete { len }, &mut [0; 256]);
        0
    }

    fn fail(&self, reason: &[u8]) -> u64 {
        self.call(&Request::Fail { reason }, &mut [0; 256]);
        0
    }

    fn infer(&self) -> u64 {
        let mut out = [0u8; 256];
        let other = Request::Infer {
            model: 1,
            max_new: 4,
            prompt_len: 1,
        };
        if self.call(&other, &mut out).0 != status::NO_ACCESS {
            return self.fail(b"model 1 was not refused");
        }
        if self.call(&Request::Next, &mut out).0 != NO_SESSION {
            return self.fail(b"NEXT without a session was not refused");
        }
        let prompt = b"hello hello";
        self.buffer.write_bytes(0, prompt);
        let generate = Request::Infer {
            model: 2,
            max_new: 20,
            prompt_len: prompt.len() as u32,
        };
        let (_, n) = self.call(&generate, &mut out);
        if Started::parse(&out[..n]).is_none() {
            return self.fail(b"GENERATE through the runtime failed");
        }
        let mut text = Vec::new();
        loop {
            let (_, n) = self.call(&Request::Next, &mut out);
            let Some(t) = Tokens::parse(&out[..n]) else {
                return self.fail(b"NEXT through the runtime failed");
            };
            text.extend_from_slice(t.text);
            if t.stop.is_some() {
                break;
            }
        }
        if text.is_empty() || text.len() > BUFFER as usize {
            return self.fail(b"no text");
        }
        self.complete(&text)
    }

    /// `DATA_GET name`: the status, and the file if found.
    fn get(&self, name: &[u8]) -> (u8, Vec<u8>) {
        let mut out = [0u8; 256];
        let (code, n) = self.call(&Request::DataGet { name }, &mut out);
        if code != status::OK || n != 5 {
            return (code, Vec::new());
        }
        let len = u32::from_le_bytes([out[1], out[2], out[3], out[4]]) as usize;
        let mut bytes = alloc::vec![0u8; len.min(BUFFER as usize)];
        self.buffer.read_bytes(0, &mut bytes);
        (code, bytes)
    }

    fn put(&self, name: &[u8], bytes: &[u8]) -> u8 {
        self.buffer.write_bytes(0, bytes);
        let len = bytes.len() as u32;
        self.call(&Request::DataPut { name, len }, &mut [0; 256]).0
    }

    /// Starts a session on model 2, waiting while another agent's session
    /// holds the service; true if it started.
    fn generate(&self, max_new: u16) -> (u8, bool) {
        let prompt = b"hello hello";
        self.buffer.write_bytes(0, prompt);
        let mut out = [0u8; 256];
        let req = Request::Infer {
            model: 2,
            max_new,
            prompt_len: prompt.len() as u32,
        };
        // Another agent's session holds the service: try again (#116).
        for _ in 0..100 {
            let (code, n) = self.call(&req, &mut out);
            if code != status::BUSY {
                return (code, Started::parse(&out[..n]).is_some());
            }
            sleep(50_000);
        }
        (status::BUSY, false)
    }

    fn ask(&self, permission: Permission, for_ms: u32) -> Option<Asked> {
        let mut out = [0u8; 256];
        let (_, n) = self.call(&Request::Ask { permission, for_ms }, &mut out);
        Asked::parse(&out[..n])
    }

    /// Asks until the answer is not pending, at most `secs`.
    fn wait_ask(&self, permission: Permission, for_ms: u32, secs: u32) -> Option<Asked> {
        for _ in 0..secs * 10 {
            match self.ask(permission, for_ms) {
                Some(Asked::Pending) => sleep(100_000),
                other => return other,
            }
        }
        Some(Asked::Pending)
    }

    fn asker(&self) -> u64 {
        let mut out = [0u8; 256];
        let net = Permission::Net {
            addr: [10, 0, 2, 2],
            port: 1,
        };
        if self.ask(net, 0) != Some(Asked::Refused) {
            return self.fail(b"a permission not askable was not refused");
        }
        if self.generate(4).0 != status::NO_ACCESS {
            return self.fail(b"model 2 was not refused before it was asked for");
        }
        let model = Permission::Model(2);
        if self.ask(model, 2_000) != Some(Asked::Pending) {
            return self.fail(b"asking for model 2 was not pending");
        }
        if self.wait_ask(model, 2_000, 30) != Some(Asked::Granted) {
            return self.fail(b"the approval did not grant model 2");
        }
        let granted = uptime();
        if !self.generate(4).1 {
            return self.fail(b"GENERATE with the approved model failed");
        }
        loop {
            let (_, n) = self.call(&Request::Next, &mut out);
            match Tokens::parse(&out[..n]) {
                Some(t) if t.stop.is_none() => {}
                Some(_) => break,
                None => return self.fail(b"NEXT failed"),
            }
        }
        let over = granted + 2_500_000;
        while uptime() < over {
            self.call(&Request::Info, &mut out);
            sleep(200_000);
        }
        if self.generate(4).0 != status::NO_ACCESS {
            return self.fail(b"model 2 was not refused after its 2 s");
        }
        if self.ask(Permission::DataWrite, 0) != Some(Asked::Pending)
            || self.wait_ask(Permission::DataWrite, 0, 30) != Some(Asked::Refused)
        {
            return self.fail(b"the user's no did not refuse data write");
        }
        if self.ask(Permission::DataWrite, 0) != Some(Asked::Refused) {
            return self.fail(b"a refused permission was asked for again");
        }
        if self.ask(Permission::DataRead, 0) != Some(Asked::Pending)
            || self.wait_ask(Permission::DataRead, 0, 30) != Some(Asked::Refused)
        {
            return self.fail(b"an unanswered request was not refused");
        }
        self.complete(b"ask ok")
    }

    fn send_to(&self, addr: [u8; 4], port: u16, payload: &[u8]) -> u8 {
        self.buffer.write_bytes(0, payload);
        let len = payload.len() as u32;
        self.call(&Request::SendTo { addr, port, len }, &mut [0; 256])
            .0
    }

    /// `RECEIVE_FROM`: the datagram and its payload, or the status.
    fn receive_from(&self) -> Result<(Datagram, Vec<u8>), u8> {
        let mut out = [0u8; 256];
        let (code, n) = self.call(&Request::ReceiveFrom, &mut out);
        let d = Datagram::parse(&out[..n]).ok_or(code)?;
        let mut bytes = alloc::vec![0u8; d.len as usize];
        self.buffer.read_bytes(0, &mut bytes);
        Ok((d, bytes))
    }

    /// The `budgets` kernel's `spender` (#116): 40 tokens, 2 datagrams of
    /// 64 bytes, and 1 KiB of files. Each request past them is refused
    /// with `OVER_LIMIT`, and a refused one costs nothing.
    fn spend(&self) -> u64 {
        const ECHO: [u8; 4] = [10, 0, 2, 2];
        let over = status::OVER_LIMIT;
        // "hello hello" is 11 bytes: a session of n new tokens costs 11 + n.
        if self.generate(30).0 != over {
            return self.fail(b"41 tokens of 40 were not refused");
        }
        if !self.generate(8).1 {
            return self.fail(b"19 tokens of 40 were refused");
        }
        self.call(&Request::CancelInfer, &mut [0; 256]);
        if self.generate(11).0 != over
            || !{
                let started = self.generate(10).1;
                self.call(&Request::CancelInfer, &mut [0; 256]);
                started
            }
        {
            return self.fail(b"tokens were not counted across sessions");
        }
        let sends = [(40, status::OK), (40, over), (10, status::OK), (1, over)];
        for (len, want) in sends {
            if self.send_to(ECHO, 47_000, &[7; 40][..len]) != want {
                return self.fail(b"datagrams past 2 or 64 bytes were not refused");
            }
        }
        // Replacing `a` counts its new size only: 500 + 500, then 100 over.
        let puts = [
            (&b"a"[..], 600, status::OK),
            (b"b", 600, over),
            (b"a", 500, status::OK),
            (b"b", 500, status::OK),
            (b"c", 100, over),
        ];
        for (name, len, want) in puts {
            if self.put(name, &[1; 600][..len]) != want {
                return self.fail(b"files past 1 KiB were not refused");
            }
        }
        self.complete(b"spend ok")
    }

    /// The `budgets` kernel's `grouper` (#116): its own budget has no
    /// limit, its group's minute has 30 tokens and 48 bytes.
    fn group_spend(&self) -> u64 {
        const ECHO: [u8; 4] = [10, 0, 2, 2];
        let over = status::OVER_LIMIT;
        if self.generate(20).0 != over {
            return self.fail(b"31 of the group's 30 tokens were not refused");
        }
        if !self.generate(19).1 {
            return self.fail(b"the group's 30 tokens were refused");
        }
        self.call(&Request::CancelInfer, &mut [0; 256]);
        if self.send_to(ECHO, 47_000, &[7; 40]) != status::OK
            || self.send_to(ECHO, 47_000, &[7; 10]) != over
        {
            return self.fail(b"50 of the group's 48 bytes were not refused");
        }
        self.complete(b"group ok")
    }

    fn net_quiet(&self) -> u64 {
        // 4 s, while `net-talk` exchanges its datagrams.
        for _ in 0..40 {
            if self.receive_from() != Err(status::NOT_FOUND) {
                return self.fail(b"an agent that sent nothing received a datagram");
            }
            sleep(100_000);
        }
        self.complete(b"quiet ok")
    }

    fn net_talk(&self) -> u64 {
        const ECHO: [u8; 4] = [10, 0, 2, 2];
        let asked = Permission::Net {
            addr: ECHO,
            port: 47_001,
        };
        let echo = Permission::Net {
            addr: ECHO,
            port: 47_000,
        };
        if self.send_to(ECHO, 47_001, b"no") != status::NO_ACCESS {
            return self.fail(b"a destination not granted was not refused");
        }
        let big = [0u8; MAX_DATAGRAM as usize + 1];
        if self.send_to(ECHO, 47_000, &big) != status::TOO_LARGE {
            return self.fail(b"an oversized datagram was not refused");
        }
        if self.send_to(ECHO, 47_000, b"agent echo") != status::OK {
            return self.fail(b"sending to the granted destination failed");
        }
        let mut echoed = false;
        for _ in 0..50 {
            match self.receive_from() {
                Ok((d, bytes)) => {
                    echoed = d.addr == ECHO && d.port == 47_000 && bytes == b"agent echo";
                    break;
                }
                Err(status::NOT_FOUND) => sleep(100_000),
                Err(_) => break,
            }
        }
        if !echoed {
            return self.fail(b"no echo from 10.0.2.2:47000");
        }
        if self.send_to(ECHO, 47_000, b"late") != status::OK {
            return self.fail(b"sending late failed");
        }
        let other = Permission::Net {
            addr: ECHO,
            port: 47_002,
        };
        if self.ask(other, 0) != Some(Asked::Refused) {
            return self.fail(b"a destination not askable was not refused");
        }
        if self.ask(asked, 0) != Some(Asked::Pending)
            || self.wait_ask(asked, 0, 30) != Some(Asked::Granted)
        {
            return self.fail(b"the user's yes did not grant 10.0.2.2:47001");
        }
        if self.send_to(ECHO, 47_001, b"asked") != status::OK {
            return self.fail(b"sending to the approved destination failed");
        }
        // The user revokes 10.0.2.2:47000 once the approval shows.
        let mut revoked = false;
        for _ in 0..200 {
            if self.ask(echo, 0) == Some(Asked::Refused) {
                revoked = true;
                break;
            }
            sleep(100_000);
        }
        if !revoked {
            return self.fail(b"10.0.2.2:47000 was never revoked");
        }
        if self.receive_from() != Err(status::NOT_FOUND) {
            return self.fail(b"a datagram from a revoked destination was delivered");
        }
        if self.send_to(ECHO, 47_000, b"after") != status::NO_ACCESS {
            return self.fail(b"sending was not refused after the revocation");
        }
        self.complete(b"talk ok")
    }

    /// A raw request: the reply's status.
    fn raw(&self, msg: &[u8]) -> u8 {
        let mut out = [0u8; 256];
        match call_timeout(RUNTIME, msg, self.reply, &mut out, TIMEOUT_US) {
            Ok(Received::Message { len, .. }) if len >= 1 => out[0],
            _ => status::INTERNAL,
        }
    }

    /// Shares `m` with the runtime as the agent's buffer; the memory
    /// capability, kept.
    fn attach(&self, m: &Mapped) -> Option<Handle> {
        let len = m.len() as u64;
        let memory = mem_share(m.addr(), len).ok()?;
        let mut msg = [0u8; 16];
        let n = encode(&Request::Attach { len }, &mut msg)?;
        send(RUNTIME, &msg[..n], memory, READ | WRITE, 0).ok()?;
        // ATTACH has no reply; any request after it is served after it.
        self.call(&Request::Info, &mut [0; 256]);
        Some(memory)
    }

    fn hostile(&self) -> u64 {
        let mut out = [0u8; 256];
        self.call(&Request::Log { text: b"check me" }, &mut out);
        sleep(500_000);

        // Nothing but handle 1, which only sends to the runtime.
        for h in 2..=64 {
            if h == self.reply {
                continue;
            }
            if try_send(h, b"x").is_ok()
                || open(h, b"bin/hello").is_ok()
                || config_read(h, 0, 4).is_ok()
                || process_stop(h).is_ok()
                || irq_create(h, 0).is_ok()
            {
                return self.fail(b"a handle other than 1 works");
            }
        }
        let refused = debug_write(RUNTIME, b"x").is_err()
            && receive_timeout(RUNTIME, &mut out, 1_000).is_err()
            && open(RUNTIME, b"bin/hello").is_err()
            && config_read(RUNTIME, 0, 4).is_err()
            && mmio_map(RUNTIME, 0, 0, 4096, 0x5000_0000).is_err()
            && dma_alloc(RUNTIME, 1, 0x5100_0000).is_err()
            && irq_create(RUNTIME, 0).is_err()
            && process_stop(RUNTIME).is_err()
            && spawn(RUNTIME, 0, &[], None).is_err()
            // Passing on handle 1 needs `GRANT`.
            && send(RUNTIME, b"x", RUNTIME, SEND, CONTROL).is_err();
        if !refused {
            return self.fail(b"handle 1 did more than send");
        }
        // 4 MiB: more than its 256 pages.
        if mem_map(4 << 20).is_ok() {
            return self.fail(b"memory over the page limit was mapped");
        }
        if self.send_to([10, 0, 2, 2], 47_000, b"x") != status::NO_ACCESS
            || self.receive_from() != Err(status::NO_ACCESS)
        {
            return self.fail(b"the network was reachable without a grant");
        }
        if self.generate(4).0 != status::NO_ACCESS {
            return self.fail(b"inference without a grant");
        }

        // Requests for control clients and for `trust`: its badge says it
        // is an agent, whatever the message claims.
        let forged = [
            Request::Submit {
                name: b"keeper",
                input_len: 0,
                deps: Deps::NONE,
            },
            Request::Status { task: 2 },
            Request::Cancel { task: 2 },
            Request::Forget { task: 2 },
            Request::Revoke {
                name: b"keeper",
                permission: Permission::DataWrite,
            },
            Request::Answer {
                number: 1,
                yes: true,
            },
        ];
        for req in &forged {
            if self.call(req, &mut out).0 != status::NO_ACCESS {
                return self.fail(b"a control or trust request was not refused");
            }
        }

        // Malformed and out-of-bounds fields.
        let v = agents::VERSION;
        let put = agents::op::DATA_PUT;
        for name in [&b"../keeper/notes"[..], b"a/b", b"", b"x y", b"notes\0"] {
            let mut msg = alloc::vec![v, put, name.len() as u8];
            msg.extend_from_slice(name);
            msg.extend_from_slice(&1u32.to_le_bytes());
            if self.raw(&msg) != status::BAD_REQUEST {
                return self.fail(b"a file name outside its own files was not refused");
            }
        }
        let mut log = alloc::vec![v, agents::op::LOG];
        log.extend_from_slice(b"\x1b[2Japprove");
        if self.raw(&log) != status::BAD_REQUEST {
            return self.fail(b"a log line with a control character was not refused");
        }
        for code in (22..=0xefu8).step_by(7) {
            if self.raw(&[v, code, 1, 2, 3]) != status::BAD_REQUEST {
                return self.fail(b"an unknown operation was not refused");
            }
        }
        if self.raw(&[v + 1, agents::op::TASK]) != status::VERSION {
            return self.fail(b"another version was not refused");
        }
        let bounds = [
            Request::DataPut {
                name: b"notes",
                len: u32::MAX,
            },
            Request::Checkpoint { len: 1 << 20 },
            Request::Complete { len: 5000 },
            Request::SendTo {
                addr: [10, 0, 2, 2],
                port: 47_000,
                len: u32::MAX,
            },
        ];
        for req in &bounds {
            let code = self.call(req, &mut out).0;
            if code != status::TOO_LARGE && code != status::NO_ACCESS {
                return self.fail(b"a length out of bounds was not refused");
            }
        }
        // Looks like `trust`'s prompt, but goes to the serial console only.
        let fake = b"approve #9: keeper task 2 wants model 1 for this task? (yes 9 / no 9)";
        if self.call(&Request::Log { text: fake }, &mut out).0 != status::OK {
            return self.fail(b"logging failed");
        }

        // A buffer the agent revokes under the runtime: the runtime reads
        // zeros and does not crash.
        let Ok(small) = mem_map_buffer(4096) else {
            return self.fail(b"no small buffer");
        };
        let Some(memory) = self.attach(&small) else {
            return self.fail(b"attaching the small buffer failed");
        };
        let len = 8192;
        if self
            .call(
                &Request::DataPut {
                    name: b"notes",
                    len,
                },
                &mut out,
            )
            .0
            != status::NO_BUFFER
        {
            return self.fail(b"a length past the buffer was not refused");
        }
        small.write_bytes(0, b"secret");
        if revoke(memory).is_err() {
            return self.fail(b"revoking its own buffer failed");
        }
        let len = 6;
        if self
            .call(
                &Request::DataPut {
                    name: b"notes",
                    len,
                },
                &mut out,
            )
            .0
            != status::OK
        {
            return self.fail(b"the runtime failed on a revoked buffer");
        }
        let mut kept = [0u8; 6];
        small.read_bytes(0, &mut kept);
        if &kept != b"secret" || self.attach(&self.buffer).is_none() {
            return self.fail(b"its own memory changed, or attaching again failed");
        }
        if self.get(b"notes") != (status::OK, alloc::vec![0u8; 6]) {
            return self.fail(b"the runtime read more than zeros from a revoked buffer");
        }

        // Its own request cannot be approved by itself; then the queue of
        // four fills, and more is refused without a prompt.
        if self.ask(Permission::Model(3), 0) != Some(Asked::Pending) {
            return self.fail(b"asking for model 3 was not pending");
        }
        let answer = Request::Answer {
            number: 1,
            yes: true,
        };
        if self.call(&answer, &mut out).0 != status::NO_ACCESS
            || self.ask(Permission::Model(3), 0) != Some(Asked::Pending)
        {
            return self.fail(b"an agent answered its own request");
        }
        for n in 4..=6 {
            if self.ask(Permission::Model(n), 0) != Some(Asked::Pending) {
                return self.fail(b"filling the approval queue failed");
            }
        }
        if self.ask(Permission::Model(7), 0) != Some(Asked::Refused) {
            return self.fail(b"a fifth request was not refused");
        }
        // A flood: refused requests (recorded once per kind), then plain
        // ones; the runtime keeps serving.
        for port in 1..=200u16 {
            let net = Permission::Net {
                addr: [10, 0, 2, 2],
                port,
            };
            if self.ask(net, 0) != Some(Asked::Refused) {
                return self.fail(b"a permission not askable was not refused");
            }
        }
        for _ in 0..200 {
            if self.call(&Request::Status { task: 1 }, &mut out).0 != status::NO_ACCESS {
                return self.fail(b"a control request was not refused in the flood");
            }
        }
        for _ in 0..2000 {
            if self.call(&Request::Info, &mut out).0 != status::OK {
                return self.fail(b"the runtime stopped answering under the flood");
            }
        }
        self.complete(b"hostile ok")
    }

    fn keeper_c(&self) -> u64 {
        let mut out = [0u8; 256];
        if self.put(b"notes", b"c") != status::OK {
            return self.fail(b"writing failed while the trail was up");
        }
        self.call(&Request::Log { text: b"audit me" }, &mut out);
        let mut refused = false;
        for _ in 0..100 {
            match self.put(b"notes", b"c") {
                status::OK => sleep(100_000),
                NO_AUDIT => {
                    refused = true;
                    break;
                }
                _ => return self.fail(b"writing failed for another reason"),
            }
        }
        if !refused {
            return self.fail(b"writing was never refused for the trail");
        }
        if self.generate(4).0 != NO_AUDIT {
            return self.fail(b"inference was not refused for the trail");
        }
        if self.get(b"notes") != (status::OK, Vec::from(&b"c"[..])) {
            return self.fail(b"reading, which is not audited, failed");
        }
        self.complete(b"c ok")
    }

    fn keeper_a(&self) -> u64 {
        if self.get(b"notes").0 != status::NOT_FOUND {
            return self.fail(b"a missing file was not NOT_FOUND");
        }
        if self.put(b"notes", b"hello") != status::OK {
            return self.fail(b"DATA_PUT failed");
        }
        self.buffer.write_bytes(0, &[0; 8]);
        if self.get(b"notes") != (status::OK, Vec::from(&b"hello"[..])) {
            return self.fail(b"DATA_GET did not return the file");
        }
        if !self.generate(4).1 {
            return self.fail(b"GENERATE through the runtime failed");
        }
        let mut out = [0u8; 256];
        loop {
            let (_, n) = self.call(&Request::Next, &mut out);
            match Tokens::parse(&out[..n]) {
                Some(t) if t.stop.is_none() => {}
                Some(_) => break,
                None => return self.fail(b"NEXT failed"),
            }
        }
        self.complete(b"a ok")
    }

    fn keeper_b(&self, task: &Assigned) -> u64 {
        let mut out = [0u8; 256];
        if task.attempt > 1 {
            let data = self.get(b"notes").0 == status::NO_ACCESS;
            let model = self.generate(4).0 == status::NO_ACCESS;
            return if data && model {
                self.complete(b"b ok")
            } else {
                self.fail(b"a revoked permission came back with the restart")
            };
        }
        if !self.generate(20).1 {
            return self.fail(b"GENERATE through the runtime failed");
        }
        self.call(
            &Request::Log {
                text: b"holding a session",
            },
            &mut out,
        );
        // Each poll counts as progress; 30 s at most.
        let mut data_gone = false;
        for _ in 0..300 {
            match self.get(b"notes") {
                (status::NO_ACCESS, _) => {
                    data_gone = true;
                    break;
                }
                (status::OK, f) if f == b"hello" => sleep(100_000),
                _ => return self.fail(b"reading notes failed before the revocation"),
            }
        }
        if !data_gone {
            return self.fail(b"data was never revoked");
        }
        let mut model_gone = false;
        for _ in 0..300 {
            match self.generate(4).0 {
                status::NO_ACCESS => {
                    model_gone = true;
                    break;
                }
                status::BUSY => sleep(100_000),
                _ => return self.fail(b"INFER was not BUSY while the session was open"),
            }
        }
        if !model_gone {
            return self.fail(b"the model was never revoked");
        }
        if self.call(&Request::Next, &mut out).0 != NO_SESSION {
            return self.fail(b"the session outlived its model's revocation");
        }
        if self.put(b"notes", b"x") != status::NO_ACCESS {
            return self.fail(b"writing was not refused after data read was revoked");
        }
        self.call(
            &Request::Log {
                text: b"refused; crashing",
            },
            &mut out,
        );
        overflow(0)
    }

    fn probe(&self) -> u64 {
        let mut out = [0u8; 256];
        let control = [
            Request::Submit {
                name: b"worker",
                input_len: 0,
                deps: Deps::NONE,
            },
            Request::Status { task: 1 },
            Request::Cancel { task: 1 },
            Request::Forget { task: 1 },
        ];
        for req in &control {
            if self.call(req, &mut out).0 != status::NO_ACCESS {
                return self.fail(b"a control request was not refused");
            }
        }
        self.complete(b"probe ok")
    }

    fn begin(&self, key: [u8; KEY], out: &mut [u8; 256]) -> Option<Got> {
        let (_, n) = self.call(&Request::Begin { key }, out);
        Some(match Begun::parse(&out[..n])? {
            Begun::Go => Got::Go,
            Begun::Unknown => Got::Unknown,
            Begun::Done(r) => Got::Done(Vec::from(r)),
        })
    }

    fn end(&self, key: [u8; KEY], result: &[u8]) -> u8 {
        self.call(&Request::End { key, result }, &mut [0; 256]).0
    }

    fn checkpoint(&self, bytes: &[u8]) -> bool {
        self.buffer.write_bytes(CHECKPOINT_AT as usize, bytes);
        let len = bytes.len() as u32;
        self.call(&Request::Checkpoint { len }, &mut [0; 256]).0 == status::OK
    }

    fn stored_checkpoint(&self, task: &Assigned) -> Vec<u8> {
        let mut cp = alloc::vec![0u8; task.checkpoint_len as usize];
        self.buffer.read_bytes(CHECKPOINT_AT as usize, &mut cp);
        cp
    }

    fn keys(&self) -> u64 {
        let mut out = [0u8; 256];
        let k = [1; KEY];
        if self.begin(k, &mut out) != Some(Got::Go) {
            return self.fail(b"a new key was not GO");
        }
        if self.begin(k, &mut out) != Some(Got::Unknown) {
            return self.fail(b"a begun key was not UNKNOWN");
        }
        if self.end([2; KEY], b"x") != status::NOT_FOUND {
            return self.fail(b"END of a key never begun was not refused");
        }
        if self.end(k, b"r1") != status::OK {
            return self.fail(b"END failed");
        }
        if self.begin(k, &mut out) != Some(Got::Done(b"r1".to_vec())) {
            return self.fail(b"an ended key was not DONE with its result");
        }
        if self.end(k, b"other") != status::BUSY {
            return self.fail(b"a second, different result was not refused");
        }
        self.complete(b"keys ok")
    }

    fn durable(&self, task: &Assigned) -> u64 {
        let mut out = [0u8; 256];
        let k = [b'd'; KEY];
        if task.attempt == 1 {
            if !self.checkpoint(b"step1") || self.begin(k, &mut out) != Some(Got::Go) {
                return self.fail(b"checkpoint or BEGIN failed");
            }
            if self.end(k, b"sent") != status::OK {
                return self.fail(b"END failed");
            }
            self.call(
                &Request::Log {
                    text: b"ready to stop",
                },
                &mut out,
            );
            loop {
                self.call(&Request::Info, &mut out);
                sleep(200_000);
            }
        }
        if self.stored_checkpoint(task) != b"step1" {
            return self.fail(b"the checkpoint was lost");
        }
        match self.begin(k, &mut out) {
            Some(Got::Done(r)) if r == b"sent" => self.complete(b"recovered sent"),
            _ => self.fail(b"the operation was not recorded as done"),
        }
    }

    fn count(&self, task: &Assigned) -> u64 {
        let mut out = [0u8; 256];
        let cp = self.stored_checkpoint(task);
        let from = match cp.as_slice() {
            [] => 0,
            [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
            _ => return self.fail(b"bad checkpoint"),
        };
        let key = |n: u32| {
            let mut k = [b'c'; KEY];
            k[..4].copy_from_slice(&n.to_le_bytes());
            k
        };
        // Every step before the checkpoint must be recorded as done.
        for n in 0..from {
            if self.begin(key(n), &mut out) != Some(Got::Done(n.to_le_bytes().to_vec())) {
                return self.fail(b"a step before the checkpoint is not done");
            }
        }
        self.call(&Request::Log { text: b"counting" }, &mut out);
        for n in from..COUNT {
            match self.begin(key(n), &mut out) {
                // Begun, maybe not done: the step is safe to do again here.
                Some(Got::Go | Got::Unknown) => {
                    if self.end(key(n), &n.to_le_bytes()) != status::OK {
                        return self.fail(b"END failed");
                    }
                }
                Some(Got::Done(r)) if r == n.to_le_bytes() => {}
                _ => return self.fail(b"a step's record is wrong"),
            }
            if !self.checkpoint(&(n + 1).to_le_bytes()) {
                return self.fail(b"CHECKPOINT failed");
            }
            // Spread over seconds, so kills land mid-count.
            sleep(150_000);
        }
        self.complete(b"count 30")
    }
}

/// Recurses until the stack runs out: a page fault.
fn overflow(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if frame[0] == u64::MAX {
        return 0;
    }
    overflow(depth + 1) + frame[1]
}

fn main(_: u64) -> u64 {
    let Ok(reply) = endpoint_create() else {
        return 10;
    };
    let Ok(buffer) = mem_map_buffer(BUFFER) else {
        return 11;
    };
    let Ok(memory) = mem_share(buffer.addr(), BUFFER) else {
        return 12;
    };
    let mut msg = [0u8; 16];
    let Some(n) = encode(&Request::Attach { len: BUFFER }, &mut msg) else {
        return 13;
    };
    let sent = send(RUNTIME, &msg[..n], memory, READ | WRITE, 0);
    // The runtime has its own copy.
    let _ = delete(memory);
    if sent.is_err() {
        return 14;
    }
    let a = Agent { reply, buffer };
    let mut out = [0u8; 256];
    let (_, n) = a.call(&Request::Task, &mut out);
    let Some(task) = Assigned::parse(&out[..n]) else {
        return 15;
    };
    let mut input = [0u8; 64];
    let input = &mut input[..(task.input_len as usize).min(64)];
    a.buffer.read_bytes(0, input);
    match &*input {
        b"complete" => {
            a.call(&Request::Log { text: b"working" }, &mut out);
            let mut result = Vec::from(&b"done: "[..]);
            result.extend_from_slice(input);
            a.complete(&result)
        }
        b"crash-once" if task.attempt == 1 => overflow(0),
        b"crash-once" => a.complete(b"recovered"),
        b"crash" => overflow(0),
        b"exit" => 3,
        b"hang" => loop {
            core::hint::spin_loop();
        },
        b"fail" => a.fail(b"asked to fail"),
        b"infer" => a.infer(),
        b"probe" => a.probe(),
        b"keys" => a.keys(),
        b"resume" if task.attempt == 1 => {
            if a.checkpoint(b"half") {
                overflow(0)
            } else {
                a.fail(b"CHECKPOINT failed")
            }
        }
        b"resume" if a.stored_checkpoint(&task) == b"half" => a.complete(b"resumed half"),
        b"resume" => a.fail(b"the checkpoint was lost"),
        b"durable" => a.durable(&task),
        b"count" => a.count(&task),
        b"keeper-a" => a.keeper_a(),
        b"keeper-b" => a.keeper_b(&task),
        b"ask" => a.asker(),
        b"keeper-c" => a.keeper_c(),
        b"net-quiet" => a.net_quiet(),
        b"net-talk" => a.net_talk(),
        b"hostile" => a.hostile(),
        b"spend" => a.spend(),
        b"group-spend" => a.group_spend(),
        // Runs 600 ms, asking the runtime for its task now and then.
        b"nap" => {
            for _ in 0..6 {
                a.call(&Request::Task, &mut out);
                sleep(100_000);
            }
            a.complete(b"napped")
        }
        b"keeper-d" if a.get(b"notes").0 == status::NO_ACCESS => a.complete(b"d ok"),
        b"keeper-d" => a.fail(b"a grant was given without its record"),
        b"wait" => loop {
            a.call(&Request::Info, &mut out);
            sleep(200_000);
        },
        _ => a.fail(b"unknown input"),
    }
}
