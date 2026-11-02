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

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_proto::agents::{
    Assigned, Begun, CHECKPOINT_AT, Deps, KEY, MAX_BUFFER, NO_SESSION, Request, encode,
};
use pharos_proto::infer::{Started, Tokens};
use pharos_proto::status;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, delete, endpoint_create, mem_map_buffer, mem_share,
    send, sleep,
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
        b"wait" => loop {
            a.call(&Request::Info, &mut out);
            sleep(200_000);
        },
        _ => a.fail(b"unknown input"),
    }
}
