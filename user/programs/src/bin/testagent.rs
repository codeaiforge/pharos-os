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
//! - `wait`: keeps asking `INFO` every 200 ms until stopped.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_proto::agents::{Assigned, NO_SESSION, Request, encode};
use pharos_proto::infer::{Started, Tokens};
use pharos_proto::status;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, delete, endpoint_create, mem_map_buffer, mem_share,
    send, sleep,
};

pharos_user::entry!(main);

const RUNTIME: Handle = 1;
const BUFFER: u64 = 4096;
const TIMEOUT_US: u64 = 60_000_000;

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
            },
            Request::Status { task: 1 },
            Request::Cancel { task: 1 },
        ];
        for req in &control {
            if self.call(req, &mut out).0 != status::NO_ACCESS {
                return self.fail(b"a control request was not refused");
            }
        }
        self.complete(b"probe ok")
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
        b"wait" => loop {
            a.call(&Request::Info, &mut out);
            sleep(200_000);
        },
        _ => a.fail(b"unknown input"),
    }
}
