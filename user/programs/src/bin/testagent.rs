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

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_proto::agents::{
    Asked, Assigned, Begun, CHECKPOINT_AT, Deps, KEY, MAX_BUFFER, NO_AUDIT, NO_SESSION, Request,
    encode,
};
use pharos_proto::infer::{Started, Tokens};
use pharos_proto::permission::Permission;
use pharos_proto::status;
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, delete, endpoint_create, mem_map_buffer, mem_share,
    send, sleep, uptime,
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

    /// Starts a session on model 2; true if it started.
    fn generate(&self, max_new: u16) -> (u8, bool) {
        let prompt = b"hello hello";
        self.buffer.write_bytes(0, prompt);
        let mut out = [0u8; 256];
        let req = Request::Infer {
            model: 2,
            max_new,
            prompt_len: prompt.len() as u32,
        };
        let (code, n) = self.call(&req, &mut out);
        (code, Started::parse(&out[..n]).is_some())
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
        b"keeper-d" if a.get(b"notes").0 == status::NO_ACCESS => a.complete(b"d ok"),
        b"keeper-d" => a.fail(b"a grant was given without its record"),
        b"wait" => loop {
            a.call(&Request::Info, &mut out);
            sleep(200_000);
        },
        _ => a.fail(b"unknown input"),
    }
}
