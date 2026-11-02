//! The `agents` test kernel's control client (#98). Handles: 1 the
//! console, 2 the agent runtime (`SEND`, badged as a control client), 3
//! the kernel's report endpoint (`SEND`). It submits `worker` tasks for
//! each case of `bin/testagent` and checks their states, attempts, and
//! results. Each passed step is sent to the kernel as `ok <step>`, and a
//! failed one printed; `check` asks the kernel to inspect running agents.
//! Exits with the number of failed steps.

#![no_std]
#![no_main]

use pharos_proto::agents::{
    MAX_RUNNING, NAME, Request, State, TaskStatus, encode, parse_submitted,
};
use pharos_proto::{Info, status};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map_buffer,
    mem_share, send, sleep,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const RUNTIME: Handle = 2;
const REPORT: Handle = 3;
const BUFFER: u64 = 4096;

struct Client {
    reply: Handle,
    buffer: Mapped,
    failed: u64,
}

impl Client {
    fn call(&self, req: &Request<'_>, out: &mut [u8; 256]) -> (u8, usize) {
        let mut msg = [0u8; 256];
        let Some(n) = encode(req, &mut msg) else {
            return (status::BAD_REQUEST, 0);
        };
        match call_timeout(RUNTIME, &msg[..n], self.reply, out, 10_000_000) {
            Ok(Received::Message { len, .. }) if len >= 1 => (out[0], len.min(256)),
            _ => (status::INTERNAL, 0),
        }
    }

    fn step(&mut self, name: &str, ok: bool) {
        let mut line = [0u8; 128];
        let (word, out): (&[u8], Handle) = if ok {
            (b"ok ", REPORT)
        } else {
            self.failed += 1;
            (b"FAILED ", CONSOLE)
        };
        let n = (word.len() + name.len()).min(line.len());
        line[..word.len()].copy_from_slice(word);
        line[word.len()..n].copy_from_slice(&name.as_bytes()[..n - word.len()]);
        if out == REPORT {
            let _ = send(REPORT, &line[..n], 0, 0, 0);
        } else {
            let _ = debug_write(CONSOLE, &line[..n]);
        }
    }

    fn submit(&self, name: &[u8], input: &[u8]) -> Result<u32, u8> {
        self.buffer.write_bytes(0, input);
        let mut out = [0u8; 256];
        let req = Request::Submit {
            name,
            input_len: input.len() as u32,
        };
        let (code, n) = self.call(&req, &mut out);
        parse_submitted(&out[..n]).ok_or(code)
    }

    fn status(&self, task: u32) -> Option<TaskStatus> {
        let mut out = [0u8; 256];
        let (_, n) = self.call(&Request::Status { task }, &mut out);
        TaskStatus::parse(&out[..n])
    }

    /// Runs one `worker` task to its end (at most 60 s): its status and
    /// whether its result is `want`.
    fn run(&self, input: &[u8], want: &[u8]) -> Option<(State, u8, bool)> {
        let task = self.submit(b"worker", input).ok()?;
        for _ in 0..600 {
            let s = self.status(task)?;
            if !matches!(s.state, State::Pending | State::Running) {
                let mut result = [0u8; 256];
                let len = (s.result_len as usize).min(256);
                self.buffer.read_bytes(0, &mut result[..len]);
                let matches = want.is_empty() && len > 0 || &result[..len] == want;
                return Some((s.state, s.attempts, matches));
            }
            sleep(100_000);
        }
        None
    }

    fn case(&mut self, name: &str, input: &[u8], want: (State, u8, &[u8])) {
        let got = self.run(input, want.2);
        self.step(name, got == Some((want.0, want.1, true)));
    }
}

fn main(_: u64) -> u64 {
    let Ok(reply) = endpoint_create() else {
        return 100;
    };
    let Ok(buffer) = mem_map_buffer(BUFFER) else {
        return 101;
    };
    let Ok(memory) = mem_share(buffer.addr(), BUFFER) else {
        return 102;
    };
    let mut msg = [0u8; 16];
    let n = encode(&Request::Attach { len: BUFFER }, &mut msg).unwrap_or(0);
    let sent = send(RUNTIME, &msg[..n], memory, READ | WRITE, 0);
    let _ = delete(memory);
    if sent.is_err() {
        return 103;
    }
    let mut c = Client {
        reply,
        buffer,
        failed: 0,
    };
    let mut out = [0u8; 256];

    let (_, n) = c.call(&Request::Info, &mut out);
    let info = Info::parse(&out[..n]);
    c.step(
        "INFO: interface agents, one agent accepted, none running",
        info.is_some_and(|i| i.name == NAME && i.details == [1, 0]),
    );
    let refused = [&b"greedy"[..], b"absent", b"noentry"]
        .iter()
        .all(|name| c.submit(name, b"complete") == Err(status::NOT_FOUND));
    c.step(
        "agents with a refused, missing, or unlisted manifest are not found",
        refused,
    );
    c.step(
        "agent requests from a control client are refused",
        c.call(&Request::Task, &mut out).0 == status::NO_ACCESS,
    );
    c.step(
        "an unknown task is not found",
        c.call(&Request::Status { task: 999 }, &mut out).0 == status::NOT_FOUND
            && c.call(&Request::Cancel { task: 999 }, &mut out).0 == status::NOT_FOUND,
    );

    c.case(
        "a task completes on its first attempt",
        b"complete",
        (State::Done, 1, b"done: complete"),
    );
    c.case(
        "a crashed agent is restarted and completes",
        b"crash-once",
        (State::Done, 2, b"recovered"),
    );
    c.case(
        "an agent that always crashes fails after 3 attempts",
        b"crash",
        (State::Failed, 3, b"retries exhausted"),
    );
    c.case(
        "an agent that exits without a result fails after 3 attempts",
        b"exit",
        (State::Failed, 3, b"retries exhausted"),
    );
    c.case(
        "a hung agent is stopped and fails after 3 attempts",
        b"hang",
        (State::Failed, 3, b"retries exhausted"),
    );
    c.case(
        "an agent's FAIL ends its task with its reason",
        b"fail",
        (State::Failed, 1, b"asked to fail"),
    );
    c.case(
        "inference through the runtime, only from the manifest's models",
        b"infer",
        (State::Done, 1, b""),
    );
    c.case(
        "an agent's control requests are refused",
        b"probe",
        (State::Done, 1, b"probe ok"),
    );

    // Five waiting agents: at most four run.
    let mut tasks = [0u32; MAX_RUNNING + 1];
    let mut submitted = true;
    for t in tasks.iter_mut() {
        match c.submit(b"worker", b"wait") {
            Ok(id) => *t = id,
            Err(_) => submitted = false,
        }
    }
    sleep(1_000_000);
    let states = tasks.map(|t| c.status(t).map(|s| s.state));
    let running = states
        .iter()
        .filter(|s| **s == Some(State::Running))
        .count();
    let pending = states
        .iter()
        .filter(|s| **s == Some(State::Pending))
        .count();
    c.step(
        "at most four agents run at once",
        submitted && running == MAX_RUNNING && pending == 1,
    );
    // The kernel inspects the running agents' capabilities.
    let _ = send(REPORT, b"check", 0, 0, 0);
    sleep(500_000);
    let cancelled = tasks
        .iter()
        .all(|&task| c.call(&Request::Cancel { task }, &mut out).0 == status::OK);
    sleep(1_000_000);
    let all = tasks
        .iter()
        .all(|&t| c.status(t).is_some_and(|s| s.state == State::Cancelled));
    let (_, n) = c.call(&Request::Info, &mut out);
    let idle = Info::parse(&out[..n]).is_some_and(|i| i.details == [1, 0]);
    c.step(
        "cancelling running and pending tasks stops their agents",
        cancelled && all && idle,
    );
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}
