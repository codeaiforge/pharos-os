//! The `agents` test kernel's control client (#98). Handles: 1 the
//! console, 2 the agent runtime (`SEND`, badged as a control client), 3
//! the kernel's report endpoint (`SEND`). It submits `worker` tasks for
//! each case of `bin/testagent` and checks their states, attempts, and
//! results. Each passed step is sent to the kernel as `ok <step>`, and a
//! failed one printed; `check` asks the kernel to inspect running agents.
//! Exits with the number of failed steps.
//!
//! Argument 0: the `agents` test kernel. Argument 1: the `agents_crash`
//! kernel, booted several times and killed while its `counter` task runs:
//! each boot prints `agents check: ok` once the runtime answers, submits
//! the task if the store has none, and waits for it to end.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_proto::agents::{
    Deps, MAX_BUFFER, MAX_RUNNING, NAME, Request, State, TaskStatus, encode, parse_submitted,
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
const BUFFER: u64 = MAX_BUFFER;

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

    /// Attaches the buffer (again, after the runtime was replaced).
    fn attach(&self) -> bool {
        let Ok(memory) = mem_share(self.buffer.addr(), BUFFER) else {
            return false;
        };
        let mut msg = [0u8; 16];
        let n = encode(&Request::Attach { len: BUFFER }, &mut msg).unwrap_or(0);
        let sent = send(RUNTIME, &msg[..n], memory, READ | WRITE, 0);
        let _ = delete(memory);
        sent.is_ok()
    }

    fn submit(&self, name: &[u8], input: &[u8]) -> Result<u32, u8> {
        self.submit_after(name, input, &[])
    }

    fn submit_after(&self, name: &[u8], input: &[u8], deps: &[u32]) -> Result<u32, u8> {
        self.buffer.write_bytes(0, input);
        let mut out = [0u8; 256];
        let req = Request::Submit {
            name,
            input_len: input.len() as u32,
            deps: Deps::new(deps).ok_or(status::TOO_LARGE)?,
        };
        let (code, n) = self.call(&req, &mut out);
        parse_submitted(&out[..n]).ok_or(code)
    }

    /// A task's status; attaches again if the runtime lost the buffer.
    fn status(&self, task: u32) -> Option<TaskStatus> {
        let mut out = [0u8; 256];
        let (code, n) = self.call(&Request::Status { task }, &mut out);
        if code == status::NO_BUFFER && self.attach() {
            let (_, n) = self.call(&Request::Status { task }, &mut out);
            return TaskStatus::parse(&out[..n]);
        }
        TaskStatus::parse(&out[..n])
    }

    /// Waits up to `secs` for `task` to end: its status and result.
    fn wait(&self, task: u32, secs: u32) -> Option<(TaskStatus, Vec<u8>)> {
        for _ in 0..secs * 10 {
            if let Some(s) = self.status(task) {
                if !matches!(s.state, State::Pending | State::Running) {
                    let mut result = alloc::vec![0u8; s.result_len as usize];
                    self.buffer.read_bytes(0, &mut result);
                    return Some((s, result));
                }
            }
            sleep(100_000);
        }
        None
    }

    /// Runs one `worker` task to its end (at most 60 s): its status and
    /// whether its result is `want`.
    fn run(&self, input: &[u8], want: &[u8]) -> Option<(State, u8, bool)> {
        let task = self.submit(b"worker", input).ok()?;
        let (s, result) = self.wait(task, 60)?;
        let matches = want.is_empty() && !result.is_empty() || result == want;
        Some((s.state, s.attempts, matches))
    }

    fn case(&mut self, name: &str, input: &[u8], want: (State, u8, &[u8])) {
        let got = self.run(input, want.2);
        self.step(name, got == Some((want.0, want.1, true)));
    }
}

fn main(arg: u64) -> u64 {
    let Ok(reply) = endpoint_create() else {
        return 100;
    };
    let Ok(buffer) = mem_map_buffer(BUFFER) else {
        return 101;
    };
    let mut c = Client {
        reply,
        buffer,
        failed: 0,
    };
    if !c.attach() {
        return 103;
    }
    if arg == 1 {
        return crash(c);
    }
    let mut out = [0u8; 256];

    let (_, n) = c.call(&Request::Info, &mut out);
    let info = Info::parse(&out[..n]);
    c.step(
        "INFO: interface agents, two agents accepted, none running",
        info.is_some_and(|i| i.name == NAME && i.details == [2, 0]),
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
    let idle = Info::parse(&out[..n]).is_some_and(|i| i.details == [2, 0]);
    c.step(
        "cancelling running and pending tasks stops their agents",
        cancelled && all && idle,
    );
    durable_cases(&mut c);
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// Keys, checkpoints, dependencies, `FORGET`, and a task that outlives
/// the runtime (#99).
fn durable_cases(c: &mut Client) {
    let mut out = [0u8; 256];
    c.case(
        "idempotency keys answer GO, UNKNOWN, and DONE",
        b"keys",
        (State::Done, 1, b"keys ok"),
    );
    c.case(
        "a checkpoint comes back to the next attempt",
        b"resume",
        (State::Done, 2, b"resumed half"),
    );

    c.step(
        "an unknown dependency is refused",
        c.submit_after(b"worker", b"complete", &[999]) == Err(status::NOT_FOUND),
    );
    let first = c.submit(b"worker", b"complete");
    let done = first.is_ok_and(|t| c.wait(t, 30).is_some_and(|(s, _)| s.state == State::Done));
    let after = first.and_then(|t| c.submit_after(b"worker", b"complete", &[t]));
    let ran = after.is_ok_and(|t| c.wait(t, 30).is_some_and(|(s, _)| s.state == State::Done));
    c.step("a task runs once its dependency is done", done && ran);

    let blocker = c.submit(b"worker", b"wait");
    let blocked = blocker.and_then(|t| c.submit_after(b"worker", b"complete", &[t]));
    sleep(1_000_000);
    let waits = blocked.is_ok_and(|t| c.status(t).is_some_and(|s| s.state == State::Pending));
    let (Ok(blocker), Ok(blocked)) = (blocker, blocked) else {
        c.step("a task waits for its dependency", false);
        return;
    };
    c.step("a task waits for its dependency", waits);
    c.step(
        "FORGET refuses a task that has not ended",
        c.call(&Request::Forget { task: blocker }, &mut out).0 == status::BUSY,
    );
    let _ = c.call(&Request::Cancel { task: blocker }, &mut out);
    let failed = c
        .wait(blocked, 10)
        .is_some_and(|(s, r)| s.state == State::Failed && r == b"dependency failed");
    c.step("a task whose dependency was cancelled fails", failed);
    let forgotten = c.call(&Request::Forget { task: blocked }, &mut out).0 == status::OK
        && c.call(&Request::Forget { task: blocker }, &mut out).0 == status::OK
        && c.call(&Request::Status { task: blocker }, &mut out).0 == status::NOT_FOUND;
    c.step("FORGET deletes an ended task's record", forgotten);

    // The kernel replaces the runtime once the agent logs `ready to stop`.
    let recovered = c.submit(b"worker", b"durable").is_ok_and(|t| {
        c.wait(t, 90).is_some_and(|(s, r)| {
            s.state == State::Done && s.attempts == 2 && r == b"recovered sent"
        })
    });
    c.step(
        "a task outlives the runtime: its checkpoint comes back and its operation is DONE",
        recovered,
    );
}

/// One boot of the `agents_crash` kernel.
fn crash(mut c: Client) -> u64 {
    let mut out = [0u8; 256];
    let task = match c.call(&Request::Status { task: 1 }, &mut out).0 {
        status::NOT_FOUND => c.submit(b"counter", b"count"),
        status::OK | status::NO_BUFFER => Ok(1),
        code => Err(code),
    };
    // What the last boot left: a task that has not failed.
    let sound = task.is_ok_and(|t| c.status(t).is_some_and(|s| s.state != State::Failed));
    let line: &[u8] = if sound {
        b"agents check: ok"
    } else {
        b"agents check: failed"
    };
    let _ = debug_write(CONSOLE, line);
    let Ok(task) = task else {
        c.step("the counter task was submitted", false);
        return c.failed;
    };
    match c.wait(task, 150) {
        Some((s, result)) => {
            let _ = debug_write(CONSOLE, b"agents check: done");
            if s.state != State::Done {
                let mut line = Vec::from(&b"counter task result: "[..]);
                line.extend_from_slice(&result[..result.len().min(200)]);
                let _ = debug_write(CONSOLE, &line);
            }
            c.step(
                "the counter task completed, each step's record checked on every attempt",
                s.state == State::Done && result == b"count 30",
            );
            c.step("it needed at most its 10 attempts", s.attempts <= 10);
        }
        None => c.step("the counter task ended", false),
    }
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}
