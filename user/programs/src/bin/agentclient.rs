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
//! the task if the store has none, and waits for it to end. Argument 2:
//! the `permissions` kernel (#105): `keeper-a`, then `keeper-b`, whose
//! permissions the runner revokes on the trusted console while it runs.
//! Argument 3: the `agents_net` kernel (#109): a `netter` task that talks
//! to the host echo server, and a `listener` task (the same grant) that
//! sends nothing. Argument 4: the `hostile` kernel (#110): a `hostile`
//! task beside a `keeper` task. Argument 5: the `budgets` kernel (#116).
//! Argument 6: the `fairness` kernel (#117). Argument 7: the `exhaustion`
//! kernel (#120). Argument 8: the `tools` kernel (#126, #127): a `reader`
//! task, then a `plain` task. Argument 9: the `injection` kernel (#129):
//! an `injected` task. Argument 10: the `channels` kernel (#133):
//! `hearer`, `talker`, `outsider`, and `spammer` tasks at once. Argument
//! 11: the `groups` kernel (#134): a `boss` task. Argument 12: the
//! `deputy` kernel (#138): three `boss` goals, one after the other.

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
    if arg == 2 {
        return permissions(c);
    }
    if arg == 3 {
        return net(c);
    }
    if arg == 4 {
        return hostile(c);
    }
    if arg == 5 {
        return budgets(c);
    }
    if arg == 6 {
        return fairness(c);
    }
    if arg == 7 {
        return exhaustion(c);
    }
    if arg == 8 {
        return tools(c);
    }
    if arg == 12 {
        let goal = |c: &Client, input: &[u8], id: u32, want: &[u8]| {
            c.submit(b"boss", input).ok() == Some(id)
                && c.wait(id, 90).is_some_and(|(s, result)| {
                    if result != want {
                        let mut line = Vec::from(&b"deputy kernel result: "[..]);
                        line.extend_from_slice(&result[..result.len().min(200)]);
                        let _ = debug_write(CONSOLE, &line);
                    }
                    s.state == State::Done && result == want
                })
        };
        let trapped = goal(&c, b"trap", 1, b"trap ok");
        c.step(
            "a compromised worker, a passed-on delegation, and injected messages gain nothing",
            trapped,
        );
        let apart = goal(&c, b"apart", 4, b"apart ok");
        c.step("a goal reads only its own subtasks", apart);
        let swarm = goal(&c, b"swarm", 5, b"swarm ok");
        c.step("a goal gets at most 32 subtasks in all", swarm);
        let _ = send(REPORT, b"done", 0, 0, 0);
        return c.failed;
    }
    if arg == 11 {
        let task = c.submit(b"boss", b"lead");
        let done = task
            .ok()
            .and_then(|t| c.wait(t, 90))
            .is_some_and(|(s, result)| {
                if result != b"boss ok" {
                    let mut line = Vec::from(&b"groups kernel result: "[..]);
                    line.extend_from_slice(&result[..result.len().min(200)]);
                    let _ = debug_write(CONSOLE, &line);
                }
                s.state == State::Done && result == b"boss ok"
            });
        c.step(
            "a supervisor completes a goal through its workers, and only them",
            done,
        );
        // #136, #137: a second goal (13) that the verifier refuses; its
        // end cancels its last subtask (17). Then a third (18, subtasks 19
        // and 20), which `stop group crew` on the trusted console ends.
        let mut out = [0u8; 256];
        let cancelled =
            |c: &Client, t: u32| c.status(t).is_some_and(|s| s.state == State::Cancelled);
        let idle = |c: &Client, out: &mut [u8; 256]| {
            let (_, n) = c.call(&Request::Info, out);
            Info::parse(&out[..n]).is_some_and(|i| i.details == [17, 0])
        };
        let refused = c.submit(b"boss", b"falter").ok() == Some(13)
            && c.wait(13, 90).is_some_and(|(s, result)| {
                s.state == State::Failed && result == b"not verified: subtask"
            });
        c.step("a goal whose subtasks failed is not verified", refused);
        sleep(1_000_000);
        c.step(
            "a goal's end cancels its open subtasks",
            cancelled(&c, 17) && idle(&c, &mut out),
        );
        let stood = c.submit(b"boss", b"stand").ok() == Some(18)
            && c.wait(18, 90)
                .is_some_and(|(s, _)| s.state == State::Cancelled);
        sleep(1_000_000);
        c.step(
            "stop group ends the group's goal, its subtasks, and its request",
            stood && cancelled(&c, 19) && cancelled(&c, 20) && idle(&c, &mut out),
        );
        let _ = send(REPORT, b"done", 0, 0, 0);
        return c.failed;
    }
    if arg == 10 {
        let tasks = [
            (&b"hearer"[..], &b"listen"[..], &b"hearer ok"[..]),
            (b"talker", b"talk", b"talker ok"),
            (b"outsider", b"outside", b"outsider ok"),
            (b"spammer", b"spam", b"spammer ok"),
        ]
        .map(|(agent, input, want)| (c.submit(agent, input), want));
        let ended = tasks.iter().all(|(task, want)| {
            task.ok()
                .and_then(|t| c.wait(t, 60))
                .is_some_and(|(s, result)| {
                    if result != *want {
                        let mut line = Vec::from(&b"channels kernel result: "[..]);
                        line.extend_from_slice(&result[..result.len().min(200)]);
                        let _ = debug_write(CONSOLE, &line);
                    }
                    s.state == State::Done && result == *want
                })
        });
        c.step(
            "agents talk only on granted channels, in order, within their budgets",
            ended,
        );
        let _ = send(REPORT, b"done", 0, 0, 0);
        return c.failed;
    }
    if arg == 9 {
        let task = c.submit(b"injected", b"inject");
        let done = task
            .ok()
            .and_then(|t| c.wait(t, 60))
            .is_some_and(|(s, result)| {
                if result != b"inject ok" {
                    let mut line = Vec::from(&b"injection kernel result: "[..]);
                    line.extend_from_slice(&result[..result.len().min(200)]);
                    let _ = debug_write(CONSOLE, &line);
                }
                s.state == State::Done && result == b"inject ok" && s.attempts == 1
            });
        c.step(
            "no injected or malformed call has any effect beyond the grants",
            done,
        );
        let _ = send(REPORT, b"done", 0, 0, 0);
        return c.failed;
    }
    let mut out = [0u8; 256];

    let (_, n) = c.call(&Request::Info, &mut out);
    let info = Info::parse(&out[..n]);
    c.step(
        "INFO: interface agents, seventeen agents accepted, none running",
        info.is_some_and(|i| i.name == NAME && i.details == [17, 0]),
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
    let idle = Info::parse(&out[..n]).is_some_and(|i| i.details == [17, 0]);
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
fn permissions(mut c: Client) -> u64 {
    for (input, want, step) in [
        (
            &b"keeper-a"[..],
            &b"a ok"[..],
            "with its grants, an agent writes and reads its own file and generates from model 2",
        ),
        (
            b"keeper-b",
            b"b ok",
            "revoked while it runs: refused at once, its session ended, and still after a restart",
        ),
        (
            b"ask",
            b"ask ok",
            "asked: approved for 2 s then refused again, refused by the user, unanswered refused",
        ),
    ] {
        let agent: &[u8] = if input == b"ask" { b"asker" } else { b"keeper" };
        let Ok(task) = c.submit(agent, input) else {
            c.step(step, false);
            continue;
        };
        let ended = c.wait(task, 60);
        if let Some((s, result)) = &ended {
            if result != want {
                let mut line = Vec::from(&b"keeper result: "[..]);
                line.extend_from_slice(&result[..result.len().min(200)]);
                let _ = debug_write(CONSOLE, &line);
            }
            // `keeper-b` crashes once after its checks, on purpose.
            let attempts = if input == b"keeper-b" { 2 } else { 1 };
            c.step(
                step,
                s.state == State::Done && result == want && s.attempts == attempts,
            );
        } else {
            c.step(step, false);
        }
    }
    // Audit (#108): `keeper-d` waits for `keeper-c`, during which the
    // kernel kills the audit service.
    let tasks = c
        .submit(b"keeper", b"keeper-c")
        .and_then(|t| c.submit_after(b"keeper", b"keeper-d", &[t]).map(|d| (t, d)));
    let ended = |c: &Client, t: u32, want: &[u8]| {
        c.wait(t, 60)
            .is_some_and(|(s, r)| s.state == State::Done && r == want)
    };
    let (c_ok, d_ok) = match tasks {
        Ok((t, d)) => (ended(&c, t, b"c ok"), ended(&c, d, b"d ok")),
        Err(_) => (false, false),
    };
    c.step(
        "with the audit trail gone, consequential actions are refused with NO_AUDIT",
        c_ok,
    );
    c.step(
        "a task started then gets no grant, as none could be recorded",
        d_ok,
    );
    c.step(
        "and a new task cannot be submitted (NO_AUDIT)",
        c.submit(b"keeper", b"keeper-a") == Err(pharos_proto::agents::NO_AUDIT),
    );
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// The `agents_net` kernel: `net-quiet` runs while `net-talk` exchanges
/// datagrams.
fn net(mut c: Client) -> u64 {
    let quiet = c.submit(b"listener", b"net-quiet");
    let talk = c.submit(b"netter", b"net-talk");
    let ended = |c: &Client, task: Result<u32, u8>, want: &[u8]| {
        let Some((s, result)) = task.ok().and_then(|t| c.wait(t, 60)) else {
            return false;
        };
        if result != want {
            let mut line = Vec::from(&b"net result: "[..]);
            line.extend_from_slice(&result[..result.len().min(200)]);
            let _ = debug_write(CONSOLE, &line);
        }
        s.state == State::Done && result == want
    };
    c.step(
        "an agent sends only to granted destinations and gets their replies until revoked",
        ended(&c, talk, b"talk ok"),
    );
    c.step(
        "another agent with the same grant that sent nothing receives nothing",
        ended(&c, quiet, b"quiet ok"),
    );
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// The `hostile` kernel: `hostile` (task 1) and `keeper-a` (task 2) run
/// side by side.
fn hostile(mut c: Client) -> u64 {
    let bad = c.submit(b"hostile", b"hostile");
    let good = c.submit(b"keeper", b"keeper-a");
    let ended = |c: &Client, task: Result<u32, u8>, want: &[u8]| {
        let Some((s, result)) = task.ok().and_then(|t| c.wait(t, 60)) else {
            return false;
        };
        if result != want {
            let mut line = Vec::from(&b"hostile kernel result: "[..]);
            line.extend_from_slice(&result[..result.len().min(200)]);
            let _ = debug_write(CONSOLE, &line);
        }
        s.state == State::Done && result == want && s.attempts == 1
    };
    c.step(
        "a hostile agent is refused everything it should not do",
        ended(&c, bad, b"hostile ok"),
    );
    c.step(
        "an agent beside it completes unaffected",
        ended(&c, good, b"a ok"),
    );
    let mut out = [0u8; 256];
    c.step(
        "the runtime still serves control requests",
        c.call(&Request::Info, &mut out).0 == status::OK,
    );
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// The `tools` kernel (#126, #127): `reader` uses `read_file` within its
/// grants, then `plain`, which may use no tool.
fn tools(mut c: Client) -> u64 {
    let ended = |c: &Client, task: Result<u32, u8>, want: &[u8]| {
        let Some((s, result)) = task.ok().and_then(|t| c.wait(t, 60)) else {
            return false;
        };
        if result != want {
            let mut line = Vec::from(&b"tools kernel result: "[..]);
            line.extend_from_slice(&result[..result.len().min(200)]);
            let _ = debug_write(CONSOLE, &line);
        }
        s.state == State::Done && result == want && s.attempts == 1
    };
    let reader = c.submit(b"reader", b"tools");
    c.step(
        "read_file reads a granted file; every other call is refused",
        ended(&c, reader, b"tools ok"),
    );
    let plain = c.submit(b"plain", b"tools-plain");
    c.step(
        "an agent that may use no tool is refused one",
        ended(&c, plain, b"plain ok"),
    );
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// The `budgets` kernel (#116): each agent within its budget or its
/// group's, `hog` stopped over its CPU time, and `pair` and `big` tasks
/// started one at a time by their groups.
fn budgets(mut c: Client) -> u64 {
    let ended = |c: &Client, task: Result<u32, u8>, state: State, want: &[u8]| {
        let Some((s, result)) = task.ok().and_then(|t| c.wait(t, 60)) else {
            return false;
        };
        if result != want {
            let mut line = Vec::from(&b"budgets kernel result: "[..]);
            line.extend_from_slice(&result[..result.len().min(200)]);
            let _ = debug_write(CONSOLE, &line);
        }
        s.state == state && (want.is_empty() || result == want) && s.attempts == 1
    };
    let spender = c.submit(b"spender", b"spend");
    let grouper = c.submit(b"grouper", b"group-spend");
    let hog = c.submit(b"hog", b"hang");
    c.step(
        "an agent is refused past its tokens, datagrams, bytes, and files",
        ended(&c, spender, State::Done, b"spend ok"),
    );
    c.step(
        "an agent is refused past its group's tokens and bytes this minute",
        ended(&c, grouper, State::Done, b"group ok"),
    );
    c.step(
        "an agent over its CPU time is stopped, a failed attempt",
        ended(&c, hog, State::Failed, b""),
    );
    // One at a time: `pair`'s group runs one attempt, `big`'s has pages
    // for one.
    for (name, step) in [
        (
            &b"pair"[..],
            "a group of one runs its agents' tasks one at a time",
        ),
        (
            b"big",
            "a group's pages hold a second task until the first ends",
        ),
    ] {
        let first = c.submit(name, b"nap");
        let second = c.submit(name, b"nap");
        sleep(300_000);
        let states = [first, second].map(|t| t.ok().and_then(|t| c.status(t)).map(|s| s.state));
        let one_waits = states == [Some(State::Running), Some(State::Pending)];
        c.step(
            step,
            one_waits
                && ended(&c, first, State::Done, b"napped")
                && ended(&c, second, State::Done, b"napped"),
        );
    }
    // Runs while the runner types `usage` on the trusted console (#119).
    let idler = c.submit(b"idler", b"wait");
    sleep(3_000_000);
    c.step("an idle agent ran while usage was asked", idler.is_ok());
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// The `fairness` kernel (#117): four tasks at once, each checking one way
/// an agent could hold the runtime.
fn fairness(mut c: Client) -> u64 {
    let tasks = [
        (
            &b"flooder"[..],
            &b"flood"[..],
            "requests for a stalled service are BUSY at once",
        ),
        (
            b"ticker",
            b"tick",
            "another agent is served while one floods a stalled service",
        ),
        (
            b"rater",
            b"rate",
            "an agent past its rate is held, then served at the rate",
        ),
        (
            b"queuer",
            b"queue",
            "an agent may have one approval request waiting",
        ),
    ];
    let submitted = tasks.map(|(name, input, _)| c.submit(name, input));
    for ((_, input, step), task) in tasks.iter().zip(submitted) {
        let mut want = Vec::from(*input);
        want.extend_from_slice(b" ok");
        let ok = task
            .ok()
            .and_then(|t| c.wait(t, 60))
            .is_some_and(|(s, result)| {
                if result != want {
                    let mut line = Vec::from(&b"fairness kernel result: "[..]);
                    line.extend_from_slice(&result[..result.len().min(200)]);
                    let _ = debug_write(CONSOLE, &line);
                }
                s.state == State::Done && result == want
            });
        c.step(step, ok);
    }
    let _ = send(REPORT, b"done", 0, 0, 0);
    c.failed
}

/// The `exhaustion` kernel (#120): two `spinner`s, `glutton`, and
/// `ticker` at once, the most that run together; `ticker` must be served
/// throughout and `glutton` held to every limit. Then a third spinner
/// (`idler`) is the runner's cue for `stop all`.
fn exhaustion(mut c: Client) -> u64 {
    let spinners = [c.submit(b"spinner", b"spin"), c.submit(b"spinner", b"spin")];
    let glutton = c.submit(b"glutton", b"glut");
    let ticker = c.submit(b"ticker", b"tick");
    let ended = |c: &Client, task: Result<u32, u8>, want: &[u8]| {
        task.ok()
            .and_then(|t| c.wait(t, 60))
            .is_some_and(|(s, result)| {
                if result != want {
                    let mut line = Vec::from(&b"exhaustion kernel result: "[..]);
                    line.extend_from_slice(&result[..result.len().min(200)]);
                    let _ = debug_write(CONSOLE, &line);
                }
                s.state == State::Done && result == want
            })
    };
    c.step(
        "a well-behaved agent is served throughout",
        ended(&c, ticker, b"tick ok"),
    );
    c.step(
        "an agent is held to its pages, handles, rate, tokens, datagrams, bytes, and files",
        ended(&c, glutton, b"spend ok"),
    );
    c.step(
        "the spinning agents still run",
        spinners
            .iter()
            .all(|t| t.is_ok_and(|t| c.status(t).is_some_and(|s| s.state == State::Running))),
    );
    let _ = send(REPORT, b"done", 0, 0, 0);
    let _ = c.submit(b"idler", b"spin");
    c.failed
}

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
