//! The agent runtime (#98, agents.md): starts agents for tasks, watches
//! them, and serves their requests. Unprivileged, and not trusted for the
//! emergency stop: `trust` holds `STOP` on it and on every agent.
//!
//! Handles: 1 the console, 2 its endpoint (`RECEIVE`, `SEND`, `GRANT`, to
//! hand agents a badged `SEND`), 3 `init`'s report endpoint, 4 the
//! read-only filesystem (agent programs and manifests), 5 the inference
//! service (`SEND`, badged), 6 `trust` (`SEND`, badged as the runtime), 7
//! the storage service, badged for namespace `agents` (read-write). The
//! argument selects the policy table (0: boot, empty; 1: the `agents` and
//! `agents_crash` test kernels).
//!
//! Each policy entry's manifest, `agents/<name>.manifest`, is read and
//! checked at start; an agent whose manifest is missing or refused never
//! runs. Every task attempt is one process holding one capability: `SEND`
//! on the runtime's endpoint, badged with its slot. The process is
//! registered with `trust` before the runtime answers it. Tasks are kept
//! in the store ([`pharos_programs::tasks`], #99): every change is stored
//! before it is answered or acted on, and at start the runtime recovers
//! them, a task that was running becoming pending again.
//!
//! Permissions (#105, capabilities.md): each attempt's grants are built
//! from its manifest within the policy entry, checked on every request
//! that needs one (inference, the agent's files), and revocable while it
//! runs: `trust` sends `REVOKE` on the capability the runtime gives it at
//! start (`CHANNEL`), and the runtime answers with `REVOKED`. A revocation
//! holds for the rest of the task, across restarts.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_programs::grants::Grants;
use pharos_programs::tasks::{self, Begin, Files, StoreFailed, Tasks};
use pharos_proto::agents::{
    self, Assigned, Begun, CHECKPOINT_AT, CONTROL, MAX_BUFFER, MAX_CHECKPOINT, MAX_INPUT,
    MAX_RESULT, MAX_RUNNING, NAME, NO_SESSION, Request, SLOTS, State, TaskStatus, VERSION,
    agent_slot, parse,
};
use pharos_proto::infer::{self, Request as InferRequest, Started, Tokens};
use pharos_proto::manifest::{self, Data, Entry, Why};
use pharos_proto::permission::Permission;
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{Info, refusal, status, trust};
use pharos_user::rights::{READ, SEND, STOP, WAIT, WRITE};
use pharos_user::{
    Grant, Handle, Mapped, Received, Status, call_timeout, debug_write, delete, endpoint_create,
    mem_map_buffer, mem_map_cap, mem_share, mem_unmap, open, process_status, process_stop, read,
    receive_timeout, send, spawn_limited, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const ROOT: Handle = 4;
const INFER: Handle = 5;
const TRUST: Handle = 6;
const STORE: Handle = 7;
/// The runtime's buffer at the storage service: the largest task file.
const STORE_BUFFER: u64 = 128 << 10;
const STORE_US: u64 = 10_000_000;

/// How long a call to the inference service may take; `GENERATE` may load
/// a model first.
const GENERATE_US: u64 = 60_000_000;
const INFER_US: u64 = 10_000_000;
/// Control clients with an attached buffer.
const MAX_CONTROLS: usize = 4;

const BOOT: &[Entry] = &[];

/// The test kernels' agents, all `bin/testagent`. `greedy`'s manifest
/// asks for more pages than its entry allows; `absent` has no manifest;
/// `counter` is the `agents_crash` kernel's.
const TEST: &[Entry] = &[
    Entry {
        name: b"worker",
        program: b"bin/testagent",
        pages: 256,
        models: 1 << 2,
        attempts: 3,
        progress_ms: 2_000,
        task_ms: 20_000,
        data: Data::None,
    },
    Entry {
        name: b"greedy",
        program: b"bin/testagent",
        pages: 64,
        models: 0,
        attempts: 1,
        progress_ms: 2_000,
        task_ms: 20_000,
        data: Data::None,
    },
    Entry {
        name: b"absent",
        program: b"bin/testagent",
        pages: 64,
        models: 0,
        attempts: 1,
        progress_ms: 2_000,
        task_ms: 20_000,
        data: Data::None,
    },
    Entry {
        name: b"counter",
        program: b"bin/testagent",
        pages: 64,
        models: 0,
        attempts: 10,
        progress_ms: 5_000,
        task_ms: 120_000,
        data: Data::None,
    },
    // The `permissions` kernel's (#105).
    Entry {
        name: b"keeper",
        program: b"bin/testagent",
        pages: 256,
        models: 1 << 2,
        attempts: 2,
        progress_ms: 5_000,
        task_ms: 60_000,
        data: Data::Write,
    },
];

/// What an accepted manifest asked for (at most its entry).
#[derive(Clone, Copy)]
struct Limits {
    entry: &'static Entry,
    pages: u32,
    models: u32,
    attempts: u8,
    progress_us: u64,
    task_us: u64,
    data: Data,
}

/// The storage service as [`Files`], through the runtime's buffer there.
struct Store {
    buffer: Mapped,
    reply: Handle,
}

impl Store {
    /// Attaches the buffer at the storage service: at start, and again
    /// after the service restarted and lost it (#100).
    fn attach(&self) -> bool {
        let len = self.buffer.len() as u64;
        let attached = mem_share(self.buffer.addr(), len).is_ok_and(|memory| {
            let mut msg = [0u8; 16];
            let sent = store::encode(&StoreRequest::Attach { len }, &mut msg)
                .is_some_and(|n| send(STORE, &msg[..n], memory, READ | WRITE, 0).is_ok());
            let _ = delete(memory);
            sent
        });
        let mut out = [0u8; 256];
        attached
            && self.call(&StoreRequest::Buffer, &mut out) == Ok(StoreStatus::Ok)
            && u64_at(&out, 1) == len
    }

    /// A request that uses the buffer, attaching it again once if the
    /// service has none from us.
    fn call_buffered(
        &self,
        req: &StoreRequest<'_>,
        out: &mut [u8; 256],
    ) -> Result<StoreStatus, StoreFailed> {
        match self.call(req, out)? {
            StoreStatus::NoBuffer if self.attach() => self.call(req, out),
            s => Ok(s),
        }
    }

    fn call(
        &self,
        req: &StoreRequest<'_>,
        out: &mut [u8; 256],
    ) -> Result<StoreStatus, StoreFailed> {
        let mut msg = [0u8; 256];
        let n = store::encode(req, &mut msg).ok_or(StoreFailed)?;
        match call_timeout(STORE, &msg[..n], self.reply, out, STORE_US) {
            Ok(Received::Message { len, .. }) if len >= 1 => Ok(StoreStatus::from_code(out[0])),
            _ => Err(StoreFailed),
        }
    }
}

/// `data/<agent>/<file>`, in the runtime's namespace.
fn data_path(agent: &[u8], file: &[u8]) -> Vec<u8> {
    let mut p = Vec::from(&b"data/"[..]);
    p.extend_from_slice(agent);
    p.push(b'/');
    p.extend_from_slice(file);
    p
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

impl Files for Store {
    fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
        if bytes.len() > self.buffer.len() {
            return Err(StoreFailed);
        }
        self.buffer.write_bytes(0, bytes);
        let len = bytes.len() as u64;
        let req = StoreRequest::Write { path, len, at: 0 };
        match self.call_buffered(&req, &mut [0; 256])? {
            StoreStatus::Ok => Ok(()),
            _ => Err(StoreFailed),
        }
    }

    fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed> {
        let mut out = [0u8; 256];
        match self.call(&StoreRequest::Stat { path }, &mut out)? {
            StoreStatus::NotFound => return Ok(None),
            StoreStatus::Ok => {}
            _ => return Err(StoreFailed),
        }
        let len = u64_at(&out, 2);
        if len > self.buffer.len() as u64 {
            return Err(StoreFailed);
        }
        let req = StoreRequest::Read {
            path,
            offset: 0,
            len,
            at: 0,
        };
        if self.call_buffered(&req, &mut out)? != StoreStatus::Ok || u64_at(&out, 1) != len {
            return Err(StoreFailed);
        }
        let mut bytes = alloc::vec![0u8; len as usize];
        self.buffer.read_bytes(0, &mut bytes);
        Ok(Some(bytes))
    }

    fn delete(&mut self, path: &[u8]) -> Result<(), StoreFailed> {
        match self.call(&StoreRequest::Delete { path }, &mut [0; 256])? {
            StoreStatus::Ok | StoreStatus::NotFound => Ok(()),
            _ => Err(StoreFailed),
        }
    }

    fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed> {
        let mut names = Vec::new();
        loop {
            let mut out = [0u8; 256];
            let start = names.len() as u32;
            if self.call(&StoreRequest::List { prefix, start }, &mut out)? != StoreStatus::Ok {
                return Err(StoreFailed);
            }
            let (count, more) = (out[1], out[2]);
            let mut at = 3;
            for _ in 0..count {
                let n = usize::from(*out.get(at).ok_or(StoreFailed)?);
                names.push(out.get(at + 1..at + 1 + n).ok_or(StoreFailed)?.to_vec());
                at += 1 + n;
            }
            if more == 0 || count == 0 {
                return Ok(names);
            }
        }
    }
}

/// Why the runtime itself ended an agent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// `COMPLETE` or `FAIL`: the task's state is already set.
    Finished,
    Hung,
    Cancelled,
}

/// A running agent process.
struct Slot {
    /// The task's ID.
    task: u32,
    process: Handle,
    buffer: Option<Mapped>,
    started: u64,
    last: u64,
    /// The open inference session and its model.
    session: Option<u32>,
    session_model: u8,
    ending: Option<Ending>,
    grants: Grants,
}

struct Runtime {
    agents: Vec<Limits>,
    tasks: Tasks,
    store: Store,
    slots: [Option<Slot>; SLOTS],
    controls: [Option<(u32, Mapped)>; MAX_CONTROLS],
    infer_buffer: Mapped,
    reply: Handle,
    /// Permissions revoked from running tasks, kept for their restarts.
    revoked: Vec<(u32, Permission)>,
}

fn decimal(mut v: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    loop {
        at -= 1;
        out[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &out[at..];
        }
    }
}

fn say(parts: &[&[u8]]) {
    let mut line = [0u8; 256];
    let mut n = 0;
    for p in parts {
        let take = p.len().min(line.len() - n);
        line[n..n + take].copy_from_slice(&p[..take]);
        n += take;
    }
    let _ = debug_write(CONSOLE, &line[..n]);
}

/// The status for a refused task change.
fn store_error(e: tasks::Error) -> u8 {
    match e {
        tasks::Error::NotFound => status::NOT_FOUND,
        tasks::Error::TooLarge => status::TOO_LARGE,
        tasks::Error::Busy => status::BUSY,
        tasks::Error::Store => status::INTERNAL,
    }
}

/// A reply of just `OK`.
fn done(out: &mut [u8; 256]) -> usize {
    out[0] = status::OK;
    1
}

fn unmap(m: Mapped) {
    let _ = mem_unmap(m.addr(), m.len() as u64);
}

fn why(w: Why) -> &'static [u8] {
    match w {
        Why::TooLarge => b"too large",
        Why::BadByte => b"bad byte",
        Why::BadLine => b"bad line",
        Why::UnknownKey => b"unknown key",
        Why::RepeatedKey => b"repeated key",
        Why::MissingKey => b"missing key",
        Why::Version => b"version",
        Why::BadValue => b"bad value",
        Why::ProgressOverTask => b"progress_ms over task_ms",
        Why::NoEntry => b"no policy entry",
        Why::WrongProgram => b"another program",
        Why::OverPolicy => b"asks for more than its policy entry",
    }
}

/// Reads and checks `e`'s manifest.
fn load(e: &'static Entry, table: &'static [Entry]) -> Result<Limits, &'static [u8]> {
    let mut path = [0u8; 64];
    let parts: [&[u8]; 3] = [b"agents/", e.name, b".manifest"];
    let mut n = 0;
    for p in parts {
        path[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let file = open(ROOT, &path[..n]).map_err(|_| &b"no manifest"[..])?;
    // One byte more than allowed, so a longer file is refused.
    let mut text = [0u8; manifest::MAX_SIZE + 1];
    let mut len = 0;
    while len < text.len() {
        // `read` takes at most 4096 bytes a call.
        let end = text.len().min(len + 4096);
        match read(file, len as u64, &mut text[len..end]) {
            Ok(0) => break,
            Ok(k) => len += k,
            Err(_) => {
                let _ = delete(file);
                return Err(b"cannot read the manifest");
            }
        }
    }
    let _ = delete(file);
    let m = manifest::parse(&text[..len]).map_err(|r| why(r.why))?;
    let entry = m.within(table).map_err(why)?;
    if !core::ptr::eq(entry, e) {
        return Err(why(Why::NoEntry));
    }
    Ok(Limits {
        entry: e,
        pages: m.pages,
        models: m.models,
        attempts: m.attempts,
        progress_us: u64::from(m.progress_ms) * 1000,
        task_us: u64::from(m.task_ms) * 1000,
        data: m.data,
    })
}

impl Runtime {
    fn limits(&self, agent: &[u8]) -> Option<Limits> {
        self.agents.iter().find(|l| l.entry.name == agent).copied()
    }

    fn event(&self, id: u32, what: &[u8], number: Option<u64>) {
        let name = self
            .tasks
            .find(id)
            .map_or(&b"?"[..], |i| &self.tasks.list[i].agent);
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        let number = number.map_or(&b""[..], |v| decimal(v, &mut b));
        let space: &[u8] = if number.is_empty() { b"" } else { b" " };
        say(&[
            b"agents: ",
            name,
            b" task ",
            decimal(u64::from(id), &mut a),
            b" ",
            what,
            space,
            number,
        ]);
    }

    /// A call to the inference service; the reply's length in `out`.
    fn infer(&self, req: &InferRequest, timeout: u64, out: &mut [u8; 256]) -> Option<usize> {
        let mut msg = [0u8; 64];
        let n = infer::encode(req, &mut msg)?;
        match call_timeout(INFER, &msg[..n], self.reply, out, timeout) {
            Ok(Received::Message { len, .. }) if len >= 1 => Some(len.min(256)),
            _ => None,
        }
    }

    fn cancel_session(&mut self, slot: usize) {
        if let Some(session) = self.slots[slot].as_mut().and_then(|s| s.session.take()) {
            let _ = self.infer(&InferRequest::Cancel { session }, INFER_US, &mut [0; 256]);
        }
    }

    /// Ends `slot`'s process for `why`; its notification frees the slot.
    fn end(&mut self, slot: usize, why: Ending) {
        self.cancel_session(slot);
        if let Some(s) = self.slots[slot].as_mut() {
            s.ending = Some(why);
            let _ = process_stop(s.process);
        }
    }

    fn running(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Ends task `id` with `state`, stored; says so if the store refused.
    fn finish(&mut self, id: u32, state: State, result: &[u8]) -> bool {
        let stored = self
            .tasks
            .find(id)
            .is_some_and(|i| self.tasks.finish(&mut self.store, i, state, result).is_ok());
        if !stored {
            self.event(id, b"not stored", None);
        }
        stored
    }

    /// Starts runnable tasks, oldest first, while slots are free.
    fn start_pending(&mut self) {
        while self.running() < MAX_RUNNING {
            let Some(slot) = self.slots.iter().position(Option::is_none) else {
                return;
            };
            let agents = &self.agents;
            let runnable = |t: &tasks::Task| agents.iter().any(|l| l.entry.name == t.agent);
            let Some(i) = self.tasks.next(&mut self.store, runnable) else {
                return;
            };
            // The attempt is counted and stored before the agent runs; if
            // the store refuses, try again on the next event.
            if self.tasks.start(&mut self.store, i).is_err() {
                return;
            }
            self.start(self.tasks.list[i].id, slot);
        }
    }

    fn start(&mut self, id: u32, slot: usize) {
        let Some(limits) = self
            .tasks
            .find(id)
            .and_then(|i| self.limits(&self.tasks.list[i].agent))
        else {
            return;
        };
        let process = open(ROOT, limits.entry.program).and_then(|file| {
            let grant = Grant {
                handle: SERVICE,
                rights: SEND,
                badge: slot as u32 + 1,
            };
            let notify = Some((SERVICE, slot as u32));
            let p = spawn_limited(file, 0, &[grant], notify, limits.pages);
            let _ = delete(file);
            p
        });
        let Ok(process) = process else {
            self.finish(id, State::Failed, b"spawn failed");
            self.event(id, b"failed", None);
            return;
        };
        // `trust` holds the agent's STOP before the runtime answers it.
        let mut msg = [0u8; 64];
        let register = trust::Request::Register {
            slot: slot as u8,
            name: limits.entry.name,
        };
        let registered = trust::encode(&register, &mut msg)
            .is_some_and(|n| send(TRUST, &msg[..n], process, STOP | WAIT, 0).is_ok());
        let now = uptime();
        self.slots[slot] = Some(Slot {
            task: id,
            process,
            buffer: None,
            started: now,
            last: now,
            session: None,
            session_model: 0,
            ending: None,
            grants: {
                let mut g = Grants::new(limits.models, limits.data);
                for (_, p) in self.revoked.iter().filter(|(t, _)| *t == id) {
                    g.revoke(p);
                }
                g
            },
        });
        if !registered {
            self.finish(id, State::Failed, b"trust registration failed");
            self.end(slot, Ending::Finished);
            self.event(id, b"failed", None);
            return;
        }
        self.event(id, b"started", None);
    }

    /// Stops agents with no request for `progress_ms`, or over `task_ms`.
    /// Returns how long until the next deadline.
    fn check_deadlines(&mut self) -> u64 {
        let now = uptime();
        let mut wait = u64::MAX;
        for i in 0..SLOTS {
            let Some(s) = &self.slots[i] else { continue };
            if s.ending.is_some() {
                continue;
            }
            let (id, last, started) = (s.task, s.last, s.started);
            let Some(l) = self
                .tasks
                .find(id)
                .and_then(|t| self.limits(&self.tasks.list[t].agent))
            else {
                continue;
            };
            let deadline = (last + l.progress_us).min(started + l.task_us);
            if now >= deadline {
                self.end(i, Ending::Hung);
                self.event(id, b"hung", None);
            } else {
                wait = wait.min(deadline - now);
            }
        }
        wait
    }

    /// Slot `i`'s process ended (its notification bit).
    fn ended(&mut self, i: usize) {
        let status = match &self.slots[i] {
            Some(s) => process_status(s.process),
            None => return,
        };
        if status == Ok(Status::Running) {
            return;
        }
        self.cancel_session(i);
        let Some(s) = self.slots[i].take() else {
            return;
        };
        let _ = delete(s.process);
        if let Some(b) = s.buffer {
            unmap(b);
        }
        let id = s.task;
        match (s.ending, status) {
            (Some(Ending::Finished | Ending::Cancelled), _) => {}
            (Some(Ending::Hung), _) => self.retry(id),
            // Stopped, but not by the runtime: the user, on the trusted path.
            (None, Ok(Status::Stopped)) => {
                self.finish(id, State::Cancelled, b"stopped");
                self.event(id, b"stopped", None);
            }
            (None, Ok(Status::Killed(vector))) => {
                self.event(id, b"crashed", Some(vector));
                self.retry(id);
            }
            // Ending without COMPLETE or FAIL is a failed attempt.
            (None, Ok(Status::Exited(code))) => {
                self.event(id, b"exited", Some(code));
                self.retry(id);
            }
            (None, _) => self.retry(id),
        }
    }

    /// A failed attempt: run again, or fail the task.
    fn retry(&mut self, id: u32) {
        let Some(i) = self.tasks.find(id) else { return };
        let max = self
            .limits(&self.tasks.list[i].agent)
            .map_or(0, |l| l.attempts);
        let outcome = self.tasks.retry(&mut self.store, i, max);
        self.retried(id, max, outcome);
    }

    /// Reports a retry's outcome.
    fn retried(&self, id: u32, max: u8, outcome: Result<bool, tasks::Error>) {
        let Some(i) = self.tasks.find(id) else { return };
        match outcome {
            Ok(false) => self.event(id, b"failed", None),
            Ok(true) => {
                let mut d = [0u8; 20];
                let mut e = [0u8; 20];
                let next = decimal(u64::from(self.tasks.list[i].attempts) + 1, &mut d);
                let max = decimal(u64::from(max), &mut e);
                let mut what = [0u8; 64];
                let mut n = 0;
                for p in [&b"restarting "[..], next, b"/", max] {
                    what[n..n + p.len()].copy_from_slice(p);
                    n += p.len();
                }
                self.event(id, &what[..n], None);
            }
            // Still marked running: tried again by `retry_stranded`.
            Err(_) => self.event(id, b"not stored", None),
        }
    }

    /// Retries tasks left running without a process because the store
    /// refused their retry. Returns whether any are still left.
    fn retry_stranded(&mut self) -> bool {
        let slots = &self.slots;
        let has = |id: u32| slots.iter().flatten().any(|s| s.task == id);
        let agents = &self.agents;
        let max = |name: &[u8]| {
            agents
                .iter()
                .find(|l| l.entry.name == name)
                .map(|l| l.attempts)
        };
        let outcomes = self.tasks.retry_stranded(&mut self.store, has, max);
        let mut left = false;
        for (id, outcome) in outcomes {
            if outcome.is_err() {
                // Said once, when the first retry was refused.
                left = true;
                continue;
            }
            let max = self
                .tasks
                .find(id)
                .and_then(|i| self.limits(&self.tasks.list[i].agent))
                .map_or(0, |l| l.attempts);
            self.retried(id, max, outcome);
        }
        left
    }

    /// `ATTACH`: maps the caller's buffer read-write.
    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let mapped = (len <= MAX_BUFFER)
            .then(|| mem_map_cap(memory, true, len).ok())
            .flatten();
        let _ = delete(memory);
        let Some(m) = mapped else { return };
        if let Some(s) = agent_slot(badge).and_then(|i| self.slots[i].as_mut()) {
            if let Some(old) = s.buffer.replace(m) {
                unmap(old);
            }
        } else if badge >= CONTROL {
            let at = self
                .controls
                .iter()
                .position(|c| c.as_ref().is_some_and(|c| c.0 == badge))
                .or_else(|| self.controls.iter().position(Option::is_none));
            match at {
                Some(at) => {
                    if let Some((_, old)) = self.controls[at].replace((badge, m)) {
                        unmap(old);
                    }
                }
                None => unmap(m),
            }
        } else {
            unmap(m);
        }
    }

    fn info(&self, out: &mut [u8]) -> Option<usize> {
        let mut details = [0u8; 2];
        details[0] = self.agents.len() as u8;
        details[1] = self.running() as u8;
        Info {
            name: NAME,
            low: VERSION,
            high: VERSION,
            details: &details,
        }
        .encode(out)
    }

    /// One request from the agent in slot `i`.
    fn agent(&mut self, i: usize, req: Request<'_>, out: &mut [u8; 256]) -> Result<usize, u8> {
        let now = uptime();
        let Some(s) = self.slots[i].as_mut().filter(|s| s.ending.is_none()) else {
            return Err(NO_SESSION);
        };
        s.last = now;
        let (id, session) = (s.task, s.session);
        let t = self.tasks.find(id).ok_or(NO_SESSION)?;
        let limits = self
            .limits(&self.tasks.list[t].agent)
            .ok_or(status::INTERNAL)?;
        let buffer = self.slots[i].as_ref().and_then(|s| s.buffer.as_ref());
        let buffer_len = buffer.map_or(0, Mapped::len);
        let stored = |r: Result<(), tasks::Error>| r.map_err(store_error);
        match req {
            Request::Task => {
                let task = &self.tasks.list[t];
                let cp = task.checkpoint.len();
                if task.input.len() > buffer_len
                    || (cp > 0 && CHECKPOINT_AT as usize + cp > buffer_len)
                {
                    return Err(status::NO_BUFFER);
                }
                if let Some(b) = buffer {
                    b.write_bytes(0, &task.input);
                    b.write_bytes(CHECKPOINT_AT as usize, &task.checkpoint);
                }
                Assigned {
                    task: task.id,
                    attempt: task.attempts,
                    input_len: task.input.len() as u32,
                    checkpoint_len: cp as u32,
                }
                .encode(out)
                .ok_or(status::INTERNAL)
            }
            Request::Checkpoint { len } => {
                if len > MAX_CHECKPOINT {
                    return Err(status::TOO_LARGE);
                }
                if CHECKPOINT_AT as usize + len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                let mut bytes = alloc::vec![0u8; len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(CHECKPOINT_AT as usize, &mut bytes);
                }
                stored(self.tasks.checkpoint(&mut self.store, t, &bytes))?;
                Ok(done(out))
            }
            Request::Begin { key } => {
                let begun = self
                    .tasks
                    .begin(&mut self.store, t, key)
                    .map_err(store_error)?;
                match begun {
                    Begin::Go => Begun::Go.encode(out),
                    Begin::Done(r) => Begun::Done(&r).encode(out),
                    Begin::Unknown => Begun::Unknown.encode(out),
                }
                .ok_or(status::INTERNAL)
            }
            Request::End { key, result } => {
                stored(self.tasks.end(&mut self.store, t, key, result))?;
                Ok(done(out))
            }
            Request::Complete { len } => {
                if len > MAX_RESULT {
                    return Err(status::TOO_LARGE);
                }
                if len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                let mut result = alloc::vec![0u8; len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(0, &mut result);
                }
                stored(self.tasks.finish(&mut self.store, t, State::Done, &result))?;
                self.end(i, Ending::Finished);
                self.event(id, b"completed", None);
                Ok(done(out))
            }
            Request::Fail { reason } => {
                stored(self.tasks.finish(&mut self.store, t, State::Failed, reason))?;
                self.end(i, Ending::Finished);
                self.event(id, b"failed", None);
                Ok(done(out))
            }
            Request::Log { text } => {
                say(&[b"agents: ", limits.entry.name, b": ", text]);
                Ok(done(out))
            }
            Request::Infer {
                model,
                max_new,
                prompt_len,
            } => {
                let allowed = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&Permission::Model(model), now));
                if !allowed {
                    return Err(status::NO_ACCESS);
                }
                if prompt_len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                if prompt_len as usize > self.infer_buffer.len() {
                    return Err(status::TOO_LARGE);
                }
                if self.slots.iter().flatten().any(|s| s.session.is_some()) {
                    return Err(status::BUSY);
                }
                // Copied out of the agent's buffer before the service sees it.
                let mut prompt = alloc::vec![0u8; prompt_len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(0, &mut prompt);
                }
                self.infer_buffer.write_bytes(0, &prompt);
                let req = InferRequest::Generate {
                    model,
                    max_new,
                    prompt_len,
                };
                let mut n = self.infer(&req, GENERATE_US, out).ok_or(status::INTERNAL)?;
                if out[0] == status::NO_BUFFER && attach_prompt(&self.infer_buffer) {
                    n = self.infer(&req, GENERATE_US, out).ok_or(status::INTERNAL)?;
                }
                if let (Some(started), Some(s)) = (Started::parse(&out[..n]), &mut self.slots[i]) {
                    s.session = Some(started.session);
                    s.session_model = model;
                }
                Ok(n)
            }
            Request::Next => {
                let session = session.ok_or(NO_SESSION)?;
                let n = self
                    .infer(&InferRequest::Next { session }, INFER_US, out)
                    .ok_or(status::INTERNAL)?;
                // Ended, or refused: the session is over either way.
                let more = Tokens::parse(&out[..n]).is_some_and(|t| t.stop.is_none());
                if !more {
                    if let Some(s) = &mut self.slots[i] {
                        s.session = None;
                    }
                }
                Ok(n)
            }
            Request::CancelInfer => {
                if session.is_none() {
                    return Err(NO_SESSION);
                }
                self.cancel_session(i);
                Ok(done(out))
            }
            Request::DataPut { name, len } => {
                let allowed = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&Permission::DataWrite, now));
                if !allowed {
                    return Err(status::NO_ACCESS);
                }
                if len > agents::MAX_DATA {
                    return Err(status::TOO_LARGE);
                }
                if len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                let mut bytes = alloc::vec![0u8; len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(0, &mut bytes);
                }
                let path = data_path(limits.entry.name, name);
                self.store
                    .write(&path, &bytes)
                    .map_err(|_| status::INTERNAL)?;
                Ok(done(out))
            }
            Request::DataGet { name } => {
                let allowed = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&Permission::DataRead, now));
                if !allowed {
                    return Err(status::NO_ACCESS);
                }
                let path = data_path(limits.entry.name, name);
                let bytes = self
                    .store
                    .read(&path)
                    .map_err(|_| status::INTERNAL)?
                    .ok_or(status::NOT_FOUND)?;
                if bytes.len() > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                if let Some(b) = self.slots[i].as_ref().and_then(|s| s.buffer.as_ref()) {
                    b.write_bytes(0, &bytes);
                }
                out[0] = status::OK;
                out[1..5].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
                Ok(5)
            }
            Request::Info => self.info(out).ok_or(status::INTERNAL),
            Request::Revoke { .. } => Err(status::NO_ACCESS),
            Request::Submit { .. }
            | Request::Status { .. }
            | Request::Cancel { .. }
            | Request::Forget { .. } => Err(status::NO_ACCESS),
            Request::Attach { .. } => Err(status::BAD_REQUEST),
        }
    }

    /// `REVOKE` from `trust`: takes `permission` from every running task
    /// of agent `name`, ends a session opened with it, and tells `trust`.
    fn revoke(&mut self, name: &[u8], permission: Permission) {
        let mut outcome = trust::Outcome::NoAgent;
        for i in 0..SLOTS {
            let Some(s) = self.slots[i].as_mut() else {
                continue;
            };
            let named = self
                .tasks
                .find(s.task)
                .is_some_and(|t| self.tasks.list[t].agent == name);
            if !named {
                continue;
            }
            if outcome == trust::Outcome::NoAgent {
                outcome = trust::Outcome::NotHeld;
            }
            if s.grants.revoke(&permission) {
                outcome = trust::Outcome::Revoked;
                self.revoked.push((s.task, permission));
                if permission == Permission::Model(s.session_model) {
                    self.cancel_session(i);
                }
            }
        }
        let mut msg = [0u8; 64];
        let answer = trust::Request::Revoked {
            outcome,
            name,
            permission,
        };
        // `trust` waits in `receive` almost always; it is never waited on
        // for long.
        if let Some(n) = trust::encode(&answer, &mut msg) {
            for _ in 0..100 {
                if try_send(TRUST, &msg[..n]).is_ok() {
                    break;
                }
                pharos_user::sleep(10_000);
            }
        }
    }

    fn control_buffer(&self, badge: u32) -> Option<&Mapped> {
        self.controls
            .iter()
            .flatten()
            .find(|c| c.0 == badge)
            .map(|c| &c.1)
    }

    /// One request from control client `badge`.
    fn control(&mut self, badge: u32, req: Request<'_>, out: &mut [u8; 256]) -> Result<usize, u8> {
        let buffer_len = self.control_buffer(badge).map_or(0, Mapped::len);
        match req {
            Request::Submit {
                name,
                input_len,
                deps,
            } => {
                if self.limits(name).is_none() {
                    return Err(status::NOT_FOUND);
                }
                if input_len > MAX_INPUT {
                    return Err(status::TOO_LARGE);
                }
                if input_len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                let mut input = alloc::vec![0u8; input_len as usize];
                if let Some(b) = self.control_buffer(badge) {
                    b.read_bytes(0, &mut input);
                }
                let id = self
                    .tasks
                    .submit(&mut self.store, name, deps.as_slice(), &input)
                    .map_err(store_error)?;
                agents::submitted(id, out).ok_or(status::INTERNAL)
            }
            Request::Status { task } => {
                let t = &self.tasks.list[self.tasks.find(task).ok_or(status::NOT_FOUND)?];
                if t.result.len() > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                if let Some(b) = self.control_buffer(badge) {
                    b.write_bytes(0, &t.result);
                }
                TaskStatus {
                    state: t.state,
                    attempts: t.attempts,
                    result_len: t.result.len() as u32,
                }
                .encode(out)
                .ok_or(status::INTERNAL)
            }
            Request::Cancel { task } => {
                let at = self.tasks.find(task).ok_or(status::NOT_FOUND)?;
                if self.tasks.list[at].ended() {
                    return Ok(done(out));
                }
                self.tasks
                    .finish(&mut self.store, at, State::Cancelled, b"cancelled")
                    .map_err(store_error)?;
                if let Some(slot) = self
                    .slots
                    .iter()
                    .position(|s| s.as_ref().is_some_and(|s| s.task == task))
                {
                    self.end(slot, Ending::Cancelled);
                }
                self.event(task, b"cancelled", None);
                Ok(done(out))
            }
            Request::Forget { task } => {
                self.tasks
                    .forget(&mut self.store, task)
                    .map_err(store_error)?;
                Ok(done(out))
            }
            Request::Info => self.info(out).ok_or(status::INTERNAL),
            Request::Attach { .. } => Err(status::BAD_REQUEST),
            _ => Err(status::NO_ACCESS),
        }
    }

    /// Handles one `call`; writes the reply (status first) into `out`.
    fn handle(&mut self, msg: &[u8], badge: u32, out: &mut [u8; 256]) -> usize {
        let req = match parse(msg) {
            Ok(req) => req,
            Err(refused) => return refusal(refused, VERSION, out),
        };
        let result = match agent_slot(badge) {
            Some(i) => self.agent(i, req, out),
            None if badge >= CONTROL => self.control(badge, req, out),
            None if badge == agents::TRUST => match req {
                Request::Revoke { name, permission } => {
                    self.revoke(name, permission);
                    Ok(done(out))
                }
                _ => Err(status::NO_ACCESS),
            },
            None => Err(status::NO_ACCESS),
        };
        match result {
            Ok(n) => n,
            Err(code) => {
                out[0] = code;
                1
            }
        }
    }
}

/// Attaches the prompt buffer at the inference service: at start, and
/// again after the service restarted and lost it (#100).
fn attach_prompt(buffer: &Mapped) -> bool {
    mem_share(buffer.addr(), infer::MAX_BUFFER).is_ok_and(|memory| {
        let mut msg = [0u8; 16];
        let len = infer::MAX_BUFFER;
        let sent = infer::encode(&InferRequest::Attach { len }, &mut msg)
            .is_some_and(|n| send(INFER, &msg[..n], memory, READ, 0).is_ok());
        let _ = delete(memory);
        sent
    })
}

fn main(arg: u64) -> u64 {
    let table: &'static [Entry] = match arg {
        0 => BOOT,
        1 => TEST,
        _ => &[],
    };
    let Ok(reply) = endpoint_create() else {
        return 1;
    };
    // The runtime's prompt buffer at the inference service.
    let Ok(infer_buffer) = mem_map_buffer(infer::MAX_BUFFER) else {
        return 2;
    };
    if !attach_prompt(&infer_buffer) {
        return 3;
    }
    let mut agents = Vec::new();
    for e in table {
        match load(e, table) {
            Ok(l) => {
                say(&[b"agents: ", e.name, b" manifest accepted"]);
                agents.push(l);
            }
            Err(w) => say(&[b"agents: ", e.name, b" manifest refused: ", w]),
        }
    }
    // The runtime's buffer at the storage service, for task files.
    let Ok(buffer) = mem_map_buffer(STORE_BUFFER) else {
        return 5;
    };
    let mut store = Store { buffer, reply };
    if !store.attach() {
        return 6;
    }
    let attempts = |name: &[u8]| {
        agents
            .iter()
            .find(|l| l.entry.name == name)
            .map(|l| l.attempts)
    };
    let Ok((tasks, found)) = Tasks::load(&mut store, attempts) else {
        say(&[b"agents: cannot read the task store"]);
        return 7;
    };
    let mut d = [[0u8; 20]; 3];
    let [a, b, c] = &mut d;
    say(&[
        b"agents: ",
        decimal(found.tasks as u64, a),
        b" tasks recovered, ",
        decimal(found.recovered as u64, b),
        b" were running, ",
        decimal(found.unreadable as u64, c),
        b" unreadable",
    ]);
    let mut r = Runtime {
        agents,
        tasks,
        store,
        slots: Default::default(),
        controls: Default::default(),
        infer_buffer,
        reply,
        revoked: Vec::new(),
    };
    // `trust`'s way to send `REVOKE`, badged so only it is served as `trust`.
    let mut msg = [0u8; 8];
    let channel = trust::encode(&trust::Request::Channel, &mut msg)
        .is_some_and(|n| send(TRUST, &msg[..n], SERVICE, SEND, agents::TRUST).is_ok());
    if !channel {
        return 8;
    }
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 4;
    }
    let mut msg = [0u8; 256];
    loop {
        // A refused retry is tried again within a second.
        let stranded = r.retry_stranded();
        r.start_pending();
        let wait = r.check_deadlines();
        let wait = if stranded { wait.min(1_000_000) } else { wait };
        match receive_timeout(SERVICE, &mut msg, wait) {
            Ok(Received::Notification(bits)) => {
                for i in 0..SLOTS {
                    if bits & 1 << i != 0 {
                        r.ended(i);
                    }
                }
            }
            Ok(Received::Message { len, cap, badge }) => {
                let msg = &msg[..len.min(256)];
                if let Ok(Request::Attach { len }) = parse(msg) {
                    if cap != 0 {
                        r.attach(badge, cap, len);
                    }
                    continue;
                }
                let mut out = [0u8; 256];
                let n = r.handle(msg, badge, &mut out);
                if cap != 0 {
                    let _ = try_send(cap, &out[..n]);
                    let _ = delete(cap);
                }
            }
            _ => {}
        }
    }
}
