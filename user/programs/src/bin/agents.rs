//! The agent runtime (#98, agents.md): starts agents for tasks, watches
//! them, and serves their requests. Unprivileged, and not trusted for the
//! emergency stop: `trust` holds `STOP` on it and on every agent.
//!
//! Handles: 1 the console, 2 its endpoint (`RECEIVE`, `SEND`, `GRANT`, to
//! hand agents a badged `SEND`), 3 `init`'s report endpoint, 4 the
//! read-only filesystem (agent programs and manifests), 5 the inference
//! service (`SEND`, badged), 6 `trust` (`SEND`, badged as the runtime), 7
//! the storage service, badged for namespace `agents` (read-write), 8 the
//! audit service (`SEND`, client 3; #108), 9 the network service (`SEND`,
//! badged with the runtime's UDP port; #109). The
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
//!
//! Approvals (#106): an agent may `ASK` for what its policy entry lists as
//! askable. The runtime asks `trust` (`APPROVE`, structured fields only),
//! answers `PENDING` until the user's `yes` or `no` comes back (`ANSWER`)
//! or the timeout passes (60 s; 5 s with the test table), and tells `trust`
//! how it ended (`RESOLVED`). At most 4 wait at once. An approval holds for
//! that task only; a refusal too, so the agent cannot ask again.
//!
//! Audit (#108): handle 8 is `SEND` on the audit service (client 3). Every
//! grant and approval is recorded before it is given, and not given if the
//! record fails. Each consequential action (inference, writing the agent's
//! files, submitting and cancelling tasks) is preceded by an `INTENT`
//! record and acted on only once it is stored, else refused with
//! `NO_AUDIT`; an `OUTCOME` record follows. Revocations, expiries, and
//! refusals always take effect and are recorded when the trail can be.
//!
//! Networking (#109): an agent sends a datagram (`SEND_TO`) only to a
//! destination it holds `net` for; each send is audited like the other
//! consequential actions, and goes out on the runtime's own port. The
//! network service lets that port reach only what `init` listed: the union
//! of the policy table's destinations. `RECEIVE_FROM` polls the service
//! and keeps each datagram for every agent that sent to its source; it is
//! delivered only if the agent still holds that grant when it takes it.
//!
//! Refusals (#110): an agent's refused requests are recorded once per kind
//! per attempt (malformed or out of bounds, a missing grant, a request not
//! for agents, a permission not askable), each with its first example, and
//! the attempt's total when it ends, so a flooding agent cannot fill the
//! trail.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_programs::budgets::{self, Bucket, GroupUse, Over, Usage};
use pharos_programs::grants::Grants;
use pharos_programs::tasks::{self, Begin, Files, StoreFailed, Tasks};
use pharos_proto::agents::{
    self, Asked, Assigned, Begun, CHECKPOINT_AT, CONTROL, MAX_BUFFER, MAX_CHECKPOINT, MAX_INPUT,
    MAX_RESULT, MAX_RUNNING, NAME, NO_AUDIT, NO_SESSION, Request, SLOTS, State, TaskStatus,
    VERSION, agent_slot, parse,
};
use pharos_proto::audit::{self, Entry as Record, Kind, action, outcome};
use pharos_proto::infer::{self, Record as InferRecord, Request as InferRequest, Started, Tokens};
use pharos_proto::manifest::{self, Budget, Data, Dest, Entry, Group, Why};
use pharos_proto::net::{self, Request as NetRequest};
use pharos_proto::permission::Permission;
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{Info, refusal, status, trust};
use pharos_user::Limits as SpawnLimits;
use pharos_user::rights::{READ, SEND, STOP, WAIT, WRITE};
use pharos_user::{
    Class, Grant, Handle, Mapped, Received, Status, Usage as Use, call_timeout, debug_write,
    delete, endpoint_create, mem_map_buffer, mem_map_cap, mem_share, mem_unmap, open,
    process_status, process_stop, process_usage, read, receive_timeout, send, spawn_with, try_send,
    uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const ROOT: Handle = 4;
const INFER: Handle = 5;
const TRUST: Handle = 6;
const STORE: Handle = 7;
const AUDIT: Handle = 8;
const NET: Handle = 9;
/// How long the network service may take to answer.
const NET_US: u64 = 1_000_000;
/// Datagrams kept for one agent; the oldest goes first.
const MAX_INBOX: usize = 4;
/// The host echo server (`cargo xtask`, networking.md), through slirp.
const HOST_ECHO: Dest = ([10, 0, 2, 2], 47_000);

/// Kinds of refused agent requests, recorded once each per attempt.
mod refusal {
    pub const MALFORMED: u16 = 1;
    pub const NO_GRANT: u16 = 2;
    pub const NOT_FOR_AGENTS: u16 = 4;
    pub const NOT_ASKABLE: u16 = 8;
    /// Over a budget (D-022, #116), one kind per resource.
    pub const OVER_TOKENS: u16 = 16;
    pub const OVER_NET_SENDS: u16 = 32;
    pub const OVER_NET_BYTES: u16 = 64;
    pub const OVER_DATA: u16 = 128;
    pub const OVER_GROUP_TOKENS: u16 = 256;
    pub const OVER_GROUP_NET: u16 = 512;
}
/// How often the runtime reads a running agent's CPU time, at most.
const CPU_CHECK_US: u64 = 100_000;
/// A stalled service is asked again (`INFO`) at most this often, and
/// given this long to answer (#117).
const PROBE_EVERY_US: u64 = 1_000_000;
const PROBE_US: u64 = 50_000;

/// A service the runtime calls (#117, resources.md): after one call times
/// out it is stalled, and requests that need it are answered at once
/// instead of each waiting its timeout, so it holds the runtime for one
/// timeout and then at most [`PROBE_US`] a second.
#[derive(Default)]
struct Health {
    stalled: core::cell::Cell<bool>,
    probe_at: core::cell::Cell<u64>,
}

impl Health {
    /// `BUSY` while stalled and not yet due to be asked again.
    fn ready(&self) -> Result<(), u8> {
        if self.stalled.get() && uptime() < self.probe_at.get() {
            Err(status::BUSY)
        } else {
            Ok(())
        }
    }

    /// `call_timeout` on `endpoint`, refused at once (`WOULD_BLOCK`) while
    /// stalled, except for one `INFO` a second that ends the stall if
    /// answered.
    fn call(
        &self,
        endpoint: Handle,
        msg: &[u8],
        reply: Handle,
        out: &mut [u8],
        timeout: u64,
    ) -> Result<Received, pharos_user::Error> {
        if self.stalled.get() {
            let now = uptime();
            if now < self.probe_at.get() {
                return Err(pharos_user::Error::WouldBlock);
            }
            self.probe_at.set(now + PROBE_EVERY_US);
            // Any answer, even a refusal, shows the service is serving.
            let info = [1, pharos_proto::op::INFO];
            let mut answer = [0u8; 256];
            if call_timeout(endpoint, &info, reply, &mut answer, PROBE_US).is_err() {
                return Err(pharos_user::Error::WouldBlock);
            }
            self.stalled.set(false);
        }
        let r = call_timeout(endpoint, msg, reply, out, timeout);
        if r == Err(pharos_user::Error::TimedOut) {
            self.stalled.set(true);
            self.probe_at.set(uptime() + PROBE_EVERY_US);
        }
        r
    }
}
/// How long an audit record may take before the action is refused.
const AUDIT_US: u64 = 2_000_000;
/// The runtime's buffer at the storage service: the largest task file.
const STORE_BUFFER: u64 = 128 << 10;
const STORE_US: u64 = 10_000_000;

/// How long a call to the inference service may take; `GENERATE` may load
/// a model first.
const GENERATE_US: u64 = 60_000_000;
const INFER_US: u64 = 10_000_000;
/// How long the user has to answer an approval request: boot table, test
/// table.
const APPROVE_US: [u64; 2] = [60_000_000, 5_000_000];
/// Handles each agent may hold (D-022): its runtime endpoint, endpoints and
/// buffers of its own. The runtime's own budget from `init` has room for
/// [`SLOTS`] of these.
pub const AGENT_HANDLES: u16 = 16;
/// Most approval requests waiting at once.
const MAX_PENDING: usize = 4;
/// Control clients with an attached buffer.
const MAX_CONTROLS: usize = 4;

const BOOT: &[Entry] = &[];

/// The `budgets` test kernel's agents (#116): `spender` within its own
/// budget, `grouper` within its group's minute, `hog` over its CPU time,
/// and `pair` and `big` held by their groups' attempts and pages.
const BUDGETS: &[Entry] = &[
    budget_entry(
        b"spender",
        Budget {
            cpu_ms: u32::MAX,
            tokens: 40,
            net_sends: 2,
            net_bytes: 64,
            data_kb: 1,
            rate: u32::MAX,
            group: b"spend",
        },
        64,
    ),
    budget_entry(
        b"grouper",
        Budget {
            group: b"tight",
            ..Budget::UNLIMITED
        },
        64,
    ),
    budget_entry(
        b"hog",
        Budget {
            cpu_ms: 300,
            ..Budget::UNLIMITED
        },
        64,
    ),
    budget_entry(
        b"pair",
        Budget {
            group: b"pair",
            ..Budget::UNLIMITED
        },
        64,
    ),
    budget_entry(
        b"big",
        Budget {
            group: b"heavy",
            ..Budget::UNLIMITED
        },
        256,
    ),
    FAIRNESS[0],
    FAIRNESS[1],
    FAIRNESS[2],
    FAIRNESS[3],
    // Runs while the runner types `usage` on the trusted console (#119).
    budget_entry(
        b"idler",
        Budget {
            group: b"heavy",
            ..Budget::UNLIMITED
        },
        64,
    ),
];

/// The `fairness` test kernel's agents (#117), in the same table:
/// `flooder` and `ticker` beside a stalled network service, `rater` at 2
/// requests a second, and `queuer`, which may ask for models 3 and 4.
const FAIRNESS: [Entry; 4] = [
    budget_entry(b"flooder", Budget::UNLIMITED, 64),
    budget_entry(b"ticker", Budget::UNLIMITED, 64),
    budget_entry(
        b"rater",
        Budget {
            rate: 2,
            ..Budget::UNLIMITED
        },
        64,
    ),
    Entry {
        ask_models: 1 << 3 | 1 << 4,
        ..budget_entry(b"queuer", Budget::UNLIMITED, 64)
    },
];

const BUDGET_GROUPS: &[Group] = &[
    Group {
        name: b"spend",
        agents: 4,
        pages: 1 << 12,
        tokens_per_min: 1000,
        net_bytes_per_min: 1000,
    },
    Group {
        name: b"tight",
        agents: 4,
        pages: 1 << 12,
        tokens_per_min: 30,
        net_bytes_per_min: 48,
    },
    Group {
        name: b"pair",
        agents: 1,
        pages: 1 << 12,
        tokens_per_min: u32::MAX,
        net_bytes_per_min: u32::MAX,
    },
    Group {
        name: b"heavy",
        agents: 4,
        pages: 300,
        tokens_per_min: u32::MAX,
        net_bytes_per_min: u32::MAX,
    },
];

/// A `budgets` test entry: `bin/testagent` with model 2, its own files,
/// and the host echo server, one attempt.
const fn budget_entry(name: &'static [u8], budget: Budget, pages: u32) -> Entry {
    Entry {
        name,
        program: b"bin/testagent",
        pages,
        models: 1 << 2,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 30_000,
        data: Data::Write,
        ask_models: 0,
        ask_data: Data::None,
        net: &[HOST_ECHO],
        ask_net: &[],
        budget,
    }
}

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
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
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
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
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
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
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
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
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
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
    },
    // Gets nothing; may ask for model 2 and data access (#106).
    Entry {
        name: b"asker",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 1 << 2,
        ask_data: Data::Write,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
    },
    // The `agents_net` kernel's (#109): gets the host echo server, may
    // ask for the port after it.
    Entry {
        name: b"netter",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[HOST_ECHO],
        ask_net: &[(HOST_ECHO.0, HOST_ECHO.1 + 1)],
        budget: Budget::UNLIMITED,
    },
    // The same grant as `netter`, which the user's `revoke netter` leaves.
    Entry {
        name: b"listener",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[HOST_ECHO],
        ask_net: &[],
        budget: Budget::UNLIMITED,
    },
    // The `hostile` kernel's (#110): its own files, and five models to ask
    // for, one more than the approval queue holds.
    Entry {
        name: b"hostile",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::Write,
        ask_models: 1 << 3 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7,
        ask_data: Data::Write,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
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
    net: manifest::Net,
}

/// The storage service as [`Files`], through the runtime's buffer there.
struct Store {
    buffer: Mapped,
    reply: Handle,
    health: Health,
}

impl Store {
    /// The size of file `path` in bytes; 0 if there is none.
    fn size(&self, path: &[u8]) -> Result<u64, StoreFailed> {
        let mut out = [0u8; 256];
        match self.call(&StoreRequest::Stat { path }, &mut out)? {
            StoreStatus::NotFound => Ok(0),
            StoreStatus::Ok => Ok(u64_at(&out, 2)),
            _ => Err(StoreFailed),
        }
    }

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
        match self
            .health
            .call(STORE, &msg[..n], self.reply, out, STORE_US)
        {
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

/// Sends `req` to `trust` without blocking, trying for at most 1 s:
/// `trust` waits in `receive` almost always, and is never waited on long.
fn tell_trust(req: &trust::Request<'_>) -> bool {
    let mut msg = [0u8; 96];
    let Some(n) = trust::encode(req, &mut msg) else {
        return false;
    };
    for _ in 0..100 {
        if try_send(TRUST, &msg[..n]).is_ok() {
            return true;
        }
        pharos_user::sleep(10_000);
    }
    false
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
    /// Over its attempt's `cpu_ms` (D-022): a failed attempt.
    OverCpu,
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
    /// The new tokens it asked for, charged until the session ends (#118).
    session_new: u16,
    ending: Option<Ending>,
    grants: Grants,
    /// Destinations it sent to, and datagrams from them kept for it.
    peers: Vec<Dest>,
    inbox: Vec<(Dest, Vec<u8>)>,
    /// Refused requests this attempt, and the kinds already recorded.
    refused: u32,
    noted: u16,
    /// What this attempt has used (#116).
    usage: Usage,
    /// Its requests over time, and the one held past its rate with its
    /// reply capability (#117).
    bucket: Bucket,
    held: Option<(Vec<u8>, Handle)>,
    /// Requests served this attempt (#119).
    requests: u32,
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
    /// Approval requests waiting for the user (#106).
    pending: Vec<Pending>,
    next_request: u16,
    approve_us: u64,
    /// Approved for a task (and until when), kept for its restarts.
    approved: Vec<(u32, Permission, Option<u64>)>,
    /// Refused, or not answered, for a task: not asked again.
    refused: Vec<(u32, Permission)>,
    /// The policy table's groups, and what each has used this minute.
    groups: &'static [Group],
    group_use: Vec<GroupUse>,
    /// The services it calls besides the store (#117).
    infer_health: Health,
    audit_health: Health,
    net_health: Health,
}

struct Pending {
    number: u16,
    task: u32,
    permission: Permission,
    for_ms: u32,
    deadline: u64,
}

/// True if `entry` lets its agent ask for `p`.
fn askable(entry: &Entry, p: &Permission) -> bool {
    match *p {
        Permission::Model(n) => n <= 31 && entry.ask_models & 1 << n != 0,
        Permission::DataRead => entry.ask_data >= Data::Read,
        Permission::DataWrite => entry.ask_data == Data::Write,
        Permission::Net { addr, port } => entry.ask_net.contains(&(addr, port)),
    }
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
        net: m.net,
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
        match self
            .infer_health
            .call(INFER, &msg[..n], self.reply, out, timeout)
        {
            Ok(Received::Message { len, .. }) if len >= 1 => Some(len.min(256)),
            _ => None,
        }
    }

    fn cancel_session(&mut self, slot: usize) {
        if let Some(session) = self.slots[slot].as_mut().and_then(|s| s.session.take()) {
            let _ = self.infer(&InferRequest::Cancel { session }, INFER_US, &mut [0; 256]);
            self.session_ended(slot, session);
        }
    }

    /// Gives slot `i`'s attempt and group back `n` tokens charged but not
    /// used (#118).
    fn refund(&mut self, i: usize, n: u64) {
        let Some(budget) = self.slots[i]
            .as_ref()
            .and_then(|s| self.tasks.find(s.task))
            .and_then(|t| self.limits(&self.tasks.list[t].agent))
            .map(|l| l.entry.budget)
        else {
            return;
        };
        let g = self
            .groups
            .iter()
            .position(|g| !budget.group.is_empty() && g.name == budget.group);
        if let Some(s) = self.slots[i].as_mut() {
            s.usage.refund_tokens(g.map(|g| &mut self.group_use[g]), n);
        }
    }

    /// Slot `i`'s `session` ended: the new tokens it did not generate come
    /// back, from the service's record.
    fn session_ended(&mut self, i: usize, session: u32) {
        let asked = self.slots[i].as_ref().map_or(0, |s| s.session_new);
        let mut out = [0u8; 256];
        let generated = self
            .infer(&InferRequest::Result { session }, INFER_US, &mut out)
            .and_then(|n| InferRecord::parse(&out[..n]))
            .map(|r| r.generated);
        if let Some(generated) = generated {
            self.refund(i, u64::from(asked).saturating_sub(u64::from(generated)));
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
            // Each group's running attempts and their pages (D-022).
            let mut in_group = alloc::vec![(0u32, 0u64); self.groups.len()];
            for s in self.slots.iter().flatten() {
                let Some(l) = self
                    .tasks
                    .find(s.task)
                    .and_then(|t| self.limits(&self.tasks.list[t].agent))
                else {
                    continue;
                };
                if let Some(g) = self
                    .groups
                    .iter()
                    .position(|g| g.name == l.entry.budget.group)
                {
                    in_group[g].0 += 1;
                    in_group[g].1 += u64::from(l.pages);
                }
            }
            let (agents, groups) = (&self.agents, self.groups);
            let runnable = |t: &tasks::Task| {
                agents
                    .iter()
                    .find(|l| l.entry.name == t.agent)
                    .is_some_and(|l| {
                        match groups.iter().position(|g| g.name == l.entry.budget.group) {
                            Some(g) => {
                                budgets::room(&groups[g], in_group[g].0, in_group[g].1, l.pages)
                            }
                            None => true,
                        }
                    })
            };
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
            let agent = SpawnLimits {
                pages: limits.pages,
                class: Class::Agents,
                processes: 0,
                handles: AGENT_HANDLES,
            };
            let p = spawn_with(file, 0, &[grant], notify, agent);
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
            session_new: 0,
            ending: None,
            grants: Grants::default(),
            peers: Vec::new(),
            inbox: Vec::new(),
            refused: 0,
            noted: 0,
            usage: Usage::default(),
            bucket: Bucket::full(limits.entry.budget.rate, now),
            held: None,
            requests: 0,
        });
        // Every grant is recorded before it is given; none is given if a
        // record fails (#108).
        let mut g = Grants::new(limits.models, limits.data, limits.net.as_slice());
        for (_, p, until) in self.approved.iter().filter(|(t, ..)| *t == id) {
            g.add(*p, *until);
        }
        for (_, p) in self.revoked.iter().filter(|(t, _)| *t == id) {
            g.revoke(p);
        }
        let recorded = g.list().iter().all(|grant| {
            self.permission_event(
                limits.entry.name,
                id,
                action::GRANT,
                grant.permission,
                outcome::OK,
                b"",
            )
        });
        if recorded {
            if let Some(s) = self.slots[slot].as_mut() {
                s.grants = g;
            }
        }
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
        // Grants past their deadline: gone (as `allows` already treats
        // them), and recorded.
        for i in 0..SLOTS {
            let Some(s) = self.slots[i].as_mut() else {
                continue;
            };
            let task = s.task;
            let gone = s.grants.expire(now);
            if let Some(u) = s.grants.list().iter().filter_map(|g| g.until).min() {
                wait = wait.min(u.saturating_sub(now));
            }
            if !gone.is_empty() {
                let agent = self.agent_of(task);
                for p in gone {
                    self.permission_event(&agent, task, action::EXPIRE, p, outcome::OK, b"");
                }
            }
        }
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
            let cpu_ms = l.entry.budget.cpu_ms;
            let cpu = (cpu_ms != u32::MAX)
                .then(|| {
                    self.slots[i]
                        .as_ref()
                        .map(|s| process_usage(s.process, Use::CpuMicros))
                })
                .flatten();
            if now >= deadline {
                self.end(i, Ending::Hung);
                self.event(id, b"hung", None);
            } else if cpu.is_some_and(|c| c.is_ok_and(|us| us > u64::from(cpu_ms) * 1000)) {
                self.end(i, Ending::OverCpu);
                self.event(id, b"over cpu", None);
                let agent = self.agent_of(id);
                self.refusal_event(&agent, id, None, b"over cpu");
            } else {
                wait = wait.min(deadline - now);
                if cpu.is_some() {
                    wait = wait.min(CPU_CHECK_US);
                }
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
        // What the attempt used, recorded as it ends (#119).
        let cpu_ms = process_usage(s.process, Use::CpuMicros).unwrap_or(0) / 1000;
        let _ = delete(s.process);
        if let Some((_, cap)) = s.held {
            let _ = delete(cap);
        }
        if let Some(b) = s.buffer {
            unmap(b);
        }
        let id = s.task;
        let mut detail = Vec::new();
        for (word, v) in [
            (&b"cpu "[..], cpu_ms),
            (b" tok ", s.usage.tokens),
            (b" net ", s.usage.net_sends),
            (b"/", s.usage.net_bytes),
            (b" req ", u64::from(s.requests)),
        ] {
            let mut d = [0u8; 20];
            detail.extend_from_slice(word);
            detail.extend_from_slice(decimal(v, &mut d));
        }
        let agent = self.agent_of(id);
        self.audit(&Record {
            kind: Kind::Event,
            refers: 0,
            actor: &agent,
            task: id,
            attempt: self.attempt(id),
            action: action::USAGE,
            permission: None,
            service: b"",
            outcome: outcome::OK,
            detail: &detail,
        });
        if s.refused > 0 {
            let mut d = [0u8; 20];
            let mut detail = Vec::from(decimal(u64::from(s.refused), &mut d));
            detail.extend_from_slice(b" requests refused");
            let agent = self.agent_of(id);
            self.refusal_event(&agent, id, None, &detail);
        }
        // Its open requests end with it.
        let open: Vec<u16> = self
            .pending
            .iter()
            .filter(|q| q.task == id)
            .map(|q| q.number)
            .collect();
        for number in open {
            self.resolve(number, trust::Resolution::Ended);
        }
        match (s.ending, status) {
            (Some(Ending::Finished | Ending::Cancelled), _) => {}
            (Some(Ending::Hung | Ending::OverCpu), _) => self.retry(id),
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
        s.requests = s.requests.saturating_add(1);
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
                self.infer_health.ready()?;
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
                let name = limits.entry.name;
                let infer_permission = Some(Permission::Model(model));
                // The prompt's bytes bound its tokens; refunded when the
                // service reports the real count (#118).
                let tokens = u64::from(prompt_len) + u64::from(max_new);
                let budget = limits.entry.budget;
                self.charge(i, &budget, infer_permission, |u, g| {
                    u.tokens(&budget, g, now, tokens)
                })?;
                let seq =
                    match self.intent(name, id, action::INFER, infer_permission, b"infer", b"") {
                        Ok(seq) => seq,
                        Err(code) => {
                            self.refund(i, tokens);
                            return Err(code);
                        }
                    };
                let mut n = self.infer(&req, GENERATE_US, out);
                if n.is_some() && out[0] == status::NO_BUFFER && attach_prompt(&self.infer_buffer) {
                    n = self.infer(&req, GENERATE_US, out);
                }
                let started = n.and_then(|n| Started::parse(&out[..n]));
                self.outcome(seq, name, id, action::INFER, started.is_some(), b"");
                // The prompt's bytes were charged for its tokens (#118).
                let unused = match started {
                    Some(st) => u64::from(prompt_len).saturating_sub(u64::from(st.prompt_tokens)),
                    None => tokens,
                };
                self.refund(i, unused);
                let n = n.ok_or(status::INTERNAL)?;
                if let (Some(started), Some(s)) = (started, &mut self.slots[i]) {
                    s.session = Some(started.session);
                    s.session_model = model;
                    s.session_new = max_new;
                }
                Ok(n)
            }
            Request::Next => {
                let session = session.ok_or(NO_SESSION)?;
                self.infer_health.ready()?;
                let n = self
                    .infer(&InferRequest::Next { session }, INFER_US, out)
                    .ok_or(status::INTERNAL)?;
                // Ended, or refused: the session is over either way.
                let more = Tokens::parse(&out[..n]).is_some_and(|t| t.stop.is_none());
                if !more {
                    if let Some(s) = &mut self.slots[i] {
                        s.session = None;
                    }
                    self.session_ended(i, session);
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
                self.store.health.ready()?;
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
                let agent = limits.entry.name;
                let path = data_path(agent, name);
                let write = Some(Permission::DataWrite);
                let budget = limits.entry.budget;
                if budget.data_kb != u32::MAX {
                    let (stored, old) = self.data_stored(agent, name)?;
                    let new = u64::from(len);
                    self.charge(i, &budget, write, |_, _| {
                        budgets::data_fits(&budget, stored, old, new)
                    })?;
                }
                let seq = self.intent(agent, id, action::DATA_WRITE, write, b"store", name)?;
                let written = self.store.write(&path, &bytes).is_ok();
                self.outcome(seq, agent, id, action::DATA_WRITE, written, name);
                if !written {
                    return Err(status::INTERNAL);
                }
                Ok(done(out))
            }
            Request::DataGet { name } => {
                let allowed = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&Permission::DataRead, now));
                if !allowed {
                    return Err(status::NO_ACCESS);
                }
                self.store.health.ready()?;
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
            Request::SendTo { addr, port, len } => {
                let p = Permission::Net { addr, port };
                let allowed = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&p, now));
                if !allowed {
                    return Err(status::NO_ACCESS);
                }
                self.net_health.ready()?;
                if len > agents::MAX_DATAGRAM {
                    return Err(status::TOO_LARGE);
                }
                if len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                let mut payload = alloc::vec![0u8; len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(0, &mut payload);
                }
                let req = NetRequest::Send {
                    ip: addr,
                    port,
                    payload: &payload,
                };
                let mut msg = [0u8; 256];
                let n = net::encode(&req, &mut msg).ok_or(status::INTERNAL)?;
                let agent = limits.entry.name;
                let budget = limits.entry.budget;
                self.charge(i, &budget, Some(p), |u, g| {
                    u.send(&budget, g, now, u64::from(len))
                })?;
                let seq = self.intent(agent, id, action::NET_SEND, Some(p), net::NAME, b"")?;
                // The request is sent from the reply buffer too.
                let mut reply = [0u8; 256];
                let code =
                    match self
                        .net_health
                        .call(NET, &msg[..n], self.reply, &mut reply, NET_US)
                    {
                        Ok(Received::Message { len, .. }) if len >= 1 => reply[0],
                        _ => status::INTERNAL,
                    };
                self.outcome(seq, agent, id, action::NET_SEND, code == net::OK, b"");
                if code != net::OK {
                    return Err(code);
                }
                if let Some(s) = self.slots[i].as_mut() {
                    if !s.peers.contains(&(addr, port)) {
                        s.peers.push((addr, port));
                    }
                }
                Ok(done(out))
            }
            Request::ReceiveFrom => {
                // Only with a destination held (M3.4 review F1): else any
                // agent could make the runtime wait on the network service.
                let (net, sent) = self.slots[i].as_ref().map_or((false, false), |s| {
                    let net = s.grants.list().iter().any(|g| {
                        matches!(g.permission, Permission::Net { .. })
                            && g.until.is_none_or(|u| now < u)
                    });
                    (net, !s.peers.is_empty())
                });
                if !net {
                    return Err(status::NO_ACCESS);
                }
                if sent {
                    self.poll_net();
                }
                let s = self.slots[i].as_mut().ok_or(NO_SESSION)?;
                while !s.inbox.is_empty() {
                    let ((addr, port), bytes) = s.inbox.remove(0);
                    // Revoked or expired since it arrived: dropped.
                    if !s.grants.allows(&Permission::Net { addr, port }, now) {
                        continue;
                    }
                    let b = s.buffer.as_ref().filter(|b| b.len() >= bytes.len());
                    let b = b.ok_or(status::NO_BUFFER)?;
                    b.write_bytes(0, &bytes);
                    let len = bytes.len() as u32;
                    return agents::Datagram { addr, port, len }
                        .encode(out)
                        .ok_or(status::INTERNAL);
                }
                Err(status::NOT_FOUND)
            }
            Request::Info => self.info(out).ok_or(status::INTERNAL),
            Request::Ask { permission, for_ms } => {
                let asked = self.ask(i, id, limits.entry, permission, for_ms);
                if asked == Asked::Refused && !askable(limits.entry, &permission) {
                    self.note(i, refusal::NOT_ASKABLE, Some(permission));
                }
                asked.encode(out).ok_or(status::INTERNAL)
            }
            Request::Revoke { .. } | Request::Answer { .. } | Request::Usage => {
                Err(status::NO_ACCESS)
            }
            Request::Submit { .. }
            | Request::Status { .. }
            | Request::Cancel { .. }
            | Request::Forget { .. } => Err(status::NO_ACCESS),
            Request::Attach { .. } => Err(status::BAD_REQUEST),
        }
    }

    /// Takes the datagrams waiting at the network service and keeps each
    /// for every agent that sent to its source (`RECEIVE_FROM` checks the
    /// grant when the agent takes it).
    fn poll_net(&mut self) {
        // The service keeps at most four for us.
        for _ in 0..4 {
            let mut msg = [0u8; 2];
            let Some(poll) = net::encode(&NetRequest::Poll, &mut msg) else {
                return;
            };
            let mut out = [0u8; 256];
            let len = match self
                .net_health
                .call(NET, &msg[..poll], self.reply, &mut out, NET_US)
            {
                Ok(Received::Message { len, .. }) => len.min(256),
                _ => return,
            };
            let Some((addr, port, payload)) = net::parse_datagram(&out[..len]) else {
                return;
            };
            for s in self.slots.iter_mut().flatten() {
                if s.peers.contains(&(addr, port)) {
                    if s.inbox.len() == MAX_INBOX {
                        s.inbox.remove(0);
                    }
                    s.inbox.push(((addr, port), payload.to_vec()));
                }
            }
        }
    }

    /// Appends `e` to the audit trail; its sequence number if stored.
    fn audit(&self, e: &Record<'_>) -> Option<u64> {
        let mut msg = [0u8; 256];
        let n = audit::encode(&audit::Request::Append(*e), &mut msg)?;
        let mut out = [0u8; 256];
        match self
            .audit_health
            .call(AUDIT, &msg[..n], self.reply, &mut out, AUDIT_US)
        {
            Ok(Received::Message { len: 9, .. }) if out[0] == status::OK => Some(u64_at(&out, 1)),
            _ => None,
        }
    }

    /// The attempt task `id` is on.
    fn attempt(&self, id: u32) -> u8 {
        self.tasks
            .find(id)
            .map_or(0, |t| self.tasks.list[t].attempts)
    }

    /// Records an `INTENT` for `act` by `actor` on `task`; its sequence
    /// number, or `NO_AUDIT` (the action must not happen).
    fn intent(
        &self,
        actor: &[u8],
        task: u32,
        act: u8,
        permission: Option<Permission>,
        service: &[u8],
        detail: &[u8],
    ) -> Result<u64, u8> {
        self.audit(&Record {
            kind: Kind::Intent,
            refers: 0,
            actor,
            task,
            attempt: self.attempt(task),
            action: act,
            permission,
            service,
            outcome: outcome::NONE,
            detail,
        })
        .ok_or(NO_AUDIT)
    }

    /// The `OUTCOME` of intent `seq` (best effort: the action happened).
    fn outcome(&self, seq: u64, actor: &[u8], task: u32, act: u8, ok: bool, detail: &[u8]) {
        self.audit(&Record {
            kind: Kind::Outcome,
            refers: seq,
            actor,
            task,
            attempt: self.attempt(task),
            action: act,
            permission: None,
            service: b"",
            outcome: if ok { outcome::OK } else { outcome::FAILED },
            detail,
        });
    }

    /// An event about `task`'s `permission`; true if recorded.
    fn permission_event(
        &self,
        actor: &[u8],
        task: u32,
        act: u8,
        permission: Permission,
        result: u8,
        detail: &[u8],
    ) -> bool {
        self.audit(&Record {
            kind: Kind::Event,
            refers: 0,
            actor,
            task,
            attempt: self.attempt(task),
            action: act,
            permission: Some(permission),
            service: b"",
            outcome: result,
            detail,
        })
        .is_some()
    }

    /// Counts a refused request from slot `i`; the first of its `kind` this
    /// attempt is recorded (best effort, as other refusals).
    fn note(&mut self, i: usize, kind: u16, p: Option<Permission>) {
        let Some(s) = self.slots[i].as_mut() else {
            return;
        };
        s.refused = s.refused.saturating_add(1);
        if s.noted & kind != 0 {
            return;
        }
        s.noted |= kind;
        let task = s.task;
        let why: &[u8] = match kind {
            refusal::MALFORMED => b"malformed",
            refusal::NO_GRANT => b"no grant",
            refusal::NOT_FOR_AGENTS => b"not for agents",
            refusal::NOT_ASKABLE => b"not askable",
            refusal::OVER_TOKENS => b"over tokens",
            refusal::OVER_NET_SENDS => b"over net sends",
            refusal::OVER_NET_BYTES => b"over net bytes",
            refusal::OVER_DATA => b"over data",
            refusal::OVER_GROUP_TOKENS => b"over group tokens",
            _ => b"over group net",
        };
        let agent = self.agent_of(task);
        self.refusal_event(&agent, task, p, why);
    }

    /// Charges slot `i`'s attempt and its group with `f` (D-022, #116); over
    /// a budget, the request is refused with `OVER_LIMIT` and noted.
    fn charge(
        &mut self,
        i: usize,
        budget: &Budget,
        p: Option<Permission>,
        f: impl FnOnce(&mut Usage, Option<(&Group, &mut GroupUse)>) -> Result<(), Over>,
    ) -> Result<(), u8> {
        let g = self
            .groups
            .iter()
            .position(|g| !budget.group.is_empty() && g.name == budget.group);
        let groups = self.groups;
        let Some(s) = self.slots[i].as_mut() else {
            return Err(NO_SESSION);
        };
        let group = g.map(|g| (&groups[g], &mut self.group_use[g]));
        let Err(over) = f(&mut s.usage, group) else {
            return Ok(());
        };
        let kind = match over {
            Over::Tokens => refusal::OVER_TOKENS,
            Over::NetSends => refusal::OVER_NET_SENDS,
            Over::NetBytes => refusal::OVER_NET_BYTES,
            Over::Data => refusal::OVER_DATA,
            Over::GroupTokens => refusal::OVER_GROUP_TOKENS,
            Over::GroupNet => refusal::OVER_GROUP_NET,
        };
        self.note(i, kind, p);
        Err(status::OVER_LIMIT)
    }

    /// The bytes in agent `agent`'s files, and in `file` among them.
    fn data_stored(&mut self, agent: &[u8], file: &[u8]) -> Result<(u64, u64), u8> {
        let prefix = data_path(agent, b"");
        let names = self.store.list(&prefix).map_err(|_| status::INTERNAL)?;
        let (mut total, mut old) = (0, 0);
        for name in names {
            let size = self.store.size(&name).map_err(|_| status::INTERNAL)?;
            total += size;
            if name.strip_prefix(prefix.as_slice()) == Some(file) {
                old = size;
            }
        }
        Ok((total, old))
    }

    fn refusal_event(&self, actor: &[u8], task: u32, p: Option<Permission>, detail: &[u8]) {
        self.audit(&Record {
            kind: Kind::Event,
            refers: 0,
            actor,
            task,
            attempt: self.attempt(task),
            action: action::REFUSE,
            permission: p,
            service: b"",
            outcome: outcome::REFUSED,
            detail,
        });
    }

    /// The agent name of task `id`.
    fn agent_of(&self, id: u32) -> Vec<u8> {
        self.tasks
            .find(id)
            .map_or_else(Vec::new, |t| self.tasks.list[t].agent.clone())
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
                let (task, model) = (s.task, s.session_model);
                self.revoked.push((task, permission));
                if permission == Permission::Model(model) {
                    self.cancel_session(i);
                }
                // Always taken away; recorded when the trail can be.
                self.permission_event(
                    name,
                    task,
                    action::REVOKE,
                    permission,
                    audit::outcome::OK,
                    b"user",
                );
            }
        }
        tell_trust(&trust::Request::Revoked {
            outcome,
            name,
            permission,
        });
    }

    /// `ASK` from the agent in slot `i`, running task `task` of `entry`.
    fn ask(&mut self, i: usize, task: u32, entry: &Entry, p: Permission, for_ms: u32) -> Asked {
        let now = uptime();
        if self.slots[i]
            .as_ref()
            .is_some_and(|s| s.grants.allows(&p, now))
        {
            return Asked::Granted;
        }
        let closed = |list: &[(u32, Permission)]| list.iter().any(|(t, q)| *t == task && *q == p);
        if !askable(entry, &p) || closed(&self.revoked) || closed(&self.refused) {
            return Asked::Refused;
        }
        if self
            .pending
            .iter()
            .any(|q| q.task == task && q.permission == p)
        {
            return Asked::Pending;
        }
        // At most one waiting per agent, so no agent fills the queue (#117).
        if self.pending.len() >= MAX_PENDING || self.pending.iter().any(|q| q.task == task) {
            return Asked::Refused;
        }
        self.next_request = self.next_request.wrapping_add(1).max(1);
        let number = self.next_request;
        let asked = tell_trust(&trust::Request::Approve {
            number,
            name: entry.name,
            task,
            permission: p,
            for_ms,
        });
        // `trust` unreachable means no (D-018 item 4).
        if !asked {
            self.refused.push((task, p));
            return Asked::Refused;
        }
        self.pending.push(Pending {
            number,
            task,
            permission: p,
            for_ms,
            deadline: now + self.approve_us,
        });
        Asked::Pending
    }

    /// Ends approval request `number` as `how`, and tells `trust`.
    fn resolve(&mut self, number: u16, how: trust::Resolution) {
        let Some(at) = self.pending.iter().position(|q| q.number == number) else {
            return;
        };
        let q = self.pending.remove(at);
        let agent = self.agent_of(q.task);
        // An approval is given only once recorded; anything else is a
        // refusal, recorded when the trail can be.
        let approved = how == trust::Resolution::Granted
            && self.permission_event(
                &agent,
                q.task,
                action::APPROVE,
                q.permission,
                outcome::OK,
                b"user",
            );
        let how = if how == trust::Resolution::Granted && !approved {
            trust::Resolution::Refused
        } else {
            how
        };
        if how != trust::Resolution::Granted {
            let why: &[u8] = match how {
                trust::Resolution::Unanswered => b"no answer",
                trust::Resolution::Ended => b"task ended",
                _ => b"user",
            };
            self.permission_event(
                &agent,
                q.task,
                action::REFUSE,
                q.permission,
                outcome::REFUSED,
                why,
            );
        }
        if how == trust::Resolution::Granted {
            let until = (q.for_ms > 0).then(|| uptime() + u64::from(q.for_ms) * 1000);
            self.approved.push((q.task, q.permission, until));
            for s in self.slots.iter_mut().flatten().filter(|s| s.task == q.task) {
                s.grants.add(q.permission, until);
            }
        } else {
            self.refused.push((q.task, q.permission));
        }
        tell_trust(&trust::Request::Resolved {
            number,
            resolution: how,
        });
    }

    /// Requests past their deadline are refused; returns the wait until
    /// the next one.
    fn expire_pending(&mut self) -> u64 {
        let now = uptime();
        let due: Vec<u16> = self
            .pending
            .iter()
            .filter(|q| q.deadline <= now)
            .map(|q| q.number)
            .collect();
        for number in due {
            self.resolve(number, trust::Resolution::Unanswered);
        }
        self.pending
            .iter()
            .map(|q| q.deadline - now)
            .min()
            .unwrap_or(u64::MAX)
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
                let seq = self.intent(name, 0, action::SUBMIT, None, NAME, b"")?;
                let submitted = self
                    .tasks
                    .submit(&mut self.store, name, deps.as_slice(), &input);
                let mut d = [0u8; 20];
                let detail = match &submitted {
                    Ok(id) => decimal(u64::from(*id), &mut d),
                    Err(_) => &b""[..],
                };
                self.outcome(seq, name, 0, action::SUBMIT, submitted.is_ok(), detail);
                let id = submitted.map_err(store_error)?;
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
                let agent = self.agent_of(task);
                let seq = self.intent(&agent, task, action::CANCEL, None, NAME, b"")?;
                let cancelled =
                    self.tasks
                        .finish(&mut self.store, at, State::Cancelled, b"cancelled");
                self.outcome(seq, &agent, task, action::CANCEL, cancelled.is_ok(), b"");
                cancelled.map_err(store_error)?;
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

    /// `USAGE` from `trust` (#119): what each running attempt has used, and
    /// each group, as numbers `trust` writes out.
    fn report_usage(&self) {
        let now = uptime();
        let clip = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        for s in self.slots.iter().flatten() {
            let used = trust::Used {
                cpu_ms: clip(process_usage(s.process, Use::CpuMicros).unwrap_or(0) / 1000),
                pages: clip(process_usage(s.process, Use::Pages).unwrap_or(0)),
                tokens: clip(s.usage.tokens),
                sends: clip(s.usage.net_sends),
                bytes: clip(s.usage.net_bytes),
                requests: s.requests,
            };
            let name = self.agent_of(s.task);
            tell_trust(&trust::Request::Used {
                name: &name,
                task: s.task,
                used,
            });
        }
        for (g, u) in self.groups.iter().zip(&self.group_use) {
            let (mut running, mut pages) = (0, 0);
            for s in self.slots.iter().flatten() {
                let l = self
                    .tasks
                    .find(s.task)
                    .and_then(|t| self.limits(&self.tasks.list[t].agent));
                if let Some(l) = l.filter(|l| l.entry.budget.group == g.name) {
                    running += 1;
                    pages += u64::from(l.pages);
                }
            }
            tell_trust(&trust::Request::GroupUsed {
                name: g.name,
                running,
                pages: clip(pages),
                tokens: clip(u.tokens.used(now)),
                bytes: clip(u.net.used(now)),
            });
        }
    }

    /// Slot `i`'s requests a second ([`Budget::rate`]).
    fn rate(&self, i: usize) -> Option<u32> {
        let s = self.slots[i].as_ref()?;
        let t = self.tasks.find(s.task)?;
        Some(self.limits(&self.tasks.list[t].agent)?.entry.budget.rate)
    }

    /// The agent's rate (#117): true to serve `msg` now. Past its rate the
    /// request is held with its reply capability `cap` and served later
    /// ([`Runtime::serve_held`]); one more while one is held is `BUSY`.
    fn admit(&mut self, badge: u32, msg: &[u8], cap: Handle) -> bool {
        let Some(i) = agent_slot(badge) else {
            return true;
        };
        let Some(rate) = self.rate(i) else {
            return true;
        };
        let now = uptime();
        let Some(s) = self.slots[i].as_mut() else {
            return true;
        };
        if s.held.is_some() {
            if cap != 0 {
                let _ = try_send(cap, &[status::BUSY]);
                let _ = delete(cap);
            }
            return false;
        }
        if s.bucket.take(rate, now).is_ok() || cap == 0 {
            return true;
        }
        // It counts as progress when it arrives.
        s.last = now;
        s.held = Some((msg.to_vec(), cap));
        false
    }

    /// Serves held requests the agents' rates now allow; returns how long
    /// until the next one may be served.
    fn serve_held(&mut self) -> u64 {
        let mut wait = u64::MAX;
        for i in 0..SLOTS {
            let Some(rate) = self.rate(i) else { continue };
            let now = uptime();
            let Some(s) = self.slots[i].as_mut().filter(|s| s.held.is_some()) else {
                continue;
            };
            match s.bucket.take(rate, now) {
                Ok(()) => {
                    let Some((msg, cap)) = s.held.take() else {
                        continue;
                    };
                    let mut out = [0u8; 256];
                    let n = self.handle(&msg, i as u32 + 1, &mut out);
                    let _ = try_send(cap, &out[..n]);
                    let _ = delete(cap);
                }
                Err(us) => wait = wait.min(us),
            }
        }
        wait
    }

    /// Handles one `call`; writes the reply (status first) into `out`.
    fn handle(&mut self, msg: &[u8], badge: u32, out: &mut [u8; 256]) -> usize {
        let req = match parse(msg) {
            Ok(req) => req,
            Err(refused) => {
                if let Some(i) = agent_slot(badge) {
                    self.note(i, refusal::MALFORMED, None);
                }
                return refusal(refused, VERSION, out);
            }
        };
        let result = match agent_slot(badge) {
            Some(i) => {
                let result = self.agent(i, req, out);
                match result {
                    Err(status::NO_ACCESS) => match needed(&req) {
                        Some(p) => self.note(i, refusal::NO_GRANT, Some(p)),
                        None => self.note(i, refusal::NOT_FOR_AGENTS, None),
                    },
                    Err(status::BAD_REQUEST | status::TOO_LARGE | status::NO_BUFFER) => {
                        self.note(i, refusal::MALFORMED, None);
                    }
                    _ => {}
                }
                result
            }
            None if badge >= CONTROL => self.control(badge, req, out),
            None if badge == agents::TRUST => match req {
                Request::Usage => {
                    self.report_usage();
                    Ok(done(out))
                }
                Request::Revoke { name, permission } => {
                    self.revoke(name, permission);
                    Ok(done(out))
                }
                Request::Answer { number, yes } => {
                    let how = if yes {
                        trust::Resolution::Granted
                    } else {
                        trust::Resolution::Refused
                    };
                    self.resolve(number, how);
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

/// The permission an agent request needs, if any.
fn needed(req: &Request<'_>) -> Option<Permission> {
    match *req {
        Request::Infer { model, .. } => Some(Permission::Model(model)),
        Request::DataPut { .. } => Some(Permission::DataWrite),
        Request::DataGet { .. } => Some(Permission::DataRead),
        Request::SendTo { addr, port, .. } => Some(Permission::Net { addr, port }),
        _ => None,
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
    let (table, groups): (&'static [Entry], &'static [Group]) = match arg {
        0 => (BOOT, &[]),
        1 => (TEST, &[]),
        2 => (BUDGETS, BUDGET_GROUPS),
        _ => (&[], &[]),
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
    let mut store = Store {
        buffer,
        reply,
        health: Health::default(),
    };
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
        pending: Vec::new(),
        next_request: 0,
        approve_us: APPROVE_US[usize::from(arg == 1)],
        approved: Vec::new(),
        refused: Vec::new(),
        groups,
        group_use: alloc::vec![GroupUse::default(); groups.len()],
        infer_health: Health::default(),
        audit_health: Health::default(),
        net_health: Health::default(),
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
        let wait = r
            .check_deadlines()
            .min(r.expire_pending())
            .min(r.serve_held());
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
                if !r.admit(badge, msg, cap) {
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
