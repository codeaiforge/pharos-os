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
//! badged with the runtime's UDP port; #109), 10 the storage service,
//! badged for namespace `files`, read-only (the files the user gives
//! agents, #127; optional: without it `read_file` finds nothing), 11 the
//! knowledge service (`SEND`, client 1; #144; optional: without it every
//! knowledge request is `INTERNAL`). The
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
//!
//! Tools (#126, #127, tools.md): `TOOL` copies a call's text out of the
//! agent's buffer, parses and validates it ([`pharos_programs::tools`]),
//! checks the tool is one the attempt may use and the permission the call
//! needs, then the budget, and audits before running it. `read_file` reads
//! one granted file of the `files` namespace into the agent's buffer.
//! `send` is sensitive (#128): each call waits for the user's `yes` on the
//! trusted console (`CONFIRM`, structured fields only), answered `PENDING`
//! while the agent repeats the same call, sent once on a yes, and
//! `REFUSED` otherwise (no answer within the approval timeout, `no`, or
//! `trust` unreachable).
//!
//! Knowledge (#144, knowledge.md): `KNOWLEDGE_PUT` needs `knowledge write`
//! for its scope, counts against the attempt's `knowledge` budget, and is
//! audited (`knowledge`, never the content) before the runtime sends it
//! with the agent's name and task as author and its readable scopes. Reads
//! need `knowledge read` for their scope and pass the readable scopes, so
//! the service leaves out what the agent cannot reach; what the service
//! answers is copied to the agent's buffer, exactly its length. `PROMOTE`
//! (#145) also needs `data read`: the runtime reads the agent's file
//! itself and puts it with the source `promoted <file>`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use pharos_programs::budgets::{self, Bucket, GroupUse, Over, Usage};
use pharos_programs::grants::Grants;
use pharos_programs::groups;
use pharos_programs::mailbox::{self, Mailboxes};
use pharos_programs::tasks::{self, Begin, Files, StoreFailed, Tasks};
use pharos_programs::tools;
use pharos_proto::agents::{
    self, Asked, Assigned, Begun, CHECKPOINT_AT, CONTROL, MAX_BUFFER, MAX_CHECKPOINT, MAX_INPUT,
    MAX_RESULT, MAX_RUNNING, NAME, NO_AUDIT, NO_SESSION, Request, SLOTS, State, TaskStatus,
    VERSION, agent_slot, parse,
};
use pharos_proto::audit::{self, Entry as Record, Kind, action, outcome};
use pharos_proto::infer::{self, Record as InferRecord, Request as InferRequest, Started, Tokens};
use pharos_proto::knowledge::{self, Author, Put, Request as KnowledgeRequest, Source};
use pharos_proto::manifest::{self, Budget, Data, Dest, Entry, Group, Verifier, Why};
use pharos_proto::net::{self, Request as NetRequest};
use pharos_proto::permission::Permission;
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{Info, refusal, status, tool, trust};
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
const FILES: Handle = 10;
const KNOWLEDGE: Handle = 11;
/// How long the knowledge service may take to answer.
const KNOWLEDGE_US: u64 = 10_000_000;
/// The runtime's buffer at the storage service for granted files: the
/// largest file `read_file` reads.
const FILES_BUFFER: u64 = agents::MAX_DATA as u64;
/// How long the network service may take to answer.
const NET_US: u64 = 1_000_000;
/// Datagrams kept for one agent; the oldest goes first.
const MAX_INBOX: usize = 4;
/// The host echo server (`cargo xtask`, networking.md), through slirp.
const HOST_ECHO: Dest = ([10, 0, 2, 2], 47_000);

/// Kinds of refused agent requests, recorded once each per attempt.
mod refusal {
    pub const MALFORMED: u32 = 1;
    pub const NO_GRANT: u32 = 2;
    pub const NOT_FOR_AGENTS: u32 = 4;
    pub const NOT_ASKABLE: u32 = 8;
    /// Over a budget (D-022, #116), one kind per resource.
    pub const OVER_TOKENS: u32 = 16;
    pub const OVER_NET_SENDS: u32 = 32;
    pub const OVER_NET_BYTES: u32 = 64;
    pub const OVER_DATA: u32 = 128;
    pub const OVER_GROUP_TOKENS: u32 = 256;
    pub const OVER_GROUP_NET: u32 = 512;
    /// Tool calls (#126): not a call or fitting no tool, a tool the attempt
    /// may not use, and granted files over `file_kb`. A call the user did
    /// not confirm is recorded with the answer (#128).
    pub const TOOL_MALFORMED: u32 = 1024;
    pub const TOOL_NOT_LISTED: u32 = 2048;
    pub const OVER_FILES: u32 = 4096;
    /// Messages past the attempt's `messages` (#133).
    pub const OVER_MESSAGES: u32 = 8192;
    /// A subtask from an agent that is not its group's supervisor, or for
    /// an agent that is not one of its workers (#134).
    pub const NOT_IN_GROUP: u32 = 16384;
    /// A subtask past its goal's total (M3.7 review F1).
    pub const OVER_SUBTASKS: u32 = 32768;
    /// Knowledge puts past the attempt's `knowledge` (#144).
    pub const OVER_KNOWLEDGE: u32 = 65536;
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
/// Most open subtasks per goal (#134).
const MAX_SUBTASKS: usize = 8;
/// Most subtasks per goal in all, so a supervisor cannot fill the task
/// table (`MAX_TASKS`) and block every submission (M3.7 review F1).
const MAX_GOAL_SUBTASKS: usize = 32;
/// Most approval requests waiting at once.
const MAX_PENDING: usize = 4;
/// Control clients with an attached buffer.
const MAX_CONTROLS: usize = 4;

const BOOT: &[Entry] = &[];

/// The `budgets` test kernel's agents (#116): `spender` within its own
/// budget, `grouper` within its group's minute, `hog` over its CPU time,
/// and `pair` and `big` held by their groups' attempts and pages.
/// `spender`'s budget: 40 tokens, 2 datagrams of 64 bytes, 1 KiB of files.
const SPEND: Budget = Budget {
    cpu_ms: u32::MAX,
    tokens: 40,
    net_sends: 2,
    net_bytes: 64,
    data_kb: 1,
    file_kb: u32::MAX,
    messages: u32::MAX,
    knowledge: u32::MAX,
    rate: u32::MAX,
    group: b"spend",
};

const BUDGETS: &[Entry] = &[
    budget_entry(b"spender", SPEND, 64),
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
    ), // The `exhaustion` kernel's (#120): `glutton` within `spender`'s
    // budget at 4 requests a second, beside `spinner`s with no limit.
    budget_entry(
        b"glutton",
        Budget {
            rate: 4,
            group: b"spend",
            ..SPEND
        },
        64,
    ),
    budget_entry(b"spinner", Budget::UNLIMITED, 64),
];

/// The test table's group (#134): `boss` supervises `helper` and `aide`,
/// three attempts at once.
const TEST_GROUPS: &[Group] = &[Group {
    name: b"crew",
    agents: 3,
    pages: 1 << 12,
    tokens_per_min: u32::MAX,
    net_bytes_per_min: u32::MAX,
    supervisor: b"boss",
    workers: &[b"helper", b"aide"],
    verifier: Verifier::Text(agents::MAX_RESULT),
}];

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
        supervisor: b"",
        workers: &[],
        verifier: Verifier::None,
    },
    Group {
        name: b"tight",
        agents: 4,
        pages: 1 << 12,
        tokens_per_min: 30,
        net_bytes_per_min: 48,
        supervisor: b"",
        workers: &[],
        verifier: Verifier::None,
    },
    Group {
        name: b"pair",
        agents: 1,
        pages: 1 << 12,
        tokens_per_min: u32::MAX,
        net_bytes_per_min: u32::MAX,
        supervisor: b"",
        workers: &[],
        verifier: Verifier::None,
    },
    Group {
        name: b"heavy",
        agents: 4,
        pages: 300,
        tokens_per_min: u32::MAX,
        net_bytes_per_min: u32::MAX,
        supervisor: b"",
        workers: &[],
        verifier: Verifier::None,
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
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
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    // The `tools` kernel's (#126, #127): both tools, `report.txt` and
    // `big.txt` (more than its 4 KiB of `file_kb`), `notes.txt` to ask for,
    // and the host echo server for `send`. `plain` has the same files and
    // no tools.
    Entry {
        name: b"reader",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::Write,
        ask_models: 0,
        ask_data: Data::None,
        net: &[HOST_ECHO],
        ask_net: &[],
        budget: Budget {
            file_kb: 4,
            ..Budget::UNLIMITED
        },
        tools: 1 << tool::number::READ_FILE | 1 << tool::number::SEND,
        files: &[b"report.txt", b"big.txt"],
        ask_files: &[b"notes.txt"],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    // The `injection` kernel's (#129): both tools, `report.txt` with its
    // injected instructions, model 2, and the host echo server.
    Entry {
        name: b"injected",
        program: b"bin/testagent",
        pages: 256,
        models: 1 << 2,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[HOST_ECHO],
        ask_net: &[],
        budget: Budget::UNLIMITED,
        tools: 1 << tool::number::READ_FILE | 1 << tool::number::SEND,
        files: &[b"report.txt"],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    // The `channels` kernel's (#133): `talker` may send to `hearer` (and
    // ask for model 3, the runner's cue to revoke its channel), `spammer` to
    // `outsider` twice; `hearer` and `outsider` may send to no one.
    Entry {
        name: b"talker",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 1 << 3,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[b"hearer"],
    },
    Entry {
        name: b"hearer",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    Entry {
        name: b"outsider",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    Entry {
        name: b"spammer",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget {
            messages: 2,
            ..Budget::UNLIMITED
        },
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[b"outsider"],
    },
    // The `groups` kernel's (#134): `boss` supervises `helper` and `aide`
    // in group `crew` (`TEST_GROUPS`); only `boss` holds model 2, and `aide`
    // may ask for model 3 (#135).
    Entry {
        name: b"boss",
        program: b"bin/testagent",
        pages: 256,
        models: 1 << 2,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget {
            group: b"crew",
            ..Budget::UNLIMITED
        },
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    Entry {
        name: b"helper",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 2,
        // A hung attempt is stopped after 2 s (#136).
        progress_ms: 2_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget {
            group: b"crew",
            ..Budget::UNLIMITED
        },
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    Entry {
        name: b"aide",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 2,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 1 << 3,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget {
            group: b"crew",
            ..Budget::UNLIMITED
        },
        tools: 0,
        files: &[],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        // Its one channel, for the `deputy` kernel (#138).
        channels: &[b"boss"],
    },
    Entry {
        name: b"plain",
        program: b"bin/testagent",
        pages: 256,
        models: 0,
        attempts: 1,
        progress_ms: 10_000,
        task_ms: 60_000,
        data: Data::None,
        ask_models: 0,
        ask_data: Data::None,
        net: &[],
        ask_net: &[],
        budget: Budget::UNLIMITED,
        tools: 0,
        files: &[b"report.txt"],
        ask_files: &[],
        knowledge_read: &[],
        knowledge_write: &[],
        ask_knowledge: &[],
        channels: &[],
    },
    KNOWLEDGE_AGENTS[0],
    KNOWLEDGE_AGENTS[1],
];

/// The `knowledge_agents` kernel's (#144): `scribe` reads and writes
/// `notes` and `ops`, puts 6 versions at most (a promotion among them),
/// has its own files, and may ask to read and write `hr`;
/// `peeker` reads `ops` and writes `team`, with no files of its own.
const KNOWLEDGE_AGENTS: [Entry; 2] = [
    Entry {
        task_ms: 120_000,
        data: Data::Write,
        budget: Budget {
            knowledge: 6,
            ..Budget::UNLIMITED
        },
        knowledge_read: &[b"notes", b"ops"],
        knowledge_write: &[b"notes", b"ops"],
        ask_knowledge: &[b"read hr", b"write hr"],
        ..knowledge_entry(b"scribe")
    },
    Entry {
        knowledge_read: &[b"ops"],
        knowledge_write: &[b"team"],
        ..knowledge_entry(b"peeker")
    },
];

/// A `knowledge_agents` entry: `bin/testagent` with nothing else.
const fn knowledge_entry(name: &'static [u8]) -> Entry {
    Entry {
        net: &[],
        models: 0,
        pages: 256,
        data: Data::None,
        progress_ms: 10_000,
        task_ms: 60_000,
        ..budget_entry(name, Budget::UNLIMITED, 256)
    }
}

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
    /// The tools it may call and the files it gets (#126, #127), as the
    /// entry's names.
    tools: u32,
    files: [&'static [u8]; manifest::MAX_FILES],
    file_count: usize,
    /// The agents it may send messages to (#133), as the entry's names.
    channels: [&'static [u8]; manifest::MAX_FILES],
    channel_count: usize,
    /// The knowledge scopes it may read and write (#144), a bit each over
    /// `knowledge::SCOPES`.
    knowledge: (u8, u8),
}

/// The storage service as [`Files`], through the runtime's buffer there:
/// on handle [`STORE`] for its tasks, [`FILES`] for granted files.
struct Store {
    handle: Handle,
    buffer: Mapped,
    reply: Handle,
    health: Health,
}

impl Store {
    /// The size of file `path` in bytes; 0 if there is none.
    fn size(&self, path: &[u8]) -> Result<u64, StoreFailed> {
        Ok(self.stat(path)?.unwrap_or(0))
    }

    /// The size of file `path`, if there is one.
    fn stat(&self, path: &[u8]) -> Result<Option<u64>, StoreFailed> {
        let mut out = [0u8; 256];
        match self.call(&StoreRequest::Stat { path }, &mut out)? {
            StoreStatus::NotFound => Ok(None),
            StoreStatus::Ok => Ok(Some(u64_at(&out, 2))),
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
                .is_some_and(|n| send(self.handle, &msg[..n], memory, READ | WRITE, 0).is_ok());
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
            .call(self.handle, &msg[..n], self.reply, out, STORE_US)
        {
            Ok(Received::Message { len, .. }) if len >= 1 => Ok(StoreStatus::from_code(out[0])),
            _ => Err(StoreFailed),
        }
    }
}

/// The knowledge service (#144), through the runtime's buffer there.
struct Knowledge {
    buffer: Mapped,
    reply: Handle,
    health: Health,
}

impl Knowledge {
    /// Attaches the buffer: at start, and again after the service
    /// restarted and lost it.
    fn attach(&self) -> bool {
        let len = self.buffer.len() as u64;
        mem_share(self.buffer.addr(), len).is_ok_and(|memory| {
            let mut msg = [0u8; 16];
            let sent = knowledge::encode(&KnowledgeRequest::Attach { len }, &mut msg)
                .is_some_and(|n| send(KNOWLEDGE, &msg[..n], memory, READ | WRITE, 0).is_ok());
            let _ = delete(memory);
            sent
        })
    }

    /// `req`'s reply length in `out`, attaching the buffer again once if
    /// the service has none from us.
    fn call(&self, req: &KnowledgeRequest<'_>, out: &mut [u8; 256]) -> Result<usize, u8> {
        let mut msg = [0u8; 256];
        let n = knowledge::encode(req, &mut msg).ok_or(status::INTERNAL)?;
        for again in [true, false] {
            match (self.health).call(KNOWLEDGE, &msg[..n], self.reply, out, KNOWLEDGE_US) {
                Ok(Received::Message { len, .. }) if len >= 1 => {
                    if !(again && out[0] == status::NO_BUFFER && self.attach()) {
                        return Ok(len.min(256));
                    }
                }
                Err(pharos_user::Error::WouldBlock) => return Err(status::BUSY),
                _ => return Err(status::INTERNAL),
            }
        }
        Err(status::INTERNAL)
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
    noted: u32,
    /// What this attempt has used (#116).
    usage: Usage,
    /// Its requests over time, and the one held past its rate with its
    /// reply capability (#117).
    bucket: Bucket,
    held: Option<(Vec<u8>, Handle)>,
    /// Requests served this attempt (#119).
    requests: u32,
    /// Its one sensitive call waiting for the user (#128).
    confirm: Option<Confirm>,
}

struct Runtime {
    agents: Vec<Limits>,
    tasks: Tasks,
    store: Store,
    /// Granted files (#127), if `init` gave the runtime handle 10.
    files: Option<Store>,
    /// Shared knowledge (#144), if `init` gave the runtime handle 11.
    knowledge: Option<Knowledge>,
    /// Messages waiting for agents, by name (#133).
    mailboxes: Mailboxes,
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
    /// A tool call to confirm (#128), not a permission to approve.
    call: bool,
}

/// A sensitive call waiting for the user, or answered and not yet taken
/// (#128): its destination and payload, compared with each repeat.
struct Confirm {
    number: u16,
    permission: Permission,
    data: Vec<u8>,
    answer: Option<bool>,
}

/// True if `entry` lets its agent ask for `p`.
fn askable(entry: &Entry, p: &Permission) -> bool {
    match *p {
        Permission::Model(n) => n <= 31 && entry.ask_models & 1 << n != 0,
        Permission::DataRead => entry.ask_data >= Data::Read,
        Permission::DataWrite => entry.ask_data == Data::Write,
        Permission::Net { addr, port } => entry.ask_net.contains(&(addr, port)),
        Permission::File { .. } => p.file_name().is_some_and(|f| entry.ask_files.contains(&f)),
        // Channels are not askable in M3.7 (coordination.md).
        Permission::Channel { .. } => false,
        // As typed after `knowledge `: `read <scope>` or `write <scope>`.
        Permission::KnowledgeRead { .. } | Permission::KnowledgeWrite { .. } => {
            p.knowledge_scope().is_some_and(|(scope, write)| {
                let how: &[u8] = if write { b"write " } else { b"read " };
                (entry.ask_knowledge.iter()).any(|a| a.strip_prefix(how) == Some(scope))
            })
        }
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
    // The entry's own names: the manifest's borrow this buffer.
    let mut files = [&b""[..]; manifest::MAX_FILES];
    let mut file_count = 0;
    for f in m.files.as_slice() {
        if let Some(name) = e.files.iter().find(|n| *n == f) {
            files[file_count] = name;
            file_count += 1;
        }
    }
    let mut channels = [&b""[..]; manifest::MAX_FILES];
    let mut channel_count = 0;
    for c in m.channels.as_slice() {
        if let Some(name) = e.channels.iter().find(|n| *n == c) {
            channels[channel_count] = name;
            channel_count += 1;
        }
    }
    let scopes = |list: manifest::Files<'_>| {
        (list.as_slice().iter())
            .filter_map(|s| knowledge::scope_number(s))
            .fold(0u8, |mask, n| mask | 1 << n)
    };
    Ok(Limits {
        entry: e,
        knowledge: (scopes(m.knowledge_read), scopes(m.knowledge_write)),
        tools: m.tools,
        files,
        file_count,
        channels,
        channel_count,
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
        let mut msg = [0u8; 80];
        let register = trust::Request::Register {
            slot: slot as u8,
            name: limits.entry.name,
            group: limits.entry.budget.group,
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
            confirm: None,
        });
        // Every grant is recorded before it is given; none is given if a
        // record fails (#108).
        let files = &limits.files[..limits.file_count];
        let channels = &limits.channels[..limits.channel_count];
        let mut g = Grants::new(
            limits.models,
            limits.data,
            limits.net.as_slice(),
            files,
            channels,
            limits.knowledge,
        );
        for (_, p, until) in self.approved.iter().filter(|(t, ..)| *t == id) {
            g.add(*p, *until);
        }
        for (_, p) in self.revoked.iter().filter(|(t, _)| *t == id) {
            g.revoke(p);
        }
        let delegated = self.delegated(id, now);
        let from = self.source(id);
        let recorded = g.list().iter().all(|grant| {
            self.permission_event(
                limits.entry.name,
                id,
                action::GRANT,
                grant.permission,
                outcome::OK,
                b"",
            )
        }) && delegated.iter().all(|&(p, _)| {
            self.permission_event(limits.entry.name, id, action::GRANT, p, outcome::OK, &from)
        });
        if recorded {
            for (p, until) in delegated {
                g.add(p, until);
            }
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
                // The group's verifier first (#137): a refused result ends
                // the task failed, and the decision is recorded before.
                if let Some(v) = self.verifier(limits.entry) {
                    let subtasks_done = self
                        .tasks
                        .list
                        .iter()
                        .filter(|c| c.parent == id)
                        .all(|c| c.state == State::Done);
                    let checked = groups::verify(v, &result, subtasks_done);
                    let (how, detail) = match checked {
                        Ok(()) => (outcome::OK, &b"verified"[..]),
                        Err(why) => (outcome::REFUSED, why.detail()),
                    };
                    let agent = limits.entry.name;
                    self.verify_event(agent, id, how, detail).ok_or(NO_AUDIT)?;
                    if checked.is_err() {
                        stored(self.tasks.finish(&mut self.store, t, State::Failed, detail))?;
                        self.end(i, Ending::Finished);
                        self.event(id, b"not verified", None);
                        return Ok(done(out));
                    }
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
            Request::KnowledgePut { .. }
            | Request::Promote { .. }
            | Request::KnowledgeGet { .. }
            | Request::KnowledgeHistory { .. }
            | Request::KnowledgeQuery { .. } => self.knowledge(i, id, &limits, req, now, out),
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
                let how = (action::NET_SEND, net::NAME, &b""[..]);
                self.send_datagram(i, id, &limits, addr, port, &payload, how)?;
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
            Request::MessageSend { to, kind, len } => {
                let p = Permission::channel(to).ok_or(status::BAD_REQUEST)?;
                let allowed = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&p, now));
                if !allowed {
                    return Err(status::NO_ACCESS);
                }
                if len as usize > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                // A full queue refuses before anything is charged.
                if !self.mailboxes.has_room(to) {
                    return Err(status::BUSY);
                }
                // Copied out first; never read by the runtime.
                let mut bytes = alloc::vec![0u8; len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(0, &mut bytes);
                }
                let budget = limits.entry.budget;
                self.charge(i, &budget, Some(p), |u, _| u.message(&budget))?;
                let agent = limits.entry.name;
                // Kind and length only: the content is never recorded.
                let mut d = [[0u8; 20]; 2];
                let [k, l] = &mut d;
                let detail = [
                    &b"kind "[..],
                    decimal(u64::from(kind), k),
                    b" len ",
                    decimal(u64::from(len), l),
                ]
                .concat();
                let seq = self.intent(agent, id, action::MESSAGE, Some(p), NAME, &detail)?;
                let queued = self.mailboxes.put(
                    to,
                    mailbox::Message {
                        from: agent.to_vec(),
                        kind,
                        bytes,
                    },
                );
                self.outcome(seq, agent, id, action::MESSAGE, queued, &detail);
                if !queued {
                    return Err(status::BUSY);
                }
                Ok(done(out))
            }
            Request::Subtask {
                worker,
                input_len,
                delegate,
            } => {
                let agent = limits.entry.name;
                let entry = |n: &[u8]| {
                    self.agents
                        .iter()
                        .find(|l| l.entry.name == n)
                        .map(|l| l.entry)
                };
                if groups::assigning(self.groups, entry, agent, worker).is_none() {
                    self.note(i, refusal::NOT_IN_GROUP, None);
                    return Err(status::NO_ACCESS);
                }
                if self.limits(worker).is_none() {
                    return Err(status::NOT_FOUND);
                }
                // Only what the supervisor holds now (#135); its deadline
                // is checked again when each attempt starts.
                let Some(held) = self.slots[i].as_ref().map(|s| &s.grants) else {
                    return Err(status::INTERNAL);
                };
                let delegated: Vec<Permission> = match groups::delegable(held, delegate.iter(), now)
                {
                    Ok(d) => d.into_iter().map(|(p, _)| p).collect(),
                    Err(p) => {
                        self.note(i, refusal::NO_GRANT, Some(p));
                        return Err(status::NO_ACCESS);
                    }
                };
                if self.tasks.children(id) >= MAX_GOAL_SUBTASKS {
                    self.note(i, refusal::OVER_SUBTASKS, None);
                    return Err(status::OVER_LIMIT);
                }
                if self.tasks.open_children(id) >= MAX_SUBTASKS {
                    return Err(status::BUSY);
                }
                if input_len as usize > buffer_len {
                    self.note(i, refusal::MALFORMED, None);
                    return Err(status::NO_BUFFER);
                }
                let mut input = alloc::vec![0u8; input_len as usize];
                if let Some(b) = buffer {
                    b.read_bytes(0, &mut input);
                }
                let seq = self.intent(agent, id, action::SUBMIT, None, NAME, worker)?;
                let submitted =
                    self.tasks
                        .submit_child(&mut self.store, worker, id, &input, &delegated);
                let mut d = [0u8; 20];
                let detail = match &submitted {
                    Ok(t) => [worker, b" ", decimal(u64::from(*t), &mut d)].concat(),
                    Err(_) => worker.to_vec(),
                };
                self.outcome(seq, agent, id, action::SUBMIT, submitted.is_ok(), &detail);
                let t = submitted.map_err(store_error)?;
                agents::submitted(t, out).ok_or(status::INTERNAL)
            }
            Request::SubtaskStatus { task } => {
                let t = self
                    .tasks
                    .find(task)
                    .map(|j| &self.tasks.list[j])
                    .filter(|t| t.parent == id)
                    .ok_or(NO_SESSION)?;
                if t.result.len() > buffer_len {
                    return Err(status::NO_BUFFER);
                }
                if let Some(b) = buffer {
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
            Request::MessageReceive => {
                if buffer_len < agents::MAX_MESSAGE as usize {
                    return Err(status::NO_BUFFER);
                }
                let m = self
                    .mailboxes
                    .take(limits.entry.name)
                    .ok_or(status::NOT_FOUND)?;
                if let Some(b) = self.slots[i].as_ref().and_then(|s| s.buffer.as_ref()) {
                    b.write_bytes(0, &m.bytes);
                }
                agents::Message {
                    from: &m.from,
                    kind: m.kind,
                    len: m.bytes.len() as u32,
                }
                .encode(out)
                .ok_or(status::INTERNAL)
            }
            Request::Tool {
                call_at,
                call_len,
                result_at,
            } => {
                let (at, n) = (call_at as usize, usize::from(call_len));
                if at.checked_add(n).is_none_or(|end| end > buffer_len) {
                    self.note(i, refusal::MALFORMED, None);
                    return Err(status::NO_BUFFER);
                }
                // Copied out first: the agent may change its buffer meanwhile.
                let mut text = [0u8; tool::MAX_CALL];
                if let Some(b) = buffer {
                    b.read_bytes(at, &mut text[..n]);
                }
                let mut scratch = [0u8; tool::MAX_CALL];
                let planned = match tools::plan(&text[..n], limits.tools, &mut scratch) {
                    Ok(p) => p,
                    Err(tools::Refused::NotListed) => {
                        self.note(i, refusal::TOOL_NOT_LISTED, None);
                        return Err(status::NO_ACCESS);
                    }
                    Err(_) => {
                        self.note(i, refusal::TOOL_MALFORMED, None);
                        return Err(status::BAD_REQUEST);
                    }
                };
                let p = planned.permission;
                let granted = self.slots[i]
                    .as_ref()
                    .is_some_and(|s| s.grants.allows(&p, now));
                if !granted {
                    // Revoked while the user was asked: that call ends.
                    let waiting = self.slots[i]
                        .as_ref()
                        .and_then(|s| s.confirm.as_ref())
                        .filter(|c| c.permission == p && c.answer.is_none())
                        .map(|c| c.number);
                    if let Some(number) = waiting {
                        self.resolve(number, trust::Resolution::Refused);
                    }
                    if let Some(s) = self.slots[i].as_mut().filter(|_| waiting.is_some()) {
                        s.confirm = None;
                    }
                    self.note(i, refusal::NO_GRANT, Some(p));
                    return Err(status::NO_ACCESS);
                }
                if tools::sensitive(planned.tool) {
                    let data = planned.data.to_vec();
                    return self.confirmed_send(i, id, &limits, p, &data, out);
                }
                self.read_file(i, id, &limits, p, result_at, out)
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

    /// One datagram from slot `i` on task `id` to `addr:port`, its grant
    /// already checked: charged, audited as `how` (action, service,
    /// detail), and sent on the runtime's port (`SEND_TO`, #109, and the
    /// `send` tool, #128).
    /// A knowledge request from slot `i`, task `id` (#144).
    fn knowledge(
        &mut self,
        i: usize,
        id: u32,
        limits: &Limits,
        req: Request<'_>,
        now: u64,
        out: &mut [u8; 256],
    ) -> Result<usize, u8> {
        let slot = self.slots[i].as_ref().ok_or(NO_SESSION)?;
        // Taken now, so a revocation holds from the next request.
        let readable = slot.grants.readable(now);
        let buffer_len = slot.buffer.as_ref().map_or(0, Mapped::len);
        let (req, scope, page) = match req {
            Request::KnowledgePut { len } => {
                return self.knowledge_put(i, id, limits, len, None, readable, now, out);
            }
            Request::Promote { file, len } => {
                return self.knowledge_put(i, id, limits, len, Some(file), readable, now, out);
            }
            Request::KnowledgeGet {
                scope,
                key,
                version,
            } => {
                let req = KnowledgeRequest::Get {
                    scope,
                    key,
                    version,
                    readable,
                };
                (req, scope, None)
            }
            Request::KnowledgeHistory { scope, key, from } => {
                let req = KnowledgeRequest::History {
                    scope,
                    key,
                    from,
                    readable,
                };
                (req, scope, Some(false))
            }
            Request::KnowledgeQuery { scope, tag, start } => {
                let req = KnowledgeRequest::Query {
                    scope,
                    tag,
                    start,
                    readable,
                };
                (req, scope, Some(true))
            }
            _ => return Err(status::INTERNAL),
        };
        if readable & 1 << scope == 0 {
            return Err(status::NO_ACCESS);
        }
        let k = self.knowledge.as_ref().ok_or(status::INTERNAL)?;
        k.health.ready()?;
        let n = k.call(&req, out)?;
        if out[0] != status::OK {
            return Ok(n);
        }
        // Exactly what the service wrote: never bytes left from an
        // earlier answer, perhaps for another agent.
        let len = match (page, &out[..n]) {
            (None, [_, _, a, b, c, d]) => u32::from_le_bytes([*a, *b, *c, *d]) as usize,
            (Some(query), [_, count, _]) => {
                let mut bytes = alloc::vec![0u8; knowledge::MAX_PAGE_BYTES.min(k.buffer.len())];
                k.buffer.read_bytes(0, &mut bytes);
                knowledge::page_len(&bytes, *count, query).ok_or(status::INTERNAL)?
            }
            _ => return Err(status::INTERNAL),
        };
        if len > k.buffer.len() {
            return Err(status::INTERNAL);
        }
        if len > buffer_len {
            return Err(status::NO_BUFFER);
        }
        let mut bytes = alloc::vec![0u8; len];
        k.buffer.read_bytes(0, &mut bytes);
        if let Some(b) = self.slots[i].as_ref().and_then(|s| s.buffer.as_ref()) {
            b.write_bytes(0, &bytes);
        }
        Ok(n)
    }

    /// `KNOWLEDGE_PUT` (#144): the put in the agent's buffer, with the
    /// runtime's author, source, and readable scopes; audited first. With
    /// `file`, `PROMOTE` (#145): that file of the agent's, read by the
    /// runtime, is the content.
    #[allow(clippy::too_many_arguments)]
    fn knowledge_put(
        &mut self,
        i: usize,
        id: u32,
        limits: &Limits,
        len: u16,
        file: Option<&[u8]>,
        readable: u8,
        now: u64,
        out: &mut [u8; 256],
    ) -> Result<usize, u8> {
        let len = usize::from(len);
        let buffer = self.slots[i].as_ref().and_then(|s| s.buffer.as_ref());
        if len > knowledge::MAX_RECORD || len > buffer.map_or(0, Mapped::len) {
            self.note(i, refusal::MALFORMED, None);
            return Err(status::TOO_LARGE);
        }
        // Copied out first: the agent may change its buffer meanwhile.
        let mut body = alloc::vec![0u8; len];
        if let Some(b) = buffer {
            b.read_bytes(0, &mut body);
        }
        let Some(put) = Put::parse(&body) else {
            self.note(i, refusal::MALFORMED, None);
            return Err(status::BAD_REQUEST);
        };
        let scope = knowledge::SCOPES[usize::from(put.scope)];
        let p = Permission::knowledge(scope, true).ok_or(status::INTERNAL)?;
        let allowed = self.slots[i]
            .as_ref()
            .is_some_and(|s| s.grants.allows(&p, now));
        if !allowed {
            self.note(i, refusal::NO_GRANT, Some(p));
            return Err(status::NO_ACCESS);
        }
        self.knowledge
            .as_ref()
            .ok_or(status::INTERNAL)?
            .health
            .ready()?;
        let agent = limits.entry.name;
        // A promotion: a claim whose content is the file, never the
        // agent's own bytes.
        let mut promoted = Vec::new();
        if let Some(f) = file {
            if put.kind != knowledge::Kind::Claim || !put.content.is_empty() {
                self.note(i, refusal::MALFORMED, None);
                return Err(status::BAD_REQUEST);
            }
            let readable_data = self.slots[i]
                .as_ref()
                .is_some_and(|s| s.grants.allows(&Permission::DataRead, now));
            if !readable_data {
                self.note(i, refusal::NO_GRANT, Some(Permission::DataRead));
                return Err(status::NO_ACCESS);
            }
            self.store.health.ready()?;
            promoted = (self.store.read(&data_path(agent, f)))
                .map_err(|_| status::INTERNAL)?
                .ok_or(status::NOT_FOUND)?;
            if promoted.len() > knowledge::MAX_CONTENT {
                self.note(i, refusal::MALFORMED, None);
                return Err(status::TOO_LARGE);
            }
        }
        let budget = limits.entry.budget;
        self.charge(i, &budget, Some(p), |u, _| u.knowledge(&budget))?;
        let put = Put {
            author: Author::Agent {
                name: agent,
                task: id,
            },
            source: file.map_or(Source::Written, Source::Promoted),
            readable,
            content: if file.is_some() {
                &promoted
            } else {
                put.content
            },
            ..put
        };
        let mut record = alloc::vec![0u8; knowledge::MAX_RECORD];
        let n = put.encode(&mut record).ok_or(status::BAD_REQUEST)?;
        // The key, what it replaces, the kind, and the length: never the
        // content.
        let mut d = [[0u8; 20]; 2];
        let [a, b] = &mut d;
        let kind: &[u8] = match put.kind {
            knowledge::Kind::Claim => b" claim ",
            knowledge::Kind::Retraction => b" retraction ",
        };
        let replaces = decimal(u64::from(put.replaces), a);
        let size = decimal(put.content.len() as u64, b);
        let detail = match file {
            Some(f) => [&b"promote "[..], f].concat(),
            None => [put.key, b" replaces ", replaces, kind, size, b" bytes"].concat(),
        };
        let detail = &detail[..detail.len().min(audit::MAX_DETAIL)];
        let seq = self.intent(
            agent,
            id,
            action::KNOWLEDGE,
            Some(p),
            knowledge::NAME,
            detail,
        )?;
        let k = self.knowledge.as_ref().ok_or(status::INTERNAL)?;
        k.buffer.write_bytes(0, &record[..n]);
        let r = k.call(&KnowledgeRequest::Put { len: n as u16 }, out);
        let version = match (r, &out[..]) {
            (Ok(5), [status::OK, v0, v1, v2, v3, ..]) => {
                Some(u32::from_le_bytes([*v0, *v1, *v2, *v3]))
            }
            _ => None,
        };
        let mut v = [0u8; 20];
        let ended: Vec<u8> = match version {
            Some(n) => [&b"version "[..], decimal(u64::from(n), &mut v)].concat(),
            None => [&b"status "[..], decimal(u64::from(out[0]), &mut v)].concat(),
        };
        self.outcome(seq, agent, id, action::KNOWLEDGE, version.is_some(), &ended);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn send_datagram(
        &mut self,
        i: usize,
        id: u32,
        limits: &Limits,
        addr: [u8; 4],
        port: u16,
        payload: &[u8],
        how: (u8, &[u8], &[u8]),
    ) -> Result<(), u8> {
        let p = Permission::Net { addr, port };
        let req = NetRequest::Send {
            ip: addr,
            port,
            payload,
        };
        let mut msg = [0u8; 256];
        let n = net::encode(&req, &mut msg).ok_or(status::INTERNAL)?;
        let now = uptime();
        let agent = limits.entry.name;
        let budget = limits.entry.budget;
        let len = payload.len() as u64;
        self.charge(i, &budget, Some(p), |u, g| u.send(&budget, g, now, len))?;
        let (act, service, detail) = how;
        let seq = self.intent(agent, id, act, Some(p), service, detail)?;
        // The request is sent from the reply buffer too.
        let mut reply = [0u8; 256];
        let code = match self
            .net_health
            .call(NET, &msg[..n], self.reply, &mut reply, NET_US)
        {
            Ok(Received::Message { len, .. }) if len >= 1 => reply[0],
            _ => status::INTERNAL,
        };
        self.outcome(seq, agent, id, act, code == net::OK, detail);
        if code != net::OK {
            return Err(code);
        }
        if let Some(s) = self.slots[i].as_mut() {
            if !s.peers.contains(&(addr, port)) {
                s.peers.push((addr, port));
            }
        }
        Ok(())
    }

    /// `read_file` (#127) for slot `i` on task `id`, its `file` permission
    /// `p` already checked: the file into the agent's buffer at
    /// `result_at`, charged to `file_kb` and audited first.
    fn read_file(
        &mut self,
        i: usize,
        id: u32,
        limits: &Limits,
        p: Permission,
        result_at: u32,
        out: &mut [u8; 256],
    ) -> Result<usize, u8> {
        let name = p.file_name().ok_or(status::INTERNAL)?;
        let files = self.files.as_ref().ok_or(status::NOT_FOUND)?;
        files.health.ready()?;
        let size = files
            .stat(name)
            .map_err(|_| status::INTERNAL)?
            .ok_or(status::NOT_FOUND)?;
        if size > FILES_BUFFER {
            return Err(status::TOO_LARGE);
        }
        let buffer_len = self.slots[i]
            .as_ref()
            .and_then(|s| s.buffer.as_ref())
            .map_or(0, Mapped::len);
        if (result_at as u64).saturating_add(size) > buffer_len as u64 {
            return Err(status::NO_BUFFER);
        }
        let budget = limits.entry.budget;
        self.charge(i, &budget, Some(p), |u, _| u.read_file(&budget, size))?;
        let agent = limits.entry.name;
        let seq = self.intent(agent, id, action::TOOL, Some(p), b"files", b"read_file")?;
        let bytes = self
            .files
            .as_mut()
            .and_then(|f| f.read(name).ok().flatten());
        self.outcome(seq, agent, id, action::TOOL, bytes.is_some(), b"read_file");
        let bytes = bytes.ok_or(status::INTERNAL)?;
        if let Some(b) = self.slots[i].as_ref().and_then(|s| s.buffer.as_ref()) {
            // The size was checked; a file replaced since would not fit.
            if result_at as usize + bytes.len() > b.len() {
                return Err(status::INTERNAL);
            }
            b.write_bytes(result_at as usize, &bytes);
        }
        out[0] = status::OK;
        out[1..5].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        Ok(5)
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
    fn note(&mut self, i: usize, kind: u32, p: Option<Permission>) {
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
            refusal::OVER_GROUP_NET => b"over group net",
            refusal::TOOL_MALFORMED => b"tool malformed",
            refusal::TOOL_NOT_LISTED => b"tool not listed",
            refusal::OVER_FILES => b"over files",
            refusal::OVER_MESSAGES => b"over messages",
            refusal::OVER_SUBTASKS => b"over subtasks",
            refusal::OVER_KNOWLEDGE => b"over knowledge",
            _ => b"not in group",
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
            Over::Files => refusal::OVER_FILES,
            Over::Messages => refusal::OVER_MESSAGES,
            Over::Knowledge => refusal::OVER_KNOWLEDGE,
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
    /// The verifier of the coordinated group `entry` belongs to (#137).
    fn verifier(&self, entry: &Entry) -> Option<Verifier> {
        let member = |n: &[u8]| {
            self.agents
                .iter()
                .find(|l| l.entry.name == n)
                .map(|l| l.entry)
        };
        self.groups
            .iter()
            .find(|g| !entry.budget.group.is_empty() && g.name == entry.budget.group)
            .filter(|g| groups::coordinated(g, member))
            .map(|g| g.verifier)
    }

    fn verify_event(&self, actor: &[u8], task: u32, how: u8, detail: &[u8]) -> Option<u64> {
        self.audit(&Record {
            kind: Kind::Event,
            refers: 0,
            actor,
            task,
            attempt: self.attempt(task),
            action: action::VERIFY,
            permission: None,
            service: b"",
            outcome: how,
            detail,
        })
    }

    /// What subtask `id` gets from its supervisor (#135): each delegated
    /// permission its parent's running attempt still holds at `now`, with
    /// that grant's deadline, and not revoked from `id`.
    fn delegated(&self, id: u32, now: u64) -> Vec<(Permission, Option<u64>)> {
        let Some(t) = self.tasks.find(id).map(|t| &self.tasks.list[t]) else {
            return Vec::new();
        };
        let held = self
            .slots
            .iter()
            .flatten()
            .find(|s| t.parent != 0 && s.task == t.parent);
        let revoked = |p: &Permission| {
            self.revoked
                .iter()
                .any(|(r, q)| *r == id && (q.covers(p) || p.covers(q)))
        };
        let wanted = t.delegated.iter().copied().filter(|p| !revoked(p));
        groups::given(held.map(|s| &s.grants), wanted, now)
    }

    /// `from <supervisor> task <id>`: the detail of a grant or revocation
    /// that subtask `id` has from its supervisor.
    fn source(&self, id: u32) -> Vec<u8> {
        let parent = self.tasks.find(id).map_or(0, |t| self.tasks.list[t].parent);
        let mut d = [0u8; 20];
        let n = decimal(u64::from(parent), &mut d);
        [&b"from "[..], &self.agent_of(parent), b" task ", n].concat()
    }

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
            let task = s.task;
            if self.take(i, permission, b"user") {
                outcome = trust::Outcome::Revoked;
                // With its source (#135): from every running subtask it
                // was delegated to.
                for j in 0..SLOTS {
                    let Some(child) = self.slots[j].as_ref().map(|c| c.task) else {
                        continue;
                    };
                    let passed = self.tasks.find(child).is_some_and(|t| {
                        let t = &self.tasks.list[t];
                        t.parent == task
                            && t.delegated
                                .iter()
                                .any(|p| p.covers(&permission) || permission.covers(p))
                    });
                    if passed {
                        let from = self.source(child);
                        self.take(j, permission, &from);
                    }
                }
            }
        }
        tell_trust(&trust::Request::Revoked {
            outcome,
            name,
            permission,
        });
    }

    /// Takes `permission` from the attempt in slot `i` and keeps it taken
    /// for its restarts; ends a session or a waiting call that used it.
    /// Records it with `detail`. Returns true if it was held.
    fn take(&mut self, i: usize, permission: Permission, detail: &[u8]) -> bool {
        let Some(s) = self.slots[i].as_mut() else {
            return false;
        };
        if !s.grants.revoke(&permission) {
            return false;
        }
        let (task, model) = (s.task, s.session_model);
        self.revoked.push((task, permission));
        if permission == Permission::Model(model) {
            self.cancel_session(i);
        }
        // Always taken away; recorded when the trail can be.
        let agent = self.agent_of(task);
        self.permission_event(
            &agent,
            task,
            action::REVOKE,
            permission,
            audit::outcome::OK,
            detail,
        );
        // A call to it waiting for the user ends at once, as a session
        // does (D-012 item 8; M3.6 review F1).
        let waiting = self.slots[i]
            .as_mut()
            .and_then(|s| {
                s.confirm
                    .take_if(|c| c.answer.is_none() && permission.covers(&c.permission))
            })
            .map(|c| c.number);
        if let Some(number) = waiting {
            self.resolve(number, trust::Resolution::Refused);
        }
        true
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
            call: false,
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
        if q.call {
            self.resolve_call(&agent, &q, how);
            return;
        }
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

    /// Ends confirmation `q` (#128): a yes only once recorded, and either
    /// way only for that call; the agent takes the answer on its next
    /// repeat.
    fn resolve_call(&mut self, agent: &[u8], q: &Pending, how: trust::Resolution) {
        let yes = how == trust::Resolution::Granted
            && self.permission_event(
                agent,
                q.task,
                action::APPROVE,
                q.permission,
                outcome::OK,
                b"user",
            );
        if !yes {
            let why: &[u8] = match how {
                trust::Resolution::Unanswered => b"no answer",
                trust::Resolution::Ended => b"task ended",
                _ => b"user",
            };
            self.permission_event(
                agent,
                q.task,
                action::REFUSE,
                q.permission,
                outcome::REFUSED,
                why,
            );
        }
        for s in self.slots.iter_mut().flatten().filter(|s| s.task == q.task) {
            if let Some(c) = s.confirm.as_mut().filter(|c| c.number == q.number) {
                c.answer = Some(yes);
            }
        }
        let resolution = match how {
            trust::Resolution::Granted if !yes => trust::Resolution::Refused,
            how => how,
        };
        tell_trust(&trust::Request::Resolved {
            number: q.number,
            resolution,
        });
    }

    /// `send` from slot `i` on task `id` (#128), its grant checked: sent
    /// once the user confirms this call; `PENDING` until then.
    fn confirmed_send(
        &mut self,
        i: usize,
        id: u32,
        limits: &Limits,
        p: Permission,
        data: &[u8],
        out: &mut [u8; 256],
    ) -> Result<usize, u8> {
        let Permission::Net { addr, port } = p else {
            return Err(status::INTERNAL);
        };
        let state = self.slots[i]
            .as_ref()
            .and_then(|s| s.confirm.as_ref())
            .map(|c| (c.permission == p && c.data == data, c.answer));
        match state {
            Some((true, None)) => return Err(agents::PENDING),
            Some((false, None)) => return Err(status::BUSY),
            Some((true, Some(yes))) => {
                if let Some(s) = self.slots[i].as_mut() {
                    s.confirm = None;
                }
                if !yes {
                    return Err(agents::REFUSED);
                }
                self.net_health.ready()?;
                let how = (action::TOOL, net::NAME, &b"send"[..]);
                self.send_datagram(i, id, limits, addr, port, data, how)?;
                return Ok(done(out));
            }
            // Answered, then a different call: asked anew.
            Some((false, Some(_))) | None => {}
        }
        // One request waiting per agent (#117).
        if self.pending.len() >= MAX_PENDING || self.pending.iter().any(|q| q.task == id) {
            return Err(status::BUSY);
        }
        self.next_request = self.next_request.wrapping_add(1).max(1);
        let number = self.next_request;
        let asked = tell_trust(&trust::Request::Confirm {
            number,
            name: limits.entry.name,
            task: id,
            tool: tool::number::SEND,
            addr,
            port,
            bytes: data.len() as u16,
        });
        // `trust` unreachable means no (D-018 item 4).
        if !asked {
            return Err(agents::REFUSED);
        }
        self.pending.push(Pending {
            number,
            task: id,
            permission: p,
            for_ms: 0,
            deadline: uptime() + self.approve_us,
            call: true,
        });
        if let Some(s) = self.slots[i].as_mut() {
            s.confirm = Some(Confirm {
                number,
                permission: p,
                data: data.to_vec(),
                answer: None,
            });
        }
        Err(agents::PENDING)
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
                self.cancel(task, b"")?;
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

    /// Cancels task `id` (recorded, with `why` as the intent's detail) and
    /// stops its agent if it runs. An ended task is left as it is.
    fn cancel(&mut self, id: u32, why: &[u8]) -> Result<(), u8> {
        let at = self.tasks.find(id).ok_or(status::NOT_FOUND)?;
        if self.tasks.list[at].ended() {
            return Ok(());
        }
        let agent = self.agent_of(id);
        let seq = self.intent(&agent, id, action::CANCEL, None, NAME, why)?;
        let cancelled = self
            .tasks
            .finish(&mut self.store, at, State::Cancelled, b"cancelled");
        self.outcome(seq, &agent, id, action::CANCEL, cancelled.is_ok(), b"");
        cancelled.map_err(store_error)?;
        if let Some(slot) = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.task == id))
        {
            self.end(slot, Ending::Cancelled);
        }
        self.event(id, b"cancelled", None);
        Ok(())
    }

    /// Cancels the open subtasks of goals that ended, however they ended
    /// (#136). One the store or trail refuses is tried again next pass.
    fn cancel_orphans(&mut self) {
        for id in self.tasks.orphans() {
            let _ = self.cancel(id, b"goal ended");
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
                // `TOOL`, `SUBTASK`, and `KNOWLEDGE_PUT` record their own
                // refusals, by kind (#126, #135, #144).
                let tool = matches!(
                    req,
                    Request::Tool { .. }
                        | Request::Subtask { .. }
                        | Request::KnowledgePut { .. }
                        | Request::Promote { .. }
                );
                match result {
                    _ if tool => {}
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
        Request::MessageSend { to, .. } => Permission::channel(to),
        Request::KnowledgeGet { scope, .. }
        | Request::KnowledgeHistory { scope, .. }
        | Request::KnowledgeQuery { scope, .. } => knowledge::SCOPES
            .get(usize::from(scope))
            .and_then(|s| Permission::knowledge(s, false)),
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
        1 => (TEST, TEST_GROUPS),
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
    for g in groups.iter().filter(|g| !g.supervisor.is_empty()) {
        let entry = |n: &[u8]| table.iter().find(|e| e.name == n);
        if !groups::coordinated(g, entry) {
            say(&[b"agents: group ", g.name, b" cannot coordinate"]);
        }
    }
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
        handle: STORE,
        buffer,
        reply,
        health: Health::default(),
    };
    if !store.attach() {
        return 6;
    }
    // Granted files (#127): optional, as handle 10 is.
    let files = mem_map_buffer(FILES_BUFFER).ok().and_then(|buffer| {
        let files = Store {
            handle: FILES,
            buffer,
            reply,
            health: Health::default(),
        };
        files.attach().then_some(files)
    });
    // Shared knowledge (#144): optional, as handle 11 is.
    let knowledge = mem_map_buffer(knowledge::MIN_BUFFER)
        .ok()
        .and_then(|buffer| {
            let k = Knowledge {
                buffer,
                reply,
                health: Health::default(),
            };
            k.attach().then_some(k)
        });
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
        files,
        knowledge,
        mailboxes: Mailboxes::default(),
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
        // Before starting any: a subtask of an ended goal never starts.
        r.cancel_orphans();
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
