//! The agent runtime's interface, version 1 (agents.md): requests from
//! agents and from control clients, and their replies. Every request is a
//! `call` except `ATTACH` ([`crate::op::ATTACH`]), a plain `send` carrying
//! the client's buffer for task input, results, and prompts.
//!
//! The badge says who calls: an agent's is its slot plus one
//! ([`agent_slot`]), a control client's is [`CONTROL`] or above. `INFER`
//! and `NEXT` answer with the inference service's own reply
//! ([`crate::infer::Started`], [`crate::infer::Tokens`]) and status codes.
//!
//! An agent's buffer holds its task's input at 0 and its last checkpoint
//! at [`CHECKPOINT_AT`]; `CHECKPOINT` takes the new one from there too.
//!
//! `trust` sends `REVOKE` with a plain `send` under [`TRUST`] (#105); the
//! runtime answers with `trust`'s `REVOKED`, never a reply, so `trust`
//! never waits on it.
//!
//! Networking (#109): `SEND_TO` sends the first bytes of the agent's
//! buffer to one granted destination; `RECEIVE_FROM` copies the oldest
//! datagram waiting for the agent into its buffer ([`Datagram`]), or
//! answers `NOT_FOUND` at once. Only replies from a granted destination
//! the agent sent to last are kept for it.
//!
//! Tools (#126, tools.md): `TOOL` names a tool call's text in the agent's
//! buffer (`call_at`, `call_len`, at most [`crate::tool::MAX_CALL`]) and
//! where its result goes (`result_at`); the reply is `[OK, length u32]`,
//! the result's bytes at `result_at`.
//!
//! Messages (#133, coordination.md): `MESSAGE_SEND` sends the first `len`
//! bytes of the agent's buffer (at most [`MAX_MESSAGE`]) with a kind byte
//! to a named agent it holds `channel` for; `MESSAGE_RECEIVE` copies the
//! oldest message waiting for it into its buffer ([`Message`]), or answers
//! `NOT_FOUND` at once. A message carries data only.

use crate::{Reader, Refused, Writer, op as common, split, status};

pub const NAME: &[u8] = b"agents";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    pub const TASK: u8 = 1;
    pub const CHECKPOINT: u8 = 2;
    pub const BEGIN: u8 = 3;
    pub const END: u8 = 4;
    pub const COMPLETE: u8 = 5;
    pub const FAIL: u8 = 6;
    pub const INFER: u8 = 7;
    pub const NEXT: u8 = 8;
    pub const CANCEL_INFER: u8 = 9;
    pub const LOG: u8 = 10;
    pub const DATA_PUT: u8 = 11;
    pub const DATA_GET: u8 = 12;
    pub const ASK: u8 = 13;
    pub const SEND_TO: u8 = 14;
    pub const RECEIVE_FROM: u8 = 15;
    pub const SUBMIT: u8 = 16;
    pub const STATUS: u8 = 17;
    pub const CANCEL: u8 = 18;
    pub const FORGET: u8 = 19;
    pub const REVOKE: u8 = 20;
    pub const ANSWER: u8 = 21;
    /// `trust`: what each running agent and each group uses (#119).
    pub const USAGE: u8 = 22;
    /// A tool call (#126, tools.md).
    pub const TOOL: u8 = 23;
    /// Messages between agents (#133, coordination.md).
    pub const MESSAGE_SEND: u8 = 24;
    pub const MESSAGE_RECEIVE: u8 = 25;
}

/// The `ASK` reply's outcome, after `OK` (#106).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Asked {
    /// Held now (already, or approved).
    Granted = 0,
    /// Not askable, refused, revoked, or not answered in time.
    Refused = 1,
    /// Waiting for the user: ask again.
    Pending = 2,
}

impl Asked {
    pub fn encode(self, out: &mut [u8]) -> Option<usize> {
        out.get_mut(..2)?.copy_from_slice(&[status::OK, self as u8]);
        Some(2)
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        match reply {
            [status::OK, 0] => Some(Self::Granted),
            [status::OK, 1] => Some(Self::Refused),
            [status::OK, 2] => Some(Self::Pending),
            _ => None,
        }
    }
}

/// The interface's own status code: the caller has no task, inference
/// session, or task of that number.
pub const NO_SESSION: u8 = status::OWN;
/// Refused: the audit trail could not record the action (#108, D-012
/// item 11).
pub const NO_AUDIT: u8 = status::OWN + 1;
/// `TOOL` (#128): a sensitive call waits for the user's answer; send the
/// same call again.
pub const PENDING: u8 = status::OWN + 2;
/// `TOOL` (#128): the user refused the call, or did not answer in time.
pub const REFUSED: u8 = status::OWN + 3;

/// Largest datagram an agent sends or receives.
pub const MAX_DATAGRAM: u32 = crate::net::MAX_PAYLOAD as u32;

/// The `RECEIVE_FROM` reply: `[OK, source IPv4, source port u16, length
/// u32]`; the payload is at the start of the agent's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub addr: [u8; 4],
    pub port: u16,
    pub len: u32,
}

impl Datagram {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK])?;
        w.bytes(&self.addr)?;
        w.u16(self.port)?;
        w.u32(self.len)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let d = Self {
            addr: r.take(4)?.try_into().ok()?,
            port: r.u16()?,
            len: r.u32()?,
        };
        (ok && r.is_empty() && d.len <= MAX_DATAGRAM).then_some(d)
    }
}

/// Largest message between agents (#133).
pub const MAX_MESSAGE: u32 = 1024;

/// The `MESSAGE_RECEIVE` reply: `[OK, sender name length, sender, kind,
/// length u32]`; the bytes are at the start of the agent's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub from: &'a [u8],
    pub kind: u8,
    pub len: u32,
}

impl<'a> Message<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK])?;
        write_name(&mut w, self.from)?;
        w.bytes(&[self.kind])?;
        w.u32(self.len)?;
        Some(w.len())
    }
    pub fn parse(reply: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let m = Self {
            from: name(&mut r)?,
            kind: r.u8()?,
            len: r.u32()?,
        };
        (ok && r.is_empty() && m.len <= MAX_MESSAGE).then_some(m)
    }
}

/// Agent slots: badges 1 to 16.
pub const SLOTS: usize = 16;
/// Most agents running at once.
pub const MAX_RUNNING: usize = 4;
/// The first control client's badge.
pub const CONTROL: u32 = 0x100;
/// The badge on the capability the runtime gives `trust` (#105).
pub const TRUST: u32 = 0x80;
/// Largest file an agent keeps with `DATA_PUT`.
pub const MAX_DATA: u32 = 64 << 10;
/// Most tasks kept.
pub const MAX_TASKS: usize = 256;
/// Longest `LOG` line and `FAIL` reason.
pub const MAX_TEXT: usize = 200;
/// Largest task input and result.
pub const MAX_INPUT: u32 = 4096;
pub const MAX_RESULT: u32 = 4096;
/// Largest checkpoint.
pub const MAX_CHECKPOINT: u32 = 64 << 10;
/// Where a checkpoint sits in an agent's buffer.
pub const CHECKPOINT_AT: u32 = MAX_INPUT;
/// Largest buffer a client may attach: input and checkpoint.
pub const MAX_BUFFER: u64 = CHECKPOINT_AT as u64 + MAX_CHECKPOINT as u64;
/// Most tasks one task may depend on.
pub const MAX_DEPS: usize = 4;
/// An idempotency key's length.
pub const KEY: usize = 16;
/// Most keys per task.
pub const MAX_KEYS: usize = 32;
/// Largest recorded result of a keyed operation.
pub const MAX_KEY_RESULT: usize = 64;

/// The tasks a submitted task depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deps {
    ids: [u32; MAX_DEPS],
    len: u8,
}

impl Deps {
    pub const NONE: Self = Self {
        ids: [0; MAX_DEPS],
        len: 0,
    };

    /// `None` if there are more than [`MAX_DEPS`].
    pub fn new(ids: &[u32]) -> Option<Self> {
        let mut d = Self {
            ids: [0; MAX_DEPS],
            len: u8::try_from(ids.len()).ok()?,
        };
        d.ids.get_mut(..ids.len())?.copy_from_slice(ids);
        Some(d)
    }
    pub fn as_slice(&self) -> &[u32] {
        &self.ids[..usize::from(self.len)]
    }
}

/// The agent slot a badge names, if it is an agent's.
pub fn agent_slot(badge: u32) -> Option<usize> {
    (1..=SLOTS as u32)
        .contains(&badge)
        .then(|| badge as usize - 1)
}

/// Text for `LOG` and `FAIL`: 1 to [`MAX_TEXT`] printable ASCII bytes.
pub fn valid_text(text: &[u8]) -> bool {
    (1..=MAX_TEXT).contains(&text.len()) && text.iter().all(|b| (b' '..=b'~').contains(b))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// Agent: its task, input and last checkpoint copied into its buffer.
    Task,
    /// Agent: the first `len` bytes at [`CHECKPOINT_AT`] become its task's
    /// checkpoint; `OK` once stored.
    Checkpoint {
        len: u32,
    },
    /// Agent: starts the operation named `key`: `GO`, `DONE` with its
    /// recorded result, or `UNKNOWN` ([`Begun`]).
    Begin {
        key: [u8; KEY],
    },
    /// Agent: records the result of the operation `key` begun.
    End {
        key: [u8; KEY],
        result: &'a [u8],
    },
    /// Agent: ends its task with the first `len` bytes of its buffer.
    Complete {
        len: u32,
    },
    /// Agent: ends its task as failed.
    Fail {
        reason: &'a [u8],
    },
    /// Agent: generate from the first `prompt_len` bytes of its buffer.
    Infer {
        model: u8,
        max_new: u16,
        prompt_len: u32,
    },
    /// Agent: the next text of its session.
    Next,
    /// Agent: cancels its session.
    CancelInfer,
    /// Agent: one console line.
    Log {
        text: &'a [u8],
    },
    /// Agent: the first `len` bytes of its buffer become its file `name`
    /// (needs `data write`).
    DataPut {
        name: &'a [u8],
        len: u32,
    },
    /// Agent: its file `name` into its buffer; the reply is `[OK, length]`
    /// (needs `data read`).
    DataGet {
        name: &'a [u8],
    },
    /// Agent: asks for `permission` beyond what it was given, for
    /// `for_ms` milliseconds (0: the rest of the task); the reply is
    /// [`Asked`] (#106).
    Ask {
        permission: crate::permission::Permission,
        for_ms: u32,
    },
    /// Agent: the first `len` bytes of its buffer as one UDP datagram to
    /// `addr:port` (needs `net addr:port`).
    SendTo {
        addr: [u8; 4],
        port: u16,
        len: u32,
    },
    /// Agent: the oldest datagram waiting for it, into its buffer.
    ReceiveFrom,
    /// Agent: the first `len` bytes of its buffer, with `kind`, to agent
    /// `to` (needs `channel <to>`, #133).
    MessageSend {
        to: &'a [u8],
        kind: u8,
        len: u32,
    },
    /// Agent: the oldest message waiting for it, into its buffer.
    MessageReceive,
    /// Agent: the tool call in its buffer at `call_at`, `call_len` bytes;
    /// the result goes to `result_at` (#126).
    Tool {
        call_at: u32,
        call_len: u16,
        result_at: u32,
    },
    /// `trust`: the user's answer to approval request `number`.
    Answer {
        number: u16,
        yes: bool,
    },
    /// `trust`: send `trust` what each running attempt and group uses.
    Usage,
    /// `trust`: takes `permission` from every running agent `name`.
    Revoke {
        name: &'a [u8],
        permission: crate::permission::Permission,
    },
    /// Control: a new task for agent `name`, input from the buffer, run
    /// once every task in `deps` is done.
    Submit {
        name: &'a [u8],
        input_len: u32,
        deps: Deps,
    },
    /// Control: a task's state; its result is copied into the buffer.
    Status {
        task: u32,
    },
    /// Control: cancels a task, stopping its agent.
    Cancel {
        task: u32,
    },
    /// Control: deletes an ended task's record.
    Forget {
        task: u32,
    },
    Attach {
        len: u64,
    },
    Info,
}

/// A length-prefixed agent or file name.
fn name<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let n = usize::from(r.u8()?);
    r.take(n).filter(|n| crate::trust::valid_name(n))
}

fn write_name(w: &mut Writer<'_>, name: &[u8]) -> Option<()> {
    if !crate::trust::valid_name(name) {
        return None;
    }
    w.bytes(&[name.len() as u8])?;
    w.bytes(name)
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = (|| {
        Some(match code {
            op::TASK => Request::Task,
            op::CHECKPOINT => Request::Checkpoint { len: r.u32()? },
            op::BEGIN => Request::Begin {
                key: r.take(KEY)?.try_into().ok()?,
            },
            op::END => {
                let key = r.take(KEY)?.try_into().ok()?;
                let n = usize::from(r.u8()?);
                Request::End {
                    key,
                    result: r.take(n).filter(|_| n <= MAX_KEY_RESULT)?,
                }
            }
            op::COMPLETE => Request::Complete { len: r.u32()? },
            op::FAIL => Request::Fail {
                reason: Some(r.rest()).filter(|t| valid_text(t))?,
            },
            op::INFER => Request::Infer {
                model: r.u8()?,
                max_new: r.u16()?,
                prompt_len: r.u32()?,
            },
            op::NEXT => Request::Next,
            op::CANCEL_INFER => Request::CancelInfer,
            op::LOG => Request::Log {
                text: Some(r.rest()).filter(|t| valid_text(t))?,
            },
            op::SUBMIT => {
                let n = usize::from(r.u8()?);
                let name = r.take(n).filter(|n| crate::trust::valid_name(n))?;
                let input_len = r.u32()?;
                let mut ids = [0u32; MAX_DEPS];
                let count = usize::from(r.u8()?);
                for id in ids.get_mut(..count)? {
                    *id = r.u32()?;
                }
                Request::Submit {
                    name,
                    input_len,
                    deps: Deps::new(&ids[..count])?,
                }
            }
            op::DATA_PUT => Request::DataPut {
                name: name(&mut r)?,
                len: r.u32()?,
            },
            op::DATA_GET => Request::DataGet {
                name: name(&mut r)?,
            },
            op::ASK => Request::Ask {
                permission: crate::permission::Permission::read(&mut r)?,
                for_ms: r.u32()?,
            },
            op::SEND_TO => Request::SendTo {
                addr: r.take(4)?.try_into().ok()?,
                port: r.u16()?,
                len: r.u32()?,
            },
            op::RECEIVE_FROM => Request::ReceiveFrom,
            op::USAGE => Request::Usage,
            op::MESSAGE_SEND => Request::MessageSend {
                to: name(&mut r)?,
                kind: r.u8()?,
                len: r.u32().filter(|n| *n <= MAX_MESSAGE)?,
            },
            op::MESSAGE_RECEIVE => Request::MessageReceive,
            op::TOOL => Request::Tool {
                call_at: r.u32()?,
                call_len: r
                    .u16()
                    .filter(|n| usize::from(*n) <= crate::tool::MAX_CALL)?,
                result_at: r.u32()?,
            },
            op::ANSWER => Request::Answer {
                number: r.u16()?,
                yes: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return None,
                },
            },
            op::REVOKE => Request::Revoke {
                name: name(&mut r)?,
                permission: crate::permission::Permission::read(&mut r)?,
            },
            op::STATUS => Request::Status { task: r.u32()? },
            op::CANCEL => Request::Cancel { task: r.u32()? },
            op::FORGET => Request::Forget { task: r.u32()? },
            common::ATTACH => Request::Attach { len: r.u64()? },
            common::INFO => Request::Info,
            _ => return None,
        })
    })();
    match req {
        Some(req) if r.is_empty() => Ok(req),
        _ => Err(Refused::Bad),
    }
}

pub fn encode(req: &Request<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    let head = |w: &mut Writer<'_>, code| w.bytes(&[VERSION, code]);
    match *req {
        Request::Task => head(&mut w, op::TASK)?,
        Request::Checkpoint { len } => {
            head(&mut w, op::CHECKPOINT)?;
            w.u32(len)?;
        }
        Request::Begin { key } => {
            head(&mut w, op::BEGIN)?;
            w.bytes(&key)?;
        }
        Request::End { key, result } => {
            if result.len() > MAX_KEY_RESULT {
                return None;
            }
            head(&mut w, op::END)?;
            w.bytes(&key)?;
            w.bytes(&[result.len() as u8])?;
            w.bytes(result)?;
        }
        Request::Complete { len } => {
            head(&mut w, op::COMPLETE)?;
            w.u32(len)?;
        }
        Request::Fail { reason } | Request::Log { text: reason } => {
            if !valid_text(reason) {
                return None;
            }
            let code = if matches!(req, Request::Fail { .. }) {
                op::FAIL
            } else {
                op::LOG
            };
            head(&mut w, code)?;
            w.bytes(reason)?;
        }
        Request::Infer {
            model,
            max_new,
            prompt_len,
        } => {
            head(&mut w, op::INFER)?;
            w.bytes(&[model])?;
            w.u16(max_new)?;
            w.u32(prompt_len)?;
        }
        Request::Next => head(&mut w, op::NEXT)?,
        Request::CancelInfer => head(&mut w, op::CANCEL_INFER)?,
        Request::Submit {
            name,
            input_len,
            deps,
        } => {
            if !crate::trust::valid_name(name) {
                return None;
            }
            head(&mut w, op::SUBMIT)?;
            w.bytes(&[name.len() as u8])?;
            w.bytes(name)?;
            w.u32(input_len)?;
            w.bytes(&[deps.len])?;
            for id in deps.as_slice() {
                w.u32(*id)?;
            }
        }
        Request::DataPut { name, len } => {
            head(&mut w, op::DATA_PUT)?;
            write_name(&mut w, name)?;
            w.u32(len)?;
        }
        Request::DataGet { name } => {
            head(&mut w, op::DATA_GET)?;
            write_name(&mut w, name)?;
        }
        Request::Ask { permission, for_ms } => {
            head(&mut w, op::ASK)?;
            permission.write(&mut w)?;
            w.u32(for_ms)?;
        }
        Request::SendTo { addr, port, len } => {
            head(&mut w, op::SEND_TO)?;
            w.bytes(&addr)?;
            w.u16(port)?;
            w.u32(len)?;
        }
        Request::ReceiveFrom => head(&mut w, op::RECEIVE_FROM)?,
        Request::Usage => head(&mut w, op::USAGE)?,
        Request::MessageSend { to, kind, len } => {
            if len > MAX_MESSAGE {
                return None;
            }
            head(&mut w, op::MESSAGE_SEND)?;
            write_name(&mut w, to)?;
            w.bytes(&[kind])?;
            w.u32(len)?;
        }
        Request::MessageReceive => head(&mut w, op::MESSAGE_RECEIVE)?,
        Request::Tool {
            call_at,
            call_len,
            result_at,
        } => {
            if usize::from(call_len) > crate::tool::MAX_CALL {
                return None;
            }
            head(&mut w, op::TOOL)?;
            w.u32(call_at)?;
            w.u16(call_len)?;
            w.u32(result_at)?;
        }
        Request::Answer { number, yes } => {
            head(&mut w, op::ANSWER)?;
            w.u16(number)?;
            w.bytes(&[u8::from(yes)])?;
        }
        Request::Revoke { name, permission } => {
            head(&mut w, op::REVOKE)?;
            write_name(&mut w, name)?;
            permission.write(&mut w)?;
        }
        Request::Status { task } => {
            head(&mut w, op::STATUS)?;
            w.u32(task)?;
        }
        Request::Cancel { task } | Request::Forget { task } => {
            let code = if matches!(req, Request::Cancel { .. }) {
                op::CANCEL
            } else {
                op::FORGET
            };
            head(&mut w, code)?;
            w.u32(task)?;
        }
        Request::Attach { len } => {
            head(&mut w, common::ATTACH)?;
            w.u64(len)?;
        }
        Request::Info => head(&mut w, common::INFO)?,
    }
    Some(w.len())
}

/// A task's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Pending = 1,
    Running = 2,
    Done = 3,
    Failed = 4,
    Cancelled = 5,
}

impl State {
    pub fn from_code(code: u8) -> Option<Self> {
        [
            Self::Pending,
            Self::Running,
            Self::Done,
            Self::Failed,
            Self::Cancelled,
        ]
        .into_iter()
        .find(|s| *s as u8 == code)
    }
}

/// The `TASK` reply: `[OK, task u32, attempt u8, input length u32,
/// checkpoint length u32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assigned {
    pub task: u32,
    pub attempt: u8,
    pub input_len: u32,
    pub checkpoint_len: u32,
}

impl Assigned {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK])?;
        w.u32(self.task)?;
        w.bytes(&[self.attempt])?;
        w.u32(self.input_len)?;
        w.u32(self.checkpoint_len)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let a = Self {
            task: r.u32()?,
            attempt: r.u8()?,
            input_len: r.u32()?,
            checkpoint_len: r.u32()?,
        };
        let fits = a.input_len <= MAX_INPUT && a.checkpoint_len <= MAX_CHECKPOINT;
        (ok && r.is_empty() && fits).then_some(a)
    }
}

/// The `BEGIN` reply: `[OK, outcome]`, then for `DONE` the result's
/// length and the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begun<'a> {
    /// Not begun before: go ahead (the key is now recorded as begun).
    Go,
    /// Done before, with this result: do not repeat it.
    Done(&'a [u8]),
    /// Begun before but never ended: it may or may not have happened.
    Unknown,
}

impl<'a> Begun<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        match *self {
            Self::Go => w.bytes(&[status::OK, 1])?,
            Self::Done(result) => {
                if result.len() > MAX_KEY_RESULT {
                    return None;
                }
                w.bytes(&[status::OK, 2, result.len() as u8])?;
                w.bytes(result)?;
            }
            Self::Unknown => w.bytes(&[status::OK, 3])?,
        }
        Some(w.len())
    }
    pub fn parse(reply: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        if r.u8()? != status::OK {
            return None;
        }
        let b = match r.u8()? {
            1 => Self::Go,
            2 => {
                let n = usize::from(r.u8()?);
                Self::Done(r.take(n).filter(|_| n <= MAX_KEY_RESULT)?)
            }
            3 => Self::Unknown,
            _ => return None,
        };
        r.is_empty().then_some(b)
    }
}

/// The `SUBMIT` reply: `[OK, task u32]`.
pub fn submitted(task: u32, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.bytes(&[status::OK])?;
    w.u32(task)?;
    Some(w.len())
}

pub fn parse_submitted(reply: &[u8]) -> Option<u32> {
    let mut r = Reader::new(reply);
    let ok = r.u8()? == status::OK;
    let task = r.u32()?;
    (ok && r.is_empty()).then_some(task)
}

/// The `STATUS` reply: `[OK, state, attempts, result length u32]`. The
/// result (or a failure's reason) is in the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskStatus {
    pub state: State,
    pub attempts: u8,
    pub result_len: u32,
}

impl TaskStatus {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK, self.state as u8, self.attempts])?;
        w.u32(self.result_len)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let s = Self {
            state: State::from_code(r.u8()?)?,
            attempts: r.u8()?,
            result_len: r.u32()?,
        };
        (ok && r.is_empty() && s.result_len <= MAX_RESULT).then_some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let long = [b'x'; MAX_TEXT];
        for req in [
            Request::Task,
            Request::Complete { len: 7 },
            Request::Fail { reason: b"no luck" },
            Request::Fail { reason: &long },
            Request::Infer {
                model: 2,
                max_new: 20,
                prompt_len: 11,
            },
            Request::Next,
            Request::CancelInfer,
            Request::Log { text: b"step 1" },
            Request::Submit {
                name: b"worker",
                input_len: 4096,
                deps: Deps::new(&[]).unwrap(),
            },
            Request::Submit {
                name: b"w",
                input_len: 0,
                deps: Deps::new(&[1, 2, 3, u32::MAX]).unwrap(),
            },
            Request::Status { task: 9 },
            Request::Cancel { task: u32::MAX },
            Request::Forget { task: 4 },
            Request::Checkpoint {
                len: MAX_CHECKPOINT,
            },
            Request::Begin { key: [7; KEY] },
            Request::End {
                key: [1; KEY],
                result: b"",
            },
            Request::End {
                key: [2; KEY],
                result: &[b'r'; MAX_KEY_RESULT],
            },
            Request::Attach { len: 1 << 16 },
            Request::Info,
            Request::DataPut {
                name: b"notes",
                len: MAX_DATA,
            },
            Request::DataGet { name: &[b'n'; 32] },
            Request::Revoke {
                name: b"worker",
                permission: crate::permission::Permission::Model(2),
            },
            Request::Ask {
                permission: crate::permission::Permission::DataWrite,
                for_ms: 0,
            },
            Request::Ask {
                permission: crate::permission::Permission::Model(3),
                for_ms: u32::MAX,
            },
            Request::Answer {
                number: 7,
                yes: true,
            },
            Request::SendTo {
                addr: [10, 0, 2, 2],
                port: 47_000,
                len: MAX_DATAGRAM,
            },
            Request::ReceiveFrom,
            Request::Usage,
            Request::MessageSend {
                to: &[b'l'; 32],
                kind: u8::MAX,
                len: MAX_MESSAGE,
            },
            Request::MessageReceive,
            Request::Tool {
                call_at: 4096,
                call_len: crate::tool::MAX_CALL as u16,
                result_at: u32::MAX,
            },
            Request::Revoke {
                name: b"w",
                permission: crate::permission::Permission::file(&[b'f'; 32]).unwrap(),
            },
            Request::Ask {
                permission: crate::permission::Permission::file(b"report.txt").unwrap(),
                for_ms: 1,
            },
            Request::Answer {
                number: u16::MAX,
                yes: false,
            },
            Request::Revoke {
                name: b"w",
                permission: crate::permission::Permission::Net {
                    addr: [10, 0, 2, 2],
                    port: 1,
                },
            },
        ] {
            let mut buf = [0u8; 256];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(parse(&buf[..n]), Ok(req), "{req:?}");
            let mut other = buf;
            other[0] = VERSION + 1;
            assert_eq!(parse(&other[..n]), Err(Refused::Version));
            // Text requests take the rest, so only the fixed ones refuse
            // a trailing byte.
            if !matches!(req, Request::Fail { .. } | Request::Log { .. }) {
                assert_eq!(parse(&buf[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
                if n > 2 {
                    assert!(parse(&buf[..n - 1]).is_err(), "{req:?} truncated");
                }
            }
        }
    }

    #[test]
    fn bad_requests_are_refused() {
        let text = |code: u8, t: &[u8]| {
            let mut m = std::vec![VERSION, code];
            m.extend_from_slice(t);
            m
        };
        for code in [op::FAIL, op::LOG] {
            assert_eq!(parse(&text(code, b"")), Err(Refused::Bad), "empty");
            assert_eq!(parse(&text(code, &[b'x'; 201])), Err(Refused::Bad), "long");
            assert_eq!(parse(&text(code, b"a\nb")), Err(Refused::Bad), "newline");
            assert_eq!(parse(&text(code, b"\x1b[2J")), Err(Refused::Bad), "escape");
        }
        assert_eq!(
            parse(&[VERSION, op::SUBMIT, 3, b'a', b' ', b'b', 0, 0, 0, 0]),
            Err(Refused::Bad)
        );
        assert_eq!(
            parse(&[VERSION, op::SUBMIT, 0, 0, 0, 0, 0]),
            Err(Refused::Bad),
            "no name"
        );
        assert_eq!(
            parse(&[VERSION, op::SUBMIT, 9, b'a']),
            Err(Refused::Bad),
            "truncated"
        );
        assert_eq!(parse(&[VERSION, op::STATUS, 1, 2, 3]), Err(Refused::Bad));
        assert_eq!(parse(&[VERSION, 99]), Err(Refused::Bad), "unknown op");
        let mut long = [0u8; 12];
        long[..2].copy_from_slice(&[VERSION, op::TOOL]);
        long[6..8].copy_from_slice(&(crate::tool::MAX_CALL as u16 + 1).to_le_bytes());
        assert_eq!(parse(&long), Err(Refused::Bad), "a call over 1 KiB");
        let mut over = std::vec![VERSION, op::MESSAGE_SEND, 1, b'a', 0];
        over.extend_from_slice(&(MAX_MESSAGE + 1).to_le_bytes());
        assert_eq!(parse(&over), Err(Refused::Bad), "a message over 1 KiB");
        assert_eq!(
            parse(&[VERSION, op::MESSAGE_SEND, 1, b'.', 0, 1, 0, 0, 0]),
            Err(Refused::Bad),
            "a bad name"
        );
        let m = Message {
            from: b"talker",
            kind: 3,
            len: MAX_MESSAGE,
        };
        let mut out = [0u8; 64];
        let n = m.encode(&mut out).unwrap();
        assert_eq!(Message::parse(&out[..n]), Some(m));
        assert_eq!(Message::parse(&out[..n - 1]), None);
        out[n - 2] = 0x10;
        assert_eq!(Message::parse(&out[..n]), None, "over 1 KiB");
        assert_eq!(
            parse(&[VERSION, op::TASK, 0]),
            Err(Refused::Bad),
            "trailing"
        );
        assert_eq!(encode(&Request::Log { text: b"" }, &mut [0; 8]), None);
        let bad = Request::Submit {
            name: b"x y",
            input_len: 0,
            deps: Deps::new(&[]).unwrap(),
        };
        assert_eq!(encode(&bad, &mut [0; 64]), None);
        assert_eq!(Deps::new(&[1; MAX_DEPS + 1]), None, "five dependencies");
        let mut submit = std::vec![VERSION, op::SUBMIT, 1, b'a', 0, 0, 0, 0, 5];
        submit.extend_from_slice(&[0; 20]);
        assert_eq!(parse(&submit), Err(Refused::Bad), "five dependencies");
        let mut end = std::vec![VERSION, op::END];
        end.extend_from_slice(&[0; KEY]);
        end.push(65);
        end.extend_from_slice(&[b'r'; 65]);
        assert_eq!(parse(&end), Err(Refused::Bad), "a 65-byte result");
        let long = Request::End {
            key: [0; KEY],
            result: &[0; 65],
        };
        assert_eq!(encode(&long, &mut [0; 256]), None);
        assert_eq!(
            parse(&[VERSION, op::BEGIN, 1, 2]),
            Err(Refused::Bad),
            "short key"
        );
        crate::fuzz(100_000, 255, |m| {
            match parse(m) {
                Ok(Request::Fail { reason: t } | Request::Log { text: t }) => {
                    assert!(valid_text(t))
                }
                Ok(Request::Submit { name, .. }) => assert!(crate::trust::valid_name(name)),
                _ => {}
            }
            let mut v = std::vec![VERSION];
            v.extend_from_slice(m);
            let _ = parse(&v);
            let _ = Assigned::parse(m);
            let _ = TaskStatus::parse(m);
            let _ = parse_submitted(m);
            if let Some(Begun::Done(r)) = Begun::parse(m) {
                assert!(r.len() <= MAX_KEY_RESULT);
            }
        });
    }

    #[test]
    fn replies_round_trip() {
        let mut out = [0u8; 32];
        let a = Assigned {
            task: 3,
            attempt: 2,
            input_len: MAX_INPUT,
            checkpoint_len: MAX_CHECKPOINT,
        };
        let n = a.encode(&mut out).unwrap();
        assert_eq!(Assigned::parse(&out[..n]), Some(a));
        assert_eq!(Assigned::parse(&out[..n - 1]), None);
        let big = Assigned {
            input_len: MAX_INPUT + 1,
            ..a
        };
        let n = big.encode(&mut out).unwrap();
        assert_eq!(Assigned::parse(&out[..n]), None, "input over the limit");
        let big = Assigned {
            checkpoint_len: MAX_CHECKPOINT + 1,
            ..a
        };
        let n = big.encode(&mut out).unwrap();
        assert_eq!(
            Assigned::parse(&out[..n]),
            None,
            "checkpoint over the limit"
        );
        let mut wide = [0u8; 128];
        for b in [
            Begun::Go,
            Begun::Unknown,
            Begun::Done(b""),
            Begun::Done(&[b'x'; 64]),
        ] {
            let n = b.encode(&mut wide).unwrap();
            assert_eq!(Begun::parse(&wide[..n]), Some(b));
            assert_eq!(Begun::parse(&wide[..n + 1]), None, "trailing");
        }
        assert_eq!(Begun::Done(&[0; 65]).encode(&mut wide), None);
        assert_eq!(Begun::parse(&[status::OK, 4]), None, "unknown outcome");
        assert_eq!(Begun::parse(&[status::BUSY]), None);

        let n = submitted(77, &mut out).unwrap();
        assert_eq!(parse_submitted(&out[..n]), Some(77));
        assert_eq!(parse_submitted(&[status::NOT_FOUND]), None);

        let s = TaskStatus {
            state: State::Failed,
            attempts: 3,
            result_len: 17,
        };
        let n = s.encode(&mut out).unwrap();
        assert_eq!(TaskStatus::parse(&out[..n]), Some(s));
        out[1] = 9;
        assert_eq!(TaskStatus::parse(&out[..n]), None, "unknown state");
        for code in 1..=5 {
            assert_eq!(State::from_code(code).map(|s| s as u8), Some(code));
        }
    }

    #[test]
    fn ask_replies_round_trip() {
        for a in [Asked::Granted, Asked::Refused, Asked::Pending] {
            let mut out = [0u8; 4];
            let n = a.encode(&mut out).unwrap();
            assert_eq!(Asked::parse(&out[..n]), Some(a));
        }
        assert_eq!(Asked::parse(&[status::OK, 3]), None);
        assert_eq!(Asked::parse(&[status::NO_ACCESS, 0]), None);
    }

    #[test]
    fn datagram_replies_round_trip() {
        let mut out = [0u8; 16];
        let d = Datagram {
            addr: [10, 0, 2, 2],
            port: 47_000,
            len: MAX_DATAGRAM,
        };
        let n = d.encode(&mut out).unwrap();
        assert_eq!(Datagram::parse(&out[..n]), Some(d));
        assert_eq!(Datagram::parse(&out[..n - 1]), None, "truncated");
        let too_long = Datagram {
            len: MAX_DATAGRAM + 1,
            ..d
        };
        let n = too_long.encode(&mut out).unwrap();
        assert_eq!(Datagram::parse(&out[..n]), None, "over the maximum");
        out[0] = status::NOT_FOUND;
        assert_eq!(Datagram::parse(&out[..n]), None);
        assert_eq!(Asked::parse(&[status::OK, 0, 0]), None);
    }

    #[test]
    fn badges_name_slots() {
        assert_eq!(agent_slot(0), None);
        assert_eq!(agent_slot(1), Some(0));
        assert_eq!(agent_slot(16), Some(15));
        assert_eq!(agent_slot(17), None);
        assert_eq!(agent_slot(CONTROL), None);
    }
}
