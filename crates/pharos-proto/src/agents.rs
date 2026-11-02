//! The agent runtime's interface, version 1 (agents.md): requests from
//! agents and from control clients, and their replies. Every request is a
//! `call` except `ATTACH` ([`crate::op::ATTACH`]), a plain `send` carrying
//! the client's buffer for task input, results, and prompts.
//!
//! The badge says who calls: an agent's is its slot plus one
//! ([`agent_slot`]), a control client's is [`CONTROL`] or above. `INFER`
//! and `NEXT` answer with the inference service's own reply
//! ([`crate::infer::Started`], [`crate::infer::Tokens`]) and status codes.
//! Durable tasks, checkpoints, and idempotency keys come with #99.

use crate::{Reader, Refused, Writer, op as common, split, status};

pub const NAME: &[u8] = b"agents";
pub const VERSION: u8 = 1;

/// Operation codes. Gaps are kept for #99's (`CHECKPOINT`, `BEGIN`,
/// `END`, `FORGET`).
pub mod op {
    pub const TASK: u8 = 1;
    pub const COMPLETE: u8 = 5;
    pub const FAIL: u8 = 6;
    pub const INFER: u8 = 7;
    pub const NEXT: u8 = 8;
    pub const CANCEL_INFER: u8 = 9;
    pub const LOG: u8 = 10;
    pub const SUBMIT: u8 = 16;
    pub const STATUS: u8 = 17;
    pub const CANCEL: u8 = 18;
}

/// The interface's own status code: the caller has no task, inference
/// session, or task of that number.
pub const NO_SESSION: u8 = status::OWN;

/// Agent slots: badges 1 to 16.
pub const SLOTS: usize = 16;
/// Most agents running at once.
pub const MAX_RUNNING: usize = 4;
/// The first control client's badge.
pub const CONTROL: u32 = 0x100;
/// Most tasks kept.
pub const MAX_TASKS: usize = 256;
/// Longest `LOG` line and `FAIL` reason.
pub const MAX_TEXT: usize = 200;
/// Largest task input and result.
pub const MAX_INPUT: u32 = 4096;
pub const MAX_RESULT: u32 = 4096;
/// Largest buffer a client may attach.
pub const MAX_BUFFER: u64 = 64 << 10;

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
    /// Agent: its task, input copied into its buffer.
    Task,
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
    /// Control: a new task for agent `name`, input from the buffer.
    Submit {
        name: &'a [u8],
        input_len: u32,
    },
    /// Control: a task's state; its result is copied into the buffer.
    Status {
        task: u32,
    },
    /// Control: cancels a task, stopping its agent.
    Cancel {
        task: u32,
    },
    Attach {
        len: u64,
    },
    Info,
}

pub fn parse(msg: &[u8]) -> Result<Request<'_>, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = (|| {
        Some(match code {
            op::TASK => Request::Task,
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
                Request::Submit {
                    name: r.take(n).filter(|n| crate::trust::valid_name(n))?,
                    input_len: r.u32()?,
                }
            }
            op::STATUS => Request::Status { task: r.u32()? },
            op::CANCEL => Request::Cancel { task: r.u32()? },
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
        Request::Submit { name, input_len } => {
            if !crate::trust::valid_name(name) {
                return None;
            }
            head(&mut w, op::SUBMIT)?;
            w.bytes(&[name.len() as u8])?;
            w.bytes(name)?;
            w.u32(input_len)?;
        }
        Request::Status { task } => {
            head(&mut w, op::STATUS)?;
            w.u32(task)?;
        }
        Request::Cancel { task } => {
            head(&mut w, op::CANCEL)?;
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

/// The `TASK` reply: `[OK, task u32, attempt u8, input length u32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assigned {
    pub task: u32,
    pub attempt: u8,
    pub input_len: u32,
}

impl Assigned {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK])?;
        w.u32(self.task)?;
        w.bytes(&[self.attempt])?;
        w.u32(self.input_len)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let a = Self {
            task: r.u32()?,
            attempt: r.u8()?,
            input_len: r.u32()?,
        };
        (ok && r.is_empty() && a.input_len <= MAX_INPUT).then_some(a)
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
            },
            Request::Status { task: 9 },
            Request::Cancel { task: u32::MAX },
            Request::Attach { len: 1 << 16 },
            Request::Info,
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
        assert_eq!(
            parse(&[VERSION, op::TASK, 0]),
            Err(Refused::Bad),
            "trailing"
        );
        assert_eq!(encode(&Request::Log { text: b"" }, &mut [0; 8]), None);
        let bad = Request::Submit {
            name: b"x y",
            input_len: 0,
        };
        assert_eq!(encode(&bad, &mut [0; 64]), None);
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
        });
    }

    #[test]
    fn replies_round_trip() {
        let mut out = [0u8; 32];
        let a = Assigned {
            task: 3,
            attempt: 2,
            input_len: MAX_INPUT,
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
    fn badges_name_slots() {
        assert_eq!(agent_slot(0), None);
        assert_eq!(agent_slot(1), Some(0));
        assert_eq!(agent_slot(16), Some(15));
        assert_eq!(agent_slot(17), None);
        assert_eq!(agent_slot(CONTROL), None);
    }
}
