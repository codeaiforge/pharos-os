//! The inference interface, version 1 (inference.md): requests, replies,
//! and status codes. Every request is a `call` except `ATTACH`
//! ([`crate::op::ATTACH`]), a plain `send` carrying the client's buffer,
//! from which `GENERATE` takes the prompt. Tokens are pulled with `NEXT`.
//! Greedy decoding only, so a result can be replayed exactly.

use crate::{Reader, Refused, Writer, op as common, split, status};

pub const NAME: &[u8] = b"inference";
pub const VERSION: u8 = 1;

/// Operation codes.
pub mod op {
    pub const GENERATE: u8 = 1;
    pub const NEXT: u8 = 2;
    pub const CANCEL: u8 = 3;
    pub const RESULT: u8 = 4;
    /// From `init` only (no badge): forget client `badge`, as its process
    /// ended: its buffer, record, and any session (#100).
    pub const RELEASE: u8 = 5;
    /// A client's admission limits (#118), only without a badge.
    pub const LIMIT: u8 = 6;
}

/// Most new tokens one `GENERATE` asks for.
pub const MAX_NEW: u16 = 2048;
/// Longest prompt (bytes of UTF-8 in the attached buffer).
pub const MAX_PROMPT: u32 = 64 << 10;
/// Largest buffer a client may attach: one prompt.
pub const MAX_BUFFER: u64 = MAX_PROMPT as u64;
/// Most tokens one `NEXT` returns.
pub const NEXT_TOKENS: usize = 16;
/// Most text bytes one `NEXT` returns.
pub const MAX_TEXT: usize = 240;

/// Reply status codes: the common ones this interface uses, then its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = status::OK,
    BadRequest = status::BAD_REQUEST,
    Version = status::VERSION,
    NoAccess = status::NO_ACCESS,
    /// Another client's session is running.
    Busy = status::BUSY,
    /// Over [`MAX_NEW`] or [`MAX_PROMPT`].
    TooLarge = status::TOO_LARGE,
    /// No attached buffer, or the prompt is longer than it.
    NoBuffer = status::NO_BUFFER,
    Internal = status::INTERNAL,
    /// The model number is not in the manifest.
    NoModel = status::OWN,
    /// The model failed loading; the reply's second byte is the [`Step`].
    ModelInvalid = status::OWN + 1,
    /// Prompt plus requested tokens exceed the context the service allows.
    Context = status::OWN + 2,
    /// The session number is unknown, or not this client's.
    NoSession = status::OWN + 3,
    /// Past the client's admission limits (#118).
    OverLimit = status::OVER_LIMIT,
}

impl Status {
    pub fn from_code(code: u8) -> Self {
        [
            Self::Ok,
            Self::Version,
            Self::NoAccess,
            Self::Busy,
            Self::TooLarge,
            Self::NoBuffer,
            Self::Internal,
            Self::NoModel,
            Self::ModelInvalid,
            Self::Context,
            Self::NoSession,
            Self::OverLimit,
        ]
        .into_iter()
        .find(|s| *s as u8 == code)
        .unwrap_or(Self::BadRequest)
    }
}

/// The loading step a model failed at (`MODEL_INVALID`, `INFO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Step {
    /// The file is missing or could not be read from the store.
    Read = 1,
    /// Its size is not the manifest's.
    Size = 2,
    /// Its SHA-256 is not the manifest's.
    Hash = 3,
    /// The GGUF reader, model loader, or tokenizer refused it.
    Format = 4,
    /// A configuration value is not the manifest's.
    Config = 5,
}

impl Step {
    pub fn from_code(code: u8) -> Option<Self> {
        [
            Self::Read,
            Self::Size,
            Self::Hash,
            Self::Format,
            Self::Config,
        ]
        .into_iter()
        .find(|s| *s as u8 == code)
    }
}

/// Why generation ended (`NEXT`, `RESULT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stop {
    /// The model produced an end-of-text token.
    EndOfText = 1,
    /// The requested number of tokens was generated.
    TokenLimit = 2,
    /// `CANCEL`, or no `NEXT` for the idle time.
    Cancelled = 3,
}

impl Stop {
    pub fn from_code(code: u8) -> Option<Self> {
        [Self::EndOfText, Self::TokenLimit, Self::Cancelled]
            .into_iter()
            .find(|s| *s as u8 == code)
    }
}

/// A parsed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// Generate from the first `prompt_len` bytes of the attached buffer.
    Generate {
        model: u8,
        max_new: u16,
        prompt_len: u32,
    },
    Next {
        session: u32,
    },
    Cancel {
        session: u32,
    },
    Result {
        session: u32,
    },
    Release {
        client: u32,
    },
    /// `client`'s admission (#118): prompt and new tokens per minute, and
    /// the longest prompt in tokens; `u32::MAX` for no limit.
    Limit {
        client: u32,
        tokens_per_min: u32,
        prompt_tokens: u32,
    },
    /// The attached capability's size in bytes.
    Attach {
        len: u64,
    },
    Info,
}

/// Parses a request message (trailing bytes refused). Limits are the
/// service's to check, so it can answer `TOO_LARGE`.
pub fn parse(msg: &[u8]) -> Result<Request, Refused> {
    let (code, body) = split(msg, VERSION)?;
    let mut r = Reader::new(body);
    let req = (|| {
        Some(match code {
            op::GENERATE => Request::Generate {
                model: r.u8()?,
                max_new: r.u16()?,
                prompt_len: r.u32()?,
            },
            op::NEXT => Request::Next { session: r.u32()? },
            op::CANCEL => Request::Cancel { session: r.u32()? },
            op::RESULT => Request::Result { session: r.u32()? },
            op::RELEASE => Request::Release { client: r.u32()? },
            op::LIMIT => Request::Limit {
                client: r.u32()?,
                tokens_per_min: r.u32()?,
                prompt_tokens: r.u32()?,
            },
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

/// Writes `req` into `out`; returns its length.
pub fn encode(req: &Request, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    match *req {
        Request::Generate {
            model,
            max_new,
            prompt_len,
        } => {
            w.bytes(&[VERSION, op::GENERATE, model])?;
            w.u16(max_new)?;
            w.u32(prompt_len)?;
        }
        Request::Next { session } => {
            w.bytes(&[VERSION, op::NEXT])?;
            w.u32(session)?;
        }
        Request::Cancel { session } => {
            w.bytes(&[VERSION, op::CANCEL])?;
            w.u32(session)?;
        }
        Request::Result { session } => {
            w.bytes(&[VERSION, op::RESULT])?;
            w.u32(session)?;
        }
        Request::Release { client } => {
            w.bytes(&[VERSION, op::RELEASE])?;
            w.u32(client)?;
        }
        Request::Limit {
            client,
            tokens_per_min,
            prompt_tokens,
        } => {
            w.bytes(&[VERSION, op::LIMIT])?;
            w.u32(client)?;
            w.u32(tokens_per_min)?;
            w.u32(prompt_tokens)?;
        }
        Request::Attach { len } => {
            w.bytes(&[VERSION, common::ATTACH])?;
            w.u64(len)?;
        }
        Request::Info => w.bytes(&[VERSION, common::INFO])?,
    }
    Some(w.len())
}

/// The `GENERATE` reply: `[OK, session u32, prompt tokens u32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    pub session: u32,
    pub prompt_tokens: u32,
}

impl Started {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK])?;
        w.u32(self.session)?;
        w.u32(self.prompt_tokens)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let s = Self {
            session: r.u32()?,
            prompt_tokens: r.u32()?,
        };
        (ok && r.is_empty()).then_some(s)
    }
}

/// The `NEXT` reply: `[OK, stop (0: more follows), text length, text]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tokens<'a> {
    pub stop: Option<Stop>,
    pub text: &'a [u8],
}

impl<'a> Tokens<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if self.text.len() > MAX_TEXT {
            return None;
        }
        let mut w = Writer::new(out);
        let stop = self.stop.map_or(0, |s| s as u8);
        w.bytes(&[status::OK, stop, self.text.len() as u8])?;
        w.bytes(self.text)?;
        Some(w.len())
    }
    pub fn parse(reply: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let stop = match r.u8()? {
            0 => None,
            c => Some(Stop::from_code(c)?),
        };
        let n = usize::from(r.u8()?);
        let text = r.take(n)?;
        (ok && n <= MAX_TEXT && r.is_empty()).then_some(Self { stop, text })
    }
}

/// The `RESULT` reply: the record of one generation, for the audit trail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub model: u8,
    pub sha256: [u8; 32],
    /// `pharos-infer`'s version: major, minor, patch.
    pub engine: [u8; 3],
    /// Settings: greedy decoding (the only one in version 1) and the
    /// requested maximum.
    pub max_new: u16,
    pub prompt_tokens: u32,
    pub generated: u32,
    pub stop: Stop,
    pub prompt_us: u64,
    pub generate_us: u64,
}

/// Sampling setting in a record: greedy.
const GREEDY: u8 = 0;

impl Record {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[status::OK, self.model])?;
        w.bytes(&self.sha256)?;
        w.bytes(&self.engine)?;
        w.bytes(&[GREEDY])?;
        w.u16(self.max_new)?;
        w.u32(self.prompt_tokens)?;
        w.u32(self.generated)?;
        w.bytes(&[self.stop as u8])?;
        w.u64(self.prompt_us)?;
        w.u64(self.generate_us)?;
        Some(w.len())
    }
    pub fn parse(reply: &[u8]) -> Option<Self> {
        let mut r = Reader::new(reply);
        let ok = r.u8()? == status::OK;
        let model = r.u8()?;
        let sha256 = r.take(32)?.try_into().ok()?;
        let engine = r.take(3)?.try_into().ok()?;
        let greedy = r.u8()? == GREEDY;
        let rec = Self {
            model,
            sha256,
            engine,
            max_new: r.u16()?,
            prompt_tokens: r.u32()?,
            generated: r.u32()?,
            stop: Stop::from_code(r.u8()?)?,
            prompt_us: r.u64()?,
            generate_us: r.u64()?,
        };
        (ok && greedy && r.is_empty()).then_some(rec)
    }
}

/// A model's state in `INFO`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelState {
    NotLoaded,
    Loaded,
    Failed(Step),
}

/// One manifest model in `INFO`'s details: `[number, state, step, context
/// u32, SHA-256, name length, name]` (step 0 unless failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Model<'a> {
    pub number: u8,
    pub state: ModelState,
    /// Prompt plus new tokens the service allows.
    pub context: u32,
    pub sha256: [u8; 32],
    pub name: &'a [u8],
}

impl<'a> Model<'a> {
    /// Appends this model to `INFO` details.
    pub fn encode(&self, w: &mut Writer<'_>) -> Option<()> {
        let (state, step) = match self.state {
            ModelState::NotLoaded => (0, 0),
            ModelState::Loaded => (1, 0),
            ModelState::Failed(s) => (2, s as u8),
        };
        w.bytes(&[self.number, state, step])?;
        w.u32(self.context)?;
        w.bytes(&self.sha256)?;
        w.bytes(&[u8::try_from(self.name.len()).ok()?])?;
        w.bytes(self.name)
    }

    fn parse(r: &mut Reader<'a>) -> Option<Self> {
        let number = r.u8()?;
        let state = match (r.u8()?, r.u8()?) {
            (0, 0) => ModelState::NotLoaded,
            (1, 0) => ModelState::Loaded,
            (2, s) => ModelState::Failed(Step::from_code(s)?),
            _ => return None,
        };
        let context = r.u32()?;
        let sha256 = r.take(32)?.try_into().ok()?;
        let n = usize::from(r.u8()?);
        Some(Self {
            number,
            state,
            context,
            sha256,
            name: r.take(n)?,
        })
    }

    /// The models in `INFO` details (a count, then each model); `None` if
    /// malformed.
    pub fn list(details: &'a [u8], out: &mut [Option<Model<'a>>]) -> Option<usize> {
        let mut r = Reader::new(details);
        let count = usize::from(r.u8()?);
        if count > out.len() {
            return None;
        }
        for slot in out.iter_mut().take(count) {
            *slot = Some(Self::parse(&mut r)?);
        }
        r.is_empty().then_some(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Info, fuzz};

    #[test]
    fn requests_round_trip() {
        let reqs = [
            Request::Generate {
                model: 2,
                max_new: 300,
                prompt_len: 70_000,
            },
            Request::Next { session: 7 },
            Request::Cancel { session: u32::MAX },
            Request::Result { session: 1 },
            Request::Release { client: 7 },
            Request::Limit {
                client: 3,
                tokens_per_min: 30,
                prompt_tokens: u32::MAX,
            },
            Request::Attach { len: 4096 },
            Request::Info,
        ];
        for req in reqs {
            let mut buf = [0u8; 64];
            let n = encode(&req, &mut buf).unwrap();
            assert_eq!(buf[0], VERSION);
            assert_eq!(parse(&buf[..n]), Ok(req));
            assert!(parse(&buf[..n - 1]).is_err(), "{req:?} truncated");
            assert_eq!(parse(&buf[..n + 1]), Err(Refused::Bad), "{req:?} + byte");
            let mut other = buf;
            other[0] = VERSION + 1;
            assert_eq!(parse(&other[..n]), Err(Refused::Version), "{req:?} v2");
            assert_eq!(encode(&req, &mut buf[..n - 1]), None, "too small");
        }
        assert_eq!(parse(&[VERSION, 0]), Err(Refused::Bad), "unknown op");
        fuzz(100_000, 8, |m| {
            let _ = parse(m);
        });
        fuzz(100_000, 8, |m| {
            let mut v = [0u8; 302];
            v[0] = VERSION;
            v[1..1 + m.len()].copy_from_slice(m);
            let _ = parse(&v[..1 + m.len()]);
        });
    }

    #[test]
    fn replies_round_trip_and_refuse_bad_bytes() {
        let mut out = [0u8; 256];
        let started = Started {
            session: 3,
            prompt_tokens: 233,
        };
        let n = started.encode(&mut out).unwrap();
        assert_eq!(Started::parse(&out[..n]), Some(started));
        assert_eq!(Started::parse(&out[..n - 1]), None);

        let text = [b'x'; MAX_TEXT];
        for stop in [None, Some(Stop::EndOfText), Some(Stop::TokenLimit)] {
            let t = Tokens { stop, text: &text };
            let n = t.encode(&mut out).unwrap();
            assert!(n <= 256, "fits one message");
            assert_eq!(Tokens::parse(&out[..n]), Some(t));
            assert_eq!(Tokens::parse(&out[..n - 1]), None);
        }
        let long = [0u8; MAX_TEXT + 1];
        assert_eq!(
            Tokens {
                stop: None,
                text: &long
            }
            .encode(&mut out),
            None
        );
        assert_eq!(Tokens::parse(&[0, 9, 0]), None, "unknown stop");

        let rec = Record {
            model: 1,
            sha256: [7; 32],
            engine: [0, 2, 0],
            max_new: 64,
            prompt_tokens: 233,
            generated: 64,
            stop: Stop::TokenLimit,
            prompt_us: 8_400_000,
            generate_us: 4_000_000,
        };
        let n = rec.encode(&mut out).unwrap();
        assert_eq!(Record::parse(&out[..n]), Some(rec));
        assert_eq!(Record::parse(&out[..n - 1]), None);
        let mut sampled = out;
        sampled[37] = 1;
        assert_eq!(Record::parse(&sampled[..n]), None, "not greedy");

        let models = [
            Model {
                number: 1,
                state: ModelState::NotLoaded,
                context: 2048,
                sha256: [1; 32],
                name: b"qwen2.5-0.5b-instruct-q8_0",
            },
            Model {
                number: 2,
                state: ModelState::Failed(Step::Hash),
                context: 64,
                sha256: [2; 32],
                name: b"test",
            },
        ];
        let mut details = [0u8; 200];
        let mut w = Writer::new(&mut details);
        w.bytes(&[2]).unwrap();
        for m in &models {
            m.encode(&mut w).unwrap();
        }
        let len = w.len();
        let info = Info {
            name: NAME,
            low: VERSION,
            high: VERSION,
            details: &details[..len],
        };
        let n = info.encode(&mut out).unwrap();
        assert!(n <= 256, "INFO with both models fits one message");
        let parsed = Info::parse(&out[..n]).unwrap();
        let mut list = [None; 4];
        assert_eq!(Model::list(parsed.details, &mut list), Some(2));
        assert_eq!(list[..2], [Some(models[0]), Some(models[1])]);
        assert_eq!(Model::list(&details[..len - 1], &mut list), None);
        assert_eq!(Model::list(&details[..len], &mut [None]), None, "room");
        fuzz(100_000, 8, |m| {
            let _ = (Started::parse(m), Tokens::parse(m), Record::parse(m));
            let _ = Model::list(m, &mut [None; 4]);
        });
    }

    #[test]
    fn status_and_step_codes() {
        for s in [
            Status::Ok,
            Status::Version,
            Status::NoAccess,
            Status::Busy,
            Status::TooLarge,
            Status::NoBuffer,
            Status::Internal,
            Status::NoModel,
            Status::ModelInvalid,
            Status::Context,
            Status::NoSession,
        ] {
            assert_eq!(Status::from_code(s as u8), s);
        }
        assert_eq!(Status::NoModel as u8, 32);
        assert_eq!(Status::NoSession as u8, 35);
        assert_eq!(Status::from_code(200), Status::BadRequest);
        assert_eq!(Step::from_code(3), Some(Step::Hash));
        assert_eq!(Step::from_code(0), None);
    }
}
