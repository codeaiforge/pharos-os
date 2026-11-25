//! The Tier 3 channel's frames (#298, bridge.md, D-036): what the guest
//! and the bridge service say on the byte stream between them. Every
//! frame is a header, `PB`, version 1, a kind, and the payload's length
//! (u32, little-endian, at most [`MAX_PAYLOAD`]), then the payload.
//!
//! - `HELLO` ([`Hello`]): the bridge's first frame of an attempt, the task
//!   and attempt; the guest answers with the same. Until it does, the
//!   bridge discards up to [`RESYNC`] bytes ([`Decoder`]).
//! - `REQUEST` (guest to bridge): one agents v1 agent message (length u8,
//!   so at most [`MAX_MESSAGE`], 255 bytes), then the bytes the operation
//!   reads from the agent's buffer ([`parse_request`]); only the
//!   operations in [`PASSED`].
//! - `REPLY` (bridge to guest): the runtime's reply message (length u8),
//!   then the bytes the operation wrote at the start of the buffer
//!   ([`reply_len`]). A reply over 255 bytes is not framed: the bridge
//!   fails the attempt with [`REPLY_TOO_LONG`]. No passed operation's
//!   reply comes near it.
//! - `ERROR` (bridge to guest): a status byte and a reason; the bridge
//!   then ends the attempt.
//!
//! Everything here parses bytes from a guest that runs arbitrary code:
//! every length is checked and nothing panics (fuzzed below).

use crate::agents::{self, Assigned, CHECKPOINT_AT, Request, op};
use crate::{Reader, Writer, gateway, status};

pub const MAGIC: [u8; 2] = *b"PB";
pub const VERSION: u8 = 1;

/// Frame kinds.
pub mod kind {
    pub const HELLO: u8 = 1;
    pub const REQUEST: u8 = 2;
    pub const REPLY: u8 = 3;
    pub const ERROR: u8 = 4;
}

/// Bytes in a frame's header.
pub const HEADER: usize = 8;
/// Largest payload.
pub const MAX_PAYLOAD: usize = 70_000;
/// Largest agents v1 message in a frame, either way: what the length byte
/// holds (#307, M6.3 review). The kernel carries 256 bytes, but no
/// operation in [`PASSED`] comes near: a `LOG` or `FAIL` of
/// [`agents::MAX_TEXT`] is 202 bytes, and the runtime's longest reply to
/// one, `TASK`'s, is 14 (tested below).
pub const MAX_MESSAGE: usize = u8::MAX as usize;
/// Why the bridge fails an attempt whose reply does not fit a frame.
pub const REPLY_TOO_LONG: &[u8] = b"bridge: reply over 255 bytes";
/// How long the bridge waits for the runtime's reply to a guest's request
/// (#302, M6.3 review R-3): the runtime's longest, an HTTPS `REQUEST`
/// ([`agents::REQUEST_US`]), and a margin, so the guest is never told the
/// attempt ended while its request goes on and takes effect.
pub const CALL_US: u64 = agents::REQUEST_US + 5_000_000;
const _: () = assert!(CALL_US >= agents::REQUEST_US + 2_000_000);
/// Largest buffer data in a frame: the agent buffer.
pub const MAX_DATA: usize = agents::MAX_BUFFER as usize;
/// Bytes discarded looking for the guest's `HELLO` before the attempt
/// fails.
pub const RESYNC: usize = 64 << 10;

const _: () = assert!(1 + MAX_MESSAGE + MAX_DATA <= MAX_PAYLOAD);

/// The operations a guest may send (bridge.md, decided open question 2).
pub const PASSED: [u8; 12] = [
    op::TASK,
    op::LOG,
    op::CHECKPOINT,
    op::BEGIN,
    op::END,
    op::COMPLETE,
    op::FAIL,
    op::REQUEST,
    op::DATA_PUT,
    op::DATA_GET,
    op::ASK,
    crate::op::INFO,
];

/// Whether the runtime serves operation `op` under `badge` (#303, M6.3
/// review R-5). Every operation for any badge but a guest attempt's
/// ([`agents::is_guest`]); for a guest's, only those in [`PASSED`], and
/// `ATTACH` only while the slot has no buffer (`attached` false): the
/// bridge's own, at the attempt's start. The bridge checks [`PASSED`] too
/// ([`parse_request`]); the runtime checks again, so a compromised bridge
/// reaches no more than a guest may.
pub fn runtime_serves(badge: u32, op: u8, attached: bool) -> bool {
    if !agents::is_guest(badge) {
        return true;
    }
    if op == crate::op::ATTACH {
        return !attached;
    }
    PASSED.contains(&op)
}

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    Magic,
    Version,
    Kind,
    Length,
    /// A `REQUEST` whose message is empty, over [`MAX_MESSAGE`], or not an
    /// agents v1 request.
    Message,
    /// An operation not in [`PASSED`].
    NotPassed,
    /// Buffer data not exactly what the operation reads.
    Data,
}

impl Bad {
    /// The reason an `ERROR` frame and the attempt's failure give.
    pub fn reason(self) -> &'static [u8] {
        match self {
            Self::Magic => b"guest protocol: bad magic",
            Self::Version => b"guest protocol: bad version",
            Self::Kind => b"guest protocol: bad kind",
            Self::Length => b"guest protocol: bad length",
            Self::Message => b"guest protocol: bad message",
            Self::NotPassed => b"guest protocol: operation not passed",
            Self::Data => b"guest protocol: bad buffer data",
        }
    }
}

/// Checks a header: returns the kind and the payload's length.
pub fn header(h: &[u8; HEADER]) -> Result<(u8, usize), Bad> {
    if h[..2] != MAGIC {
        return Err(Bad::Magic);
    }
    if h[2] != VERSION {
        return Err(Bad::Version);
    }
    if !(kind::HELLO..=kind::ERROR).contains(&h[3]) {
        return Err(Bad::Kind);
    }
    let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Bad::Length);
    }
    Ok((h[3], len))
}

/// A header for `kind` and `len` payload bytes (at most [`MAX_PAYLOAD`]).
pub fn write_header(kind: u8, len: usize) -> Option<[u8; HEADER]> {
    let n = u32::try_from(len).ok().filter(|_| len <= MAX_PAYLOAD)?;
    let mut h = [0u8; HEADER];
    h[..2].copy_from_slice(&MAGIC);
    h[2] = VERSION;
    h[3] = kind;
    h[4..].copy_from_slice(&n.to_le_bytes());
    Some(h)
}

/// The `HELLO` payload: the attempt the bridge is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub task: u32,
    pub attempt: u8,
}

impl Hello {
    pub const LEN: usize = 5;
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..4].copy_from_slice(&self.task.to_le_bytes());
        out[4] = self.attempt;
        out
    }
    pub fn parse(p: &[u8]) -> Option<Self> {
        let mut r = Reader::new(p);
        let h = Self {
            task: r.u32()?,
            attempt: r.u8()?,
        };
        r.is_empty().then_some(h)
    }
}

/// What [`Decoder::feed`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    More,
    /// A whole frame; its payload is the first `len` bytes of the buffer.
    Frame {
        kind: u8,
        len: usize,
    },
    /// A bad header: the attempt fails.
    Bad(Bad),
    /// [`RESYNC`] bytes discarded with no `HELLO`.
    Silent,
}

/// Splits the byte stream into frames, one byte at a time, into a payload
/// buffer of at least [`MAX_PAYLOAD`] bytes. Until [`Decoder::sync`], only
/// `HELLO` frames are found and everything else is discarded, counted.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    head: [u8; HEADER],
    filled: usize,
    body: Option<(u8, usize)>,
    got: usize,
    skipped: usize,
    synced: bool,
}

impl Decoder {
    /// The guest's `HELLO` matched: every frame counts from here.
    pub fn sync(&mut self) {
        self.synced = true;
    }

    pub fn synced(&self) -> bool {
        self.synced
    }

    pub fn feed(&mut self, b: u8, payload: &mut [u8]) -> Step {
        if let Some((kind, len)) = self.body {
            let Some(slot) = payload.get_mut(self.got) else {
                return Step::Bad(Bad::Length);
            };
            *slot = b;
            self.got += 1;
            return if self.got == len {
                self.end(kind, len)
            } else {
                Step::More
            };
        }
        self.head[self.filled] = b;
        self.filled += 1;
        if self.filled < HEADER {
            return Step::More;
        }
        let found = header(&self.head);
        if !self.synced {
            if found == Ok((kind::HELLO, Hello::LEN)) {
                self.filled = 0;
                self.body = Some((kind::HELLO, Hello::LEN));
                self.got = 0;
                return Step::More;
            }
            // Slide by one byte and look again.
            self.head.copy_within(1.., 0);
            self.filled -= 1;
            self.skipped += 1;
            return if self.skipped > RESYNC {
                Step::Silent
            } else {
                Step::More
            };
        }
        self.filled = 0;
        match found {
            Err(e) => Step::Bad(e),
            Ok((_, len)) if len > payload.len() => Step::Bad(Bad::Length),
            Ok((kind, 0)) => Step::Frame { kind, len: 0 },
            Ok((kind, len)) => {
                self.body = Some((kind, len));
                self.got = 0;
                Step::More
            }
        }
    }

    fn end(&mut self, kind: u8, len: usize) -> Step {
        self.body = None;
        if !self.synced {
            // A `HELLO` the bridge may refuse (an earlier attempt's) counts
            // as discarded; once accepted, nothing more is counted.
            self.skipped += HEADER + len;
            if self.skipped > RESYNC {
                return Step::Silent;
            }
        }
        Step::Frame { kind, len }
    }
}

/// A guest's `REQUEST`, checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call<'a> {
    /// The agents v1 message, as sent to the runtime.
    pub msg: &'a [u8],
    pub req: Request<'a>,
    /// Where `data` goes in the agent's buffer.
    pub at: usize,
    pub data: &'a [u8],
}

/// Where in the buffer an operation reads, and how many bytes.
fn reads(req: &Request<'_>) -> (usize, usize) {
    match *req {
        Request::Checkpoint { len } => (CHECKPOINT_AT as usize, len as usize),
        Request::Complete { len } | Request::DataPut { len, .. } => (0, len as usize),
        Request::Request {
            path_len, body_len, ..
        } => (0, usize::from(path_len) + body_len as usize),
        _ => (0, 0),
    }
}

/// Checks a `REQUEST` payload: a message the runtime parses, an operation
/// in [`PASSED`], and exactly the bytes it reads, inside the buffer.
pub fn parse_request(p: &[u8]) -> Result<Call<'_>, Bad> {
    let (&n, rest) = p.split_first().ok_or(Bad::Message)?;
    let n = usize::from(n);
    if !(2..=MAX_MESSAGE).contains(&n) {
        return Err(Bad::Message);
    }
    let msg = rest.get(..n).ok_or(Bad::Message)?;
    let data = &rest[n..];
    let req = agents::parse(msg).map_err(|_| Bad::Message)?;
    if !PASSED.contains(&msg[1]) {
        return Err(Bad::NotPassed);
    }
    let (at, len) = reads(&req);
    if data.len() != len || at + len > MAX_DATA {
        return Err(Bad::Data);
    }
    Ok(Call { msg, req, at, data })
}

/// A `REQUEST` payload for `msg` and `data` (the guest's side, and tests).
pub fn encode_request(msg: &[u8], data: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = u8::try_from(msg.len()).ok()?;
    let mut w = Writer::new(out);
    w.bytes(&[n])?;
    w.bytes(msg)?;
    w.bytes(data)?;
    (w.len() <= MAX_PAYLOAD).then(|| w.len())
}

/// How many bytes at the start of the buffer a `REPLY` to `req` carries,
/// from the runtime's `reply`: `TASK`'s input, or its checkpoint and
/// everything before it; `DATA_GET`'s file; `REQUEST`'s content type and
/// answer. 0 for everything else, and for any refusal.
pub fn reply_len(req: &Request<'_>, reply: &[u8]) -> usize {
    let n = match req {
        Request::Task => Assigned::parse(reply).map_or(0, |a| {
            if a.checkpoint_len > 0 {
                CHECKPOINT_AT as usize + a.checkpoint_len as usize
            } else {
                a.input_len as usize
            }
        }),
        Request::DataGet { .. } => match reply {
            [status::OK, l @ ..] if l.len() == 4 => {
                u32::from_le_bytes([l[0], l[1], l[2], l[3]]) as usize
            }
            _ => 0,
        },
        Request::Request { .. } => gateway::Answered::parse(reply)
            .filter(|a| a.status == status::OK)
            .map_or(0, |a| usize::from(a.type_len) + a.answer_len as usize),
        _ => 0,
    };
    n.min(MAX_DATA)
}

/// A `REPLY` payload's start: the reply message's length and the message;
/// the buffer bytes follow.
pub fn reply_head(reply: &[u8], out: &mut [u8; 1 + MAX_MESSAGE]) -> Option<usize> {
    let n = u8::try_from(reply.len()).ok()?;
    out[0] = n;
    out.get_mut(1..=reply.len())?.copy_from_slice(reply);
    Some(1 + reply.len())
}

/// An `ERROR` payload: `status`, then `reason`.
pub fn error(status: u8, reason: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.bytes(&[status])?;
    w.bytes(reason)?;
    Some(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = write_header(kind, payload.len()).unwrap().to_vec();
        f.extend_from_slice(payload);
        f
    }

    fn run(d: &mut Decoder, bytes: &[u8], buf: &mut [u8]) -> Vec<Step> {
        bytes
            .iter()
            .map(|b| d.feed(*b, buf))
            .filter(|s| *s != Step::More)
            .collect()
    }

    fn msg(req: &Request<'_>) -> Vec<u8> {
        let mut out = [0u8; 256];
        let n = agents::encode(req, &mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn the_runtime_serves_a_guest_only_what_the_bridge_passes() {
        let guest = agents::guest_badge(7, 1);
        for o in 0..=u8::MAX {
            // An agent process's badge, a control badge: not limited here.
            for badge in [1, agents::SLOTS as u32, agents::CONTROL] {
                assert!(runtime_serves(badge, o, true), "{badge} {o}");
            }
            if o != crate::op::ATTACH {
                assert_eq!(runtime_serves(guest, o, false), PASSED.contains(&o), "{o}");
                assert_eq!(runtime_serves(guest, o, true), PASSED.contains(&o), "{o}");
            }
        }
        // What a compromised bridge could otherwise send (M6.3 review R-5).
        for o in [
            op::INFER,
            op::TOOL,
            op::SUBTASK,
            op::SEND_TO,
            op::MESSAGE_SEND,
            op::KNOWLEDGE_PUT,
            op::KNOWLEDGE_GET,
            op::KNOWLEDGE_HISTORY,
            op::KNOWLEDGE_QUERY,
            op::PROPOSE,
            op::BIND,
            op::STOP_GUEST,
        ] {
            assert!(!runtime_serves(guest, o, false), "{o}");
        }
        // The bridge's one ATTACH, then no second.
        assert!(runtime_serves(guest, crate::op::ATTACH, false));
        assert!(!runtime_serves(guest, crate::op::ATTACH, true));
        assert!(runtime_serves(guest, op::REQUEST, true));
    }

    #[test]
    fn each_header_field_is_checked() {
        let good = write_header(kind::REQUEST, 9).unwrap();
        assert_eq!(header(&good), Ok((kind::REQUEST, 9)));
        let mut h = good;
        h[0] = b'X';
        assert_eq!(header(&h), Err(Bad::Magic));
        let mut h = good;
        h[2] = 2;
        assert_eq!(header(&h), Err(Bad::Version));
        for k in [0, 5, 255] {
            let mut h = good;
            h[3] = k;
            assert_eq!(header(&h), Err(Bad::Kind), "{k}");
        }
        let largest = write_header(kind::REPLY, MAX_PAYLOAD).unwrap();
        assert_eq!(header(&largest), Ok((kind::REPLY, MAX_PAYLOAD)));
        let mut h = largest;
        h[4..].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_le_bytes());
        assert_eq!(header(&h), Err(Bad::Length));
        assert_eq!(write_header(kind::REPLY, MAX_PAYLOAD + 1), None);
    }

    #[test]
    fn hello_is_found_after_noise_within_the_limit_and_not_past_it() {
        let hello = Hello {
            task: 7,
            attempt: 2,
        };
        let mut buf = std::vec![0u8; MAX_PAYLOAD];
        // An earlier attempt's half frame, then this one's HELLO.
        let mut bytes = frame(kind::REQUEST, &[1, 2, 3])[..6].to_vec();
        bytes.extend(frame(kind::HELLO, &hello.encode()));
        let mut d = Decoder::default();
        let steps = run(&mut d, &bytes, &mut buf);
        assert_eq!(
            steps,
            [Step::Frame {
                kind: kind::HELLO,
                len: Hello::LEN
            }]
        );
        assert_eq!(Hello::parse(&buf[..Hello::LEN]), Some(hello));
        d.sync();
        let steps = run(&mut d, &frame(kind::REQUEST, b"abc"), &mut buf);
        assert_eq!(
            steps,
            [Step::Frame {
                kind: kind::REQUEST,
                len: 3
            }]
        );

        // Noise up to the limit still finds it; one byte more is silence.
        for (noise, want) in [(RESYNC - HEADER - Hello::LEN, true), (RESYNC + 1, false)] {
            let mut bytes = std::vec![b'P'; noise];
            bytes.extend(frame(kind::HELLO, &hello.encode()));
            let steps = run(&mut Decoder::default(), &bytes, &mut buf);
            assert_eq!(steps.first() == Some(&Step::Silent), !want, "{noise}");
            assert_eq!(
                steps.contains(&Step::Frame {
                    kind: kind::HELLO,
                    len: Hello::LEN
                }),
                want,
                "{noise}"
            );
        }

        // Unsynced, other frames and a HELLO of another length are noise.
        let mut bytes = frame(kind::REQUEST, &[0; 8]);
        bytes.extend(frame(kind::HELLO, &[0; 4]));
        assert!(run(&mut Decoder::default(), &bytes, &mut buf).is_empty());
    }

    #[test]
    fn synced_bad_headers_and_the_largest_frame() {
        let mut buf = std::vec![0u8; MAX_PAYLOAD];
        let mut d = Decoder::default();
        d.sync();
        assert_eq!(
            run(&mut d, b"XB\x01\x02\0\0\0\0", &mut buf),
            [Step::Bad(Bad::Magic)]
        );
        let big = std::vec![9u8; MAX_PAYLOAD];
        let mut d = Decoder::default();
        d.sync();
        assert_eq!(
            run(&mut d, &frame(kind::REQUEST, &big), &mut buf),
            [Step::Frame {
                kind: kind::REQUEST,
                len: MAX_PAYLOAD
            }]
        );
        assert_eq!(buf, big);
        // A payload buffer smaller than the frame is refused, not overrun.
        let mut small = [0u8; 4];
        let mut d = Decoder::default();
        d.sync();
        assert_eq!(
            run(&mut d, &frame(kind::REQUEST, &[1; 5]), &mut small),
            [Step::Bad(Bad::Length)]
        );
        // An empty frame ends at its header.
        let mut d = Decoder::default();
        d.sync();
        assert_eq!(
            run(&mut d, &frame(kind::REQUEST, &[]), &mut buf),
            [Step::Frame {
                kind: kind::REQUEST,
                len: 0
            }]
        );
    }

    #[test]
    fn requests_carry_exactly_what_the_operation_reads() {
        let mut out = std::vec![0u8; MAX_PAYLOAD];
        let check = |m: &[u8], data: &[u8], out: &mut [u8]| {
            let n = encode_request(m, data, out).unwrap();
            parse_request(&out[..n]).map(|c| (c.at, c.data.len()))
        };
        let log = msg(&Request::Log { text: b"hi" });
        assert_eq!(check(&log, b"", &mut out), Ok((0, 0)));
        assert_eq!(check(&log, b"x", &mut out), Err(Bad::Data));
        let cp = msg(&Request::Checkpoint { len: 3 });
        assert_eq!(
            check(&cp, b"abc", &mut out),
            Ok((CHECKPOINT_AT as usize, 3))
        );
        assert_eq!(check(&cp, b"ab", &mut out), Err(Bad::Data));
        // The largest checkpoint fills the buffer; one byte more is out.
        let max = agents::MAX_CHECKPOINT;
        let full = std::vec![0u8; max as usize];
        assert!(check(&msg(&Request::Checkpoint { len: max }), &full, &mut out).is_ok());
        let req = msg(&Request::Request {
            route: b"api",
            path_len: 2,
            body_len: 3,
        });
        assert_eq!(check(&req, b"/xbody", &mut out), Err(Bad::Data));
        assert_eq!(check(&req, b"/xbod", &mut out), Ok((0, 5)));
        // Not passed: inference, tools, messages, control requests.
        for r in [
            Request::Next,
            Request::MessageReceive,
            Request::Status { task: 1 },
            Request::Cancel { task: 1 },
            Request::Usage,
            Request::Attach { len: 4096 },
        ] {
            assert_eq!(check(&msg(&r), b"", &mut out), Err(Bad::NotPassed), "{r:?}");
        }
        // Malformed: empty, over 255, not agents v1, cut short.
        assert_eq!(parse_request(&[]), Err(Bad::Message));
        assert_eq!(parse_request(&[0]), Err(Bad::Message));
        assert_eq!(parse_request(&[5, 1, 10]), Err(Bad::Message));
        assert_eq!(
            check(&[9, op::LOG, 2, b'h'], b"", &mut out),
            Err(Bad::Message)
        );
        assert_eq!(parse_request(&[1, agents::VERSION]), Err(Bad::Message));
        let long = std::vec![1u8; 257];
        assert_eq!(encode_request(&long, b"", &mut out), None);
    }

    #[test]
    fn each_passed_operation_has_its_reply_length() {
        let a = Assigned {
            task: 1,
            attempt: 1,
            input_len: 10,
            checkpoint_len: 0,
        };
        let mut r = [0u8; 32];
        let n = a.encode(&mut r).unwrap();
        assert_eq!(reply_len(&Request::Task, &r[..n]), 10);
        let n = Assigned {
            checkpoint_len: 7,
            ..a
        }
        .encode(&mut r)
        .unwrap();
        assert_eq!(
            reply_len(&Request::Task, &r[..n]),
            CHECKPOINT_AT as usize + 7
        );
        let get = Request::DataGet { name: b"f" };
        assert_eq!(reply_len(&get, &[0, 9, 0, 0, 0]), 9);
        assert_eq!(reply_len(&get, &[status::NOT_FOUND]), 0);
        assert_eq!(reply_len(&get, &[0, 0xff, 0xff, 0xff, 0xff]), MAX_DATA);
        let https = Request::Request {
            route: b"api",
            path_len: 1,
            body_len: 0,
        };
        let ok = gateway::Answered {
            status: status::OK,
            http: 200,
            type_len: 4,
            answer_len: 20,
            ..Default::default()
        };
        assert_eq!(reply_len(&https, &ok.encode()), 24);
        let refused = gateway::Answered {
            status: status::NO_ACCESS,
            ..ok
        };
        assert_eq!(reply_len(&https, &refused.encode()), 0);
        for req in [
            Request::Log { text: b"x" },
            Request::Complete { len: 3 },
            Request::Checkpoint { len: 3 },
            Request::Info,
        ] {
            assert_eq!(reply_len(&req, &[0, 1, 2, 3, 4]), 0, "{req:?}");
        }
        let mut head = [0u8; 1 + MAX_MESSAGE];
        assert_eq!(reply_head(&[0, 1], &mut head), Some(3));
        assert_eq!(&head[..3], &[2, 0, 1]);
        let mut e = [0u8; 64];
        let n = error(status::BAD_REQUEST, Bad::Kind.reason(), &mut e).unwrap();
        assert_eq!(e[0], status::BAD_REQUEST);
        assert_eq!(&e[1..n], b"guest protocol: bad kind");
    }

    /// #307 (M6.3 review): the length byte's 255 bytes, both ways, and
    /// every passed operation's longest request and reply well inside.
    #[test]
    fn messages_and_replies_fit_the_length_byte() {
        assert_eq!(MAX_MESSAGE, usize::from(u8::MAX));
        let mut out = std::vec![0u8; MAX_PAYLOAD];
        assert!(encode_request(&[1; MAX_MESSAGE], b"", &mut out).is_some());
        assert_eq!(encode_request(&[1; MAX_MESSAGE + 1], b"", &mut out), None);
        let mut head = [0u8; 1 + MAX_MESSAGE];
        assert_eq!(reply_head(&[7; MAX_MESSAGE], &mut head), Some(256));
        assert_eq!((head[0], head[255]), (255, 7));
        // What the kernel carries, but no frame: the bridge fails the
        // attempt with its own reason, not as a bad reply.
        assert_eq!(reply_head(&[7; MAX_MESSAGE + 1], &mut head), None);
        assert_eq!(REPLY_TOO_LONG, b"bridge: reply over 255 bytes");

        let text = std::vec![b'x'; agents::MAX_TEXT];
        for req in [
            Request::Log { text: &text },
            Request::Fail { reason: &text },
        ] {
            let n = msg(&req).len();
            assert!(n <= MAX_MESSAGE, "{req:?} is {n} bytes");
        }
        let mut r = [0u8; 256];
        let replies = [
            Assigned {
                task: u32::MAX,
                attempt: u8::MAX,
                input_len: u32::MAX,
                checkpoint_len: u32::MAX,
            }
            .encode(&mut r)
            .unwrap(),
            gateway::Answered::default().encode().len(),
            agents::Asked::Pending.encode(&mut r).unwrap(),
            crate::Info {
                name: agents::NAME,
                low: agents::VERSION,
                high: agents::VERSION,
                details: &[0; 2],
            }
            .encode(&mut r)
            .unwrap(),
        ];
        // The gateway's reply is 11 bytes since its `sent` mark (#293).
        assert_eq!(replies, [14, 11, 2, 12]);
        assert!(replies.iter().all(|n| *n <= MAX_MESSAGE));
    }

    /// #302 (M6.3 review R-3): the bridge waits out the runtime's longest
    /// request, two gateway tries of 35 s and both records of 2 s, with
    /// 5 s to spare (the compile-time asserts hold the relations).
    #[test]
    fn the_bridge_waits_out_the_runtimes_longest_request() {
        assert_eq!(gateway::WAIT_US, 35_000_000);
        assert_eq!(agents::REQUEST_US, 74_250_000);
        assert_eq!(CALL_US, 79_250_000);
    }

    #[test]
    fn fuzzed_streams_and_requests_never_panic() {
        let mut buf = std::vec![0u8; MAX_PAYLOAD];
        let mut parsed = 0;
        let mut frames = 0;
        let mut synced = Decoder::default();
        synced.sync();
        crate::fuzz(100_000, 255, |m| {
            // A REQUEST payload with a passed message's shape half the time.
            let extra = (m.len() % 3).min(m.len());
            let op = PASSED[usize::from(m.first().copied().unwrap_or(0)) % PASSED.len()];
            let mut p = std::vec![2 + extra as u8, agents::VERSION, op];
            p.extend_from_slice(&m[..extra]);
            for p in [&p[..], m] {
                if let Ok(c) = parse_request(p) {
                    parsed += 1;
                    assert!(c.at + c.data.len() <= MAX_DATA);
                    let _ = reply_len(&c.req, m);
                }
            }
            // Streams, with a real header in front half the time.
            let mut s = frame(kind::REQUEST, &m[..m.len() / 2]);
            s.extend_from_slice(m);
            for bytes in [&s[..], m] {
                let mut d = Decoder::default();
                for b in bytes {
                    for d in [&mut d, &mut synced] {
                        if let Step::Frame { len, .. } = d.feed(*b, &mut buf) {
                            assert!(len <= MAX_PAYLOAD);
                            frames += 1;
                        }
                    }
                }
            }
        });
        assert!(parsed > 100, "only {parsed} fuzzed requests parsed");
        assert!(frames > 100, "only {frames} fuzzed frames found");
    }
}
