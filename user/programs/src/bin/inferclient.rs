//! An inference-service client for the `inference` test kernel (#88).
//! Handles: 1 the console, 2 `SEND` on the service (badged with a client
//! number), 3 the storage service for `models`, read-only (for the host's
//! expected text). Each step prints `ok <step>` or `FAIL <step>`; the exit
//! code is the number of failures.
//!
//! - 1: `INFO`, a version-2 request, `GENERATE` refusals (no buffer, an
//!   unknown model), then "hello hello" with the test model for 20 tokens,
//!   pulled with `NEXT`; the text must equal `models/test.expected`, which
//!   `cargo xtask` computed on the host. Then `RESULT`, and `INFO` again.
//! - 2 (#89): failures, with two more handles: 4 `SEND` on the service as
//!   a second client, 5 `SEND` on an endpoint nobody receives on (a stopped
//!   service). `CONTEXT`, `BUSY`, `CANCEL`, an idle session dropped,
//!   `MODEL_INVALID` for models 3 and 4, and a timeout.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use pharos_proto::infer::{
    Model, ModelState, NAME, Record, Request, Started, Status, Step, Stop, Tokens, VERSION, encode,
};
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{Info, versions};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Error, Handle, Mapped, Received, call_timeout, debug_write, endpoint_create, mem_map_buffer,
    mem_share, send, sleep, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const STORE: Handle = 3;
const OTHER: Handle = 4;
const DEAD: Handle = 5;
const PROMPT: &[u8] = b"hello hello";
const NEW: u16 = 20;
/// Timeouts from the design: `GENERATE` includes loading the model.
const GENERATE_US: u64 = 120_000_000;
const NEXT_US: u64 = 30_000_000;
const SHORT_US: u64 = 1_000_000;

fn report(failures: &mut u64, step: &str, ok: bool) {
    let mut line = [0u8; 96];
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let n = (prefix.len() + step.len()).min(line.len());
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..n].copy_from_slice(&step.as_bytes()[..n - prefix.len()]);
    let _ = debug_write(CONSOLE, &line[..n]);
    if !ok {
        *failures += 1;
    }
}

/// Sends `msg` by `call` on `to`; returns the reply and its length (0 if
/// none arrived).
fn raw(to: Handle, reply: Handle, msg: &[u8], micros: u64) -> ([u8; 256], usize) {
    let mut buf = [0u8; 256];
    match call_timeout(to, msg, reply, &mut buf, micros) {
        Ok(Received::Message { len, .. }) => (buf, len.min(256)),
        _ => (buf, 0),
    }
}

fn call(reply: Handle, req: Request, micros: u64) -> ([u8; 256], usize) {
    call_to(SERVICE, reply, req, micros)
}

fn call_to(to: Handle, reply: Handle, req: Request, micros: u64) -> ([u8; 256], usize) {
    let mut msg = [0u8; 32];
    let n = encode(&req, &mut msg).unwrap_or(0);
    raw(to, reply, &msg[..n], micros)
}

fn status(r: &([u8; 256], usize)) -> Status {
    if r.1 == 0 {
        Status::Internal
    } else {
        Status::from_code(r.0[0])
    }
}

/// Maps a `len`-byte buffer and sends it to `to` with `ATTACH`.
fn attach(to: Handle, msg: &[u8], len: u64) -> Option<Mapped> {
    let buf = mem_map_buffer(len).ok()?;
    let memory = mem_share(buf.addr(), len).ok()?;
    send(to, msg, memory, READ | WRITE, 0).ok()?;
    Some(buf)
}

/// Reads `models/test.expected` (small) from the store.
fn expected(reply: Handle) -> Option<Vec<u8>> {
    let mut msg = [0u8; 64];
    let n = store::encode(&StoreRequest::Attach { len: 4096 }, &mut msg)?;
    let window = attach(STORE, &msg[..n], 4096)?;
    let path = b"test.expected";
    let n = store::encode(&StoreRequest::Stat { path }, &mut msg)?;
    let (r, len) = raw(STORE, reply, &msg[..n], SHORT_US);
    if len < 10 || StoreStatus::from_code(r[0]) != StoreStatus::Ok {
        return None;
    }
    let size = u64::from_le_bytes(r[2..10].try_into().ok()?);
    let read = StoreRequest::Read {
        path,
        offset: 0,
        len: size.min(4096),
        at: 0,
    };
    let n = store::encode(&read, &mut msg)?;
    let (r, _) = raw(STORE, reply, &msg[..n], SHORT_US);
    if StoreStatus::from_code(r[0]) != StoreStatus::Ok {
        return None;
    }
    let mut out = alloc::vec![0u8; size.min(4096) as usize];
    window.read_bytes(0, &mut out);
    Some(out)
}

/// The test model's entry in an `INFO` reply.
fn test_model(r: &[u8]) -> Option<(Model<'_>, usize)> {
    let info = Info::parse(r)?;
    if info.name != NAME || (info.low, info.high) != (VERSION, VERSION) {
        return None;
    }
    let (list, count) = models(r)?;
    let m = list[..count].iter().flatten().find(|m| m.number == 2)?;
    Some((*m, count))
}

/// The models in an `INFO` reply.
fn models(r: &[u8]) -> Option<([Option<Model<'_>>; 8], usize)> {
    let info = Info::parse(r)?;
    let mut list = [None; 8];
    let count = Model::list(info.details, &mut list)?;
    Some((list, count))
}

fn state(r: &[u8], number: u8) -> Option<ModelState> {
    let (list, count) = models(r)?;
    list[..count]
        .iter()
        .flatten()
        .find(|m| m.number == number)
        .map(|m| m.state)
}

fn record(reply: Handle, session: u32) -> Option<Record> {
    let (r, n) = call(reply, Request::Result { session }, SHORT_US);
    Record::parse(&r[..n])
}

/// The step a `MODEL_INVALID` reply names.
fn invalid(r: &([u8; 256], usize)) -> Option<u8> {
    (r.1 == 2 && Status::from_code(r.0[0]) == Status::ModelInvalid).then_some(r.0[1])
}

fn failures(f: &mut u64) {
    let Ok(reply) = endpoint_create() else {
        report(f, "create a reply endpoint", false);
        return;
    };
    let mut msg = [0u8; 32];
    let n = encode(&Request::Attach { len: 4096 }, &mut msg).unwrap_or(0);
    let Some(buffer) = attach(SERVICE, &msg[..n], 4096) else {
        report(f, "attach a prompt buffer", false);
        return;
    };
    buffer.write_bytes(0, PROMPT);
    let generate = |model, max_new| Request::Generate {
        model,
        max_new,
        prompt_len: PROMPT.len() as u32,
    };
    report(
        f,
        "GENERATE with 5 + 60 tokens, context 64: CONTEXT",
        status(&call(reply, generate(2, 60), GENERATE_US)) == Status::Context,
    );
    let (r, n) = call(reply, generate(2, 59), GENERATE_US);
    let Some(Started { session, .. }) = Started::parse(&r[..n]) else {
        report(f, "GENERATE with 5 + 59 tokens: a session", false);
        return;
    };
    report(f, "GENERATE with 5 + 59 tokens: a session", true);
    report(
        f,
        "a second client's GENERATE: BUSY",
        status(&call_to(OTHER, reply, generate(2, 20), SHORT_US)) == Status::Busy,
    );
    report(
        f,
        "a second client's NEXT and CANCEL: NO_SESSION",
        status(&call_to(OTHER, reply, Request::Next { session }, SHORT_US)) == Status::NoSession
            && status(&call_to(
                OTHER,
                reply,
                Request::Cancel { session },
                SHORT_US,
            )) == Status::NoSession,
    );
    report(
        f,
        "RESULT while running: BUSY",
        status(&call(reply, Request::Result { session }, SHORT_US)) == Status::Busy,
    );
    report(
        f,
        "CANCEL, then NEXT: NO_SESSION",
        status(&call(reply, Request::Cancel { session }, SHORT_US)) == Status::Ok
            && status(&call(reply, Request::Next { session }, SHORT_US)) == Status::NoSession,
    );
    report(
        f,
        "RESULT: cancelled, no tokens",
        record(reply, session).is_some_and(|r| {
            (r.stop, r.generated, r.max_new, r.prompt_tokens) == (Stop::Cancelled, 0, 59, 5)
        }),
    );

    let (r, n) = call(reply, generate(2, 59), GENERATE_US);
    let Some(Started { session, .. }) = Started::parse(&r[..n]) else {
        report(f, "GENERATE again", false);
        return;
    };
    let r = call(reply, Request::Next { session }, NEXT_US);
    report(
        f,
        "NEXT: text, not the end",
        Tokens::parse(&r.0[..r.1]).is_some_and(|t| !t.text.is_empty() && t.stop.is_none()),
    );
    // Over the service's 10 s idle limit.
    sleep(11_000_000);
    report(
        f,
        "NEXT after 11 s idle: NO_SESSION",
        status(&call(reply, Request::Next { session }, SHORT_US)) == Status::NoSession,
    );
    report(
        f,
        "RESULT: cancelled after the first NEXT",
        record(reply, session)
            .is_some_and(|r| r.stop == Stop::Cancelled && r.generated > 0 && r.generated < 59),
    );
    report(
        f,
        "the second client is no longer BUSY (NO_BUFFER)",
        status(&call_to(OTHER, reply, generate(2, 20), SHORT_US)) == Status::NoBuffer,
    );

    report(
        f,
        "model 3, one byte changed: MODEL_INVALID, hash",
        invalid(&call(reply, generate(3, 20), GENERATE_US)) == Some(Step::Hash as u8),
    );
    report(
        f,
        "model 4, 32 bytes short: MODEL_INVALID, size",
        invalid(&call(reply, generate(4, 20), GENERATE_US)) == Some(Step::Size as u8),
    );
    report(
        f,
        "model 3 again: MODEL_INVALID, hash",
        invalid(&call(reply, generate(3, 20), SHORT_US)) == Some(Step::Hash as u8),
    );
    let (r, n) = call(reply, Request::Info, SHORT_US);
    let r = &r[..n];
    report(
        f,
        "INFO: model 2 loaded, 3 failed at hash, 4 at size",
        state(r, 2) == Some(ModelState::Loaded)
            && state(r, 3) == Some(ModelState::Failed(Step::Hash))
            && state(r, 4) == Some(ModelState::Failed(Step::Size)),
    );

    let mut msg = [0u8; 32];
    let n = encode(&Request::Info, &mut msg).unwrap_or(0);
    let mut buf = [0u8; 256];
    let start = uptime();
    let r = call_timeout(DEAD, &msg[..n], reply, &mut buf, 200_000);
    let took = uptime() - start;
    report(
        f,
        "a stopped service: TIMED_OUT after 200 ms, within 3 ticks",
        matches!(r, Err(Error::TimedOut)) && (200_000..230_000).contains(&took),
    );
}

fn generate(f: &mut u64) {
    let Ok(reply) = endpoint_create() else {
        report(f, "create a reply endpoint", false);
        return;
    };
    let want = expected(reply);
    report(f, "read the host's expected text", want.is_some());

    let (r, n) = call(reply, Request::Info, SHORT_US);
    let before = test_model(&r[..n]);
    report(
        f,
        "INFO: inference v1, 4 models, test model not loaded, context 64",
        before.is_some_and(|(m, count)| {
            count == 4 && m.name == b"test" && m.state == ModelState::NotLoaded && m.context == 64
        }),
    );
    let mut v2 = [0u8; 32];
    let n = encode(&Request::Info, &mut v2).unwrap_or(0);
    v2[0] = VERSION + 1;
    let (r, len) = raw(SERVICE, reply, &v2[..n], SHORT_US);
    report(
        f,
        "version 2: VERSION, supported 1 to 1",
        versions(&r[..len]) == Some((VERSION, VERSION)),
    );
    let generate = |model| Request::Generate {
        model,
        max_new: NEW,
        prompt_len: PROMPT.len() as u32,
    };
    report(
        f,
        "GENERATE with no buffer: NO_BUFFER",
        status(&call(reply, generate(2), SHORT_US)) == Status::NoBuffer,
    );
    let mut msg = [0u8; 32];
    let n = encode(&Request::Attach { len: 4096 }, &mut msg).unwrap_or(0);
    let Some(buffer) = attach(SERVICE, &msg[..n], 4096) else {
        report(f, "attach a prompt buffer", false);
        return;
    };
    buffer.write_bytes(0, PROMPT);
    report(
        f,
        "GENERATE with model 9: NO_MODEL",
        status(&call(reply, generate(9), SHORT_US)) == Status::NoModel,
    );
    let (r, n) = call(reply, generate(2), GENERATE_US);
    let started = Started::parse(&r[..n]);
    report(
        f,
        "GENERATE: a session, 5 prompt tokens",
        started.is_some_and(|s| s.prompt_tokens == 5),
    );
    let Some(started) = started else {
        return;
    };
    let mut text = Vec::new();
    let mut stop = None;
    let mut pulls = 0;
    while stop.is_none() && pulls < 40 {
        pulls += 1;
        let (r, n) = call(
            reply,
            Request::Next {
                session: started.session,
            },
            NEXT_US,
        );
        let Some(t) = Tokens::parse(&r[..n]) else {
            break;
        };
        text.extend_from_slice(t.text);
        stop = t.stop;
    }
    report(
        f,
        "NEXT until the token limit",
        stop == Some(Stop::TokenLimit),
    );
    report(f, "the text is the host's", want.is_some_and(|w| w == text));
    report(
        f,
        "NEXT after the end: NO_SESSION",
        status(&call(
            reply,
            Request::Next {
                session: started.session,
            },
            SHORT_US,
        )) == Status::NoSession,
    );
    let (r, n) = call(
        reply,
        Request::Result {
            session: started.session,
        },
        SHORT_US,
    );
    let record = Record::parse(&r[..n]);
    let sha = before.map(|(m, _)| m.sha256);
    report(
        f,
        "RESULT: model 2 and its SHA-256, engine version, 5 + 20 tokens, token limit",
        record.is_some_and(|rec| {
            rec.model == 2
                && Some(rec.sha256) == sha
                && rec.engine == pharos_infer::VERSION
                && (rec.max_new, rec.prompt_tokens, rec.generated) == (NEW, 5, 20)
                && rec.stop == Stop::TokenLimit
                && rec.generate_us > 0
        }),
    );
    let (r, n) = call(reply, Request::Info, SHORT_US);
    report(
        f,
        "INFO: the test model is loaded",
        test_model(&r[..n]).is_some_and(|(m, _)| m.state == ModelState::Loaded),
    );
}

fn main(arg: u64) -> u64 {
    let mut f = 0;
    match arg {
        1 => generate(&mut f),
        2 => failures(&mut f),
        _ => f = 0xbad,
    }
    f
}
