//! The inference service (#88, inference.md): generates text with
//! `pharos-infer` for clients, one session at a time, from the models in
//! the compiled-in manifest ([`pharos_programs::models`]).
//!
//! Handles: 1 the console, 2 its endpoint (`RECEIVE`), 3 the report
//! endpoint (`SEND`), 4 the storage service, badged for the `models`
//! namespace read-only (`SEND`). Nothing else. It sends `ready` at once
//! and loads a model on its first `GENERATE`; the model then stays in
//! memory. Serves [`pharos_proto::infer`], version 1.
//!
//! Clients are told apart by their badge (0 is refused). Replies use
//! non-blocking sends, so a client that does not wait cannot stall the
//! service, and a session that sees no `NEXT` for [`IDLE_US`] is cancelled.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use pharos_infer::session::{self, Engine, Session};
use pharos_programs::fp::Libm;
use pharos_programs::models::{self, MANIFEST, Model as Entry, find};
use pharos_proto::infer::{
    MAX_BUFFER, MAX_NEW, MAX_PROMPT, MAX_TEXT, Model, ModelState, NAME, NEXT_TOKENS, Record,
    Request, Started, Status, Step, Stop, Tokens, VERSION, parse,
};
use pharos_proto::store::{self, Request as StoreRequest, Status as StoreStatus};
use pharos_proto::{Info, Writer, refusal};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, debug_write, delete, endpoint_create, mem_map_buffer,
    mem_map_cap, mem_share, mem_unmap, receive_timeout, send, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const STORE: Handle = 4;
/// A session with no `NEXT` for this long is cancelled.
const IDLE_US: u64 = 10_000_000;
/// The window model files are read through (as #78).
const WINDOW: u64 = 16 << 20;
/// Most clients with an attached buffer.
const MAX_CLIENTS: usize = 8;
/// Each store request may take this long.
const STORE_TIMEOUT_US: u64 = 10_000_000;

/// A loaded model, kept until the service ends. Leaked so sessions can
/// borrow it for `'static`.
// ponytail: models are never unloaded; one 1 GiB service holds one S1 model.
type Loaded = &'static Engine<'static>;

/// A running generation.
struct Active {
    badge: u32,
    number: u32,
    model: &'static Entry,
    session: Session<'static, 'static>,
    /// Generated text not yet returned.
    pending: Vec<u8>,
    max_new: u16,
    prompt_tokens: u32,
    prompt_us: u64,
    generate_us: u64,
    last_seen: u64,
}

/// One client's attached prompt buffer, and its last ended session.
struct Client {
    badge: u32,
    buffer: Mapped,
    /// The session number and record, kept per client so another client's
    /// session cannot replace it before it is read (M3.2 review, F1).
    ended: Option<(u32, Record)>,
}

struct Service {
    /// Per manifest entry: not tried, loaded, or failed at a step.
    models: [Option<Result<Loaded, Step>>; MANIFEST.len()],
    clients: [Option<Client>; MAX_CLIENTS],
    active: Option<Active>,
    next_number: u32,
    /// The window into the storage service, once attached.
    window: Option<Mapped>,
    store_reply: Handle,
}

fn say(parts: &[&[u8]]) {
    let mut line = [0u8; 128];
    let mut n = 0;
    for p in parts {
        let take = p.len().min(line.len() - n);
        line[n..n + take].copy_from_slice(&p[..take]);
        n += take;
    }
    let _ = debug_write(CONSOLE, &line[..n]);
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

impl Service {
    /// A storage request by `call`; the status and the reply.
    fn store(&self, req: StoreRequest<'_>) -> (StoreStatus, [u8; 256]) {
        let mut msg = [0u8; 256];
        let mut buf = [0u8; 256];
        let Some(n) = store::encode(&req, &mut msg) else {
            return (StoreStatus::BadRequest, buf);
        };
        match call_timeout(
            STORE,
            &msg[..n],
            self.store_reply,
            &mut buf,
            STORE_TIMEOUT_US,
        ) {
            Ok(Received::Message { len, .. }) if len >= 1 => (StoreStatus::from_code(buf[0]), buf),
            _ => (StoreStatus::IoError, buf),
        }
    }

    /// Maps the window and attaches it to the storage service (once).
    fn window(&mut self) -> Option<&Mapped> {
        if self.window.is_none() {
            let buf = mem_map_buffer(WINDOW).ok()?;
            let memory = mem_share(buf.addr(), WINDOW).ok()?;
            let mut msg = [0u8; 16];
            let n = store::encode(&StoreRequest::Attach { len: WINDOW }, &mut msg)?;
            let sent = send(STORE, &msg[..n], memory, READ | WRITE, 0);
            // The store has its own copy; the service keeps only the mapping.
            let _ = delete(memory);
            sent.ok()?;
            let (s, r) = self.store(StoreRequest::Buffer);
            if s != StoreStatus::Ok || u64_at(&r, 1) != WINDOW {
                return None;
            }
            self.window = Some(buf);
        }
        self.window.as_ref()
    }

    /// Loads manifest entry `m`: size, then the whole file into private
    /// memory, its SHA-256, the GGUF reader and loader, and every
    /// configuration value.
    fn load(&mut self, m: &Entry) -> Result<Loaded, Step> {
        let (s, r) = self.store(StoreRequest::Stat { path: m.path });
        if s != StoreStatus::Ok || r[1] != 1 {
            return Err(Step::Read);
        }
        if u64_at(&r, 2) != m.size {
            return Err(Step::Size);
        }
        let len = usize::try_from(m.size).map_err(|_| Step::Size)?;
        let mut file = Vec::new();
        file.try_reserve_exact(len).map_err(|_| Step::Read)?;
        file.resize(len, 0u8);
        let mut done = 0u64;
        while done < m.size {
            let n = WINDOW.min(m.size - done);
            let (s, r) = self.store(StoreRequest::Read {
                path: m.path,
                offset: done,
                len: n,
                at: 0,
            });
            if s != StoreStatus::Ok || u64_at(&r, 1) != n {
                return Err(Step::Read);
            }
            // Copied out: the store may write the window at any time.
            let window = self.window().ok_or(Step::Read)?;
            window.read_bytes(0, &mut file[done as usize..(done + n) as usize]);
            done += n;
        }
        models::verify(m, &file)?;
        // ponytail: leaked once the hash matches; a file that then fails
        // below stays in memory until the service restarts (only possible
        // if the manifest entry itself is wrong).
        let bytes: &'static [u8] = file.leak();
        let engine = models::open(m, bytes)?;
        Ok(Box::leak(Box::new(engine)))
    }

    /// The loaded model for entry `i`, loading it on first use.
    fn model(&mut self, i: usize) -> Result<Loaded, Step> {
        if let Some(done) = self.models[i] {
            return done;
        }
        if self.window().is_none() {
            return Err(Step::Read);
        }
        let result = self.load(&MANIFEST[i]);
        let step: &[u8] = match result {
            Ok(_) => b"loaded",
            Err(Step::Read) => b"failed: read",
            Err(Step::Size) => b"failed: size",
            Err(Step::Hash) => b"failed: hash",
            Err(Step::Format) => b"failed: format",
            Err(Step::Config) => b"failed: configuration",
        };
        say(&[b"infer: model ", MANIFEST[i].name, b" ", step]);
        self.models[i] = Some(result);
        result
    }

    /// `ATTACH`: maps the client's prompt buffer read-only.
    fn attach(&mut self, badge: u32, memory: Handle, len: u64) {
        let mapped = (badge != 0 && len <= MAX_BUFFER)
            .then(|| mem_map_cap(memory, false, len).ok())
            .flatten();
        let _ = delete(memory);
        let Some(buffer) = mapped else {
            return;
        };
        let slot = self
            .clients
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.badge == badge))
            .or_else(|| self.clients.iter().position(Option::is_none));
        let Some(slot) = slot else {
            let _ = mem_unmap(buffer.addr(), buffer.len() as u64);
            return;
        };
        // The slot is this client's or empty: a new buffer keeps the record.
        let ended = self.clients[slot].take().and_then(|old| {
            let _ = mem_unmap(old.buffer.addr(), old.buffer.len() as u64);
            old.ended
        });
        self.clients[slot] = Some(Client {
            badge,
            buffer,
            ended,
        });
    }

    /// Ends the active session with `stop`, keeping its record.
    fn end(&mut self, stop: Stop) {
        if let Some(a) = self.active.take() {
            let record = Record {
                model: a.model.number,
                sha256: a.model.sha256,
                engine: pharos_infer::VERSION,
                max_new: a.max_new,
                prompt_tokens: a.prompt_tokens,
                generated: a.session.generated() as u32,
                stop,
                prompt_us: a.prompt_us,
                generate_us: a.generate_us,
            };
            // Every session's client has a slot: GENERATE needs its buffer.
            if let Some(c) = self
                .clients
                .iter_mut()
                .flatten()
                .find(|c| c.badge == a.badge)
            {
                c.ended = Some((a.number, record));
            }
        }
    }

    fn generate(
        &mut self,
        badge: u32,
        model: u8,
        max_new: u16,
        prompt_len: u32,
        out: &mut [u8],
    ) -> Result<usize, Status> {
        if self.active.is_some() {
            return Err(Status::Busy);
        }
        let i = MANIFEST
            .iter()
            .position(|m| m.number == model)
            .ok_or(Status::NoModel)?;
        let entry = find(model).ok_or(Status::NoModel)?;
        if max_new == 0 || prompt_len == 0 {
            return Err(Status::BadRequest);
        }
        if max_new > MAX_NEW || prompt_len > MAX_PROMPT {
            return Err(Status::TooLarge);
        }
        let buffer = self
            .clients
            .iter()
            .flatten()
            .find(|c| c.badge == badge)
            .map(|c| &c.buffer)
            .filter(|b| prompt_len as usize <= b.len())
            .ok_or(Status::NoBuffer)?;
        // Copied out first, so the client cannot change it while we work.
        let mut prompt = alloc::vec![0u8; prompt_len as usize];
        buffer.read_bytes(0, &mut prompt);
        let text = core::str::from_utf8(&prompt).map_err(|_| Status::BadRequest)?;
        let engine = match self.model(i) {
            Ok(e) => e,
            Err(step) => {
                out[1] = step as u8;
                return Err(Status::ModelInvalid);
            }
        };
        let start = uptime();
        let tokens = engine.tokenizer.encode(text);
        if tokens.len() + usize::from(max_new) > entry.context as usize {
            return Err(Status::Context);
        }
        let session = Session::new(engine, &tokens, usize::from(max_new), &Libm)
            .map_err(|_| Status::Internal)?;
        let number = self.next_number;
        self.next_number = self.next_number.wrapping_add(1).max(1);
        let now = uptime();
        self.active = Some(Active {
            badge,
            number,
            model: entry,
            session,
            pending: Vec::new(),
            max_new,
            prompt_tokens: tokens.len() as u32,
            prompt_us: now - start,
            generate_us: 0,
            last_seen: now,
        });
        Started {
            session: number,
            prompt_tokens: tokens.len() as u32,
        }
        .encode(out)
        .ok_or(Status::Internal)
    }

    fn next(&mut self, badge: u32, number: u32, out: &mut [u8]) -> Result<usize, Status> {
        let a = match &mut self.active {
            Some(a) if a.badge == badge && a.number == number => a,
            _ => return Err(Status::NoSession),
        };
        let start = uptime();
        let mut steps = 0;
        while steps < NEXT_TOKENS
            && a.pending.len() < MAX_TEXT
            && a.session.step(&mut a.pending, &Libm)
        {
            steps += 1;
        }
        let now = uptime();
        a.generate_us += now - start;
        a.last_seen = now;
        let n = a.pending.len().min(MAX_TEXT);
        let stop = match a.session.stop() {
            _ if n < a.pending.len() => None,
            Some(session::Stop::EndOfText) => Some(Stop::EndOfText),
            Some(session::Stop::TokenLimit) => Some(Stop::TokenLimit),
            None => None,
        };
        let len = Tokens {
            stop,
            text: &a.pending[..n],
        }
        .encode(out)
        .ok_or(Status::Internal)?;
        a.pending.drain(..n);
        if let Some(stop) = stop {
            self.end(stop);
        }
        Ok(len)
    }

    fn info(&self, out: &mut [u8]) -> Option<usize> {
        let mut details = [0u8; 240];
        let mut w = Writer::new(&mut details);
        w.bytes(&[MANIFEST.len() as u8])?;
        for (m, state) in MANIFEST.iter().zip(&self.models) {
            Model {
                number: m.number,
                state: match state {
                    None => ModelState::NotLoaded,
                    Some(Ok(_)) => ModelState::Loaded,
                    Some(Err(step)) => ModelState::Failed(*step),
                },
                context: m.context,
                sha256: m.sha256,
                name: m.name,
            }
            .encode(&mut w)?;
        }
        let len = w.len();
        Info {
            name: NAME,
            low: VERSION,
            high: VERSION,
            details: &details[..len],
        }
        .encode(out)
    }

    /// Handles one `call`; writes the reply (status first) into `out`.
    fn handle(&mut self, msg: &[u8], badge: u32, out: &mut [u8; 256]) -> usize {
        let req = match parse(msg) {
            Ok(req) => req,
            Err(refused) => return refusal(refused, VERSION, out),
        };
        if badge == 0 {
            out[0] = Status::NoAccess as u8;
            return 1;
        }
        let result = match req {
            Request::Info => self.info(out).ok_or(Status::Internal),
            Request::Generate {
                model,
                max_new,
                prompt_len,
            } => self.generate(badge, model, max_new, prompt_len, out),
            Request::Next { session } => self.next(badge, session, out),
            Request::Cancel { session } => match &self.active {
                Some(a) if a.badge == badge && a.number == session => {
                    self.end(Stop::Cancelled);
                    Ok(1)
                }
                _ => Err(Status::NoSession),
            },
            Request::Result { session } => {
                let ended = self.clients.iter().flatten().find(|c| c.badge == badge);
                match (&self.active, ended.and_then(|c| c.ended.as_ref())) {
                    (Some(a), _) if a.badge == badge && a.number == session => Err(Status::Busy),
                    (_, Some((n, record))) if *n == session => {
                        record.encode(out).ok_or(Status::Internal)
                    }
                    _ => Err(Status::NoSession),
                }
            }
            // A `call` with ATTACH carries no buffer.
            Request::Attach { .. } => Err(Status::BadRequest),
        };
        match result {
            Ok(n) => {
                out[0] = Status::Ok as u8;
                n
            }
            Err(Status::ModelInvalid) => {
                out[0] = Status::ModelInvalid as u8;
                2
            }
            Err(s) => {
                out[0] = s as u8;
                1
            }
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(store_reply) = endpoint_create() else {
        return 1;
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 2;
    }
    let mut s = Service {
        models: [None; MANIFEST.len()],
        clients: Default::default(),
        active: None,
        next_number: 1,
        window: None,
        store_reply,
    };
    let mut msg = [0u8; 256];
    loop {
        // Wake up in time to drop an idle session.
        let wait = match &s.active {
            Some(a) => (a.last_seen + IDLE_US).saturating_sub(uptime()).max(1),
            None => u64::MAX,
        };
        let received = receive_timeout(SERVICE, &mut msg, wait);
        if s.active
            .as_ref()
            .is_some_and(|a| uptime() - a.last_seen >= IDLE_US)
        {
            s.end(Stop::Cancelled);
        }
        let Ok(Received::Message { len, cap, badge }) = received else {
            continue;
        };
        let msg = &msg[..len.min(256)];
        if let Ok(Request::Attach { len }) = parse(msg) {
            if cap != 0 {
                s.attach(badge, cap, len);
            }
            continue;
        }
        // A call: the capability is the one-shot reply capability.
        let mut reply = [0u8; 256];
        let n = s.handle(msg, badge, &mut reply);
        if cap != 0 {
            let _ = try_send(cap, &reply[..n]);
            let _ = delete(cap);
        }
    }
}
