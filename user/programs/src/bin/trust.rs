//! The trusted service (D-018, agents.md): the user's controls on the
//! trusted path, which work without any agent, the agent runtime, or a
//! model. It owns the virtio-console device; no other process can read
//! what the user types or write what looks like its answers.
//!
//! Handles: 1 the virtio-console device, 2 its endpoint (`RECEIVE`), 3
//! `init`'s report endpoint (`SEND`), 4 the audit service (`SEND`,
//! badged as `trust`; #107), and 5 the knowledge service (`SEND`, client
//! 2; #144), when given. Nothing else: it holds no serial console,
//! storage, network, or inference capability.
//!
//! The audit trail's anchor (#107): at start and on `audit`, `trust` shows
//! the audit service's boot, record count, and chain head, so the user can
//! compare them with what was shown before.
//!
//! The user's commands are recorded there too (#108), as actor `user`:
//! stops (after stopping: an emergency stop never waits for the trail),
//! revocations, and answers. A record that fails is skipped. It receives
//! process capabilities over [`pharos_proto::trust`]: the agent runtime's
//! from `init`, each agent's from the runtime.
//!
//! Commands, one per line: `list`, `stop <agent>`, `stop group <group>` (#136), `stop all`, and
//! `revoke <agent> <permission>` (#105), which `trust` passes to the
//! runtime with a non-blocking send on the capability the runtime gave it
//! (`CHANNEL`), so a hung runtime never holds `trust`; the runtime's
//! `REVOKED` answer is shown when it comes.
//!
//! Approvals (#106): the runtime's `APPROVE` becomes a prompt that `trust`
//! writes from its fields alone, `approve #<n>: <agent> task <id> wants
//! <permission> for this task? (yes <n> / no <n>)`; the user answers
//! `yes <n>` or `no <n>`. The runtime decides the outcome (including the
//! timeout) and says so with `RESOLVED`, which `trust` shows.
//!
//! Services (#152): `init` sends each service event as `SERVICE`, which
//! `trust` writes from its fields; `services` asks `init` for each
//! service's state (`pharos_proto::service`, on the report capability),
//! waiting at most 1 s. `trust` keeps no state of its own about services.
//!
//! Recovery (#164, boot.md section 8): `system` asks `init` for the mode,
//! the image running, and each slot (`SYSTEM`); `safe` and `recovery` ask
//! it to write that mode for the next boot into the slot record (`NEXT`),
//! recorded as the user's. Answers are written from `init`'s fields.
//!
//! Updates (#165): `update` asks `init` to check the incoming images
//! (`UPDATE`); `init` answers at once and sends an `OFFER` for each, which
//! `trust` shows as `update #<n>: <file> version <v> (sha256 <16 hex>),
//! now <image> version <v'>; apply? (apply <n> / discard <n>)` or as
//! refused with the reason. `apply <n>` and `discard <n>` (`ANSWER`) and
//! `rollback` (`ROLLBACK`) are recorded as the user's; `init` reports the
//! outcome as image events. `trust` never waits on the checks.
//!
//! Verification (#144, knowledge.md): `verify <scope> <key> <version>
//! <hash>` asks the knowledge service, with a bounded wait, to mark the
//! version verified if its content's SHA-256 starts with the 8 typed
//! hexadecimal digits, read where the user read the content. The console
//! shows the version's author or why not, never its content.

#![no_std]
#![no_main]

use pharos_programs::virtio_console::{Console, RX_BUFFER, TX_BUFFER};
use pharos_proto::knowledge::{self, Author};
use pharos_proto::permission::Permission;
use pharos_proto::service::{self as listing, Action, Managed, Reply, Settings, System};
use pharos_proto::trust::{
    self, Command, Event, INIT, Line, Lines, MAX_NAME, MAX_NAMES, Names, Outcome, RUNTIME, Request,
    SLOTS, parse,
};
use pharos_proto::{agents, audit, status};
use pharos_user::{
    Handle, Received, Status, Usage as Use, call_timeout, delete, endpoint_create, irq_create,
    irq_notify, process_status, process_stop, process_usage, receive, send, sleep, try_send,
};

pharos_user::entry!(main);

const DEVICE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const AUDIT: Handle = 4;
const KNOWLEDGE: Handle = 5;
/// How long `trust` waits for the knowledge service's `VERIFY`.
const KNOWLEDGE_US: u64 = 1_000_000;
/// How long `trust` waits for the audit service's `HEAD`.
const AUDIT_US: u64 = 1_000_000;
/// How long `trust` waits for each page of `init`'s `SERVICES`.
const INIT_US: u64 = 1_000_000;
const BASE: u64 = 0x1000_0000;
/// Two lines: one console line holds at most 256 bytes.
const HELP: &[u8] = b"commands: list, stop <agent>, stop group <group>, stop all, \
revoke <agent> <permission>, yes <n>, no <n>, audit, usage, verify <scope> <key> <version> <hash>";
const HELP_SYSTEM: &[u8] = b"commands: services, health, config, start <service>, \
restart <service>, stop service <service>, system, safe, recovery, update, apply <n>, discard <n>, rollback";
/// How long a stop may take before the answer says it is still running.
const STOP_WAIT_US: u64 = 1_000_000;

/// A registered agent: its name, its group (#136), and its process
/// capability (`STOP`, `WAIT`).
#[derive(Clone, Copy)]
struct Agent {
    name: [u8; MAX_NAME],
    len: usize,
    group: [u8; MAX_NAME],
    group_len: usize,
    process: Handle,
}

struct Trust {
    console: Console,
    runtime: Option<Handle>,
    /// `SEND` on the runtime, badged as `trust` (`CHANNEL`).
    channel: Option<Handle>,
    /// Approval requests shown and not yet resolved.
    open: [u16; 4],
    /// Which of them are confirmations of a tool call (#128).
    confirms: [u16; 4],
    /// For `call`s to the audit service.
    reply: Option<Handle>,
    agents: [Option<Agent>; SLOTS as usize],
}

impl Trust {
    /// One line on the trusted console, `\r\n` added. Dropped if the
    /// console is full: output never makes the service wait.
    fn say(&mut self, parts: &[&[u8]]) {
        let mut line = [0u8; TX_BUFFER];
        let mut n = 0;
        for p in parts.iter().chain([&&b"\r\n"[..]]) {
            let take = p.len().min(line.len() - n);
            line[n..n + take].copy_from_slice(&p[..take]);
            n += take;
        }
        let _ = self.console.send(&line[..n]);
    }

    fn status(&mut self, label: &[u8], process: Handle) {
        let mut digits = [0u8; 20];
        let (word, number): (&[u8], Option<u64>) = match process_status(process) {
            Ok(Status::Running) => (b"running", None),
            Ok(Status::Exited(code)) => (b"exited", Some(code)),
            Ok(Status::Killed(vector)) => (b"killed", Some(vector)),
            Ok(Status::Stopped) => (b"stopped", None),
            Err(_) => (b"unknown", None),
        };
        let number = number.map_or(&b""[..], |v| decimal(v, &mut digits));
        let space: &[u8] = if number.is_empty() { b"" } else { b" " };
        self.say(&[label, b" ", word, space, number]);
    }

    /// Stops `process` and waits up to [`STOP_WAIT_US`] for it to end.
    fn stop(&mut self, label: &[u8], process: Handle) {
        let _ = process_stop(process);
        let mut waited = 0;
        while waited < STOP_WAIT_US && process_status(process) == Ok(Status::Running) {
            sleep(10_000);
            waited += 10_000;
        }
        match process_status(process) {
            Ok(Status::Running) => self.say(&[b"stopping ", label, b": still running"]),
            _ => self.say(&[b"stopped ", label]),
        }
    }

    /// Sends `req` on the channel without blocking, for at most 2 s: the
    /// runtime may be busy or hung, and `stop` must keep working.
    fn tell_runtime(&self, req: &agents::Request<'_>) -> bool {
        let mut msg = [0u8; 64];
        let (Some(c), Some(n)) = (self.channel, agents::encode(req, &mut msg)) else {
            return false;
        };
        for _ in 0..200 {
            if try_send(c, &msg[..n]).is_ok() {
                return true;
            }
            sleep(10_000);
        }
        false
    }

    /// Records a user command (best effort, at most 1 s).
    fn record(&self, act: u8, permission: Option<Permission>, detail: &[u8]) {
        let entry = audit::Entry {
            kind: audit::Kind::Event,
            refers: 0,
            actor: b"user",
            task: 0,
            attempt: 0,
            action: act,
            permission,
            service: b"trust",
            outcome: audit::outcome::OK,
            detail,
        };
        let mut msg = [0u8; 256];
        let (Some(reply), Some(n)) = (
            self.reply,
            audit::encode(&audit::Request::Append(entry), &mut msg),
        ) else {
            return;
        };
        // The request is sent from this buffer too, so it must hold it.
        let mut out = [0u8; 256];
        let _ = call_timeout(AUDIT, &msg[..n], reply, &mut out, AUDIT_US);
    }

    /// The audit trail's anchor: boot, record count, chain head.
    fn audit(&mut self) {
        let mut out = [0u8; 256];
        let msg = [audit::VERSION, audit::op::HEAD];
        let head = self.reply.and_then(|reply| {
            match call_timeout(AUDIT, &msg, reply, &mut out, AUDIT_US) {
                Ok(Received::Message { len, .. }) => audit::Head::parse(&out[..len.min(256)]),
                _ => None,
            }
        });
        let Some(h) = head else {
            self.say(&[b"audit: not answering"]);
            return;
        };
        let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
        let mut hex = [0u8; 64];
        for (i, byte) in h.head.iter().enumerate() {
            hex[2 * i] = b"0123456789abcdef"[usize::from(byte >> 4)];
            hex[2 * i + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
        }
        self.say(&[
            b"audit: boot ",
            decimal(u64::from(h.boot), &mut a),
            b", ",
            decimal(h.records, &mut b),
            b" records, head ",
            &hex,
        ]);
    }

    fn command(&mut self, line: &[u8]) {
        match trust::command(line) {
            Command::List => {
                if let Some(runtime) = self.runtime {
                    self.status(b"runtime", runtime);
                }
                let agents = self.agents;
                if agents.iter().all(Option::is_none) {
                    self.say(&[b"no agents"]);
                }
                for a in agents.iter().flatten() {
                    self.status(&a.name[..a.len], a.process);
                }
            }
            // Every process registered under the name: one agent may run
            // several tasks at once, one process each.
            Command::Stop(name) => {
                let agents = self.agents;
                let mut found = false;
                for a in agents.iter().flatten().filter(|a| &a.name[..a.len] == name) {
                    self.stop(&a.name[..a.len], a.process);
                    found = true;
                }
                if found {
                    self.record(audit::action::STOP, None, name);
                } else {
                    self.say(&[b"no agent ", name]);
                }
            }
            // Without the runtime (#136): `trust` holds every agent's STOP.
            // The runtime cancels each stopped task, and a goal's end
            // cancels its subtasks not yet started.
            Command::StopGroup(group) => {
                let agents = self.agents;
                let mut found = false;
                for a in agents
                    .iter()
                    .flatten()
                    .filter(|a| &a.group[..a.group_len] == group)
                {
                    self.stop(&a.name[..a.len], a.process);
                    found = true;
                }
                if found {
                    self.record(audit::action::STOP, None, &[&b"group "[..], group].concat());
                    self.say(&[b"stopped group ", group]);
                } else {
                    self.say(&[b"no group ", group]);
                }
            }
            // The runtime first: its agents end with it (children stop
            // with their parent). Then each agent, in case one is not its.
            Command::StopAll => {
                if let Some(runtime) = self.runtime {
                    self.stop(b"runtime", runtime);
                }
                let agents = self.agents;
                for a in agents.iter().flatten() {
                    self.stop(&a.name[..a.len], a.process);
                }
                self.say(&[b"stopped all"]);
                self.record(audit::action::STOP, None, b"all");
            }
            Command::Revoke(name, permission) => {
                if self.tell_runtime(&agents::Request::Revoke { name, permission }) {
                    self.record(audit::action::REVOKE, Some(permission), name);
                } else {
                    self.say(&[b"revoke: the runtime is not answering; stop works"]);
                }
            }
            Command::Answer(number, yes) => {
                let mut d = [0u8; 20];
                let n = decimal(u64::from(number), &mut d);
                if number == 0 || !self.open.contains(&number) {
                    self.say(&[b"no request #", n]);
                } else if self.tell_runtime(&agents::Request::Answer { number, yes }) {
                    let act = if yes {
                        audit::action::APPROVE
                    } else {
                        audit::action::REFUSE
                    };
                    let mut detail = [0u8; 21];
                    detail[0] = b'#';
                    detail[1..1 + n.len()].copy_from_slice(n);
                    let k = 1 + n.len();
                    self.record(act, None, &detail[..k]);
                } else {
                    self.say(&[b"answer: the runtime is not answering; stop works"]);
                }
            }
            Command::Audit => self.audit(),
            Command::Services => self.services(false),
            Command::Health => self.services(true),
            Command::Config => self.config(),
            Command::System => self.system(),
            Command::NextBoot(mode) => self.next_boot(mode),
            Command::Update => self.update(),
            Command::UpdateAnswer(number, apply) => self.update_answer(number, apply),
            Command::Rollback => self.rollback(),
            // The runtime's own from the kernel; each attempt's and group's
            // from the runtime, which answers with numbers only (#119).
            Command::Usage => {
                if let Some(runtime) = self.runtime {
                    let cpu = process_usage(runtime, Use::CpuMicros).unwrap_or(0) / 1000;
                    let pages = process_usage(runtime, Use::Pages).unwrap_or(0);
                    let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
                    let (cpu, pages) = (decimal(cpu, &mut a), decimal(pages, &mut b));
                    self.say(&[b"usage: runtime cpu ", cpu, b" ms, ", pages, b" pages"]);
                }
                if !self.tell_runtime(&agents::Request::Usage) {
                    self.say(&[b"usage: the runtime is not answering; stop works"]);
                }
            }
            Command::Verify {
                scope,
                key,
                version,
                prefix,
            } => self.verify(scope, key, version, prefix),
            Command::Help => {
                self.say(&[HELP]);
                self.say(&[HELP_SYSTEM]);
            }
            Command::Manage(action, name) => self.manage(action, name),
        }
    }

    /// `start`, `stop service`, or `restart` (#170): `init` decides and
    /// reports the action itself (`SERVICE`); only a refusal is said here.
    fn manage(&mut self, action: Action, name: &[u8]) {
        let word: &[u8] = match action {
            Action::Start => b"start: ",
            Action::Stop => b"stop: ",
            Action::Restart => b"restart: ",
        };
        let mut out = [0u8; 256];
        let req = listing::Request::Manage { action, name };
        let answer = self.ask_init(&req, &mut out).map(Managed::parse);
        match answer {
            Some(Some(Managed::Ok)) => {}
            Some(Some(Managed::Unknown)) => self.say(&[word, b"no service ", name]),
            Some(Some(Managed::Busy)) => {
                self.say(&[word, b"not now (booting, updating, or in recovery)"])
            }
            Some(Some(Managed::Protected)) => self.say(&[
                word,
                name,
                b" is protected: it can be restarted, not stopped",
            ]),
            Some(Some(Managed::Running)) => self.say(&[word, name, b" is running"]),
            Some(Some(Managed::NotRunning)) => self.say(&[word, name, b" is not running"]),
            Some(Some(Managed::Needs(d))) => self.say(&[word, name, b" needs ", d]),
            Some(None) => self.say(&[word, b"refused"]),
            None => self.say(&[word, b"init is not answering"]),
        }
    }

    /// Asks `init` (on the report capability) and returns its answer.
    fn ask_init<'a>(&self, req: &listing::Request, out: &'a mut [u8; 256]) -> Option<&'a [u8]> {
        let mut msg = [0u8; 48];
        let n = listing::encode(req, &mut msg)?;
        match call_timeout(REPORT, &msg[..n], self.reply?, out, INIT_US) {
            Ok(Received::Message { len, .. }) => Some(&out[..len.min(256)]),
            _ => None,
        }
    }

    /// After a restart (#170): the running runtime's process capability
    /// from `init`, before any typed command, so `stop all` works at once.
    /// At boot the runtime does not run yet; it is registered when it
    /// starts (`RUNTIME` from `init`).
    fn ask_runtime(&mut self) {
        let (Some(reply), mut out, mut msg) = (self.reply, [0u8; 8], [0u8; 8]) else {
            return;
        };
        let Some(n) = listing::encode(&listing::Request::Runtime, &mut msg) else {
            return;
        };
        if let Ok(Received::Message { cap, len, .. }) =
            call_timeout(REPORT, &msg[..n], reply, &mut out, INIT_US)
        {
            if out[..len.min(8)] == [status::OK] && cap != 0 && process_status(cap).is_ok() {
                if let Some(old) = self.runtime.replace(cap) {
                    let _ = delete(old);
                }
                self.say(&[b"registered runtime"]);
            } else if cap != 0 {
                let _ = delete(cap);
            }
        }
    }

    /// The mode, the image running, and each slot, from `init` (#164).
    fn system(&mut self) {
        let mut out = [0u8; 256];
        let Some(sys) = self
            .ask_init(&listing::Request::System, &mut out)
            .and_then(System::parse)
        else {
            self.say(&[b"system: init is not answering"]);
            return;
        };
        let active: &[u8] = match sys.active {
            1 => b"A",
            2 => b"B",
            _ => b"none",
        };
        let mut d = [0u8; 20];
        self.say(&[
            b"system: ",
            sys.mode_word(),
            b" mode, running ",
            trust::image::name(sys.image.into()),
            b", active slot ",
            active,
            b", ",
            decimal(sys.incoming.into(), &mut d),
            b" incoming",
        ]);
        for (name, slot) in [(b"A", sys.slots[0]), (b"B", sys.slots[1])] {
            if slot.state == 0 {
                self.say(&[b"system: slot ", name, b" empty"]);
                continue;
            }
            let mut d = [[0u8; 20]; 2];
            let [a, b] = &mut d;
            let mut hex = [0u8; 16];
            for (i, byte) in slot.sha256.iter().enumerate() {
                hex[2 * i] = b"0123456789abcdef"[usize::from(byte >> 4)];
                hex[2 * i + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
            }
            self.say(&[
                b"system: slot ",
                name,
                b" ",
                slot.word(),
                b", version ",
                decimal(slot.version, a),
                b", attempts ",
                decimal(slot.attempts.into(), b),
                b", sha256 ",
                &hex,
            ]);
        }
    }

    /// Asks `init` to boot the next time in `mode` (1 safe, 2 recovery).
    fn next_boot(&mut self, mode: u8) {
        let word: &[u8] = if mode == 1 { b"safe" } else { b"recovery" };
        let mut out = [0u8; 256];
        match self.ask_init(&listing::Request::Next { mode }, &mut out) {
            Some([status::OK]) => {
                self.say(&[b"next boot: ", word, b" mode"]);
                self.record(audit::action::SYSTEM, None, &[b"next boot ", word].concat());
            }
            Some(_) => self.say(&[b"next boot: the slot record cannot be written"]),
            None => self.say(&[b"next boot: init is not answering"]),
        }
    }

    /// Asks `init` to check the incoming images (#165); the offers come
    /// as `OFFER`s.
    fn update(&mut self) {
        let mut out = [0u8; 256];
        let mut d = [0u8; 20];
        match self.ask_init(&listing::Request::Update, &mut out) {
            Some([status::OK, 0]) => self.say(&[b"update: nothing incoming"]),
            Some([status::OK, n]) => {
                let n = decimal(u64::from(*n), &mut d);
                self.say(&[b"update: checking ", n, b" incoming"]);
            }
            Some([status::BUSY]) => {
                self.say(&[b"update: not now (booting, updating, or not in normal mode)"])
            }
            Some(_) => self.say(&[b"update: refused"]),
            None => self.say(&[b"update: init is not answering"]),
        }
    }

    /// The user's answer to update offer `number` (#165).
    fn update_answer(&mut self, number: u16, apply: bool) {
        let mut out = [0u8; 256];
        let mut d = [0u8; 20];
        let n = decimal(u64::from(number), &mut d);
        let req = listing::Request::Answer { number, apply };
        match self.ask_init(&req, &mut out) {
            Some([status::OK]) => {
                let (word, what): (&[u8], &[u8]) = if apply {
                    (b"apply #", b": applying; the services start again")
                } else {
                    (b"discard #", b": discarded")
                };
                self.say(&[b"update #", n, what]);
                let detail = [word, n].concat();
                self.record(audit::action::SYSTEM, None, &detail);
            }
            Some([status::NOT_FOUND]) => self.say(&[b"update: no offer #", n]),
            Some([status::CANCELLED]) => self.say(&[
                b"update #",
                n,
                b": not answered within 60 s; not applied (ask again with update)",
            ]),
            Some([status::BUSY]) => {
                self.say(&[b"update: not now (booting, updating, or not in normal mode)"])
            }
            Some(_) => self.say(&[b"update: refused"]),
            None => self.say(&[b"update: init is not answering"]),
        }
    }

    /// Back to the other slot (#165).
    fn rollback(&mut self) {
        let mut out = [0u8; 256];
        match self.ask_init(&listing::Request::Rollback, &mut out) {
            Some([status::OK]) => {
                self.say(&[b"rollback: the services start again"]);
                self.record(audit::action::SYSTEM, None, b"rollback");
            }
            Some([status::NOT_FOUND]) => self.say(&[b"rollback: no good slot to roll back to"]),
            Some([status::BUSY]) => {
                self.say(&[b"rollback: not now (booting, updating, or not in normal mode)"])
            }
            Some(_) => self.say(&[b"rollback: the slot record cannot be written"]),
            None => self.say(&[b"rollback: init is not answering"]),
        }
    }

    /// An incoming image `init` checked (#165), written from its fields.
    fn offer(&mut self, o: trust::Offer<'_>) {
        let mut d = [[0u8; 20]; 3];
        let [a, b, c] = &mut d;
        let n = decimal(u64::from(o.number), a);
        if let Some(reason) = o.refused {
            let why = (trust::image::REASONS.get(usize::from(reason)))
                .copied()
                .unwrap_or(b"unknown reason");
            let (lead, n, sep): (&[u8], &[u8], &[u8]) = if o.number == 0 {
                (b"update: ", b"", b"")
            } else {
                (b"update #", n, b": ")
            };
            // A refused configuration names its line (M4.5).
            let mut l = [0u8; 20];
            let line: &[u8] = if why == b"bad configuration" && o.version > 0 {
                &[&b", line "[..], decimal(o.version, &mut l)].concat()
            } else {
                b""
            };
            self.say(&[lead, n, sep, o.name, b" refused: ", why, line]);
            return;
        }
        let mut hex = [0u8; 16];
        for (i, byte) in o.sha256.iter().enumerate() {
            hex[2 * i] = b"0123456789abcdef"[usize::from(byte >> 4)];
            hex[2 * i + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
        }
        let (now, of): (&[u8], &[u8]) = if o.image == 1 || o.image == 2 {
            (b" version ", decimal(o.now, c))
        } else {
            (b"", b"")
        };
        self.say(&[
            b"update #",
            n,
            b": ",
            o.name,
            b" version ",
            decimal(o.version, b),
            b" (sha256 ",
            &hex,
            b"), now ",
            trust::image::name(o.image.into()),
            now,
            of,
            b"; apply? (apply ",
            n,
            b" / discard ",
            n,
            b")",
        ]);
    }

    /// The configuration in use, as `init` answers it (M4.5).
    fn config(&mut self) {
        let mut out = [0u8; 256];
        let answer = self
            .ask_init(&listing::Request::Config, &mut out)
            .map(Settings::parse);
        let s = match answer {
            Some(Some(s)) => s,
            _ => return self.say(&[b"config: init is not answering"]),
        };
        let from: &[u8] = if s.image == listing::COMPILED {
            b"compiled values"
        } else {
            trust::image::name(s.image.into())
        };
        let all: &[u8] = if s.total == 0 {
            b"; every compiled value"
        } else {
            b""
        };
        self.say(&[b"config: from ", from, all]);
        for e in s.iter() {
            let mut d = [[0u8; 20]; 2];
            let [a, b] = &mut d;
            let off: &[u8] = if e.off { b" start = no" } else { b"" };
            let (r, rn): (&[u8], &[u8]) = match e.restarts {
                Some(n) => (b" restarts = ", decimal(n.into(), a)),
                None => (b"", b""),
            };
            let (dl, dn): (&[u8], &[u8]) = match e.delay_ms {
                Some(ms) => (b" delay_ms = ", decimal(ms.into(), b)),
                None => (b"", b""),
            };
            self.say(&[b"config: ", e.name, off, r, rn, dl, dn]);
        }
        if s.count < s.total {
            let mut d = [0u8; 20];
            self.say(&[
                b"config: and ",
                decimal((s.total - s.count).into(), &mut d),
                b" more",
            ]);
        }
    }

    /// Each agent's process as the kernel reports it (M4.5): what it is
    /// and what it used, so it is shown even if the runtime is stuck.
    fn agent_health(&mut self, label: &[u8], process: Handle) {
        let cpu = process_usage(process, Use::CpuMicros).unwrap_or(0) / 1000;
        let pages = process_usage(process, Use::Pages).unwrap_or(0);
        let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
        let (cpu, pages) = (
            decimal(cpu, &mut a).to_vec(),
            decimal(pages, &mut b).to_vec(),
        );
        let label = [&b"health: agent "[..], label].concat();
        self.status(&label, process);
        self.say(&[&label, b": cpu ", &cpu, b" ms, ", &pages, b" pages"]);
    }

    /// Each service's state, as `init` answers it (#152), one line each;
    /// with `health` (M4.5), its uptime and last health check, then each
    /// agent.
    fn services(&mut self, health: bool) {
        if health {
            self.services_page(true);
            if let Some(runtime) = self.runtime {
                self.agent_health(b"runtime", runtime);
            }
            let agents = self.agents;
            for a in agents.iter().flatten() {
                self.agent_health(&a.name[..a.len], a.process);
            }
        } else {
            self.services_page(false);
        }
    }

    fn services_page(&mut self, health: bool) {
        let mut from = 0u8;
        loop {
            let (mut msg, mut out) = ([0u8; 8], [0u8; 256]);
            let req = listing::Request::Services { from };
            let answer = match (self.reply, listing::encode(&req, &mut msg)) {
                (Some(reply), Some(n)) => {
                    match call_timeout(REPORT, &msg[..n], reply, &mut out, INIT_US) {
                        Ok(Received::Message { len, .. }) => Reply::parse(&out[..len.min(256)]),
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some(page) = answer else {
                self.say(&[b"services: init is not answering"]);
                return;
            };
            for e in page.iter() {
                let mut d = [[0u8; 20]; 4];
                let [a, b, c, q] = &mut d;
                let lead: &[u8] = if health { b"health: " } else { b"services: " };
                let up: [&[u8]; 3] = if health && e.up_s > 0 {
                    [b", up ", decimal(e.up_s.into(), c), b" s"]
                } else {
                    [b""; 3]
                };
                let checked: [&[u8]; 3] = match (health, e.quiet_s) {
                    (false, _) => [b""; 3],
                    (true, listing::NOT_CHECKED) => [b", not checked", b"", b""],
                    (true, s) => [b", answered ", decimal(s.into(), q), b" s ago"],
                };
                self.say(&[
                    lead,
                    e.name,
                    b" ",
                    e.state.word(),
                    b", restarts ",
                    decimal(e.restarts.into(), a),
                    b" of ",
                    decimal(e.limit.into(), b),
                    up[0],
                    up[1],
                    up[2],
                    checked[0],
                    checked[1],
                    checked[2],
                ]);
            }
            from = from.saturating_add(page.count);
            if page.count == 0 || from >= page.total {
                return;
            }
        }
    }

    /// Marks `scope/key` version `version` verified if its hash starts
    /// with `prefix` (#144); shows its author, never its content.
    fn verify(&mut self, scope: &[u8], key: &[u8], version: u32, prefix: [u8; 4]) {
        let mut d = [[0u8; 20]; 2];
        let [v, t] = &mut d;
        let v = decimal(u64::from(version), v);
        let Some(number) = knowledge::scope_number(scope) else {
            self.say(&[b"verify: no scope ", scope]);
            return;
        };
        let req = knowledge::Request::Verify {
            scope: number,
            key,
            version,
            prefix,
        };
        let (mut msg, mut out) = ([0u8; 256], [0u8; 256]);
        let reply: &[u8] = match (self.reply, knowledge::encode(&req, &mut msg)) {
            (Some(reply), Some(n)) => {
                match call_timeout(KNOWLEDGE, &msg[..n], reply, &mut out, KNOWLEDGE_US) {
                    Ok(Received::Message { len, .. }) => &out[..len.min(256)],
                    _ => &[],
                }
            }
            _ => &[],
        };
        match reply {
            [status::OK, author @ ..] => {
                let by: [&[u8]; 4] = match knowledge::parse_author(author) {
                    Some(Author::Agent { name, task }) => {
                        [b"agent ", name, b" task ", decimal(u64::from(task), t)]
                    }
                    Some(Author::User) => [b"user", b"", b"", b""],
                    None => [b"?", b"", b"", b""],
                };
                let what = [scope, b"/", key, b" version ", v].concat();
                self.say(&[b"verified ", &what, b" by ", by[0], by[1], by[2], by[3]]);
                self.record(
                    audit::action::VERIFY,
                    None,
                    &what[..what.len().min(audit::MAX_DETAIL)],
                );
            }
            [status::NOT_FOUND, ..] => self.say(&[b"verify: no version"]),
            [knowledge::code::HASH_DIFFERS, ..] => self.say(&[b"verify: hash differs"]),
            [] => self.say(&[b"verify: the knowledge service is not answering"]),
            _ => self.say(&[b"verify: refused"]),
        }
    }

    /// A message on the endpoint. Keeps the capability only for a valid
    /// request from the badge allowed to send it.
    fn message(&mut self, msg: &[u8], cap: Handle, badge: u32) {
        // `init`'s health check (M4.5): any answer counts.
        if badge == INIT && cap != 0 && msg == [trust::VERSION, pharos_proto::op::INFO] {
            let _ = try_send(cap, &[status::OK]);
            let _ = delete(cap);
            return;
        }
        let valid = cap != 0 && process_status(cap).is_ok();
        match parse(msg) {
            Ok(Request::Channel) if badge == RUNTIME && cap != 0 && !valid => {
                if let Some(old) = self.channel.replace(cap) {
                    let _ = delete(old);
                }
            }
            Ok(Request::Approve {
                number,
                name,
                task,
                permission,
                for_ms,
            }) if badge == RUNTIME && number != 0 => {
                if let Some(free) = self.open.iter_mut().find(|n| **n == 0) {
                    *free = number;
                }
                let (mut a, mut b, mut c) = ([0u8; 20], [0u8; 20], [0u8; 20]);
                let n = decimal(u64::from(number), &mut a);
                let id = decimal(u64::from(task), &mut b);
                let mut t = [0u8; pharos_proto::permission::TEXT];
                let p = permission.text(&mut t);
                let mut how = [0u8; 40];
                let how: &[u8] = if for_ms == 0 {
                    b"for this task"
                } else {
                    let ms = decimal(u64::from(for_ms), &mut c);
                    let k = 4 + ms.len() + 3;
                    how[..4].copy_from_slice(b"for ");
                    how[4..4 + ms.len()].copy_from_slice(ms);
                    how[4 + ms.len()..k].copy_from_slice(b" ms");
                    &how[..k]
                };
                self.say(&[
                    b"approve #",
                    n,
                    b": ",
                    name,
                    b" task ",
                    id,
                    b" wants ",
                    p,
                    b" ",
                    how,
                    b"? (yes ",
                    n,
                    b" / no ",
                    n,
                    b")",
                ]);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Confirm {
                number,
                name,
                task,
                tool,
                addr,
                port,
                bytes,
            }) if badge == RUNTIME && number != 0 => {
                if let Some(free) = self.open.iter_mut().find(|n| **n == 0) {
                    *free = number;
                }
                if let Some(free) = self.confirms.iter_mut().find(|n| **n == 0) {
                    *free = number;
                }
                let mut d = [[0u8; 20]; 3];
                let [a, b, c] = &mut d;
                let n = decimal(u64::from(number), a);
                let id = decimal(u64::from(task), b);
                let size = decimal(u64::from(bytes), c);
                let mut t = [0u8; pharos_proto::permission::TEXT];
                // Only `send` is sensitive; its destination as `net` types it.
                let dest = &Permission::Net { addr, port }.text(&mut t)[4..];
                let (what, size, to, dest): (&[u8], &[u8], &[u8], &[u8]) =
                    if tool == pharos_proto::tool::number::SEND {
                        (b" wants to send ", size, b" bytes to ", dest)
                    } else {
                        (b" wants to use an unknown tool", b"", b"", b"")
                    };
                self.say(&[
                    b"confirm #",
                    n,
                    b": ",
                    name,
                    b" task ",
                    id,
                    what,
                    size,
                    to,
                    dest,
                    b"? (yes ",
                    n,
                    b" / no ",
                    n,
                    b")",
                ]);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Resolved { number, resolution }) if badge == RUNTIME => {
                for open in self.open.iter_mut().filter(|n| **n == number) {
                    *open = 0;
                }
                let confirm = self.confirms.contains(&number);
                for c in self.confirms.iter_mut().filter(|n| **n == number) {
                    *c = 0;
                }
                let mut a = [0u8; 20];
                let n = decimal(u64::from(number), &mut a);
                let what: &[u8] = match resolution {
                    trust::Resolution::Granted if confirm => b"confirmed",
                    trust::Resolution::Granted => b"granted",
                    trust::Resolution::Refused => b"refused",
                    trust::Resolution::Unanswered => b"no answer; refused",
                    trust::Resolution::Ended => b"the task ended",
                };
                let label: &[u8] = if confirm { b"confirm #" } else { b"approve #" };
                self.say(&[label, n, b": ", what]);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Revoked {
                outcome,
                name,
                permission,
            }) if badge == RUNTIME => {
                let mut t = [0u8; pharos_proto::permission::TEXT];
                let p = permission.text(&mut t);
                match outcome {
                    Outcome::Revoked => self.say(&[b"revoked ", p, b" from ", name]),
                    Outcome::NotHeld => self.say(&[name, b" does not hold ", p]),
                    Outcome::NoAgent => self.say(&[b"no agent ", name, b" runs"]),
                }
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Used { name, task, used }) if badge == RUNTIME => {
                let mut d = [[0u8; 20]; 7];
                let [t, c, p, k, s, b, r] = &mut d;
                self.say(&[
                    b"usage: ",
                    name,
                    b" task ",
                    decimal(u64::from(task), t),
                    b": cpu ",
                    decimal(u64::from(used.cpu_ms), c),
                    b" ms, ",
                    decimal(u64::from(used.pages), p),
                    b" pages, ",
                    decimal(u64::from(used.tokens), k),
                    b" tokens, ",
                    decimal(u64::from(used.sends), s),
                    b" datagrams of ",
                    decimal(u64::from(used.bytes), b),
                    b" bytes, ",
                    decimal(u64::from(used.requests), r),
                    b" requests",
                ]);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::GroupUsed {
                name,
                running,
                pages,
                tokens,
                bytes,
            }) if badge == RUNTIME => {
                let mut d = [[0u8; 20]; 4];
                let [a, p, k, b] = &mut d;
                self.say(&[
                    b"usage: group ",
                    name,
                    b": ",
                    decimal(u64::from(running), a),
                    b" running, ",
                    decimal(u64::from(pages), p),
                    b" pages, ",
                    decimal(u64::from(tokens), k),
                    b" tokens and ",
                    decimal(u64::from(bytes), b),
                    b" bytes this minute",
                ]);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Service {
                event,
                name,
                numbers,
                names,
            }) if badge == INIT => {
                self.service(event, name, numbers, names);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Offer(offer)) if badge == INIT => {
                self.offer(offer);
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
            Ok(Request::Runtime) if badge == INIT && valid => {
                if let Some(old) = self.runtime.replace(cap) {
                    let _ = delete(old);
                }
                self.say(&[b"registered runtime"]);
            }
            Ok(Request::Register { slot, name, group }) if badge == RUNTIME && valid => {
                let mut a = Agent {
                    name: [0; MAX_NAME],
                    len: name.len(),
                    group: [0; MAX_NAME],
                    group_len: group.len(),
                    process: cap,
                };
                a.name[..name.len()].copy_from_slice(name);
                a.group[..group.len()].copy_from_slice(group);
                if let Some(old) = self.agents[usize::from(slot)].replace(a) {
                    let _ = delete(old.process);
                }
                self.say(&[b"registered ", name]);
            }
            _ => {
                if cap != 0 {
                    let _ = delete(cap);
                }
            }
        }
    }
}

impl Trust {
    /// A service event or the system's state from `init` (#151), written
    /// from its fields: names from `init`'s table, numbers, fixed words.
    fn service(&mut self, event: Event, name: &[u8], n: [u32; 3], names: Names<'_>) {
        let mut d = [[0u8; 20]; 3];
        let [a, b, c] = &mut d;
        let [n0, n1, n2] = n.map(u64::from);
        // A device's PCI ID as `vendor:device` (#171).
        let mut hex = [0u8; 9];
        for (k, nibble) in [12, 8, 4, 0, 28, 24, 20, 16].into_iter().enumerate() {
            hex[k + usize::from(k >= 4)] = b"0123456789abcdef"[((n[1] >> nibble) & 15) as usize];
        }
        hex[4] = b':';
        let driven = names.iter().next().is_some();
        // At most 9 fixed parts, then 2 per listed name.
        let mut parts: [&[u8]; 9 + 2 * MAX_NAMES] = [b""; 9 + 2 * MAX_NAMES];
        let fixed: &[&[u8]] = match event {
            Event::Ready => &[b"system ready: ", decimal(n0, a), b" services"],
            Event::NotReady => &[b"system not ready: ", decimal(n0, a), b" failed"],
            Event::Exited => &[b"service ", name, b" exited ", decimal(n0, a)],
            Event::Killed => &[b"service ", name, b" killed ", decimal(n0, a)],
            Event::NoReady => &[b"service ", name, b" sent no ready within 10 s; stopped"],
            Event::Skipped => &[b"service ", name, b" skipped: a service it needs failed"],
            Event::Restarting => &[
                b"service ",
                name,
                b" restarting ",
                decimal(n0, a),
                b" of ",
                decimal(n1, b),
                b" in ",
                decimal(n2, c),
                b" ms",
            ],
            Event::GivenUp => &[b"service ", name, b" not restarted: restarts used up"],
            Event::Never => &[b"service ", name, b" not restarted: restart policy never"],
            Event::Stopped => &[b"service ", name, b" stopped; not restarted"],
            Event::Unresponsive => &[
                b"service ",
                name,
                b" unresponsive for ",
                decimal(n0, a),
                b" s; stopped",
            ],
            Event::DeviceAdded if driven => &[b"device ", &hex, b" added to slot ", decimal(n0, a)],
            Event::DeviceAdded => &[
                b"device ",
                &hex,
                b" in slot ",
                decimal(n0, a),
                b" has no free driver",
            ],
            Event::DeviceRemoved => &[b"device ", &hex, b" removed from slot ", decimal(n0, a)],
            Event::ByUser => match n[0] {
                trust::by_user::STOPPED => &[b"service ", name, b" stopped by the user"],
                trust::by_user::STARTED => &[b"service ", name, b" started by the user"],
                trust::by_user::READY => &[b"service ", name, b" ready"],
                _ => &[b"service ", name, b" restarted by the user"],
            },
            Event::Image => {
                let image = trust::image::name(n[1]);
                match n[0] {
                    trust::image::RUNNING => &[b"system: running ", image],
                    trust::image::REFUSED => &[
                        b"system: ",
                        image,
                        b" refused: ",
                        (trust::image::REASONS.get(n2 as usize))
                            .copied()
                            .unwrap_or(b"unknown reason"),
                    ],
                    trust::image::UPDATED => &[b"system: update applied; running ", image],
                    trust::image::ROLLED_BACK => &[b"system: rolled back; running ", image],
                    trust::image::MODE if n1 == 1 => {
                        &[b"system: safe mode: the agent runtime is not started"]
                    }
                    trust::image::MODE => &[
                        b"system: recovery mode: the agent runtime is not started, slots not used",
                    ],
                    _ => &[
                        b"system: ",
                        image,
                        b" not ready within 20 s; its services stopped",
                    ],
                }
            }
            Event::NotStarted => match n[0] {
                trust::not_started::MISSING_PROGRAM => {
                    &[b"service ", name, b" not started: missing program"]
                }
                trust::not_started::NO_DEVICE => &[b"service ", name, b" not started: no device"],
                _ => &[
                    b"service ",
                    name,
                    b" not started: spawn error ",
                    decimal(n1, b),
                ],
            },
        };
        parts[..fixed.len()].copy_from_slice(fixed);
        let mut k = fixed.len();
        let lead: &[u8] = if matches!(event, Event::DeviceAdded | Event::DeviceRemoved) {
            b"; driver "
        } else if matches!(event, Event::Restarting | Event::ByUser) {
            b"; used by "
        } else {
            b": "
        };
        for (i, n) in names.iter().enumerate() {
            parts[k] = if i == 0 { lead } else { b", " };
            parts[k + 1] = n;
            k += 2;
        }
        self.say(&parts[..k]);
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

fn main(_: u64) -> u64 {
    let Ok(irq) = irq_create(DEVICE, 0) else {
        return 1;
    };
    if irq_notify(irq, SERVICE, 0).is_err() {
        return 2;
    }
    let Ok(console) = Console::init(DEVICE, 0, BASE) else {
        return 3;
    };
    let mut t = Trust {
        console,
        runtime: None,
        channel: None,
        open: [0; 4],
        confirms: [0; 4],
        reply: endpoint_create().ok(),
        agents: [None; SLOTS as usize],
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 4;
    }
    t.say(&[b"trust: ready; ", HELP]);
    t.audit();
    t.ask_runtime();
    let mut lines = Lines::new();
    let mut msg = [0u8; 256];
    let mut bytes = [0u8; RX_BUFFER];
    loop {
        match receive(SERVICE, &mut msg) {
            Ok(Received::Notification(_)) => {
                if t.console.reclaim().is_err() {
                    return 5;
                }
                loop {
                    match t.console.recv(&mut bytes) {
                        Ok(Some(n)) => {
                            for &b in &bytes[..n] {
                                match lines.push(b) {
                                    Line::Done(len) => {
                                        let mut line = [0u8; Lines::MAX];
                                        line[..len].copy_from_slice(lines.line(len));
                                        t.command(&line[..len]);
                                    }
                                    Line::TooLong => t.say(&[b"line too long"]),
                                    Line::None => {}
                                }
                            }
                        }
                        Ok(None) => break,
                        // A device that breaks the queue rules is not
                        // trusted further.
                        Err(_) => return 6,
                    }
                }
            }
            Ok(Received::Message { len, cap, badge }) => {
                t.message(&msg[..len.min(256)], cap, badge)
            }
            _ => {}
        }
    }
}
