//! The service manager (issue #61, services.md): the first user process.
//!
//! The kernel gives it handles 1 debug console, 2 the root filesystem
//! (`READ | GRANT`), 3 the kernel's report endpoint (`SEND`), and from 4
//! each supported device (`MAP | CONFIG | IRQ | GRANT`). The argument
//! selects a service table (0: boot; 1: the `services` test kernel; 2: the
//! `network` test kernel; 3: the `supervision` test kernel).
//! Services start one after another; each gets only what its entry lists.
//! A one-shot service succeeds by exiting with 0, a daemon by sending
//! `ready` within 10 s (else it is stopped). Every event is printed; after
//! the last service `init` sends the kernel `[ready, failed]` and keeps
//! supervising (#100): a daemon that crashes or exits is restarted, at
//! most 3 times, with the same capabilities on the same endpoints, so its
//! clients reach the new one; one that was stopped is never restarted.
//! Every failure, skip, restart, give-up, and stop (#152) is a line here,
//! an audit record, and a `SERVICE` to `trust`, which writes its own line;
//! `trust`'s `services` asks `init` for each service's state (`SERVICES`,
//! `pharos_proto::service`), on its report capability.
//! When any service ends, `init` sends the storage and inference services
//! `RELEASE` for the badges it gave it, so they free its slots.
//! Each time the network service reports ready, `init` sends it every
//! network client's destinations (`ALLOW`, #109), on its own unbadged
//! capability: a client can send only where its entry lists.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use pharos_programs::supervise;
use pharos_proto::infer::{self, Request as InferRequest};
use pharos_proto::net::{self, Allowed, Request as NetRequest};
use pharos_proto::service::{self as listing, Entry, Reply, State as Shown};
use pharos_proto::store::{self, Request as StoreRequest};
use pharos_proto::trust::{self, Event, Names, not_started};
use pharos_proto::{audit, status};
use pharos_services::{
    Ep, Give, Kind, MAX_SERVICES, Object, RUNTIME_HANDLES, RUNTIME_PATH, Restart, Service,
};
use pharos_user::rights::{RECEIVE, SEND, STOP, WAIT};
use pharos_user::{
    Class, Error, Grant, Handle, Limits, MAX_SPAWN_CAPS, Received, Status, call_timeout,
    config_read, debug_write, endpoint_create, open, process_status, receive_timeout, send,
    spawn_with, try_send, uptime,
};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const ROOT: Handle = 2;
const REPORT: Handle = 3;
const FIRST_DEVICE: Handle = 4;

/// `pharos_proto::trust`: `RUNTIME`, sent through `init`'s own unbadged
/// handle (badge 0, `trust::INIT`).
const TRUST_RUNTIME: [u8; 2] = [1, 1];

/// Prints `init: <name> <what>[ <number>]`.
fn say(name: &str, what: &str, number: Option<u64>) {
    let mut line = [0u8; 96];
    let mut n = 0;
    let mut put = |bytes: &[u8]| {
        let take = bytes.len().min(line.len() - n);
        line[n..n + take].copy_from_slice(&bytes[..take]);
        n += take;
    };
    put(b"init: ");
    put(name.as_bytes());
    put(b" ");
    put(what.as_bytes());
    if let Some(mut v) = number {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        put(b" ");
        put(&digits[i..]);
    }
    let _ = debug_write(CONSOLE, &line[..n]);
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

/// The devices the kernel passed: `(handle, vendor and device ID)`.
fn devices() -> ([(Handle, u32); 8], usize) {
    let mut found = [(0, 0); 8];
    let mut count = 0;
    for handle in FIRST_DEVICE..FIRST_DEVICE + 8 {
        match config_read(handle, 0, 4) {
            Ok(id) => {
                found[count] = (handle, id);
                count += 1;
            }
            Err(Error::InvalidHandle) => break,
            Err(_) => {}
        }
    }
    (found, count)
}

/// What became of a service.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    /// Started; a daemon has not sent `ready` yet.
    Running(Handle),
    /// A daemon that sent `ready`.
    Ok(Handle),
    /// Waiting to be started again at this `uptime` (#150).
    Restarting(u64),
    /// A one-shot service that exited with 0.
    Done,
    Failed,
    /// A service it needs failed (#152).
    Skipped,
    /// Stopped by the user; never restarted.
    Stopped,
}

/// How long a daemon may take to send `ready` (#100).
const READY_US: u64 = 10_000_000;
/// How long `init` waits for an audit record, and first waits before
/// trying one again (doubling to [`AUDIT_RETRY_MAX_US`]).
const AUDIT_US: u64 = 1_000_000;
const AUDIT_RETRY_MAX_US: u64 = 60_000_000;
/// Most records waiting for the audit service; the oldest is dropped.
const MAX_UNSENT: usize = 32;
/// How long a service may take to answer `RELEASE`.
const RELEASE_US: u64 = 1_000_000;

struct Init {
    table: &'static [Service],
    events: Handle,
    reply: Handle,
    net: Handle,
    store: Handle,
    infer: Handle,
    trust: Handle,
    agents: Handle,
    audit: Handle,
    knowledge: Handle,
    devices: [(Handle, u32); 8],
    device_count: usize,
    state: [State; MAX_SERVICES],
    /// When each running daemon must have sent `ready`.
    deadline: [u64; MAX_SERVICES],
    restarts: [u8; MAX_SERVICES],
    /// Whether each start is in the audit trail yet (#108).
    recorded: [bool; MAX_SERVICES],
    /// Records the audit service has not taken yet, oldest first (#152):
    /// it may be starting, or blocked on a restarting store.
    unsent: VecDeque<Vec<u8>>,
    /// When to try them again, and the wait after the next failure.
    retry_at: u64,
    retry_us: u64,
}

impl Init {
    /// `init`'s handle for `object`, if it has it.
    fn handle(&self, object: Object) -> Option<Handle> {
        Some(match object {
            Object::DebugConsole => CONSOLE,
            Object::Root => ROOT,
            Object::Endpoint(e) => match e {
                Ep::Events => self.events,
                Ep::Net => self.net,
                Ep::Store => self.store,
                Ep::Infer => self.infer,
                Ep::Trust => self.trust,
                Ep::Agents => self.agents,
                Ep::Audit => self.audit,
                Ep::Knowledge => self.knowledge,
            },
            Object::Device(id, nth) => {
                (self.devices[..self.device_count].iter())
                    .filter(|d| d.1 == id)
                    .nth(usize::from(nth))?
                    .0
            }
        })
    }

    /// Service `i`'s capability `give`, exactly as its entry writes it
    /// (D-027). Never a `SEND` with badge 0 on another service's endpoint:
    /// that is `init`'s own (the host-tested rules refuse such a table).
    fn grant(&self, i: usize, give: &Give) -> Option<Grant> {
        let badge = give.badge.value(i);
        if give.rights & SEND != 0 && give.rights & RECEIVE == 0 && badge == 0 {
            return None;
        }
        Some(Grant {
            handle: self.handle(give.object)?,
            rights: give.rights,
            badge,
        })
    }

    /// Starts service `i` with exactly what its entry lists.
    fn start(&mut self, i: usize) {
        let service = &self.table[i];
        self.state[i] = State::Failed;
        let Ok(file) = open(ROOT, service.path) else {
            let numbers = [not_started::MISSING_PROGRAM, 0, 0];
            self.event(i, b"missing program", Event::NotStarted, numbers, &[]);
            return;
        };
        let mut grants = [Grant {
            handle: 0,
            rights: 0,
            badge: 0,
        }; MAX_SPAWN_CAPS];
        for (grant, give) in grants.iter_mut().zip(service.caps) {
            match self.grant(i, give) {
                Some(g) => *grant = g,
                None => {
                    let _ = pharos_user::delete(file);
                    let (what, numbers): (&[u8], _) = match give.object {
                        Object::Device(..) => (b"no device", [not_started::NO_DEVICE, 0, 0]),
                        _ => (
                            b"capability refused",
                            [
                                not_started::SPAWN_ERROR,
                                Error::MissingRight.code() as u32,
                                0,
                            ],
                        ),
                    };
                    self.event(i, what, Event::NotStarted, numbers, &[]);
                    return;
                }
            }
        }
        let caps = &grants[..service.caps.len().min(MAX_SPAWN_CAPS)];
        let notify = Some((self.events, i as u32));
        // D-022: `trust` keeps `init`'s class, so the emergency stop runs
        // ahead of everything else; every other service is below it.
        // ponytail: chosen by name; a table field if a second one is trusted.
        let class = if service.name == "trust" {
            Class::Same
        } else {
            Class::Services
        };
        // The runtime starts up to 16 agents of 16 handles each (D-022);
        // every other service gets a full table and no descendants.
        let (processes, handles) = if service.path == RUNTIME_PATH {
            (16, RUNTIME_HANDLES)
        } else {
            (0, 0)
        };
        let limits = Limits {
            pages: service.limit,
            class,
            processes,
            handles,
        };
        let spawned = spawn_with(file, service.arg, caps, notify, limits);
        let _ = pharos_user::delete(file);
        let process = match spawned {
            Ok(process) => process,
            Err(e) => {
                let mut d = [0u8; 20];
                let what = [&b"spawn failed, error "[..], decimal(e.code(), &mut d)].concat();
                let numbers = [not_started::SPAWN_ERROR, e.code() as u32, 0];
                self.event(i, &what, Event::NotStarted, numbers, &[]);
                return;
            }
        };
        say(service.name, "started", None);
        // `trust` gets the runtime's STOP before the runtime can start any
        // agent; a failed send leaves the runtime unstoppable, so stop it.
        if service.path == RUNTIME_PATH {
            let sent = send(self.trust, &TRUST_RUNTIME, process, STOP | WAIT, 0);
            if sent.is_err() {
                let _ = pharos_user::process_stop(process);
                say(service.name, "not registered with trust", None);
            }
        }
        self.state[i] = State::Running(process);
        self.deadline[i] = uptime().saturating_add(READY_US);
        self.recorded[i] = false;
    }

    /// Records every start not yet in the audit trail (#108): a `start`
    /// event per service, with how many capabilities its entry lists.
    /// Starts before the audit service was ready are recorded once it is.
    fn record_starts(&mut self) {
        let ready = self
            .table
            .iter()
            .position(|s| s.path == b"bin/audit")
            .is_some_and(|a| matches!(self.state[a], State::Ok(_)));
        if !ready {
            return;
        }
        for i in 0..self.table.len().min(MAX_SERVICES) {
            let started = matches!(
                self.state[i],
                State::Running(_) | State::Ok(_) | State::Done
            );
            if !started || self.recorded[i] {
                continue;
            }
            self.recorded[i] = true;
            let service = &self.table[i];
            let mut d = [0u8; 20];
            let mut detail = [0u8; 40];
            let count = decimal(service.caps.len() as u64, &mut d);
            let k = count.len();
            detail[..k].copy_from_slice(count);
            detail[k..k + 13].copy_from_slice(b" capabilities");
            let entry = audit::Entry {
                kind: audit::Kind::Event,
                refers: 0,
                actor: service.name.as_bytes(),
                task: 0,
                attempt: 0,
                action: audit::action::START,
                permission: None,
                service: b"init",
                outcome: audit::outcome::OK,
                detail: &detail[..k + 13],
            };
            self.append(&entry);
        }
    }

    /// Queues `entry` for the audit trail and sends what it can.
    fn append(&mut self, entry: &audit::Entry<'_>) {
        let mut msg = [0u8; 256];
        if let Some(n) = audit::encode(&audit::Request::Append(*entry), &mut msg) {
            if self.unsent.len() == MAX_UNSENT {
                self.unsent.pop_front();
            }
            self.unsent.push_back(msg[..n].to_vec());
            self.flush();
        }
    }

    /// Sends queued records, oldest first, once the audit service is ready
    /// and the retry time has passed; stops at the first it does not take.
    /// At least once: a record written just before the store or audit
    /// service failed, or answered after 1 s, is sent again, so it may be
    /// in the trail twice (seen when the store is killed mid-write).
    /// ponytail: a number per record from `init` would let the reader
    /// drop the copy.
    fn flush(&mut self) {
        if !self.up(b"bin/audit") || uptime() < self.retry_at {
            return;
        }
        while let Some(msg) = self.unsent.front() {
            // The request is sent from this buffer too.
            let mut out = [0u8; 256];
            // No badge: the audit service knows `init` by that.
            let taken = call_timeout(self.audit, msg, self.reply, &mut out, AUDIT_US)
                .is_ok_and(|r| matches!(r, Received::Message { len, .. } if len >= 1))
                && out[0] == status::OK;
            if !taken {
                self.retry_at = uptime().saturating_add(self.retry_us);
                self.retry_us = (self.retry_us * 2).min(AUDIT_RETRY_MAX_US);
                return;
            }
            self.unsent.pop_front();
            self.retry_us = AUDIT_US;
        }
    }

    /// True if the entry running `path` has succeeded.
    fn up(&self, path: &[u8]) -> bool {
        (self.table.iter())
            .position(|s| s.path == path)
            .is_some_and(|i| matches!(self.state[i], State::Ok(_)))
    }

    /// A `service` event in the audit trail (#151): queued until the audit
    /// service takes it.
    fn record(&mut self, actor: &[u8], detail: &[u8]) {
        let entry = audit::Entry {
            kind: audit::Kind::Event,
            refers: 0,
            actor,
            task: 0,
            attempt: 0,
            action: audit::action::SERVICE,
            permission: None,
            service: b"init",
            outcome: audit::outcome::OK,
            detail: &supervise::cut_list(detail, audit::MAX_DETAIL),
        };
        self.append(&entry);
    }

    /// Tells `trust` a `SERVICE` (#151), with as many of `names` as fit,
    /// if it runs, trying for at most 100 ms: it waits in `receive` almost
    /// always, and `init` never waits on it longer.
    fn tell_trust(&self, event: Event, name: &[u8], numbers: [u32; 3], names: &[&[u8]]) {
        if !self.up(b"bin/trust") {
            return;
        }
        let (mut wire, mut msg) = ([0u8; 256], [0u8; 256]);
        let fits = (0..=names.len().min(trust::MAX_NAMES)).rev().find_map(|k| {
            let names = Names::build(&names[..k], &mut wire)?;
            let req = trust::Request::Service {
                event,
                name,
                numbers,
                names,
            };
            trust::encode(&req, &mut msg)
        });
        let Some(n) = fits else { return };
        for _ in 0..10 {
            if try_send(self.trust, &msg[..n]).is_ok() {
                return;
            }
            pharos_user::sleep(10_000);
        }
    }

    /// Service `j`'s event (#152): `init: <name> <what>` on the debug
    /// console, an audit record (actor its name, detail `what`, cut to 64
    /// bytes after a whole name), and `SERVICE` to `trust`, which writes its own line from
    /// `event`, `numbers`, and `names`, never from `what`.
    fn event(&mut self, j: usize, what: &[u8], event: Event, numbers: [u32; 3], names: &[&[u8]]) {
        let name = self.table[j].name.as_bytes();
        let _ = debug_write(CONSOLE, &[&b"init: "[..], name, b" ", what].concat());
        self.record(name, what);
        self.tell_trust(event, name, numbers, names);
    }

    /// Answers `trust`'s `SERVICES` on `reply` without waiting (#152):
    /// each entry from `from`, as many as fit.
    fn list(&self, from: u8, reply: Handle) {
        let count = self.table.len().min(MAX_SERVICES);
        let entries: alloc::vec::Vec<Entry<'_>> = (usize::from(from)..count)
            .map(|i| Entry {
                name: self.table[i].name.as_bytes(),
                state: match self.state[i] {
                    State::Pending => Shown::Pending,
                    State::Running(_) => Shown::Starting,
                    State::Ok(_) => Shown::Ready,
                    State::Restarting(_) => Shown::Restarting,
                    State::Done => Shown::Done,
                    State::Failed => Shown::Failed,
                    State::Skipped => Shown::Skipped,
                    State::Stopped => Shown::Stopped,
                },
                restarts: self.restarts[i],
                limit: self.table[i].restart.limit(),
            })
            .collect();
        let mut out = [0u8; 256];
        if let Some((n, _)) = Reply::write(count as u8, &entries, &mut out) {
            let _ = try_send(reply, &out[..n]);
            let _ = debug_write(CONSOLE, b"init: services listed for trust");
        }
    }

    /// The system's state after the boot sequence (#151): ready if every
    /// entry succeeded, else what failed; to the trail and `trust`. The
    /// kernel gets its `[ready, failed]` as before.
    fn report_ready(&mut self, ready: usize) {
        let failed: alloc::vec::Vec<&[u8]> = (self.table.iter().zip(&self.state))
            .filter(|(_, s)| !matches!(s, State::Ok(_) | State::Done))
            .map(|(t, _)| t.name.as_bytes())
            .collect();
        let mut d = [0u8; 20];
        let detail = if failed.is_empty() {
            [&b"ready "[..], decimal(ready as u64, &mut d), b" services"].concat()
        } else {
            let mut v = [
                &b"not ready "[..],
                decimal(failed.len() as u64, &mut d),
                b" failed: ",
            ]
            .concat();
            v.extend_from_slice(&failed.join(&b", "[..]));
            v
        };
        self.record(b"init", &detail);
        let (event, count) = match failed.len() {
            0 => (Event::Ready, ready),
            n => (Event::NotReady, n),
        };
        self.tell_trust(event, b"", [count as u32, 0, 0], &failed);
    }

    /// Tells the storage and inference services that service `i`'s
    /// capabilities on them are gone, so they free its slots (#100).
    fn release(&self, i: usize) {
        for give in self.table[i].caps {
            // Only a client's `SEND`: the service itself receives there.
            let pharos_services::Badge::Fixed(badge) = give.badge else {
                continue;
            };
            if give.rights & RECEIVE != 0 {
                continue;
            }
            let (endpoint, client, msg) = match give.object {
                Object::Endpoint(Ep::Store) => {
                    let mut msg = [0u8; 16];
                    let n = store::encode(&StoreRequest::Release { client: badge }, &mut msg);
                    (self.store, badge, n.map(|n| (msg, n)))
                }
                Object::Endpoint(Ep::Infer) => {
                    let mut msg = [0u8; 16];
                    let n = infer::encode(&InferRequest::Release { client: badge }, &mut msg);
                    (self.infer, badge, n.map(|n| (msg, n)))
                }
                _ => continue,
            };
            let Some((msg, n)) = msg else { continue };
            let mut buf = [0u8; 16];
            let answered = call_timeout(endpoint, &msg[..n], self.reply, &mut buf, RELEASE_US)
                .is_ok_and(|r| matches!(r, Received::Message { len, .. } if len >= 1))
                && buf[0] == 0;
            if !answered {
                say(
                    self.table[i].name,
                    "slot not released, badge",
                    Some(u64::from(client)),
                );
            }
        }
    }

    /// Sends the network service every client's destinations (#109).
    fn allow(&self) {
        for (service, give) in (self.table.iter()).flat_map(|s| s.caps.iter().map(move |g| (s, g)))
        {
            let (Object::Endpoint(Ep::Net), pharos_services::Badge::Fixed(port)) =
                (give.object, give.badge)
            else {
                continue;
            };
            if give.rights & SEND == 0 {
                continue;
            }
            let dests = service.net;
            let req = Allowed::new(dests)
                .zip(u16::try_from(port).ok())
                .map(|(dests, client)| NetRequest::Allow { client, dests });
            let mut msg = [0u8; 64];
            let Some(n) = req.and_then(|r| net::encode(&r, &mut msg)) else {
                continue;
            };
            // The request is sent from this buffer too.
            let mut buf = [0u8; 64];
            let answered = call_timeout(self.net, &msg[..n], self.reply, &mut buf, RELEASE_US)
                .is_ok_and(|r| matches!(r, Received::Message { len, .. } if len >= 1))
                && buf[0] == net::OK;
            if !answered {
                say(
                    service.name,
                    "destinations not sent, port",
                    Some(port.into()),
                );
            }
        }
    }

    /// Service `j`'s process ended (its notification bit was set).
    fn ended(&mut self, j: usize) {
        let (State::Running(p) | State::Ok(p)) = self.state[j] else {
            return;
        };
        let service = &self.table[j];
        let status = process_status(p);
        if status == Ok(Status::Running) {
            return;
        }
        let _ = pharos_user::delete(p);
        self.release(j);
        let mut d = [0u8; 20];
        // Its state first: the audit service's own end is not sent to it.
        let (what, event, number) = match status {
            Ok(Status::Exited(0)) if service.kind == Kind::OneShot => {
                say(service.name, "done", None);
                self.state[j] = State::Done;
                return;
            }
            Ok(Status::Exited(code)) => (
                [&b"exited "[..], decimal(code, &mut d)],
                Event::Exited,
                code,
            ),
            Ok(Status::Killed(vector)) => (
                [&b"killed "[..], decimal(vector, &mut d)],
                Event::Killed,
                vector,
            ),
            Ok(Status::Stopped) => {
                self.state[j] = State::Stopped;
                let what = b"stopped; not restarted";
                self.event(j, what, Event::Stopped, [0; 3], &[]);
                return;
            }
            _ => {
                self.state[j] = State::Failed;
                return;
            }
        };
        self.state[j] = State::Failed;
        self.event(j, &what.concat(), event, [number as u32, 0, 0], &[]);
        self.crashed(j);
    }

    /// Service `j` crashed, exited, or sent no `ready` in time: restarted
    /// after its policy's delay, or left (#150). One the user stopped
    /// never comes here: the trusted path's safe mode.
    fn crashed(&mut self, j: usize) {
        let service = &self.table[j];
        let Some(wait) = supervise::delay(service.restart, self.restarts[j]) else {
            let (why, event): (&[u8], _) = match service.restart {
                Restart::Never => (b"not restarted: restart policy never", Event::Never),
                Restart::Up(_) => (b"not restarted: restarts used up", Event::GivenUp),
            };
            self.event(j, why, event, [0; 3], &[]);
            return;
        };
        self.restarts[j] += 1;
        self.state[j] = State::Restarting(uptime().saturating_add(wait));
        let numbers = [
            u32::from(self.restarts[j]),
            u32::from(service.restart.limit()),
            (wait / 1000) as u32,
        ];
        let mut d = [[0u8; 20]; 3];
        let [a, b, c] = &mut d;
        let mut what = [
            &b"restarting "[..],
            decimal(numbers[0].into(), a),
            b" of ",
            decimal(numbers[1].into(), b),
            b" in ",
            decimal(numbers[2].into(), c),
            b" ms",
        ]
        .concat();
        let after: alloc::vec::Vec<&[usize]> = self.table.iter().map(|s| s.after).collect();
        let users: alloc::vec::Vec<&[u8]> = (supervise::dependents(&after, j).into_iter())
            .map(|d| self.table[d].name.as_bytes())
            .collect();
        for (k, name) in users.iter().enumerate() {
            what.extend_from_slice(if k == 0 { b"; used by " } else { b", " });
            what.extend_from_slice(name);
        }
        self.event(j, &what, Event::Restarting, numbers, &users);
    }

    /// Starts services whose restart delay has passed, and stops daemons
    /// that did not send `ready` in time. Returns how long until the next
    /// deadline.
    fn check_ready(&mut self) -> u64 {
        let now = uptime();
        let mut wait = u64::MAX;
        for j in 0..self.table.len().min(MAX_SERVICES) {
            if let State::Restarting(at) = self.state[j] {
                if now >= at {
                    self.start(j);
                } else {
                    wait = wait.min(at - now);
                    continue;
                }
            }
            let State::Running(p) = self.state[j] else {
                continue;
            };
            if self.table[j].kind != Kind::Daemon {
                continue;
            }
            if now >= self.deadline[j] {
                let _ = pharos_user::process_stop(p);
                let _ = pharos_user::delete(p);
                self.release(j);
                self.state[j] = State::Failed;
                let what = b"no ready within 10 s; stopped";
                self.event(j, what, Event::NoReady, [0; 3], &[]);
                // Counted as a crash (D-026 design, #149).
                self.crashed(j);
                if let State::Restarting(at) = self.state[j] {
                    wait = wait.min(at.saturating_sub(now));
                }
            } else {
                wait = wait.min(self.deadline[j] - now);
            }
        }
        wait
    }

    /// Waits for one event (a `ready`, an end, or a deadline) and handles it.
    fn step(&mut self) {
        self.record_starts();
        self.flush();
        let mut wait = self.check_ready();
        if !self.unsent.is_empty() {
            wait = wait.min(self.retry_at.saturating_sub(uptime()).max(10_000));
        }
        let mut buf = [0u8; 16];
        match receive_timeout(self.events, &mut buf, wait) {
            Ok(Received::Message { badge, cap, len }) => {
                let i = (badge as usize).wrapping_sub(1);
                // `trust`'s `services` (#152); only its badge is answered.
                let from_trust = self.table.get(i).is_some_and(|s| s.path == b"bin/trust");
                let asked = listing::parse(&buf[..len.min(buf.len())]);
                if let (true, Ok(listing::Request::Services { from })) = (from_trust, asked) {
                    self.list(from, cap);
                } else if let (Some(service), Some(State::Running(p))) =
                    (self.table.get(i), self.state.get(i).copied())
                {
                    if service.kind == Kind::Daemon {
                        say(service.name, "ready", None);
                        self.state[i] = State::Ok(p);
                        if service.path == b"bin/net" {
                            self.allow();
                        }
                    }
                }
                if cap != 0 {
                    let _ = pharos_user::delete(cap);
                }
            }
            Ok(Received::Notification(bits)) => {
                for j in 0..self.table.len().min(MAX_SERVICES) {
                    if bits & 1 << j != 0 {
                        self.ended(j);
                    }
                }
            }
            _ => {}
        }
    }
}

fn main(arg: u64) -> u64 {
    let table = pharos_services::table(arg);
    let mut handles = [0; 9];
    for h in handles.iter_mut() {
        match endpoint_create() {
            Ok(e) => *h = e,
            Err(_) => {
                let _ = debug_write(CONSOLE, b"init: cannot create an endpoint");
                return 1;
            }
        }
    }
    let [
        events,
        reply,
        net,
        store,
        infer,
        trust,
        agents,
        audit,
        knowledge,
    ] = handles;
    let (devices, device_count) = devices();
    let mut init = Init {
        table,
        events,
        reply,
        net,
        store,
        infer,
        trust,
        agents,
        audit,
        knowledge,
        devices,
        device_count,
        state: [State::Pending; MAX_SERVICES],
        deadline: [0; MAX_SERVICES],
        restarts: [0; MAX_SERVICES],
        recorded: [false; MAX_SERVICES],
        unsent: VecDeque::new(),
        retry_at: 0,
        retry_us: AUDIT_US,
    };
    for (i, service) in table.iter().enumerate().take(MAX_SERVICES) {
        let met = service
            .after
            .iter()
            .all(|&a| matches!(init.state[a], State::Ok(_) | State::Done));
        if !met {
            init.state[i] = State::Skipped;
            init.event(i, b"skipped", Event::Skipped, [0; 3], &[]);
            continue;
        }
        init.start(i);
        // Until this service succeeds or fails; others' events too.
        while matches!(init.state[i], State::Running(_) | State::Restarting(_)) {
            init.step();
        }
    }
    let ready = init
        .state
        .iter()
        .filter(|s| matches!(s, State::Ok(_) | State::Done))
        .count();
    let failed = table.len().min(MAX_SERVICES) - ready;
    // The trail and `trust` first: the kernel may end the boot check
    // once it has the summary.
    init.report_ready(ready);
    let _ = send(REPORT, &[ready as u8, failed as u8], 0, 0, 0);

    // Keep supervising: restarts, and `ready` from restarted daemons.
    loop {
        init.step();
    }
}
