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
//!
//! With the boot table, `init` boots from an image (#163, boot.md section
//! 8): the storage service and `trust` always come from the factory image
//! (the root filesystem); the slot record `system/state` names the slot
//! to try. Each attempt is written before the slot is used; the slot is
//! read, verified against the public key `init` was built with
//! (`PHAROS_IMAGE_KEY`), and mounted with `fs_mount`, and every other
//! service starts from it. If they are not all ready within 20 s, they are
//! stopped and the next candidate is tried in place: the other slot, then
//! the factory image. The kernel gets `[ready, failed, image, mode]`.
//!
//! Modes (#164): the argument's bits 8 and up are the kernel's mode (from
//! the Limine command line, or recovery when `root` failed and its copy
//! runs); in normal mode the record's one-shot `next` is used and cleared.
//! Safe mode starts every boot service but the agent runtime; recovery is
//! safe mode on the factory image, slots ignored. If the factory image is
//! not ready in normal mode, its services are stopped and it starts again
//! in recovery. `trust`'s `system` asks for the mode, image, and slots
//! (`SYSTEM`); `safe` and `recovery` set the next boot's mode (`NEXT`).
//!
//! Updates (#165): `trust`'s `update` (`UPDATE`) makes `init` check each
//! file in `system/incoming` (signature, a version above every good
//! slot's, not a bad slot's image) and send `trust` an `OFFER` for each.
//! `apply <n>` (`ANSWER`, within 60 s) checks the file again, copies it
//! into the slot that is not active, deletes it, and tries it in place:
//! every service but the storage service and `trust` is stopped and the
//! slots are tried as at boot, so an update that is not ready is bad and
//! the previous slot runs again. `discard <n>` deletes the file.
//! `rollback` (`ROLLBACK`) makes the active slot bad and the other, if
//! good, run in place. Only in normal mode, and never during another.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "init/system.rs"]
mod system;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use pharos_image::slots::{Mode, Record, Slot, State as SlotState};
use pharos_programs::manage::{self, Plan, Refusal as Refused};
use pharos_programs::supervise;
use pharos_programs::system::{Gone, Offers, Refusal};
use pharos_proto::infer::{self, Request as InferRequest};
use pharos_proto::net::{self, Allowed, Request as NetRequest};
use pharos_proto::service::{
    self as listing, Action, Entry, Managed, Reply, Setting, Settings, State as Shown, System,
};
use pharos_proto::store::{self, Request as StoreRequest};
use pharos_proto::trust::{self, Event, Names, by_user, image as shown, not_started};
use pharos_proto::{audit, status};
use pharos_services::config::{self, Config};
use pharos_services::{
    Ep, Give, Kind, MAX_SERVICES, Object, RUNTIME_HANDLES, Restart, SLOT_BIT, Service,
};
use pharos_user::rights::{RECEIVE, SEND, STOP, WAIT};
use pharos_user::{
    Class, Error, Grant, Handle, Limits, MAX_SPAWN_CAPS, Received, Status, call_timeout,
    config_read, debug_write, endpoint_create, open, process_status, receive_timeout, send,
    slot_answer, slot_next, slot_notify, spawn_with, try_send, try_send_cap, uptime,
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
    /// The agent runtime in safe mode and recovery (#164): not started.
    Off,
    /// A driver entry whose device is not in a slot (#171).
    NoDevice,
    /// Not started at boot: the configuration says so (M4.5).
    Configured,
}

/// How long a daemon may take to send `ready` (#100).
const READY_US: u64 = 10_000_000;
/// How long `init` waits for an audit record, and first waits before
/// trying one again (doubling to [`AUDIT_RETRY_MAX_US`]).
const AUDIT_US: u64 = 1_000_000;
const AUDIT_RETRY_MAX_US: u64 = 60_000_000;
/// Most records waiting for the audit service; the oldest is dropped.
const MAX_UNSENT: usize = 32;
/// Events and offers kept for `trust` while it is busy (M4.6 review F1).
const MAX_TO_TRUST: usize = 32;
/// How long a service may take to answer `RELEASE`.
const RELEASE_US: u64 = 1_000_000;
/// How long an image's services may take to be ready (boot.md section 8).
const IMAGE_READY_US: u64 = 20_000_000;
/// Programs always started from the factory image: a slot cannot break
/// the code that falls back, or the trusted path.
const FACTORY: [&[u8]; 2] = [b"bin/store", b"bin/trust"];

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
    /// Events and offers `trust` has not taken yet, oldest first, and when
    /// the oldest was first offered (M4.6 review F1): `init` never waits on
    /// `trust`, which may be waiting on `init`.
    to_trust: core::cell::RefCell<VecDeque<Vec<u8>>>,
    to_trust_since: core::cell::Cell<u64>,
    /// The filesystem services start from (but [`FACTORY`]'s), and which
    /// image it is: 0 factory, 1 slot A, 2 slot B.
    image: Handle,
    image_number: u8,
    /// When the wait in `step` must end at the latest.
    wake_by: u64,
    /// This boot's mode, and whether the agent runtime is left off (#164).
    mode: Mode,
    safe: bool,
    /// The slot store, `None` if the record cannot be read (then it is
    /// never written), and the record as `init` last wrote or read it.
    slots: Option<system::Slots>,
    record: Record,
    /// The public key slots and updates are verified with.
    key: Option<[u8; 32]>,
    /// The factory image's version: updates must be newer (#167).
    factory: u64,
    /// The updates offered since the last `update` (#165).
    offers: Offers,
    /// Booting, or applying an update or a rollback: `trust`'s update
    /// requests get `BUSY` (they would start one inside the other).
    busy: bool,
    /// Daemons the user started, or drivers started for a device (#171),
    /// that have not sent `ready` yet (#170): their `ready` is told to
    /// `trust`.
    by_user: [bool; MAX_SERVICES],
    /// The hotplug object, if the kernel gave one (#171).
    hotplug: Option<Handle>,
    /// The configuration of the image that runs (M4.5); compiled values
    /// in safe mode and recovery. `config_from`: that image, as `SYSTEM`
    /// numbers it, or `COMPILED`.
    config: Config,
    config_from: u8,
    /// When each service last started, and last answered a health check
    /// (M4.5; its ready time until the first); a bit per entry that has
    /// answered one since it was ready (M4.5 review F2); when the next
    /// round of checks is due.
    started: [u64; MAX_SERVICES],
    answered: [u64; MAX_SERVICES],
    heard: u32,
    next_check: u64,
    /// Each driver entry's device: its slot's index and `init`'s handle.
    arrived: [Option<(u8, Handle)>; MAX_SERVICES],
}

impl Init {
    /// Entry `i`'s restart policy, as the configuration sets it (M4.5).
    fn restart(&self, i: usize) -> Restart {
        self.config.restart(i, self.table[i].restart)
    }

    /// `init`'s handle for `object`, if it has it.
    fn handle(&self, object: Object) -> Option<Handle> {
        Some(match object {
            Object::DebugConsole => CONSOLE,
            Object::Root => self.image,
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
            // Per entry, in `grant`.
            Object::Arrived(_) => return None,
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
        if let Object::Arrived(_) = give.object {
            return self.arrived[i].map(|(_, handle)| Grant {
                handle,
                rights: give.rights,
                badge: 0,
            });
        }
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
        let fs = if FACTORY.contains(&service.path) {
            ROOT
        } else {
            self.image
        };
        let Ok(file) = open(fs, service.path) else {
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
                        Object::Device(..) | Object::Arrived(_) => {
                            (b"no device", [not_started::NO_DEVICE, 0, 0])
                        }
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
        let (processes, handles) = if service.is_runtime() {
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
        if service.is_runtime() {
            let sent = send(self.trust, &TRUST_RUNTIME, process, STOP | WAIT, 0);
            if sent.is_err() {
                let _ = pharos_user::process_stop(process);
                say(service.name, "not registered with trust", None);
            }
        }
        self.state[i] = State::Running(process);
        self.started[i] = uptime();
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
        self.record_as(audit::action::SERVICE, actor, detail);
    }

    /// An `action` event in the audit trail, as [`Self::record`].
    fn record_as(&mut self, action: u8, actor: &[u8], detail: &[u8]) {
        let entry = audit::Entry {
            kind: audit::Kind::Event,
            refers: 0,
            actor,
            task: 0,
            attempt: 0,
            action,
            permission: None,
            service: b"init",
            outcome: audit::outcome::OK,
            detail: &supervise::cut_list(detail, audit::MAX_DETAIL),
        };
        self.append(&entry);
    }

    /// Tells `trust` a `SERVICE` (#151), with as many of `names` as fit,
    /// if it runs: now, or from the queue once `trust` waits for it
    /// ([`Self::offer_trust`]; M4.6 review F1: it was dropped after 100 ms).
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
        self.offer_trust(&msg[..n]);
    }

    /// Gives `trust` `msg` now if it is waiting, else queues it behind the
    /// others (at most [`MAX_TO_TRUST`], the oldest dropped first).
    fn offer_trust(&self, msg: &[u8]) {
        let mut queue = self.to_trust.borrow_mut();
        if queue.is_empty() && try_send(self.trust, msg).is_ok() {
            return;
        }
        if queue.is_empty() {
            self.to_trust_since.set(uptime());
        }
        if queue.len() == MAX_TO_TRUST {
            queue.pop_front();
        }
        queue.push_back(msg.to_vec());
    }

    /// Gives `trust` what it has not taken, in order; one it has not taken
    /// for [`trust::EVENT_US`], longer than any one wait of `trust`, is
    /// dropped (M4.6 review F1). Nothing is kept for a `trust` not running.
    fn flush_trust(&self) {
        let mut queue = self.to_trust.borrow_mut();
        if !self.up(b"bin/trust") {
            queue.clear();
            return;
        }
        while let Some(msg) = queue.front() {
            let now = uptime();
            if try_send(self.trust, msg).is_err() {
                if now.saturating_sub(self.to_trust_since.get()) < trust::EVENT_US {
                    return;
                }
                say("trust", "event not taken; dropped", None);
            }
            queue.pop_front();
            self.to_trust_since.set(now);
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
    /// The endpoint `init` checks entry `i`'s health on (M4.5): a daemon
    /// that receives on one of `init`'s endpoints.
    fn checked(&self, i: usize) -> Option<Handle> {
        const EPS: [Ep; 7] = [
            Ep::Net,
            Ep::Store,
            Ep::Infer,
            Ep::Trust,
            Ep::Agents,
            Ep::Audit,
            Ep::Knowledge,
        ];
        let service = &self.table[i];
        if service.kind != Kind::Daemon {
            return None;
        }
        let ep = EPS
            .into_iter()
            .find(|e| e.receiver() == Some(service.name))?;
        self.handle(Object::Endpoint(ep))
    }

    /// One round of health checks (M4.5, services.md): `INFO` to each
    /// ready daemon, 100 ms each; any answer counts. One silent past its
    /// window is stopped and handled as a crash by its policy.
    fn check_health(&mut self) {
        for j in 0..self.table.len().min(MAX_SERVICES) {
            let (Some(ep), State::Ok(p)) = (self.checked(j), self.state[j]) else {
                continue;
            };
            let mut out = [0u8; 256];
            let info = [1, pharos_proto::op::INFO];
            if let Ok(Received::Message { .. }) =
                pharos_user::call_timeout(ep, &info, self.reply, &mut out, supervise::INFO_US)
            {
                self.answered[j] = uptime();
                self.heard |= 1 << j;
                continue;
            }
            let now = uptime();
            if !supervise::unresponsive(self.table[j].name, self.answered[j], now) {
                continue;
            }
            let secs = (now.saturating_sub(self.answered[j]) / 1_000_000) as u32;
            let _ = pharos_user::process_stop(p);
            let _ = pharos_user::delete(p);
            self.release(j);
            self.state[j] = State::Failed;
            let mut d = [0u8; 20];
            let what = [
                &b"unresponsive for "[..],
                decimal(secs.into(), &mut d),
                b" s; stopped",
            ]
            .concat();
            self.event(j, &what, Event::Unresponsive, [secs, 0, 0], &[]);
            self.crashed(j);
        }
    }

    /// `trust`'s `CONFIG` (M4.5): what the configuration in use sets.
    fn show_config(&self, reply: Handle) {
        let settings: Vec<Setting<'_>> = (self.config.settings())
            .filter(|(i, ..)| *i < self.table.len())
            .map(|(i, off, restarts, delay_ms)| Setting {
                name: self.table[i].name.as_bytes(),
                off,
                restarts,
                delay_ms,
            })
            .collect();
        let mut out = [0u8; 256];
        if let Some(n) = Settings::write(self.config_from, &settings, &mut out) {
            let _ = try_send(reply, &out[..n]);
        }
    }

    fn list(&self, from: u8, reply: Handle) {
        let count = self.table.len().min(MAX_SERVICES);
        let entries: alloc::vec::Vec<Entry<'_>> = (usize::from(from)..count)
            .map(|i| {
                let now = uptime();
                let up_s = match self.state[i] {
                    State::Running(_) | State::Ok(_) => {
                        (now.saturating_sub(self.started[i]) / 1_000_000) as u32
                    }
                    _ => 0,
                };
                let quiet_s = match (self.checked(i), self.state[i]) {
                    (Some(_), State::Ok(_)) if self.heard & (1 << i) == 0 => listing::NO_ANSWER,
                    (Some(_), State::Ok(_)) => {
                        (now.saturating_sub(self.answered[i]) / 1_000_000) as u32
                    }
                    _ => listing::NOT_CHECKED,
                };
                Entry {
                    name: self.table[i].name.as_bytes(),
                    state: self.shown(i),
                    restarts: self.restarts[i],
                    limit: self.restart(i).limit(),
                    up_s,
                    quiet_s,
                }
            })
            .collect();
        let mut out = [0u8; 256];
        if let Some((n, _)) = Reply::write(count as u8, &entries, &mut out) {
            let _ = try_send(reply, &out[..n]);
            let _ = debug_write(CONSOLE, b"init: services listed for trust");
        }
    }

    /// Service `i`'s state as `trust` sees it.
    fn shown(&self, i: usize) -> Shown {
        match self.state[i] {
            State::Pending => Shown::Pending,
            State::Running(_) => Shown::Starting,
            State::Ok(_) => Shown::Ready,
            State::Restarting(_) => Shown::Restarting,
            State::Done => Shown::Done,
            State::Failed => Shown::Failed,
            State::Skipped => Shown::Skipped,
            State::Stopped => Shown::Stopped,
            State::Off => Shown::Off,
            State::NoDevice => Shown::NoDevice,
            State::Configured => Shown::Configured,
        }
    }

    /// The names of the entries that depend on entry `j`.
    fn users(&self, j: usize) -> Vec<&'static [u8]> {
        let table = self.table;
        let after: Vec<&[usize]> = table.iter().map(|s| s.after).collect();
        (supervise::dependents(&after, j).into_iter())
            .map(|d| table[d].name.as_bytes())
            .collect()
    }

    /// `trust`'s `START`, `STOP`, or `RESTART` of service `name` (#170,
    /// D-029): decided by `pharos_programs::manage`, answered on `reply`
    /// before anything is done (a restart of `trust` ends its call), then
    /// carried out and reported as one event.
    fn manage(&mut self, action: Action, name: &[u8], reply: Handle) {
        let count = self.table.len().min(MAX_SERVICES);
        let found = (0..count).find(|&i| self.table[i].name.as_bytes() == name);
        let decided = match found {
            _ if self.busy || self.mode == Mode::Recovery => Err(Managed::Busy),
            None => Err(Managed::Unknown),
            Some(j) => {
                let unmet = (self.table[j].after.iter().copied())
                    .find(|&a| !matches!(self.state[a], State::Ok(_) | State::Done));
                let service = self.table[j].name;
                manage::decide(action, service, self.shown(j), unmet)
                    .map(|plan| (j, plan))
                    .map_err(|r| match r {
                        Refused::Unknown => Managed::Unknown,
                        Refused::Protected => Managed::Protected,
                        Refused::Running => Managed::Running,
                        Refused::NotRunning => Managed::NotRunning,
                        Refused::Needs(d) => Managed::Needs(self.table[d].name.as_bytes()),
                    })
            }
        };
        let answer = match decided {
            Ok(_) => Managed::Ok,
            Err(m) => m,
        };
        let mut out = [0u8; 48];
        if let Some(n) = answer.write(&mut out) {
            let _ = try_send(reply, &out[..n]);
        }
        let (j, plan) = match decided {
            Ok(d) => d,
            Err(Managed::Protected) => {
                // Only `trust`'s badge gets here: the user tried.
                let j = found.unwrap_or(0);
                let what = b"stop refused: protected";
                let _ = debug_write(CONSOLE, &[&b"init: "[..], name, b" ", what].concat());
                self.record_as(audit::action::MANAGE, self.table[j].name.as_bytes(), what);
                return;
            }
            Err(_) => return,
        };
        let users = self.users(j);
        let (word, code): (&[u8], _) = match plan {
            Plan::Stop => (b"stopped by the user", by_user::STOPPED),
            Plan::Start => (b"started by the user", by_user::STARTED),
            Plan::StopThenStart => (b"restarted by the user", by_user::RESTARTED),
        };
        let mut what = word.to_vec();
        if plan != Plan::Start {
            for (k, user) in users.iter().enumerate() {
                what.extend_from_slice(if k == 0 { b"; used by " } else { b", " });
                what.extend_from_slice(user);
            }
        }
        let shown_users: &[&[u8]] = if plan == Plan::Start { &[] } else { &users };
        let me = self.table[j].name.as_bytes();
        let _ = debug_write(CONSOLE, &[&b"init: "[..], me, b" ", &what].concat());
        self.record_as(audit::action::MANAGE, me, &what);
        // Reported first, so a stop or restart of `trust` is still said
        // by the `trust` that is about to end.
        self.tell_trust(Event::ByUser, me, [code, 0, 0], shown_users);
        if plan != Plan::Start {
            if self.table[j].path == b"bin/trust" {
                // The old `trust` takes what is queued, then gets a fixed
                // 100 ms to print the line it took.
                // ponytail: a reply to `SERVICE` if 100 ms is ever too short.
                let start = uptime();
                while !self.to_trust.borrow().is_empty()
                    && uptime().saturating_sub(start) < trust::EVENT_US
                {
                    self.flush_trust();
                    pharos_user::sleep(10_000);
                }
                pharos_user::sleep(100_000);
            }
            self.stop_one(j);
        }
        if plan != Plan::Stop {
            self.restarts[j] = 0;
            self.start(j);
            self.by_user[j] = self.table[j].kind == Kind::Daemon;
        }
    }

    /// `trust`'s `RUNTIME` (#170): the running runtime's `STOP` and
    /// `WAIT` in the reply, so a restarted `trust` holds the emergency
    /// stop; at boot the runtime is registered when it starts.
    fn give_runtime(&self, reply: Handle) {
        let runtime = (self.table.iter().zip(&self.state))
            .find(|(s, _)| s.is_runtime())
            .and_then(|(_, st)| match st {
                State::Running(p) | State::Ok(p) => Some(*p),
                _ => None,
            });
        let sent = match runtime {
            Some(p) => try_send_cap(reply, &[status::OK], p, STOP | WAIT, 0),
            None => try_send(reply, &[status::NOT_FOUND]),
        };
        if runtime.is_some() && sent.is_err() {
            say("trust", "runtime not given", None);
        }
    }

    /// Slot events (#171, drivers.md), until the kernel has none: an
    /// arrival starts the driver entry for its PCI ID; a removal stops the
    /// driver, then releases the slot. No driver entry is protected (a
    /// table rule), so a removal is never refused.
    fn slots(&mut self) {
        let Some(hotplug) = self.hotplug else { return };
        while let Ok(Some(e)) = slot_next(hotplug) {
            let count = self.table.len().min(MAX_SERVICES);
            let driving = (0..count).find(|&j| self.arrived[j].is_some_and(|(s, _)| s == e.slot));
            match e.event {
                1 => {
                    let free = (0..count).find(|&j| {
                        self.table[j].driver() == Some(e.id) && self.arrived[j].is_none()
                    });
                    self.device(Event::DeviceAdded, e.number, e.id, free);
                    let Some(j) = free else {
                        // Left powered and unused until it is removed.
                        let _ = pharos_user::delete(e.handle);
                        continue;
                    };
                    self.arrived[j] = Some((e.slot, e.handle));
                    // One the user stopped stays stopped; `start` uses it.
                    if self.state[j] != State::Stopped {
                        self.restarts[j] = 0;
                        self.start(j);
                        // `service <name> ready` on the console, too.
                        self.by_user[j] = true;
                    }
                }
                // The user asks to remove it: the driver is stopped, then
                // the slot released (revoked and powered off at once), or
                // it was taken without asking (3): the kernel revoked it.
                2 | 3 => {
                    if let Some(j) = driving {
                        self.unplug(j);
                    }
                    if e.event == 2 && slot_answer(hotplug, e.slot, true).is_err() {
                        continue;
                    }
                    self.device(Event::DeviceRemoved, e.number, e.id, driving);
                    if let Some((_, handle)) = driving.and_then(|j| self.arrived[j].take()) {
                        let _ = pharos_user::delete(handle);
                    }
                }
                _ => {}
            }
        }
    }

    /// Stops driver `j` because its device leaves (not the user's stop:
    /// it starts again when a device arrives).
    fn unplug(&mut self, j: usize) {
        if let State::Running(p) | State::Ok(p) = self.state[j] {
            let _ = pharos_user::process_stop(p);
            for _ in 0..trust::INIT_STOP_US / 10_000 {
                if process_status(p) != Ok(Status::Running) {
                    break;
                }
                pharos_user::sleep(10_000);
            }
            let _ = pharos_user::delete(p);
            self.release(j);
        }
        if self.state[j] != State::Stopped {
            self.state[j] = State::NoDevice;
        }
        self.by_user[j] = false;
    }

    /// A device event: a debug line, a `device` audit record, and a `trust`
    /// line, with the driver entry `j` started or stopped for it.
    fn device(&mut self, event: Event, slot: u8, id: u32, j: Option<usize>) {
        let word: &[u8] = if event == Event::DeviceAdded {
            b" added "
        } else {
            b" removed "
        };
        let mut d = [0u8; 20];
        let mut hex = [0u8; 9];
        for (k, nibble) in [12, 8, 4, 0, 28, 24, 20, 16].into_iter().enumerate() {
            hex[k + usize::from(k >= 4)] = b"0123456789abcdef"[((id >> nibble) & 15) as usize];
        }
        hex[4] = b':';
        let driver: &[&[u8]] = match j {
            Some(j) => &[self.table[j].name.as_bytes()],
            None => &[],
        };
        let mut what = [&b"slot "[..], decimal(slot.into(), &mut d), word, &hex].concat();
        match driver.first() {
            Some(name) => what.extend_from_slice(&[&b"; driver "[..], name].concat()),
            None if event == Event::DeviceAdded => what.extend_from_slice(b"; no driver"),
            None => {}
        }
        let _ = debug_write(CONSOLE, &[&b"init: "[..], &what].concat());
        self.record_as(audit::action::DEVICE, b"init", &what);
        self.tell_trust(event, b"", [slot.into(), id, 0], driver);
    }

    /// Stops service `j` for the user: never restarted. Waits (up to 1 s)
    /// until it has ended, so a restart finds its devices free.
    fn stop_one(&mut self, j: usize) {
        if let State::Running(p) | State::Ok(p) = self.state[j] {
            let _ = pharos_user::process_stop(p);
            for _ in 0..trust::INIT_STOP_US / 10_000 {
                if process_status(p) != Ok(Status::Running) {
                    break;
                }
                pharos_user::sleep(10_000);
            }
            let _ = pharos_user::delete(p);
            self.release(j);
        }
        self.state[j] = State::Stopped;
        self.by_user[j] = false;
    }

    /// The system's state after the boot sequence (#151): ready if every
    /// entry succeeded, else what failed; to the trail and `trust`. The
    /// kernel gets its `[ready, failed]` as before.
    fn report_ready(&mut self, ready: usize) {
        let failed: alloc::vec::Vec<&[u8]> = (self.table.iter().zip(&self.state))
            .filter(|(_, s)| {
                !matches!(
                    s,
                    State::Ok(_) | State::Done | State::Off | State::NoDevice | State::Configured
                )
            })
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
        let policy = self.restart(j);
        let first = (self.config).first_delay_us(j, supervise::FIRST_DELAY_US);
        let Some(wait) = supervise::delay(policy, first, self.restarts[j]) else {
            let (why, event): (&[u8], _) = match policy {
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
            u32::from(policy.limit()),
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
        let users = self.users(j);
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
        self.flush_trust();
        if uptime() >= self.next_check {
            self.check_health();
            self.next_check = uptime().saturating_add(supervise::CHECK_US);
        }
        let mut wait = self.check_ready();
        wait = wait.min(self.next_check.saturating_sub(uptime()));
        wait = wait.min(self.wake_by.saturating_sub(uptime()));
        if !self.unsent.is_empty() {
            wait = wait.min(self.retry_at.saturating_sub(uptime()).max(10_000));
        }
        if !self.to_trust.borrow().is_empty() {
            wait = wait.min(10_000);
        }

        // Room for a management request's name (#170).
        let mut buf = [0u8; 40];
        match receive_timeout(self.events, &mut buf, wait) {
            Ok(Received::Message { badge, cap, len }) => {
                let i = (badge as usize).wrapping_sub(1);
                // `trust`'s `services` (#152); only its badge is answered.
                let from_trust = self.table.get(i).is_some_and(|s| s.path == b"bin/trust");
                let asked = listing::parse(&buf[..len.min(buf.len())]);
                if let (true, Ok(asked)) = (from_trust, asked) {
                    match asked {
                        listing::Request::Services { from } => self.list(from, cap),
                        listing::Request::System => self.show_system(cap),
                        listing::Request::Next { mode } => self.next_boot(mode, cap),
                        listing::Request::Update => self.update(cap),
                        listing::Request::Answer { number, apply } => {
                            self.answer(number, apply, cap)
                        }
                        listing::Request::Rollback => self.roll_back(cap),
                        listing::Request::Runtime => self.give_runtime(cap),
                        listing::Request::Config => self.show_config(cap),
                        listing::Request::Manage { action, name } => {
                            let name = name.to_vec();
                            self.manage(action, &name, cap)
                        }
                    }
                } else if let (Some(service), Some(State::Running(p))) =
                    (self.table.get(i), self.state.get(i).copied())
                {
                    if service.kind == Kind::Daemon {
                        say(service.name, "ready", None);
                        self.state[i] = State::Ok(p);
                        self.answered[i] = uptime();
                        // Checked at once, so its first answer is seen
                        // (M4.5 review F2); `i` is below `MAX_SERVICES`.
                        self.heard &= !(1 << i);
                        self.next_check = 0;
                        if core::mem::take(&mut self.by_user[i]) {
                            let name = service.name.as_bytes();
                            self.tell_trust(Event::ByUser, name, [by_user::READY, 0, 0], &[]);
                        }
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
                if bits & 1 << SLOT_BIT != 0 {
                    self.slots();
                }
            }
            _ => {}
        }
    }

    /// Starts every pending entry `which` selects, in table order, each
    /// once the entries it needs have succeeded, and waits until each has
    /// succeeded or failed. False if `deadline` (an `uptime`) passed first.
    fn start_all(&mut self, which: impl Fn(&Service) -> bool, deadline: u64) -> bool {
        for i in 0..self.table.len().min(MAX_SERVICES) {
            if self.state[i] != State::Pending || !which(&self.table[i]) {
                continue;
            }
            // A driver starts only with its device (#171).
            if self.table[i].driver().is_some() && self.arrived[i].is_none() {
                self.state[i] = State::NoDevice;
                continue;
            }
            if !self.config.starts(i) {
                self.state[i] = State::Configured;
                say(self.table[i].name, "not started: configuration", None);
                continue;
            }
            if self.safe && self.table[i].is_runtime() {
                self.state[i] = State::Off;
                say(self.table[i].name, "not started: safe mode", None);
                continue;
            }
            let met = (self.table[i].after.iter())
                .all(|&a| matches!(self.state[a], State::Ok(_) | State::Done));
            if !met {
                self.state[i] = State::Skipped;
                self.event(i, b"skipped", Event::Skipped, [0; 3], &[]);
                continue;
            }
            self.start(i);
            self.wake_by = deadline;
            // Until this service succeeds or fails; others' events too.
            while matches!(self.state[i], State::Running(_) | State::Restarting(_)) {
                if uptime() >= deadline {
                    self.wake_by = u64::MAX;
                    return false;
                }
                self.step();
            }
        }
        self.wake_by = u64::MAX;
        true
    }

    /// True if every entry succeeded (or is off in safe mode).
    fn all_ready(&self) -> bool {
        (self.state[..self.table.len().min(MAX_SERVICES)].iter()).all(|s| {
            matches!(
                s,
                State::Ok(_) | State::Done | State::Off | State::NoDevice | State::Configured
            )
        })
    }

    /// Stops every service the image started, so the next image's start
    /// afresh; a [`FACTORY`] service that runs keeps running.
    fn stop_image(&mut self) {
        let mut stopped = Vec::new();
        for j in 0..self.table.len().min(MAX_SERVICES) {
            let factory = FACTORY.contains(&self.table[j].path);
            match self.state[j] {
                State::Running(_) | State::Ok(_) | State::Restarting(_) if factory => continue,
                State::Running(p) | State::Ok(p) => {
                    let _ = pharos_user::process_stop(p);
                    self.release(j);
                    stopped.push(p);
                }
                _ => {}
            }
            self.state[j] = State::Pending;
            self.restarts[j] = 0;
            self.recorded[j] = false;
        }
        // A stop ends a process at its next return to user mode: wait (up
        // to 1 s) until they have, so the next image's drivers find their
        // devices free.
        for _ in 0..100 {
            if stopped
                .iter()
                .all(|&p| process_status(p) != Ok(Status::Running))
            {
                break;
            }
            pharos_user::sleep(10_000);
        }
        for p in stopped {
            let _ = pharos_user::delete(p);
        }
    }

    /// An image event (#163): `init: system: <detail>` on the debug
    /// console, a `system` audit record, and, with `numbers`, an `IMAGE`
    /// to `trust`, which writes its own line from them.
    fn system(&mut self, detail: &[u8], numbers: Option<[u32; 3]>) {
        let _ = debug_write(CONSOLE, &[&b"init: system: "[..], detail].concat());
        let entry = audit::Entry {
            kind: audit::Kind::Event,
            refers: 0,
            actor: b"init",
            task: 0,
            attempt: 0,
            action: audit::action::SYSTEM,
            permission: None,
            service: b"init",
            outcome: audit::outcome::OK,
            detail: &supervise::cut_list(detail, audit::MAX_DETAIL),
        };
        self.append(&entry);
        if let Some(numbers) = numbers {
            self.tell_trust(Event::Image, b"", numbers, &[]);
        }
    }

    /// Boots from an image (#163, boot.md section 8) in the kernel's mode
    /// `kernel` (#164): the storage service from the factory image, then
    /// each candidate the slot record names in turn (none in recovery),
    /// then the factory image; `image` is then the one that runs. `copy`:
    /// the root filesystem is the `recovery` copy.
    fn boot_image(&mut self, key: Option<[u8; 32]>, kernel: Mode, copy: bool) {
        self.start_all(|s| s.path == b"bin/store", u64::MAX);
        let mut slots = if self.up(b"bin/store") {
            system::Slots::open(self.store, self.reply)
        } else {
            None
        };
        let mut record = Record::EMPTY;
        match slots.as_ref().map(system::Slots::load) {
            Some(system::Loaded::Record(r)) => record = r,
            Some(system::Loaded::Missing) => self.system(b"no slot record", None),
            Some(system::Loaded::Corrupt) => {
                let rewritten = slots.as_ref().is_some_and(|s| s.save(&Record::EMPTY));
                self.system(
                    if rewritten {
                        b"slot record corrupt; rewritten empty"
                    } else {
                        b"slot record corrupt; not rewritten"
                    },
                    None,
                );
            }
            Some(system::Loaded::Unreadable) | None => {
                self.system(b"slot record unreadable", None);
                // Never written over: it may hold slots.
                slots = None;
            }
        }
        let (mode, from_record) = record.take_mode(kernel);
        if from_record {
            let saved = slots.as_ref().is_some_and(|s| s.save(&record));
            let what: &[u8] = if saved {
                b" (from the slot record, now cleared)"
            } else {
                b" (from the slot record, not cleared)"
            };
            self.system(&[mode_word(mode), b" mode", what].concat(), None);
        } else if mode != Mode::Normal {
            let why: &[u8] = if copy {
                b" mode (root failed its checks; the recovery copy runs)"
            } else {
                b" mode (from the kernel)"
            };
            self.system(&[mode_word(mode), why].concat(), None);
        }
        self.mode = mode;
        self.safe = mode != Mode::Normal;
        if mode != Mode::Recovery {
            self.boot_slots(&slots, &mut record, key);
        }
        if self.image_number == 0 {
            self.boot_factory(copy);
        }
        if self.mode != Mode::Normal {
            self.tell_trust(Event::Image, b"", [shown::MODE, self.mode as u32, 0], &[]);
        }
        self.slots = slots;
        self.record = record;
    }

    /// Tries each candidate slot in turn; `image_number` is the one that
    /// is ready, or 0.
    fn boot_slots(
        &mut self,
        slots: &Option<system::Slots>,
        record: &mut Record,
        key: Option<[u8; 32]>,
    ) {
        let loaded = *record;
        let mut tried = [false; 2];
        let mut d = [0u8; 20];
        while let (Some(slots), Some(slot)) = (slots.as_ref(), record.candidate(tried)) {
            let number = 1 + slot as u32;
            let name = shown::name(number);
            tried[slot as usize] = true;
            // The attempt is on the disk before the slot is used, so a
            // crash or a hang during it counts on the next boot.
            record.attempt(slot);
            if !slots.save(record) {
                self.system(
                    &[name, b": the attempt cannot be written; not tried"].concat(),
                    None,
                );
                break;
            }
            let attempt = decimal(record.slot(slot).attempts.into(), &mut d).to_vec();
            self.system(&[name, b": attempt ", &attempt].concat(), None);
            let (fs, version, config) =
                match slots.mount(ROOT, slot, record, key.as_ref(), self.table) {
                    Ok(mounted) => mounted,
                    Err(why) => {
                        record.refuse(slot);
                        let _ = slots.save(record);
                        let numbers = [shown::REFUSED, number, why.code()];
                        self.system(&[name, b" refused: ", why.text()].concat(), Some(numbers));
                        continue;
                    }
                };
            // Its configuration is checked before anything starts from it
            // (M4.5): a bad one refuses the slot. Safe mode ignores it.
            let config = match config {
                _ if self.safe => {
                    self.config_from = listing::COMPILED;
                    Config::COMPILED
                }
                Ok(config) => {
                    self.config_from = number as u8;
                    config
                }
                Err(e) => {
                    let _ = pharos_user::delete(fs);
                    record.refuse(slot);
                    let _ = slots.save(record);
                    let numbers = [shown::REFUSED, number, Refusal::Config.code()];
                    let mut why = [0u8; config::MAX_TEXT];
                    let detail = [
                        name,
                        b" refused: ",
                        Refusal::Config.text(),
                        b": ",
                        e.text(&mut why),
                    ];
                    self.system(&detail.concat(), Some(numbers));
                    continue;
                }
            };
            self.config = config;
            let version = decimal(version, &mut d).to_vec();
            self.image = fs;
            self.image_number = number as u8;
            let deadline = uptime().saturating_add(IMAGE_READY_US);
            if self.start_all(|_| true, deadline) && self.all_ready() {
                record.ready(slot);
                let saved = slots.save(record);
                let what: &[u8] = if saved { b"" } else { b" (record not written)" };
                let numbers = [shown::RUNNING, number, 0];
                self.system(
                    &[b"running ", name, b" version ", &version, what].concat(),
                    Some(numbers),
                );
                return;
            }
            let numbers = [shown::NOT_READY, number, 0];
            let what = b" not ready within 20 s; its services stopped";
            self.system(
                &[name, b" version ", &version, what].concat(),
                Some(numbers),
            );
            self.stop_image();
            let _ = pharos_user::delete(fs);
            self.image = ROOT;
            self.image_number = 0;
            self.config = Config::COMPILED;
            self.config_from = listing::COMPILED;
        }
        // Slots whose attempts ran out became bad when they were passed
        // over; that is written too.
        for slot in [Slot::A, Slot::B] {
            let (was, is) = (loaded.slot(slot).state, record.slot(slot).state);
            if was == SlotState::Trying && is == SlotState::Bad {
                let name = shown::name(1 + slot as u32);
                self.system(&[name, b": attempts used up; bad"].concat(), None);
            }
        }
        if *record != loaded {
            if let Some(slots) = slots.as_ref() {
                let _ = slots.save(record);
            }
        }
    }

    /// Starts the factory image (or the recovery copy); if it is not
    /// ready in normal mode, its services are stopped and it starts again
    /// in recovery (#164).
    fn boot_factory(&mut self, copy: bool) {
        self.image = ROOT;
        self.image_number = if copy { 3 } else { 0 };
        self.config_from = listing::COMPILED;
        self.config = if self.safe {
            Config::COMPILED
        } else {
            self.factory_config()
        };
        self.start_all(|_| true, u64::MAX);
        if !self.all_ready() && !self.safe {
            self.system(
                b"factory image not ready; its services stopped; recovery mode",
                None,
            );
            self.stop_image();
            self.mode = Mode::Recovery;
            self.safe = true;
            self.config = Config::COMPILED;
            self.config_from = listing::COMPILED;
            self.start_all(|_| true, u64::MAX);
        }
        let numbers = [shown::RUNNING, u32::from(self.image_number), 0];
        let what: &[u8] = if copy {
            b"running recovery copy"
        } else {
            b"running factory image"
        };
        self.system(what, Some(numbers));
    }

    /// The factory image's configuration (M4.5): the build checked it, so
    /// a bad one is reported and the compiled values run.
    fn factory_config(&mut self) -> Config {
        match read_config(ROOT, self.table) {
            Ok(config) => {
                self.config_from = self.image_number;
                config
            }
            Err(e) => {
                let mut why = [0u8; config::MAX_TEXT];
                let detail = [
                    &b"factory image: configuration refused: "[..],
                    e.text(&mut why),
                    b"; compiled values",
                ];
                self.system(&detail.concat(), None);
                Config::COMPILED
            }
        }
    }

    /// Answers `trust`'s `SYSTEM` on `reply` without waiting (#164).
    fn show_system(&self, reply: Handle) {
        let slot = |s: Slot| {
            let info = self.record.slot(s);
            let mut sha256 = [0u8; 8];
            sha256.copy_from_slice(&info.sha256[..8]);
            listing::Slot {
                state: info.state as u8,
                attempts: info.attempts,
                version: info.version,
                sha256,
            }
        };
        let incoming = (self.slots.as_ref())
            .and_then(system::Slots::incoming)
            .map_or(0, |n| n.len() as u8);
        let answer = System {
            mode: self.mode as u8,
            image: self.image_number,
            active: self.record.active.map_or(0, |s| 1 + s as u8),
            incoming,
            slots: [slot(Slot::A), slot(Slot::B)],
        };
        let mut out = [0u8; listing::SYSTEM_LEN];
        if let Some(n) = answer.write(&mut out) {
            let _ = try_send(reply, &out[..n]);
        }
    }

    /// `trust`'s `NEXT` (#164): writes the next boot's mode to the record
    /// and answers on `reply` whether it was written.
    fn next_boot(&mut self, mode: u8, reply: Handle) {
        let mode = if mode == 1 {
            Mode::Safe
        } else {
            Mode::Recovery
        };
        let mut record = self.record;
        record.next = mode;
        let saved = self.slots.as_ref().is_some_and(|s| s.save(&record));
        if saved {
            self.record = record;
        }
        let answer = if saved { status::OK } else { status::INTERNAL };
        let _ = try_send(reply, &[answer]);
        let what: &[u8] = if saved {
            b" mode (asked on the trusted path)"
        } else {
            b" mode not written"
        };
        self.system(&[b"next boot: ", mode_word(mode), what].concat(), None);
    }
}

impl Init {
    /// The image running and its version, for an `OFFER`.
    fn running(&self) -> (u8, u64) {
        let version = match self.image_number {
            n @ (1 | 2) => self.record.slots[usize::from(n - 1)].version,
            _ => 0,
        };
        (self.image_number, version)
    }

    /// Sends `trust` an `OFFER`, as [`Self::tell_trust`].
    fn tell_offer(
        &self,
        number: u16,
        refused: Option<Refusal>,
        name: &[u8],
        found: (u64, [u8; 32]),
    ) {
        let (image, now) = self.running();
        let mut sha256 = [0u8; 8];
        sha256.copy_from_slice(&found.1[..8]);
        let offer = trust::Offer {
            number,
            refused: refused.map(|r| r.code() as u8),
            name,
            version: found.0,
            sha256,
            image,
            now,
        };
        let mut msg = [0u8; 256];
        let Some(n) = trust::encode(&trust::Request::Offer(offer), &mut msg) else {
            return;
        };
        self.offer_trust(&msg[..n]);
    }

    /// Whether `trust`'s update request may run now; else `BUSY` is sent.
    fn idle(&self, reply: Handle) -> bool {
        let idle = !self.busy && self.mode == Mode::Normal && self.slots.is_some();
        if !idle {
            let _ = try_send(reply, &[status::BUSY]);
        }
        idle
    }

    /// `trust`'s `UPDATE` (#165): answers how many files wait, then checks
    /// each and sends `trust` an `OFFER`: numbered if it may be applied,
    /// else refused with the reason.
    fn update(&mut self, reply: Handle) {
        if !self.idle(reply) {
            return;
        }
        let names = (self.slots.as_ref())
            .and_then(system::Slots::incoming)
            .unwrap_or_default();
        let _ = try_send(reply, &[status::OK, names.len() as u8]);
        self.offers.clear();
        let mut d = [0u8; 20];
        for name in &names {
            let path = [system::INCOMING, name].concat();
            // A bad configuration (M4.5), to name its line and reason.
            let mut bad = None;
            let checked = (self.slots.as_ref())
                .map_or(Err(Refusal::Unreadable), |s| {
                    s.check(&path, self.key.as_ref(), self.table)
                })
                .and_then(|(version, sha256, _, config)| {
                    pharos_programs::system::admit(&self.record, self.factory, version, &sha256)?;
                    if let Err(e) = config {
                        bad = Some(e);
                        return Err(Refusal::Config);
                    }
                    Ok((version, sha256))
                });
            match checked {
                Ok((version, sha256)) => {
                    let Some(number) = self.offers.offer(name, sha256, uptime()) else {
                        continue;
                    };
                    self.tell_offer(number, None, name, (version, sha256));
                    let n = decimal(number.into(), &mut d).to_vec();
                    let v = decimal(version, &mut d).to_vec();
                    self.system(
                        &[
                            &b"offered #"[..],
                            &n,
                            b": incoming ",
                            name,
                            b" version ",
                            &v,
                        ]
                        .concat(),
                        None,
                    );
                }
                Err(why) => {
                    // A configuration's line rides in the version field.
                    let line = bad.map_or(0, |e| e.line as u64);
                    if pharos_proto::trust::valid_name(name) {
                        self.tell_offer(0, Some(why), name, (line, [0; 32]));
                    }
                    let mut text = [0u8; config::MAX_TEXT];
                    let (sep, detail): (&[u8], &[u8]) = match &bad {
                        Some(e) => (b": ", e.text(&mut text)),
                        None => (b"", b""),
                    };
                    self.system(
                        &[
                            &b"incoming "[..],
                            name,
                            b" refused: ",
                            why.text(),
                            sep,
                            detail,
                        ]
                        .concat(),
                        None,
                    );
                }
            }
        }
    }

    /// `trust`'s `ANSWER` (#165): discards offer `number`'s file, or checks
    /// it again (it must be the image offered), copies it into the slot
    /// that is not active, and tries it in place.
    fn answer(&mut self, number: u16, apply: bool, reply: Handle) {
        if !self.idle(reply) {
            return;
        }
        let offer = match self.offers.take(number, uptime()) {
            Ok(offer) => offer,
            Err(gone) => {
                let code = match gone {
                    Gone::Unknown => status::NOT_FOUND,
                    Gone::Expired => status::CANCELLED,
                };
                let _ = try_send(reply, &[code]);
                return;
            }
        };
        let _ = try_send(reply, &[status::OK]);
        let name = offer.name();
        let path = [system::INCOMING, name].concat();
        let Some(slots) = self.slots.take() else {
            return;
        };
        if !apply {
            let deleted = slots.delete(&path);
            self.slots = Some(slots);
            let what: &[u8] = if deleted { b"" } else { b" (not deleted)" };
            self.system(&[b"update discarded: incoming ", name, what].concat(), None);
            return;
        }
        let checked = slots.check(&path, self.key.as_ref(), self.table).and_then(
            |(version, sha256, len, config)| {
                if sha256 != offer.sha256 {
                    return Err(Refusal::Changed);
                }
                // Offered, so checked; the same image cannot fail now.
                config.map_err(|_| Refusal::Config)?;
                pharos_programs::system::admit(&self.record, self.factory, version, &sha256)?;
                Ok((version, sha256, len))
            },
        );
        let (version, sha256, len) = match checked {
            Ok(found) => found,
            Err(why) => {
                self.slots = Some(slots);
                self.tell_offer(number, Some(why), name, (0, [0; 32]));
                self.system(
                    &[b"update refused: incoming ", name, b": ", why.text()].concat(),
                    None,
                );
                return;
            }
        };
        let mut record = self.record;
        let slot = record.stage(version, sha256);
        let slot_name = shown::name(1 + slot as u32);
        // The file first, then the record that names it: a crash between
        // leaves the record as it was.
        if !slots.write_slot(slot, len) || !slots.save(&record) {
            self.slots = Some(slots);
            self.system(
                &[b"update failed: ", slot_name, b" cannot be written"].concat(),
                None,
            );
            return;
        }
        let _ = slots.delete(&path);
        self.slots = Some(slots);
        self.record = record;
        let mut d = [0u8; 20];
        let v = decimal(version, &mut d).to_vec();
        self.system(
            &[
                &b"staged version "[..],
                &v,
                b" in ",
                slot_name,
                b"; trying it",
            ]
            .concat(),
            None,
        );
        self.switch();
        let running = u32::from(self.image_number);
        if running == 1 + slot as u32 {
            let numbers = [shown::UPDATED, running, 0];
            self.system(
                &[b"update applied: running ", slot_name, b" version ", &v].concat(),
                Some(numbers),
            );
            return;
        }
        // Not ready: never tried again, and its image never offered again.
        self.record.refuse(slot);
        if let Some(slots) = self.slots.as_ref() {
            let _ = slots.save(&self.record);
        }
        let numbers = [shown::ROLLED_BACK, running, 0];
        self.system(
            &[
                b"update failed: ",
                slot_name,
                b" bad; rolled back: running ",
                shown::name(running),
            ]
            .concat(),
            Some(numbers),
        );
    }

    /// `trust`'s `ROLLBACK` (#165): the active slot bad, the other active,
    /// and the slots tried again in place.
    fn roll_back(&mut self, reply: Handle) {
        if !self.idle(reply) {
            return;
        }
        let mut record = self.record;
        let Some(to) = record.rollback() else {
            let _ = try_send(reply, &[status::NOT_FOUND]);
            return;
        };
        let saved = self.slots.as_ref().is_some_and(|s| s.save(&record));
        if !saved {
            let _ = try_send(reply, &[status::INTERNAL]);
            return;
        }
        let _ = try_send(reply, &[status::OK]);
        self.record = record;
        let to = shown::name(1 + to as u32);
        self.system(&[b"rollback: trying ", to].concat(), None);
        self.switch();
        let running = u32::from(self.image_number);
        self.system(
            &[
                b"update rolled back by the user: running ",
                shown::name(running),
            ]
            .concat(),
            Some([shown::ROLLED_BACK, running, 0]),
        );
    }

    /// Stops the image's services and boots again in place from the slot
    /// record, as at boot: the slots, then the factory image.
    fn switch(&mut self) {
        self.busy = true;
        self.stop_image();
        if self.image != ROOT {
            let _ = pharos_user::delete(self.image);
        }
        self.image = ROOT;
        self.image_number = 0;
        let slots = self.slots.take();
        let mut record = self.record;
        self.boot_slots(&slots, &mut record, self.key);
        self.slots = slots;
        self.record = record;
        if self.image_number == 0 {
            self.boot_factory(false);
        }
        self.report_ready(self.ready_count());
        self.busy = false;
    }

    fn ready_count(&self) -> usize {
        (self.state.iter())
            .filter(|s| matches!(s, State::Ok(_) | State::Done))
            .count()
    }
}

/// `etc/system.conf` in the filesystem behind `fs`, checked against
/// `table`; every compiled value if there is none (M4.5).
fn read_config(fs: Handle, table: &[Service]) -> Result<Config, config::Error> {
    let unreadable = config::Error {
        line: 0,
        why: config::Why::Unreadable,
    };
    let file = match open(fs, config::PATH) {
        Ok(file) => file,
        Err(pharos_user::Error::NotFound) => return Ok(Config::COMPILED),
        Err(_) => return Err(unreadable),
    };
    // One byte more than the largest file, to see it is too large.
    let mut text = [0u8; config::MAX_SIZE + 1];
    let mut len = 0;
    while len < text.len() {
        // `read` takes at most 4 KiB at a time.
        let end = text.len().min(len + 4096);
        match pharos_user::read(file, len as u64, &mut text[len..end]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(_) => {
                let _ = pharos_user::delete(file);
                return Err(unreadable);
            }
        }
    }
    let _ = pharos_user::delete(file);
    config::parse(&text[..len], table)
}

fn mode_word(mode: Mode) -> &'static [u8] {
    match mode {
        Mode::Normal => b"normal",
        Mode::Safe => b"safe",
        Mode::Recovery => b"recovery",
    }
}

fn main(arg: u64) -> u64 {
    let (table_number, kernel_mode, copy) = pharos_programs::system::split_arg(arg);
    let table = pharos_services::table(table_number);
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
        to_trust: core::cell::RefCell::new(VecDeque::new()),
        to_trust_since: core::cell::Cell::new(0),
        retry_at: 0,
        retry_us: AUDIT_US,
        image: ROOT,
        image_number: 0,
        wake_by: u64::MAX,
        mode: Mode::Normal,
        safe: false,
        slots: None,
        record: Record::EMPTY,
        key: pharos_programs::system::parse_key(option_env!("PHAROS_IMAGE_KEY")),
        factory: pharos_programs::system::parse_version(option_env!("PHAROS_IMAGE_VERSION")),
        offers: Offers::new(),
        busy: true,
        by_user: [false; MAX_SERVICES],
        hotplug: None,
        config: Config::COMPILED,
        config_from: listing::COMPILED,
        started: [0; MAX_SERVICES],
        answered: [0; MAX_SERVICES],
        heard: 0,
        next_check: 0,
        arrived: [None; MAX_SERVICES],
    };
    // The hotplug object follows the devices (#171).
    let hotplug = FIRST_DEVICE + device_count as u64;
    if slot_notify(hotplug, events, SLOT_BIT).is_ok() {
        init.hotplug = Some(hotplug);
    }
    // Only the boot table boots from an image; the test tables run from
    // the root filesystem.
    if table_number == 0 {
        init.boot_image(init.key, kernel_mode, copy);
    } else {
        init.start_all(|_| true, u64::MAX);
    }
    let ready = init.ready_count();
    let off = (init.state.iter())
        .filter(|s| matches!(s, State::Off | State::NoDevice | State::Configured))
        .count();
    let failed = table.len().min(MAX_SERVICES) - ready - off;
    // Idle before `trust` hears the system is ready, so an `update`
    // typed at once is answered.
    init.busy = false;
    // The trail and `trust` first: the kernel may end the boot check
    // once it has the summary.
    init.report_ready(ready);
    let summary = [
        ready as u8,
        failed as u8,
        init.image_number,
        init.mode as u8,
    ];
    let _ = send(REPORT, &summary, 0, 0, 0);

    // Keep supervising: restarts, and `ready` from restarted daemons.
    loop {
        init.step();
    }
}
