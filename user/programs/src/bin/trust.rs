//! The trusted service (D-018, agents.md): the user's controls on the
//! trusted path, which work without any agent, the agent runtime, or a
//! model. It owns the virtio-console device; no other process can read
//! what the user types or write what looks like its answers.
//!
//! Handles: 1 the virtio-console device, 2 its endpoint (`RECEIVE`), 3
//! `init`'s report endpoint (`SEND`). Nothing else: it holds no serial
//! console, storage, network, or inference capability. It receives
//! process capabilities over [`pharos_proto::trust`]: the agent runtime's
//! from `init`, each agent's from the runtime.
//!
//! Commands, one per line: `list`, `stop <agent>`, `stop all`.

#![no_std]
#![no_main]

use pharos_programs::virtio_console::{Console, RX_BUFFER};
use pharos_proto::trust::{
    self, Command, INIT, Line, Lines, MAX_NAME, RUNTIME, Request, SLOTS, parse,
};
use pharos_user::{
    Handle, Received, Status, delete, irq_create, irq_notify, process_status, process_stop,
    receive, send, sleep,
};

pharos_user::entry!(main);

const DEVICE: Handle = 1;
const SERVICE: Handle = 2;
const REPORT: Handle = 3;
const BASE: u64 = 0x1000_0000;
/// How long a stop may take before the answer says it is still running.
const STOP_WAIT_US: u64 = 1_000_000;

/// A registered agent: its name and process capability (`STOP`, `WAIT`).
#[derive(Clone, Copy)]
struct Agent {
    name: [u8; MAX_NAME],
    len: usize,
    process: Handle,
}

struct Trust {
    console: Console,
    runtime: Option<Handle>,
    agents: [Option<Agent>; SLOTS as usize],
}

impl Trust {
    /// One line on the trusted console, `\r\n` added. Dropped if the
    /// console is full: output never makes the service wait.
    fn say(&mut self, parts: &[&[u8]]) {
        let mut line = [0u8; 128];
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
                if !found {
                    self.say(&[b"no agent ", name]);
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
            }
            Command::Help => self.say(&[b"commands: list, stop <agent>, stop all"]),
        }
    }

    /// A message on the endpoint. Keeps the capability only for a valid
    /// request from the badge allowed to send it.
    fn message(&mut self, msg: &[u8], cap: Handle, badge: u32) {
        let valid = cap != 0 && process_status(cap).is_ok();
        match parse(msg) {
            Ok(Request::Runtime) if badge == INIT && valid => {
                if let Some(old) = self.runtime.replace(cap) {
                    let _ = delete(old);
                }
                self.say(&[b"registered runtime"]);
            }
            Ok(Request::Register { slot, name }) if badge == RUNTIME && valid => {
                let mut a = Agent {
                    name: [0; MAX_NAME],
                    len: name.len(),
                    process: cap,
                };
                a.name[..name.len()].copy_from_slice(name);
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
        agents: [None; SLOTS as usize],
    };
    if send(REPORT, b"ready", 0, 0, 0).is_err() {
        return 4;
    }
    t.say(&[b"trust: ready; commands: list, stop <agent>, stop all"]);
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
