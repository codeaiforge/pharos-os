//! Test kernel: the system working, restarting, and being managed for a
//! long time, with nothing leaking or drifting (M5.1, #189, testing.md
//! "Soak"). `cargo xtask runner` boots it with the boot image's modules
//! and disks; the kernel starts `init` with the `soak` table (argument 7):
//! the boot table, the runtime on its test policy table, and `soaker`, which
//! runs one `worker` task after another. Each cycle:
//! 1. the knowledge service is killed, and restarted by its policy;
//! 2. `restart knowledge` on the trusted console (the runner types it when
//!    the kernel prints `soak: restart knowledge`), which also resets its
//!    restart count, so the policy is never used up;
//! 3. `stop service net`, then `start net` (on `soak: restart net`);
//! 4. at least one of `soaker`'s tasks done since the last cycle.
//!
//! The run lasts `PHAROS_SOAK_MINUTES` (a build-time setting; unset, one
//! cycle, as in every push run). After the first cycle and every
//! [`CHECK_EVERY`], and at the end: free frames within [`FRAME_MARGIN`] of
//! the first cycle's, the same number of processes and of handles held by
//! them all, every service holding
//! exactly its manifest, and no process killed by a fault. The runner then
//! checks the audit trail: one record and one console line per event.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{MAX_HANDLES, Object};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

#[path = "common/manifests.rs"]
mod manifests;

pharos_kernel::test_kernel!(run);

/// How long the run lasts, in minutes; 0 for one cycle.
const MINUTES: u64 = match option_env!("PHAROS_SOAK_MINUTES") {
    Some(m) => parse(m),
    None => 0,
};

const fn parse(s: &str) -> u64 {
    let b = s.as_bytes();
    let (mut i, mut n) = (0, 0);
    while i < b.len() {
        assert!(
            b[i].is_ascii_digit(),
            "PHAROS_SOAK_MINUTES must be a number of minutes"
        );
        n = n * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    n
}

/// How often the drift checks run.
const CHECK_EVERY: Duration = Duration::from_secs(300);
/// Most free frames may differ from the first cycle's: the services' heaps
/// and the store's caches settle at different sizes from cycle to cycle.
// ponytail: 1 frame measured in 2 hours (708 cycles, M5.1 gate, testing.md); a leak of one
// frame per cycle passes 32 within 6 minutes. Tighten if an 8-hour run stays this flat.
const FRAME_MARGIN: u64 = 32;
/// A cycle starts at most this often: the audit trail grows about 110
/// bytes a record, and at a cycle every 2 s (12 records) an 8-hour run
/// would fill the store's 16 MiB (testing.md).
const CYCLE_EVERY: Duration = Duration::from_secs(10);
/// Most one step of a cycle may take.
const STEP_LIMIT: Duration = Duration::from_secs(60);
/// The vector a killed service's end reports.
const KILLED: u64 = 13;
/// The knowledge service holds `init`'s report badge 6 (entry 5) and
/// storage badge 8; no other service holds both.
const KNOWLEDGE_BADGES: [u32; 2] = [6, 8];

/// The live child of `init` holding both of `KNOWLEDGE_BADGES`.
fn knowledge_of(init: TaskId) -> Option<TaskId> {
    (init + 1..init + 100_000).find(|&id| {
        process::by_id(id).is_some_and(|p| {
            let mut caps = p.caps.lock();
            let held: Vec<u32> = (1..=MAX_HANDLES as u64)
                .filter_map(|h| caps.get(h, 0).ok())
                .filter(|c| matches!(c.object(), Object::Endpoint(_)))
                .map(|c| c.badge())
                .collect();
            p.parent == Some(init) && KNOWLEDGE_BADGES.iter().all(|b| held.contains(b))
        })
    })
}

/// Every debug line once, counted as it comes.
struct Watch {
    seen: u64,
    /// Lines since the cycle began.
    lines: Vec<Vec<u8>>,
    tasks: u64,
    failed: Option<String>,
}

impl Watch {
    fn poll(&mut self) {
        let (now, new) = process::debug_output_since(self.seen);
        self.seen = now;
        let Some(new) = new else {
            self.failed
                .get_or_insert("more debug lines came than the log keeps".into());
            return;
        };
        for (_, line) in new {
            if line.starts_with(b"soak: task ") {
                if line.ends_with(b" done") {
                    self.tasks += 1;
                } else {
                    let text = String::from_utf8_lossy(&line).into_owned();
                    self.failed.get_or_insert(text);
                }
            }
            self.lines.push(line);
        }
    }

    fn has(&self, line: &str) -> bool {
        self.lines.iter().any(|l| l == line.as_bytes())
    }

    /// Polls until every one of `lines` came this cycle; false after
    /// [`STEP_LIMIT`].
    fn wait(&mut self, lines: &[&str]) -> bool {
        let start = time::uptime();
        loop {
            self.poll();
            if lines.iter().all(|l| self.has(l)) {
                return true;
            }
            if self.failed.is_some() || time::uptime() - start > STEP_LIMIT {
                return false;
            }
            sched::sleep(Duration::from_millis(50));
        }
    }
}

fn free_frames() -> u64 {
    mm::frames().as_ref().map_or(0, |f| f.stats().free as u64)
}

/// What must not drift.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct State {
    frames: u64,
    processes: usize,
    /// Handles every process holds, together.
    handles: usize,
}

/// The fewest processes and handles over 1 s of samples (#200): a
/// service holds a handle for a moment while it serves a request (one was
/// counted after the first cycle in CI and gone by the 5-minute check). A
/// leaked handle is in every sample, so it still counts. Says when the
/// samples differed.
fn settled() -> State {
    let samples: Vec<State> = (0..50)
        .map(|_| {
            let s = state();
            sched::sleep(Duration::from_millis(20));
            s
        })
        .collect();
    let key = |s: &State| (s.processes, s.handles);
    let low = *samples.iter().min_by_key(|s| key(s)).unwrap_or(&samples[0]);
    let high = samples.iter().map(key).max().unwrap_or(key(&low));
    if high != key(&low) {
        kprintln!(
            "soak: sampled {} to {} processes, {} to {} handles; counted the fewest",
            low.processes,
            high.0,
            low.handles,
            high.1
        );
    }
    low
}

fn state() -> State {
    let ids = process::ids();
    State {
        frames: free_frames(),
        processes: ids.len(),
        handles: (ids.into_iter().filter_map(process::by_id))
            .map(|p| p.caps.lock().len())
            .sum(),
    }
}

/// One cycle; the step that failed, if one did.
fn cycle(w: &mut Watch, init: TaskId) -> Result<(), &'static str> {
    w.lines.clear();
    let tasks = w.tasks;
    let killed = knowledge_of(init).is_some_and(|id| process::kill(id, KILLED));
    if !killed {
        return Err("the knowledge service found and killed");
    }
    if !w.wait(&[
        "init: knowledge killed 13",
        "init: knowledge restarting 1 of 3 in 100 ms; used by trust, agents, soaker",
        "init: knowledge ready",
    ]) {
        return Err("init restarted the knowledge service, ready");
    }
    w.lines.clear();
    kprintln!("soak: restart knowledge");
    if !w.wait(&[
        "init: knowledge restarted by the user; used by trust, agents, soaker",
        "init: knowledge ready",
    ]) {
        return Err("the user restarted the knowledge service, ready");
    }
    w.lines.clear();
    kprintln!("soak: restart net");
    if !w.wait(&[
        "init: net stopped by the user",
        "init: net started by the user",
        "init: net ready",
    ]) {
        return Err("the user stopped and started the network service, ready");
    }
    let start = time::uptime();
    while w.tasks == tasks && w.failed.is_none() && time::uptime() - start < STEP_LIMIT {
        sched::sleep(Duration::from_millis(100));
        w.poll();
    }
    if w.tasks == tasks {
        return Err("a soaker task done this cycle");
    }
    Ok(())
}

/// The drift checks; prints each and returns whether all held.
fn checked(t: &mut TestRun, when: &str, first: State, audit: &manifests::Audit<'_>) -> bool {
    let now = settled();
    let (findings, _) = audit.check();
    for f in &findings {
        kprintln!("  audit: {f}");
    }
    kprintln!(
        "soak: {when}: {} frames free (first cycle {}), {} processes ({}), {} handles ({})",
        now.frames,
        first.frames,
        now.processes,
        first.processes,
        now.handles,
        first.handles
    );
    // Which process holds what, to find one that drifted: `id:handles`
    // each (a restarted service has a new id).
    let mut line = String::from("soak: handles by process:");
    for p in process::ids().into_iter().filter_map(process::by_id) {
        line += &alloc::format!(" {}:{}", p.record.id, p.caps.lock().len());
    }
    kprintln!("{line}");
    let held = [
        (
            "free frames within the margin of the first cycle's",
            now.frames.abs_diff(first.frames) <= FRAME_MARGIN,
        ),
        (
            "the same number of processes",
            now.processes == first.processes,
        ),
        ("the same number of handles", now.handles == first.handles),
        (
            "every service holds exactly its manifest",
            findings.is_empty(),
        ),
        ("no process killed by a fault", process::kills().is_empty()),
    ];
    let mut all = true;
    for (what, ok) in held {
        if !ok {
            t.check(&alloc::format!("{when}: {what}"), false);
            all = false;
        }
    }
    all
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    let Some(hhdm) = requests::HHDM.response() else {
        return;
    };
    if memory {
        storage::record_modules(requests::MODULES.response(), hhdm.offset);
    }
    let ready = memory
        && mm::init_heap().is_ok()
        && apic::init(hhdm.offset).is_ok()
        && time::init().is_ok()
        && sched::init().is_ok();
    t.check("memory, heap, APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    process::init();
    t.check("preemption enabled", sched::enable_preemption().is_ok());
    pci::enumerate();
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let init = process::spawn_elf_limited(&root, b"bin/init", 7, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the soak table", init.is_ok());
    let Ok(init) = init else {
        return;
    };
    let summary = ipc::poll(&report, Duration::from_secs(50)).map(|m| m.bytes().to_vec());
    t.check(
        "init reported every service ready: [9, 0, 0, 0]",
        summary.as_deref() == Some(&[9, 0, 0, 0][..]),
    );
    let audit = match manifests::Audit::new(init, &report, pharos_services::SOAK) {
        Ok(a) => a,
        Err(why) => {
            t.check(
                &alloc::format!("the audit learned init's endpoints: {why}"),
                false,
            );
            return;
        }
    };
    let mut w = Watch {
        seen: 0,
        lines: Vec::new(),
        tasks: 0,
        failed: None,
    };
    let start = time::uptime();
    let end = start + Duration::from_secs(MINUTES * 60);
    kprintln!("soak: {MINUTES} minutes");
    let mut cycles: u64 = 0;
    let mut first = None;
    let mut next_check = start + CHECK_EVERY;
    let mut drifted = false;
    let outcome = loop {
        let began = time::uptime();
        if let Err(step) = cycle(&mut w, init) {
            break Err(step);
        }
        cycles += 1;
        let base = *first.get_or_insert_with(settled);
        if cycles == 1 {
            drifted |= !checked(t, "after the first cycle", base, &audit);
        }
        if time::uptime() >= next_check {
            next_check += CHECK_EVERY;
            let minute = (time::uptime() - start).as_secs() / 60;
            drifted |= !checked(t, &alloc::format!("at {minute} minutes"), base, &audit);
        }
        if drifted || time::uptime() >= end {
            break Ok(());
        }
        let next = began + CYCLE_EVERY;
        while time::uptime() < next {
            sched::sleep(Duration::from_millis(100));
            w.poll();
        }
    };
    if let Some(base) = first {
        drifted |= !checked(t, "at the end", base, &audit);
    }
    if let Err(step) = outcome {
        t.check(&alloc::format!("cycle {}: {step}", cycles + 1), false);
    }
    if let Some(why) = &w.failed {
        kprintln!("  soak: {why}");
    }
    kprintln!(
        "soak: {cycles} cycles, {} tasks, {} minutes",
        w.tasks,
        (time::uptime() - start).as_secs() / 60
    );
    t.check(
        "every cycle and task passed, and nothing drifted",
        outcome.is_ok() && w.failed.is_none() && !drifted && cycles > 0,
    );
}
