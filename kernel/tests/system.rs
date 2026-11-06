//! Test kernel: the integrated system to its ready state, and recovery
//! (#153, services.md, D-026). `cargo xtask runner` boots it with the boot
//! image's modules (the `root` filesystem) and disks, so the kernel starts
//! `init` with the boot table (argument 0) exactly as the main kernel does.
//! It checks the summary (every boot service ready), then acts as faults
//! would: it kills the knowledge service (restarted after its delay, its
//! dependents named and still running), stops the network service (a
//! stop, never restarted), and kills the inference service four times
//! (restarted three times, then given up). The runner types `services` on
//! the trusted console once `trust` shows the give-up; the kernel waits
//! until `init` answered it. The runner then checks the trusted console
//! and the audit trail: ready, each event one line and one record, and
//! each service's state. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{MAX_HANDLES, Object};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, ipc, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// The vector a killed service's end reports.
const KILLED: u64 = 13;
/// The boot table's 8 entries, all succeeded.
const SUMMARY: [u8; 2] = [8, 0];
const VIRTIO_NET: u16 = 0x1041;
/// `trust` holds the virtio-console.
const VIRTIO_CONSOLE: u16 = 0x1043;
/// Namespace 3 read-only: the inference service's storage badge.
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
/// The knowledge service holds `init`'s report badge 6 (entry 5) and
/// storage badge 8 (namespace `knowledge`); no other service holds both.
const KNOWLEDGE_BADGES: [u32; 2] = [6, 8];

/// The live children of `init` whose capabilities match `f`.
fn children(init: TaskId, f: impl Fn(&[(&Object, u32)]) -> bool) -> Option<TaskId> {
    (init + 1..init + 400).find(|&id| {
        process::by_id(id).is_some_and(|p| {
            let mut caps = p.caps.lock();
            let held: Vec<_> = (1..=MAX_HANDLES as u64)
                .filter_map(|h| caps.get(h, 0).ok())
                .collect();
            let held: Vec<(&Object, u32)> = held.iter().map(|c| (c.object(), c.badge())).collect();
            p.parent == Some(init) && f(&held)
        })
    })
}

fn net_of(init: TaskId) -> Option<TaskId> {
    children(init, |caps| {
        caps.iter()
            .any(|(o, _)| matches!(o, Object::Device(d) if d.pci.device == VIRTIO_NET))
    })
}

fn infer_of(init: TaskId) -> Option<TaskId> {
    children(init, |caps| {
        caps.iter()
            .any(|(o, b)| matches!(o, Object::Endpoint(_)) && *b == MODELS_READ_ONLY)
    })
}

fn knowledge_of(init: TaskId) -> Option<TaskId> {
    children(init, |caps| {
        KNOWLEDGE_BADGES.iter().all(|want| {
            caps.iter()
                .any(|(o, b)| matches!(o, Object::Endpoint(_)) && b == want)
        })
    })
}

/// The console so far.
#[derive(Default)]
struct Watch {
    lines: Vec<(TaskId, Vec<u8>)>,
}

impl Watch {
    fn poll(&mut self) {
        for l in process::debug_output() {
            if !self.lines.contains(&l) {
                kprintln!("  {}: {}", l.0, core::str::from_utf8(&l.1).unwrap_or("?"));
                self.lines.push(l);
            }
        }
    }
    fn has(&self, text: &str) -> bool {
        self.lines.iter().any(|(_, l)| l == text.as_bytes())
    }
    fn starts(&self, prefix: &str) -> bool {
        self.lines
            .iter()
            .any(|(_, l)| l.starts_with(prefix.as_bytes()))
    }
}

/// What the kernel does next, in order. Within 50 s (about 7 s needed),
/// under the runner's default 60 s limit, so a stuck step is reported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    Ready,
    KillKnowledge,
    StopNet,
    /// Kill the inference service; this many kills done.
    KillInfer(u8),
    Listed,
    Done,
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
    let init = process::spawn_elf_limited(&root, b"bin/init", 0, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the boot table", init.is_ok());
    let Ok(init) = init else {
        return;
    };

    let mut w = Watch::default();
    let mut summary = None;
    let mut step = Step::Ready;
    // The processes before each fault, so the kernel waits for new ones.
    let (mut knowledge, mut infer) = (None, None);
    let (mut trust, mut agents) = (None, None);
    let start = time::uptime();
    while step != Step::Done && time::uptime() - start < Duration::from_secs(50) {
        w.poll();
        match step {
            Step::Ready => {
                summary = ipc::poll(&report, Duration::from_millis(1)).map(|m| m.bytes().to_vec());
                if summary.is_some() {
                    knowledge = knowledge_of(init);
                    step = Step::KillKnowledge;
                }
            }
            Step::KillKnowledge => {
                // Who depends on it, to check they keep running.
                trust = children(init, |caps| {
                    caps.iter().any(
                        |(o, _)| matches!(o, Object::Device(d) if d.pci.device == VIRTIO_CONSOLE),
                    )
                });
                // Only the runtime holds the root filesystem (its manifest).
                agents = children(init, |caps| {
                    caps.iter().any(|(o, _)| matches!(o, Object::Filesystem(_)))
                });
                if knowledge.is_some_and(|id| process::kill(id, KILLED)) {
                    step = Step::StopNet;
                } else {
                    break;
                }
            }
            Step::StopNet => {
                let back = knowledge_of(init).is_some_and(|id| Some(id) != knowledge);
                if back && w.has("init: knowledge ready") && w.starts("init: knowledge restarting")
                {
                    if net_of(init).is_some_and(process::stop) {
                        step = Step::KillInfer(0);
                    } else {
                        break;
                    }
                }
            }
            Step::KillInfer(n) => {
                let now = infer_of(init);
                let fresh = now.is_some() && now != infer;
                if w.has("init: net stopped; not restarted") && fresh {
                    // Give the new one a moment to start.
                    sched::sleep(Duration::from_millis(200));
                    if now.is_some_and(|id| process::kill(id, KILLED)) {
                        infer = now;
                        step = if n == 3 {
                            Step::Listed
                        } else {
                            Step::KillInfer(n + 1)
                        };
                    }
                }
            }
            Step::Listed => {
                if w.has("init: services listed for trust") {
                    step = Step::Done;
                }
            }
            Step::Done => {}
        }
        sched::sleep(Duration::from_millis(50));
    }
    sched::sleep(Duration::from_millis(500));
    w.poll();
    kprintln!("  reached step {step:?}");

    t.check(
        "init reported every boot service ready: [8, 0]",
        summary.as_deref() == Some(&SUMMARY[..]),
    );
    for (what, line) in [
        (
            "the knowledge service's kill is reported",
            "init: knowledge killed 13",
        ),
        (
            "and it is restarted after its delay, its dependents named",
            "init: knowledge restarting 1 of 3 in 100 ms; used by trust, agents",
        ),
        (
            "the network service's stop is reported",
            "init: net stopped; not restarted",
        ),
        (
            "the inference service's kills are reported",
            "init: infer killed 13",
        ),
        (
            "and it is restarted",
            "init: infer restarting 1 of 3 in 100 ms; used by agents",
        ),
        (
            "again",
            "init: infer restarting 2 of 3 in 400 ms; used by agents",
        ),
        (
            "and again",
            "init: infer restarting 3 of 3 in 1600 ms; used by agents",
        ),
        (
            "then given up",
            "init: infer not restarted: restarts used up",
        ),
        ("init answered services", "init: services listed for trust"),
    ] {
        t.check(&alloc::format!("{what}: {line}"), w.has(line));
    }
    t.check(
        "the network service was not restarted",
        !w.starts("init: net restarting"),
    );
    t.check(
        "the inference service was not restarted a fourth time",
        !w.starts("init: infer restarting 4"),
    );
    t.check(
        "the knowledge service runs again",
        knowledge_of(init).is_some_and(|id| Some(id) != knowledge),
    );
    t.check(
        "its dependents kept running: trust and the agent runtime",
        trust
            .zip(agents)
            .is_some_and(|(a, b)| process::by_id(a).is_some() && process::by_id(b).is_some()),
    );
    t.check("no network service runs", net_of(init).is_none());
    t.check("no inference service runs", infer_of(init).is_none());
}
