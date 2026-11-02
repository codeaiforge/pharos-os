//! Test kernel: `init` supervising services (#100, agents.md). The kernel
//! starts `init` with its `supervision` table (argument 3) and the store
//! disk `cargo xtask runner` writes (the test model staged as
//! `models/staged.gguf`). It watches the console and acts on what it
//! sees: when `client: kill the store` appears it kills the storage
//! service, when `client: kill the inference service` appears the
//! inference service (`process::kill`, as a crash would), and it stops the
//! `steady` daemon once ready. Then it checks `init`'s lines: a daemon
//! that never sends `ready` is stopped after 10 s, a crashing one is
//! restarted 3 times and then left, a stopped one is not restarted, and
//! both killed services are restarted. The client's steps check that its
//! services served again, and the kernel that the storage and inference
//! services freed the slots of clients that ended. Runs under UEFI
//! (D-009).

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
/// Namespace 3 read-only: the inference service's storage badge.
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;

/// The live child of `init` whose capabilities match `f`.
fn service(init: TaskId, f: impl Fn(&Object, u32) -> bool) -> Option<TaskId> {
    (init + 1..init + 400).find(|&id| {
        process::by_id(id).is_some_and(|p| {
            let mut caps = p.caps.lock();
            p.parent == Some(init)
                && (1..=MAX_HANDLES as u64)
                    .filter_map(|h| caps.get(h, 0).ok())
                    .any(|c| f(c.object(), c.badge()))
        })
    })
}

fn store_of(init: TaskId) -> Option<TaskId> {
    service(init, |o, _| matches!(o, Object::Device(_)))
}

fn infer_of(init: TaskId) -> Option<TaskId> {
    service(init, |o, b| {
        matches!(o, Object::Endpoint(_)) && b == MODELS_READ_ONLY
    })
}

/// Pages `id` has mapped.
fn used(id: Option<TaskId>) -> Option<u64> {
    id.and_then(process::by_id).map(|p| p.memory.lock().used)
}

/// The console so far, and what the kernel did on it.
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
    fn who(&self, text: &str) -> Option<TaskId> {
        self.lines
            .iter()
            .find(|(_, l)| l == text.as_bytes())
            .map(|(id, _)| *id)
    }
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
    let Ok(programs) = fs::mount("programs") else {
        t.check("the programs are found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(programs.clone(), report.clone(), true);
    let init =
        process::spawn_elf_limited(&programs, b"bin/init", 3, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with its supervision table", init.is_ok());
    let Ok(init) = init else {
        return;
    };

    let mut w = Watch::default();
    let (mut store_killed, mut infer_killed, mut steady_stopped) = (false, false, false);
    let (mut holding, mut held) = (None, None);
    let (mut serving, mut served) = (None, None);
    let mut summary = None;
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(150) {
        w.poll();
        if summary.is_none() {
            summary = ipc::poll(&report, Duration::from_millis(1)).map(|m| m.bytes().to_vec());
        }
        if !steady_stopped && w.has("init: steady ready") {
            if let Some(id) = w.who("svc: steady") {
                steady_stopped = process::stop(id);
            }
        }
        if !store_killed && w.has("client: kill the store") {
            store_killed = store_of(init).is_some_and(|id| process::kill(id, KILLED));
        }
        if !infer_killed && w.has("client: kill the inference service") {
            infer_killed = infer_of(init).is_some_and(|id| process::kill(id, KILLED));
        }
        // Memory before each client ends, while it still holds its slot.
        if holding.is_none() && w.has("svc: holding") {
            holding = used(store_of(init));
        }
        if serving.is_none() && w.has("client: done") {
            serving = used(infer_of(init));
        }
        // And after: `init` prints `done` once it sent `RELEASE`.
        if held.is_none() && w.has("init: holder done") {
            held = used(store_of(init));
        }
        if served.is_none() && w.has("init: client done") {
            served = used(infer_of(init));
        }
        let finished = w.has("init: holder done") || w.has("init: holder exited");
        if finished && w.has("init: flaky not restarted: restarts used up") {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    // `init` releases the slots right after it sees the end.
    sched::sleep(Duration::from_millis(500));
    w.poll();

    t.check("init reported its summary", summary.is_some());
    for (what, line) in [
        (
            "a daemon that never sends ready is stopped after 10 s",
            "init: silent no ready within 10 s; stopped",
        ),
        ("a crashed daemon is reported", "init: flaky killed 14"),
        ("and restarted", "init: flaky restarting 1"),
        ("a third time", "init: flaky restarting 3"),
        (
            "but not a fourth",
            "init: flaky not restarted: restarts used up",
        ),
        (
            "a stopped daemon is not restarted",
            "init: steady stopped; not restarted",
        ),
        (
            "the killed storage service is reported",
            "init: store killed 13",
        ),
        ("and restarted", "init: store restarting 1"),
        (
            "the killed inference service is reported",
            "init: infer killed 13",
        ),
        ("and restarted", "init: infer restarting 1"),
        ("the holder exited", "init: holder done"),
        ("the client exited with no failed step", "init: client done"),
    ] {
        t.check(&alloc::format!("{what}: {line}"), w.has(line));
    }
    t.check("the kernel stopped steady", steady_stopped);
    t.check(
        "the kernel killed both services",
        store_killed && infer_killed,
    );
    t.check(
        "steady was not restarted",
        !w.has("init: steady restarting 1"),
    );
    t.check(
        "flaky was not restarted a fourth time",
        !w.has("init: flaky restarting 4"),
    );
    for step in [
        "a missing model file is a read failure",
        "a read failure is not kept: the model is not loaded",
        "the model file is put in place",
        "RELEASE from a client is refused by both services",
        "after the store restarted, the model loads and generates the host's text",
        "the restarted inference service answers",
        "it has no buffer from the old one",
        "attached again, it loads the model and generates the host's text again",
    ] {
        t.check(step, w.has(&alloc::format!("ok {step}")));
    }
    let freed_store = holding.zip(held);
    kprintln!("  store pages while held and after: {freed_store:?}");
    // The next client may attach 32 pages meanwhile.
    t.check(
        "the storage service freed the 4 MiB buffer of the client that ended",
        freed_store.is_some_and(|(before, after)| before >= after + 768),
    );
    let freed_infer = serving.zip(served);
    kprintln!("  inference pages while serving and after: {freed_infer:?}");
    t.check(
        "the inference service freed the slot of the client that ended",
        freed_infer.is_some_and(|(before, after)| before > after),
    );
    t.check(
        "every slot release was answered",
        !w.lines
            .iter()
            .any(|(_, l)| l.windows(18).any(|x| x == b"slot not released,")),
    );
}
