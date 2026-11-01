//! Test kernel: the inference service (#88, inference.md). `cargo xtask`
//! boots it with a store holding `models/test.gguf`, the service's test
//! model (manifest model 2), and `models/test.expected`, the text the host
//! generated from "hello hello" with the same engine and math. The kernel
//! starts the `store` program, then `infer` with exactly the capabilities
//! `init` gives it, then an `inferclient` that generates through the
//! service and compares. A second `inferclient` tests failures (#89),
//! using `models/corrupt.gguf` and `models/short.gguf`, broken copies of
//! the test model (manifest models 3 and 4). Last, the service's handles
//! must be exactly the four it was given and its own reply endpoint. Runs
//! under UEFI (D-009).
//!
//! Built with `PHAROS_INFER_S1` set (`cargo xtask bench-infer`, #90), it
//! instead runs scenario S1 with the real model: `inferclient` mode 3 times
//! it, and the kernel samples the service's mapped memory.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{CONFIG, Capability, IRQ, MAP, Object, RECEIVE, SEND, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// Namespace 3 (`models`), read-only (`pharos_proto::store`).
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
/// 1 GiB, as `init` gives the service (D-011).
const SERVICE_PAGES: u64 = 1 << 18;
/// 1 MiB: the client's buffers.
const CLIENT_PAGES: u64 = 256;
/// The clients' badges on the inference endpoint.
const CLIENT: u32 = 1;
const OTHER: u32 = 2;

/// Set by `cargo xtask bench-infer`: run S1 instead of the checks.
const S1: bool = option_env!("PHAROS_INFER_S1").is_some();

/// Runs `inferclient` in mode `arg`, sampling `service`'s mapped pages
/// every 100 ms; its exit code, lines, and the most pages seen.
fn client(
    programs: &fs::Fs,
    arg: u64,
    caps: Vec<alloc::sync::Arc<Capability>>,
    service: Option<TaskId>,
) -> (Option<u64>, Vec<Vec<u8>>, u64) {
    let start = time::uptime();
    let Ok(id) = process::spawn_elf_limited(programs, b"bin/inferclient", arg, caps, CLIENT_PAGES)
    else {
        return (None, Vec::new(), 0);
    };
    let mut code = None;
    let mut peak = 0;
    // 300 s: S1 loads a 676 MB model.
    for _ in 0..3000 {
        if let Some(p) = service.and_then(process::by_id) {
            peak = peak.max(p.memory.lock().used);
        }
        if let Some(e) = process::exits().into_iter().find(|e| e.task == id) {
            code = Some(e.code);
            break;
        }
        sched::sleep(Duration::from_millis(100));
    }
    kprintln!(
        "  client {arg} finished in {} ms",
        (time::uptime() - start).as_millis()
    );
    (code, lines(id), peak)
}

fn steps(t: &mut TestRun, out: &[Vec<u8>], steps: &[&str]) {
    for step in steps {
        let want = alloc::format!("ok {step}");
        t.check(step, out.iter().any(|l| l == want.as_bytes()));
    }
}

fn lines(id: TaskId) -> Vec<Vec<u8>> {
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, l)| l)
        .collect();
    for l in &lines {
        kprintln!("  {id}: {}", core::str::from_utf8(l).unwrap_or("?"));
    }
    lines
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
    let disk = pci::devices()
        .into_iter()
        .filter(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .nth(1);
    let (Some(disk), Ok(programs)) = (disk, fs::mount("programs")) else {
        t.check("the store disk and the programs are found", false);
        return;
    };
    let Some(device) = DeviceHandle::grant(disk) else {
        t.check("the store disk is granted", false);
        return;
    };
    let (endpoint, report) = (Endpoint::new(), Endpoint::new());
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(device), MAP | CONFIG | IRQ),
        Capability::new(Object::Endpoint(endpoint.clone()), RECEIVE),
        Capability::new(Object::Endpoint(report.clone()), SEND),
    ];
    // 40 MiB: the service's 16 MiB window, the client's, and the heap.
    let service = process::spawn_elf_limited(&programs, b"bin/store", 0, caps, 10_240);
    t.check("the storage service started", service.is_ok());
    let ready = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "it mounted the store and reported ready",
        ready.is_some_and(|m| m.bytes() == b"ready"),
    );
    let store_endpoint = endpoint.clone();
    let store = Capability::new(Object::Endpoint(endpoint), SEND);
    let (infer, infer_report) = (Endpoint::new(), Endpoint::new());
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Endpoint(infer.clone()), RECEIVE),
        Capability::new(Object::Endpoint(infer_report.clone()), SEND),
        store.derive_badged(SEND, MODELS_READ_ONLY),
    ];
    let service = process::spawn_elf_limited(&programs, b"bin/infer", 0, caps, SERVICE_PAGES);
    t.check("the inference service started", service.is_ok());
    let ready = ipc::poll(&infer_report, Duration::from_secs(10));
    t.check(
        "it reported ready without loading a model",
        ready.is_some_and(|m| m.bytes() == b"ready"),
    );
    let root = Capability::new(Object::Endpoint(infer.clone()), SEND);
    if S1 {
        let caps = vec![
            Capability::new(Object::DebugConsole, WRITE),
            root.derive_badged(SEND, CLIENT),
            store.derive_badged(SEND, MODELS_READ_ONLY | 1 << 17),
        ];
        let (code, out, peak) = client(&programs, 3, caps, service.as_ref().ok().copied());
        steps(
            t,
            &out,
            &[
                "read the S1 prompt and the host's text",
                "S1: the text is the host's",
            ],
        );
        kprintln!("S1 peak: {peak} pages mapped by the service");
        t.check("the S1 client exited with no failures", code == Some(0));
        return;
    }
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        root.derive_badged(SEND, CLIENT),
        // Bit 17 tells the client's store buffer from the service's.
        store.derive_badged(SEND, MODELS_READ_ONLY | 1 << 17),
    ];
    let (code, out, _) = client(&programs, 1, caps, None);
    steps(
        t,
        &out,
        &[
            "read the host's expected text",
            "INFO: inference v1, 4 models, test model not loaded, context 64",
            "version 2: VERSION, supported 1 to 1",
            "GENERATE with no buffer: NO_BUFFER",
            "GENERATE with model 9: NO_MODEL",
            "GENERATE: a session, 5 prompt tokens",
            "NEXT until the token limit",
            "the text is the host's",
            "NEXT after the end: NO_SESSION",
            "RESULT: model 2 and its SHA-256, engine version, 5 + 20 tokens, token limit",
            "INFO: the test model is loaded",
        ],
    );
    t.check("the client exited with no failures", code == Some(0));

    // A stopped service: an endpoint nobody receives on.
    let dead = Capability::new(Object::Endpoint(Endpoint::new()), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        root.derive_badged(SEND, CLIENT),
        store.derive_badged(SEND, MODELS_READ_ONLY | 1 << 17),
        root.derive_badged(SEND, OTHER),
        dead,
    ];
    let (code, out, _) = client(&programs, 2, caps, None);
    steps(
        t,
        &out,
        &[
            "GENERATE with 5 + 60 tokens, context 64: CONTEXT",
            "GENERATE with 5 + 59 tokens: a session",
            "a second client's GENERATE: BUSY",
            "a second client's NEXT and CANCEL: NO_SESSION",
            "RESULT while running: BUSY",
            "CANCEL, then NEXT: NO_SESSION",
            "RESULT: cancelled, no tokens",
            "NEXT: text, not the end",
            "NEXT after 11 s idle: NO_SESSION",
            "RESULT: cancelled after the first NEXT",
            "the second client is no longer BUSY (NO_BUFFER)",
            "model 3, one byte changed: MODEL_INVALID, hash",
            "model 4, 32 bytes short: MODEL_INVALID, size",
            "model 3 again: MODEL_INVALID, hash",
            "INFO: model 2 loaded, 3 failed at hash, 4 at size",
            "a stopped service: TIMED_OUT after 200 ms, within 3 ticks",
        ],
    );
    t.check(
        "the failure client exited with no failures",
        code == Some(0),
    );

    // The service still runs and holds nothing it was not given: the four
    // handles (same objects, rights, badges) and one endpoint of its own.
    let held: Vec<_> = service
        .ok()
        .and_then(process::by_id)
        .map(|p| {
            let mut caps = p.caps.lock();
            (1..=pharos_kernel::cap::MAX_HANDLES as u64)
                .filter_map(|h| caps.get(h, 0).ok())
                .collect()
        })
        .unwrap_or_default();
    let same = |c: &Capability, e: &alloc::sync::Arc<Endpoint>| matches!(c.object(), Object::Endpoint(o) if alloc::sync::Arc::ptr_eq(o, e));
    let given = |c: &Capability| match c.object() {
        Object::DebugConsole => c.rights() == WRITE,
        Object::Endpoint(_) if same(c, &infer) => (c.rights(), c.badge()) == (RECEIVE, 0),
        Object::Endpoint(_) if same(c, &infer_report) => (c.rights(), c.badge()) == (SEND, 0),
        Object::Endpoint(_) if same(c, &store_endpoint) => {
            (c.rights(), c.badge()) == (SEND, MODELS_READ_ONLY)
        }
        _ => false,
    };
    let own = |c: &Capability| {
        matches!(c.object(), Object::Endpoint(e)
            if ![&infer, &infer_report, &store_endpoint].iter().any(|g| alloc::sync::Arc::ptr_eq(e, g)))
    };
    for c in &held {
        kprintln!("  service holds {c:?}");
    }
    t.check(
        "the service runs and holds only its four handles and its reply endpoint",
        held.len() == 5
            && held.iter().filter(|c| given(c)).count() == 4
            && held.iter().filter(|c| own(c)).count() == 1,
    );
}
