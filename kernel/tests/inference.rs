//! Test kernel: the inference service (#88, inference.md). `cargo xtask`
//! boots it with a store holding `models/test.gguf`, the service's test
//! model (manifest model 2), and `models/test.expected`, the text the host
//! generated from "hello hello" with the same engine and math. The kernel
//! starts the `store` program, then `infer` with exactly the capabilities
//! `init` gives it, then an `inferclient` that generates through the
//! service and compares. Runs under UEFI (D-009).

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
/// The client's badge on the inference endpoint.
const CLIENT: u32 = 1;

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
    let root = Capability::new(Object::Endpoint(infer), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        root.derive_badged(SEND, CLIENT),
        // Bit 17 tells the client's store buffer from the service's.
        store.derive_badged(SEND, MODELS_READ_ONLY | 1 << 17),
    ];
    let start = time::uptime();
    let Ok(id) = process::spawn_elf_limited(&programs, b"bin/inferclient", 1, caps, CLIENT_PAGES)
    else {
        t.check("the client started", false);
        return;
    };
    let mut code = None;
    for _ in 0..600 {
        if let Some(e) = process::exits().into_iter().find(|e| e.task == id) {
            code = Some(e.code);
            break;
        }
        sched::sleep(Duration::from_millis(100));
    }
    kprintln!(
        "  client finished in {} ms",
        (time::uptime() - start).as_millis()
    );
    let out = lines(id);
    for step in [
        "read the host's expected text",
        "INFO: inference v1, 2 models, test model not loaded, context 64",
        "version 2: VERSION, supported 1 to 1",
        "GENERATE with no buffer: NO_BUFFER",
        "GENERATE with model 9: NO_MODEL",
        "GENERATE: a session, 5 prompt tokens",
        "NEXT until the token limit",
        "the text is the host's",
        "NEXT after the end: NO_SESSION",
        "RESULT: model 2 and its SHA-256, engine version, 5 + 20 tokens, token limit",
        "INFO: the test model is loaded",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, out.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the client exited with no failures", code == Some(0));
}
