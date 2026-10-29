//! Test kernel: a model file of the M3.1 target size read from disk into
//! one process (#78, user-environment.md). `cargo xtask` boots it with
//! 2 GiB of guest memory and a store holding `models/model.gguf` (676 MB:
//! the Qwen2.5-0.5B q8_0 file from `PHAROS_MODEL`, or a generated GGUF of
//! the same size) and `models/model.sha256`. The `store` program serves it
//! to a read-only `storeclient`, which copies it into its own memory,
//! checks the SHA-256, and parses it with `pharos-infer`'s GGUF reader.
//! Runs under UEFI (D-009).

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

/// Namespace 3 (`models`), read-only (`store_proto`).
const MODELS_READ_ONLY: u32 = 3 | 1 << 16;
/// 800 MiB: the file, the 16 MiB window, and the heap.
const CLIENT_PAGES: u64 = 204_800;

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
    // 32 MiB: the client's 16 MiB window and the store's heap.
    let service = process::spawn_elf_limited(&programs, b"bin/store", 0, caps, 8192);
    t.check("the storage service started", service.is_ok());
    let ready = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "it mounted the store and reported ready",
        ready.is_some_and(|m| m.bytes() == b"ready"),
    );
    let root = Capability::new(Object::Endpoint(endpoint), SEND);
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        root.derive_badged(SEND, MODELS_READ_ONLY),
    ];
    let start = time::uptime();
    let Ok(id) = process::spawn_elf_limited(&programs, b"bin/storeclient", 5, caps, CLIENT_PAGES)
    else {
        t.check("the client started", false);
        return;
    };
    let mut code = None;
    for _ in 0..3000 {
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
        "stat the model file: at least 675,710,816 bytes",
        "read the expected SHA-256",
        "allocate the file's size in one process",
        "read the whole file through the window",
        "its SHA-256 matches",
        "pharos-infer's GGUF reader parses it",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, out.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the client exited with no failures", code == Some(0));
}
