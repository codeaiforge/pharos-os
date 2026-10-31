//! Test kernel: first inference on Pharos (#87). `cargo xtask` boots it
//! with a store holding `models/tiny.gguf`, a tiny random Qwen2 model with
//! Q8_0 weights (`pharos_infer::synth`), and `models/tiny.expected`, the
//! tokens and logit hash the host computed for it with the same `libm`
//! math. The `store` program serves them to a read-only `storeclient`,
//! which runs the model with `pharos-infer` and compares. Runs under UEFI
//! (D-009).

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
/// 8 MiB: the model, the 1 MiB window, and the engine's buffers.
const CLIENT_PAGES: u64 = 2048;

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
    // 8 MiB: the client's 1 MiB window and the store's heap.
    let service = process::spawn_elf_limited(&programs, b"bin/store", 0, caps, 2048);
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
    let Ok(id) = process::spawn_elf_limited(&programs, b"bin/storeclient", 6, caps, CLIENT_PAGES)
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
        "read the tiny model and the host's output",
        "pharos-infer loads and runs the model",
        "tokens and logit hash identical to the host's",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, out.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the client exited with no failures", code == Some(0));
}
