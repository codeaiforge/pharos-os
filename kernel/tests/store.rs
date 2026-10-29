//! Test kernel: the storage service (#77, storage.md part 8). The `store`
//! program drives the second, writable virtio-blk disk (a fresh, empty
//! store from `cargo xtask`) and serves `storeclient` processes badged
//! with namespaces: files through a shared buffer, streams with their
//! chain, listing, deletion, `NO_SPACE`, read-only and foreign clients,
//! and refused badges. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
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

/// Namespace badges (`store_proto`): 1 `test`, 2 `spare`; bit 16 read-only.
const READ_ONLY: u32 = 1 << 16;

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

/// Runs `storeclient` with `arg`, page limit `limit`, and a service
/// capability for each badge; returns its exit code and output.
fn client(
    programs: &fs::Fs,
    service: &Arc<Capability>,
    arg: u64,
    limit: u64,
    badges: &[u32],
) -> (Option<u64>, Vec<Vec<u8>>) {
    let mut caps = vec![Capability::new(Object::DebugConsole, WRITE)];
    caps.extend(badges.iter().map(|&b| service.derive_badged(SEND, b)));
    let Ok(id) = process::spawn_elf_limited(programs, b"bin/storeclient", arg, caps, limit) else {
        return (None, Vec::new());
    };
    for _ in 0..600 {
        if let Some(e) = process::exits().into_iter().find(|e| e.task == id) {
            return (Some(e.code), lines(id));
        }
        sched::sleep(Duration::from_millis(50));
    }
    (None, lines(id))
}

fn passed(t: &mut TestRun, (code, lines): &(Option<u64>, Vec<Vec<u8>>), steps: &[&str]) {
    for step in steps {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check("the client exited with no failures", *code == Some(0));
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
    let blks: Vec<_> = pci::devices()
        .into_iter()
        .filter(|d| (d.vendor, d.device) == (0x1af4, 0x1042))
        .collect();
    t.check(
        "two virtio-blk disks: read-only, then the store",
        blks.len() == 2,
    );
    let (Some(disk), Ok(programs)) = (blks.get(1).cloned(), fs::mount("programs")) else {
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
    // 32 MiB: the 17 MiB buffer a client attaches, and the store's heap.
    let service = process::spawn_elf_limited(&programs, b"bin/store", 0, caps, 8192);
    t.check("the storage service started", service.is_ok());
    let ready = ipc::poll(&report, Duration::from_secs(10));
    t.check(
        "it mounted the store and reported ready",
        ready.is_some_and(|m| m.bytes() == b"ready"),
    );
    if let Ok(id) = service {
        lines(id);
    }
    let root = Capability::new(Object::Endpoint(endpoint), SEND);

    let writer = client(&programs, &root, 1, 5000, &[1]);
    passed(
        t,
        &writer,
        &[
            "attach a 64 KiB buffer",
            "write a file from the buffer",
            "stat it",
            "read it back into the buffer",
            "a read past the end stops there",
            "replace it",
            "append records; numbers and chain head match",
            "list the namespace",
            "delete; then NOT_FOUND",
            "a path escaping the namespace: BAD_REQUEST",
            "a range outside the buffer: NO_BUFFER",
            "a file as a stream: BAD_REQUEST",
            "attach a 17 MiB buffer",
            "a write larger than the store: NO_SPACE, nothing written",
        ],
    );
    let reader = client(&programs, &root, 2, 64, &[1 | READ_ONLY]);
    passed(
        t,
        &reader,
        &[
            "read-only: reads what the writer left",
            "read-only: write, append, and delete refused",
        ],
    );
    let other = client(&programs, &root, 3, 64, &[2]);
    passed(t, &other, &["another namespace sees nothing of the first"]);
    let strangers = client(&programs, &root, 4, 64, &[0, 99]);
    passed(
        t,
        &strangers,
        &["badge 0 and an unknown namespace: NO_ACCESS"],
    );
    t.check(
        "the service is still running",
        service.is_ok_and(|id| {
            !process::exits().iter().any(|e| e.task == id)
                && !process::kills().iter().any(|k| k.task == id)
        }),
    );
}
