//! Test kernel: the store's crash writer (#77, storage.md part 8). The
//! `store` program checks what the store on the writable disk holds (a
//! counter file and a log stream that must agree), then writes. Under
//! `cargo xtask runner` this kernel is first booted 20 times and killed at
//! random moments while it writes; this run then checks the last kill's
//! result, writes, and checks again. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{CONFIG, Capability, IRQ, MAP, Object, WRITE};
use pharos_kernel::device::DeviceHandle;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

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
        t.check("the store disk and programs are there", false);
        return;
    };
    let Some(device) = DeviceHandle::grant(disk) else {
        t.check("the store disk is granted", false);
        return;
    };
    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Device(device), MAP | CONFIG | IRQ),
    ];
    let id = process::spawn_elf_limited(&programs, b"bin/store", 1, caps, 4096);
    t.check("the crash writer started", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    for _ in 0..1200 {
        if process::exits().iter().any(|e| e.task == id) {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(task, _)| *task == id)
        .map(|(_, l)| l)
        .collect();
    for l in &lines {
        kprintln!("  {}", core::str::from_utf8(l).unwrap_or("?"));
    }
    let said = |p: &[u8]| lines.iter().any(|l| l.starts_with(p));
    t.check(
        "the store was consistent at the start",
        said(b"store check: ok"),
    );
    t.check(
        "it wrote and was consistent after",
        said(b"store crash: done"),
    );
    t.check(
        "the writer exited with code 0",
        process::exits().iter().any(|e| e.task == id && e.code == 0),
    );
}
