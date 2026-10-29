//! Test kernel: a process starts processes (issue #60, services.md). The
//! `spawner` program starts `child` with two capabilities (one badged),
//! gets its message with the badge, its end as a notification bit, and its
//! exit code; a crashing child is reported killed. Every refusal returns
//! its error, the process limit holds, and no frame is lost. Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, GRANT, Object, READ, SEND, WRITE};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::syscall::MAX_PROCESSES;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Steps `spawner` must report as passed.
const STEPS: [&str; 16] = [
    "endpoint_create and open bin/child",
    "spawn a child with two capabilities",
    "the child's message carries badge 7",
    "its end arrives as notification bit 3",
    "process_status: exited with 42",
    "a crashing child is reported killed by a page fault",
    "call: the server's answer arrives",
    "call: a second answer on the reply capability is REVOKED",
    "file without READ: MISSING_RIGHT",
    "capability without GRANT: MISSING_RIGHT",
    "notify endpoint without RECEIVE: MISSING_RIGHT",
    "send with a 25-bit badge: TOO_LARGE",
    "9 capabilities: TOO_LARGE",
    "malformed programs: BAD_PROGRAM",
    "the process limit: NO_MEMORY",
    "released the waiting children",
];

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
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    let Ok(child) = programs.lookup(b"bin/child") else {
        t.check("bin/child in the programs image", false);
        return;
    };
    // The limit test runs 33 processes at once, so stacks reach past the
    // first 2 MiB of the stack window, whose second page table the kernel
    // then keeps. Touch those slots first, so the frame count below sees
    // only what processes use.
    for _ in 0..40 {
        let _ = sched::spawn(|| sched::sleep(Duration::from_millis(30)));
    }
    sched::sleep(Duration::from_millis(100));
    let before = free_frames();
    let live = process::count();

    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE | GRANT),
        Capability::new(Object::Filesystem(programs.clone()), READ | GRANT),
        Capability::new(
            Object::File {
                fs: programs.clone(),
                file: child,
            },
            GRANT,
        ),
        Capability::new(Object::Endpoint(Endpoint::new()), SEND),
    ];
    let id = process::spawn_elf(&programs, b"bin/spawner", 0, caps);
    t.check("spawner started", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    for _ in 0..60 {
        sched::sleep(Duration::from_millis(50));
        if process::exits().iter().any(|e| e.task == id) {
            break;
        }
    }
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, line)| line)
        .collect();
    for line in &lines {
        kprintln!("  spawner: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in STEPS {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    let want = alloc::format!("limit {:02}", MAX_PROCESSES - live - 1);
    t.check(
        "children started up to the limit of 32 live processes",
        lines.iter().any(|l| l == want.as_bytes()),
    );
    t.check(
        "the child printed through the console it was given",
        process::debug_output()
            .iter()
            .any(|(_, l)| l == b"child: hello"),
    );
    t.check(
        "spawner exited with no failures",
        process::exits().iter().any(|e| e.task == id && e.code == 0),
    );
    sched::sleep(Duration::from_millis(100));
    t.check("every process ended", process::count() == live);
    t.check("every frame returned", free_frames() == before);
}
