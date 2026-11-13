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

use pharos_kernel::arch::x86_64::user_programs::TestProgram;
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
const STEPS: [&str; 24] = [
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
    "12 capabilities: the child runs",
    "13 capabilities: TOO_LARGE",
    "malformed programs: BAD_PROGRAM",
    "a child in the agents class: a higher class is TOO_LARGE",
    "process_usage: CPU time and pages while running, CPU time kept once stopped",
    "process_usage: a child whose child started a child has two descendants",
    "a child given 2 descendants starts 2, then TOO_LARGE",
    "a child given 8 handles holds 8, then NO_MEMORY",
    "more descendants or handles than this process has: TOO_LARGE",
    "a child given fewer handles than its capabilities: TOO_LARGE",
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
    // 256 pages for its child that maps 1 MiB (#114).
    let id = process::spawn_elf_limited(&programs, b"bin/spawner", 0, caps, 256);
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

    failed_starts_free_their_space(t);
}

/// #205: a process that cannot start gives back its address space: its
/// page tables and loaded pages.
fn failed_starts_free_their_space(t: &mut TestRun) {
    let program = TestProgram::SyscallTable.bytes();
    let before = free_frames();
    let bad_entry = process::load(program)
        .is_ok_and(|space| process::start(space, 0x7000_0000, 0, Vec::new()).is_err());
    t.check(
        "a bad entry point: refused, and every frame returned",
        bad_entry && free_frames() == before,
    );

    // No frame left for the kernel stack: the test holds every free one.
    let no_stack = process::load(program).is_ok_and(|space| {
        let held: Vec<_> = {
            let mut frames = mm::frames();
            let Some(frames) = frames.as_mut() else {
                return false;
            };
            core::iter::from_fn(|| frames.alloc().ok()).collect()
        };
        let refused = process::start(space, 0, 0, Vec::new()).is_err();
        if let Some(frames) = mm::frames().as_mut() {
            for frame in held {
                let _ = frames.free(frame);
            }
        }
        refused
    });
    t.check(
        "no frame for its kernel stack: refused, and every frame returned",
        no_stack && free_frames() == before,
    );
}
