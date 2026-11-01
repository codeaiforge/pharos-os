//! Test kernel: stopping processes (#95, agents.md). The `stopper` program
//! starts `child` in each stop mode: looping, waiting in `receive`, in
//! `send`, sleeping, holding memory, with a child of its own, a server in
//! a call, a parent that exits, and a handle without `STOP`. Each ends as
//! stopped (or as expected), and afterwards no process, frame, or endpoint
//! entry is left. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt, without_interrupts};
use pharos_kernel::cap::{Capability, GRANT, Object, READ, WRITE};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Steps `stopper` must report as passed.
const STEPS: [&str; 13] = [
    "a looping process: stopped, and its end notified",
    "stopping it again: OK",
    "a process waiting in receive: stopped, and no longer queued",
    "a process waiting in send: stopped, and its message withdrawn",
    "a sleeping process: stopped",
    "a process holding 1 MiB: stopped",
    "a process with a looping child: stopped",
    "a server stopped during a call: its client gets TIMED_OUT",
    "a process that starts a child and exits: exited",
    "a handle without STOP: MISSING_RIGHT",
    "the target then stops",
    "process_stop on a console: MISSING_RIGHT",
    "stopper exited",
];

/// What a task told to stop saw from `block_until` and `sleep`: 0 not
/// yet, 1 both returned at once, 2 the wait reported a wake-up.
static NO_WAIT: AtomicU8 = AtomicU8::new(0);

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
    // Touch the stack window's slots first, so the frame count below sees
    // only what processes use (as in the `spawn` test).
    for _ in 0..20 {
        let _ = sched::spawn(|| sched::sleep(Duration::from_millis(30)));
    }
    sched::sleep(Duration::from_millis(100));
    // A task told to stop never waits again (the window between a
    // wake-up inside a system call and its next wait). Interrupts stay
    // off, so no tick ends it first.
    let _ = sched::spawn(|| {
        let woken = without_interrupts(|| {
            sched::current_id().map(sched::stop);
            let woken = sched::block_until(None);
            sched::sleep(Duration::from_secs(3600));
            woken
        });
        NO_WAIT.store(if woken { 2 } else { 1 }, Ordering::Relaxed);
    });
    sched::sleep(Duration::from_millis(100));
    t.check(
        "a task told to stop returns from its waits at once",
        NO_WAIT.load(Ordering::Relaxed) == 1,
    );
    let before = free_frames();
    let live = process::count();

    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE | GRANT),
        Capability::new(Object::Filesystem(programs.clone()), READ | GRANT),
    ];
    let id = process::spawn_elf_limited(&programs, b"bin/stopper", 0, caps, 1024);
    t.check("stopper started", id.is_ok());
    let id = id.unwrap_or(u64::MAX);
    let mut code = None;
    for _ in 0..200 {
        sched::sleep(Duration::from_millis(50));
        if let Some(e) = process::exits().iter().find(|e| e.task == id) {
            code = Some(e.code);
            break;
        }
    }
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, line)| line)
        .collect();
    for line in &lines {
        kprintln!("  stopper: {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in &STEPS[..STEPS.len() - 1] {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check("stopper exited", code.is_some());
    t.check("stopper exited with no failures", code == Some(0));
    // Children and grandchildren of processes that ended are stopped too.
    sched::sleep(Duration::from_millis(200));
    t.check(
        "every process ended, grandchildren included",
        process::count() == live,
    );
    t.check("every frame returned", free_frames() == before);
}
