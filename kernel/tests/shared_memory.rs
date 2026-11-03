//! Test kernel: shared memory (issue #80, user-environment.md). Two
//! `shmprobe` processes share a buffer twice: once the sharer ends first,
//! once the receiver does. Writes are seen both ways; a read-only grant
//! cannot be mapped writable, and writing its mapping is a page fault; the
//! receiver's limit applies; revocation stops new mappings and turns
//! existing ones into zeroed private pages with the same access (#104);
//! the object lives while either side maps it, and every frame returns.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, Object, RECEIVE, SEND, WRITE};
use pharos_kernel::fs::Fs;
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

fn ended(id: TaskId) -> bool {
    process::exits().iter().any(|e| e.task == id) || process::kills().iter().any(|k| k.task == id)
}

/// Waits up to 20 s for `id` to end.
fn wait_end(id: TaskId) {
    for _ in 0..400 {
        if ended(id) {
            return;
        }
        sched::sleep(Duration::from_millis(50));
    }
}

/// Starts A (`a_arg`, 2-page limit) and B (`a_arg + 1`, 4 pages) wired
/// together; returns their IDs.
fn start(programs: &Fs, a_arg: u64) -> Option<(TaskId, TaskId)> {
    let (to_b, to_a) = (Endpoint::new(), Endpoint::new());
    let cap = |e: &Arc<Endpoint>, rights| Capability::new(Object::Endpoint(e.clone()), rights);
    let console = || Capability::new(Object::DebugConsole, WRITE);
    let a = vec![console(), cap(&to_b, SEND), cap(&to_a, RECEIVE)];
    let b = vec![console(), cap(&to_b, RECEIVE), cap(&to_a, SEND)];
    let a = process::spawn_elf_limited(programs, b"bin/shmprobe", a_arg, a, 2).ok()?;
    let b = process::spawn_elf_limited(programs, b"bin/shmprobe", a_arg + 1, b, 4).ok()?;
    Some((a, b))
}

/// The `ok`/`FAIL` lines `id` printed.
fn lines(id: TaskId) -> Vec<Vec<u8>> {
    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == id)
        .map(|(_, l)| l)
        .collect();
    for l in &lines {
        kprintln!("  {}", core::str::from_utf8(l).unwrap_or("?"));
    }
    lines
}

fn passed(t: &mut TestRun, lines: &[Vec<u8>], steps: &[&str]) {
    for step in steps {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "no step failed",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
}

const B_STEPS: [&str; 7] = [
    "B: map the writable grant",
    "B: sees A's write",
    "B: a read-only grant cannot be mapped writable",
    "B: a wrong length is refused",
    "B: a received mapping cannot be shared again",
    "B: map the read-only grant",
    "B: the receiver's limit applies",
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
    for _ in 0..8 {
        let _ = sched::spawn(|| sched::sleep(Duration::from_millis(30)));
    }
    sched::sleep(Duration::from_millis(100));
    let before = free_frames();

    // Run 1: A revokes, unmaps, and exits while B still maps the buffer.
    let Some((a, b)) = start(&programs, 1) else {
        t.check("run 1: both processes started", false);
        return;
    };
    wait_end(a);
    t.check(
        "run 1: A exited with no failures",
        process::exits().iter().any(|e| e.task == a && e.code == 0),
    );
    // Wait until B has deleted its revoked grants.
    for _ in 0..200 {
        let dropped = process::debug_output()
            .iter()
            .any(|(t, l)| *t == b && l == b"ok B: dropped its grants");
        if dropped || ended(b) {
            break;
        }
        sched::sleep(Duration::from_millis(10));
    }
    t.check(
        "run 1: with A gone and B's grants deleted, B's revoked mappings do not keep the object",
        !ended(b) && process::shared_objects() == 0,
    );
    wait_end(b);
    passed(
        t,
        &lines(a),
        &[
            "A: share the buffer",
            "A: send a writable and a read-only grant",
            "A: B is done",
            "A: sees B's write",
            "A: revoke both grants",
            "A: unmap while B still maps it",
        ],
    );
    let b_lines = lines(b);
    passed(t, &b_lines, &B_STEPS);
    passed(
        t,
        &b_lines,
        &[
            "B: A revoked and unmapped",
            "B: revoked grants map nothing new",
            "B: dropped its grants",
            "B: revoked, its mappings read zeros",
            "B: its writes stay in its own pages",
        ],
    );
    let region = process::MAP_REGION;
    t.check(
        "run 1: B's write to its read-only mapping is a page fault there",
        process::kills()
            .iter()
            .any(|k| k.task == b && k.vector == 14 && region.contains(&k.cr2)),
    );
    sched::sleep(Duration::from_millis(100));
    t.check("run 1: the object is gone", process::shared_objects() == 0);
    t.check("run 1: every frame returned", free_frames() == before);

    // Run 2: B exits first; A still maps the buffer.
    let Some((a, b)) = start(&programs, 3) else {
        t.check("run 2: both processes started", false);
        return;
    };
    wait_end(b);
    t.check(
        "run 2: B exited with no failures",
        process::exits().iter().any(|e| e.task == b && e.code == 0),
    );
    t.check(
        "run 2: after B ended, A's mapping keeps the object alive",
        !ended(a) && process::shared_objects() == 1,
    );
    wait_end(a);
    passed(t, &lines(b), &B_STEPS);
    passed(
        t,
        &lines(a),
        &["A: sees B's write", "A: buffer intact after B ended"],
    );
    t.check(
        "run 2: A exited with no failures",
        process::exits().iter().any(|e| e.task == a && e.code == 0),
    );
    sched::sleep(Duration::from_millis(100));
    t.check("run 2: the object is gone", process::shared_objects() == 0);
    t.check("run 2: every frame returned", free_frames() == before);
    t.check(
        "no shared frame was freed twice",
        process::shared_free_errors() == 0,
    );
}
