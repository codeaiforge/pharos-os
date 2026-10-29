//! Shared body of the `vector_state` and `vector_state_avx` test kernels
//! (issue #74, D-016): user programs keep their x87/SSE (and AVX) registers
//! across preemption, a new process never sees another process's values,
//! and floating-point results match the host's.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, fpu, gdt, idt};
use pharos_kernel::cap::{Capability, Object, WRITE};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, process, sched, storage, time};

const STEPS: [&str; 6] = [
    "worker 1: registers survived 10 rounds of preemption",
    "worker 2: registers survived 10 rounds of preemption",
    "worker 1: floating-point checksum matches the host",
    "worker 2: floating-point checksum matches the host",
    "fresh process: no register holds another process's values",
    "fresh process: MXCSR is clean (0x1F80)",
];

/// Waits until `id` has exited or been killed, at most `limit`.
fn wait_end(id: TaskId, limit: Duration) {
    let mut waited = Duration::ZERO;
    while waited < limit {
        let ended = process::exits().iter().any(|e| e.task == id)
            || process::kills().iter().any(|k| k.task == id);
        if ended {
            return;
        }
        sched::sleep(Duration::from_millis(50));
        waited += Duration::from_millis(50);
    }
}

pub fn run(t: &mut TestRun, expect: fpu::Mode) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        crate::requests::HHDM.response(),
        crate::requests::MEMMAP.response(),
        crate::requests::EXECUTABLE_ADDRESS.response(),
    );
    let Some(hhdm) = crate::requests::HHDM.response() else {
        return;
    };
    if memory {
        storage::record_modules(crate::requests::MODULES.response(), hhdm.offset);
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
    t.check(
        &format!("vector state is saved with {expect:?}"),
        fpu::mode() == expect,
    );
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    let console = || vec![Capability::new(Object::DebugConsole, WRITE)];
    let spawn = |arg| process::spawn_elf(&programs, b"bin/vecprobe", arg, console()).ok();

    // Two workers at once, so each is preempted while the other runs.
    let workers = [spawn(1), spawn(2)];
    t.check("two workers started", workers.iter().all(Option::is_some));
    for id in workers.iter().flatten() {
        wait_end(*id, Duration::from_secs(120));
    }
    // The crasher holds a marker in its registers while it spins; the fresh
    // process starts meanwhile, so it is switched in from the crasher.
    let crasher = spawn(3);
    sched::sleep(Duration::from_millis(30));
    let fresh = spawn(4);
    for id in [crasher, fresh].iter().flatten() {
        wait_end(*id, Duration::from_secs(30));
    }

    let lines: Vec<Vec<u8>> = process::debug_output()
        .into_iter()
        .map(|(_, l)| l)
        .collect();
    for line in &lines {
        kprintln!("  {}", core::str::from_utf8(line).unwrap_or("?"));
    }
    for step in STEPS {
        let want = format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check(
        "no probe reported a failure",
        !lines.iter().any(|l| l.starts_with(b"FAIL")),
    );
    let avx_line: &[u8] = if expect == fpu::Mode::XsaveAvx {
        b"avx: yes"
    } else {
        b"avx: no"
    };
    let avx_lines: Vec<_> = lines.iter().filter(|l| l.starts_with(b"avx: ")).collect();
    t.check(
        &format!(
            "every probe sees {}",
            core::str::from_utf8(avx_line).unwrap_or("?")
        ),
        avx_lines.len() == 4 && avx_lines.iter().all(|l| l.as_slice() == avx_line),
    );
    let exited_ok = |id: Option<TaskId>| {
        id.is_some_and(|id| process::exits().iter().any(|e| e.task == id && e.code == 0))
    };
    t.check(
        "the workers and the fresh process exited with no failures",
        exited_ok(workers[0]) && exited_ok(workers[1]) && exited_ok(fresh),
    );
    t.check(
        "the crashing process was killed with #UD",
        crasher.is_some_and(|id| {
            process::kills()
                .iter()
                .any(|k| k.task == id && k.vector == 6)
        }),
    );
}
