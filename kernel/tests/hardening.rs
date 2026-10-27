//! Test kernel: regressions for the M2.7 security review (#42). User flags
//! (DF, AC) do not leak into the kernel; the x87 FPU, port I/O, and
//! software interrupts are refused in user mode; process-driven kernel logs
//! stay bounded.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::paging::{self, Flags};
use pharos_kernel::arch::x86_64::user_programs::TestProgram;
use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{self, Capability, Object};
use pharos_kernel::process::{self, Kill, LOG_ENTRIES};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm, sched, time};

pharos_kernel::test_kernel!(run);

const COUNTER_PAGE: u64 = 0x5000_0000;
const WRITES: u64 = 300;

/// General-protection error code for an IDT gate: index << 3, IDT bit 1.
const fn idt_error(vector: u64) -> u64 {
    vector << 3 | 2
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    let ready = memory
        && mm::init_heap().is_ok()
        && requests::HHDM
            .response()
            .is_some_and(|hhdm| apic::init(hhdm.offset).is_ok())
        && time::init().is_ok()
        && sched::init().is_ok();
    t.check("memory, heap, APIC, clock, and scheduler set up", ready);
    if !ready {
        return;
    }
    process::init();
    t.check("preemption enabled", sched::enable_preemption().is_ok());

    // F1: a process with DF and AC set is interrupted by ticks. The kernel
    // asserts (debug builds) that both are clear in every handler; the
    // program checks they are set again when it resumes.
    let flags = process::load(TestProgram::FlagsSpin.bytes()).and_then(|mut space| {
        let counter = mm::frames()
            .as_mut()
            .and_then(|f| {
                space
                    .map_new_page(COUNTER_PAGE, Flags::USER_DATA, &[], f)
                    .ok()
            })
            .ok_or(process::ProcessError::NoFrameAllocator)?;
        process::start(space, 0, COUNTER_PAGE, Vec::new()).map(|id| (id, counter))
    });
    t.check("flag-setting process started", flags.is_ok());
    let Ok((flags_id, counter)) = flags else {
        return;
    };
    let count = || paging::read_phys_u64(counter).unwrap_or(0);
    sched::sleep(Duration::from_millis(100));
    let first = count();
    sched::sleep(Duration::from_millis(100));
    t.check(
        "with DF and AC set in user mode, ticks keep arriving and both flags come back",
        first > 0 && count() > first && process::kills().is_empty(),
    );

    // The x87 FPU (F3: its state is not saved per process), port I/O, and
    // software interrupts from user mode.
    let attempts = [
        (
            TestProgram::X87,
            7,
            0,
            "x87 instruction: device not available (#NM)",
        ),
        (TestProgram::PortOut, 13, 0, "out to QEMU's exit port: #GP"),
        (
            TestProgram::Int3,
            13,
            idt_error(3),
            "int3: #GP on the kernel-only gate",
        ),
        (
            TestProgram::Int80,
            13,
            idt_error(0x80),
            "int 0x80: #GP on the kernel-only gate",
        ),
    ];
    let ids: Vec<_> = attempts
        .iter()
        .map(|(program, _, _, _)| process::spawn(program.bytes(), 0, 0, Vec::new()).ok())
        .collect();
    sched::sleep(Duration::from_millis(50));
    let kills = process::kills();
    for ((program, vector, error, what), id) in attempts.iter().zip(&ids) {
        let code = process::USER_BASE..process::USER_BASE + program.bytes().len() as u64;
        let kill: Option<Kill> = id.and_then(|id| kills.iter().find(|k| k.task == id).copied());
        t.check(
            what,
            kill.is_some_and(|k| {
                k.vector == *vector
                    && k.error_code == *error
                    && code.contains(&k.rip)
                    && k.cs & 3 == 3
            }),
        );
    }

    // F2: a process floods the debug console; the kernel keeps only the
    // newest entries instead of filling its heap.
    let heap_before = mm::heap_stats().used;
    let writer = process::spawn(
        TestProgram::WriteLoop.bytes(),
        0,
        WRITES,
        vec![Capability::new(Object::DebugConsole, cap::WRITE)],
    );
    for _ in 0..500 {
        if writer
            .as_ref()
            .is_ok_and(|id| process::exits().iter().any(|e| e.task == *id))
        {
            break;
        }
        sched::sleep(Duration::from_millis(10));
    }
    sched::sleep(Duration::from_millis(20)); // reap
    let growth = mm::heap_stats().used.saturating_sub(heap_before);
    kprintln!("heap growth after {WRITES} debug writes: {growth} bytes");
    t.check(
        "the writer finished 300 writes of 256 bytes",
        writer.is_ok_and(|id| process::exits().iter().any(|e| e.task == id && e.code == 0)),
    );
    t.check(
        "the debug log keeps only the newest 64 entries",
        process::debug_output().len() == LOG_ENTRIES,
    );
    t.check(
        "kernel heap growth stays under 48 KiB (unbounded would exceed 75 KiB)",
        growth < 48 * 1024,
    );
    t.check(
        "the flag-setting process is still running",
        process::kills().iter().all(|k| k.task != flags_id),
    );
}
