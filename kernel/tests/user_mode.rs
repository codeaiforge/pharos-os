//! Test kernel: user processes run in ring 3, are preempted, and are killed
//! (with the kernel continuing) when they touch kernel memory, another
//! process's memory, or privileged instructions (issue #39). Runs under
//! UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use core::time::Duration;

use pharos_kernel::arch::x86_64::context::{MAX_STACKS, SLOT_SIZE, STACK_WINDOW};
use pharos_kernel::arch::x86_64::paging::{self, Flags};
use pharos_kernel::arch::x86_64::user_programs::TestProgram;
use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::process::{self, Kill};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm, sched, time};

pharos_kernel::test_kernel!(run);

/// A page only the spinning process maps; the spinner counts there.
const COUNTER_PAGE: u64 = 0x5000_0000;

/// Kernel data a user process tries to read and write.
static KERNEL_SECRET: u64 = 0x5ec2e7;

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// Page-fault error code bits.
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const FETCH: u64 = 16;

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
    let (smep, smap) = paging::smep_smap_enabled();
    kprintln!("SMEP {smep}, SMAP {smap}");

    // A process that counts forever in ring 3 on a page of its own.
    let spinner = process::load(TestProgram::Spin.bytes()).and_then(|mut space| {
        let counter = mm::frames()
            .as_mut()
            .and_then(|frames| {
                space
                    .map_new_page(COUNTER_PAGE, Flags::USER_DATA, &[], frames)
                    .ok()
            })
            .ok_or(process::ProcessError::NoFrameAllocator)?;
        process::start(space, 0, COUNTER_PAGE, Vec::new()).map(|id| (id, counter))
    });
    t.check("spinning process started", spinner.is_ok());
    let Ok((spinner_id, counter)) = spinner else {
        return;
    };
    let count = || paging::read_phys_u64(counter).unwrap_or(0);
    sched::sleep(Duration::from_millis(100));
    let first = count();
    sched::sleep(Duration::from_millis(100));
    let second = count();
    kprintln!("spinner counted {first}, then {second}");
    t.check(
        "the process runs in ring 3 and is preempted: it counts while task 0 sleeps and wakes",
        first > 0 && second > first,
    );
    t.check(
        "the TSS ring-0 stack is a task stack top while processes run",
        (STACK_WINDOW + 1..=STACK_WINDOW + MAX_STACKS * SLOT_SIZE).contains(&gdt::kernel_stack())
            && gdt::kernel_stack() % SLOT_SIZE == 0,
    );

    // Each of these processes tries something forbidden and is killed.
    let secret = &raw const KERNEL_SECRET as u64;
    let kernel_code = run as *const () as u64;
    let attempts = [
        (TestProgram::Read, secret, "reads kernel data"),
        (TestProgram::Write, secret, "writes kernel data"),
        (TestProgram::Jump, kernel_code, "jumps into kernel code"),
        (
            TestProgram::Read,
            COUNTER_PAGE,
            "reads another process's page",
        ),
        (TestProgram::Cli, 0, "executes cli"),
        (TestProgram::Hlt, 0, "executes hlt"),
        (TestProgram::WriteCr3, 0, "writes CR3"),
    ];
    let before = free_frames();
    let mut ids = [0; 7];
    let mut started = true;
    for (slot, (program, arg, _)) in ids.iter_mut().zip(attempts) {
        match process::spawn(program.bytes(), 0, arg, Vec::new()) {
            Ok(id) => *slot = id,
            Err(_) => started = false,
        }
    }
    t.check("seven misbehaving processes started", started);
    sched::sleep(Duration::from_millis(100));

    let kills = process::kills();
    let killed = |id: u64| kills.iter().find(|k| k.task == id).copied();
    let page_fault = |k: Option<Kill>, error: u64, cr2: u64| {
        k.is_some_and(|k| k.vector == 14 && k.error_code == error && k.cr2 == cr2)
    };
    let protection = |k: Option<Kill>| k.is_some_and(|k| k.vector == 13 && k.error_code == 0);
    t.check(
        "reading kernel data: page fault, user read of a present page",
        page_fault(killed(ids[0]), PRESENT | USER, secret),
    );
    t.check(
        "writing kernel data: page fault, user write of a present page",
        page_fault(killed(ids[1]), PRESENT | WRITE | USER, secret),
    );
    t.check(
        "jumping into kernel code: page fault, user instruction fetch",
        page_fault(killed(ids[2]), PRESENT | USER | FETCH, kernel_code),
    );
    t.check(
        "reading another process's page: page fault, not present",
        page_fault(killed(ids[3]), USER, COUNTER_PAGE),
    );
    t.check(
        "cli, hlt, and mov cr3: general-protection faults",
        protection(killed(ids[4])) && protection(killed(ids[5])) && protection(killed(ids[6])),
    );
    t.check(
        "all seven killed in ring 3, the spinner and task 0 alive",
        kills.len() == 7 && kills.iter().all(|k| k.cs & 3 == 3) && sched::live_tasks() == 2,
    );
    t.check("the spinner never faulted", killed(spinner_id).is_none());
    t.check(
        "killed processes returned every frame",
        free_frames() == before,
    );
    let after_kills = count();
    sched::sleep(Duration::from_millis(50));
    t.check(
        "the spinner keeps running after the kills",
        count() > after_kills,
    );
}
