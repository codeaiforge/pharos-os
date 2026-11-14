//! Test kernel: agents exhausting their limits all at once (#120,
//! resources.md). The kernel starts the services and the network service
//! as the `budgets` kernel does, then the runtime with its `budgets` policy
//! table and `agentclient` in mode 7: two `spinner`s spin, `glutton` takes
//! pages and handles until refused, floods requests past its rate (also without a reply capability, which must be held
//! to it too, #209), and goes
//! past its tokens, datagrams, bytes, and files, while `ticker` must be
//! served within 400 ms throughout. The runner types `usage` on the
//! trusted console under that load and `stop all` once a third spinner
//! starts, and checks each answer came within `EXHAUSTION_BOUND` (in
//! xtask). The kernel's own task (trusted class) checks its 20 ms waits
//! end within [`LATE_BOUND`] the whole time, while `memprobe` (services
//! class) maps and unmaps 64 MiB, shares 128 MiB and maps the share, and
//! maps 64 MiB more, each in one call, and is then stopped, and that `stop all` ends the runtime and
//! every agent. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

#[path = "common/agents.rs"]
mod common;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{ipc, kprintln, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

const WAIT: Duration = Duration::from_millis(20);
/// Most the kernel's task may wake late: as in the `classes` kernel, its
/// own extra tick, one slice, and a delayed tick.
const LATE_BOUND: Duration = Duration::from_millis(40);

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
    let Some(mut services) = common::setup(t) else {
        return;
    };
    if !common::start_net(t, &mut services) {
        return;
    }
    let Some(runtime) = common::start_runtime_table(t, &services, 2) else {
        return;
    };
    let (client, steps) = common::client(t, &services, 7);
    // A services-class process mapping and unmapping 64 MiB, sharing 128
    // MiB and mapping the share, and mapping 64 MiB more, each in one call, then stopped while the agents
    // run: none of it may hold the kernel's task past the bound (#120,
    // #122).
    let mapper = process::load_elf(&services.programs, b"bin/memprobe")
        .and_then(|(space, entry)| {
            let budget = process::Budget::kernel(82_100);
            let entry = entry - process::USER_BASE;
            process::start_class(space, entry, 4, Vec::new(), budget, sched::SERVICES)
        })
        .ok();
    t.check("memprobe started to map 64 MiB", mapper.is_some());
    let mut mapped = false;
    let mut passed: Vec<Vec<u8>> = Vec::new();
    let mut late = Duration::ZERO;
    let wait = |late: &mut Duration| {
        let before = time::uptime();
        let m = ipc::poll(&steps, WAIT);
        if m.is_none() {
            *late = (*late).max((time::uptime() - before).saturating_sub(WAIT));
        }
        m
    };
    let start = time::uptime();
    while time::uptime() - start < Duration::from_secs(90) {
        match wait(&mut late) {
            Some(m) if m.bytes() == b"done" => break,
            Some(m) => {
                kprintln!("  {}", core::str::from_utf8(m.bytes()).unwrap_or("?"));
                passed.push(m.bytes().to_vec());
            }
            None => {}
        }
        // Once it holds all three (320 MiB of mappings), it is stopped: its
        // address space is freed under the same measurement.
        let holds = |m| process::by_id(m).is_some_and(|p| p.memory.lock().used >= 5 * 16_384);
        if !mapped && mapper.is_some_and(holds) {
            mapped = true;
            mapper.map(process::stop);
        }
    }
    for step in [
        "a well-behaved agent is served throughout",
        "an agent is held to its pages, handles, rate, tokens, datagrams, bytes, and files",
        "the spinning agents still run",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    // The runner types `stop all` once the third spinner registers.
    let start = time::uptime();
    let mut agents = 0;
    while time::uptime() - start < Duration::from_secs(30) {
        agents = agents.max(process::descendants(runtime));
        if process::by_id(runtime).is_none() && process::descendants(runtime) == 0 {
            break;
        }
        wait(&mut late);
    }
    t.check(
        "stop all ended the runtime and its agents",
        agents >= 2 && process::by_id(runtime).is_none() && process::descendants(runtime) == 0,
    );
    kprintln!(
        "  the kernel's task was at most {} us late",
        late.as_micros()
    );
    t.check(
        "the kernel's trusted task waited at most 40 ms past each 20 ms wait",
        late <= LATE_BOUND,
    );
    t.check(
        "memprobe mapped, unmapped, shared, and mapped the share, and was stopped",
        mapped && mapper.is_some_and(|m| process::by_id(m).is_none()),
    );
    t.check(
        "the client exited with no failed step",
        process::exits()
            .into_iter()
            .any(|e| e.task == client && e.code == 0),
    );
    // #209: of 12 `LOG`s without a reply capability past its rate, one is
    // held and served, and one more if a request was due meanwhile.
    let flood = process::debug_output()
        .iter()
        .filter(|(id, l)| *id == runtime && l == b"agents: glutton: flood")
        .count();
    t.check(
        "requests without a reply capability are held to the rate too",
        (1..=2).contains(&flood),
    );
    for (_, line) in process::debug_output()
        .into_iter()
        .filter(|(id, _)| *id == runtime)
    {
        kprintln!("  runtime: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
    // Let the runner read `stopped all` before QEMU exits.
    sched::sleep(Duration::from_millis(500));
}
