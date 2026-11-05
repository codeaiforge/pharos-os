//! Test kernel: the agent runtime (#98, agents.md). `cargo xtask` boots it
//! with the inference test's store (the service's test model, manifest
//! model 2) and the programs image, which holds `agents/worker.manifest`,
//! `agents/greedy.manifest` (asks for more pages than its policy entry),
//! and `agents/noentry.manifest` (no entry). The kernel starts `store`,
//! `infer`, `trust`, and `agents` with the capabilities `init` gives them,
//! registers the runtime with `trust` as `init` does, then runs
//! `agentclient`, which submits `bin/testagent` tasks for each case and
//! reports each passed step. While four agents wait, the kernel checks
//! what each holds. Last, the runtime's events and `trust`'s registrations.
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

#[path = "common/agents.rs"]
mod common;

use common::{Services, caps_of, endpoint};
use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Object, SEND};
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::process;
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm, sched, storage, time};

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
    let Some(services) = common::setup(t) else {
        return;
    };
    let Services {
        runtime_ep,
        report,
        infer,
        trust_ep,
        store,
        trust,
        ..
    } = &services;
    let trust = *trust;
    let Some(mut runtime) = common::start_runtime(t, &services) else {
        return;
    };
    let mut runtimes = vec![runtime];
    let (client, steps) = common::client(t, &services, 0);

    let mut passed: Vec<Vec<u8>> = Vec::new();
    let mut events: Vec<Vec<u8>> = Vec::new();
    let mut checked = None;
    let mut replaced = None;
    let start = time::uptime();
    // Up to 240 s; about 40 s on the reference host.
    while time::uptime() - start < Duration::from_secs(240) {
        for (id, line) in process::debug_output() {
            if runtimes.contains(&id) && !events.contains(&line) {
                events.push(line);
            }
        }
        // The `durable` agent stored its checkpoint and key: replace the
        // runtime while the task runs (#99).
        let ready = events
            .iter()
            .any(|l| l.ends_with(b"agents: worker: ready to stop"));
        if ready && replaced.is_none() {
            replaced = Some(common::replace_runtime(t, &services, runtime));
            if let Some(Some(new)) = replaced {
                runtime = new;
                runtimes.push(new);
            }
        }
        let Some(m) = ipc::poll(&steps, Duration::from_millis(50)) else {
            continue;
        };
        match m.bytes() {
            b"done" => break,
            b"check" => {
                let known = [store, infer, trust_ep, report, &steps];
                checked = Some(check_agents(runtime, runtime_ep, &known));
            }
            step => {
                kprintln!("  {}", core::str::from_utf8(step).unwrap_or("?"));
                passed.push(step.to_vec());
            }
        }
    }
    for (id, line) in process::debug_output() {
        if runtimes.contains(&id) && !events.contains(&line) {
            events.push(line);
        }
    }
    t.check(
        "the runtime was stopped mid-task and a new one started on the same store",
        matches!(replaced, Some(Some(_))),
    );
    for step in [
        "INFO: interface agents, fourteen agents accepted, none running",
        "agents with a refused, missing, or unlisted manifest are not found",
        "agent requests from a control client are refused",
        "an unknown task is not found",
        "a task completes on its first attempt",
        "a crashed agent is restarted and completes",
        "an agent that always crashes fails after 3 attempts",
        "an agent that exits without a result fails after 3 attempts",
        "a hung agent is stopped and fails after 3 attempts",
        "an agent's FAIL ends its task with its reason",
        "inference through the runtime, only from the manifest's models",
        "an agent's control requests are refused",
        "at most four agents run at once",
        "cancelling running and pending tasks stops their agents",
        "idempotency keys answer GO, UNKNOWN, and DONE",
        "a checkpoint comes back to the next attempt",
        "an unknown dependency is refused",
        "a task runs once its dependency is done",
        "a task waits for its dependency",
        "FORGET refuses a task that has not ended",
        "a task whose dependency was cancelled fails",
        "FORGET deletes an ended task's record",
        "a task outlives the runtime: its checkpoint comes back and its operation is DONE",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, passed.iter().any(|l| l == want.as_bytes()));
    }
    // It exits just after its `done`.
    let mut exit = None;
    for _ in 0..40 {
        exit = process::exits().into_iter().find(|e| e.task == client);
        if exit.is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(50));
    }
    t.check(
        "the client exited with no failed step",
        exit.is_some_and(|e| e.code == 0),
    );
    t.check(
        "each running agent held only its runtime endpoint and its own endpoints, in the agents class",
        checked == Some(true),
    );

    let has = |text: &str| {
        events
            .iter()
            .any(|l| l.windows(text.len()).any(|w| w == text.as_bytes()))
    };
    for (what, text) in [
        ("an accepted manifest", "agents: worker manifest accepted"),
        (
            "a manifest over its policy entry refused",
            "agents: greedy manifest refused: asks for more than its policy entry",
        ),
        (
            "a missing manifest refused",
            "agents: absent manifest refused: no manifest",
        ),
        ("a start", " started"),
        ("a completion", " completed"),
        ("a crash with its vector", " crashed 14"),
        ("an exit with its code", " exited 3"),
        ("a hang", " hung"),
        ("a restart", " restarting 2/3"),
        ("a failure", " failed"),
        ("a cancellation", " cancelled"),
        ("an agent's log line", "agents: worker: working"),
        (
            "a recovered running task",
            " tasks recovered, 1 were running, 0 unreadable",
        ),
    ] {
        t.check(&alloc::format!("the runtime reported {what}"), has(text));
    }
    for e in &events {
        kprintln!("  runtime: {}", core::str::from_utf8(e).unwrap_or("?"));
    }
    // The runtime, then every agent, registered with `trust`.
    let processes = caps_of(trust)
        .iter()
        .filter(|c| matches!(c.object(), Object::Process(_)))
        .count();
    t.check(
        "trust holds the runtime and the agents' process capabilities",
        processes >= 2,
    );
    t.check(
        "the runtime still runs",
        process::by_id(runtime).is_some_and(|p| p.record.end().is_none()),
    );
}

/// Every process the runtime started holds `SEND` on the runtime with an
/// agent badge (1 to 16), and otherwise only endpoints it made itself
/// (none of `services`), and nothing but endpoints; each runs in the
/// agents class (D-022).
fn check_agents(runtime: TaskId, runtime_ep: &Arc<Endpoint>, services: &[&Arc<Endpoint>]) -> bool {
    let agents: Vec<TaskId> = (runtime + 1..runtime + 200)
        .filter(|&id| process::by_id(id).is_some_and(|p| p.parent == Some(runtime)))
        .collect();
    kprintln!("  checking {} running agents", agents.len());
    agents.len() == 4
        && agents.iter().all(|&id| {
            let caps = caps_of(id);
            let to_runtime: Vec<_> = caps
                .iter()
                .filter(|c| endpoint(c).is_some_and(|e| Arc::ptr_eq(e, runtime_ep)))
                .collect();
            let only_own = caps.iter().all(|c| match endpoint(c) {
                Some(e) => !services.iter().any(|s| Arc::ptr_eq(e, s)),
                None => false,
            });
            to_runtime.len() == 1
                && sched::class_of(id) == Some(sched::AGENTS)
                && to_runtime[0].rights() == SEND
                && (1..=16).contains(&to_runtime[0].badge())
                && only_own
        })
}
