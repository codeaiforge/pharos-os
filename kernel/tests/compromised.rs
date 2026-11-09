//! Test kernel: compromised AI services stay inside their manifests (M4.6,
//! D-031, #183, services.md "AI services"). `cargo xtask runner` boots it
//! with the boot image's modules and disks; the kernel starts `init` with
//! the `compromised` table (argument 6): the boot table with `infer`
//! replaced by `rogue` 1 and the agent runtime by `rogue` 2, each holding
//! exactly the shipped service's manifest. Each tries every handle,
//! kernel addresses, memory past its limit, and forged requests to
//! `init`, the store, and `trust`, and prints its tally. Checked: every
//! attempt refused; `init` started, stopped, or restarted nothing for
//! them; every service ready; and the capability audit matches the
//! manifests. The runner types `services` and checks the trusted console
//! never showed the forged registration. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

#[path = "common/manifests.rs"]
mod manifests;

use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::ipc::{self, Endpoint};
use pharos_kernel::sched::TaskId;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, pci, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn lines() -> Vec<(TaskId, Vec<u8>)> {
    process::debug_output()
}

fn any(f: impl Fn(&[u8]) -> bool) -> bool {
    lines().iter().any(|(_, l)| f(l))
}

/// Waits up to `secs` for `done`.
fn wait(secs: u64, done: impl Fn() -> bool) -> bool {
    let start = time::uptime();
    while !done() && time::uptime() - start < Duration::from_secs(secs) {
        sched::sleep(Duration::from_millis(50));
    }
    done()
}

/// `rogue`'s tally as `name`: its refused count if none was allowed.
fn tally(name: &str) -> Option<u64> {
    let prefix = alloc::format!("rogue: as {name}: ");
    lines().iter().find_map(|(_, l)| {
        let rest = core::str::from_utf8(l.strip_prefix(prefix.as_bytes())?).ok()?;
        rest.strip_suffix(" refused, 0 allowed")?.parse().ok()
    })
}

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
    let Ok(root) = fs::mount("root") else {
        t.check("the boot image's root filesystem is found", false);
        return;
    };
    let report = Endpoint::new();
    let caps = process::init_capabilities(root.clone(), report.clone(), true);
    let init = process::spawn_elf_limited(&root, b"bin/init", 6, caps, process::INIT_MEMORY_LIMIT);
    t.check("init started with the compromised table", init.is_ok());
    let Ok(init) = init else {
        return;
    };
    let summary = ipc::poll(&report, Duration::from_secs(30)).map(|m| m.bytes().to_vec());
    let boot = (pharos_services::BOOT.iter())
        .filter(|s| s.driver().is_none())
        .count();
    t.check(
        "every service ready: [8, 0]",
        summary
            .as_deref()
            .is_some_and(|s| s.len() == 4 && usize::from(s[0]) == boot && s[1] == 0),
    );
    let done = wait(30, || tally("infer").is_some() && tally("agents").is_some());
    let (a, b) = (tally("infer"), tally("agents"));
    kprintln!("  refused: as infer {a:?}, as the runtime {b:?}");
    // As `infer`: 59 empty handles, 8 on its 4, its endpoint, 3 store
    // requests, 4 memory, 8 to `init`. As the runtime: 55 empty, 15 on
    // its 8, 5 memory, 2 store, a spawn, 8 to `init`.
    t.check("as infer: all 83 attempts refused", a == Some(83));
    t.check("as the runtime: all 86 attempts refused", b == Some(86));
    t.check(
        "no attempt allowed",
        done && !any(|l| l.starts_with(b"rogue: ALLOWED")),
    );

    // The audit once the probes are over, so nothing they held briefly
    // counts.
    match manifests::Audit::new(init, &report, pharos_services::COMPROMISED) {
        Ok(audit) => {
            let (findings, lines) = audit.check();
            for line in lines.iter().chain(&findings) {
                kprintln!("  audit: {line}");
            }
            t.check(
                "every service holds exactly its manifest and declared gains",
                findings.is_empty(),
            );
        }
        Err(why) => {
            kprintln!("  audit: {why}");
            t.check("the audit learned init's endpoints", false);
        }
    }

    // The runner types `services`; the forged requests changed nothing.
    t.check(
        "init answered trust's services",
        wait(20, || any(|l| l == b"init: services listed for trust")),
    );
    sched::sleep(Duration::from_millis(500));
    t.check(
        "init started, stopped, or restarted nothing for them",
        !any(|l| {
            [
                &b" by the user"[..],
                b" stopped",
                b" restarting",
                b" killed",
            ]
            .iter()
            .any(|w| l.windows(w.len()).any(|x| x == *w))
        }),
    );
    for (task, line) in lines() {
        kprintln!("  {task}: {}", core::str::from_utf8(&line).unwrap_or("?"));
    }
}
