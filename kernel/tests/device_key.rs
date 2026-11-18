//! Test kernel: the device secret (#255, D-047, release-integrity.md).
//! `xtask` passes the known test key through `fw_cfg`; the kernel reads it
//! once, derives one key per purpose, gives `init` the two `Key`
//! capabilities, and a process holding one reads only that purpose's key
//! (`keyprobe`), never the secret. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, GRANT, Object, READ, WRITE};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::key::{self, Purpose};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, mm, process, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// `xtask`'s `TEST_DEVICE_KEY`: bytes 0 to 31.
const TEST_KEY: [u8; 32] = {
    let mut key = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        key[i] = i as u8;
        i += 1;
    }
    key
};

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

fn output_of(task: u64) -> Vec<Vec<u8>> {
    process::debug_output()
        .into_iter()
        .filter(|(t, _)| *t == task)
        .map(|(_, line)| line)
        .collect()
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

    t.check("no key before it is read", !key::present());
    t.check("the device key is read from fw_cfg", key::init().is_ok());
    t.check(
        "it is read only once",
        key::init() == Err(key::Error::AlreadySet),
    );
    let audit = key::derived(Purpose::AuditAnchor);
    let slot = key::derived(Purpose::SlotRecord);
    t.check(
        "AuditAnchor is derived from the key xtask passed",
        audit == Some(pharos_crypto::derive(&TEST_KEY, b"pharos audit anchor v1")),
    );
    t.check(
        "SlotRecord is derived from it, and differs",
        slot == Some(pharos_crypto::derive(&TEST_KEY, b"pharos slot record v1")) && slot != audit,
    );
    t.check(
        "neither is the secret",
        audit != Some(TEST_KEY) && slot != Some(TEST_KEY),
    );

    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    let caps = process::init_capabilities(programs.clone(), Endpoint::new(), false);
    let keys: Vec<_> = caps
        .iter()
        .filter_map(|c| match c.object() {
            Object::Key(p) => Some((*p, c.rights())),
            _ => None,
        })
        .collect();
    t.check(
        "init gets the AuditAnchor key (READ | GRANT) and the SlotRecord key (READ), last",
        keys == [
            (Purpose::AuditAnchor, READ | GRANT),
            (Purpose::SlotRecord, READ),
        ] && matches!(
            caps[caps.len() - 2].object(),
            Object::Key(Purpose::AuditAnchor)
        ),
    );

    let caps = vec![
        Capability::new(Object::DebugConsole, WRITE),
        Capability::new(Object::Key(Purpose::AuditAnchor), READ),
        Capability::new(Object::Key(Purpose::SlotRecord), GRANT),
    ];
    let id = process::spawn_elf(&programs, b"bin/keyprobe", 0, caps).unwrap_or(u64::MAX);
    let mut code = None;
    for _ in 0..100 {
        code = process::exits()
            .iter()
            .find(|e| e.task == id)
            .map(|e| e.code);
        if code.is_some() {
            break;
        }
        sched::sleep(Duration::from_millis(20));
    }
    let lines = output_of(id);
    let want = alloc::format!("key {}", audit.map(|k| hex(&k)).unwrap_or_default());
    t.check(
        "key_read returns the AuditAnchor key to a process holding it",
        lines.iter().any(|l| l == want.as_bytes()),
    );
    for step in [
        "a key without READ: MISSING_RIGHT",
        "the console is not a key: MISSING_RIGHT",
        "no such handle: refused",
    ] {
        let want = alloc::format!("ok {step}");
        t.check(step, lines.iter().any(|l| l == want.as_bytes()));
    }
    t.check("keyprobe exits with no failures", code == Some(0));
}
