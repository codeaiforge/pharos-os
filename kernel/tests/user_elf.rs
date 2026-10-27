//! Test kernel: a Rust user program loaded from a filesystem image runs in
//! ring 3, and malformed program files are refused with no process created
//! and no frames lost (issue #52). The `programs` module comes from
//! `cargo xtask` (`program_test_image`). Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use core::time::Duration;

use pharos_elf::ElfError;
use pharos_kernel::arch::x86_64::{apic, gdt, idt, paging};
use pharos_kernel::cap::{Capability, Object, WRITE};
use pharos_kernel::process::{self, ProcessError, USER_BASE};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, sched, storage, time};

pharos_kernel::test_kernel!(run);

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
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
    let Ok(programs) = fs::mount("programs") else {
        t.check("programs image mounts", false);
        return;
    };
    // Warm up the task stack window so frame counts compare cleanly.
    let _ = sched::spawn(|| {});
    sched::sleep(Duration::from_millis(20));
    let before = free_frames();

    // Its segments map with their own permissions.
    let layout = process::load_elf(&programs, b"bin/hello").map(|(space, entry)| {
        let flags = |va| space.translate(va).map(|t| t.flags);
        let ok = entry == 0x40_1000
            && flags(0x40_1000).is_some_and(|f| f.user && f.executable && !f.writable)
            && flags(0x40_2000).is_some_and(|f| f.user && !f.executable && !f.writable)
            && flags(0x40_3000).is_some_and(|f| f.user && !f.executable && f.writable)
            && flags(USER_BASE).is_none();
        if let Some(frames) = mm::frames().as_mut() {
            space.destroy(frames);
        }
        ok
    });
    t.check(
        "hello: code R+X, rodata R, data R+W, nothing at USER_BASE",
        layout == Ok(true),
    );
    t.check(
        "loading and destroying returned every frame",
        free_frames() == before,
    );

    let console = Capability::new(Object::DebugConsole, WRITE);
    let id = process::spawn_elf(&programs, b"bin/hello", 39, vec![console]);
    t.check("hello started", id.is_ok());
    sched::sleep(Duration::from_millis(100));
    let id = id.unwrap_or(u64::MAX);
    t.check(
        "hello printed its greeting",
        process::debug_output()
            .iter()
            .any(|(task, out)| *task == id && out == b"hello from a Rust user program"),
    );
    t.check(
        "hello exited with its argument plus its static count (39 + 3)",
        process::exits()
            .iter()
            .any(|e| e.task == id && e.code == 42),
    );
    t.check("no process killed", process::kills().is_empty());
    t.check("hello returned every frame", free_frames() == before);

    // Malformed program files: each refused, nothing created, nothing lost.
    use ElfError::*;
    let cases: [(&[u8], ProcessError); 11] = [
        (b"bad/magic", ProcessError::Elf(BadMagic)),
        (b"bad/class", ProcessError::Elf(BadIdent)),
        (b"bad/type", ProcessError::Elf(NotExecutable)),
        (b"bad/machine", ProcessError::Elf(WrongMachine)),
        (b"bad/entry", ProcessError::Elf(BadEntry)),
        (b"bad/interp", ProcessError::Elf(Unsupported { index: 0 })),
        (b"bad/wx", ProcessError::Elf(WritableCode { index: 0 })),
        (b"bad/kernel", ProcessError::Elf(BadSegment { index: 0 })),
        (b"bad/truncated", ProcessError::Elf(Truncated)),
        (b"bad/empty", ProcessError::BadImage),
        (b"bin/missing", ProcessError::NoSuchProgram),
    ];
    for (path, expected) in cases {
        let result = process::spawn_elf(&programs, path, 0, vec![]);
        let name = core::str::from_utf8(path).unwrap_or("?");
        if result.as_ref().err() != Some(&expected) {
            kprintln!("  {name}: got {result:?}");
        }
        let label = alloc::format!("{name}: refused ({expected})");
        t.check(&label, result.err() == Some(expected));
    }
    t.check(
        "refusals created no process and lost no frames",
        process::count() == 0 && free_frames() == before,
    );
    // The code page of a loaded program is never writable from user mode.
    t.check(
        "the kernel half stays unmapped for users",
        paging::translate_kernel(0xffff_ffff_8000_0000).is_some_and(|m| !m.flags.user),
    );
}
