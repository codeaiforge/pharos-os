//! Test kernel: the system-call entry, the minimal calls, argument
//! validation, capability checks, and the `sysret` hazard (issue #40).
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::paging::{self, Flags, LAST_USER_PAGE, MapError};
use pharos_kernel::arch::x86_64::user_programs::TestProgram;
use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, Object, WRITE};
use pharos_kernel::process::{self, USER_BASE};
use pharos_kernel::syscall::{Error, number};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{mm, sched, time};

pharos_kernel::test_kernel!(run);

/// The call table (first page) and a second page the message spills into.
const TABLE: u64 = 0x6000_0000;
const MESSAGE: &[u8] = b"hello from ring 3";
/// The message starts 8 bytes before the end of the first page.
const MESSAGE_AT: u64 = TABLE + 0x1000 - 8;
const UNMAPPED: u64 = 0x7000_0000;
const ENTRY_WORDS: usize = 10;

fn free_frames() -> usize {
    mm::frames().as_ref().map_or(0, |f| f.stats().free)
}

/// One call: number, three arguments, expected status and value.
struct Case {
    what: &'static str,
    number: u64,
    args: [u64; 3],
    status: u64,
    value: u64,
}

fn case(what: &'static str, number: u64, args: [u64; 3], status: Result<u64, Error>) -> Case {
    let (status, value) = match status {
        Ok(value) => (0, value),
        Err(error) => (error as u64, 0),
    };
    Case {
        what,
        number,
        args,
        status,
        value,
    }
}

fn cases() -> Vec<Case> {
    use number::*;
    let msg = MESSAGE.len() as u64;
    vec![
        case("yield", YIELD, [0; 3], Ok(0)),
        case(
            "debug_write across a page boundary",
            DEBUG_WRITE,
            [1, MESSAGE_AT, msg],
            Ok(msg),
        ),
        case(
            "debug_write from the code page",
            DEBUG_WRITE,
            [1, USER_BASE, 4],
            Ok(4),
        ),
        case(
            "debug_write of 0 bytes",
            DEBUG_WRITE,
            [1, MESSAGE_AT, 0],
            Ok(0),
        ),
        case(
            "kernel pointer",
            DEBUG_WRITE,
            [1, 0xffff_ffff_8000_0000, 8],
            Err(Error::BadAddress),
        ),
        case(
            "unmapped pointer",
            DEBUG_WRITE,
            [1, UNMAPPED, 8],
            Err(Error::BadAddress),
        ),
        case(
            "buffer running into an unmapped page",
            DEBUG_WRITE,
            [1, TABLE + 0x2000 - 4, 8],
            Err(Error::BadAddress),
        ),
        case(
            "buffer reaching the last user page",
            DEBUG_WRITE,
            [1, LAST_USER_PAGE - 4, 8],
            Err(Error::BadAddress),
        ),
        case(
            "overflowing range",
            DEBUG_WRITE,
            [1, u64::MAX - 4, 16],
            Err(Error::BadAddress),
        ),
        case(
            "257 bytes",
            DEBUG_WRITE,
            [1, MESSAGE_AT, 257],
            Err(Error::TooLarge),
        ),
        case(
            "handle 0",
            DEBUG_WRITE,
            [0, MESSAGE_AT, 4],
            Err(Error::InvalidHandle),
        ),
        case(
            "handle not in the table",
            DEBUG_WRITE,
            [3, MESSAGE_AT, 4],
            Err(Error::InvalidHandle),
        ),
        case(
            "capability without WRITE",
            DEBUG_WRITE,
            [2, MESSAGE_AT, 4],
            Err(Error::MissingRight),
        ),
        case("unknown call 99", 99, [0; 3], Err(Error::UnknownCall)),
        case(
            "unknown call 2^64 - 1",
            u64::MAX,
            [0; 3],
            Err(Error::UnknownCall),
        ),
        case(
            "send on a debug-console capability",
            SEND,
            [1, MESSAGE_AT, 4],
            Err(Error::MissingRight),
        ),
        case("delete handle 2", DELETE, [2, 0, 0], Ok(0)),
        case(
            "use the deleted handle",
            DEBUG_WRITE,
            [2, MESSAGE_AT, 4],
            Err(Error::InvalidHandle),
        ),
        case(
            "delete it again",
            DELETE,
            [2, 0, 0],
            Err(Error::InvalidHandle),
        ),
    ]
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
    // Warm up the task stack window so frame counts compare cleanly.
    let _ = sched::spawn(|| {});
    sched::sleep(Duration::from_millis(20));
    let before = free_frames();

    // Build the table page: count, entries, and the first 8 message bytes
    // at its end; the rest of the message starts the second page.
    let cases = cases();
    let mut table = vec![0u8; 4096];
    let mut put = |word: usize, value: u64| {
        table[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(0, cases.len() as u64);
    for (i, c) in cases.iter().enumerate() {
        let base = 1 + i * ENTRY_WORDS;
        put(base, c.number);
        for (j, &arg) in c.args.iter().enumerate() {
            put(base + 1 + j, arg);
        }
        // r10, r8, r9: patterns the call must preserve.
        put(base + 4, 0x1010_1010_0000_0000 | i as u64);
        put(base + 5, 0x0808_0808_0000_0000 | i as u64);
        put(base + 6, 0x0909_0909_0000_0000 | i as u64);
    }
    table[4096 - 8..].copy_from_slice(&MESSAGE[..8]);

    let process = process::load(TestProgram::SyscallTable.bytes()).and_then(|mut space| {
        let table_phys = mm::frames()
            .as_mut()
            .and_then(|frames| {
                let phys = space
                    .map_new_page(TABLE, Flags::USER_DATA, &table, frames)
                    .ok()?;
                space
                    .map_new_page(TABLE + 0x1000, Flags::USER_DATA, &MESSAGE[8..], frames)
                    .ok()?;
                Some(phys)
            })
            .ok_or(process::ProcessError::NoFrameAllocator)?;
        let caps = vec![
            Capability::new(Object::DebugConsole, WRITE),
            Capability::new(Object::DebugConsole, 0),
        ];
        process::start(space, 0, TABLE, caps).map(|id| (id, table_phys))
    });
    t.check("system-call process started", process.is_ok());
    let Ok((id, table_phys)) = process else {
        return;
    };
    sched::sleep(Duration::from_millis(100));

    let word = |w: usize| paging::read_phys_u64(table_phys + w as u64 * 8).unwrap_or(u64::MAX);
    let mut all_preserved = true;
    for (i, c) in cases.iter().enumerate() {
        let base = 1 + i * ENTRY_WORDS;
        let (status, value) = (word(base + 7), word(base + 8));
        all_preserved &= word(base + 9) == 1;
        if status != c.status || value != c.value {
            pharos_kernel::kprintln!(
                "{}: got status {status}, value {value}; expected {}, {}",
                c.what,
                c.status,
                c.value
            );
        }
        t.check(c.what, status == c.status && value == c.value);
    }
    t.check(
        "rdi, rsi, r10, r8, r9, and rsp survive every call",
        all_preserved,
    );
    t.check(
        "exit ended the process with its code",
        process::exits()
            .iter()
            .any(|e| e.task == id && e.code == 0x600d)
            && process::kills().is_empty()
            && process::count() == 0,
    );
    let output = process::debug_output();
    t.check(
        "debug_write delivered the message and the code bytes",
        output.len() == 3
            && output[0] == (id, MESSAGE.to_vec())
            && output[1] == (id, TestProgram::SyscallTable.bytes()[..4].to_vec())
            && output[2].1.is_empty(),
    );
    t.check("the process returned every frame", free_frames() == before);

    // The sysret hazard: the last user page can never be mapped, so a
    // `syscall` at the very end of the page below it returns to a canonical
    // address, faults there in user mode, and only the process dies.
    // (`process::load` takes the frame-allocator lock itself, so load first.)
    let last_page_refused = process::load(&[0xf4]).is_ok_and(|mut space| {
        mm::frames().as_mut().is_some_and(|frames| {
            let refused = space.map_new_page(LAST_USER_PAGE, Flags::USER_CODE, &[], frames)
                == Err(MapError::WrongHalf);
            space.destroy(frames);
            refused
        })
    });
    t.check("the last user page cannot be mapped", last_page_refused);
    let page = LAST_USER_PAGE - 0x1000;
    let mut code = vec![0x90u8; 4096]; // nop
    code[..5].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1 (yield)
    code[4094..].copy_from_slice(&[0x0f, 0x05]); // syscall, the page's last bytes
    let edge = process::load(&[0xf4]).and_then(|mut space| {
        mm::frames()
            .as_mut()
            .and_then(|frames| {
                space
                    .map_new_page(page, Flags::USER_CODE, &code, frames)
                    .ok()
            })
            .ok_or(process::ProcessError::NoFrameAllocator)?;
        process::start(space, page - USER_BASE, 0, Vec::new())
    });
    sched::sleep(Duration::from_millis(50));
    let kill = edge
        .ok()
        .and_then(|id| process::kills().into_iter().find(|k| k.task == id));
    t.check(
        "a syscall at the end of the user half returns, then faults in user mode",
        kill.is_some_and(|k| {
            k.vector == 14 && k.cr2 == LAST_USER_PAGE && k.rip == LAST_USER_PAGE && k.cs & 3 == 3
        }),
    );
}
