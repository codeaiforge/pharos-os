//! Test kernel: processes read files only through capabilities (issue
//! #48). A process runs a table of `open` and `read` calls against the
//! `fs-good` image, including every refusal; then a file capability passes
//! over IPC and the receiver reads with it. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use pharos_kernel::arch::x86_64::paging::{self, Flags};
use pharos_kernel::arch::x86_64::user_programs::TestProgram;
use pharos_kernel::arch::x86_64::{apic, gdt, idt};
use pharos_kernel::cap::{Capability, GRANT, Object, READ, RECEIVE, SEND};
use pharos_kernel::ipc::Endpoint;
use pharos_kernel::process::{self, ProcessError};
use pharos_kernel::syscall::{Error, number};
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{fs, kprintln, mm, sched, storage, time};

pharos_kernel::test_kernel!(run);

/// Call table (one page), paths (one page), read buffer (two pages).
const TABLE: u64 = 0x6000_0000;
const PATHS: u64 = 0x6000_1000;
const BUF: u64 = 0x6000_2000;
const UNMAPPED: u64 = 0x7000_0000;
const ENTRY_WORDS: usize = 10;

/// Paths in the paths page, at fixed offsets.
const HELLO: (u64, &[u8]) = (PATHS, b"hello.txt");
const BIG: (u64, &[u8]) = (PATHS + 0x100, b"dir/big.bin");
const NOPE: (u64, &[u8]) = (PATHS + 0x200, b"nope");
const HELLO_TEXT: &[u8] = b"Hello from the Pharos filesystem.\n";

struct Case {
    what: &'static str,
    number: u64,
    args: [u64; 4],
    expect: Result<u64, Error>,
}

fn case(what: &'static str, number: u64, args: [u64; 4], expect: Result<u64, Error>) -> Case {
    Case {
        what,
        number,
        args,
        expect,
    }
}

/// Handles: 1 filesystem (READ | GRANT), 2 filesystem without READ; files
/// opened later get 3, 4, ...
fn cases() -> Vec<Case> {
    use number::{OPEN, READ as RD, REVOKE};
    let len = |p: (u64, &[u8])| p.1.len() as u64;
    vec![
        case("open hello.txt", OPEN, [1, HELLO.0, len(HELLO), 0], Ok(3)),
        case("read all of it", RD, [3, BUF, 64, 0], Ok(34)),
        case(
            "read 4 bytes at offset 6",
            RD,
            [3, BUF + 0x100, 4, 6],
            Ok(4),
        ),
        case("read past the end", RD, [3, BUF, 64, 100], Ok(0)),
        case("open dir/big.bin", OPEN, [1, BIG.0, len(BIG), 0], Ok(4)),
        // Into the buffer's second half, across the page boundary.
        case(
            "read 3000 bytes across a page boundary",
            RD,
            [4, BUF + 0x800, 3000, 0],
            Ok(3000),
        ),
        case(
            "open without READ",
            OPEN,
            [2, HELLO.0, len(HELLO), 0],
            Err(Error::MissingRight),
        ),
        case(
            "open a missing file",
            OPEN,
            [1, NOPE.0, len(NOPE), 0],
            Err(Error::NotFound),
        ),
        case(
            "open with a 105-byte path",
            OPEN,
            [1, HELLO.0, 105, 0],
            Err(Error::TooLarge),
        ),
        case(
            "open with a kernel pointer",
            OPEN,
            [1, 0xffff_ffff_8000_0000, 8, 0],
            Err(Error::BadAddress),
        ),
        case(
            "open with an unmapped path",
            OPEN,
            [1, UNMAPPED, 8, 0],
            Err(Error::BadAddress),
        ),
        case(
            "open through a handle not held",
            OPEN,
            [9, HELLO.0, len(HELLO), 0],
            Err(Error::InvalidHandle),
        ),
        case(
            "read into an unmapped buffer",
            RD,
            [3, UNMAPPED, 8, 0],
            Err(Error::BadAddress),
        ),
        case(
            "read into the read-only code page",
            RD,
            [3, process::USER_BASE, 8, 0],
            Err(Error::BadAddress),
        ),
        case(
            "read 4097 bytes",
            RD,
            [3, BUF, 4097, 0],
            Err(Error::TooLarge),
        ),
        case(
            "read through the filesystem capability",
            RD,
            [1, BUF, 8, 0],
            Err(Error::MissingRight),
        ),
        case(
            "revoke what handle 1 handed out",
            REVOKE,
            [1, 0, 0, 0],
            Ok(2),
        ),
        case(
            "read a revoked file",
            RD,
            [3, BUF, 8, 0],
            Err(Error::Revoked),
        ),
        case(
            "open again after revoking",
            OPEN,
            [1, HELLO.0, len(HELLO), 0],
            Ok(5),
        ),
        case("read the new file", RD, [5, BUF + 0x200, 64, 0], Ok(34)),
    ]
}

fn table_page(cases: &[Case]) -> Vec<u8> {
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
    }
    table
}

fn paths_page() -> Vec<u8> {
    let mut page = vec![0u8; 4096];
    for (at, path) in [HELLO, BIG, NOPE] {
        let at = (at - PATHS) as usize;
        page[at..at + path.len()].copy_from_slice(path);
    }
    page
}

/// `len` bytes at user offset `at` in the two-page buffer, read through the
/// direct map.
fn user_bytes(pages: [u64; 2], at: usize, len: usize) -> Vec<u8> {
    (at..at + len)
        .map(|i| {
            let phys = pages[i / 4096] + (i % 4096) as u64;
            let word = paging::read_phys_u64(phys & !7).unwrap_or(0);
            (word >> ((phys & 7) * 8)) as u8
        })
        .collect()
}

/// Starts a table process with the table, paths, and buffer pages mapped.
/// Returns its id, the table's physical page, and the buffer's two pages.
fn start_table(
    table: &[u8],
    caps: Vec<Arc<Capability>>,
) -> Result<(u64, u64, [u64; 2]), ProcessError> {
    let mut space = process::load(TestProgram::SyscallTable.bytes())?;
    let pages = mm::frames()
        .as_mut()
        .and_then(|frames| {
            let t = space
                .map_new_page(TABLE, Flags::USER_DATA, table, frames)
                .ok()?;
            space
                .map_new_page(PATHS, Flags::USER_DATA, &paths_page(), frames)
                .ok()?;
            let b0 = space
                .map_new_page(BUF, Flags::USER_DATA, &[], frames)
                .ok()?;
            let b1 = space
                .map_new_page(BUF + 0x1000, Flags::USER_DATA, &[], frames)
                .ok()?;
            Some((t, [b0, b1]))
        })
        .ok_or(ProcessError::NoFrameAllocator)?;
    let id = process::start(space, 0, TABLE, caps)?;
    Ok((id, pages.0, pages.1))
}

/// Status and value of entry `i` in a finished table.
fn result(table_phys: u64, i: usize) -> (u64, u64) {
    let word = |w: usize| paging::read_phys_u64(table_phys + w as u64 * 8).unwrap_or(u64::MAX);
    let base = 1 + i * ENTRY_WORDS;
    (word(base + 7), word(base + 8))
}

fn expected(e: Result<u64, Error>) -> (u64, u64) {
    match e {
        Ok(value) => (0, value),
        Err(error) => (error as u64, 0),
    }
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
    let Ok(image) = fs::mount("fs-good") else {
        t.check("fs-good mounts", false);
        return;
    };

    // One process, every call and refusal.
    let cases = cases();
    let caps = vec![
        Capability::new(Object::Filesystem(image.clone()), READ | GRANT),
        Capability::new(Object::Filesystem(image.clone()), GRANT),
    ];
    let started = start_table(&table_page(&cases), caps);
    t.check("file process started", started.is_ok());
    let Ok((id, table_phys, buf)) = started else {
        return;
    };
    sched::sleep(Duration::from_millis(100));
    for (i, c) in cases.iter().enumerate() {
        let got = result(table_phys, i);
        if got != expected(c.expect) {
            kprintln!(
                "  {}: got {got:?}, expected {:?}",
                c.what,
                expected(c.expect)
            );
        }
        t.check(c.what, got == expected(c.expect));
    }
    t.check(
        "process exited normally",
        process::exits()
            .iter()
            .any(|e| e.task == id && e.code == 0x600d)
            && process::kills().is_empty(),
    );
    t.check(
        "bytes read match the file",
        user_bytes(buf, 0, 34) == HELLO_TEXT && user_bytes(buf, 0x100, 4) == b"from",
    );
    t.check(
        "3000 bytes across the page boundary match dir/big.bin",
        user_bytes(buf, 0x800, 3000)
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (i % 251) as u8),
    );
    t.check(
        "the file opened after revoking reads",
        user_bytes(buf, 0x200, 34) == HELLO_TEXT,
    );

    // IPC: a sender passes a file capability (READ only) to a receiver.
    let endpoint = Endpoint::new();
    let file = image.lookup(b"hello.txt").expect("in fs-good");
    let sender_cases = vec![case(
        "send the file capability",
        number::SEND,
        [1, PATHS, 4, 2],
        Ok(0),
    )];
    // r8 (the rights mask) is the table's fifth argument: set it below.
    let mut sender_table = table_page(&sender_cases);
    sender_table[(1 + 5) * 8..(1 + 6) * 8].copy_from_slice(&(READ as u64).to_le_bytes());
    let receiver_cases = vec![
        case(
            "receive it as handle 2",
            number::RECEIVE,
            [1, BUF, 64, u64::MAX],
            Ok(4 | 2 << 32),
        ),
        case(
            "read with it",
            number::READ,
            [2, BUF + 0x300, 64, 0],
            Ok(34),
        ),
        case(
            "it cannot be passed on (no GRANT)",
            number::SEND,
            [1, PATHS, 4, 2],
            Err(Error::MissingRight),
        ),
    ];
    let receiver = start_table(
        &table_page(&receiver_cases),
        vec![Capability::new(
            Object::Endpoint(endpoint.clone()),
            RECEIVE | SEND,
        )],
    );
    let sender = start_table(
        &sender_table,
        vec![
            Capability::new(Object::Endpoint(endpoint.clone()), SEND),
            Capability::new(
                Object::File {
                    fs: image.clone(),
                    file,
                },
                READ | GRANT,
            ),
        ],
    );
    t.check("IPC processes started", receiver.is_ok() && sender.is_ok());
    let (Ok((_, receiver_table, receiver_buf)), Ok((_, sender_table_phys, _))) = (receiver, sender)
    else {
        return;
    };
    sched::sleep(Duration::from_millis(100));
    for (i, c) in sender_cases.iter().enumerate() {
        t.check(c.what, result(sender_table_phys, i) == expected(c.expect));
    }
    for (i, c) in receiver_cases.iter().enumerate() {
        let got = result(receiver_table, i);
        if got != expected(c.expect) {
            kprintln!(
                "  {}: got {got:?}, expected {:?}",
                c.what,
                expected(c.expect)
            );
        }
        t.check(c.what, got == expected(c.expect));
    }
    t.check(
        "the receiver read the file's bytes",
        user_bytes(receiver_buf, 0x300, 34) == HELLO_TEXT,
    );
    t.check(
        "all processes ended, none killed",
        process::count() == 0 && process::kills().is_empty(),
    );
}
