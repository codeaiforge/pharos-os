//! Test kernel: Limine modules become read-only RAM disks (issue #46).
//! The runner (`cargo xtask runner`) adds two modules with known contents:
//! `pattern` (41 blocks) and `odd` (1000 bytes, not a whole number of
//! blocks). Runs under UEFI (D-009).

#![no_std]
#![no_main]

use pharos_fs::{BLOCK_SIZE, BlockDevice, BlockError};
use pharos_kernel::arch::x86_64::{gdt, idt, paging};
use pharos_kernel::storage;
use pharos_kernel::testing::{self, TestRun};
use pharos_kernel::{kprintln, mm};

pharos_kernel::test_kernel!(run);

/// Must match `xtask`'s `test_modules`.
const PATTERN_LEN: usize = 41 * BLOCK_SIZE;
const ODD_LEN: usize = 1000;

fn pattern_byte(i: usize) -> u8 {
    ((i * 7) ^ (i >> 9)) as u8
}

fn pattern_intact(disk: &[u8]) -> bool {
    disk.len() == PATTERN_LEN && disk.iter().enumerate().all(|(i, &b)| b == pattern_byte(i))
}

fn block_matches(disk: &[u8], block: usize) -> bool {
    let mut buf = [0u8; BLOCK_SIZE];
    disk.read(block as u64, &mut buf).is_ok()
        && buf
            .iter()
            .enumerate()
            .all(|(i, &b)| b == pattern_byte(block * BLOCK_SIZE + i))
}

fn run(t: &mut TestRun) {
    gdt::init();
    idt::init();
    let memory = testing::init_memory(
        requests::HHDM.response(),
        requests::MEMMAP.response(),
        requests::EXECUTABLE_ADDRESS.response(),
    );
    t.check("frame allocator and kernel page tables set up", memory);
    let Some(hhdm) = requests::HHDM.response() else {
        return;
    };
    if !memory {
        return;
    }

    let (recorded, skipped) = storage::record_modules(requests::MODULES.response(), hhdm.offset);
    for m in storage::modules().iter().flatten() {
        kprintln!("  module {}: {} bytes at {:#x}", m.name(), m.size, m.phys);
    }
    t.check(
        "modules recorded, none skipped",
        recorded >= 2 && skipped == 0,
    );
    t.check(
        "module addresses are 4 KiB aligned",
        storage::modules()
            .iter()
            .flatten()
            .all(|m| m.phys % 4096 == 0),
    );

    let Some(pattern) = storage::ram_disk("pattern") else {
        t.check("RAM disk 'pattern' found", false);
        return;
    };
    t.check(
        "pattern: size and every byte as built",
        pattern_intact(pattern),
    );
    t.check("pattern: 41 blocks", pattern.block_count() == 41);
    t.check("pattern: first block", block_matches(pattern, 0));
    t.check("pattern: middle block", block_matches(pattern, 20));
    t.check("pattern: last block", block_matches(pattern, 40));
    let mut buf = [0u8; 2 * BLOCK_SIZE];
    t.check(
        "pattern: one past the end refused",
        pattern.read(41, &mut buf[..BLOCK_SIZE]) == Err(BlockError::OutOfRange),
    );
    t.check(
        "pattern: a read running past the end refused",
        pattern.read(40, &mut buf) == Err(BlockError::OutOfRange),
    );
    t.check(
        "pattern: a partial block refused",
        pattern.read(0, &mut buf[..100]) == Err(BlockError::BadLength),
    );

    let virt = pattern.as_ptr() as u64;
    let mapping = paging::translate_kernel(virt);
    t.check(
        "pattern: mapped read-only and no-execute",
        mapping.is_some_and(|m| !m.flags.writable && !m.flags.executable && !m.flags.user),
    );

    let odd = storage::ram_disk("odd");
    t.check(
        "odd: 1000 bytes, one whole block",
        odd.is_some_and(|d| d.len() == ODD_LEN && d.block_count() == 1),
    );
    t.check(
        "missing module: no RAM disk",
        storage::ram_disk("missing").is_none(),
    );

    // Module memory must survive reclaim and never reach the frame allocator.
    let reclaimed = mm::reclaim_bootloader_memory();
    t.check("bootloader memory reclaimed", reclaimed.is_ok());
    let module_ranges = storage::modules();
    let mut handed_out = 0;
    let mut overlaps = 0;
    if let Some(frames) = mm::frames().as_mut() {
        while handed_out < 4096 {
            let Ok(frame) = frames.alloc() else { break };
            handed_out += 1;
            let a = frame.addr();
            if module_ranges
                .iter()
                .flatten()
                .any(|m| a + 4096 > m.phys && a < m.phys + m.size)
            {
                overlaps += 1;
            }
        }
    }
    t.check(
        "4096 frames allocated, none inside a module",
        handed_out == 4096 && overlaps == 0,
    );
    t.check(
        "RAM disk unchanged after reclaim and allocation",
        storage::ram_disk("pattern").is_some_and(pattern_intact),
    );
}
