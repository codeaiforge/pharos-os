//! Test kernel: the kernel heap and `alloc` collections (D-005, issue #29).
//! Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use pharos_kernel::arch::x86_64::paging::{self, Flags};
use pharos_kernel::arch::x86_64::{disable_interrupts, enable_interrupts, gdt, idt};
use pharos_kernel::mm::{self, heap::HEAP_BASE};
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

#[repr(align(4096))]
struct PageAligned([u8; 64]);

/// Deterministic pseudo-random numbers (xorshift64).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
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
    let heap = memory && mm::init_heap().is_ok();
    t.check("memory management and heap set up", heap);
    if !heap {
        return;
    }
    t.check(
        "heap window mapped writable, no-execute",
        paging::translate_kernel(HEAP_BASE).is_some_and(|tr| tr.flags == Flags::DATA),
    );
    let start = mm::heap_stats();
    t.check(
        "heap is 4 MiB and empty",
        start.size == 4 * 1024 * 1024 && start.used == 0,
    );

    // Collections.
    let boxed = Box::new(41u64 + 1);
    t.check("Box", *boxed == 42);
    let squares: Vec<u64> = (0..10_000).map(|i| i * i).collect();
    t.check(
        "Vec of 10,000",
        squares.len() == 10_000 && squares[9_999] == 9_999 * 9_999,
    );
    let text: String = format!("{} {}", "Pharos", 0x05);
    t.check("String and format!", text == "Pharos 5");
    let mut map = BTreeMap::new();
    for i in 0..1_000u32 {
        map.insert(i, i * 3);
    }
    t.check(
        "BTreeMap",
        map.len() == 1_000 && map.get(&500) == Some(&1_500),
    );
    let aligned = Box::new(PageAligned([7; 64]));
    t.check(
        "4 KiB-aligned allocation",
        (&*aligned as *const PageAligned as usize) % 4096 == 0 && aligned.0[63] == 7,
    );
    t.check("heap in use", mm::heap_stats().used > 0);
    drop((boxed, squares, text, map, aligned));
    t.check("usage back to zero after drops", mm::heap_stats().used == 0);

    // Fragmentation stress: mixed sizes, random frees, contents checked.
    const SLOTS: usize = 256;
    let mut slots: [Option<Vec<u8>>; SLOTS] = [const { None }; SLOTS];
    let mut rng = Rng(0x5048_4152_4f53);
    let mut intact = true;
    for _ in 0..20_000 {
        let i = (rng.next() % SLOTS as u64) as usize;
        if let Some(block) = slots[i].take() {
            let tag = block.len() as u8;
            intact &= block.iter().all(|&b| b == tag);
        } else {
            let len = 1 + (rng.next() % 2048) as usize;
            slots[i] = Some(alloc::vec![len as u8; len]);
        }
    }
    for block in slots.iter_mut().filter_map(Option::take) {
        let tag = block.len() as u8;
        intact &= block.iter().all(|&b| b == tag);
    }
    t.check(
        "20,000 mixed allocations and frees kept contents intact",
        intact,
    );
    t.check(
        "usage back to zero after the stress run",
        mm::heap_stats().used == 0,
    );

    // Allocating with interrupts enabled (the heap lock disables them).
    enable_interrupts();
    let v: Vec<u32> = (0..100).collect();
    let still_enabled = pharos_kernel::arch::x86_64::interrupts_enabled();
    disable_interrupts();
    t.check(
        "allocation keeps interrupts enabled",
        still_enabled && v.len() == 100,
    );
}
