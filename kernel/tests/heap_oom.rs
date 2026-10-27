//! Test kernel: exhausting the kernel heap is reported through the panic
//! handler, not undefined behaviour (D-005, issue #29). Runs under UEFI.

#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;
use core::panic::PanicInfo;

use alloc::vec::Vec;

use pharos_kernel::arch::x86_64::{gdt, idt};
use pharos_kernel::mm;
use pharos_kernel::testing::{self, TestRun};

pharos_kernel::test_kernel!(run);

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
    testing::set_panic_hook(on_panic);
    // 8 MiB cannot fit in the 4 MiB heap.
    let v: Vec<u8> = Vec::with_capacity(8 * 1024 * 1024);
    t.check("allocation larger than the heap failed", v.capacity() == 0);
}

/// A small buffer to capture the panic message.
struct Message {
    bytes: [u8; 128],
    len: usize,
}

impl Write for Message {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len < self.bytes.len() {
                self.bytes[self.len] = b;
                self.len += 1;
            }
        }
        Ok(())
    }
}

fn on_panic(info: &PanicInfo<'_>) -> ! {
    let mut message = Message {
        bytes: [0; 128],
        len: 0,
    };
    let _ = write!(message, "{}", info.message());
    let text = core::str::from_utf8(&message.bytes[..message.len]).unwrap_or("");
    let mut t = TestRun::new();
    t.check(
        "out of memory reported: memory allocation of 8388608 bytes failed",
        text == "memory allocation of 8388608 bytes failed",
    );
    t.check("heap still consistent", mm::heap_stats().used == 0);
    t.finish()
}
