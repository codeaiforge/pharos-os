//! x86-64 hardware layer: port I/O, the COM1 serial port and kernel
//! console, interrupt control, QEMU exit signalling, halting, and (in
//! submodules) the GDT and TSS.
//!
//! All of the kernel's hardware `unsafe` code lives here and in submodules
//! (D-004), behind safe functions. Each `unsafe` block states why it is sound.

#![allow(unsafe_code)]

pub mod gdt;

use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::SpinLock;

/// Writes a byte to an I/O port.
///
/// # Safety
///
/// Writing `value` to `port` must not break memory safety, for example by
/// programming a DMA engine. Callers in this module only use the serial port.
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller guarantees the write is harmless; `out` touches no
    // memory and does not use the stack.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

/// Reads a byte from an I/O port.
///
/// # Safety
///
/// Reading `port` must have no side effects that break memory safety.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees the read is harmless; `in` touches no
    // memory and does not use the stack.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

/// I/O base of the first serial port (COM1), the kernel's early log channel.
const COM1: u16 = 0x3f8;

/// Register offsets from the serial port base (16550 UART).
const DATA: u16 = 0;
const INTERRUPT_ENABLE: u16 = 1;
const FIFO_CONTROL: u16 = 2;
const LINE_CONTROL: u16 = 3;
const MODEM_CONTROL: u16 = 4;
const LINE_STATUS: u16 = 5;
/// Line status bit: transmit holding register empty.
const TRANSMIT_EMPTY: u8 = 0x20;

/// The COM1 serial port, configured for 115200 baud, 8N1, polled output.
pub struct Serial {
    base: u16,
}

impl Serial {
    /// Initializes COM1 and returns a handle for writing to it.
    pub fn com1() -> Self {
        let serial = Serial { base: COM1 };
        serial.write_register(INTERRUPT_ENABLE, 0x00); // polled mode: no interrupts
        serial.write_register(LINE_CONTROL, 0x80); // expose the baud-rate divisor
        serial.write_register(DATA, 0x01); // divisor low byte: 115200 baud
        serial.write_register(INTERRUPT_ENABLE, 0x00); // divisor high byte
        serial.write_register(LINE_CONTROL, 0x03); // 8 data bits, no parity, 1 stop bit
        serial.write_register(FIFO_CONTROL, 0xc7); // enable and clear FIFOs
        serial.write_register(MODEM_CONTROL, 0x03); // DTR and RTS
        serial
    }

    fn write_register(&self, offset: u16, value: u8) {
        // SAFETY: the port is one of the 8 COM1 UART registers. Writing them
        // configures the UART only and has no effect on memory.
        unsafe { outb(self.base + offset, value) };
    }

    fn read_register(&self, offset: u16) -> u8 {
        // SAFETY: the port is a COM1 UART register; reading it has no memory
        // side effects.
        unsafe { inb(self.base + offset) }
    }

    fn write_byte(&self, byte: u8) {
        while self.read_register(LINE_STATUS) & TRANSMIT_EMPTY == 0 {
            core::hint::spin_loop();
        }
        self.write_register(DATA, byte);
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// True if CPUID reports a hypervisor (CPUID leaf 1, ECX bit 31). Physical
/// CPUs leave this bit clear.
// `__cpuid` is a safe function in recent Rust but `unsafe` in Rust 1.85, the
// minimum supported version, so the block is kept and the warning allowed.
#[allow(unused_unsafe)]
pub fn under_hypervisor() -> bool {
    // SAFETY: CPUID exists on every x86-64 CPU and has no side effects.
    let leaf1 = unsafe { core::arch::x86_64::__cpuid(1) };
    leaf1.ecx & (1 << 31) != 0
}

/// I/O port of QEMU's `isa-debug-exit` device, attached by `cargo xtask run`.
const QEMU_DEBUG_EXIT: u16 = 0xf4;

/// Result reported to QEMU. QEMU exits with status `(value << 1) | 1`.
#[derive(Clone, Copy)]
pub enum QemuExit {
    /// QEMU exit status 33.
    Success = 0x10,
    /// QEMU exit status 35.
    Failure = 0x11,
}

/// Asks QEMU to exit with `status`. Only acts under a hypervisor, so real
/// hardware never sees the write; returns if QEMU did not exit.
pub fn qemu_exit(status: QemuExit) {
    if under_hypervisor() {
        // SAFETY: under a hypervisor, port 0xf4 is QEMU's debug-exit device
        // or an unassigned port whose writes are ignored; neither touches
        // memory.
        unsafe { outb(QEMU_DEBUG_EXIT, status as u8) };
    }
}

/// RFLAGS interrupt-enable flag (IF).
const RFLAGS_IF: u64 = 1 << 9;

/// True if maskable interrupts are enabled (RFLAGS.IF).
pub fn interrupts_enabled() -> bool {
    let rflags: u64;
    // SAFETY: `pushfq; pop` reads RFLAGS through the stack and changes no
    // state; the stack slot it uses is released before the block ends.
    unsafe { asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags)) };
    rflags & RFLAGS_IF != 0
}

/// Enables maskable interrupts (`sti`).
pub fn enable_interrupts() {
    // SAFETY: `sti` only sets RFLAGS.IF. Whether a handler is ready for each
    // unmasked interrupt source is the interrupt setup's responsibility; with
    // all sources masked (as Limine leaves them) nothing is delivered.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

/// Disables maskable interrupts (`cli`).
pub fn disable_interrupts() {
    // SAFETY: `cli` only clears RFLAGS.IF; it touches no memory.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Runs `f` with maskable interrupts disabled, then restores the previous
/// state: enabled stays enabled, disabled stays disabled (so calls nest).
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    let was_enabled = interrupts_enabled();
    if was_enabled {
        disable_interrupts();
    }
    let result = f();
    if was_enabled {
        enable_interrupts();
    }
    result
}

/// Serializes console output so lines from different code paths do not mix.
/// Held only with interrupts disabled, so an interrupt handler on this CPU
/// never waits for a holder it interrupted.
static CONSOLE_LOCK: SpinLock = SpinLock::new();
/// Whether COM1 has been configured. Only changed while holding the lock.
static CONSOLE_READY: AtomicBool = AtomicBool::new(false);

/// Writes formatted text to the kernel console (COM1). Used by `kprint!` and
/// `kprintln!`; configures COM1 on first use. Interrupts are disabled while
/// the lock is held and restored afterwards, so interrupt handlers may print.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    without_interrupts(|| {
        let _guard = CONSOLE_LOCK.lock();
        let mut serial = if CONSOLE_READY.load(Ordering::Acquire) {
            Serial { base: COM1 }
        } else {
            let serial = Serial::com1();
            CONSOLE_READY.store(true, Ordering::Release);
            serial
        };
        // Writing to the UART cannot fail.
        let _ = serial.write_fmt(args);
    });
}

/// Emergency console output for the panic handler and for fatal CPU
/// exception handlers. A CPU exception (for example a page fault) can occur
/// while this CPU holds the console lock, even with interrupts disabled, and
/// the holder never resumes on this single CPU, so the lock is released
/// first; the interrupted line may be cut short. Not for recoverable paths:
/// those use `kprintln!`.
#[doc(hidden)]
pub fn _print_panic(args: fmt::Arguments<'_>) {
    CONSOLE_LOCK.force_unlock();
    _print(args);
}

/// Stops the CPU permanently, with interrupts disabled.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli; hlt` only disables interrupts and stops the CPU; it
        // touches no memory. Looping guards against spurious wake-ups (NMI).
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
