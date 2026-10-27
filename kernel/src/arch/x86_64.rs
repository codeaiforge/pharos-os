//! x86-64 hardware layer: port I/O, the COM1 serial port and kernel
//! console, interrupt control, the PIT and TSC (timer calibration), QEMU
//! exit signalling, halting, and (in submodules) the GDT, TSS, IDT, exception handlers, page tables, and the
//! local APIC.
//!
//! All of the kernel's hardware `unsafe` code lives here and in submodules
//! (D-004), behind safe functions. Each `unsafe` block states why it is sound.

#![allow(unsafe_code)]

pub mod apic;
pub mod context;
pub mod gdt;
pub mod idt;
pub mod paging;
pub mod syscall;
pub mod user_programs;

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

/// Reads a model-specific register.
pub(crate) fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: callers read architectural MSRs that exist on every x86-64 CPU
    // (IA32_APIC_BASE, IA32_EFER); reading them has no side effects.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    u64::from(hi) << 32 | u64::from(lo)
}

/// True if CPUID reports a local APIC (leaf 1, EDX bit 9).
#[allow(unused_unsafe)] // see `under_hypervisor`
pub fn cpu_has_apic() -> bool {
    // SAFETY: CPUID exists on every x86-64 CPU and has no side effects.
    let leaf1 = unsafe { core::arch::x86_64::__cpuid(1) };
    leaf1.edx & (1 << 9) != 0
}

/// Halts the CPU until the next interrupt (`hlt`). With interrupts
/// disabled, only an NMI wakes it.
pub fn wait_for_interrupt() {
    // SAFETY: `hlt` only pauses the CPU until an interrupt; it touches no
    // memory.
    unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
}

/// Reads the time-stamp counter.
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` only reads a counter into EDX:EAX; it touches no memory.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    u64::from(hi) << 32 | u64::from(lo)
}

/// Input clock of the legacy PIT, in Hz.
pub const PIT_HZ: u64 = 1_193_182;

// PIT channel 2 (D-006 timer part): its gate and output are wired to port
// 0x61, so it can be polled without interrupts.
const PIT_CHANNEL2: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;
const PIT_GATE_PORT: u16 = 0x61;
/// Channel 2, low byte then high byte, mode 0 (interrupt on terminal count), binary.
const PIT_CH2_ONE_SHOT: u8 = 0b1011_0000;
const GATE2_ON: u8 = 1 << 0;
const SPEAKER_ON: u8 = 1 << 1;
const OUT2: u8 = 1 << 5;

/// Programs PIT channel 2 for a one-shot count of `ticks` (at least 1) with
/// the speaker off. Counting starts when [`pit_start`] writes the high byte.
fn pit_arm(ticks: u16) {
    // SAFETY: ports 0x42, 0x43, and 0x61 are the PIT and its gate/speaker
    // control; programming them touches no memory.
    unsafe {
        let control = inb(PIT_GATE_PORT);
        outb(PIT_GATE_PORT, (control & !SPEAKER_ON) | GATE2_ON);
        outb(PIT_COMMAND, PIT_CH2_ONE_SHOT);
        outb(PIT_CHANNEL2, ticks as u8);
    }
}

/// Starts the count armed by [`pit_arm`].
fn pit_start(ticks: u16) {
    // SAFETY: as in `pit_arm`.
    unsafe { outb(PIT_CHANNEL2, (ticks >> 8) as u8) };
}

/// Busy-waits until the started count reaches zero.
fn pit_wait_done() {
    // SAFETY: reading port 0x61 has no side effects.
    while unsafe { inb(PIT_GATE_PORT) } & OUT2 == 0 {
        core::hint::spin_loop();
    }
}

/// Busy-waits for `ticks` periods of the PIT (1 to 65,535, about 55 ms at
/// most), independent of the TSC and the APIC. Used to check calibration.
pub fn pit_wait(ticks: u16) {
    let ticks = ticks.max(1);
    pit_arm(ticks);
    pit_start(ticks);
    pit_wait_done();
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

/// Size of the kernel stack.
pub const KERNEL_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(4096))]
struct KernelStack([u8; KERNEL_STACK_SIZE]);

/// The kernel stack. `linker.ld` places it in its own segment after an
/// unmapped guard page, so an overflow raises a page fault (and, since the
/// fault cannot push its frame, a double fault on the IST stack).
// SAFETY: `.kernel_stack` is a NOLOAD section in `linker.ld` reserved for
// this one static; placing it there has no other effect.
#[unsafe(link_section = ".kernel_stack")]
static mut KERNEL_STACK: KernelStack = KernelStack([0; KERNEL_STACK_SIZE]);

/// Bounds of the kernel stack, `(bottom, top)`. The guard page is the page
/// below `bottom`.
pub fn kernel_stack_bounds() -> (u64, u64) {
    let bottom = (&raw const KERNEL_STACK) as u64;
    (bottom, bottom + KERNEL_STACK_SIZE as u64)
}

/// Current stack pointer (RSP).
pub fn stack_pointer() -> u64 {
    let rsp: u64;
    // SAFETY: copying RSP into a register has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

/// Leaves the bootloader's stack: switches to the empty kernel stack and
/// calls `entry`, which must never return. Call once, first thing in the
/// entry point; anything on the old stack is abandoned.
pub fn run_on_kernel_stack(entry: extern "C" fn() -> !) -> ! {
    let (_, top) = kernel_stack_bounds();
    // SAFETY: the kernel stack is reserved for this use, unused until now,
    // and its top is 4096-byte aligned, so RSP is 16-byte aligned at the
    // call as the System V ABI requires. RBP is cleared to end frame-pointer
    // chains. `entry` never returns, so nothing uses the abandoned stack.
    unsafe {
        asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "call {entry}",
            "ud2",
            top = in(reg) top,
            entry = in(reg) entry,
            options(noreturn),
        )
    }
}

/// Stops the CPU permanently, with interrupts disabled.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli; hlt` only disables interrupts and stops the CPU; it
        // touches no memory. Looping guards against spurious wake-ups (NMI).
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
