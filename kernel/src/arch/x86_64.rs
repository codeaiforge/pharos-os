//! x86-64 hardware layer: port I/O, the COM1 serial port, and halting.
//!
//! All of the kernel's hardware `unsafe` code lives here (D-004), behind safe
//! functions. Each `unsafe` block states why it is sound.

#![allow(unsafe_code)]

use core::arch::asm;
use core::fmt;

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

/// Stops the CPU permanently, with interrupts disabled.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli; hlt` only disables interrupts and stops the CPU; it
        // touches no memory. Looping guards against spurious wake-ups (NMI).
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
