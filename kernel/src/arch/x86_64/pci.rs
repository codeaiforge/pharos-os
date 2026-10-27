//! PCI configuration access, mechanism #1 (ports `0xCF8`/`0xCFC`; D-008,
//! drivers.md). Safe functions only: reads, and BAR size probing that puts
//! everything back. Writes that could re-point a BAR or start DMA are not
//! offered here.

use core::arch::asm;

use crate::mm::raw::IrqMutex;

const ADDRESS: u16 = 0xcf8;
const DATA: u16 = 0xcfc;
/// Configuration offset of the command register.
const COMMAND: u8 = 0x04;
/// Command bits: I/O space and memory space decoding.
const DECODE: u32 = 0b11;

/// Serialises address/data pairs (one CPU; interrupts off while held).
static LOCK: IrqMutex<()> = IrqMutex::new(());

/// A PCI function's location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    fn config(self, offset: u8) -> u32 {
        0x8000_0000
            | u32::from(self.bus) << 16
            | u32::from(self.device & 0x1f) << 11
            | u32::from(self.function & 0x7) << 8
            | u32::from(offset & 0xfc)
    }
}

fn outl(port: u16, value: u32) {
    // SAFETY: only the PCI configuration ports are used, through the
    // functions below; selecting a configuration address or writing the
    // values below changes no memory the kernel relies on. `out` touches
    // no memory and does not use the stack.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags))
    };
}

fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: reads the PCI configuration data port; `in` touches no memory
    // and does not use the stack.
    unsafe {
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Reads the 32-bit configuration register at `offset` (rounded down to a
/// multiple of 4). Absent functions read as all ones.
pub fn read32(address: Address, offset: u8) -> u32 {
    let _guard = LOCK.lock();
    outl(ADDRESS, address.config(offset));
    inl(DATA)
}

fn write32_locked(address: Address, offset: u8, value: u32) {
    outl(ADDRESS, address.config(offset));
    outl(DATA, value);
}

fn read32_locked(address: Address, offset: u8) -> u32 {
    outl(ADDRESS, address.config(offset));
    inl(DATA)
}

/// Probes BAR register `index` (0–5): with I/O and memory decoding off,
/// writes all ones, reads the result, and restores the BAR and the command
/// register. Returns `(original, probe)`. Interrupts stay off throughout,
/// so nothing sees the device in between.
pub fn probe_bar(address: Address, index: u8) -> (u32, u32) {
    let offset = 0x10 + 4 * (index % 6);
    let _guard = LOCK.lock();
    let command = read32_locked(address, COMMAND);
    write32_locked(address, COMMAND, command & !DECODE & 0xffff);
    let original = read32_locked(address, offset);
    write32_locked(address, offset, u32::MAX);
    let probe = read32_locked(address, offset);
    write32_locked(address, offset, original);
    write32_locked(address, COMMAND, command & 0xffff);
    (original, probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_address_layout() {
        let a = Address {
            bus: 0x12,
            device: 0x1f,
            function: 7,
        };
        assert_eq!(a.config(0x3f), 0x8012_ff3c);
        let b = Address {
            bus: 0,
            device: 0x20,
            function: 8,
        };
        assert_eq!(b.config(0), 0x8000_0000, "out-of-range fields are masked");
    }
}
