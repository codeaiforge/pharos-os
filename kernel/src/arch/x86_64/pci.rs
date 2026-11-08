//! PCI configuration access, mechanism #1 (ports `0xCF8`/`0xCFC`; D-008,
//! drivers.md). Safe functions only: reads; BAR size probing that puts
//! everything back; the command and MSI-X control bits the kernel's
//! device handling sets (`device.rs`); MSI-X table entries (`irq.rs`);
//! and for hotplug (M4.4, `hotplug.rs`), a slot's control register and the
//! BARs of a function that has just arrived, before it is handed out.

use core::arch::asm;

use crate::mm::raw::IrqMutex;

const ADDRESS: u16 = 0xcf8;
const DATA: u16 = 0xcfc;
/// Configuration offset of the command register.
const COMMAND: u8 = 0x04;
/// Command bits: I/O space and memory space decoding.
const DECODE: u32 = 0b11;
/// Command bit: memory space decoding.
const MEMORY: u32 = 1 << 1;
/// Command bit: the device may master the bus (DMA, MSI writes).
const BUS_MASTER: u32 = 1 << 2;

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

/// Writes the Slot Control register of the PCI Express capability at
/// `cap` (offset `cap + 0x18`), and `clear` into Slot Status, whose event
/// bits are cleared by writing ones (hotplug).
pub fn write_slot(address: Address, cap: u8, control: u16, clear: u16) {
    let _guard = LOCK.lock();
    write32_locked(
        address,
        cap.wrapping_add(0x18),
        u32::from(control) | u32::from(clear) << 16,
    );
}

/// Writes BAR register `index` (0–5) with decoding off, then restores the
/// command register: only for a hot-added function before any driver has
/// it (`hotplug.rs`, inside its port's window).
pub fn write_bar(address: Address, index: u8, value: u32) {
    let offset = 0x10 + 4 * (index % 6);
    let _guard = LOCK.lock();
    let command = read32_locked(address, COMMAND);
    write32_locked(address, COMMAND, command & !DECODE & 0xffff);
    write32_locked(address, offset, value);
    write32_locked(address, COMMAND, command & 0xffff);
}

/// Turns memory decoding and bus mastering on (`on`) or off together with
/// I/O decoding (`!on`). Turning them off stops the device's DMA and MSI
/// writes. Writes zeros to the status half, which clears nothing.
pub fn set_enabled(address: Address, on: bool) {
    let _guard = LOCK.lock();
    let command = read32_locked(address, COMMAND) & 0xffff;
    let command = if on {
        command | MEMORY | BUS_MASTER
    } else {
        command & !(DECODE | BUS_MASTER)
    };
    write32_locked(address, COMMAND, command);
}

/// Turns bus mastering on or off, leaving memory and I/O decoding as they
/// are (DMA buffers freed or allocated, M4.4 review F1 and F3).
pub fn set_bus_master(address: Address, on: bool) {
    let _guard = LOCK.lock();
    let command = read32_locked(address, COMMAND) & 0xffff;
    let command = if on {
        command | BUS_MASTER
    } else {
        command & !BUS_MASTER
    };
    write32_locked(address, COMMAND, command);
}

/// The command register's memory-decoding and bus-master bits.
pub fn enabled_bits(address: Address) -> (bool, bool) {
    let command = read32(address, COMMAND);
    (command & MEMORY != 0, command & BUS_MASTER != 0)
}

/// Sets the MSI-X capability at `cap` (its configuration offset): MSI-X
/// enable and the function mask (which masks every vector).
pub fn set_msix_control(address: Address, cap: u8, enable: bool, function_mask: bool) {
    let _guard = LOCK.lock();
    let header = read32_locked(address, cap);
    let mut control = header >> 16;
    control = (control & !(3 << 14)) | u32::from(enable) << 15 | u32::from(function_mask) << 14;
    // The low half (ID and next pointer) is read-only.
    write32_locked(address, cap, (header & 0xffff) | control << 16);
}

/// Vector control bit of an MSI-X table entry: masked.
const MSIX_MASKED: u32 = 1;

/// Programs the MSI-X table entry at physical address `entry` (16 bytes,
/// in a device BAR that only the kernel maps): to raise `vector` on the
/// local APIC `apic_id` and unmasked, or masked with `None`. The entry is
/// masked while its address and data change.
pub fn set_msix_entry(
    entry: u64,
    target: Option<(u8, u32)>,
) -> Result<(), super::paging::MapError> {
    use super::paging::mmio_write32;
    mmio_write32(entry + 12, MSIX_MASKED)?;
    if let Some((vector, apic_id)) = target {
        // Fixed delivery, edge-triggered, physical destination.
        mmio_write32(entry, 0xfee0_0000 | (apic_id & 0xff) << 12)?;
        mmio_write32(entry + 4, 0)?;
        mmio_write32(entry + 8, u32::from(vector))?;
        mmio_write32(entry + 12, 0)?;
    }
    Ok(())
}

/// True if the MSI-X table entry at physical address `entry` is masked.
pub fn msix_entry_masked(entry: u64) -> bool {
    super::paging::mmio_read32(entry + 12).is_ok_and(|c| c & MSIX_MASKED != 0)
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
