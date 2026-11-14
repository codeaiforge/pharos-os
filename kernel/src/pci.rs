//! PCI devices (M2.9, [drivers.md](../../docs/architecture/drivers.md)):
//! enumeration, BAR decoding, and the capability list, including MSI-X.
//!
//! The decoding is safe Rust and host-tested. Configuration space is
//! device-provided data, so the capability walk is bounded: at most
//! [`MAX_CAPS`] steps, every pointer at or above `0x40` and 4-byte aligned.
//! Hardware access is in `arch::x86_64::pci`.

use alloc::vec::Vec;

/// Most capabilities walked per function.
pub const MAX_CAPS: usize = 48;
/// Capability ID of MSI-X.
pub const CAP_MSIX: u8 = 0x11;
/// Capability ID of vendor-specific capabilities (virtio uses these).
pub const CAP_VENDOR: u8 = 0x09;
/// Capability ID of PCI Express (hotplug slot registers, M4.4).
pub const CAP_EXPRESS: u8 = 0x10;

/// A decoded base address register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    /// Memory space: physical base and size in bytes.
    Memory {
        base: u64,
        size: u64,
        prefetchable: bool,
        wide: bool,
    },
    /// I/O space: port base and size.
    Io { base: u32, size: u32 },
}

/// Decodes six BAR registers from their original values and the values
/// read back after writing all ones. A 64-bit BAR takes two slots; the
/// second is `None`. Unimplemented BARs (probe 0) are `None`.
pub fn decode_bars(original: [u32; 6], probe: [u32; 6]) -> [Option<Bar>; 6] {
    let mut bars = [None; 6];
    let mut i = 0;
    while i < 6 {
        let (o, p) = (original[i], probe[i]);
        if o & 1 == 1 {
            // I/O BAR: bits 1:0 are flags; 16-bit port space.
            let mask = p & !0b11 & 0xffff;
            if mask != 0 {
                bars[i] = Some(Bar::Io {
                    base: o & !0b11,
                    size: (!mask & 0xffff) + 1,
                });
            }
            i += 1;
            continue;
        }
        let wide = (o >> 1) & 0b11 == 0b10;
        let prefetchable = o & 0b1000 != 0;
        let low_mask = u64::from(p & !0xf);
        let (base, mask) = if wide && i < 5 {
            let base = u64::from(o & !0xf) | u64::from(original[i + 1]) << 32;
            (base, low_mask | u64::from(probe[i + 1]) << 32)
        } else {
            (u64::from(o & !0xf), low_mask | 0xffff_ffff_0000_0000)
        };
        if low_mask != 0 || (wide && i < 5 && probe[i + 1] != 0) {
            bars[i] = Some(Bar::Memory {
                base,
                size: (!mask).wrapping_add(1),
                prefetchable,
                wide: wide && i < 5,
            });
        }
        i += if wide && i < 5 { 2 } else { 1 };
    }
    bars
}

/// One entry of a function's capability list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub id: u8,
    /// Configuration-space offset of the capability.
    pub offset: u8,
}

/// Why a capability list was cut short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapListError {
    /// A pointer below `0x40` or not 4-byte aligned.
    BadPointer(u8),
    /// More than [`MAX_CAPS`] entries (a loop).
    TooLong,
}

/// Walks the capability list starting at `first` (the byte at `0x34`),
/// reading 32-bit configuration registers with `read32`. Returns the
/// entries found before any error, and the error.
pub fn capabilities(
    first: u8,
    read32: impl Fn(u8) -> u32,
) -> (Vec<Capability>, Option<CapListError>) {
    let mut caps = Vec::new();
    let mut next = first;
    while next != 0 {
        if next < 0x40 || next % 4 != 0 {
            return (caps, Some(CapListError::BadPointer(next)));
        }
        if caps.len() == MAX_CAPS {
            return (caps, Some(CapListError::TooLong));
        }
        let header = read32(next);
        caps.push(Capability {
            id: header as u8,
            offset: next,
        });
        next = (header >> 8) as u8;
    }
    (caps, None)
}

/// An MSI-X capability's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    /// Configuration-space offset of the capability.
    pub offset: u8,
    /// Number of table entries (1–2048).
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

impl Msix {
    /// The physical address of table entry `entry`, if its 16 bytes lie
    /// inside the table's memory BAR. The offset comes from the device, so
    /// an address past the BAR could be RAM (#218).
    pub fn entry_address(&self, bars: &[Option<Bar>; 6], entry: u16) -> Option<u64> {
        if entry >= self.table_size {
            return None;
        }
        let Some(Some(Bar::Memory { base, size, .. })) = bars.get(usize::from(self.table_bar))
        else {
            return None;
        };
        let at = u64::from(self.table_offset) + 16 * u64::from(entry);
        if at + 16 > *size {
            return None;
        }
        base.checked_add(at)
    }
}

/// Removes memory BARs that overlap an entry of the boot memory map
/// (`(base, length)`: RAM, the kernel, modules, firmware tables, the
/// framebuffer) or run past the end of the address space. Device registers
/// never lie there, so such a BAR is hostile or misconfigured, and mapping
/// it would hand out memory. With an incomplete map (`complete` false)
/// every memory BAR is removed. Returns how many were removed.
pub fn remove_bars_over_memory(
    bars: &mut [Option<Bar>; 6],
    map: impl Iterator<Item = (u64, u64)> + Clone,
    complete: bool,
) -> usize {
    let mut removed = 0;
    for bar in bars.iter_mut() {
        let Some(Bar::Memory { base, size, .. }) = *bar else {
            continue;
        };
        let bad = match base.checked_add(size) {
            None => true,
            Some(end) => {
                !complete
                    || map
                        .clone()
                        .any(|(b, len)| b < end && base < b.saturating_add(len))
            }
        };
        if bad {
            *bar = None;
            removed += 1;
        }
    }
    removed
}

/// Decodes the MSI-X capability at `offset`.
pub fn msix(offset: u8, read32: impl Fn(u8) -> u32) -> Msix {
    let control = read32(offset) >> 16;
    let table = read32(offset.wrapping_add(4));
    let pba = read32(offset.wrapping_add(8));
    Msix {
        offset,
        table_size: (control & 0x7ff) as u16 + 1,
        table_bar: (table & 0b111) as u8,
        table_offset: table & !0b111,
        pba_bar: (pba & 0b111) as u8,
        pba_offset: pba & !0b111,
    }
}

pub use crate::arch::x86_64::pci::Address;

/// One PCI function found at boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    /// Class, subclass, programming interface.
    pub class: [u8; 3],
    pub bars: [Option<Bar>; 6],
    pub capabilities: Vec<Capability>,
    /// Set if the capability walk stopped early.
    pub capability_error: Option<CapListError>,
    pub msix: Option<Msix>,
}

impl Device {
    /// A short name for well-known devices, for the boot log.
    pub fn name(&self) -> &'static str {
        match (self.vendor, self.device, self.class[0], self.class[1]) {
            (0x1af4, 0x1042, _, _) => "virtio-blk",
            (0x1af4, 0x1041, _, _) => "virtio-net",
            (_, _, 0x06, 0x00) => "host bridge",
            (_, _, 0x06, 0x01) => "ISA bridge",
            (_, _, 0x01, 0x06) => "SATA controller",
            (_, _, 0x03, _) => "display",
            (_, _, 0x02, _) => "network",
            (_, _, 0x0c, 0x05) => "SMBus",
            _ => "device",
        }
    }
}

#[cfg(target_os = "none")]
pub use kernel::{add, devices, enumerate, remove, scan_function};

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::pci::{self as hw, Address};
    use crate::mm::raw::IrqMutex;
    use alloc::sync::Arc;

    static DEVICES: IrqMutex<Vec<Arc<Device>>> = IrqMutex::new(Vec::new());

    /// Scans one function as enumeration does (hotplug, after its BARs
    /// are assigned); `None` if nothing answers.
    pub fn scan_function(address: Address) -> Option<Device> {
        scan(address)
    }

    /// Adds a function that arrived (hotplug).
    pub fn add(device: Arc<Device>) {
        DEVICES.lock().push(device);
    }

    /// Forgets the function at `address` (hotplug removal).
    pub fn remove(address: Address) {
        DEVICES.lock().retain(|d| d.address != address);
    }

    fn scan(address: Address) -> Option<Device> {
        let id = hw::read32(address, 0);
        let vendor = id as u16;
        if vendor == 0xffff {
            return None;
        }
        let class = hw::read32(address, 0x08);
        let header = (hw::read32(address, 0x0c) >> 16) as u8;
        let mut bars = [None; 6];
        let (mut capabilities, mut capability_error, mut msix) = (Vec::new(), None, None);
        // Only type 0 (ordinary devices) has six BARs and a driver.
        if header & 0x7f == 0 {
            let mut original = [0; 6];
            let mut probe = [0; 6];
            for i in 0..6u8 {
                (original[i as usize], probe[i as usize]) = hw::probe_bar(address, i);
            }
            bars = decode_bars(original, probe);
            let removed = match crate::mm::memory_map().as_ref() {
                Some(map) => remove_bars_over_memory(
                    &mut bars,
                    map.entries().iter().map(|e| (e.base, e.length)),
                    map.truncated() == 0,
                ),
                None => remove_bars_over_memory(&mut bars, core::iter::empty(), false),
            };
            if removed > 0 {
                crate::kprintln!(
                    "pci: {:02x}:{:02x}.{}: {removed} memory BAR(s) overlap memory, ignored",
                    address.bus,
                    address.device,
                    address.function
                );
            }
            let status = hw::read32(address, 0x04) >> 16;
            if status & (1 << 4) != 0 {
                let first = hw::read32(address, 0x34) as u8 & !0b11;
                (capabilities, capability_error) =
                    super::capabilities(first, |offset| hw::read32(address, offset));
                msix = capabilities
                    .iter()
                    .find(|c| c.id == CAP_MSIX)
                    .map(|c| super::msix(c.offset, |o| hw::read32(address, o)));
            }
        }
        Some(Device {
            address,
            vendor,
            device: (id >> 16) as u16,
            class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
            bars,
            capabilities,
            capability_error,
            msix,
        })
    }

    /// Scans every bus, device, and function and records what it finds.
    /// Needs the heap. Returns the number of functions.
    pub fn enumerate() -> usize {
        let mut found = Vec::new();
        for bus in 0..=255u8 {
            for device in 0..32u8 {
                let first = Address {
                    bus,
                    device,
                    function: 0,
                };
                let Some(d) = scan(first) else { continue };
                let multifunction = (hw::read32(first, 0x0c) >> 16) & 0x80 != 0;
                found.push(Arc::new(d));
                if multifunction {
                    for function in 1..8u8 {
                        let address = Address {
                            bus,
                            device,
                            function,
                        };
                        if let Some(d) = scan(address) {
                            found.push(Arc::new(d));
                        }
                    }
                }
            }
        }
        let count = found.len();
        *DEVICES.lock() = found;
        crate::hotplug::find();
        count
    }

    /// The functions found by [`enumerate`].
    pub fn devices() -> Vec<Arc<Device>> {
        DEVICES.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_over_memory_are_removed() {
        let mem = |base, size| {
            Some(Bar::Memory {
                base,
                size,
                prefetchable: false,
                wide: false,
            })
        };
        let map = [(0x0, 0x9_f000), (0x10_0000, 0x7ff0_0000)];
        let mut bars = [
            mem(0xfebf_0000, 0x1000), // MMIO hole: kept
            mem(0x7000_0000, 0x1000), // inside RAM
            mem(0x9_e000, 0x2000),    // runs into RAM's end
            Some(Bar::Io {
                base: 0xc000,
                size: 0x40,
            }),
            mem(0x9_f000, 0x6_1000),       // exactly the gap: kept
            mem(u64::MAX - 0xfff, 0x2000), // wraps
        ];
        assert_eq!(
            remove_bars_over_memory(&mut bars, map.iter().copied(), true),
            3
        );
        assert!(bars[0].is_some() && bars[3].is_some() && bars[4].is_some());
        assert!(bars[1].is_none() && bars[2].is_none() && bars[5].is_none());
        // An incomplete map trusts no memory BAR; I/O BARs stay.
        assert_eq!(
            remove_bars_over_memory(&mut bars, map.iter().copied(), false),
            2
        );
        assert!(bars[3].is_some() && bars.iter().filter(|b| b.is_some()).count() == 1);
    }

    #[test]
    fn decodes_bars() {
        // BAR0: 32-bit memory, 4 KiB at 0xfebf_1000. BAR1: I/O, 32 ports at
        // 0xc040. BAR2+3: 64-bit prefetchable memory, 16 KiB at
        // 0x8_0000_0000. BAR4: absent. BAR5: 32-bit memory, 1 MiB.
        let original = [0xfebf_1000, 0xc041, 0x0000_000c, 0x8, 0, 0xfe00_0000];
        let probe = [
            0xffff_f000,
            0xffff_ffe1,
            0xffff_c00c,
            0xffff_ffff,
            0,
            0xfff0_0000,
        ];
        let bars = decode_bars(original, probe);
        assert_eq!(
            bars[0],
            Some(Bar::Memory {
                base: 0xfebf_1000,
                size: 0x1000,
                prefetchable: false,
                wide: false
            })
        );
        assert_eq!(
            bars[1],
            Some(Bar::Io {
                base: 0xc040,
                size: 32
            })
        );
        assert_eq!(
            bars[2],
            Some(Bar::Memory {
                base: 0x8_0000_0000,
                size: 0x4000,
                prefetchable: true,
                wide: true
            })
        );
        assert_eq!(bars[3], None, "upper half of the 64-bit BAR");
        assert_eq!(bars[4], None, "unimplemented");
        assert!(matches!(
            bars[5],
            Some(Bar::Memory {
                size: 0x10_0000,
                ..
            })
        ));
    }

    #[test]
    fn a_64_bit_bar_in_the_last_slot_is_treated_as_32_bit() {
        let mut original = [0; 6];
        let mut probe = [0; 6];
        original[5] = 0x4; // claims 64-bit, but no slot follows
        probe[5] = 0xffff_f004;
        assert!(matches!(
            decode_bars(original, probe)[5],
            Some(Bar::Memory {
                size: 0x1000,
                wide: false,
                ..
            })
        ));
    }

    /// A fake configuration space: 256 bytes.
    fn space(entries: &[(u8, u8, u8)]) -> [u8; 256] {
        let mut s = [0u8; 256];
        for &(at, id, next) in entries {
            s[at as usize] = id;
            s[at as usize + 1] = next;
        }
        s
    }

    fn reader(s: &[u8; 256]) -> impl Fn(u8) -> u32 + '_ {
        move |o| {
            let o = (o & 0xfc) as usize;
            u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]])
        }
    }

    #[test]
    fn walks_capabilities() {
        let s = space(&[
            (0x40, CAP_VENDOR, 0x50),
            (0x50, CAP_MSIX, 0x60),
            (0x60, 0x05, 0),
        ]);
        let (caps, error) = capabilities(0x40, reader(&s));
        assert_eq!(error, None);
        assert_eq!(
            caps.iter().map(|c| (c.id, c.offset)).collect::<Vec<_>>(),
            [(CAP_VENDOR, 0x40), (CAP_MSIX, 0x50), (0x05, 0x60)]
        );
        assert_eq!(
            capabilities(0, reader(&s)),
            (Vec::new(), None),
            "empty list"
        );
    }

    #[test]
    fn malformed_capability_lists_stop_safely() {
        let looped = space(&[(0x40, 0x09, 0x44), (0x44, 0x09, 0x40)]);
        let (caps, error) = capabilities(0x40, reader(&looped));
        assert_eq!((caps.len(), error), (MAX_CAPS, Some(CapListError::TooLong)));
        let low = space(&[(0x40, 0x09, 0x10)]);
        assert_eq!(
            capabilities(0x40, reader(&low)).1,
            Some(CapListError::BadPointer(0x10))
        );
        let odd = space(&[(0x40, 0x09, 0x41)]);
        assert_eq!(
            capabilities(0x40, reader(&odd)).1,
            Some(CapListError::BadPointer(0x41))
        );
        assert_eq!(
            capabilities(0x3c, reader(&odd)).1,
            Some(CapListError::BadPointer(0x3c))
        );
    }

    #[test]
    fn decodes_msix() {
        let mut s = [0u8; 256];
        // Control: table size field 3 (4 entries), enable bit set.
        s[0x50..0x54].copy_from_slice(&(0x8003u32 << 16 | 0x11).to_le_bytes());
        s[0x54..0x58].copy_from_slice(&0x0000_2001u32.to_le_bytes()); // BAR1 + 0x2000
        s[0x58..0x5c].copy_from_slice(&0x0000_3801u32.to_le_bytes()); // BAR1 + 0x3800
        let m = msix(0x50, reader(&s));
        assert_eq!(
            m,
            Msix {
                offset: 0x50,
                table_size: 4,
                table_bar: 1,
                table_offset: 0x2000,
                pba_bar: 1,
                pba_offset: 0x3800
            }
        );
    }

    #[test]
    fn msix_entries_stay_inside_their_bar() {
        let mut bars = [None; 6];
        bars[1] = Some(Bar::Memory {
            base: 0xfe00_0000,
            size: 0x4000,
            prefetchable: false,
            wide: false,
        });
        let m = Msix {
            offset: 0x50,
            table_size: 4,
            table_bar: 1,
            table_offset: 0x3fc0,
            pba_bar: 1,
            pba_offset: 0x3800,
        };
        assert_eq!(m.entry_address(&bars, 3), Some(0xfe00_3ff0));
        assert_eq!(m.entry_address(&bars, 4), None, "past the table");
        // A table offset past the BAR could point the kernel's write at RAM.
        let past = Msix {
            table_offset: 0x3ff8,
            ..m
        };
        assert_eq!(past.entry_address(&bars, 0), None);
        let far = Msix {
            table_offset: 0x8000_0000,
            ..m
        };
        assert_eq!(far.entry_address(&bars, 0), None);
        assert_eq!(Msix { table_bar: 2, ..m }.entry_address(&bars, 0), None);
    }
}
