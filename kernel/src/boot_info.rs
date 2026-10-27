//! Interpreting boot information. Hardware-independent, so it is unit-tested
//! on the host.

use crate::limine::{MEMMAP_BOOTLOADER_RECLAIMABLE, MEMMAP_EXECUTABLE_AND_MODULES, MEMMAP_USABLE};

/// Name of a Limine firmware type ("Firmware Type Feature").
pub fn firmware_name(firmware_type: u64) -> &'static str {
    match firmware_type {
        0 => "x86 BIOS",
        1 => "UEFI (32-bit)",
        2 => "UEFI (64-bit)",
        3 => "SBI",
        _ => "unknown",
    }
}

/// Totals over the memory map, for reporting.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MemorySummary {
    pub entries: usize,
    pub usable_regions: usize,
    pub usable_bytes: u64,
    pub reclaimable_bytes: u64,
    pub kernel_bytes: u64,
}

/// Summarizes memory map entries given as `(kind, length)` pairs. Totals
/// saturate instead of overflowing, so a malformed map cannot cause a panic.
pub fn summarize<I: IntoIterator<Item = (u64, u64)>>(entries: I) -> MemorySummary {
    let mut summary = MemorySummary::default();
    for (kind, length) in entries {
        summary.entries += 1;
        match kind {
            MEMMAP_USABLE => {
                summary.usable_regions += 1;
                summary.usable_bytes = summary.usable_bytes.saturating_add(length);
            }
            MEMMAP_BOOTLOADER_RECLAIMABLE => {
                summary.reclaimable_bytes = summary.reclaimable_bytes.saturating_add(length);
            }
            MEMMAP_EXECUTABLE_AND_MODULES => {
                summary.kernel_bytes = summary.kernel_bytes.saturating_add(length);
            }
            _ => {}
        }
    }
    summary
}

/// Converts bytes to whole mebibytes (rounded down).
pub fn mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_firmware_types() {
        assert_eq!(firmware_name(0), "x86 BIOS");
        assert_eq!(firmware_name(2), "UEFI (64-bit)");
        assert_eq!(firmware_name(99), "unknown");
    }

    #[test]
    fn summarizes_by_kind() {
        let map = [
            (MEMMAP_USABLE, 0x9f000),
            (1, 0x1000), // reserved
            (MEMMAP_USABLE, 0x7ee0000),
            (MEMMAP_BOOTLOADER_RECLAIMABLE, 0x20000),
            (MEMMAP_EXECUTABLE_AND_MODULES, 0x5000),
        ];
        assert_eq!(
            summarize(map),
            MemorySummary {
                entries: 5,
                usable_regions: 2,
                usable_bytes: 0x9f000 + 0x7ee0000,
                reclaimable_bytes: 0x20000,
                kernel_bytes: 0x5000,
            }
        );
    }

    #[test]
    fn empty_and_overflowing_maps() {
        assert_eq!(summarize([]), MemorySummary::default());
        let huge = summarize([(MEMMAP_USABLE, u64::MAX), (MEMMAP_USABLE, 1)]);
        assert_eq!(huge.usable_bytes, u64::MAX);
    }

    #[test]
    fn converts_to_mib() {
        assert_eq!(mib(256 * 1024 * 1024), 256);
        assert_eq!(mib(1024 * 1024 - 1), 0);
    }
}
