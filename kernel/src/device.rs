//! Devices handed to user-space drivers (M2.9,
//! [drivers.md](../../docs/architecture/drivers.md)).
//!
//! A [`DeviceHandle`] is the object behind a `Device` capability: one PCI
//! function, granted to one driver at a time. Granting it turns on memory
//! decoding and bus mastering. The handle owns the DMA buffers allocated
//! for the device. When its last
//! reference goes, it first turns bus mastering off and masks MSI-X, and
//! only then frees those buffers, so the device can never write to memory
//! that has been reused. Each buffer also records the process that
//! allocated it: when that process ends, bus mastering is turned off and
//! its buffers are freed, so a restarted driver does not pile up pages
//! (M4.4 review F1); the next `dma_alloc` turns bus mastering on again.
//! [`mmio_range`] decides which BAR ranges a driver
//! may map: never outside a memory BAR, and never the MSI-X table or PBA.
//! Safe Rust.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::mm::raw::IrqMutex;
use crate::pci::{self, Bar};

/// Most DMA pages one device may hold at a time.
pub const MAX_DMA_PAGES: usize = 64;
/// Most device register pages one process may map in all, which bounds
/// the page tables a driver can make the kernel allocate.
pub const MAX_MMIO_PAGES: u64 = 256;
/// Most pages one `dma_alloc` call may ask for.
pub const MAX_DMA_ALLOC: usize = 16;
const PAGE: u64 = 4096;

/// Why a BAR range may not be mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioError {
    /// No memory BAR with that index.
    NoBar,
    /// Offset or length not page-aligned, or length 0.
    Misaligned,
    /// The range runs past the BAR.
    OutOfRange,
    /// The range touches a page of the MSI-X table or PBA.
    Msix,
}

/// The physical address of `len` bytes at `offset` in memory BAR `bar` of
/// `device`, if a driver may map them.
pub fn mmio_range(device: &pci::Device, bar: u64, offset: u64, len: u64) -> Result<u64, MmioError> {
    let Some(Some(Bar::Memory { base, size, .. })) =
        usize::try_from(bar).ok().and_then(|i| device.bars.get(i))
    else {
        return Err(MmioError::NoBar);
    };
    if len == 0 || offset % PAGE != 0 || len % PAGE != 0 {
        return Err(MmioError::Misaligned);
    }
    let end = offset.checked_add(len).ok_or(MmioError::OutOfRange)?;
    if end > *size {
        return Err(MmioError::OutOfRange);
    }
    if let Some(m) = device.msix {
        let table = (
            m.table_bar,
            u64::from(m.table_offset),
            u64::from(m.table_size) * 16,
        );
        let pba_len = u64::from(m.table_size).div_ceil(64) * 8;
        let pba = (m.pba_bar, u64::from(m.pba_offset), pba_len);
        for (b, start, len) in [table, pba] {
            let pages = start / PAGE * PAGE..(start + len).div_ceil(PAGE) * PAGE;
            if u64::from(b) == bar && offset < pages.end && pages.start < end {
                return Err(MmioError::Msix);
            }
        }
    }
    Ok(base + offset)
}

/// One PCI function handed to a driver.
pub struct DeviceHandle {
    pub pci: Arc<pci::Device>,
    /// DMA buffers: (physical address, pages, the process that allocated
    /// it).
    dma: IrqMutex<Vec<(u64, usize, u64)>>,
}

impl core::fmt::Debug for DeviceHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let a = self.pci.address;
        write!(f, "Device({:02x}:{:02x}.{})", a.bus, a.device, a.function)
    }
}

impl DeviceHandle {
    /// A handle without touching the hardware (host tests).
    pub fn new(pci: Arc<pci::Device>) -> Self {
        Self {
            pci,
            dma: IrqMutex::new(Vec::new()),
        }
    }

    /// DMA pages held.
    pub fn dma_pages(&self) -> usize {
        self.dma.lock().iter().map(|&(_, n, _)| n).sum()
    }

    /// True if `pages` more DMA pages stay within [`MAX_DMA_PAGES`].
    pub fn dma_fits(&self, pages: usize) -> bool {
        self.dma_pages() + pages <= MAX_DMA_PAGES
    }

    /// Records a DMA buffer the handle now owns, allocated by process
    /// `owner`.
    pub fn add_dma(&self, phys: u64, pages: usize, owner: u64) {
        self.dma.lock().push((phys, pages, owner));
    }

    /// Takes the buffers process `owner` allocated, to be freed once the
    /// device can no longer reach them.
    pub fn take_owned(&self, owner: u64) -> Vec<(u64, usize)> {
        let mut dma = self.dma.lock();
        let (mine, rest): (Vec<_>, Vec<_>) = dma.drain(..).partition(|b| b.2 == owner);
        *dma = rest;
        mine.into_iter().map(|(p, n, _)| (p, n)).collect()
    }
}

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::pci as hw;
    use crate::mm::frame::Frame;

    /// Functions with a live handle: each is granted to one driver at a
    /// time.
    static GRANTED: IrqMutex<Vec<hw::Address>> = IrqMutex::new(Vec::new());

    impl DeviceHandle {
        /// Hands `pci` to a driver: turns memory decoding and bus mastering
        /// on. `None` if the function already has a live handle (until that
        /// handle's last reference, including pins, is gone).
        pub fn grant(pci: Arc<pci::Device>) -> Option<Arc<Self>> {
            {
                let mut granted = GRANTED.lock();
                if granted.contains(&pci.address) {
                    return None;
                }
                granted.push(pci.address);
            }
            hw::set_enabled(pci.address, true);
            Some(Arc::new(Self::new(pci)))
        }
    }

    impl DeviceHandle {
        /// Stops the device: no more DMA or MSI writes. Its buffers stay
        /// allocated until the handle is dropped.
        pub fn stop(&self) {
            hw::set_enabled(self.pci.address, false);
            if let Some(m) = self.pci.msix {
                hw::set_msix_control(self.pci.address, m.offset, false, true);
            }
        }
    }

    fn free(buffers: impl IntoIterator<Item = (u64, usize)>) {
        if let Some(frames) = crate::mm::frames().as_mut() {
            for (phys, pages) in buffers {
                if let Some(frame) = Frame::from_addr(phys) {
                    let _ = frames.free_contiguous(frame, pages);
                }
            }
        }
    }

    impl DeviceHandle {
        /// Process `owner` has ended (review F1): if it allocated buffers,
        /// bus mastering goes off (no DMA can reach them) and they are
        /// freed. Memory decoding stays on, so the next driver can reset
        /// the device through its registers before its first `dma_alloc`
        /// turns bus mastering on again ([`Self::master`]).
        pub fn release_from(&self, owner: u64) {
            let mine = self.take_owned(owner);
            if mine.is_empty() {
                return;
            }
            hw::set_bus_master(self.pci.address, false);
            free(mine);
        }

        /// Turns bus mastering on (a `dma_alloc`: the driver now has
        /// buffers the device may use).
        pub fn master(&self) {
            hw::set_bus_master(self.pci.address, true);
        }

        /// Turns bus mastering off and keeps memory decoding: a hot-added
        /// device has no buffers until its driver asks (review F3).
        pub fn unmaster(&self) {
            hw::set_bus_master(self.pci.address, false);
        }
    }

    impl Drop for DeviceHandle {
        fn drop(&mut self) {
            // Stop the device first: no more DMA or MSI writes.
            self.stop();
            // Only now may its buffers be reused.
            let buffers = core::mem::take(&mut *self.dma.lock());
            free(buffers.into_iter().map(|(p, n, _)| (p, n)));
            // Stopped and its memory freed: it may be granted again.
            GRANTED.lock().retain(|a| *a != self.pci.address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::{Address, Msix};

    fn device() -> pci::Device {
        let mut bars = [None; 6];
        bars[1] = Some(Bar::Memory {
            base: 0xfebf_0000,
            size: 0x1000,
            prefetchable: false,
            wide: false,
        });
        bars[2] = Some(Bar::Io {
            base: 0xc000,
            size: 0x40,
        });
        bars[4] = Some(Bar::Memory {
            base: 0xc0_0000_0000,
            size: 0x4000,
            prefetchable: true,
            wide: true,
        });
        pci::Device {
            address: Address {
                bus: 0,
                device: 3,
                function: 0,
            },
            vendor: 0x1af4,
            device: 0x1042,
            class: [1, 0, 0],
            bars,
            capabilities: Vec::new(),
            capability_error: None,
            msix: Some(Msix {
                offset: 0x98,
                table_size: 2,
                table_bar: 1,
                table_offset: 0,
                pba_bar: 1,
                pba_offset: 0x800,
            }),
        }
    }

    #[test]
    fn maps_only_whole_pages_inside_a_memory_bar() {
        let d = device();
        assert_eq!(mmio_range(&d, 4, 0, 0x4000), Ok(0xc0_0000_0000));
        assert_eq!(mmio_range(&d, 4, 0x3000, 0x1000), Ok(0xc0_0000_3000));
        assert_eq!(
            mmio_range(&d, 4, 0x3000, 0x2000),
            Err(MmioError::OutOfRange)
        );
        assert_eq!(
            mmio_range(&d, 4, u64::MAX - 0xfff, 0x1000),
            Err(MmioError::OutOfRange)
        );
        assert_eq!(mmio_range(&d, 4, 0x10, 0x1000), Err(MmioError::Misaligned));
        assert_eq!(mmio_range(&d, 4, 0, 0x10), Err(MmioError::Misaligned));
        assert_eq!(mmio_range(&d, 4, 0, 0), Err(MmioError::Misaligned));
        assert_eq!(
            mmio_range(&d, 0, 0, 0x1000),
            Err(MmioError::NoBar),
            "absent"
        );
        assert_eq!(
            mmio_range(&d, 2, 0, 0x1000),
            Err(MmioError::NoBar),
            "I/O BAR"
        );
        assert_eq!(
            mmio_range(&d, 5, 0, 0x1000),
            Err(MmioError::NoBar),
            "upper half"
        );
        assert_eq!(mmio_range(&d, 6, 0, 0x1000), Err(MmioError::NoBar));
        assert_eq!(mmio_range(&d, u64::MAX, 0, 0x1000), Err(MmioError::NoBar));
    }

    #[test]
    fn never_maps_the_msix_table_or_pba() {
        let mut d = device();
        assert_eq!(
            mmio_range(&d, 1, 0, 0x1000),
            Err(MmioError::Msix),
            "table page"
        );
        // Table and PBA in different pages of a bigger BAR.
        d.bars[1] = Some(Bar::Memory {
            base: 0xfebf_0000,
            size: 0x4000,
            prefetchable: false,
            wide: false,
        });
        d.msix = d.msix.map(|m| Msix {
            pba_offset: 0x2000,
            ..m
        });
        assert_eq!(
            mmio_range(&d, 1, 0x1000, 0x1000),
            Ok(0xfebf_1000),
            "between them"
        );
        assert_eq!(
            mmio_range(&d, 1, 0x2000, 0x1000),
            Err(MmioError::Msix),
            "PBA page"
        );
        assert_eq!(
            mmio_range(&d, 1, 0x1000, 0x2000),
            Err(MmioError::Msix),
            "runs into the PBA"
        );
        assert_eq!(mmio_range(&d, 1, 0x3000, 0x1000), Ok(0xfebf_3000));
    }

    #[test]
    fn dma_page_limit() {
        let h = DeviceHandle::new(Arc::new(device()));
        assert!(h.dma_fits(MAX_DMA_PAGES));
        h.add_dma(0x10_0000, 60, 7);
        assert!(h.dma_fits(4) && !h.dma_fits(5));
        assert_eq!(h.dma_pages(), 60);
    }

    #[test]
    fn an_ended_process_gives_back_only_its_own_buffers() {
        let h = DeviceHandle::new(Arc::new(device()));
        h.add_dma(0x10_0000, 4, 7);
        h.add_dma(0x20_0000, 2, 8);
        h.add_dma(0x30_0000, 1, 7);
        assert_eq!(h.take_owned(9), std::vec![], "a process with none");
        assert_eq!(h.take_owned(7), std::vec![(0x10_0000, 4), (0x30_0000, 1)]);
        assert_eq!(h.dma_pages(), 2);
        // A restarted driver can allocate again: 16 starts of 4 pages
        // fit only if each start's pages come back (review F1).
        for start in 0..20 {
            assert!(h.dma_fits(4), "start {start}");
            h.add_dma(0x40_0000, 4, 100 + start);
            assert_eq!(h.take_owned(100 + start).len(), 1);
        }
    }
}
