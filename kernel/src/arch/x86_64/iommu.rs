//! A VT-d unit's registers and the frames its tables live in (iommu.md,
//! #242). The encodings and the tables are safe logic in `crate::iommu`;
//! this module only reads and writes the unit's register page (through
//! the kernel's uncached device mapping) and the table frames (through the
//! direct map).
//!
//! 64-bit registers are accessed as two 32-bit halves, low first: a
//! command's trigger bit (`CCMD.ICC`, `IOTLB.IVT`) is in the high half, so
//! the command starts only once both are written (VT-d 11.4).

#![allow(unsafe_code)]

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::paging::{self, MapError, mmio_read32, mmio_write32};
use crate::iommu::{
    CCMD_GLOBAL, CCMD_ICC, Capabilities, FSTS_PFO, FSTS_PPF, Fault, GCMD_SRTP, GCMD_TE,
    GSTS_ONE_SHOT, IOTLB_DRAIN, IOTLB_GLOBAL, IOTLB_IVT, Memory, PAGE, reg,
};
use crate::mm::frame::Frame;

/// Why a unit did not do what it was told.
#[derive(Debug, PartialEq, Eq)]
pub enum UnitError {
    /// Its register page could not be mapped.
    Map(MapError),
    /// A status bit did not change in time (the named register).
    Timeout(&'static str),
}

impl From<MapError> for UnitError {
    fn from(error: MapError) -> Self {
        Self::Map(error)
    }
}

/// Polls of a status bit before giving up. QEMU completes every command
/// before the write returns; hardware within microseconds.
const POLLS: u32 = 1_000_000;

/// One VT-d unit, at the register base its DMAR entry names.
pub struct Unit {
    base: u64,
    cap: u64,
    ecap: u64,
}

impl Unit {
    pub fn new(base: u64) -> Result<Self, UnitError> {
        let mut unit = Self {
            base,
            cap: 0,
            ecap: 0,
        };
        unit.cap = unit.read64(reg::CAP)?;
        unit.ecap = unit.read64(reg::ECAP)?;
        Ok(unit)
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn cap(&self) -> u64 {
        self.cap
    }

    pub fn ecap(&self) -> u64 {
        self.ecap
    }

    /// The decoded capabilities. Only for a unit `crate::iommu::init`
    /// accepted, so decoding cannot fail.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities::decode(self.cap, self.ecap).expect("checked by iommu::init")
    }

    fn read32(&self, offset: u64) -> Result<u32, UnitError> {
        Ok(mmio_read32(self.base + offset)?)
    }

    fn write32(&self, offset: u64, value: u32) -> Result<(), UnitError> {
        Ok(mmio_write32(self.base + offset, value)?)
    }

    fn read64(&self, offset: u64) -> Result<u64, UnitError> {
        let low = self.read32(offset)?;
        Ok(u64::from(low) | u64::from(self.read32(offset + 4)?) << 32)
    }

    fn write64(&self, offset: u64, value: u64) -> Result<(), UnitError> {
        self.write32(offset, value as u32)?;
        self.write32(offset + 4, (value >> 32) as u32)
    }

    /// Polls `offset` until `done` holds for its value.
    fn wait(
        &self,
        offset: u64,
        name: &'static str,
        done: impl Fn(u64) -> bool,
    ) -> Result<(), UnitError> {
        for _ in 0..POLLS {
            if done(self.read64(offset)?) {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(UnitError::Timeout(name))
    }

    /// Sets one `GCMD` bit, keeping the others enabled, and waits for
    /// `GSTS` to show it.
    fn command(&self, bit: u32, name: &'static str) -> Result<(), UnitError> {
        let status = self.read32(reg::GSTS)? & !GSTS_ONE_SHOT;
        self.write32(reg::GCMD, status | bit)?;
        self.wait(reg::GSTS, name, |s| s as u32 & bit != 0)
    }

    /// Installs root table `root` and turns translation on: from here, a
    /// device reaches only what its context entry maps (VT-d 6.6 order:
    /// root pointer, then invalidations, then enable).
    pub fn enable(&self, root: u64) -> Result<(), UnitError> {
        self.write64(reg::RTADDR, root)?; // legacy mode: TTM 0
        self.command(GCMD_SRTP, "GSTS.RTPS")?;
        self.invalidate_context()?;
        self.invalidate_iotlb()?;
        self.command(GCMD_TE, "GSTS.TES")
    }

    /// Invalidates every cached context entry, and waits.
    pub fn invalidate_context(&self) -> Result<(), UnitError> {
        // ponytail: global invalidation; device-selective if drivers start often.
        self.write64(reg::CCMD, CCMD_ICC | CCMD_GLOBAL)?;
        self.wait(reg::CCMD, "CCMD.ICC", |v| v & CCMD_ICC == 0)
    }

    /// Invalidates every cached translation, after draining the device
    /// reads and writes in flight, and waits: once this returns, no device
    /// reaches a page the tables no longer map.
    pub fn invalidate_iotlb(&self) -> Result<(), UnitError> {
        let offset = self.capabilities().iotlb_offset;
        self.write64(offset, IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DRAIN)?;
        self.wait(offset, "IOTLB.IVT", |v| v & IOTLB_IVT == 0)
    }

    /// Whether translation is on (`GSTS.TES`).
    pub fn translating(&self) -> bool {
        self.read32(reg::GSTS).is_ok_and(|s| s & GCMD_TE != 0)
    }

    /// The root table the unit uses (`RTADDR`).
    pub fn root_table(&self) -> u64 {
        self.read64(reg::RTADDR).map_or(0, |a| a & !(PAGE - 1))
    }

    /// Reads and clears every recorded fault, then the overflow flag.
    pub fn take_faults(&self) -> Vec<Fault> {
        let caps = self.capabilities();
        let mut faults = Vec::new();
        if self
            .read32(reg::FSTS)
            .is_ok_and(|s| s & (FSTS_PPF | FSTS_PFO) != 0)
        {
            for i in 0..u64::from(caps.fault_registers) {
                let at = caps.fault_offset + i * 16;
                let (Ok(low), Ok(high)) = (self.read64(at), self.read64(at + 8)) else {
                    break;
                };
                if let Some(fault) = Fault::decode(low, high) {
                    faults.push(fault);
                    // F is write-1-to-clear, in the top dword.
                    let _ = self.write32(at + 12, 1 << 31);
                }
            }
            let _ = self.write32(reg::FSTS, FSTS_PFO);
        }
        faults
    }
}

/// The frames the kernel's VT-d tables live in. Writes go only to frames
/// it allocated and still owns, so a table bug cannot write other memory.
/// Each write, and each new frame's zeroing, is flushed from the CPU's
/// caches before the caller tells the unit: a unit that does not snoop
/// them (`ECAP.C` 0, as QEMU's) reads memory directly (VT-d 6.1).
#[derive(Default)]
pub struct KernelMemory {
    owned: BTreeSet<u64>,
}

impl KernelMemory {
    fn word(&self, frame: u64, index: usize) -> *mut u64 {
        assert!(
            self.owned.contains(&frame) && index < 512,
            "iommu: table access outside its frames ({frame:#x}[{index}])"
        );
        (paging::hhdm() + frame + index as u64 * 8) as *mut u64
    }
}

impl Memory for KernelMemory {
    fn alloc(&mut self) -> Option<u64> {
        let frame = crate::mm::frames().as_mut()?.alloc().ok()?.addr();
        // SAFETY: the frame was just allocated, so nothing else uses it,
        // and the direct map covers it writable (usable RAM).
        unsafe { core::ptr::write_bytes((paging::hhdm() + frame) as *mut u8, 0, PAGE as usize) };
        for line in (0..PAGE).step_by(64) {
            flush(paging::hhdm() + frame + line);
        }
        self.owned.insert(frame);
        Some(frame)
    }

    fn free(&mut self, frame: u64) {
        assert!(
            self.owned.remove(&frame),
            "iommu: freeing {frame:#x}, not a table"
        );
        if let (Some(frames), Some(f)) = (crate::mm::frames().as_mut(), Frame::from_addr(frame)) {
            let _ = frames.free(f);
        }
    }

    fn read(&self, frame: u64, index: usize) -> u64 {
        // SAFETY: `word` checked that `frame` is a table frame this owns
        // (allocated above, covered by the direct map) and `index < 512`.
        unsafe { self.word(frame, index).read_volatile() }
    }

    fn write(&mut self, frame: u64, index: usize, value: u64) {
        // SAFETY: as in `read`; `&mut self` serializes writers, and the
        // unit only reads the tables.
        unsafe { self.word(frame, index).write_volatile(value) }
        flush(self.word(frame, index) as u64);
    }
}

/// Writes the cache line holding `virt` back to memory, and waits for it.
fn flush(virt: u64) {
    // SAFETY: callers pass a direct-map address of a table frame this
    // module owns; `clflush` and `mfence` change no memory contents.
    unsafe {
        core::arch::x86_64::_mm_clflush(virt as *const u8);
        core::arch::x86_64::_mm_mfence();
    }
}
