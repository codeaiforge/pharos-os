//! DMA isolation with VT-d (iommu.md, #242): the translation tables and
//! the encodings of the unit's registers, as safe logic host-tested here.
//! The register accesses and the frames the tables live in are in
//! `arch::x86_64::iommu`.
//!
//! Legacy (not scalable) mode, as QEMU's `intel-iommu` defaults to:
//!
//! - the root table: 256 entries of 16 bytes, one per bus, each pointing at
//!   that bus's context table;
//! - a context table: 256 entries of 16 bytes, one per device and function,
//!   each naming a domain: its second-level table and its domain ID;
//! - a domain's second-level table: 3 levels (39-bit addresses) or 4
//!   (48-bit), as `CAP.SAGAW` allows, 512 entries of 8 bytes per table.
//!
//! An entry that is not present blocks the device's DMA, and the unit
//! records a fault. With every root entry absent, no device reaches memory.

use alloc::vec::Vec;

/// Bytes per page and per table.
pub const PAGE: u64 = 4096;

/// Register offsets in a unit's 4 KiB register page (VT-d 3.x, 11.4).
pub mod reg {
    pub const CAP: u64 = 0x08;
    pub const ECAP: u64 = 0x10;
    pub const GCMD: u64 = 0x18;
    pub const GSTS: u64 = 0x1c;
    pub const RTADDR: u64 = 0x20;
    pub const CCMD: u64 = 0x28;
    pub const FSTS: u64 = 0x34;
}

/// `GCMD` and `GSTS` bits.
pub const GCMD_TE: u32 = 1 << 31;
pub const GCMD_SRTP: u32 = 1 << 30;
/// `GSTS` bits that are one-shot commands in `GCMD` (SRTP, SFL, WBF,
/// SIRTP): masked out of the status before a command is written, so an
/// update of one bit does not repeat them (VT-d 11.4.4).
pub const GSTS_ONE_SHOT: u32 = (1 << 30) | (1 << 29) | (1 << 27) | (1 << 24);
/// `CCMD`: invalidate the context cache, globally.
pub const CCMD_ICC: u64 = 1 << 63;
pub const CCMD_GLOBAL: u64 = 1 << 61;
/// The IOTLB invalidate register: invalidate, globally, draining reads and
/// writes first.
pub const IOTLB_IVT: u64 = 1 << 63;
pub const IOTLB_GLOBAL: u64 = 1 << 60;
pub const IOTLB_DRAIN: u64 = (1 << 49) | (1 << 48);
/// `FSTS`: primary fault overflow (write 1 to clear) and primary fault
/// pending.
pub const FSTS_PFO: u32 = 1 << 0;
pub const FSTS_PPF: u32 = 1 << 1;

/// What a unit's `CAP` and `ECAP` registers say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Table levels the kernel uses: 3 (39-bit) if the unit supports them,
    /// else 4 (48-bit).
    pub levels: u32,
    /// Domain IDs the unit supports.
    pub domains: u32,
    /// The unit needs a write-buffer flush after table updates.
    pub write_buffer_flush: bool,
    /// Offset of the first fault-recording register, and their count.
    pub fault_offset: u64,
    pub fault_registers: u32,
    /// Offset of the IOTLB invalidate register.
    pub iotlb_offset: u64,
}

/// Why a unit cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// `CAP.SAGAW` offers neither 3- nor 4-level tables.
    TableLevels(u64),
}

impl Capabilities {
    pub fn decode(cap: u64, ecap: u64) -> Result<Self, Unsupported> {
        let sagaw = (cap >> 8) & 0x1f;
        let levels = if sagaw & 0b010 != 0 {
            3
        } else if sagaw & 0b100 != 0 {
            4
        } else {
            return Err(Unsupported::TableLevels(sagaw));
        };
        Ok(Self {
            levels,
            domains: 1 << (4 + 2 * (cap & 0x7)),
            write_buffer_flush: cap & (1 << 4) != 0,
            fault_offset: ((cap >> 24) & 0x3ff) * 16,
            fault_registers: ((cap >> 40) & 0xff) as u32 + 1,
            iotlb_offset: ((ecap >> 8) & 0x3ff) * 16 + 8,
        })
    }
}

/// A fault the unit recorded: which device, which page, read or write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Requester ID: bus in bits 15:8, device and function in 7:0.
    pub source: u16,
    /// The page the device tried to reach.
    pub page: u64,
    pub write: bool,
    /// The fault reason (VT-d appendix A), such as 1 (root entry absent).
    pub reason: u8,
}

impl Fault {
    /// Decodes a fault-recording register (`low`: bits 63:0, `high`:
    /// bits 127:64). `None` unless its F bit says it holds a fault.
    pub fn decode(low: u64, high: u64) -> Option<Self> {
        if high & (1 << 63) == 0 {
            return None;
        }
        Some(Self {
            source: high as u16,
            page: low & !(PAGE - 1),
            // T: 0 for a write, 1 for a read.
            write: high & (1 << 62) == 0,
            reason: (high >> 32) as u8,
        })
    }
}

/// The physical frames tables are written in. The kernel's is in
/// `arch::x86_64::iommu`, and flushes each write from the CPU's caches,
/// since a unit may read memory without snooping them (`ECAP.C` 0, as
/// QEMU's); tests use a map.
pub trait Memory {
    /// A zeroed frame, or `None` when memory is exhausted.
    fn alloc(&mut self) -> Option<u64>;
    fn free(&mut self, frame: u64);
    /// Reads or writes the 8-byte word `index` (below 512) of `frame`,
    /// which must be one `alloc` returned and `free` has not taken back.
    fn read(&self, frame: u64, index: usize) -> u64;
    fn write(&mut self, frame: u64, index: usize, value: u64);
}

/// Why a table update failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OutOfMemory,
    /// The device already has a domain, or the page is already mapped.
    InUse,
    /// The address is not page-aligned or beyond what the tables reach.
    BadAddress(u64),
}

const PRESENT: u64 = 1;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
/// Second-level entry bits: read and write.
const READ: u64 = 1 << 0;
const WRITE: u64 = 1 << 1;

/// The root table and, through it, the context tables.
pub struct Tables {
    root: u64,
}

impl Tables {
    /// An empty root table: every device blocked.
    pub fn new(mem: &mut impl Memory) -> Result<Self, Error> {
        Ok(Self {
            root: mem.alloc().ok_or(Error::OutOfMemory)?,
        })
    }

    /// The root table's physical address, for `RTADDR`.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Points device `devfn` on `bus` at `domain`. The caller then
    /// invalidates the context cache, before the device may start DMA.
    pub fn attach(
        &mut self,
        mem: &mut impl Memory,
        bus: u8,
        devfn: u8,
        domain: &Domain,
    ) -> Result<(), Error> {
        let index = usize::from(bus) * 2;
        let mut context = mem.read(self.root, index);
        if context & PRESENT == 0 {
            let frame = mem.alloc().ok_or(Error::OutOfMemory)?;
            context = frame | PRESENT;
            mem.write(self.root, index, context);
        }
        let table = context & ADDRESS;
        let entry = usize::from(devfn) * 2;
        if mem.read(table, entry) & PRESENT != 0 {
            return Err(Error::InUse);
        }
        // The high half (address width, domain ID) first, then the present
        // bit, so the unit never sees half an entry.
        let aw = u64::from(domain.levels - 2); // 1: 3 levels, 2: 4
        mem.write(table, entry + 1, aw | (u64::from(domain.id) << 8));
        // Translation type 0: requests go through the second-level table.
        mem.write(table, entry, domain.root | PRESENT);
        Ok(())
    }

    /// Blocks device `devfn` on `bus` again. Returns whether it had a
    /// domain. The caller then invalidates the context cache and IOTLB.
    pub fn detach(&mut self, mem: &mut impl Memory, bus: u8, devfn: u8) -> bool {
        let context = mem.read(self.root, usize::from(bus) * 2);
        if context & PRESENT == 0 {
            return false;
        }
        let (table, entry) = (context & ADDRESS, usize::from(devfn) * 2);
        let was = mem.read(table, entry) & PRESENT != 0;
        mem.write(table, entry, 0);
        mem.write(table, entry + 1, 0);
        was
    }

    /// The domain ID device `devfn` on `bus` uses, if attached.
    pub fn domain_of(&self, mem: &impl Memory, bus: u8, devfn: u8) -> Option<u16> {
        let context = mem.read(self.root, usize::from(bus) * 2);
        if context & PRESENT == 0 {
            return None;
        }
        let (table, entry) = (context & ADDRESS, usize::from(devfn) * 2);
        (mem.read(table, entry) & PRESENT != 0).then(|| (mem.read(table, entry + 1) >> 8) as u16)
    }
}

/// One device's address space: a second-level table that maps only the
/// pages given to it.
pub struct Domain {
    root: u64,
    id: u16,
    levels: u32,
}

impl Domain {
    pub fn new(mem: &mut impl Memory, id: u16, levels: u32) -> Result<Self, Error> {
        Ok(Self {
            root: mem.alloc().ok_or(Error::OutOfMemory)?,
            id,
            levels,
        })
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    fn check(&self, iova: u64) -> Result<(), Error> {
        let reach = 1u64 << (12 + 9 * self.levels);
        if iova % PAGE != 0 || iova >= reach {
            return Err(Error::BadAddress(iova));
        }
        Ok(())
    }

    fn index(&self, iova: u64, level: u32) -> usize {
        ((iova >> (12 + 9 * (level - 1))) & 511) as usize
    }

    /// Maps the page at `iova` to frame `phys`, readable by the device and
    /// writable if `write`. The caller flushes the write buffer if the unit
    /// needs it, before the device uses the page.
    pub fn map(
        &mut self,
        mem: &mut impl Memory,
        iova: u64,
        phys: u64,
        write: bool,
    ) -> Result<(), Error> {
        self.check(iova)?;
        if phys % PAGE != 0 || phys & !ADDRESS != 0 {
            return Err(Error::BadAddress(phys));
        }
        let mut table = self.root;
        for level in (2..=self.levels).rev() {
            let index = self.index(iova, level);
            let mut entry = mem.read(table, index);
            if entry & READ == 0 {
                entry = mem.alloc().ok_or(Error::OutOfMemory)? | READ | WRITE;
                mem.write(table, index, entry);
            }
            table = entry & ADDRESS;
        }
        let index = self.index(iova, 1);
        if mem.read(table, index) & (READ | WRITE) != 0 {
            return Err(Error::InUse);
        }
        mem.write(table, index, phys | READ | if write { WRITE } else { 0 });
        Ok(())
    }

    /// Unmaps the page at `iova` and returns the frame it mapped. The
    /// caller then invalidates the IOTLB and waits for it before reusing
    /// the frame.
    pub fn unmap(&mut self, mem: &mut impl Memory, iova: u64) -> Option<u64> {
        self.check(iova).ok()?;
        let mut table = self.root;
        for level in (2..=self.levels).rev() {
            let entry = mem.read(table, self.index(iova, level));
            if entry & READ == 0 {
                return None;
            }
            table = entry & ADDRESS;
        }
        let index = self.index(iova, 1);
        let entry = mem.read(table, index);
        if entry & (READ | WRITE) == 0 {
            return None;
        }
        mem.write(table, index, 0);
        Some(entry & ADDRESS)
    }

    /// The frame `iova` maps to and whether the device may write it.
    pub fn translate(&self, mem: &impl Memory, iova: u64) -> Option<(u64, bool)> {
        self.check(iova).ok()?;
        let mut table = self.root;
        for level in (1..=self.levels).rev() {
            let entry = mem.read(table, self.index(iova, level));
            if entry & READ == 0 {
                return None;
            }
            if level == 1 {
                return Some((entry & ADDRESS, entry & WRITE != 0));
            }
            table = entry & ADDRESS;
        }
        None
    }

    /// Frees the domain's tables (not the pages they map). The device must
    /// be detached and the IOTLB invalidated first.
    pub fn destroy(self, mem: &mut impl Memory) {
        fn free(mem: &mut impl Memory, table: u64, level: u32) {
            if level > 1 {
                let children: Vec<u64> = (0..512)
                    .map(|i| mem.read(table, i))
                    .filter(|e| e & READ != 0)
                    .collect();
                for entry in children {
                    free(mem, entry & ADDRESS, level - 1);
                }
            }
            mem.free(table);
        }
        free(mem, self.root, self.levels);
    }
}

#[cfg(target_arch = "x86_64")]
pub use global::*;

#[cfg(target_arch = "x86_64")]
mod global {
    use alloc::vec::Vec;
    use core::fmt;

    use super::{Capabilities, Fault, Tables, Unsupported};
    use crate::acpi::Dmar;
    use crate::arch::x86_64::iommu::{KernelMemory, Unit, UnitError};
    use crate::mm::raw::IrqMutex;

    struct State {
        units: Vec<Unit>,
        tables: Tables,
        // Kept for #243's `attach` and `map`, which write through it.
        #[allow(dead_code)]
        mem: KernelMemory,
    }

    static STATE: IrqMutex<Option<State>> = IrqMutex::new(None);

    /// Why the kernel cannot isolate devices; each refuses the boot.
    #[derive(Debug)]
    pub enum InitError {
        AlreadyStarted,
        NoUnits,
        /// The DMAR lists reserved memory (RMRR) a device needs mapped:
        /// not supported (QEMU has none).
        ReservedRegions(usize),
        /// A unit on a PCI segment other than 0, which the kernel does not
        /// enumerate.
        Segment(u16),
        Unsupported(u64, Unsupported),
        Unit(u64, UnitError),
        OutOfMemory,
    }

    impl fmt::Display for InitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::AlreadyStarted => f.write_str("already started"),
                Self::NoUnits => f.write_str("the DMAR table lists no unit"),
                Self::ReservedRegions(n) => {
                    write!(f, "the DMAR table lists {n} reserved regions (unsupported)")
                }
                Self::Segment(s) => write!(f, "a unit on PCI segment {s} (unsupported)"),
                Self::Unsupported(base, why) => write!(f, "unit at {base:#x}: {why:?}"),
                Self::Unit(base, error) => write!(f, "unit at {base:#x}: {error:?}"),
                Self::OutOfMemory => f.write_str("out of memory for the root table"),
            }
        }
    }

    /// Turns translation on in every unit `dmar` lists, with an empty root
    /// table: no device reaches memory until it is attached (iommu.md).
    /// Call once, before any driver runs. Returns the first unit's
    /// capabilities.
    pub fn init(dmar: &Dmar) -> Result<Capabilities, InitError> {
        let mut state = STATE.lock();
        if state.is_some() {
            return Err(InitError::AlreadyStarted);
        }
        if dmar.reserved_regions > 0 {
            return Err(InitError::ReservedRegions(dmar.reserved_regions));
        }
        if let Some(u) = dmar.units.iter().find(|u| u.segment != 0) {
            return Err(InitError::Segment(u.segment));
        }
        let mut units = Vec::new();
        for u in &dmar.units {
            let unit = Unit::new(u.base).map_err(|e| InitError::Unit(u.base, e))?;
            Capabilities::decode(unit.cap(), unit.ecap())
                .map_err(|why| InitError::Unsupported(u.base, why))?;
            units.push(unit);
        }
        let first = units.first().ok_or(InitError::NoUnits)?;
        let caps = first.capabilities();
        let mut mem = KernelMemory::default();
        let tables = Tables::new(&mut mem).map_err(|_| InitError::OutOfMemory)?;
        for unit in &units {
            unit.enable(tables.root())
                .map_err(|e| InitError::Unit(unit.base(), e))?;
        }
        *state = Some(State { units, tables, mem });
        Ok(caps)
    }

    /// Whether every unit translates, from root table `root` (`None`
    /// before [`init`]).
    pub fn translating() -> Option<(bool, u64)> {
        let state = STATE.lock();
        let state = state.as_ref()?;
        let on = state
            .units
            .iter()
            .all(|u| u.translating() && u.root_table() == state.tables.root());
        Some((on, state.tables.root()))
    }

    /// The faults the units recorded since the last call, cleared.
    pub fn take_faults() -> Vec<Fault> {
        STATE.lock().as_ref().map_or_else(Vec::new, |s| {
            s.units.iter().flat_map(Unit::take_faults).collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    #[derive(Default)]
    struct Fake {
        frames: BTreeMap<u64, [u64; 512]>,
        next: u64,
        limit: Option<usize>,
    }

    impl Memory for Fake {
        fn alloc(&mut self) -> Option<u64> {
            if self.limit.is_some_and(|l| self.frames.len() >= l) {
                return None;
            }
            self.next += PAGE;
            self.frames.insert(0x10_0000 + self.next, [0; 512]);
            Some(0x10_0000 + self.next)
        }
        fn free(&mut self, frame: u64) {
            assert!(
                self.frames.remove(&frame).is_some(),
                "double free {frame:#x}"
            );
        }
        fn read(&self, frame: u64, index: usize) -> u64 {
            self.frames[&frame][index]
        }
        fn write(&mut self, frame: u64, index: usize, value: u64) {
            self.frames.get_mut(&frame).expect("not a table frame")[index] = value;
        }
    }

    /// QEMU 8.2's `intel-iommu` defaults, as its registers read.
    const QEMU_CAP: u64 = 0x00d2_008c_2226_0206;
    const QEMU_ECAP: u64 = 0x0f42;

    #[test]
    fn decodes_the_capabilities() {
        let c = Capabilities::decode(QEMU_CAP, QEMU_ECAP).unwrap();
        assert_eq!(c.levels, 3);
        assert_eq!(c.domains, 65536);
        assert!(!c.write_buffer_flush);
        assert_eq!(c.fault_offset, 0x220);
        assert_eq!(c.fault_registers, 1);
        assert_eq!(c.iotlb_offset, 0xf8);
        // 48-bit only: 4 levels; neither: unusable.
        assert_eq!(
            Capabilities::decode(4 << 8, 1).unwrap().levels,
            4,
            "SAGAW bit 2"
        );
        assert_eq!(
            Capabilities::decode(1 << 8, 1),
            Err(Unsupported::TableLevels(1))
        );
    }

    #[test]
    fn decodes_a_fault_record() {
        assert_eq!(Fault::decode(0x1234_5678, 0), None, "F clear");
        let high = (1 << 63) | (1 << 62) | (2 << 32) | 0x0018;
        assert_eq!(
            Fault::decode(0x0123_4567, high),
            Some(Fault {
                source: 0x18,
                page: 0x0123_4000,
                write: false,
                reason: 2
            })
        );
        assert!(Fault::decode(0, 1 << 63).unwrap().write);
    }

    #[test]
    fn a_new_root_table_blocks_every_device() {
        let mut mem = Fake::default();
        let tables = Tables::new(&mut mem).unwrap();
        assert!(mem.frames[&tables.root()].iter().all(|&e| e == 0));
        for bus in [0, 1, 255] {
            assert_eq!(tables.domain_of(&mem, bus, 0x18), None);
        }
    }

    #[test]
    fn attach_writes_the_root_and_context_entries() {
        let mut mem = Fake::default();
        let mut tables = Tables::new(&mut mem).unwrap();
        let domain = Domain::new(&mut mem, 3, 3).unwrap();
        tables.attach(&mut mem, 0, 0x18, &domain).unwrap();
        let root_entry = mem.read(tables.root(), 0);
        assert_eq!(root_entry & 1, 1, "bus 0 present");
        assert_eq!(mem.read(tables.root(), 1), 0, "high half reserved");
        let context = root_entry & ADDRESS;
        let (lo, hi) = (mem.read(context, 0x30), mem.read(context, 0x31));
        assert_eq!(lo, domain.root | 1, "second-level pointer, present, TT 0");
        assert_eq!(hi, 1 | (3 << 8), "AW 1 (39-bit), domain 3");
        assert_eq!(tables.domain_of(&mem, 0, 0x18), Some(3));
        assert_eq!(tables.domain_of(&mem, 0, 0x19), None, "only that function");
        assert_eq!(
            tables.attach(&mut mem, 0, 0x18, &domain),
            Err(Error::InUse),
            "one domain per device"
        );
        // A second device on the bus shares its context table.
        let frames = mem.frames.len();
        tables.attach(&mut mem, 0, 0x20, &domain).unwrap();
        assert_eq!(mem.frames.len(), frames);

        assert!(tables.detach(&mut mem, 0, 0x18));
        assert_eq!((mem.read(context, 0x30), mem.read(context, 0x31)), (0, 0));
        assert!(!tables.detach(&mut mem, 0, 0x18));
        assert!(!tables.detach(&mut mem, 7, 0x18), "bus without a table");
    }

    #[test]
    fn a_domain_maps_only_its_pages() {
        for levels in [3, 4] {
            let mut mem = Fake::default();
            let mut d = Domain::new(&mut mem, 1, levels).unwrap();
            d.map(&mut mem, 0x20_0000, 0x20_0000, true).unwrap();
            d.map(&mut mem, 0x3fff_f000, 0x3fff_f000, false).unwrap();
            assert_eq!(d.translate(&mem, 0x20_0000), Some((0x20_0000, true)));
            assert_eq!(d.translate(&mem, 0x3fff_f000), Some((0x3fff_f000, false)));
            assert_eq!(d.translate(&mem, 0x20_1000), None, "the next page");
            assert_eq!(d.translate(&mem, 0x1f_f000), None, "the page before");
            assert_eq!(
                d.map(&mut mem, 0x20_0000, 0x30_0000, true),
                Err(Error::InUse)
            );
            assert_eq!(d.unmap(&mut mem, 0x20_0000), Some(0x20_0000));
            assert_eq!(d.translate(&mem, 0x20_0000), None);
            assert_eq!(d.unmap(&mut mem, 0x20_0000), None);
            d.destroy(&mut mem);
            assert!(mem.frames.is_empty(), "every table freed ({levels} levels)");
        }
    }

    #[test]
    fn page_entries_are_encoded_as_the_specification_says() {
        let mut mem = Fake::default();
        let mut d = Domain::new(&mut mem, 1, 3).unwrap();
        // Indices 1, 2, 3 at levels 3, 2, 1.
        let iova = (1 << 30) | (2 << 21) | (3 << 12);
        d.map(&mut mem, iova, 0x7654_3000, true).unwrap();
        let l3 = mem.read(d.root, 1);
        assert_eq!(l3 & 3, 3, "non-leaf: read and write");
        let l2 = mem.read(l3 & ADDRESS, 2);
        assert_eq!(l2 & 3, 3);
        assert_eq!(mem.read(l2 & ADDRESS, 3), 0x7654_3000 | 3);
        d.map(&mut mem, iova + PAGE, 0x7654_4000, false).unwrap();
        assert_eq!(mem.read(l2 & ADDRESS, 4), 0x7654_4000 | 1, "read only");
    }

    #[test]
    fn bad_addresses_are_refused() {
        let mut mem = Fake::default();
        let mut d = Domain::new(&mut mem, 1, 3).unwrap();
        assert_eq!(
            d.map(&mut mem, 0x1001, 0x1000, true),
            Err(Error::BadAddress(0x1001))
        );
        assert_eq!(
            d.map(&mut mem, 1 << 39, 0x1000, true),
            Err(Error::BadAddress(1 << 39)),
            "beyond 39 bits"
        );
        assert_eq!(
            d.map(&mut mem, 0x1000, 0x1008, true),
            Err(Error::BadAddress(0x1008))
        );
        assert_eq!(
            d.map(&mut mem, 0x1000, 1 << 52, true),
            Err(Error::BadAddress(1 << 52))
        );
        assert_eq!(d.unmap(&mut mem, 1 << 39), None);
    }

    #[test]
    fn out_of_memory_is_reported() {
        let mut mem = Fake {
            limit: Some(2),
            ..Fake::default()
        };
        let mut d = Domain::new(&mut mem, 1, 3).unwrap();
        assert_eq!(
            d.map(&mut mem, 0x1000, 0x1000, true),
            Err(Error::OutOfMemory)
        );
    }
}
