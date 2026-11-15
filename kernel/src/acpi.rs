//! The ACPI tables the kernel reads (#241, [iommu.md]): the walk from the
//! RSDP to the XSDT (or RSDT), and the DMAR table, which names the VT-d
//! units the IOMMU driver programs.
//!
//! Firmware tables are trusted as the firmware is, but still checked: every
//! table's length is bounded and its checksum verified, and every structure
//! and device scope inside DMAR must fit in its parent. A bad table is an
//! error, never a panic. The reads go through [`Memory`], so the host tests
//! (and the fuzz test) feed the parser made-up memory. Safe Rust.
//!
//! [iommu.md]: ../../docs/architecture/iommu.md

use alloc::vec;
use alloc::vec::Vec;

/// Physical memory as the parser sees it.
pub trait Memory {
    /// Copies `buf.len()` bytes from `phys`; `false` if any is unreadable.
    fn read(&self, phys: u64, buf: &mut [u8]) -> bool;
}

/// Physical memory through the kernel's direct map, which covers the ACPI
/// regions (reserved memory is mapped, paging.rs).
#[cfg(target_arch = "x86_64")]
pub struct DirectMap;

#[cfg(target_arch = "x86_64")]
impl Memory for DirectMap {
    fn read(&self, phys: u64, buf: &mut [u8]) -> bool {
        crate::arch::x86_64::paging::read_phys(phys, buf).is_some()
    }
}

/// The longest table the kernel reads; firmware's are a few KiB.
pub const MAX_TABLE: usize = 64 * 1024;
/// The standard table header: signature, length, revision, checksum, OEM
/// fields, creator.
const HEADER: usize = 36;

/// Why the tables could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Memory at this physical address could not be read.
    Unreadable(u64),
    /// The RSDP's signature or checksum is wrong.
    BadRsdp,
    /// A table's length is below its header or above [`MAX_TABLE`].
    BadLength([u8; 4]),
    /// A table's bytes do not sum to zero.
    BadChecksum([u8; 4]),
    /// A table's contents do not fit its own fields.
    Malformed([u8; 4]),
}

/// One table the root table lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub signature: [u8; 4],
    pub phys: u64,
}

/// `DMAR` flags bit 0, and a DRHD unit's flags bit 0: the unit covers
/// every PCI device on its segment not named by another unit.
pub const INCLUDE_PCI_ALL: u8 = 1;

/// The DMA Remapping table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dmar {
    /// Guest address width the platform supports, in bits.
    pub address_width: u8,
    pub flags: u8,
    pub units: Vec<Unit>,
    /// Reserved memory regions (RMRR) firmware asks to keep mapped for some
    /// devices; QEMU has none, and the driver must refuse to ignore them.
    pub reserved_regions: usize,
}

/// One remapping unit (DRHD).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub flags: u8,
    pub segment: u16,
    /// Physical address of its 4 KiB register page.
    pub base: u64,
    pub scopes: Vec<Scope>,
}

/// A device scope: the devices or bridges a unit covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub kind: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    /// (device, function) per hop from `start_bus`.
    pub path: Vec<(u8, u8)>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn sums_to_zero(b: &[u8]) -> bool {
    b.iter().fold(0u8, |sum, x| sum.wrapping_add(*x)) == 0
}

fn read(mem: &impl Memory, phys: u64, len: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; len];
    if mem.read(phys, &mut buf) {
        Ok(buf)
    } else {
        Err(Error::Unreadable(phys))
    }
}

/// The table at `phys`, checked: its length within its 36-byte header and
/// [`MAX_TABLE`], and its checksum.
pub fn table(mem: &impl Memory, phys: u64) -> Result<Vec<u8>, Error> {
    let header = read(mem, phys, HEADER)?;
    let mut signature = [0; 4];
    signature.copy_from_slice(&header[..4]);
    let len = u32_at(&header, 4).ok_or(Error::BadLength(signature))? as usize;
    if !(HEADER..=MAX_TABLE).contains(&len) {
        return Err(Error::BadLength(signature));
    }
    let bytes = read(mem, phys, len)?;
    if !sums_to_zero(&bytes) {
        return Err(Error::BadChecksum(signature));
    }
    Ok(bytes)
}

/// The root table's address and entry size (8 for the XSDT, 4 for the
/// RSDT) from the RSDP at `rsdp`.
fn root(mem: &impl Memory, rsdp: u64) -> Result<(u64, usize), Error> {
    let v1 = read(mem, rsdp, 20)?;
    if &v1[..8] != b"RSD PTR " || !sums_to_zero(&v1) {
        return Err(Error::BadRsdp);
    }
    // ACPI 2.0 and later: a 36-byte RSDP with the XSDT's 64-bit address.
    if v1[15] >= 2 {
        let v2 = read(mem, rsdp, 36)?;
        let xsdt = u64_at(&v2, 24).ok_or(Error::BadRsdp)?;
        if !sums_to_zero(&v2) {
            return Err(Error::BadRsdp);
        }
        if xsdt != 0 {
            return Ok((xsdt, 8));
        }
    }
    let rsdt = u32_at(&v1, 16).ok_or(Error::BadRsdp)?;
    Ok((u64::from(rsdt), 4))
}

/// Every table the root table lists, from the RSDP at `rsdp`.
pub fn tables(mem: &impl Memory, rsdp: u64) -> Result<Vec<Entry>, Error> {
    let (phys, size) = root(mem, rsdp)?;
    let root = table(mem, phys)?;
    let mut name = [0; 4];
    name.copy_from_slice(&root[..4]);
    let entries = &root[HEADER..];
    if entries.len() % size != 0 {
        return Err(Error::Malformed(name));
    }
    let mut out = Vec::new();
    for at in (0..entries.len()).step_by(size) {
        let phys = if size == 8 {
            u64_at(entries, at)
        } else {
            u32_at(entries, at).map(u64::from)
        }
        .ok_or(Error::Malformed(name))?;
        let head = read(mem, phys, 4)?;
        let mut signature = [0; 4];
        signature.copy_from_slice(&head);
        out.push(Entry { signature, phys });
    }
    Ok(out)
}

/// The first table named `signature`, checked, or `None` if there is none.
pub fn find(mem: &impl Memory, rsdp: u64, signature: &[u8; 4]) -> Result<Option<Vec<u8>>, Error> {
    match tables(mem, rsdp)?
        .iter()
        .find(|e| &e.signature == signature)
    {
        Some(entry) => table(mem, entry.phys).map(Some),
        None => Ok(None),
    }
}

/// Parses a `DMAR` table (as returned by [`table`]).
pub fn parse_dmar(t: &[u8]) -> Result<Dmar, Error> {
    let bad = Error::Malformed(*b"DMAR");
    if t.get(..4) != Some(b"DMAR") {
        return Err(bad);
    }
    // Host address width at 36 is the width minus one; flags at 37; the
    // remapping structures start at 48.
    let address_width = t.get(36).ok_or(bad)?.checked_add(1).ok_or(bad)?;
    let flags = *t.get(37).ok_or(bad)?;
    let mut units = Vec::new();
    let mut reserved_regions = 0;
    let mut at = 48;
    while at < t.len() {
        let kind = u16_at(t, at).ok_or(bad)?;
        let len = usize::from(u16_at(t, at + 2).ok_or(bad)?);
        let body = t.get(at..at.checked_add(len).ok_or(bad)?).ok_or(bad)?;
        if len < 4 {
            return Err(bad);
        }
        match kind {
            0 => units.push(unit(body).ok_or(bad)?),
            1 => reserved_regions += 1,
            // ATSR, RHSA, ANDD, SATC: nothing the driver uses.
            _ => {}
        }
        at += len;
    }
    Ok(Dmar {
        address_width,
        flags,
        units,
        reserved_regions,
    })
}

/// A DRHD structure: flags at 4, segment at 6, register base at 8, device
/// scopes from 16.
fn unit(b: &[u8]) -> Option<Unit> {
    if b.len() < 16 {
        return None;
    }
    let mut scopes = Vec::new();
    let mut at = 16;
    while at < b.len() {
        let len = usize::from(*b.get(at + 1)?);
        let s = b.get(at..at.checked_add(len)?)?;
        // Type, length, 2 reserved, enumeration ID, start bus, then
        // (device, function) pairs.
        if len < 6 || (len - 6) % 2 != 0 {
            return None;
        }
        scopes.push(Scope {
            kind: s[0],
            enumeration_id: s[4],
            start_bus: s[5],
            path: s[6..].chunks_exact(2).map(|p| (p[0], p[1])).collect(),
        });
        at += len;
    }
    Some(Unit {
        flags: b[4],
        segment: u16_at(b, 6)?,
        base: u64_at(b, 8)?,
        scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memory made of a few byte ranges.
    struct Fake(Vec<(u64, Vec<u8>)>);

    impl Memory for Fake {
        fn read(&self, phys: u64, buf: &mut [u8]) -> bool {
            for (base, bytes) in &self.0 {
                let Some(off) = phys.checked_sub(*base) else {
                    continue;
                };
                let off = off as usize;
                if let Some(src) = bytes.get(off..off + buf.len()) {
                    buf.copy_from_slice(src);
                    return true;
                }
            }
            false
        }
    }

    fn fix_checksum(b: &mut [u8], at: usize) {
        b[at] = 0;
        let sum = b.iter().fold(0u8, |s, x| s.wrapping_add(*x));
        b[at] = 0u8.wrapping_sub(sum);
    }

    fn sdt(signature: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = vec![0; HEADER];
        t[..4].copy_from_slice(signature);
        t.extend_from_slice(body);
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        fix_checksum(&mut t, 9);
        t
    }

    fn rsdp_v2(xsdt: u64) -> Vec<u8> {
        let mut r = vec![0; 36];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[15] = 2;
        r[20..24].copy_from_slice(&36u32.to_le_bytes());
        r[24..32].copy_from_slice(&xsdt.to_le_bytes());
        fix_checksum(&mut r[..20], 8);
        fix_checksum(&mut r, 32);
        r
    }

    /// One unit at 0xfed9_0000 covering every device (INCLUDE_PCI_ALL).
    fn dmar() -> Vec<u8> {
        let mut body = vec![38, INCLUDE_PCI_ALL];
        body.extend_from_slice(&[0; 10]);
        let mut drhd = vec![0, 0, 16, 0, INCLUDE_PCI_ALL, 0, 0, 0];
        drhd.extend_from_slice(&0xfed9_0000u64.to_le_bytes());
        body.extend_from_slice(&drhd);
        sdt(b"DMAR", &body)
    }

    fn machine(with_dmar: bool) -> Fake {
        let apic = sdt(b"APIC", &[1, 2, 3, 4]);
        let mut entries = 0x2000u64.to_le_bytes().to_vec();
        if with_dmar {
            entries.extend_from_slice(&0x3000u64.to_le_bytes());
        }
        Fake(vec![
            (0xe0000, rsdp_v2(0x1000)),
            (0x1000, sdt(b"XSDT", &entries)),
            (0x2000, apic),
            (0x3000, dmar()),
        ])
    }

    #[test]
    fn walks_the_xsdt() {
        let names: Vec<_> = tables(&machine(true), 0xe0000)
            .unwrap()
            .iter()
            .map(|e| e.signature)
            .collect();
        assert_eq!(names, [*b"APIC", *b"DMAR"]);
        assert!(find(&machine(false), 0xe0000, b"DMAR").unwrap().is_none());
    }

    #[test]
    fn finds_and_parses_qemus_dmar() {
        let t = find(&machine(true), 0xe0000, b"DMAR").unwrap().unwrap();
        let d = parse_dmar(&t).unwrap();
        assert_eq!(d.address_width, 39);
        assert_eq!(d.reserved_regions, 0);
        assert_eq!(
            d.units,
            [Unit {
                flags: INCLUDE_PCI_ALL,
                segment: 0,
                base: 0xfed9_0000,
                scopes: Vec::new(),
            }]
        );
    }

    #[test]
    fn the_rsdt_serves_acpi_1() {
        let mut r = vec![0; 20];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        fix_checksum(&mut r, 8);
        let mem = Fake(vec![
            (0xe0000, r),
            (0x1000, sdt(b"RSDT", &0x3000u32.to_le_bytes())),
            (0x3000, dmar()),
        ]);
        assert_eq!(tables(&mem, 0xe0000).unwrap()[0].signature, *b"DMAR");
    }

    #[test]
    fn refuses_bad_rsdps_and_tables() {
        let mut m = machine(true);
        m.0[0].1[0] = b'X';
        assert_eq!(tables(&m, 0xe0000), Err(Error::BadRsdp));
        let mut m = machine(true);
        m.0[0].1[33] ^= 1; // extended checksum
        assert_eq!(tables(&m, 0xe0000), Err(Error::BadRsdp));

        let mut m = machine(true);
        m.0[3].1[40] ^= 1; // a byte of DMAR
        assert_eq!(
            find(&m, 0xe0000, b"DMAR"),
            Err(Error::BadChecksum(*b"DMAR"))
        );
        let mut m = machine(true);
        m.0[3].1[4..8].copy_from_slice(&20u32.to_le_bytes());
        assert_eq!(find(&m, 0xe0000, b"DMAR"), Err(Error::BadLength(*b"DMAR")));
        let mut m = machine(true);
        m.0[3].1[4..8].copy_from_slice(&(MAX_TABLE as u32 + 1).to_le_bytes());
        assert_eq!(find(&m, 0xe0000, b"DMAR"), Err(Error::BadLength(*b"DMAR")));
        // Points past the memory there is.
        let mut m = machine(true);
        m.0[1].1[HEADER + 8..HEADER + 16].copy_from_slice(&0x9000u64.to_le_bytes());
        fix_checksum(&mut m.0[1].1, 9);
        assert_eq!(tables(&m, 0xe0000), Err(Error::Unreadable(0x9000)));
        // An XSDT whose entries are not whole.
        let mut m = machine(false);
        m.0[1].1 = sdt(b"XSDT", &[1, 2, 3]);
        assert_eq!(tables(&m, 0xe0000), Err(Error::Malformed(*b"XSDT")));
    }

    #[test]
    fn parses_scopes_and_counts_reserved_regions() {
        let mut t = dmar();
        // A second unit with one endpoint scope, 00:02.0, then an RMRR.
        let mut drhd = vec![0, 0, 24, 0, 0, 0, 0, 0];
        drhd.extend_from_slice(&0xfed9_1000u64.to_le_bytes());
        drhd.extend_from_slice(&[1, 8, 0, 0, 0, 0, 2, 0]);
        t.extend_from_slice(&drhd);
        t.extend_from_slice(&[1, 0, 24, 0]);
        t.extend_from_slice(&[0; 20]);
        let d = parse_dmar(&t).unwrap();
        assert_eq!(d.units.len(), 2);
        assert_eq!(
            d.units[1].scopes,
            [Scope {
                kind: 1,
                enumeration_id: 0,
                start_bus: 0,
                path: vec![(2, 0)],
            }]
        );
        assert_eq!(d.reserved_regions, 1);
    }

    #[test]
    fn refuses_structures_that_do_not_fit() {
        let ok = dmar();
        let at = 48;
        // Structure length 0, 3, past the end, and a DRHD shorter than 16.
        for len in [0u16, 3, 200, 12] {
            let mut t = ok.clone();
            t[at + 2..at + 4].copy_from_slice(&len.to_le_bytes());
            assert_eq!(
                parse_dmar(&t),
                Err(Error::Malformed(*b"DMAR")),
                "length {len}"
            );
        }
        // A scope of length 5, and one with an odd path.
        for len in [5u8, 7] {
            let mut t = ok.clone();
            t[at + 2] = 16 + len;
            t.extend_from_slice(&[1, len, 0, 0, 0, 0, 0]);
            t.truncate(at + 16 + usize::from(len));
            assert_eq!(
                parse_dmar(&t),
                Err(Error::Malformed(*b"DMAR")),
                "scope {len}"
            );
        }
        assert!(parse_dmar(b"APIC").is_err());
        assert!(parse_dmar(&ok[..37]).is_err());
    }

    /// Random changes to a valid table never panic.
    #[test]
    fn fuzz_dmar() {
        let base = {
            let mut t = dmar();
            let mut drhd = vec![0, 0, 24, 0, 0, 0, 0, 0];
            drhd.extend_from_slice(&0xfed9_1000u64.to_le_bytes());
            drhd.extend_from_slice(&[1, 8, 0, 0, 0, 0, 2, 0]);
            t.extend_from_slice(&drhd);
            t
        };
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200_000 {
            let mut t = base.clone();
            for _ in 0..(next() % 4 + 1) {
                let i = (next() as usize) % t.len();
                t[i] = next() as u8;
            }
            if next() % 8 == 0 {
                t.truncate((next() as usize) % t.len());
            }
            let _ = parse_dmar(&t);
        }
    }
}
