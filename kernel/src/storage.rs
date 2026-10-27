//! Boot storage (M2.8, [storage.md](../../docs/architecture/storage.md)):
//! Limine modules, recorded at boot, as read-only RAM disks.
//!
//! Limine's module response lives in bootloader-reclaimable memory, so
//! [`record_modules`] copies what the kernel needs (physical address, size,
//! name) before that memory is reused. A RAM disk is the module's bytes as a
//! `&'static [u8]`, which is a [`pharos_fs::BlockDevice`]; the slice comes
//! from `mm::raw`, which checks that the range is module memory. Safe Rust.

/// Most modules recorded; more are skipped and counted.
pub const MAX_MODULES: usize = 16;
/// Longest module name (the `module_string` in `limine.conf`).
pub const MAX_NAME: usize = 32;

/// A boot module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    /// Physical address, 4 KiB aligned.
    pub phys: u64,
    /// Size in bytes.
    pub size: u64,
    name: [u8; MAX_NAME],
    name_len: u8,
}

impl Module {
    /// The module's name.
    pub fn name(&self) -> &str {
        // Only valid UTF-8 names are recorded.
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }
}

/// Recorded modules, in configuration order.
pub type Modules = [Option<Module>; MAX_MODULES];

/// Turns Limine's module list, `(direct-map address, size, string)` per
/// module, into records. Skips (and counts) modules without a name of 1 to
/// [`MAX_NAME`] bytes, with a duplicate name, with an address below the
/// direct map, or beyond [`MAX_MODULES`].
pub fn plan<'a>(
    hhdm: u64,
    files: impl Iterator<Item = (u64, u64, Option<&'a str>)>,
) -> (Modules, usize) {
    let mut modules: Modules = [None; MAX_MODULES];
    let (mut count, mut skipped) = (0, 0);
    for (address, size, string) in files {
        let name = string.unwrap_or("");
        let duplicate = modules[..count].iter().flatten().any(|m| m.name() == name);
        let phys = address.checked_sub(hhdm);
        match phys {
            Some(phys)
                if !name.is_empty()
                    && name.len() <= MAX_NAME
                    && !duplicate
                    && count < MAX_MODULES =>
            {
                let mut bytes = [0; MAX_NAME];
                bytes[..name.len()].copy_from_slice(name.as_bytes());
                modules[count] = Some(Module {
                    phys,
                    size,
                    name: bytes,
                    name_len: name.len() as u8,
                });
                count += 1;
            }
            _ => skipped += 1,
        }
    }
    (modules, skipped)
}

/// True if `len` bytes at `phys` lie inside one "executable and modules"
/// entry of the memory map (`(base, length, kind)` tuples), without
/// overflow. An empty range at a valid address counts as inside.
pub fn inside_module_region(
    mut entries: impl Iterator<Item = (u64, u64, u64)>,
    phys: u64,
    len: u64,
) -> bool {
    let Some(end) = phys.checked_add(len) else {
        return false;
    };
    entries.any(|(base, length, kind)| {
        kind == crate::limine::MEMMAP_EXECUTABLE_AND_MODULES
            && base <= phys
            && base
                .checked_add(length)
                .is_some_and(|region_end| end <= region_end)
    })
}

#[cfg(target_arch = "x86_64")]
pub use global::*;

#[cfg(target_arch = "x86_64")]
mod global {
    use super::*;
    use crate::mm::raw::IrqMutex;

    static MODULES: IrqMutex<Modules> = IrqMutex::new([None; MAX_MODULES]);

    /// Records the modules from Limine's response (`None` when there are
    /// none). Call before bootloader memory is reclaimed. Returns
    /// `(recorded, skipped)`.
    pub fn record_modules(
        response: Option<&crate::limine::ModuleResponse>,
        hhdm: u64,
    ) -> (usize, usize) {
        let files = response
            .into_iter()
            .flat_map(|r| r.modules())
            .map(|f| (f.address(), f.size, f.string()));
        let (modules, skipped) = plan(hhdm, files);
        let recorded = modules.iter().flatten().count();
        *MODULES.lock() = modules;
        (recorded, skipped)
    }

    /// The recorded modules.
    pub fn modules() -> Modules {
        *MODULES.lock()
    }

    /// The module named `name` as a read-only RAM disk, or `None` if there
    /// is no such module or its range is not module memory. Needs the
    /// kernel's own page tables.
    #[cfg(target_os = "none")]
    pub fn ram_disk(name: &str) -> Option<&'static [u8]> {
        let module = modules().into_iter().flatten().find(|m| m.name() == name)?;
        crate::mm::raw::module_bytes(module.phys, module.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limine::{MEMMAP_EXECUTABLE_AND_MODULES as MODULES_KIND, MEMMAP_USABLE};

    const HHDM: u64 = 0xffff_8000_0000_0000;

    #[test]
    fn plan_records_named_modules_in_order() {
        let files = [
            (HHDM + 0x10_0000, 4096, Some("root")),
            (HHDM + 0x20_0000, 1000, Some("pattern")),
        ];
        let (modules, skipped) = plan(HHDM, files.into_iter());
        assert_eq!(skipped, 0);
        let m: Vec<_> = modules.iter().flatten().collect();
        assert_eq!(m.len(), 2);
        assert_eq!(
            (m[0].name(), m[0].phys, m[0].size),
            ("root", 0x10_0000, 4096)
        );
        assert_eq!(m[1].name(), "pattern");
    }

    #[test]
    fn plan_skips_bad_modules() {
        let long = "x".repeat(MAX_NAME + 1);
        let files = [
            (HHDM + 0x1000, 1, None),
            (HHDM + 0x2000, 1, Some("")),
            (HHDM + 0x3000, 1, Some(long.as_str())),
            (0x4000, 1, Some("below-hhdm")),
            (HHDM + 0x5000, 1, Some("a")),
            (HHDM + 0x6000, 1, Some("a")),
        ];
        let (modules, skipped) = plan(HHDM, files.into_iter());
        assert_eq!(skipped, 5);
        assert_eq!(modules.iter().flatten().count(), 1);

        let names: Vec<String> = (0..MAX_MODULES + 3).map(|i| format!("m{i}")).collect();
        let many = names.iter().map(|n| (HHDM, 1, Some(n.as_str())));
        let (modules, skipped) = plan(HHDM, many);
        assert_eq!(
            (modules.iter().flatten().count(), skipped),
            (MAX_MODULES, 3)
        );
        let longest = "y".repeat(MAX_NAME);
        let (modules, _) = plan(HHDM, [(HHDM, 1, Some(longest.as_str()))].into_iter());
        assert_eq!(modules[0].unwrap().name(), longest);
    }

    #[test]
    fn module_region_check() {
        let map = [
            (0x10_0000, 0x10_0000, MODULES_KIND),
            (0x20_0000, 0x10_0000, MEMMAP_USABLE),
        ];
        let inside = |phys, len| inside_module_region(map.into_iter(), phys, len);
        assert!(inside(0x10_0000, 0x10_0000), "the whole region");
        assert!(inside(0x18_0000, 0x1000));
        assert!(inside(0x10_0000, 0), "empty range");
        assert!(!inside(0x1f_f000, 0x2000), "runs into usable memory");
        assert!(!inside(0x20_0000, 0x1000), "usable memory");
        assert!(!inside(0x0f_f000, 0x1000), "below the region");
        assert!(!inside(u64::MAX, 2), "overflow");
        let huge = [(u64::MAX - 10, 100, MODULES_KIND)];
        assert!(
            !inside_module_region(huge.into_iter(), u64::MAX - 5, 1),
            "region end overflows"
        );
    }
}
