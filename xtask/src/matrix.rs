//! The release test matrix (M5.1, D-032, testing.md): each cell changes one
//! setting from the push configuration. `cargo xtask matrix <cell>` runs
//! `cargo xtask test` again with the cell's name in `PHAROS_CELL`; every
//! boot reads it in `qemu_args`, so the runner Cargo starts gets it too.

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;

use crate::Result;

/// Names the cell to `cargo xtask test`, the runner, and every boot.
pub const CELL_ENV: &str = "PHAROS_CELL";

#[derive(Debug)]
pub struct Cell {
    pub name: &'static str,
    /// SeaBIOS instead of OVMF.
    pub bios: bool,
    /// QEMU arguments after the push configuration's, before a test
    /// kernel's own (`test_qemu_args`), so a kernel's own settings win.
    pub args: &'static [&'static str],
    pub about: &'static str,
}

pub const CELLS: [Cell; 8] = [
    Cell {
        name: "push",
        bios: false,
        args: &[],
        about: "UEFI, 256 MiB, qemu64, TCG: the push run, the reference",
    },
    Cell {
        name: "bios",
        bios: true,
        args: &[],
        about: "SeaBIOS",
    },
    Cell {
        name: "mem-min",
        bios: false,
        args: &["-m", "144M"],
        about: "144 MiB, the smallest that boots the system table",
    },
    Cell {
        name: "mem-2g",
        bios: false,
        args: &["-m", "2G"],
        about: "2 GiB",
    },
    Cell {
        name: "mem-4g",
        bios: false,
        args: &["-m", "4G"],
        about: "4 GiB, RAM above 4 GiB",
    },
    Cell {
        name: "cpu-skylake",
        bios: false,
        args: &["-cpu", "Skylake-Client"],
        about: "Skylake-Client: SMEP, SMAP, XSAVE, AVX2",
    },
    Cell {
        name: "cpu-max",
        bios: false,
        args: &["-cpu", "max"],
        about: "max: every CPU feature QEMU emulates",
    },
    Cell {
        name: "kvm",
        bios: false,
        args: &["-enable-kvm", "-cpu", "host"],
        about: "KVM with the host CPU (needs read-write /dev/kvm)",
    },
];

pub fn find(name: &str) -> Result<&'static Cell> {
    CELLS.iter().find(|c| c.name == name).ok_or_else(|| {
        let names: Vec<_> = CELLS.iter().map(|c| c.name).collect();
        format!("no matrix cell '{name}' (cells: {})", names.join(", "))
    })
}

/// The cell this process runs in: `PHAROS_CELL`, or `push` without it.
/// `main` checks the name first, so this never sees an unknown one.
pub fn current() -> &'static Cell {
    env::var(CELL_ENV)
        .ok()
        .and_then(|n| find(&n).ok())
        .unwrap_or(&CELLS[0])
}

/// Refuses an unknown `PHAROS_CELL` before anything boots.
pub fn check_env() -> Result<()> {
    match env::var(CELL_ENV) {
        Ok(name) => find(&name).map(|_| ()),
        Err(_) => Ok(()),
    }
}

/// How result lines name the cell: `uefi` in `push`, as before the matrix.
pub fn label(cell: &Cell) -> &'static str {
    if cell.name == "push" {
        "uefi"
    } else {
        cell.name
    }
}

/// Why `cell` skips test kernel `kernel`, if it does (testing.md).
pub fn skip(cell: &Cell, kernel: &str) -> Option<&'static str> {
    match kernel {
        "recovery" if cell.bios => Some("needs UEFI: its rounds boot with the OVMF variable store"),
        // The boot check covers the BIOS boot's firmware and memory map.
        "boot_info" if cell.bios => Some("checks that 64-bit UEFI booted it"),
        _ => None,
    }
}

pub fn list() {
    for c in &CELLS {
        println!("{:<12} {:<34} {}", c.name, c.args.join(" "), c.about);
    }
}

/// `cargo xtask matrix <cell> [test options]`: `cargo xtask test` in the cell.
pub fn run(cell: &str, test_args: &[String]) -> Result<()> {
    find(cell)?;
    let exe = env::current_exe().map_err(|e| format!("cannot find xtask itself: {e}"))?;
    println!("Matrix cell {cell}:");
    let status = Command::new(exe)
        .arg("test")
        .args(test_args)
        .env(CELL_ENV, cell)
        .status()
        .map_err(|e| format!("cannot start cargo xtask test: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("matrix cell {cell} failed (see above)"))
    }
}

/// One line in the CI job's summary (`GITHUB_STEP_SUMMARY`), if there is one.
pub fn summary(line: &str) {
    let Some(path) = env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    if let Ok(mut f) = OpenOptions::new().append(true).create(true).open(path) {
        let _ = writeln!(f, "- {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn every_cell_changes_one_setting_from_push() {
        assert_eq!(CELLS[0].name, "push");
        assert!(!CELLS[0].bios && CELLS[0].args.is_empty());
        for c in &CELLS[1..] {
            let changed = [
                c.bios,
                c.args.contains(&"-m"),
                c.args.contains(&"-cpu") && !c.args.contains(&"-enable-kvm"),
                c.args.contains(&"-enable-kvm"),
            ];
            assert_eq!(changed.iter().filter(|&&x| x).count(), 1, "{}", c.name);
        }
        let mut names: Vec<_> = CELLS.iter().map(|c| c.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), CELLS.len());
    }

    #[test]
    fn cells_are_found_by_name_only() {
        assert_eq!(find("bios").map(|c| c.name), Ok("bios"));
        assert!(find("BIOS").unwrap_err().contains("cells: push, bios"));
        assert_eq!(label(find("push").unwrap()), "uefi");
        assert_eq!(label(find("mem-4g").unwrap()), "mem-4g");
    }

    #[test]
    fn skips_name_test_kernels_that_exist() {
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kernel/tests");
        let bios = find("bios").unwrap();
        for kernel in ["recovery", "boot_info"] {
            assert!(skip(bios, kernel).is_some());
            assert!(tests.join(format!("{kernel}.rs")).is_file(), "{kernel}");
        }
        assert!(skip(bios, "system").is_none());
        assert!(skip(&CELLS[0], "recovery").is_none());
    }
}
