//! The kernel filesystem (M2.8, [storage.md](../../docs/architecture/storage.md)):
//! a boot module mounted with the shared parser in `pharos-fs`, which checks
//! the whole image before anything is used. A corrupt image fails to mount
//! with the parser's reason; the kernel keeps running without it. Safe Rust.

use core::fmt;

use pharos_fs::{FsError, Image};

/// A mounted image on a RAM disk.
pub type Fs = Image<&'static [u8]>;

/// Why a mount failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountError {
    /// No boot module with that name.
    NoModule,
    /// The image failed a check.
    Fs(FsError),
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoModule => f.write_str("no such boot module"),
            Self::Fs(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(target_os = "none")]
pub use kernel::*;

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use alloc::sync::Arc;

    use crate::mm::raw::IrqMutex;
    use crate::storage;

    static ROOT: IrqMutex<Option<Arc<Fs>>> = IrqMutex::new(None);

    /// Mounts the boot module `name`. Needs the heap (the directory is
    /// copied into it, at most 128 KiB, after its size is checked).
    pub fn mount(name: &str) -> Result<Arc<Fs>, MountError> {
        let disk = storage::ram_disk(name).ok_or(MountError::NoModule)?;
        Image::mount(disk).map(Arc::new).map_err(MountError::Fs)
    }

    /// Mounts the module `root` as the root filesystem. Returns the number
    /// of files.
    pub fn mount_root() -> Result<usize, MountError> {
        let fs = mount("root")?;
        let files = fs.entries().count();
        *ROOT.lock() = Some(fs);
        Ok(files)
    }

    /// The root filesystem, once mounted.
    pub fn root() -> Option<Arc<Fs>> {
        ROOT.lock().clone()
    }
}
