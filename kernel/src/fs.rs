//! The kernel filesystem (M2.8, [storage.md](../../docs/architecture/storage.md)):
//! a boot module mounted with the shared parser in `pharos-fs`, which checks
//! the whole image before anything is used. A corrupt image fails to mount
//! with the parser's reason; the kernel keeps running without it. Safe Rust.
//!
//! `fs_mount` (#163, boot.md section 8) mounts a copy of an image a process
//! hands over in a `Memory` object: the copy lives in frames the kernel
//! owns, so the process cannot change the bytes after the checks.

use core::fmt;

use pharos_fs::{BlockDevice, BlockError, FsError, Image};

/// A mounted image: a boot module, or a copy `fs_mount` made.
pub type Fs = Image<Disk>;

/// The bytes under a mounted image.
pub enum Disk {
    /// A boot module, read-only for the kernel's lifetime.
    Module(&'static [u8]),
    /// A copy in kernel-owned frames.
    #[cfg(target_os = "none")]
    Copy(kernel::Copy),
}

impl BlockDevice for Disk {
    fn block_count(&self) -> u64 {
        match self {
            Self::Module(bytes) => bytes.block_count(),
            #[cfg(target_os = "none")]
            Self::Copy(copy) => copy.block_count(),
        }
    }

    fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        match self {
            Self::Module(bytes) => bytes.read(block, buf),
            #[cfg(target_os = "none")]
            Self::Copy(copy) => copy.read(block, buf),
        }
    }
}

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

/// Most images `fs_mount` keeps mounted at once (boot.md section 8).
pub const MAX_COPIES: usize = 2;

#[cfg(target_os = "none")]
pub use kernel::*;

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::arch::x86_64::paging::{AddressSpace, Flags, MapError};
    use crate::mm::raw::IrqMutex;
    use crate::storage;

    static ROOT: IrqMutex<Option<Arc<Fs>>> = IrqMutex::new(None);

    /// Copies alive (at most [`MAX_COPIES`]).
    static COPIES: AtomicUsize = AtomicUsize::new(0);

    /// Where a copy's pages sit in its own address space, and where each
    /// source frame is mapped while it is read. The space is never loaded:
    /// it only gives the copy page tables to read through.
    const COPY_AT: u64 = 1 << 30;
    const SOURCE_AT: u64 = 1 << 32;

    /// A copy of an image in frames the kernel owns, mapped in an address
    /// space no process runs in. Every access is the safe `read_user`.
    pub struct Copy {
        space: Option<AddressSpace>,
        len: u64,
    }

    impl Copy {
        /// Copies `len` bytes at `offset` of `source` (physical frames, in
        /// order) into new frames. `None` if [`MAX_COPIES`] are alive or
        /// memory ran out (nothing is kept then). The caller checked the
        /// range against the frames. `pause` runs between pages, with no
        /// lock held.
        pub fn new(source: &[u64], offset: u64, len: u64, mut pause: impl FnMut()) -> Option<Self> {
            if COPIES.fetch_add(1, Ordering::AcqRel) >= MAX_COPIES {
                COPIES.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            // From here on, dropping `copy` gives everything back.
            let mut copy = Self { space: None, len };
            let space = AddressSpace::new_user(crate::mm::frames().as_mut()?);
            copy.space = Some(space.ok()?);
            let first = offset / 4096;
            let mut page = [0u8; 4096];
            for i in 0..len.div_ceil(4096) {
                // The source frames this page's bytes come from, mapped
                // one after another at `SOURCE_AT` while they are read.
                let from = offset + i * 4096;
                let take = (len - i * 4096).min(4096) as usize;
                let sources = (from / 4096)..(from + take as u64).div_ceil(4096);
                let space = copy.space.as_mut()?;
                let mut guard = crate::mm::frames();
                let frames = guard.as_mut()?;
                for f in sources.clone() {
                    let phys = *source.get(f as usize)?;
                    let at = SOURCE_AT + (f - first) * 4096;
                    space.map_device(at, phys, Flags::USER_DATA, frames).ok()?;
                }
                let read = space.read_user(SOURCE_AT + (from - first * 4096), &mut page[..take]);
                for f in sources {
                    let _ = space.unmap(SOURCE_AT + (f - first) * 4096);
                }
                read.ok()?;
                page[take..].fill(0);
                space
                    .map_new_page(COPY_AT + i * 4096, Flags::USER_DATA, &page, frames)
                    .ok()?;
                drop(guard);
                pause();
            }
            Some(copy)
        }
    }

    impl BlockDevice for Copy {
        fn block_count(&self) -> u64 {
            self.len / pharos_fs::BLOCK_SIZE as u64
        }

        fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            if buf.is_empty() || buf.len() % pharos_fs::BLOCK_SIZE != 0 {
                return Err(BlockError::BadLength);
            }
            let count = (buf.len() / pharos_fs::BLOCK_SIZE) as u64;
            match block.checked_add(count) {
                Some(end) if end <= self.block_count() => {}
                _ => return Err(BlockError::OutOfRange),
            }
            let at = COPY_AT + block * pharos_fs::BLOCK_SIZE as u64;
            let space = self.space.as_ref().ok_or(BlockError::OutOfRange)?;
            space
                .read_user(at, buf)
                .map_err(|_: MapError| BlockError::OutOfRange)
        }
    }

    impl Drop for Copy {
        /// Frees the copy's frames and tables. Never runs with the frame
        /// allocator locked: the last capability on the filesystem is
        /// dropped after the system call's locks are released.
        fn drop(&mut self) {
            if let Some(space) = self.space.take() {
                if let Some(frames) = crate::mm::frames().as_mut() {
                    space.destroy(frames);
                }
            }
            COPIES.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Mounts the boot module `name`. Needs the heap (the directory is
    /// copied into it, at most 128 KiB, after its size is checked).
    pub fn mount(name: &str) -> Result<Arc<Fs>, MountError> {
        let disk = storage::ram_disk(name).ok_or(MountError::NoModule)?;
        Image::mount(Disk::Module(disk))
            .map(Arc::new)
            .map_err(MountError::Fs)
    }

    /// Mounts the module `root` as the root filesystem, or, if it fails,
    /// its copy `recovery` (#164, boot.md section 8). Returns the number
    /// of files and, if the copy was mounted, why `root` was not.
    pub fn mount_root() -> Result<(usize, Option<MountError>), MountError> {
        let (fs, why) = match mount("root") {
            Ok(fs) => (fs, None),
            Err(why) => (mount("recovery").map_err(|_| why)?, Some(why)),
        };
        let files = fs.entries().count();
        *ROOT.lock() = Some(fs);
        Ok((files, why))
    }

    /// The root filesystem, once mounted.
    pub fn root() -> Option<Arc<Fs>> {
        ROOT.lock().clone()
    }

    /// Copies alive now (for tests).
    pub fn copies() -> usize {
        COPIES.load(Ordering::Acquire)
    }
}
