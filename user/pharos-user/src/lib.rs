//! Pharos OS user-space library ([drivers.md](../../../docs/architecture/drivers.md)):
//! safe wrappers for every system call, the program entry point, and a
//! panic handler. Programs start with [`entry!`].
//!
//! `no_std`. The only `unsafe` code is in the `syscall` module.

#![cfg_attr(not(test), no_std)]

mod syscall;

pub use syscall::Mapped;

/// Call numbers (syscalls-ipc.md, storage.md).
pub mod number {
    pub const EXIT: u64 = 0;
    pub const YIELD: u64 = 1;
    pub const DEBUG_WRITE: u64 = 2;
    pub const SEND: u64 = 3;
    pub const RECEIVE: u64 = 4;
    pub const DELETE: u64 = 5;
    pub const REVOKE: u64 = 6;
    pub const OPEN: u64 = 7;
    pub const READ: u64 = 8;
    pub const CONFIG_READ: u64 = 9;
    pub const MMIO_MAP: u64 = 10;
    pub const DMA_ALLOC: u64 = 11;
    pub const IRQ_CREATE: u64 = 12;
    pub const IRQ_WAIT: u64 = 13;
}

/// A capability handle in this process's table.
pub type Handle = u64;

/// Error codes the kernel returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownCall,
    InvalidHandle,
    Revoked,
    MissingRight,
    BadAddress,
    TooLarge,
    NoMemory,
    NotFound,
    InUse,
    /// A code this library does not know.
    Other(u64),
}

impl Error {
    fn from_code(code: u64) -> Self {
        match code {
            1 => Self::UnknownCall,
            2 => Self::InvalidHandle,
            3 => Self::Revoked,
            4 => Self::MissingRight,
            5 => Self::BadAddress,
            6 => Self::TooLarge,
            7 => Self::NoMemory,
            8 => Self::NotFound,
            9 => Self::InUse,
            other => Self::Other(other),
        }
    }

    /// The kernel's code for this error.
    pub fn code(self) -> u64 {
        match self {
            Self::UnknownCall => 1,
            Self::InvalidHandle => 2,
            Self::Revoked => 3,
            Self::MissingRight => 4,
            Self::BadAddress => 5,
            Self::TooLarge => 6,
            Self::NoMemory => 7,
            Self::NotFound => 8,
            Self::InUse => 9,
            Self::Other(code) => code,
        }
    }
}

/// Status 0 is success with `value`; anything else is an error.
fn result((status, value): (u64, u64)) -> Result<u64, Error> {
    match status {
        0 => Ok(value),
        code => Err(Error::from_code(code)),
    }
}

fn call(number: u64, args: [u64; 6]) -> Result<u64, Error> {
    result(syscall::raw(number, args))
}

/// Ends this process with `code`.
pub fn exit(code: u64) -> ! {
    call(number::EXIT, [code, 0, 0, 0, 0, 0]).ok();
    // The kernel never returns from exit; stop here if it ever did.
    loop {
        core::hint::spin_loop();
    }
}

/// Gives the CPU to another thread.
pub fn yield_now() {
    call(number::YIELD, [0; 6]).ok();
}

/// Writes up to 256 bytes to the debug console behind `console`.
pub fn debug_write(console: Handle, bytes: &[u8]) -> Result<u64, Error> {
    call(
        number::DEBUG_WRITE,
        [console, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 0],
    )
}

/// Sends `bytes` (up to 256) on `endpoint`, passing `cap` (0 = none) with
/// `rights`.
pub fn send(endpoint: Handle, bytes: &[u8], cap: Handle, rights: u32) -> Result<u64, Error> {
    let args = [
        endpoint,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        cap,
        rights.into(),
        0,
    ];
    call(number::SEND, args)
}

/// Receives a message on `endpoint` into `buf`; returns the message length
/// and the handle of a passed capability (0 = none).
pub fn receive(endpoint: Handle, buf: &mut [u8]) -> Result<(usize, Handle), Error> {
    let args = [endpoint, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0];
    let v = call(number::RECEIVE, args)?;
    Ok(((v & 0xffff_ffff) as usize, v >> 32))
}

/// Removes `handle` from this process's table.
pub fn delete(handle: Handle) -> Result<u64, Error> {
    call(number::DELETE, [handle, 0, 0, 0, 0, 0])
}

/// Revokes every capability derived from `handle`; returns how many.
pub fn revoke(handle: Handle) -> Result<u64, Error> {
    call(number::REVOKE, [handle, 0, 0, 0, 0, 0])
}

/// Opens the file at `path` on the filesystem behind `fs`.
pub fn open(fs: Handle, path: &[u8]) -> Result<Handle, Error> {
    call(
        number::OPEN,
        [fs, path.as_ptr() as u64, path.len() as u64, 0, 0, 0],
    )
}

/// Reads from `file` at `offset` into `buf` (up to 4096 bytes); returns the
/// bytes read, 0 at the end of the file.
pub fn read(file: Handle, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
    let args = [
        file,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        offset,
        0,
        0,
    ];
    call(number::READ, args).map(|n| n as usize)
}

/// Reads `width` (1, 2, or 4) bytes of the device's PCI configuration
/// space at `offset`.
pub fn config_read(device: Handle, offset: u8, width: u8) -> Result<u32, Error> {
    let args = [device, offset.into(), width.into(), 0, 0, 0];
    call(number::CONFIG_READ, args).map(|v| v as u32)
}

/// Maps `len` bytes (whole pages) at `offset` in memory BAR `bar` of the
/// device at user address `at` (page-aligned, unused).
pub fn mmio_map(device: Handle, bar: u8, offset: u64, len: u64, at: u64) -> Result<Mapped, Error> {
    call(number::MMIO_MAP, [device, bar.into(), offset, len, at, 0])?;
    Ok(Mapped::new(at, len))
}

/// Allocates `pages` contiguous, zeroed DMA pages for the device at user
/// address `at`; returns the mapping and the physical address the device
/// uses.
pub fn dma_alloc(device: Handle, pages: u64, at: u64) -> Result<(Mapped, u64), Error> {
    let phys = call(number::DMA_ALLOC, [device, pages, at, 0, 0, 0])?;
    Ok((Mapped::new(at, pages * 4096), phys))
}

/// Routes MSI-X table entry `entry` of `device` (needs `IRQ`) to a new
/// interrupt and returns its handle.
pub fn irq_create(device: Handle, entry: u16) -> Result<Handle, Error> {
    call(number::IRQ_CREATE, [device, entry.into(), 0, 0, 0, 0])
}

/// Waits for an interrupt (needs `WAIT`); returns how many arrived since
/// the last wait (at least 1).
pub fn irq_wait(interrupt: Handle) -> Result<u64, Error> {
    call(number::IRQ_WAIT, [interrupt, 0, 0, 0, 0, 0])
}

/// Exit code a program's panic ends it with.
pub const PANIC_EXIT: u64 = 0xdead;

/// Defines the program's entry point: `$main` is a `fn(u64) -> u64` that
/// gets the starter's argument; its result is the exit code.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        /// Called by the entry stub in `pharos-user`.
        #[allow(unsafe_code)] // `no_mangle` names the symbol; the function is safe Rust.
        #[unsafe(no_mangle)]
        extern "C" fn pharos_main(arg: u64) -> ! {
            let main: fn(u64) -> u64 = $main;
            $crate::exit(main(arg))
        }
    };
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(PANIC_EXIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip() {
        for code in 1..=10 {
            assert_eq!(Error::from_code(code).code(), code);
        }
        assert_eq!(result((0, 42)), Ok(42));
        assert_eq!(result((8, 0)), Err(Error::NotFound));
    }

    #[test]
    fn mapped_checks_bounds_and_alignment() {
        let mut page = [0u64; 512];
        let m = Mapped::new(page.as_mut_ptr() as u64, 4096);
        m.write32(8, 0xdead_beef);
        assert_eq!(m.read32(8), 0xdead_beef);
        assert_eq!(m.read16(10), 0xdead);
        m.write64(4088, 7);
        assert_eq!(m.read64(4088), 7);
        let past = std::panic::catch_unwind(|| m.read32(4094));
        assert!(past.is_err(), "past the end");
        let odd = std::panic::catch_unwind(|| m.read32(2));
        assert!(odd.is_err(), "misaligned");
    }
}
