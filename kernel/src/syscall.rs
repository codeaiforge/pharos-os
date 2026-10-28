//! System calls (D-014, syscalls-ipc.md): numbers, error codes, argument
//! decoding, and the handler the entry stub calls.
//!
//! Every argument is untrusted. [`decode`] checks what needs no state (call
//! number, lengths, user address ranges) and is host-tested with random
//! input. The handler then checks the handle and its rights in the caller's
//! capability table, and copies user memory only through
//! `AddressSpace::read_user`/`write_user`. Check order: number, length,
//! address range, handle, rights, then the pages themselves.

use crate::arch::x86_64::paging::{MapError, user_range_ok};
use crate::cap::{self, CapError, Handle};

/// Call numbers.
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

/// Largest buffer `debug_write` accepts (and the IPC message size).
pub const MAX_MESSAGE: usize = 256;
/// Largest path `open` accepts.
pub const MAX_PATH: usize = pharos_fs::MAX_PATH;
/// Largest buffer `read` accepts.
pub const MAX_READ: usize = 4096;

/// Error codes returned in `rax` (0 is success).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Error {
    UnknownCall = 1,
    InvalidHandle = 2,
    Revoked = 3,
    MissingRight = 4,
    BadAddress = 5,
    TooLarge = 6,
    NoMemory = 7,
    NotFound = 8,
    InUse = 9,
}

impl From<CapError> for Error {
    fn from(error: CapError) -> Self {
        match error {
            CapError::InvalidHandle => Self::InvalidHandle,
            CapError::Revoked => Self::Revoked,
            CapError::MissingRight => Self::MissingRight,
            CapError::TableFull => Self::NoMemory,
        }
    }
}

impl From<crate::irq::IrqError> for Error {
    fn from(error: crate::irq::IrqError) -> Self {
        use crate::irq::IrqError;
        match error {
            IrqError::NoEntry => Self::NotFound,
            IrqError::InUse => Self::InUse,
            IrqError::NoVector | IrqError::Hardware => Self::NoMemory,
        }
    }
}

impl From<MapError> for Error {
    fn from(_: MapError) -> Self {
        Self::BadAddress
    }
}

/// A decoded system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Exit {
        code: u64,
    },
    Yield,
    DebugWrite {
        handle: Handle,
        addr: u64,
        len: usize,
    },
    Delete {
        handle: Handle,
    },
    Send {
        handle: Handle,
        addr: u64,
        len: usize,
        /// Capability to pass (0 = none).
        cap: Handle,
        /// Rights the receiver gets, at most those of `cap`.
        rights: cap::Rights,
    },
    Receive {
        handle: Handle,
        addr: u64,
        max_len: usize,
    },
    Revoke {
        handle: Handle,
    },
    Open {
        handle: Handle,
        addr: u64,
        len: usize,
    },
    Read {
        handle: Handle,
        addr: u64,
        len: usize,
        offset: u64,
    },
    ConfigRead {
        handle: Handle,
        offset: u8,
        width: u8,
    },
    MmioMap {
        handle: Handle,
        bar: u64,
        offset: u64,
        len: u64,
        addr: u64,
    },
    DmaAlloc {
        handle: Handle,
        pages: usize,
        addr: u64,
    },
    IrqCreate {
        handle: Handle,
        /// MSI-X table entry.
        entry: u16,
    },
    IrqWait {
        handle: Handle,
    },
}

/// A page-aligned user range of `len` bytes (at least one page).
fn user_pages(addr: u64, len: u64) -> Result<u64, Error> {
    if addr % 4096 != 0 || len == 0 || len % 4096 != 0 {
        return Err(Error::BadAddress);
    }
    if !user_range_ok(addr, len) {
        return Err(Error::BadAddress);
    }
    Ok(addr)
}

/// Checks a user buffer argument of at most `max` bytes: length first,
/// then the address range.
fn buffer_up_to(max: usize, addr: u64, len: u64) -> Result<usize, Error> {
    if len > max as u64 {
        return Err(Error::TooLarge);
    }
    if !user_range_ok(addr, len) {
        return Err(Error::BadAddress);
    }
    Ok(len as usize)
}

/// A user buffer of at most [`MAX_MESSAGE`] bytes.
fn buffer(addr: u64, len: u64) -> Result<usize, Error> {
    buffer_up_to(MAX_MESSAGE, addr, len)
}

/// Decodes call `number` with `args` (`rdi`, `rsi`, `rdx`, `r10`, `r8`,
/// `r9`). Checks everything that needs no state.
pub fn decode(number: u64, args: [u64; 6]) -> Result<Call, Error> {
    match number {
        number::EXIT => Ok(Call::Exit { code: args[0] }),
        number::YIELD => Ok(Call::Yield),
        number::DEBUG_WRITE => Ok(Call::DebugWrite {
            handle: args[0],
            addr: args[1],
            len: buffer(args[1], args[2])?,
        }),
        number::SEND => Ok(Call::Send {
            handle: args[0],
            addr: args[1],
            len: buffer(args[1], args[2])?,
            cap: args[3],
            // Rights are a 32-bit mask; higher bits name no right.
            rights: args[4] as cap::Rights,
        }),
        number::RECEIVE => Ok(Call::Receive {
            handle: args[0],
            addr: args[1],
            max_len: buffer(args[1], args[2])?,
        }),
        number::DELETE => Ok(Call::Delete { handle: args[0] }),
        number::REVOKE => Ok(Call::Revoke { handle: args[0] }),
        number::OPEN => Ok(Call::Open {
            handle: args[0],
            addr: args[1],
            len: buffer_up_to(MAX_PATH, args[1], args[2])?,
        }),
        number::READ => Ok(Call::Read {
            handle: args[0],
            addr: args[1],
            len: buffer_up_to(MAX_READ, args[1], args[2])?,
            offset: args[3],
        }),
        number::CONFIG_READ => {
            let (offset, width) = (args[1], args[2]);
            if !matches!(width, 1 | 2 | 4) || offset >= 256 || offset % width != 0 {
                return Err(Error::TooLarge);
            }
            Ok(Call::ConfigRead {
                handle: args[0],
                offset: offset as u8,
                width: width as u8,
            })
        }
        number::MMIO_MAP => Ok(Call::MmioMap {
            handle: args[0],
            bar: args[1],
            offset: args[2],
            len: args[3],
            addr: user_pages(args[4], args[3])?,
        }),
        number::DMA_ALLOC => {
            let pages = args[1];
            if pages == 0 || pages > crate::device::MAX_DMA_ALLOC as u64 {
                return Err(Error::TooLarge);
            }
            Ok(Call::DmaAlloc {
                handle: args[0],
                pages: pages as usize,
                addr: user_pages(args[2], pages * 4096)?,
            })
        }
        number::IRQ_CREATE => Ok(Call::IrqCreate {
            handle: args[0],
            // MSI-X tables have at most 2048 entries.
            entry: u16::try_from(args[1])
                .ok()
                .filter(|&e| e < 2048)
                .ok_or(Error::NotFound)?,
        }),
        number::IRQ_WAIT => Ok(Call::IrqWait { handle: args[0] }),
        _ => Err(Error::UnknownCall),
    }
}

/// Needed right for each capability-using call.
pub fn needed_rights(call: &Call) -> cap::Rights {
    match call {
        Call::DebugWrite { .. } => cap::WRITE,
        Call::Send { .. } => cap::SEND,
        Call::Receive { .. } => cap::RECEIVE,
        Call::Open { .. } | Call::Read { .. } => cap::READ,
        Call::ConfigRead { .. } => cap::CONFIG,
        Call::MmioMap { .. } | Call::DmaAlloc { .. } => cap::MAP,
        Call::IrqCreate { .. } => cap::IRQ,
        Call::IrqWait { .. } => cap::WAIT,
        _ => 0,
    }
}

#[cfg(target_os = "none")]
pub use kernel::handle;

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::syscall::SyscallFrame;
    use crate::cap::{MAX_HANDLES, Object};
    use crate::ipc::{self, Message};
    use crate::{process, sched};

    /// Device memory mapped into a driver: user, writable, uncached,
    /// no-execute.
    const USER_MMIO: crate::arch::x86_64::paging::Flags = crate::arch::x86_64::paging::Flags {
        writable: true,
        executable: false,
        uncached: true,
        user: true,
    };

    /// The device behind `handle`, if the caller holds `needed` on it.
    fn device(
        process: &process::Process,
        handle: Handle,
        needed: cap::Rights,
    ) -> Result<alloc::sync::Arc<crate::device::DeviceHandle>, Error> {
        match process.caps.lock().get(handle, needed)?.object() {
            Object::Device(device) => Ok(device.clone()),
            _ => Err(Error::MissingRight),
        }
    }

    /// Keeps `device` alive (granted, enabled, its DMA buffers allocated)
    /// for as long as `process` lives: the process has its registers or
    /// buffers mapped, even if it deletes every handle (drivers.md).
    fn pin(process: &process::Process, device: alloc::sync::Arc<crate::device::DeviceHandle>) {
        let mut pins = process.pins.lock();
        if !pins.iter().any(|p| alloc::sync::Arc::ptr_eq(p, &device)) {
            pins.push(device);
        }
    }

    /// The endpoint behind `handle`, if the caller holds `needed` on it.
    fn endpoint(
        process: &process::Process,
        handle: Handle,
        needed: cap::Rights,
    ) -> Result<alloc::sync::Arc<ipc::Endpoint>, Error> {
        match process.caps.lock().get(handle, needed)?.object() {
            Object::Endpoint(endpoint) => Ok(endpoint.clone()),
            _ => Err(Error::MissingRight),
        }
    }

    /// The system-call handler (installed by `process::init`). Runs on the
    /// calling thread's kernel stack with interrupts disabled.
    pub fn handle(frame: &mut SyscallFrame) {
        let result = decode(frame.rax, frame.args()).and_then(execute);
        let (status, value) = match result {
            Ok(value) => (0, value),
            Err(error) => (error as u64, 0),
        };
        frame.rax = status;
        frame.rdx = value;
    }

    fn execute(call: Call) -> Result<u64, Error> {
        let process = process::current().ok_or(Error::UnknownCall)?;
        match call {
            Call::Exit { code } => {
                drop(process);
                process::exit_current(code)
            }
            Call::Yield => {
                drop(process);
                sched::yield_now();
                Ok(0)
            }
            Call::DebugWrite { handle, addr, len } => {
                let cap = process.caps.lock().get(handle, needed_rights(&call))?;
                if !matches!(cap.object(), Object::DebugConsole) {
                    return Err(Error::MissingRight);
                }
                let mut buf = [0u8; MAX_MESSAGE];
                sched::with_current_space(|space| space.read_user(addr, &mut buf[..len]))
                    .ok_or(Error::BadAddress)??;
                process::debug_write(&buf[..len]);
                Ok(len as u64)
            }
            Call::Delete { handle } => {
                process.caps.lock().delete(handle)?;
                Ok(0)
            }
            Call::Send {
                handle,
                addr,
                len,
                cap,
                rights,
            } => {
                let endpoint = endpoint(&process, handle, cap::SEND)?;
                let mut message = Message {
                    data: [0; MAX_MESSAGE],
                    len,
                    cap: None,
                };
                sched::with_current_space(|space| space.read_user(addr, &mut message.data[..len]))
                    .ok_or(Error::BadAddress)??;
                if cap != 0 {
                    let passed = process.caps.lock().get(cap, cap::GRANT)?;
                    message.cap = Some(passed.derive(rights));
                }
                drop(process);
                ipc::send(&endpoint, message);
                Ok(0)
            }
            Call::Receive {
                handle,
                addr,
                max_len,
            } => {
                let endpoint = endpoint(&process, handle, cap::RECEIVE)?;
                // Check everything before taking a message, so none is lost.
                sched::with_current_space(|space| space.check_user(addr, max_len, true))
                    .ok_or(Error::BadAddress)??;
                if process.caps.lock().len() >= MAX_HANDLES {
                    return Err(Error::NoMemory);
                }
                let message = ipc::receive(&endpoint).ok_or(Error::UnknownCall)?;
                // Longer messages are cut to the buffer; the value reports
                // the full length.
                let copied = message.len.min(max_len);
                sched::with_current_space(|space| space.write_user(addr, &message.data[..copied]))
                    .ok_or(Error::BadAddress)??;
                let new_handle = match message.cap {
                    Some(cap) => process.caps.lock().insert(cap)?,
                    None => 0,
                };
                Ok(message.len as u64 | new_handle << 32)
            }
            Call::Revoke { handle } => {
                let cap = process.caps.lock().get(handle, 0)?;
                Ok(cap.revoke() as u64)
            }
            Call::Open { handle, addr, len } => {
                let parent = process.caps.lock().get(handle, cap::READ)?;
                let Object::Filesystem(fs) = parent.object() else {
                    return Err(Error::MissingRight);
                };
                let mut path = [0u8; MAX_PATH];
                sched::with_current_space(|space| space.read_user(addr, &mut path[..len]))
                    .ok_or(Error::BadAddress)??;
                let file = fs.lookup(&path[..len]).map_err(|_| Error::NotFound)?;
                let object = Object::File {
                    fs: fs.clone(),
                    file,
                };
                let child =
                    parent.derive_object(object, parent.rights() & (cap::READ | cap::GRANT));
                Ok(process.caps.lock().insert(child)?)
            }
            Call::Read {
                handle,
                addr,
                len,
                offset,
            } => {
                let cap = process.caps.lock().get(handle, cap::READ)?;
                let Object::File { fs, file } = cap.object() else {
                    return Err(Error::MissingRight);
                };
                sched::with_current_space(|space| space.check_user(addr, len, true))
                    .ok_or(Error::BadAddress)??;
                // On the heap: kernel stacks are 16 KiB.
                let mut buf = alloc::vec::Vec::new();
                buf.try_reserve_exact(len).map_err(|_| Error::NoMemory)?;
                buf.resize(len, 0);
                // A RAM disk read of a validated range cannot fail.
                let n = fs
                    .read(*file, offset, &mut buf)
                    .map_err(|_| Error::NotFound)?;
                sched::with_current_space(|space| space.write_user(addr, &buf[..n]))
                    .ok_or(Error::BadAddress)??;
                Ok(n as u64)
            }
            Call::ConfigRead {
                handle,
                offset,
                width,
            } => {
                let device = device(&process, handle, cap::CONFIG)?;
                let dword = crate::arch::x86_64::pci::read32(device.pci.address, offset);
                let shift = u32::from(offset % 4) * 8;
                let mask = if width == 4 {
                    u32::MAX
                } else {
                    (1 << (u32::from(width) * 8)) - 1
                };
                Ok(u64::from((dword >> shift) & mask))
            }
            Call::MmioMap {
                handle,
                bar,
                offset,
                len,
                addr,
            } => {
                let device = device(&process, handle, cap::MAP)?;
                let phys = crate::device::mmio_range(&device.pci, bar, offset, len).map_err(
                    |e| match e {
                        crate::device::MmioError::NoBar => Error::NotFound,
                        _ => Error::BadAddress,
                    },
                )?;
                let pages = len / 4096;
                if *process.mmio_pages.lock() + pages > crate::device::MAX_MMIO_PAGES {
                    return Err(Error::NoMemory);
                }
                sched::with_current_space(|space| {
                    if !space.range_free(addr, pages) {
                        return Err(Error::InUse);
                    }
                    let mut guard = crate::mm::frames();
                    let frames = guard.as_mut().ok_or(Error::NoMemory)?;
                    for i in 0..pages {
                        let (virt, at) = (addr + i * 4096, phys + i * 4096);
                        if let Err(e) = space.map_device(virt, at, USER_MMIO, frames) {
                            for j in 0..i {
                                let _ = space.unmap(addr + j * 4096);
                            }
                            return Err(e.into());
                        }
                    }
                    Ok(0)
                })
                .ok_or(Error::BadAddress)??;
                *process.mmio_pages.lock() += pages;
                pin(&process, device);
                Ok(0)
            }
            Call::DmaAlloc {
                handle,
                pages,
                addr,
            } => {
                let device = device(&process, handle, cap::MAP)?;
                if !device.dma_fits(pages) {
                    return Err(Error::NoMemory);
                }
                let phys = sched::with_current_space(|space| {
                    if !space.range_free(addr, pages as u64) {
                        return Err(Error::InUse);
                    }
                    let mut guard = crate::mm::frames();
                    let frames = guard.as_mut().ok_or(Error::NoMemory)?;
                    space.map_dma(addr, pages, frames).map_err(|e| match e {
                        MapError::OutOfMemory => Error::NoMemory,
                        _ => Error::BadAddress,
                    })
                })
                .ok_or(Error::BadAddress)??;
                device.add_dma(phys, pages);
                pin(&process, device);
                Ok(phys)
            }
            Call::IrqCreate { handle, entry } => {
                let parent = process.caps.lock().get(handle, cap::IRQ)?;
                let Object::Device(device) = parent.object() else {
                    return Err(Error::MissingRight);
                };
                if process.caps.lock().len() >= MAX_HANDLES {
                    return Err(Error::NoMemory);
                }
                let irq = crate::irq::Irq::create(device.clone(), entry)?;
                let rights = cap::WAIT | (parent.rights() & cap::GRANT);
                let child = parent.derive_object(Object::Interrupt(irq), rights);
                Ok(process.caps.lock().insert(child)?)
            }
            Call::IrqWait { handle } => {
                let cap = process.caps.lock().get(handle, cap::WAIT)?;
                let Object::Interrupt(irq) = cap.object() else {
                    return Err(Error::MissingRight);
                };
                let irq = irq.clone();
                drop((cap, process));
                Ok(crate::irq::wait(&irq)?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::paging::LAST_USER_PAGE;

    #[test]
    fn decodes_valid_calls() {
        assert_eq!(decode(0, [7, 0, 0, 0, 0, 0]), Ok(Call::Exit { code: 7 }));
        assert_eq!(decode(1, [9; 6]), Ok(Call::Yield));
        assert_eq!(
            decode(2, [1, 0x40_0000, 256, 0, 0, 0]),
            Ok(Call::DebugWrite {
                handle: 1,
                addr: 0x40_0000,
                len: 256
            })
        );
        assert_eq!(
            decode(5, [3, 0, 0, 0, 0, 0]),
            Ok(Call::Delete { handle: 3 })
        );
    }

    #[test]
    fn rejects_bad_arguments() {
        assert_eq!(decode(99, [0; 6]), Err(Error::UnknownCall));
        assert_eq!(decode(u64::MAX, [0; 6]), Err(Error::UnknownCall));
        assert_eq!(decode(14, [0; 6]), Err(Error::UnknownCall));
        assert_eq!(
            decode(12, [2, 2047, 0, 0, 0, 0]),
            Ok(Call::IrqCreate {
                handle: 2,
                entry: 2047
            })
        );
        assert_eq!(decode(12, [2, 2048, 0, 0, 0, 0]), Err(Error::NotFound));
        assert_eq!(decode(12, [2, u64::MAX, 0, 0, 0, 0]), Err(Error::NotFound));
        assert_eq!(
            decode(13, [5, 9, 9, 9, 9, 9]),
            Ok(Call::IrqWait { handle: 5 })
        );
        let config = |offset, width| decode(9, [1, offset, width, 0, 0, 0]);
        assert_eq!(
            config(0x10, 4),
            Ok(Call::ConfigRead {
                handle: 1,
                offset: 0x10,
                width: 4
            })
        );
        assert_eq!(config(0xff, 1).map(|_| ()), Ok(()));
        assert_eq!(config(0x11, 2), Err(Error::TooLarge), "unaligned");
        assert_eq!(config(0x100, 1), Err(Error::TooLarge), "past the header");
        assert_eq!(config(0, 3), Err(Error::TooLarge), "bad width");
        let mmio = |len, addr| decode(10, [1, 4, 0, len, addr, 0]);
        assert!(mmio(0x1000, 0x1000_0000).is_ok());
        assert_eq!(
            mmio(0x1000, 0x1000_0010),
            Err(Error::BadAddress),
            "unaligned"
        );
        assert_eq!(mmio(0, 0x1000_0000), Err(Error::BadAddress), "empty");
        assert_eq!(
            mmio(0x1000, 0xffff_ffff_8000_0000),
            Err(Error::BadAddress),
            "kernel"
        );
        let dma = |pages, addr| decode(11, [1, pages, addr, 0, 0, 0]);
        assert_eq!(
            dma(16, 0x2000_0000),
            Ok(Call::DmaAlloc {
                handle: 1,
                pages: 16,
                addr: 0x2000_0000
            })
        );
        assert_eq!(dma(0, 0x2000_0000), Err(Error::TooLarge));
        assert_eq!(dma(17, 0x2000_0000), Err(Error::TooLarge));
        assert_eq!(dma(1, 0), Err(Error::BadAddress), "null page");
        let open = |addr, len| decode(7, [1, addr, len, 0, 0, 0]);
        assert_eq!(
            open(0x40_0000, 104),
            Ok(Call::Open {
                handle: 1,
                addr: 0x40_0000,
                len: 104
            })
        );
        assert_eq!(open(0x40_0000, 105), Err(Error::TooLarge));
        assert_eq!(open(0xffff_ffff_8000_0000, 8), Err(Error::BadAddress));
        let read = |addr, len, offset| decode(8, [2, addr, len, offset, 0, 0]);
        assert_eq!(
            read(0x40_0000, 4096, u64::MAX),
            Ok(Call::Read {
                handle: 2,
                addr: 0x40_0000,
                len: 4096,
                offset: u64::MAX
            })
        );
        assert_eq!(read(0x40_0000, 4097, 0), Err(Error::TooLarge));
        assert_eq!(read(0, 8, 0), Err(Error::BadAddress));
        assert_eq!(
            decode(3, [1, 0x40_0000, 300, 0, 0, 0]),
            Err(Error::TooLarge),
            "send checks its buffer"
        );
        assert_eq!(
            decode(4, [1, 0, 16, 0, 0, 0]),
            Err(Error::BadAddress),
            "receive checks its buffer"
        );
        assert_eq!(
            decode(3, [1, 0x40_0000, 8, 2, u64::MAX, 0]),
            Ok(Call::Send {
                handle: 1,
                addr: 0x40_0000,
                len: 8,
                cap: 2,
                rights: u32::MAX
            })
        );
        assert_eq!(
            decode(6, [4, 0, 0, 0, 0, 0]),
            Ok(Call::Revoke { handle: 4 })
        );
        let write = |addr, len| decode(2, [1, addr, len, 0, 0, 0]);
        assert_eq!(write(0x40_0000, 257), Err(Error::TooLarge));
        assert_eq!(write(0x40_0000, u64::MAX), Err(Error::TooLarge));
        assert_eq!(
            write(0xffff_ffff_8000_0000, 8),
            Err(Error::BadAddress),
            "kernel"
        );
        assert_eq!(write(0, 8), Err(Error::BadAddress), "null page");
        assert_eq!(write(LAST_USER_PAGE - 4, 8), Err(Error::BadAddress));
        assert_eq!(write(u64::MAX - 4, 16), Err(Error::BadAddress), "overflow");
    }

    #[test]
    fn random_input_never_panics_and_accepts_only_safe_buffers() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0;
        for _ in 0..200_000 {
            // Small numbers and lengths often, huge ones sometimes.
            let number = next() % 15;
            let args: [u64; 6] = core::array::from_fn(|_| next() >> (next() % 64));
            match decode(number, args) {
                Ok(
                    Call::DebugWrite { addr, len, .. }
                    | Call::Send { addr, len, .. }
                    | Call::Receive {
                        addr, max_len: len, ..
                    },
                ) => {
                    accepted += 1;
                    assert!(len <= MAX_MESSAGE);
                    assert!(user_range_ok(addr, len as u64));
                }
                Ok(Call::Open { addr, len, .. }) => {
                    accepted += 1;
                    assert!(len <= MAX_PATH);
                    assert!(user_range_ok(addr, len as u64));
                }
                Ok(Call::Read { addr, len, .. }) => {
                    accepted += 1;
                    assert!(len <= MAX_READ);
                    assert!(user_range_ok(addr, len as u64));
                }
                Ok(Call::ConfigRead { offset, width, .. }) => {
                    assert!(matches!(width, 1 | 2 | 4) && offset % width == 0);
                }
                Ok(Call::MmioMap { addr, len, .. }) => {
                    assert!(addr % 4096 == 0 && len % 4096 == 0 && len > 0);
                    assert!(user_range_ok(addr, len));
                }
                Ok(Call::DmaAlloc { addr, pages, .. }) => {
                    assert!((1..=16).contains(&pages) && addr % 4096 == 0);
                    assert!(user_range_ok(addr, pages as u64 * 4096));
                }
                Ok(Call::IrqCreate { entry, .. }) => assert!(entry < 2048),
                Ok(_) => assert!(matches!(number, 0 | 1 | 5 | 6 | 13)),
                Err(error) => assert!(error as u64 >= 1 && error as u64 <= 9),
            }
        }
        assert!(accepted > 0, "the generator must reach valid buffers");
    }
}
