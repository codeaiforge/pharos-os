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
    pub const ENDPOINT_CREATE: u64 = 14;
    pub const SPAWN: u64 = 15;
    pub const PROCESS_STATUS: u64 = 16;
    pub const IRQ_NOTIFY: u64 = 17;
    pub const CALL: u64 = 18;
    pub const MEM_MAP: u64 = 19;
    pub const MEM_UNMAP: u64 = 20;
    pub const SLEEP: u64 = 21;
    pub const MEM_SHARE: u64 = 22;
    pub const MEM_MAP_CAP: u64 = 23;
    pub const UPTIME: u64 = 24;
    pub const PROCESS_STOP: u64 = 25;
    pub const PROCESS_USAGE: u64 = 26;
}

/// What `process_usage` reports (its second argument).
pub mod usage {
    /// CPU time in microseconds.
    pub const CPU_US: u64 = 0;
    /// Pages mapped with `mem_map` and `mem_map_cap` (0 once it has ended).
    pub const PAGES: u64 = 1;
    /// Live processes it started, and they started, and so on.
    pub const DESCENDANTS: u64 = 2;
}

/// `process_status`'s value for a stopped process, beside the killed bit.
pub const STOPPED: u64 = 256;

/// Largest buffer `debug_write` accepts (and the IPC message size).
pub const MAX_MESSAGE: usize = 256;
/// Largest path `open` accepts.
pub const MAX_PATH: usize = pharos_fs::MAX_PATH;
/// Largest buffer `read` accepts.
pub const MAX_READ: usize = 4096;
/// Most capabilities one `spawn` passes (services.md).
pub const MAX_SPAWN_CAPS: usize = 8;
/// Bytes per `spawn` capability entry: handle u64, rights u32, badge u32.
pub const SPAWN_ENTRY: usize = 16;
/// Most live processes (services.md).
pub const MAX_PROCESSES: usize = 32;

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
    BadProgram = 10,
    WouldBlock = 11,
    TimedOut = 12,
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
            IrqError::TimedOut => Self::TimedOut,
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
        /// Badge for the passed capability, if it has none yet.
        badge: u32,
        /// Fail with `WOULD_BLOCK` instead of waiting for a receiver.
        nonblocking: bool,
    },
    Receive {
        handle: Handle,
        addr: u64,
        max_len: usize,
        /// Microseconds (`u64::MAX`: forever, 0: do not block).
        timeout: u64,
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
        timeout: u64,
    },
    EndpointCreate,
    Spawn {
        handle: Handle,
        arg: u64,
        /// User address of `count` capability entries.
        addr: u64,
        count: usize,
        /// Endpoint to notify when the child ends (0 = none).
        endpoint: Handle,
        bit: u32,
        /// The child's `mem_map` limit in pages.
        limit: u64,
        /// The child's scheduling class plus one; 0 is the creator's.
        class: u8,
        /// Live descendants the child may have.
        processes: u64,
        /// Handles for the child and its descendants (0: a full table).
        handles: u64,
    },
    ProcessStatus {
        handle: Handle,
    },
    ProcessUsage {
        handle: Handle,
        what: u64,
    },
    ProcessStop {
        handle: Handle,
    },
    IrqNotify {
        handle: Handle,
        endpoint: Handle,
        bit: u32,
    },
    Call {
        handle: Handle,
        /// One buffer: the request (`len` bytes), then the reply (`max`).
        addr: u64,
        len: usize,
        reply: Handle,
        max: usize,
        timeout: u64,
    },
    Sleep {
        micros: u64,
    },
    Uptime,
    MemMap {
        pages: u64,
    },
    MemUnmap {
        addr: u64,
        pages: u64,
    },
    MemShare {
        addr: u64,
        pages: u64,
    },
    MemMapCap {
        handle: Handle,
        writable: bool,
        /// Must equal the shared object's size (so the caller knows its
        /// bounds).
        pages: u64,
    },
}

/// A whole-mapping range in the map region (`mem_unmap`, `mem_share`).
fn mapping(addr: u64, len: u64) -> Result<(u64, u64), Error> {
    match map_pages(len) {
        Some(pages) if addr % 4096 == 0 && crate::process::MAP_REGION.contains(&addr) => {
            Ok((addr, pages))
        }
        _ => Err(Error::BadAddress),
    }
}

/// Pages in a `mem_map`/`mem_unmap` length: rounded up, at least one, at
/// most the whole map region.
fn map_pages(len: u64) -> Option<u64> {
    let region = crate::process::MAP_REGION.end - crate::process::MAP_REGION.start;
    (len != 0 && len <= region).then(|| len.div_ceil(4096))
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
            // Rights in bits 0-31, a badge in bits 32-55: checked by the
            // handler, after the handles, and only if a capability is passed.
            rights: args[4] as cap::Rights,
            badge: (args[4] >> 32) as u32,
            // Bit 0 of the flags; other bits name nothing.
            nonblocking: args[5] & 1 != 0,
        }),
        number::RECEIVE => Ok(Call::Receive {
            handle: args[0],
            addr: args[1],
            max_len: buffer(args[1], args[2])?,
            timeout: args[3],
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
        number::IRQ_WAIT => Ok(Call::IrqWait {
            handle: args[0],
            timeout: args[1],
        }),
        number::SLEEP => Ok(Call::Sleep { micros: args[0] }),
        number::UPTIME => Ok(Call::Uptime),
        number::ENDPOINT_CREATE => Ok(Call::EndpointCreate),
        number::SPAWN => {
            // Capabilities in bits 0-31, the child's page limit in 32-63;
            // in the last argument the notification bit in bits 0-31, the
            // class (plus one; 0: the creator's) in 32-33, the child's
            // descendants in 40-47 and handles in 48-59 (D-022), the rest 0.
            let (count, limit, bit) = (args[3] & 0xffff_ffff, args[3] >> 32, args[5] & 0xffff_ffff);
            let (class, processes, handles) =
                (args[5] >> 32 & 0xff, args[5] >> 40 & 0xff, args[5] >> 48);
            if count > MAX_SPAWN_CAPS as u64 || bit >= 32 || class > 3 || handles >= 1 << 12 {
                return Err(Error::TooLarge);
            }
            Ok(Call::Spawn {
                handle: args[0],
                arg: args[1],
                addr: args[2],
                // With no capabilities the array is never read.
                count: match count {
                    0 => 0,
                    _ => {
                        buffer_up_to(
                            MAX_SPAWN_CAPS * SPAWN_ENTRY,
                            args[2],
                            count * SPAWN_ENTRY as u64,
                        )? / SPAWN_ENTRY
                    }
                },
                endpoint: args[4],
                bit: bit as u32,
                limit,
                class: class as u8,
                processes,
                handles: match handles {
                    0 => crate::process::DEFAULT_HANDLES,
                    n => n,
                },
            })
        }
        number::PROCESS_STATUS => Ok(Call::ProcessStatus { handle: args[0] }),
        number::PROCESS_USAGE => match args[1] {
            what @ 0..=2 => Ok(Call::ProcessUsage {
                handle: args[0],
                what,
            }),
            _ => Err(Error::TooLarge),
        },
        number::PROCESS_STOP => Ok(Call::ProcessStop { handle: args[0] }),
        number::CALL => Ok(Call::Call {
            handle: args[0],
            addr: args[1],
            len: buffer(args[1], args[2])?,
            reply: args[3],
            max: buffer(args[1], args[4])?,
            timeout: args[5],
        }),
        number::IRQ_NOTIFY => match args[2] {
            bit @ 0..32 => Ok(Call::IrqNotify {
                handle: args[0],
                endpoint: args[1],
                bit: bit as u32,
            }),
            _ => Err(Error::TooLarge),
        },
        number::MEM_MAP => Ok(Call::MemMap {
            pages: map_pages(args[0]).ok_or(Error::TooLarge)?,
        }),
        number::MEM_UNMAP => {
            let (addr, pages) = mapping(args[0], args[1])?;
            Ok(Call::MemUnmap { addr, pages })
        }
        number::MEM_SHARE => {
            let (addr, pages) = mapping(args[0], args[1])?;
            Ok(Call::MemShare { addr, pages })
        }
        number::MEM_MAP_CAP => Ok(Call::MemMapCap {
            handle: args[0],
            writable: match args[1] {
                0 => false,
                1 => true,
                _ => return Err(Error::TooLarge),
            },
            pages: map_pages(args[2]).ok_or(Error::TooLarge)?,
        }),
        _ => Err(Error::UnknownCall),
    }
}

/// Needed right for each capability-using call.
pub fn needed_rights(call: &Call) -> cap::Rights {
    match call {
        Call::DebugWrite { .. } => cap::WRITE,
        Call::Send { .. } | Call::Call { .. } => cap::SEND,
        Call::Receive { .. } => cap::RECEIVE,
        Call::Open { .. } | Call::Read { .. } => cap::READ,
        Call::ConfigRead { .. } => cap::CONFIG,
        Call::MmioMap { .. } | Call::DmaAlloc { .. } => cap::MAP,
        Call::IrqCreate { .. } => cap::IRQ,
        Call::IrqWait { .. }
        | Call::ProcessStatus { .. }
        | Call::ProcessUsage { .. }
        | Call::IrqNotify { .. } => cap::WAIT,
        Call::ProcessStop { .. } => cap::STOP,
        Call::Spawn { .. } => cap::READ,
        _ => 0,
    }
}

#[cfg(target_os = "none")]
pub use kernel::handle;

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::syscall::SyscallFrame;
    use crate::cap::Object;
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
        device_cap(process, handle, needed).map(|(_, device)| device)
    }

    /// [`device`] and the capability itself, which a mapping records so
    /// that revoking it reaches the mapping (#104).
    fn device_cap(
        process: &process::Process,
        handle: Handle,
        needed: cap::Rights,
    ) -> Result<
        (
            alloc::sync::Arc<cap::Capability>,
            alloc::sync::Arc<crate::device::DeviceHandle>,
        ),
        Error,
    > {
        let cap = process.caps.lock().get(handle, needed)?;
        match cap.object() {
            Object::Device(device) => {
                let device = device.clone();
                Ok((cap, device))
            }
            _ => Err(Error::MissingRight),
        }
    }

    /// Records a device mapping and keeps the device alive ([`pin`]).
    fn record_device(
        process: &process::Process,
        via: alloc::sync::Arc<cap::Capability>,
        device: alloc::sync::Arc<crate::device::DeviceHandle>,
        start: u64,
        pages: u64,
    ) {
        process.devices.lock().push(process::DeviceMapping {
            start,
            pages,
            via,
            device: device.clone(),
        });
        pin(process, device);
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

    /// `send`, in its own function for the same reason as [`do_call`].
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn do_send(
        process: alloc::sync::Arc<process::Process>,
        handle: Handle,
        addr: u64,
        len: usize,
        cap: Handle,
        rights: cap::Rights,
        badge: u32,
        nonblocking: bool,
    ) -> Result<u64, Error> {
        let sent_through = process.caps.lock().get(handle, cap::SEND)?;
        let Object::Endpoint(endpoint) = sent_through.object() else {
            return Err(Error::MissingRight);
        };
        let endpoint = endpoint.clone();
        let mut message = Message {
            data: [0; MAX_MESSAGE],
            len,
            cap: None,
            badge: sent_through.badge(),
        };
        sched::with_current_space(|space| space.read_user(addr, &mut message.data[..len]))
            .ok_or(Error::BadAddress)??;
        if cap != 0 {
            let passed = process.caps.lock().get(cap, cap::GRANT)?;
            if badge > cap::BADGE_MASK {
                return Err(Error::TooLarge);
            }
            message.cap = Some(passed.derive_badged(rights, badge));
        }
        drop(process);
        if nonblocking {
            return match ipc::try_send(&endpoint, message) {
                true => Ok(0),
                false => Err(Error::WouldBlock),
            };
        }
        // System calls run with interrupts off.
        ipc::send_now(&endpoint, message);
        Ok(0)
    }

    /// `call` (networking.md), in its own function: its message buffer
    /// stays off the dispatcher's stack frame, which every system call
    /// pays for on the kernel stack (D-013).
    #[inline(never)]
    fn do_call(
        process: &process::Process,
        handle: Handle,
        addr: u64,
        len: usize,
        reply: Handle,
        max: usize,
        timeout: u64,
    ) -> Result<u64, Error> {
        let sent_through = process.caps.lock().get(handle, cap::SEND)?;
        let Object::Endpoint(endpoint) = sent_through.object() else {
            return Err(Error::MissingRight);
        };
        let reply_cap = process.caps.lock().get(reply, cap::SEND | cap::RECEIVE)?;
        let Object::Endpoint(reply_endpoint) = reply_cap.object() else {
            return Err(Error::MissingRight);
        };
        // Check everything before sending, so no reply is lost.
        sched::with_current_space(|space| space.check_user(addr, max, true))
            .ok_or(Error::BadAddress)??;
        if process.caps.lock().full() {
            return Err(Error::NoMemory);
        }
        if !reply_endpoint.is_idle() {
            return Err(Error::InUse);
        }
        // Replies are one-shot: the server's capability is a child of
        // `one_shot`, revoked as soon as the call returns, so a server
        // cannot keep it and slip a "reply" into a later call.
        let one_shot = reply_cap.derive(cap::SEND);
        let mut message = Message {
            data: [0; MAX_MESSAGE],
            len,
            cap: Some(one_shot.derive(cap::SEND)),
            badge: sent_through.badge(),
        };
        sched::with_current_space(|space| space.read_user(addr, &mut message.data[..len]))
            .ok_or(Error::BadAddress)??;
        let received = ipc::call_now(endpoint, message, reply_endpoint, sched::deadline(timeout));
        one_shot.revoke();
        deliver(process, received.ok_or(Error::UnknownCall)?, addr, max)
    }

    /// Copies a received message out (cut to `max` bytes; the value reports
    /// the full length) and installs its capability; returns `receive`'s
    /// value.
    fn deliver(
        process: &process::Process,
        received: ipc::Received,
        addr: u64,
        max: usize,
    ) -> Result<u64, Error> {
        let message = match received {
            ipc::Received::Message(message) => message,
            ipc::Received::Notification(bits) => return Ok(1 << 16 | u64::from(bits) << 32),
            ipc::Received::TimedOut => return Err(Error::TimedOut),
        };
        let copied = message.len.min(max);
        sched::with_current_space(|space| space.write_user(addr, &message.data[..copied]))
            .ok_or(Error::BadAddress)??;
        let new_handle = match message.cap {
            Some(cap) => process.caps.lock().insert(cap)?,
            None => 0,
        };
        Ok(message.len as u64 | new_handle << 32 | u64::from(message.badge) << 40)
    }

    /// `mem_map`: the limit is checked before any frame is allocated; on
    /// failure nothing stays mapped.
    fn mem_map(process: &process::Process, pages: u64) -> Result<u64, Error> {
        use crate::arch::x86_64::paging::Flags;
        let start = process
            .memory
            .lock()
            .reserve(pages)
            .ok_or(Error::NoMemory)?;
        // In batches, with interrupts on between them, so a large mapping
        // does not hold the CPU while it zeroes its pages (D-022). No lock is
        // held between batches; the region is reserved, so nothing else
        // maps there. A process told to stop meanwhile gives up.
        let unmap = |done: u64| {
            sched::with_current_space(|space| {
                let mut guard = crate::mm::frames();
                if let Some(frames) = guard.as_mut() {
                    for j in 0..done {
                        space.unmap_owned(start + j * 4096, frames);
                    }
                }
            });
            process.memory.lock().release(start, pages);
        };
        let mut done = 0;
        while done < pages {
            let batch = (pages - done).min(MAP_BATCH);
            let mapped = sched::with_current_space(|space| {
                let mut guard = crate::mm::frames();
                let frames = guard.as_mut()?;
                for i in done..done + batch {
                    if space
                        .map_new_page(start + i * 4096, Flags::USER_DATA, &[], frames)
                        .is_err()
                    {
                        for j in done..i {
                            space.unmap_owned(start + j * 4096, frames);
                        }
                        return None;
                    }
                }
                Some(())
            });
            if mapped.flatten().is_none() {
                unmap(done);
                return Err(Error::NoMemory);
            }
            done += batch;
            if done < pages {
                // A tick or device interrupt here switches to a woken task.
                crate::arch::x86_64::interrupt_window();
                if sched::stopping() {
                    unmap(done);
                    return Err(Error::NoMemory);
                }
            }
        }
        Ok(start)
    }

    /// Pages `mem_map` maps and zeroes between two chances for interrupts.
    const MAP_BATCH: u64 = 64;

    /// `mem_share`: turns one whole `mem_map` mapping into a `Memory`
    /// object (or returns another capability on it, if already shared) and
    /// a capability with `READ`, `WRITE`, and `GRANT`. A mapping from
    /// `mem_map_cap` is refused (`BAD_ADDRESS`): it is not the caller's.
    fn mem_share(process: &process::Process, addr: u64, pages: u64) -> Result<u64, Error> {
        use alloc::vec::Vec;
        if !process.memory.lock().contains(addr, pages) {
            return Err(Error::BadAddress);
        }
        if process.caps.lock().full() {
            return Err(Error::NoMemory);
        }
        let existing = process
            .shared
            .lock()
            .iter()
            .find(|s| s.start == addr)
            .map(|s| (s.memory.clone(), s.own));
        let memory = match existing {
            Some((memory, true)) => memory,
            Some((_, false)) => return Err(Error::BadAddress),
            None => {
                let mut frames = Vec::new();
                frames
                    .try_reserve_exact(pages as usize)
                    .map_err(|_| Error::NoMemory)?;
                // The kernel's frame list (8 bytes a page) is charged to the
                // sharer, one page per 512, until it ends (D-022).
                if !process.memory.lock().take(pages.div_ceil(512), true) {
                    return Err(Error::NoMemory);
                }
                // Every page of a recorded mapping is mapped and owned, so
                // `disown` cannot fail part-way.
                sched::with_current_space(|space| {
                    (0..pages)
                        .try_for_each(|i| space.disown(addr + i * 4096).map(|p| frames.push(p)))
                })
                .ok_or(Error::BadAddress)??;
                let memory = process::SharedMemory::new(frames);
                process.shared.lock().push(process::SharedMapping {
                    start: addr,
                    memory: memory.clone(),
                    own: true,
                    via: None,
                    writable: true,
                });
                memory
            }
        };
        let rights = cap::READ | cap::WRITE | cap::GRANT;
        let cap = cap::Capability::new(Object::Memory(memory), rights);
        Ok(process.caps.lock().insert(cap)?)
    }

    /// `mem_map_cap`: maps a `Memory` object at the first gap of the map
    /// region, read-only or writable as the capability allows, never
    /// executable; counted against the caller's limit.
    fn mem_map_cap(
        process: &process::Process,
        handle: Handle,
        writable: bool,
        pages: u64,
    ) -> Result<u64, Error> {
        use crate::arch::x86_64::paging::Flags;
        let needed = cap::READ | if writable { cap::WRITE } else { 0 };
        let via = process.caps.lock().get(handle, needed)?;
        let memory = match via.object() {
            Object::Memory(memory) => memory.clone(),
            _ => return Err(Error::MissingRight),
        };
        if memory.frames().len() as u64 != pages {
            return Err(Error::TooLarge);
        }
        let start = process
            .memory
            .lock()
            .reserve(pages)
            .ok_or(Error::NoMemory)?;
        let flags = Flags {
            writable,
            executable: false,
            uncached: false,
            user: true,
        };
        let mapped = sched::with_current_space(|space| {
            let mut guard = crate::mm::frames();
            let frames = guard.as_mut()?;
            for (i, &phys) in memory.frames().iter().enumerate() {
                let virt = start + i as u64 * 4096;
                if space.map_device(virt, phys, flags, frames).is_err() {
                    for j in 0..i as u64 {
                        let _ = space.unmap(start + j * 4096);
                    }
                    return None;
                }
            }
            Some(())
        });
        if mapped.flatten().is_none() {
            process.memory.lock().release(start, pages);
            return Err(Error::NoMemory);
        }
        process.shared.lock().push(process::SharedMapping {
            start,
            memory,
            own: false,
            via: Some(via),
            writable,
        });
        Ok(start)
    }

    /// `spawn`: every handle and the limits are checked before anything is
    /// allocated; then the program is loaded and checked.
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        process: &process::Process,
        handle: Handle,
        arg: u64,
        addr: u64,
        count: usize,
        endpoint: Handle,
        bit: u32,
        limit: u64,
        class: u8,
        processes: u64,
        handles: u64,
    ) -> Result<u64, Error> {
        // Never above the creator's class (D-022 item 1).
        let class = match class {
            0 => sched::current_class(),
            c => c - 1,
        };
        if class < sched::current_class() {
            return Err(Error::TooLarge);
        }
        let file = process.caps.lock().get(handle, cap::READ)?;
        let Object::File { fs, file } = file.object() else {
            return Err(Error::MissingRight);
        };
        let mut entries = [0u8; MAX_SPAWN_CAPS * SPAWN_ENTRY];
        let entries = &mut entries[..count * SPAWN_ENTRY];
        sched::with_current_space(|space| space.read_user(addr, entries))
            .ok_or(Error::BadAddress)??;
        let mut caps = alloc::vec::Vec::new();
        for entry in entries.chunks_exact(SPAWN_ENTRY) {
            let field = |at: usize, len: usize| {
                entry[at..at + len]
                    .iter()
                    .rev()
                    .fold(0u64, |v, &b| v << 8 | u64::from(b))
            };
            let parent = process.caps.lock().get(field(0, 8), cap::GRANT)?;
            let badge = field(12, 4);
            if badge > u64::from(cap::BADGE_MASK) {
                return Err(Error::TooLarge);
            }
            caps.push(parent.derive_badged(field(8, 4) as cap::Rights, badge as u32));
        }
        let notify = match endpoint {
            0 => None,
            handle => Some(self::endpoint(process, handle, cap::RECEIVE)?),
        };
        if process.caps.lock().full() || process::count() >= MAX_PROCESSES {
            return Err(Error::NoMemory);
        }
        // Carved from the creator's (D-022): returned when the child ends.
        let budget = process::Budget {
            pages: limit,
            processes,
            handles,
        };
        if caps.len() as u64 > handles || !process.give(&budget) {
            return Err(Error::TooLarge);
        }
        let id = match start_child(fs, *file, arg, caps, budget, class) {
            Ok(id) => id,
            Err(e) => {
                process.take_back(&budget);
                return Err(e);
            }
        };
        let record = process::by_id(id).ok_or(Error::NoMemory)?.record.clone();
        if let Some(endpoint) = notify {
            record.notify_on_end(endpoint, 1 << bit);
        }
        let child =
            cap::Capability::new(Object::Process(record), cap::WAIT | cap::GRANT | cap::STOP);
        Ok(process.caps.lock().insert(child)?)
    }

    /// Loads and starts a child with `budget`, already taken from its
    /// creator's.
    fn start_child(
        fs: &crate::fs::Fs,
        file: pharos_fs::FileId,
        arg: u64,
        caps: alloc::vec::Vec<alloc::sync::Arc<cap::Capability>>,
        budget: process::Budget,
        class: sched::Class,
    ) -> Result<u64, Error> {
        let (space, entry) = process::load_elf_file(fs, file).map_err(|e| match e {
            process::ProcessError::Map(_) | process::ProcessError::NoFrameAllocator => {
                Error::NoMemory
            }
            _ => Error::BadProgram,
        })?;
        process::start_class(space, entry - process::USER_BASE, arg, caps, budget, class)
            .map_err(|_| Error::NoMemory)
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
        // A task of a higher class woken by this call runs now (D-022).
        sched::preempt();
        // Told to end (by another process, itself, or its parent ending):
        // it ends here instead of returning to user mode.
        if sched::stopping() {
            process::end_stopped();
        }
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
                badge,
                nonblocking,
            } => do_send(process, handle, addr, len, cap, rights, badge, nonblocking),
            Call::Call {
                handle,
                addr,
                len,
                reply,
                max,
                timeout,
            } => do_call(&process, handle, addr, len, reply, max, timeout),
            Call::Receive {
                handle,
                addr,
                max_len,
                timeout,
            } => {
                let endpoint = endpoint(&process, handle, cap::RECEIVE)?;
                // Check everything before taking a message, so none is lost.
                sched::with_current_space(|space| space.check_user(addr, max_len, true))
                    .ok_or(Error::BadAddress)??;
                if process.caps.lock().full() {
                    return Err(Error::NoMemory);
                }
                let received = ipc::receive_now(&endpoint, sched::deadline(timeout))
                    .ok_or(Error::UnknownCall)?;
                deliver(&process, received, addr, max_len)
            }
            Call::Revoke { handle } => {
                let cap = process.caps.lock().get(handle, 0)?;
                drop(process);
                Ok(process::revoke(&cap) as u64)
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
                // On the heap: kernel stacks are small (32 KiB, D-013).
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
                let (via, device) = device_cap(&process, handle, cap::MAP)?;
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
                record_device(&process, via, device, addr, pages);
                Ok(0)
            }
            Call::DmaAlloc {
                handle,
                pages,
                addr,
            } => {
                let (via, device) = device_cap(&process, handle, cap::MAP)?;
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
                record_device(&process, via, device, addr, pages as u64);
                Ok(phys)
            }
            Call::IrqCreate { handle, entry } => {
                let parent = process.caps.lock().get(handle, cap::IRQ)?;
                let Object::Device(device) = parent.object() else {
                    return Err(Error::MissingRight);
                };
                if process.caps.lock().full() {
                    return Err(Error::NoMemory);
                }
                let irq = crate::irq::Irq::create(device.clone(), entry)?;
                let rights = cap::WAIT | (parent.rights() & cap::GRANT);
                let child = parent.derive_object(Object::Interrupt(irq), rights);
                Ok(process.caps.lock().insert(child)?)
            }
            Call::IrqWait { handle, timeout } => {
                let cap = process.caps.lock().get(handle, cap::WAIT)?;
                let Object::Interrupt(irq) = cap.object() else {
                    return Err(Error::MissingRight);
                };
                let irq = irq.clone();
                drop((cap, process));
                Ok(crate::irq::wait(&irq, sched::deadline(timeout))?)
            }
            Call::Sleep { micros } => {
                drop(process);
                // `sleep` rounds as `deadline` does; 0 does not sleep, and
                // u64::MAX sleeps forever.
                if micros != 0 {
                    sched::sleep(core::time::Duration::from_micros(micros));
                }
                Ok(0)
            }
            // Microseconds since boot, for timing work (D-021). Needs no
            // capability: timeouts already let a program measure time.
            Call::Uptime => Ok(crate::time::uptime().as_micros() as u64),
            Call::EndpointCreate => {
                let endpoint = Object::Endpoint(ipc::Endpoint::new());
                let rights = cap::SEND | cap::RECEIVE | cap::GRANT;
                Ok(process
                    .caps
                    .lock()
                    .insert(cap::Capability::new(endpoint, rights))?)
            }
            Call::Spawn {
                handle,
                arg,
                addr,
                count,
                endpoint,
                bit,
                limit,
                class,
                processes,
                handles,
            } => spawn(
                &process, handle, arg, addr, count, endpoint, bit, limit, class, processes, handles,
            ),
            Call::MemMap { pages } => mem_map(&process, pages),
            Call::MemUnmap { addr, pages } => {
                if !process.memory.lock().release(addr, pages) {
                    return Err(Error::BadAddress);
                }
                let shared = {
                    let mut list = process.shared.lock();
                    let at = list.iter().position(|s| s.start == addr);
                    at.map(|at| list.remove(at))
                };
                sched::with_current_space(|space| {
                    let mut guard = crate::mm::frames();
                    if let Some(frames) = guard.as_mut() {
                        for i in 0..pages {
                            match shared {
                                // The object owns the frames.
                                Some(_) => drop(space.unmap(addr + i * 4096)),
                                None => space.unmap_owned(addr + i * 4096, frames),
                            }
                        }
                    }
                });
                // Dropped here, after the frame allocator's lock: this may
                // have been the last reference.
                drop(shared);
                Ok(0)
            }
            Call::MemShare { addr, pages } => mem_share(&process, addr, pages),
            Call::MemMapCap {
                handle,
                writable,
                pages,
            } => mem_map_cap(&process, handle, writable, pages),
            Call::IrqNotify {
                handle,
                endpoint,
                bit,
            } => {
                let cap = process.caps.lock().get(handle, cap::WAIT)?;
                let Object::Interrupt(irq) = cap.object() else {
                    return Err(Error::MissingRight);
                };
                let target = self::endpoint(&process, endpoint, cap::RECEIVE)?;
                irq.bind(target, 1 << bit)?;
                Ok(0)
            }
            Call::ProcessStatus { handle } => {
                let cap = process.caps.lock().get(handle, cap::WAIT)?;
                let Object::Process(record) = cap.object() else {
                    return Err(Error::MissingRight);
                };
                const VALUE: u64 = (1 << 62) - 1;
                Ok(match record.end() {
                    None => 0,
                    Some(process::End::Exited(code)) => 1 << 63 | code & VALUE,
                    Some(process::End::Killed(vector)) => 1 << 63 | 1 << 62 | vector & VALUE,
                    // Exception vectors are below 32, so 256 is free.
                    Some(process::End::Stopped) => 1 << 63 | 1 << 62 | STOPPED,
                })
            }
            Call::ProcessUsage { handle, what } => {
                let cap = process.caps.lock().get(handle, cap::WAIT)?;
                let Object::Process(record) = cap.object() else {
                    return Err(Error::MissingRight);
                };
                let record = record.clone();
                drop((cap, process));
                Ok(match what {
                    usage::CPU_US => crate::time::cycles_to_micros(record.cpu_cycles()),
                    usage::PAGES => process::by_id(record.id).map_or(0, |p| p.memory.lock().used),
                    _ => process::descendants(record.id) as u64,
                })
            }
            // Ends the process and the processes it started (agents.md).
            // Returns at once; `process_status` shows when it has ended.
            Call::ProcessStop { handle } => {
                let cap = process.caps.lock().get(handle, cap::STOP)?;
                let Object::Process(record) = cap.object() else {
                    return Err(Error::MissingRight);
                };
                let id = record.id;
                drop((cap, process));
                process::stop(id);
                Ok(0)
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
        assert_eq!(decode(27, [0; 6]), Err(Error::UnknownCall));
        let region = crate::process::MAP_REGION;
        assert_eq!(
            decode(22, [region.start, 8192, 9, 9, 9, 9]),
            Ok(Call::MemShare {
                addr: region.start,
                pages: 2
            })
        );
        assert_eq!(
            decode(22, [0x40_0000, 4096, 0, 0, 0, 0]),
            Err(Error::BadAddress)
        );
        assert_eq!(
            decode(23, [3, 1, 4097, 9, 9, 9]),
            Ok(Call::MemMapCap {
                handle: 3,
                writable: true,
                pages: 2
            })
        );
        assert_eq!(
            decode(23, [3, 2, 4096, 0, 0, 0]),
            Err(Error::TooLarge),
            "writable is 0 or 1"
        );
        assert_eq!(
            decode(23, [3, 0, 0, 0, 0, 0]),
            Err(Error::TooLarge),
            "no length"
        );
        assert_eq!(
            decode(18, [2, 0x40_0000, 8, 3, 256, 7]),
            Ok(Call::Call {
                handle: 2,
                addr: 0x40_0000,
                len: 8,
                reply: 3,
                max: 256,
                timeout: 7
            })
        );
        assert_eq!(
            decode(18, [2, 0x40_0000, 8, 3, 257, 0]),
            Err(Error::TooLarge)
        );
        assert_eq!(
            decode(18, [2, 0x40_0000, 300, 3, 8, 0]),
            Err(Error::TooLarge)
        );
        assert_eq!(decode(18, [2, 0, 8, 3, 8, 0]), Err(Error::BadAddress));
        assert!(matches!(
            decode(3, [1, 0x40_0000, 8, 0, 0, 1]),
            Ok(Call::Send {
                nonblocking: true,
                ..
            })
        ));
        assert_eq!(
            decode(17, [5, 6, 31, 9, 9, 9]),
            Ok(Call::IrqNotify {
                handle: 5,
                endpoint: 6,
                bit: 31
            })
        );
        assert_eq!(decode(17, [5, 6, 32, 0, 0, 0]), Err(Error::TooLarge));
        assert_eq!(decode(14, [9; 6]), Ok(Call::EndpointCreate));
        assert_eq!(
            decode(16, [3, 0, 0, 0, 0, 0]),
            Ok(Call::ProcessStatus { handle: 3 })
        );
        let spawn = |addr, count, bit| decode(15, [2, 7, addr, count, 4, bit]);
        assert_eq!(
            spawn(0x40_0000, 8, 31),
            Ok(Call::Spawn {
                handle: 2,
                arg: 7,
                addr: 0x40_0000,
                count: 8,
                endpoint: 4,
                bit: 31,
                limit: 0,
                class: 0,
                processes: 0,
                handles: 64
            })
        );
        assert!(
            matches!(
                spawn(0x40_0000, 1 | 256 << 32, 0),
                Ok(Call::Spawn {
                    count: 1,
                    limit: 256,
                    ..
                })
            ),
            "the limit rides in bits 32-63"
        );
        assert!(spawn(0, 0, 0).is_ok(), "no capabilities: no buffer");
        assert_eq!(
            spawn(0x40_0000, 9, 0),
            Err(Error::TooLarge),
            "9 capabilities"
        );
        assert_eq!(spawn(0x40_0000, 1, 32), Err(Error::TooLarge), "bit 32");
        assert!(
            matches!(
                spawn(0, 0, 5 | 3 << 32),
                Ok(Call::Spawn {
                    bit: 5,
                    class: 3,
                    ..
                })
            ),
            "the class rides in bits 32-33 of the last argument"
        );
        assert_eq!(spawn(0, 0, 4 << 32), Err(Error::TooLarge), "class above 3");
        assert!(
            matches!(
                spawn(0, 0, 2 << 40 | 8 << 48),
                Ok(Call::Spawn {
                    processes: 2,
                    handles: 8,
                    ..
                })
            ),
            "descendants in bits 40-47, handles in 48-59"
        );
        assert_eq!(spawn(0, 0, 1 << 60), Err(Error::TooLarge), "bits above 59");
        assert_eq!(
            decode(26, [3, 2, 0, 0, 0, 0]),
            Ok(Call::ProcessUsage { handle: 3, what: 2 })
        );
        assert_eq!(decode(26, [3, 3, 0, 0, 0, 0]), Err(Error::TooLarge));
        assert_eq!(spawn(0, 1, 0), Err(Error::BadAddress), "null page");

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
            Ok(Call::IrqWait {
                handle: 5,
                timeout: 9
            })
        );
        assert!(matches!(
            decode(4, [1, 0x40_0000, 8, u64::MAX, 0, 0]),
            Ok(Call::Receive {
                timeout: u64::MAX,
                ..
            })
        ));
        assert_eq!(
            decode(21, [0, 9, 9, 9, 9, 9]),
            Ok(Call::Sleep { micros: 0 })
        );
        assert_eq!(decode(24, [9; 6]), Ok(Call::Uptime));
        assert_eq!(
            decode(25, [4, 9, 9, 9, 9, 9]),
            Ok(Call::ProcessStop { handle: 4 })
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
        let region = crate::process::MAP_REGION;
        let map = |len| decode(19, [len, 9, 9, 9, 9, 9]);
        assert_eq!(map(1), Ok(Call::MemMap { pages: 1 }));
        assert_eq!(map(4097), Ok(Call::MemMap { pages: 2 }));
        assert_eq!(map(0), Err(Error::TooLarge));
        assert_eq!(map(u64::MAX), Err(Error::TooLarge));
        let unmap = |addr, len| decode(20, [addr, len, 9, 9, 9, 9]);
        assert_eq!(
            unmap(region.start, 4097),
            Ok(Call::MemUnmap {
                addr: region.start,
                pages: 2
            })
        );
        assert_eq!(
            unmap(region.start + 8, 4096),
            Err(Error::BadAddress),
            "unaligned"
        );
        assert_eq!(unmap(region.start, 0), Err(Error::BadAddress), "empty");
        assert_eq!(
            unmap(region.end, 4096),
            Err(Error::BadAddress),
            "past the region"
        );
        assert_eq!(
            unmap(0x40_0000, 4096),
            Err(Error::BadAddress),
            "the program"
        );
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
            decode(3, [1, 0x40_0000, 8, 2, u64::from(u32::MAX), 0]),
            Ok(Call::Send {
                handle: 1,
                addr: 0x40_0000,
                len: 8,
                cap: 2,
                rights: u32::MAX,
                badge: 0,
                nonblocking: false
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
            let number = next() % 25;
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
                Ok(Call::Spawn {
                    addr,
                    count,
                    bit,
                    class,
                    ..
                }) => {
                    assert!(count <= MAX_SPAWN_CAPS && bit < 32 && class <= 3);
                    assert!(count == 0 || user_range_ok(addr, (count * SPAWN_ENTRY) as u64));
                }
                Ok(Call::IrqNotify { bit, .. }) => assert!(bit < 32),
                Ok(Call::MemMap { pages } | Call::MemMapCap { pages, .. }) => assert!(pages > 0),
                Ok(Call::MemShare { addr, pages }) => {
                    let region = crate::process::MAP_REGION;
                    assert!(pages > 0 && addr % 4096 == 0 && region.contains(&addr));
                }
                Ok(Call::MemUnmap { addr, pages }) => {
                    let region = crate::process::MAP_REGION;
                    assert!(pages > 0 && addr % 4096 == 0 && region.contains(&addr));
                }
                Ok(Call::Call { addr, len, max, .. }) => {
                    accepted += 1;
                    assert!(len <= MAX_MESSAGE && max <= MAX_MESSAGE);
                    assert!(user_range_ok(addr, len as u64) && user_range_ok(addr, max as u64));
                }
                Ok(_) => assert!(matches!(
                    number,
                    0 | 1 | 5 | 6 | 13 | 14 | 16 | 21 | 24 | 25
                )),
                Err(error) => assert!(error as u64 >= 1 && error as u64 <= 12),
            }
        }
        assert!(accepted > 0, "the generator must reach valid buffers");
    }
}
