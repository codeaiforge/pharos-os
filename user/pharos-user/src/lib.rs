//! Pharos OS user-space library ([drivers.md](../../../docs/architecture/drivers.md)):
//! safe wrappers for every system call, the program entry point, and a
//! panic handler. Programs start with [`entry!`].
//!
//! `no_std`. The only `unsafe` code is in the `syscall` module.

#![cfg_attr(not(test), no_std)]

mod syscall;

pub use syscall::{Mapped, vector};

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
}

/// Capability rights (syscalls-ipc.md, drivers.md, services.md).
pub mod rights {
    pub const SEND: u32 = 1;
    pub const RECEIVE: u32 = 1 << 1;
    pub const GRANT: u32 = 1 << 2;
    pub const WRITE: u32 = 1 << 3;
    pub const READ: u32 = 1 << 4;
    pub const MAP: u32 = 1 << 5;
    pub const IRQ: u32 = 1 << 6;
    pub const CONFIG: u32 = 1 << 7;
    pub const WAIT: u32 = 1 << 8;
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
    BadProgram,
    WouldBlock,
    /// Nothing arrived before the timeout.
    TimedOut,
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
            10 => Self::BadProgram,
            11 => Self::WouldBlock,
            12 => Self::TimedOut,
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
            Self::BadProgram => 10,
            Self::WouldBlock => 11,
            Self::TimedOut => 12,
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
/// `rights`, and `badge` if `cap` has none yet.
pub fn send(
    endpoint: Handle,
    bytes: &[u8],
    cap: Handle,
    rights: u32,
    badge: u32,
) -> Result<u64, Error> {
    let args = [
        endpoint,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        cap,
        u64::from(rights) | u64::from(badge) << 32,
        0,
    ];
    call(number::SEND, args)
}

/// Sends `bytes` on `endpoint` only if a receiver is waiting now;
/// otherwise nothing is queued and the result is [`Error::WouldBlock`].
pub fn try_send(endpoint: Handle, bytes: &[u8]) -> Result<u64, Error> {
    let args = [endpoint, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 1];
    call(number::SEND, args)
}

/// Wait forever: the timeout every wrapper passes unless given one.
pub const FOREVER: u64 = u64::MAX;

/// Request and reply: sends `request` (up to 256 bytes) on `endpoint` with
/// a send-only capability on `reply` (needs `SEND | RECEIVE`, and nothing
/// pending on it) attached, then waits for the first event on `reply`. The
/// reply goes into `buf` (which must hold `request`, too).
pub fn call_reply(
    endpoint: Handle,
    request: &[u8],
    reply: Handle,
    buf: &mut [u8],
) -> Result<Received, Error> {
    call_timeout(endpoint, request, reply, buf, FOREVER)
}

/// [`call_reply`] that gives up after `micros` microseconds (rounded up to
/// the 10 ms tick, plus one) with [`Error::TimedOut`]; a request no server
/// has taken by then is withdrawn. 0 does not wait.
pub fn call_timeout(
    endpoint: Handle,
    request: &[u8],
    reply: Handle,
    buf: &mut [u8],
    micros: u64,
) -> Result<Received, Error> {
    if request.len() > buf.len() {
        return Err(Error::TooLarge);
    }
    buf[..request.len()].copy_from_slice(request);
    let args = [
        endpoint,
        buf.as_mut_ptr() as u64,
        request.len() as u64,
        reply,
        buf.len() as u64,
        micros,
    ];
    call(number::CALL, args).map(Received::decode)
}

/// What [`receive`] got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// A message of `len` bytes (cut to the buffer), a passed capability
    /// (0 = none), and the badge of the capability it was sent through.
    Message { len: usize, cap: Handle, badge: u32 },
    /// Notification bits set by the kernel (a child ended, an interrupt).
    Notification(u32),
}

impl Received {
    fn decode(v: u64) -> Self {
        if v & 1 << 16 != 0 {
            return Self::Notification((v >> 32) as u32);
        }
        Self::Message {
            len: (v & 0xffff) as usize,
            cap: (v >> 32) & 0xff,
            badge: (v >> 40) as u32,
        }
    }
}

/// Receives on `endpoint`: pending notification bits first, else a
/// message into `buf`, waiting if neither is there.
pub fn receive(endpoint: Handle, buf: &mut [u8]) -> Result<Received, Error> {
    receive_timeout(endpoint, buf, FOREVER)
}

/// [`receive`] that gives up after `micros` microseconds with
/// [`Error::TimedOut`]; 0 does not wait.
pub fn receive_timeout(endpoint: Handle, buf: &mut [u8], micros: u64) -> Result<Received, Error> {
    let args = [
        endpoint,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        micros,
        0,
        0,
    ];
    call(number::RECEIVE, args).map(Received::decode)
}

/// Sleeps for at least `micros` microseconds (rounded up to the 10 ms tick,
/// plus one); 0 returns at once.
pub fn sleep(micros: u64) {
    call(number::SLEEP, [micros, 0, 0, 0, 0, 0]).ok();
}

/// Creates an endpoint; the handle has `SEND`, `RECEIVE`, and `GRANT`.
pub fn endpoint_create() -> Result<Handle, Error> {
    call(number::ENDPOINT_CREATE, [0; 6])
}

/// Delivers `interrupt` (needs `WAIT`) as notification bit `bit` on
/// `endpoint` (needs `RECEIVE`) from now on, instead of to [`irq_wait`].
pub fn irq_notify(interrupt: Handle, endpoint: Handle, bit: u32) -> Result<u64, Error> {
    call(
        number::IRQ_NOTIFY,
        [interrupt, endpoint, bit.into(), 0, 0, 0],
    )
}

/// A capability passed to a new process: the caller's `handle` (needs
/// `GRANT`), narrowed to `rights`, with `badge` if it has none yet.
#[derive(Clone, Copy, Debug)]
pub struct Grant {
    pub handle: Handle,
    pub rights: u32,
    pub badge: u32,
}

/// Most capabilities one [`spawn`] passes.
pub const MAX_SPAWN_CAPS: usize = 8;

/// Starts the program in `file` (needs `READ`) with `arg`; `caps[i]`
/// becomes the child's handle `i + 1`. With `notify = Some((endpoint,
/// bit))` the kernel sets that bit on the endpoint (needs `RECEIVE`) when
/// the child ends. Returns a process handle for [`process_status`].
pub fn spawn(
    file: Handle,
    arg: u64,
    caps: &[Grant],
    notify: Option<(Handle, u32)>,
) -> Result<Handle, Error> {
    spawn_limited(file, arg, caps, notify, 0)
}

/// [`spawn`], letting the child [`mem_map`] up to `limit` pages (at most
/// this process's own limit, else [`Error::TooLarge`]).
pub fn spawn_limited(
    file: Handle,
    arg: u64,
    caps: &[Grant],
    notify: Option<(Handle, u32)>,
    limit: u32,
) -> Result<Handle, Error> {
    // Room for one more than the kernel accepts, so passing too many
    // reaches the kernel's check instead of being cut here.
    let mut entries = [0u8; 16 * (MAX_SPAWN_CAPS + 1)];
    if caps.len() > MAX_SPAWN_CAPS + 1 {
        return Err(Error::TooLarge);
    }
    for (entry, grant) in entries.chunks_exact_mut(16).zip(caps) {
        entry[..8].copy_from_slice(&grant.handle.to_le_bytes());
        entry[8..12].copy_from_slice(&grant.rights.to_le_bytes());
        entry[12..].copy_from_slice(&grant.badge.to_le_bytes());
    }
    let (endpoint, bit) = notify.unwrap_or((0, 0));
    let args = [
        file,
        arg,
        entries.as_ptr() as u64,
        caps.len() as u64 | u64::from(limit) << 32,
        endpoint,
        bit.into(),
    ];
    call(number::SPAWN, args)
}

/// How a started process is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Running,
    Exited(u64),
    /// Killed by this CPU exception vector.
    Killed(u64),
}

/// The status of the process behind `process` (needs `WAIT`).
pub fn process_status(process: Handle) -> Result<Status, Error> {
    let v = call(number::PROCESS_STATUS, [process, 0, 0, 0, 0, 0])?;
    const VALUE: u64 = (1 << 62) - 1;
    Ok(match (v >> 63, v >> 62 & 1) {
        (0, _) => Status::Running,
        (_, 0) => Status::Exited(v & VALUE),
        _ => Status::Killed(v & VALUE),
    })
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
    irq_wait_timeout(interrupt, FOREVER)
}

/// [`irq_wait`] that gives up after `micros` microseconds with
/// [`Error::TimedOut`], leaving the count for the next wait.
pub fn irq_wait_timeout(interrupt: Handle, micros: u64) -> Result<u64, Error> {
    call(number::IRQ_WAIT, [interrupt, micros, 0, 0, 0, 0])
}

/// Maps `len` bytes (rounded up to whole pages) of zeroed memory and
/// returns its address. Fails with [`Error::NoMemory`] beyond this process's
/// page limit.
pub fn mem_map(len: u64) -> Result<u64, Error> {
    call(number::MEM_MAP, [len, 0, 0, 0, 0, 0])
}

/// Unmaps one whole earlier [`mem_map`] mapping (`addr` and `len` as
/// mapped); anything else is [`Error::BadAddress`].
pub fn mem_unmap(addr: u64, len: u64) -> Result<u64, Error> {
    call(number::MEM_UNMAP, [addr, len, 0, 0, 0, 0])
}

/// [`mem_map`] with a [`Mapped`] view of the memory, for buffers to share
/// or fill through volatile accesses.
pub fn mem_map_buffer(len: u64) -> Result<Mapped, Error> {
    let addr = mem_map(len)?;
    Ok(Mapped::new(addr, len.div_ceil(4096) * 4096))
}

/// Turns the whole [`mem_map`] mapping at `addr` (`len` bytes as mapped)
/// into shared memory and returns a `Memory` capability with `READ`,
/// `GRANT`, and `WRITE` (if the mapping is writable). Pass it with
/// [`send`], narrowed to `READ` for read-only access.
pub fn mem_share(addr: u64, len: u64) -> Result<Handle, Error> {
    call(number::MEM_SHARE, [addr, len, 0, 0, 0, 0])
}

/// Maps the shared memory behind `memory` (needs `READ`, and `WRITE` if
/// `writable`); `len` must be its size. The pages count against this
/// process's limit.
pub fn mem_map_cap(memory: Handle, writable: bool, len: u64) -> Result<Mapped, Error> {
    let addr = call(number::MEM_MAP_CAP, [memory, writable.into(), len, 0, 0, 0])?;
    Ok(Mapped::new(addr, len.div_ceil(4096) * 4096))
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

#[cfg(pharos_user)]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(PANIC_EXIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip() {
        for code in 1..=13 {
            assert_eq!(Error::from_code(code).code(), code);
        }
        assert_eq!(result((0, 42)), Ok(42));
        assert_eq!(result((8, 0)), Err(Error::NotFound));
    }

    #[test]
    fn receive_values_decode() {
        assert_eq!(
            Received::decode(9 | 3 << 32 | 0xab_cdef << 40),
            Received::Message {
                len: 9,
                cap: 3,
                badge: 0xab_cdef
            }
        );
        assert_eq!(
            Received::decode(1 << 16 | 0x8000_0001 << 32),
            Received::Notification(0x8000_0001)
        );
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
        let text: Vec<u8> = (0..37).collect();
        m.write_bytes(3, &text);
        let mut back = [0u8; 37];
        m.read_bytes(3, &mut back);
        assert_eq!(back[..], text[..], "unaligned start, aligned middle, tail");
        assert_eq!(m.read8(2), 0, "bytes before are untouched");
        let past = std::panic::catch_unwind(|| m.write_bytes(4090, &[0; 7]));
        assert!(past.is_err(), "past the end");
    }
}
