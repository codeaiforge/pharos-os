//! User processes (M2.7, syscalls-ipc.md): one thread each, in its own
//! address space, running in ring 3.
//!
//! [`load`] builds a process address space with the program image at
//! [`USER_BASE`] (read + execute) and a zeroed 64 KiB stack below
//! [`STACK_TOP`] (read + write, no-execute). [`start`] runs it as a
//! scheduler task that enters user mode. A CPU exception in user mode kills
//! the process and the kernel continues ([`init`] installs the handler).
//!
//! Each process has a capability table ([`Process::caps`]); [`start`] fills
//! it with the initial capabilities, under handles 1, 2, ... in order.
//! System calls (#40) reach the calling process through [`current`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::arch::x86_64::idt::{self, ExceptionFrame, Report};
use crate::arch::x86_64::paging::{AddressSpace, Flags, MapError};
use crate::arch::x86_64::{context, without_interrupts};
use crate::cap::{CapTable, Capability};
use crate::kprintln;
use crate::mm::frame::{FRAME_SIZE, FrameAllocator};
use crate::mm::{self, raw::IrqMutex};
use crate::sched::{self, SchedError, TaskId};

/// Where a program image is loaded.
pub const USER_BASE: u64 = 0x40_0000;
/// Top of the user stack (exclusive).
pub const STACK_TOP: u64 = 0x7fff_ff80_0000;
/// Size of the user stack.
pub const STACK_SIZE: u64 = 64 * 1024;
/// Largest program image.
pub const MAX_IMAGE: usize = 1024 * 1024;
/// Where ELF programs may place segments (drivers.md).
pub const PROGRAM_RANGE: core::ops::Range<u64> = USER_BASE..USER_BASE + 16 * 1024 * 1024;
/// Largest ELF program file.
pub const MAX_PROGRAM: u64 = 4 * 1024 * 1024;

/// Why a process could not be created.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessError {
    /// The image is empty, or larger than [`MAX_IMAGE`] (flat) or
    /// [`MAX_PROGRAM`] (ELF).
    BadImage,
    /// The entry point lies outside the image.
    BadEntry,
    /// The frame allocator is not set up yet.
    NoFrameAllocator,
    /// Mapping the image or stack failed (including out of memory).
    Map(MapError),
    /// The scheduler could not start the thread.
    Sched(SchedError),
    /// More initial capabilities than a table holds.
    TooManyCapabilities,
    /// No program file with that path.
    NoSuchProgram,
    /// The program file failed a check.
    Elf(pharos_elf::ElfError),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadImage => f.write_str("program image empty or too large"),
            Self::BadEntry => f.write_str("entry point outside the program image"),
            Self::NoFrameAllocator => f.write_str("frame allocator not set up"),
            Self::Map(error) => write!(f, "cannot map the process: {error}"),
            Self::Sched(error) => write!(f, "cannot start the process: {error}"),
            Self::TooManyCapabilities => f.write_str("too many initial capabilities"),
            Self::NoSuchProgram => f.write_str("no such program file"),
            Self::Elf(error) => write!(f, "bad program file: {error}"),
        }
    }
}

/// Builds a process address space holding `image` at [`USER_BASE`] and an
/// empty stack. On failure everything allocated is freed again.
pub fn load(image: &[u8]) -> Result<AddressSpace, ProcessError> {
    if image.is_empty() || image.len() > MAX_IMAGE {
        return Err(ProcessError::BadImage);
    }
    let mut guard = mm::frames();
    let frames = guard.as_mut().ok_or(ProcessError::NoFrameAllocator)?;
    let mut space = AddressSpace::new_user(frames).map_err(ProcessError::Map)?;
    let pages = image
        .chunks(FRAME_SIZE as usize)
        .zip((USER_BASE..).step_by(FRAME_SIZE as usize));
    let map = || {
        for (chunk, virt) in pages {
            space.map_new_page(virt, Flags::USER_CODE, chunk, frames)?;
        }
        map_stack(&mut space, frames)
    };
    match map() {
        Ok(()) => Ok(space),
        Err(error) => {
            space.destroy(frames);
            Err(ProcessError::Map(error))
        }
    }
}

/// Maps the empty user stack below [`STACK_TOP`].
fn map_stack(space: &mut AddressSpace, frames: &mut FrameAllocator<'_>) -> Result<(), MapError> {
    for virt in (STACK_TOP - STACK_SIZE..STACK_TOP).step_by(FRAME_SIZE as usize) {
        space.map_new_page(virt, Flags::USER_DATA, &[], frames)?;
    }
    Ok(())
}

/// User read-only data: no write, no execute.
const USER_RODATA: Flags = Flags {
    writable: false,
    executable: false,
    uncached: false,
    user: true,
};

/// Builds a process address space from the ELF program at `path` on `fs`
/// (drivers.md): the file is checked completely with `pharos-elf` before
/// anything is allocated, then each segment page is filled from the file
/// and the stack is mapped. Returns the space and the entry point. On
/// failure everything allocated is freed again.
pub fn load_elf(fs: &crate::fs::Fs, path: &[u8]) -> Result<(AddressSpace, u64), ProcessError> {
    let file = fs.lookup(path).map_err(|_| ProcessError::NoSuchProgram)?;
    load_elf_file(fs, file)
}

/// [`load_elf`] for a file already looked up (`spawn` takes a file
/// capability).
pub fn load_elf_file(
    fs: &crate::fs::Fs,
    file: pharos_fs::FileId,
) -> Result<(AddressSpace, u64), ProcessError> {
    let size = fs.size(file).map_err(|_| ProcessError::NoSuchProgram)?;
    if size == 0 || size > MAX_PROGRAM {
        return Err(ProcessError::BadImage);
    }
    // One page buffer on the heap (kernel stacks are 16 KiB), used first for
    // the headers, then for each page's contents.
    let mut page = alloc::vec![0u8; FRAME_SIZE as usize];
    let head = fs
        .read(file, 0, &mut page)
        .map_err(|_| ProcessError::BadImage)?;
    let program =
        pharos_elf::parse(&page[..head], size, PROGRAM_RANGE).map_err(ProcessError::Elf)?;

    let mut guard = mm::frames();
    let frames = guard.as_mut().ok_or(ProcessError::NoFrameAllocator)?;
    let mut space = AddressSpace::new_user(frames).map_err(ProcessError::Map)?;
    let mut fill = |space: &mut AddressSpace, frames: &mut FrameAllocator<'_>| {
        for segment in program.segments() {
            let flags = match (segment.executable, segment.writable) {
                (true, _) => Flags::USER_CODE,
                (false, true) => Flags::USER_DATA,
                (false, false) => USER_RODATA,
            };
            for virt in segment.pages().step_by(FRAME_SIZE as usize) {
                page.fill(0);
                if let Some((range, offset)) = segment.file_part(virt) {
                    let want = range.len();
                    let got = fs.read(file, offset, &mut page[range]);
                    if got != Ok(want) {
                        return Err(ProcessError::BadImage);
                    }
                }
                space
                    .map_new_page(virt, flags, &page, frames)
                    .map_err(ProcessError::Map)?;
            }
        }
        map_stack(space, frames).map_err(ProcessError::Map)
    };
    match fill(&mut space, frames) {
        Ok(()) => Ok((space, program.entry)),
        Err(error) => {
            space.destroy(frames);
            Err(error)
        }
    }
}

/// [`load_elf`] and [`start`] in one step: runs the program at `path` on
/// `fs` with `arg` in `rdi` and `caps` under handles 1, 2, ...
pub fn spawn_elf(
    fs: &crate::fs::Fs,
    path: &[u8],
    arg: u64,
    caps: Vec<Arc<Capability>>,
) -> Result<TaskId, ProcessError> {
    let (space, entry) = load_elf(fs, path)?;
    start(space, entry - USER_BASE, arg, caps)
}

/// Kernel-side state of a process (its thread and address space belong to
/// the scheduler task).
pub struct Process {
    /// The process's capabilities.
    pub caps: IrqMutex<CapTable>,
    /// A message handed over by a sender while this process waited in
    /// `receive` (#41).
    pub inbox: IrqMutex<Option<crate::ipc::Message>>,
    /// Devices whose registers or DMA buffers are mapped into this process.
    /// Holding them keeps each device granted to this process, enabled, and
    /// its buffers allocated for as long as the process lives, even if it
    /// deletes its device handles (drivers.md).
    pub pins: IrqMutex<Vec<Arc<crate::device::DeviceHandle>>>,
    /// How it ended, once it has; whom to notify (services.md).
    pub record: Arc<ProcessRecord>,
    /// Device register pages mapped so far (at most
    /// [`crate::device::MAX_MMIO_PAGES`]; they and their page tables are
    /// freed only when the process ends).
    pub mmio_pages: IrqMutex<u64>,
}

/// Live processes by task ID (one thread each).
static PROCESSES: IrqMutex<BTreeMap<TaskId, Arc<Process>>> = IrqMutex::new(BTreeMap::new());

/// Runs the process in `space` (from [`load`], possibly with more pages
/// mapped) as a new thread entering user mode at `USER_BASE + entry`, with
/// `arg` in `rdi` and `caps` under handles 1, 2, ... The thread owns
/// `space`.
pub fn start(
    space: AddressSpace,
    entry: u64,
    arg: u64,
    caps: Vec<Arc<Capability>>,
) -> Result<TaskId, ProcessError> {
    if space.translate(USER_BASE.saturating_add(entry)).is_none() {
        return Err(ProcessError::BadEntry);
    }
    let mut table = CapTable::new();
    for cap in caps {
        table
            .insert(cap)
            .map_err(|_| ProcessError::TooManyCapabilities)?;
    }
    // Register the process before its thread can run (no preemption here).
    without_interrupts(|| {
        let id = sched::spawn_in(space, move || {
            context::enter_user(USER_BASE + entry, STACK_TOP, arg)
        })
        .map_err(ProcessError::Sched)?;
        let process = Arc::new(Process {
            caps: IrqMutex::new(table),
            inbox: IrqMutex::new(None),
            pins: IrqMutex::new(Vec::new()),
            mmio_pages: IrqMutex::new(0),
            record: Arc::new(ProcessRecord {
                id,
                end: IrqMutex::new(None),
                notify: IrqMutex::new(None),
            }),
        });
        PROCESSES.lock().insert(id, process);
        Ok(id)
    })
}

/// PCI vendor and device IDs of the devices `init` is given.
pub const INIT_DEVICES: [(u16, u16); 2] = [(0x1af4, 0x1042), (0x1af4, 0x1041)];

/// The capabilities the kernel starts `init` with (services.md): 1 the
/// debug console, 2 `fs`, 3 `report` (`SEND`), then each device in
/// [`INIT_DEVICES`] found by PCI enumeration (granted, in PCI order) when
/// `devices` is true.
#[cfg(target_os = "none")]
pub fn init_capabilities(
    fs: Arc<crate::fs::Fs>,
    report: Arc<crate::ipc::Endpoint>,
    devices: bool,
) -> Vec<Arc<Capability>> {
    use crate::cap::{CONFIG, GRANT, IRQ, MAP, Object, READ, SEND, WRITE};
    let mut caps = alloc::vec![
        Capability::new(Object::DebugConsole, WRITE | GRANT),
        Capability::new(Object::Filesystem(fs), READ | GRANT),
        Capability::new(Object::Endpoint(report), SEND),
    ];
    let wanted = crate::pci::devices()
        .into_iter()
        .filter(|d| devices && INIT_DEVICES.contains(&(d.vendor, d.device)));
    for device in wanted {
        if let Some(handle) = crate::device::DeviceHandle::grant(device) {
            caps.push(Capability::new(
                Object::Device(handle),
                MAP | CONFIG | IRQ | GRANT,
            ));
        }
    }
    caps
}

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// With the `exit` system call and this code.
    Exited(u64),
    /// Killed by this CPU exception vector.
    Killed(u64),
}

/// What outlives a process for those observing it (a `Process`
/// capability): how it ended, and the endpoint bit to signal then.
pub struct ProcessRecord {
    pub id: TaskId,
    end: IrqMutex<Option<End>>,
    notify: IrqMutex<Option<(Arc<crate::ipc::Endpoint>, u32)>>,
}

impl ProcessRecord {
    /// How the process ended, or `None` while it runs.
    pub fn end(&self) -> Option<End> {
        *self.end.lock()
    }

    /// Signals `bits` on `endpoint` when the process ends.
    pub fn notify_on_end(&self, endpoint: Arc<crate::ipc::Endpoint>, bits: u32) {
        *self.notify.lock() = Some((endpoint, bits));
    }

    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    fn finish(&self, end: End) {
        *self.end.lock() = Some(end);
        let notify = self.notify.lock().take();
        #[cfg(target_os = "none")]
        if let Some((endpoint, bits)) = notify {
            crate::ipc::notify(&endpoint, bits);
        }
        #[cfg(not(target_os = "none"))]
        drop(notify);
    }
}

/// [`load`] and [`start`] in one step.
pub fn spawn(
    image: &[u8],
    entry: u64,
    arg: u64,
    caps: Vec<Arc<Capability>>,
) -> Result<TaskId, ProcessError> {
    start(load(image)?, entry, arg, caps)
}

/// The calling process, or `None` for kernel tasks.
pub fn current() -> Option<Arc<Process>> {
    let id = sched::current_id()?;
    PROCESSES.lock().get(&id).cloned()
}

/// The process whose thread is task `id`.
pub fn by_id(id: TaskId) -> Option<Arc<Process>> {
    PROCESSES.lock().get(&id).cloned()
}

/// Live processes.
pub fn count() -> usize {
    PROCESSES.lock().len()
}

/// Ends the calling process: forgets its state and ends its thread (the
/// address space is freed when the thread is reaped).
fn end_current(end: End) -> ! {
    if let Some(id) = sched::current_id() {
        // Dropped after the table's lock is released: dropping a process may
        // drop device handles, which stop their devices and free memory.
        let process = PROCESSES.lock().remove(&id);
        if let Some(process) = &process {
            process.record.finish(end);
        }
        drop(process);
    }
    sched::exit()
}

/// A process that ended with the `exit` system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exit {
    pub task: TaskId,
    pub code: u64,
    /// Uptime when it exited.
    pub at: core::time::Duration,
}

/// Entries each log keeps (the newest). Processes drive these logs, so they
/// must not grow without bound (security review F2, #42).
pub const LOG_ENTRIES: usize = 64;

/// A log that keeps only its newest [`LOG_ENTRIES`] entries.
struct Log<T>(IrqMutex<VecDeque<T>>);

impl<T: Clone> Log<T> {
    const fn new() -> Self {
        Self(IrqMutex::new(VecDeque::new()))
    }

    fn push(&self, entry: T) {
        let mut log = self.0.lock();
        if log.len() == LOG_ENTRIES {
            log.pop_front();
        }
        log.push_back(entry);
    }

    fn entries(&self) -> Vec<T> {
        self.0.lock().iter().cloned().collect()
    }
}

static EXITS: Log<Exit> = Log::new();
static DEBUG_OUTPUT: Log<(TaskId, Vec<u8>)> = Log::new();

/// The `exit` system call: records the code and ends the process.
#[cfg_attr(not(target_os = "none"), allow(dead_code))] // used by the kernel-only handler
pub(crate) fn exit_current(code: u64) -> ! {
    let task = sched::current_id().unwrap_or(0);
    EXITS.push(Exit {
        task,
        code,
        at: crate::time::uptime(),
    });
    end_current(End::Exited(code))
}

/// The newest [`LOG_ENTRIES`] process exits, oldest first.
pub fn exits() -> Vec<Exit> {
    EXITS.entries()
}

/// The `debug_write` system call's output: prints `bytes` (non-printable
/// bytes as `?`) prefixed with the process ID, and records them.
#[cfg_attr(not(target_os = "none"), allow(dead_code))] // used by the kernel-only handler
pub(crate) fn debug_write(bytes: &[u8]) {
    let task = sched::current_id().unwrap_or(0);
    let mut text = [0u8; crate::syscall::MAX_MESSAGE];
    for (out, &b) in text.iter_mut().zip(bytes) {
        *out = if b.is_ascii_graphic() || b == b' ' {
            b
        } else {
            b'?'
        };
    }
    let text = core::str::from_utf8(&text[..bytes.len()]).unwrap_or("");
    kprintln!("process {task}: {text}");
    DEBUG_OUTPUT.push((task, bytes.to_vec()));
}

/// The newest [`LOG_ENTRIES`] `debug_write` outputs, oldest first.
pub fn debug_output() -> Vec<(TaskId, Vec<u8>)> {
    DEBUG_OUTPUT.entries()
}

/// A process killed by a CPU exception in user mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kill {
    pub task: TaskId,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    /// CR2 at the time (meaningful for page faults).
    pub cr2: u64,
}

static KILLS: Log<Kill> = Log::new();

/// Installs the user-fault handler and the system-call entry. Call once,
/// after `sched::init`.
pub fn init() {
    idt::set_user_fault_handler(on_user_fault);
    #[cfg(target_os = "none")]
    crate::arch::x86_64::syscall::init(crate::syscall::handle);
}

/// The newest [`LOG_ENTRIES`] processes killed, oldest first.
pub fn kills() -> Vec<Kill> {
    KILLS.entries()
}

/// A CPU exception in user mode: report it, record it, and end the thread
/// (its address space is freed when it is reaped). Runs on the thread's
/// kernel stack with interrupts disabled.
fn on_user_fault(frame: &ExceptionFrame) -> ! {
    let task = sched::current_id().unwrap_or(0);
    let cr2 = idt::read_cr2();
    kprintln!("PHAROS: process {task} killed: {}", Report { frame, cr2 });
    KILLS.push(Kill {
        task,
        vector: frame.vector,
        error_code: frame.error_code,
        rip: frame.rip,
        cs: frame.cs,
        cr2,
    });
    end_current(End::Killed(frame.vector))
}
