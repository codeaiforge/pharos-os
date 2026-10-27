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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::arch::x86_64::idt::{self, ExceptionFrame, Report};
use crate::arch::x86_64::paging::{AddressSpace, Flags, MapError};
use crate::arch::x86_64::{context, without_interrupts};
use crate::cap::{CapTable, Capability};
use crate::kprintln;
use crate::mm::{self, frame::FRAME_SIZE, raw::IrqMutex};
use crate::sched::{self, SchedError, TaskId};

/// Where a program image is loaded.
pub const USER_BASE: u64 = 0x40_0000;
/// Top of the user stack (exclusive).
pub const STACK_TOP: u64 = 0x7fff_ff80_0000;
/// Size of the user stack.
pub const STACK_SIZE: u64 = 64 * 1024;
/// Largest program image.
pub const MAX_IMAGE: usize = 1024 * 1024;

/// Why a process could not be created.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessError {
    /// The image is empty or larger than [`MAX_IMAGE`].
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
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadImage => write!(f, "program image empty or over {MAX_IMAGE} bytes"),
            Self::BadEntry => f.write_str("entry point outside the program image"),
            Self::NoFrameAllocator => f.write_str("frame allocator not set up"),
            Self::Map(error) => write!(f, "cannot map the process: {error}"),
            Self::Sched(error) => write!(f, "cannot start the process: {error}"),
            Self::TooManyCapabilities => f.write_str("too many initial capabilities"),
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
        .zip((USER_BASE..).step_by(FRAME_SIZE as usize))
        .map(|(chunk, virt)| (virt, Flags::USER_CODE, chunk))
        .chain(
            (STACK_TOP - STACK_SIZE..STACK_TOP)
                .step_by(FRAME_SIZE as usize)
                .map(|virt| (virt, Flags::USER_DATA, &[][..])),
        );
    for (virt, flags, contents) in pages {
        if let Err(error) = space.map_new_page(virt, flags, contents, frames) {
            space.destroy(frames);
            return Err(ProcessError::Map(error));
        }
    }
    Ok(space)
}

/// Kernel-side state of a process (its thread and address space belong to
/// the scheduler task).
pub struct Process {
    /// The process's capabilities.
    pub caps: IrqMutex<CapTable>,
    /// A message handed over by a sender while this process waited in
    /// `receive` (#41).
    pub inbox: IrqMutex<Option<crate::ipc::Message>>,
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
    let process = Arc::new(Process {
        caps: IrqMutex::new(table),
        inbox: IrqMutex::new(None),
    });
    // Register the process before its thread can run (no preemption here).
    without_interrupts(|| {
        let id = sched::spawn_in(space, move || {
            context::enter_user(USER_BASE + entry, STACK_TOP, arg)
        })
        .map_err(ProcessError::Sched)?;
        PROCESSES.lock().insert(id, process);
        Ok(id)
    })
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
fn end_current() -> ! {
    if let Some(id) = sched::current_id() {
        PROCESSES.lock().remove(&id);
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

// ponytail: exits, kills, and debug output are kept in full for tests and
// reports; cap or ring-buffer them when processes come and go in numbers.
static EXITS: IrqMutex<Vec<Exit>> = IrqMutex::new(Vec::new());
static DEBUG_OUTPUT: IrqMutex<Vec<(TaskId, Vec<u8>)>> = IrqMutex::new(Vec::new());

/// The `exit` system call: records the code and ends the process.
#[cfg_attr(not(target_os = "none"), allow(dead_code))] // used by the kernel-only handler
pub(crate) fn exit_current(code: u64) -> ! {
    let task = sched::current_id().unwrap_or(0);
    EXITS.lock().push(Exit {
        task,
        code,
        at: crate::time::uptime(),
    });
    end_current()
}

/// Processes that exited so far, oldest first.
pub fn exits() -> Vec<Exit> {
    EXITS.lock().clone()
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
    DEBUG_OUTPUT.lock().push((task, bytes.to_vec()));
}

/// Everything processes wrote with `debug_write`, oldest first.
pub fn debug_output() -> Vec<(TaskId, Vec<u8>)> {
    DEBUG_OUTPUT.lock().clone()
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

static KILLS: IrqMutex<Vec<Kill>> = IrqMutex::new(Vec::new());

/// Installs the user-fault handler and the system-call entry. Call once,
/// after `sched::init`.
pub fn init() {
    idt::set_user_fault_handler(on_user_fault);
    #[cfg(target_os = "none")]
    crate::arch::x86_64::syscall::init(crate::syscall::handle);
}

/// Processes killed so far, oldest first.
pub fn kills() -> Vec<Kill> {
    KILLS.lock().clone()
}

/// A CPU exception in user mode: report it, record it, and end the thread
/// (its address space is freed when it is reaped). Runs on the thread's
/// kernel stack with interrupts disabled.
fn on_user_fault(frame: &ExceptionFrame) -> ! {
    let task = sched::current_id().unwrap_or(0);
    let cr2 = idt::read_cr2();
    kprintln!("PHAROS: process {task} killed: {}", Report { frame, cr2 });
    KILLS.lock().push(Kill {
        task,
        vector: frame.vector,
        error_code: frame.error_code,
        rip: frame.rip,
        cs: frame.cs,
        cr2,
    });
    end_current()
}
