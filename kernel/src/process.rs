//! User processes (M2.7, syscalls-ipc.md): one thread each, in its own
//! address space, running in ring 3.
//!
//! [`load`] builds a process address space with the program image at
//! [`USER_BASE`] (read + execute) and a zeroed 64 KiB stack below
//! [`STACK_TOP`] (read + write, no-execute). [`start`] runs it as a
//! scheduler task that enters user mode. A CPU exception in user mode kills
//! the process and the kernel continues ([`init`] installs the handler).
//! System calls and capabilities follow in #40 and #41.

use alloc::vec::Vec;
use core::fmt;

use crate::arch::x86_64::context;
use crate::arch::x86_64::idt::{self, ExceptionFrame, Report};
use crate::arch::x86_64::paging::{AddressSpace, Flags, MapError};
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
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadImage => write!(f, "program image empty or over {MAX_IMAGE} bytes"),
            Self::BadEntry => f.write_str("entry point outside the program image"),
            Self::NoFrameAllocator => f.write_str("frame allocator not set up"),
            Self::Map(error) => write!(f, "cannot map the process: {error}"),
            Self::Sched(error) => write!(f, "cannot start the process: {error}"),
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

/// Runs the process in `space` (from [`load`], possibly with more pages
/// mapped) as a new thread entering user mode at `USER_BASE + entry`, with
/// `arg` in `rdi`. The thread owns `space`.
pub fn start(space: AddressSpace, entry: u64, arg: u64) -> Result<TaskId, ProcessError> {
    if space.translate(USER_BASE.saturating_add(entry)).is_none() {
        return Err(ProcessError::BadEntry);
    }
    sched::spawn_in(space, move || {
        context::enter_user(USER_BASE + entry, STACK_TOP, arg)
    })
    .map_err(ProcessError::Sched)
}

/// [`load`] and [`start`] in one step.
pub fn spawn(image: &[u8], entry: u64, arg: u64) -> Result<TaskId, ProcessError> {
    start(load(image)?, entry, arg)
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

/// ponytail: every kill is kept; cap or ring-buffer it when processes come
/// and go in large numbers.
static KILLS: IrqMutex<Vec<Kill>> = IrqMutex::new(Vec::new());

/// Installs the user-fault handler. Call once, after `sched::init`.
pub fn init() {
    idt::set_user_fault_handler(on_user_fault);
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
    sched::exit()
}
