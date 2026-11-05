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
/// Where `mem_map` places mappings (user-environment.md): 16 TiB clear of
/// the program and the stack.
pub const MAP_REGION: core::ops::Range<u64> = 0x0000_1000_0000_0000..0x0000_2000_0000_0000;
/// Most `mem_map` mappings one process has at once.
pub const MAX_MAPPINGS: usize = 1024;
/// The page limit the kernel starts `init` with: 3 GiB. Its services'
/// limits are carved from it (D-022): storage and inference 1 GiB each and
/// the agent runtime 64 MiB, with room. A limit is a bound, not a promise:
/// frames are allocated only when mapped.
pub const INIT_MEMORY_LIMIT: u64 = 3 * 1024 * 1024 * 1024 / FRAME_SIZE;

/// Frames shared through `Memory` capabilities (user-environment.md): each
/// mapping and each capability holds a reference, and the frames are freed
/// when the last is gone.
// ponytail: one u64 per page on the kernel heap (1.4 MiB for a 700 MB
// buffer); store runs of frames if more or larger buffers are shared.
pub struct SharedMemory {
    frames: Vec<u64>,
}

/// `SharedMemory` objects alive, and frames they failed to free (already
/// free: a bug elsewhere freed them early). For tests.
static SHARED_LIVE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static SHARED_FREE_ERRORS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

impl SharedMemory {
    /// An object owning `frames` (physical addresses, one per page).
    pub fn new(frames: Vec<u64>) -> Arc<Self> {
        SHARED_LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Arc::new(Self { frames })
    }

    /// The frames, in page order.
    pub fn frames(&self) -> &[u64] {
        &self.frames
    }
}

impl Drop for SharedMemory {
    /// Frees the frames, [`BATCH`] at a time, pausing between batches
    /// under `with_pauses`. Never runs with the frame allocator locked:
    /// the last reference is dropped by a capability table, a process, or
    /// the system-call handler after its locks are released.
    fn drop(&mut self) {
        SHARED_LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        #[cfg(target_os = "none")]
        for batch in self.frames.chunks(BATCH as usize) {
            if let Some(frames) = mm::frames().as_mut() {
                for &phys in batch {
                    let freed = crate::mm::frame::Frame::from_addr(phys)
                        .is_some_and(|frame| frames.free(frame).is_ok());
                    if !freed {
                        SHARED_FREE_ERRORS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            pause();
        }
    }
}

/// The task whose drops may pause ([`with_pauses`]); `u64::MAX` for none.
static PAUSING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Runs `f`, letting interrupts in between the batches of frames that
/// drops in it free (#122). Only where nothing relies on interrupts
/// staying off; called with interrupts disabled and no lock held. Another
/// task that runs meanwhile does not pause (the mark is the current
/// task's), and may take the mark over, ending this task's pauses early:
/// that costs latency only.
pub(crate) fn with_pauses(f: impl FnOnce()) {
    let id = sched::current_id().unwrap_or(u64::MAX);
    PAUSING.store(id, core::sync::atomic::Ordering::Relaxed);
    f();
    unmark(&PAUSING, id);
}

/// Clears `id`'s mark, and only its: restoring the mark from before would
/// leave a stale one when two tasks' `with_pauses` overlap (M3.5 review F1).
fn unmark(mark: &core::sync::atomic::AtomicU64, id: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let _ = mark.compare_exchange(id, u64::MAX, Relaxed, Relaxed);
}

/// Lets interrupts in if the current task is in [`with_pauses`], with
/// interrupts disabled and no lock held.
#[cfg(target_os = "none")]
fn pause() {
    let marked = sched::current_id()
        .is_some_and(|id| id == PAUSING.load(core::sync::atomic::Ordering::Relaxed));
    if marked && mm::raw::irq_locks_held() == 0 && !crate::arch::x86_64::interrupts_enabled() {
        crate::arch::x86_64::interrupt_window();
    }
}

/// Live `SharedMemory` objects.
pub fn shared_objects() -> usize {
    SHARED_LIVE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Frames a `SharedMemory` object found already freed (0 unless a bug).
pub fn shared_free_errors() -> usize {
    SHARED_FREE_ERRORS.load(core::sync::atomic::Ordering::Relaxed)
}

/// A shared mapping in a process: where, of what, and whose.
pub struct SharedMapping {
    pub start: u64,
    pub memory: Arc<SharedMemory>,
    /// True for the sharer's own `mem_map` memory, false for a mapping
    /// from `mem_map_cap`. Only the sharer's can be shared again: a
    /// receiver doing so would get a capability outside the sharer's
    /// derivation tree, which its `revoke` could not reach.
    pub own: bool,
    /// The capability it was mapped through (`None` for the sharer's
    /// own): when that is revoked, the mapping becomes zeroed pages.
    pub via: Option<Arc<Capability>>,
    pub writable: bool,
}

/// Device registers or a DMA buffer mapped into a process, and the device
/// capability it was mapped through: when that is revoked, the device is
/// stopped and the pages become zeroed ones (capabilities.md).
pub struct DeviceMapping {
    pub start: u64,
    pub pages: u64,
    pub via: Arc<Capability>,
    pub device: Arc<crate::device::DeviceHandle>,
}

/// A process's `mem_map` mappings and its page limit (user-environment.md).
/// Only the bookkeeping: the system call maps and frees the pages.
#[derive(Debug, Default)]
pub struct UserMemory {
    /// Most pages mapped at once, given away included.
    pub limit: u64,
    /// Pages mapped now.
    pub used: u64,
    /// Pages given to its live children as their limits (D-022).
    pub given: u64,
    /// Pages charged for the kernel's bookkeeping of memory it shared
    /// (one per 512 shared pages), until it ends.
    pub charged: u64,
    /// Mappings as (start, pages), sorted by start.
    maps: Vec<(u64, u64)>,
}

impl UserMemory {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Records a mapping of `pages` at the first gap in [`MAP_REGION`] that
    /// fits and returns its start; `None` if the limit, the mapping count,
    /// or the region does not allow it.
    pub fn reserve(&mut self, pages: u64) -> Option<u64> {
        let used = self.used.checked_add(pages)?;
        if pages == 0 || pages > self.available() || self.maps.len() >= MAX_MAPPINGS {
            return None;
        }
        let len = pages.checked_mul(FRAME_SIZE)?;
        let (mut at, mut index) = (MAP_REGION.start, 0);
        for &(start, n) in &self.maps {
            if start - at >= len {
                break;
            }
            at = start + n * FRAME_SIZE;
            index += 1;
        }
        if MAP_REGION.end - at < len {
            return None;
        }
        self.maps.insert(index, (at, pages));
        self.used = used;
        Some(at)
    }

    /// Pages it may still map, charge, or give away.
    pub fn available(&self) -> u64 {
        self.limit
            .saturating_sub(self.used)
            .saturating_sub(self.given)
            .saturating_sub(self.charged)
    }

    /// Takes `pages` for a child's limit, or for bookkeeping when
    /// `charge`; false (nothing taken) if fewer are available.
    pub fn take(&mut self, pages: u64, charge: bool) -> bool {
        if pages > self.available() {
            return false;
        }
        if charge {
            self.charged += pages;
        } else {
            self.given += pages;
        }
        true
    }

    /// True if there is a mapping of exactly `pages` at `start`.
    pub fn contains(&self, start: u64, pages: u64) -> bool {
        self.maps.contains(&(start, pages))
    }

    /// Forgets the mapping of exactly `pages` at `start`; false if there is
    /// none.
    pub fn release(&mut self, start: u64, pages: u64) -> bool {
        let Some(i) = self.maps.iter().position(|&m| m == (start, pages)) else {
            return false;
        };
        self.maps.remove(i);
        self.used -= pages;
        true
    }
}

/// Pages mapped, unmapped, or shared between two chances for interrupts
/// (D-022, #120, #122), so a large mapping does not hold the CPU.
pub const BATCH: u64 = 64;

/// Unmaps `pages` at `start` from the current address space, freeing the
/// frames if `owned`, `BATCH` at a time with interrupts let in between.
/// Called with interrupts disabled and no lock held.
#[cfg(target_os = "none")]
pub(crate) fn unmap_batched(start: u64, pages: u64, owned: bool) {
    debug_assert!(!crate::arch::x86_64::interrupts_enabled());
    let mut done = 0;
    while done < pages {
        let n = (pages - done).min(BATCH);
        sched::with_current_space(|space| {
            let mut guard = crate::mm::frames();
            if let Some(frames) = guard.as_mut() {
                for i in done..done + n {
                    let virt = start + i * FRAME_SIZE;
                    if owned {
                        space.unmap_owned(virt, frames);
                    } else {
                        drop(space.unmap(virt));
                    }
                }
            }
        });
        done += n;
        if done < pages {
            crate::arch::x86_64::interrupt_window();
        }
    }
}

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
    spawn_elf_limited(fs, path, arg, caps, 0)
}

/// [`spawn_elf`] with a `mem_map` limit of `limit` pages.
pub fn spawn_elf_limited(
    fs: &crate::fs::Fs,
    path: &[u8],
    arg: u64,
    caps: Vec<Arc<Capability>>,
    limit: u64,
) -> Result<TaskId, ProcessError> {
    let (space, entry) = load_elf(fs, path)?;
    start_limited(space, entry - USER_BASE, arg, caps, limit)
}

/// What a process was given at start, carved from its creator's (D-022):
/// pages it may map (with its children's), live descendants, and handles
/// held by itself and its descendants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub pages: u64,
    pub processes: u64,
    pub handles: u64,
}

impl Budget {
    /// A process the kernel starts gets the whole system: every other
    /// process slot and a full table for each.
    pub const fn kernel(pages: u64) -> Self {
        Self {
            pages,
            processes: MAX_DESCENDANTS,
            handles: KERNEL_HANDLES,
        }
    }
}

/// Live descendants a process started by the kernel may have (the 32
/// process slots less its own).
pub const MAX_DESCENDANTS: u64 = 31;
/// Handles for a process started by the kernel and all its descendants:
/// a full table for each of 32 processes.
pub const KERNEL_HANDLES: u64 = 32 * crate::cap::MAX_HANDLES as u64;
/// Handles a child gets when its creator asks for 0: a full table.
pub const DEFAULT_HANDLES: u64 = crate::cap::MAX_HANDLES as u64;

/// What a process has given its live children, from its [`Budget`].
#[derive(Debug, Default)]
pub struct Given {
    /// Each child counts once for itself and once per descendant it may
    /// have.
    pub processes: u64,
    pub handles: u64,
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
    /// Its `mem_map` mappings and page limit.
    pub memory: IrqMutex<UserMemory>,
    /// Which of those mappings are shared memory (dropping one may free
    /// the frames, so it is dropped after the frame allocator's lock).
    pub shared: IrqMutex<Vec<SharedMapping>>,
    /// Its device register and DMA mappings, until revoked.
    pub devices: IrqMutex<Vec<DeviceMapping>>,
    /// The process that started it (`None`: the kernel did). When a
    /// process ends, the processes it started are stopped (agents.md).
    pub parent: Option<TaskId>,
    /// What it was given; returned to its parent when it ends.
    pub budget: Budget,
    /// What it has given its live children.
    pub given: IrqMutex<Given>,
}

impl Process {
    /// Its table's limit: its handle budget less what its children hold,
    /// at most a full table.
    fn handle_limit(&self, given: &Given) -> usize {
        usize::try_from(self.budget.handles.saturating_sub(given.handles)).unwrap_or(usize::MAX)
    }

    /// Takes `child` out of its budget (D-022); false, with nothing taken,
    /// if it does not fit: pages beyond those available, more processes
    /// than are left, or handles that would leave its own table less room
    /// than it uses plus one (for the child's process handle).
    pub fn give(&self, child: &Budget) -> bool {
        let mut given = self.given.lock();
        let processes = given
            .processes
            .saturating_add(1)
            .saturating_add(child.processes);
        let handles = given.handles.saturating_add(child.handles);
        let mut caps = self.caps.lock();
        let room = self.budget.handles.saturating_sub(handles);
        if processes > self.budget.processes || room < caps.len() as u64 + 1 {
            return false;
        }
        if !self.memory.lock().take(child.pages, false) {
            return false;
        }
        given.processes = processes;
        given.handles = handles;
        caps.set_limit(self.handle_limit(&given));
        true
    }

    /// Takes back what [`Process::give`] took for `child`, which ended.
    pub(crate) fn take_back(&self, child: &Budget) {
        let mut given = self.given.lock();
        given.processes = given.processes.saturating_sub(1 + child.processes);
        given.handles = given.handles.saturating_sub(child.handles);
        self.caps.lock().set_limit(self.handle_limit(&given));
        let mut memory = self.memory.lock();
        memory.given = memory.given.saturating_sub(child.pages);
    }
}

/// Live processes by task ID (one thread each).
static PROCESSES: IrqMutex<BTreeMap<TaskId, Arc<Process>>> = IrqMutex::new(BTreeMap::new());

/// Runs the process in `space` (from [`load`], possibly with more pages
/// mapped) as a new thread entering user mode at `USER_BASE + entry`, with
/// `arg` in `rdi` and `caps` under handles 1, 2, ... The thread owns
/// `space`. It may not `mem_map` ([`start_limited`] allows it).
pub fn start(
    space: AddressSpace,
    entry: u64,
    arg: u64,
    caps: Vec<Arc<Capability>>,
) -> Result<TaskId, ProcessError> {
    start_limited(space, entry, arg, caps, 0)
}

/// [`start`] with a `mem_map` limit of `limit` pages, in the trusted
/// class with the kernel's [`Budget`] (processes the kernel starts).
pub fn start_limited(
    space: AddressSpace,
    entry: u64,
    arg: u64,
    caps: Vec<Arc<Capability>>,
    limit: u64,
) -> Result<TaskId, ProcessError> {
    start_class(
        space,
        entry,
        arg,
        caps,
        Budget::kernel(limit),
        sched::TRUSTED,
    )
}

/// [`start_limited`] with `budget` (its `pages` the `mem_map` limit), in
/// scheduling class `class` (D-022). The caller has taken `budget` from
/// the creator's ([`Process::give`]).
pub fn start_class(
    space: AddressSpace,
    entry: u64,
    arg: u64,
    caps: Vec<Arc<Capability>>,
    budget: Budget,
    class: sched::Class,
) -> Result<TaskId, ProcessError> {
    let limit = budget.pages;
    if space.translate(USER_BASE.saturating_add(entry)).is_none() {
        return Err(ProcessError::BadEntry);
    }
    let mut table = CapTable::new();
    table.set_limit(usize::try_from(budget.handles).unwrap_or(usize::MAX));
    for cap in caps {
        table
            .insert(cap)
            .map_err(|_| ProcessError::TooManyCapabilities)?;
    }
    // Started from a process's `spawn`: that process is the parent.
    let parent = current().map(|p| p.record.id);
    // Register the process before its thread can run (no preemption here).
    without_interrupts(|| {
        let id = sched::spawn_in(space, class, move || {
            context::enter_user(USER_BASE + entry, STACK_TOP, arg)
        })
        .map_err(ProcessError::Sched)?;
        let process = Arc::new(Process {
            caps: IrqMutex::new(table),
            inbox: IrqMutex::new(None),
            pins: IrqMutex::new(Vec::new()),
            mmio_pages: IrqMutex::new(0),
            memory: IrqMutex::new(UserMemory::new(limit)),
            shared: IrqMutex::new(Vec::new()),
            devices: IrqMutex::new(Vec::new()),
            parent,
            budget,
            given: IrqMutex::new(Given::default()),
            record: Arc::new(ProcessRecord {
                id,
                end: IrqMutex::new(None),
                notify: IrqMutex::new(None),
                cpu: core::sync::atomic::AtomicU64::new(0),
            }),
        });
        PROCESSES.lock().insert(id, process);
        Ok(id)
    })
}

/// PCI vendor and device IDs of the devices `init` is given.
pub const INIT_DEVICES: [(u16, u16); 3] = [(0x1af4, 0x1042), (0x1af4, 0x1041), (0x1af4, 0x1043)];

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
    /// Stopped by `process_stop`, or because the process that started it
    /// ended.
    Stopped,
}

/// What outlives a process for those observing it (a `Process`
/// capability): how it ended, and the endpoint bit to signal then.
pub struct ProcessRecord {
    pub id: TaskId,
    end: IrqMutex<Option<End>>,
    notify: IrqMutex<Option<(Arc<crate::ipc::Endpoint>, u32)>>,
    /// TSC cycles it ran, set when it ends.
    cpu: core::sync::atomic::AtomicU64,
}

impl ProcessRecord {
    /// TSC cycles the process has run: so far while it runs, all of them
    /// once it has ended.
    pub fn cpu_cycles(&self) -> u64 {
        match sched::cpu_cycles(self.id) {
            Some(cycles) if self.end().is_none() => cycles,
            _ => self.cpu.load(core::sync::atomic::Ordering::Relaxed),
        }
    }

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
    // Its address space first, in batches: the scheduler would free it
    // whole under its locks (#122). Shared and device pages stay with
    // their objects, as in `destroy`.
    if current().is_some() {
        sched::free_current_space(crate::arch::x86_64::interrupt_window);
    }
    if let Some(id) = sched::current_id() {
        // Dropped after the table's lock is released: dropping a process may
        // drop device handles, which stop their devices and free memory.
        let (process, children) = {
            let mut table = PROCESSES.lock();
            let process = table.remove(&id);
            let children: Vec<TaskId> = table
                .values()
                .filter(|p| p.parent == Some(id))
                .map(|p| p.record.id)
                .collect();
            (process, children)
        };
        // No work outlives the process that started it. Each child, as it
        // ends, stops its own children in turn.
        for child in children {
            sched::stop(child);
        }
        // Its budget returns to its parent, if that still runs.
        let parent = process
            .as_ref()
            .and_then(|p| p.parent.and_then(by_id).zip(Some(p.budget)));
        if let Some((parent, budget)) = parent {
            parent.take_back(&budget);
        }
        if let Some(process) = &process {
            let cpu = sched::cpu_cycles(id).unwrap_or(0);
            process
                .record
                .cpu
                .store(cpu, core::sync::atomic::Ordering::Relaxed);
            process.record.finish(end);
        }
        // Shared objects it was the last to hold free their frames here,
        // in batches (#122).
        with_pauses(|| drop(process));
    }
    sched::exit()
}

/// Live processes started by process `id`, by those, and so on.
pub fn descendants(id: TaskId) -> usize {
    let table = PROCESSES.lock();
    table
        .values()
        .filter(|p| {
            // ponytail: walks parents per process; at most 32 processes.
            let mut parent = p.parent;
            while let Some(pid) = parent {
                if pid == id {
                    return true;
                }
                parent = table.get(&pid).and_then(|q| q.parent);
            }
            false
        })
        .count()
}

/// Tells process `id` to end ([`End::Stopped`]); it does at its next
/// return to user mode, and its children after it. Returns false if no
/// such process runs.
pub fn stop(id: TaskId) -> bool {
    by_id(id).is_some() && sched::stop(id)
}

/// Revokes every capability derived from `cap` (it keeps its own), and
/// ends every mapping made through one of them, in every process, before
/// returning (capabilities.md, #104). A mapping's pages become fresh
/// zeroed pages the process owns, with the same access, so its next read
/// sees zeros and its writes reach nothing shared; no process faults
/// because another revoked memory it was using. If no frame is free, the
/// page is left unmapped. A device is stopped (no DMA, no MSI) before its
/// buffers are unmapped. Returns the number of capabilities revoked.
pub fn revoke(cap: &Capability) -> usize {
    let revoked = cap.revoke();
    #[cfg(target_os = "none")]
    if revoked > 0 {
        sweep_revoked();
    }
    revoked
}

#[cfg(target_os = "none")]
fn sweep_revoked() {
    let processes: Vec<(TaskId, Arc<Process>)> = PROCESSES
        .lock()
        .iter()
        .map(|(id, p)| (*id, p.clone()))
        .collect();
    for (id, p) in processes {
        let shared: Vec<SharedMapping> = {
            let mut list = p.shared.lock();
            let (dead, live) = core::mem::take(&mut *list)
                .into_iter()
                .partition(|s| s.via.as_ref().is_some_and(|c| c.is_revoked()));
            *list = live;
            dead
        };
        let devices: Vec<DeviceMapping> = {
            let mut list = p.devices.lock();
            let (dead, live) = core::mem::take(&mut *list)
                .into_iter()
                .partition(|d: &DeviceMapping| d.via.is_revoked());
            *list = live;
            dead
        };
        if shared.is_empty() && devices.is_empty() {
            continue;
        }
        for d in &devices {
            d.device.stop();
        }
        let read_only = Flags {
            writable: false,
            ..Flags::USER_DATA
        };
        let mut pages: Vec<(u64, Flags)> = Vec::new();
        for s in &shared {
            let flags = if s.writable {
                Flags::USER_DATA
            } else {
                read_only
            };
            let n = s.memory.frames().len() as u64;
            pages.extend((0..n).map(|i| (s.start + i * FRAME_SIZE, flags)));
        }
        for d in &devices {
            pages.extend((0..d.pages).map(|i| (d.start + i * FRAME_SIZE, Flags::USER_DATA)));
        }
        sched::with_space(id, |space| {
            let mut guard = mm::frames();
            let Some(frames) = guard.as_mut() else { return };
            for (virt, flags) in pages {
                // Not owned: the object or the device holds the frame.
                let _ = space.unmap(virt);
                let _ = space.map_new_page(virt, flags, &[], frames);
            }
        });
        // Dropped after the frame allocator's lock: one may have been the
        // last reference to a `Memory` object.
        drop(shared);
    }
}

/// Processes [`kill`] ends, with the vector their end reports.
static INJECTED: IrqMutex<BTreeMap<TaskId, u64>> = IrqMutex::new(BTreeMap::new());

/// Fault injection for test kernels (#100): ends process `id` as
/// [`stop`] does, but its end reads [`End::Killed`] with `vector`, as a
/// crash would, so supervision can be tested on unmodified services.
/// Nothing in user space can reach it. Returns false if no such process
/// runs.
pub fn kill(id: TaskId, vector: u64) -> bool {
    if by_id(id).is_none() {
        return false;
    }
    INJECTED.lock().insert(id, vector);
    sched::stop(id)
}

/// Ends the running process, which was told to stop.
pub(crate) fn end_stopped() -> ! {
    let injected = sched::current_id().and_then(|id| INJECTED.lock().remove(&id));
    end_current(injected.map_or(End::Stopped, End::Killed))
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

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = FRAME_SIZE;

    #[test]
    fn mappings_fill_gaps_and_respect_the_limit() {
        let mut m = UserMemory::new(10);
        let a = m.reserve(2).unwrap();
        let b = m.reserve(3).unwrap();
        let c = m.reserve(1).unwrap();
        assert_eq!((a, b, c), (MAP_REGION.start, a + 2 * PAGE, a + 5 * PAGE));
        assert_eq!(m.reserve(5), None, "11 pages > limit 10");
        assert_eq!(m.used, 6, "a refusal changes nothing");
        assert_eq!(m.reserve(0), None);
        assert!(!m.release(b, 2), "only the whole mapping");
        assert!(!m.release(b + PAGE, 2));
        assert!(m.release(b, 3));
        assert_eq!(m.used, 3);
        assert_eq!(m.reserve(2), Some(b), "first gap that fits");
        assert_eq!(
            m.reserve(2),
            Some(c + PAGE),
            "the rest of the gap is 1 page"
        );
        assert_eq!(m.reserve(1), Some(b + 2 * PAGE), "now it fits");
    }

    #[test]
    fn mapping_count_and_region_are_bounded() {
        let mut m = UserMemory::new(u64::MAX);
        for _ in 0..MAX_MAPPINGS {
            assert!(m.reserve(1).is_some());
        }
        assert_eq!(m.reserve(1), None, "1,024 mappings");
        let mut m = UserMemory::new(u64::MAX);
        let region = (MAP_REGION.end - MAP_REGION.start) / PAGE;
        assert_eq!(m.reserve(region + 1), None, "larger than the region");
        assert_eq!(m.reserve(region), Some(MAP_REGION.start));
        assert_eq!(m.reserve(1), None, "region full");
        assert_eq!(UserMemory::new(5).reserve(u64::MAX), None, "no overflow");
        assert_eq!(UserMemory::new(0).reserve(1), None, "limit 0");
    }

    #[test]
    fn overlapping_pauses_leave_no_stale_mark() {
        use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
        // Task 1 marks, is preempted; task 2 marks; 1 ends, then 2.
        let mark = AtomicU64::new(u64::MAX);
        mark.store(1, Relaxed);
        mark.store(2, Relaxed);
        unmark(&mark, 1);
        assert_eq!(mark.load(Relaxed), 2, "task 2's mark stays");
        unmark(&mark, 2);
        assert_eq!(mark.load(Relaxed), u64::MAX, "no task stays marked");
    }

    #[test]
    fn given_and_charged_pages_are_not_available() {
        let mut m = UserMemory::new(10);
        assert!(m.reserve(3).is_some());
        assert!(m.take(4, false), "4 given to a child");
        assert!(m.take(1, true), "1 charged");
        assert_eq!(m.available(), 2);
        assert!(!m.take(3, false), "3 more do not fit");
        assert_eq!(m.reserve(3), None);
        assert!(m.reserve(2).is_some());
        assert_eq!((m.used, m.given, m.charged), (5, 4, 1));
        m.given -= 4; // the child ended
        assert_eq!(m.available(), 4);
    }
}
