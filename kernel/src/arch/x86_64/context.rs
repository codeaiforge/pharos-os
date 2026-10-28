//! Kernel thread stacks, saved contexts, and the context switch (D-013,
//! issue #33).
//!
//! A [`Context`] is a saved stack pointer plus the stack it points into. The
//! switch routine pushes the callee-saved registers (System V AMD64: `rbx`,
//! `rbp`, `r12`–`r15`), stores the stack pointer, loads the next one, pops,
//! and returns, so on both sides it looks like an ordinary function call.
//! The kernel is soft-float: there is no FPU or SSE state to save.
//!
//! [`switch`] is safe because it checks at run time what would otherwise be
//! memory errors: the source is the running context, the target is neither
//! running nor exited, both stay referenced elsewhere during the switch, and
//! interrupts are disabled. A context that is still running cannot be
//! dropped.

use alloc::sync::Arc;
use core::arch::global_asm;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::paging::{self, AddressSpace, Flags, MapError, PageSize};
use crate::mm::frame::{FRAME_SIZE, Frame};
use crate::mm::raw::{IrqMutex, IrqMutexGuard};

/// Start of the virtual window for task stacks (D-013).
pub const STACK_WINDOW: u64 = 0xffff_c800_0000_0000;
/// Usable size of a task stack: 32 KiB since M2.10 (#63, D-013 amended).
/// Debug builds of the IPC paths (`call`) need more than 16 KiB.
pub const STACK_SIZE: u64 = 32 * 1024;
/// Virtual space per stack: an unmapped guard area below, then the stack.
pub const SLOT_SIZE: u64 = 2 * STACK_SIZE;
/// ponytail: one bitmap word of stack slots, so at most 64 task stacks;
/// widen the bitmap when more tasks are needed.
pub const MAX_STACKS: u64 = 64;

/// Stack slots in use, one bit per slot.
static SLOTS: AtomicU64 = AtomicU64::new(0);

/// Why a stack could not be created.
#[derive(Debug, PartialEq, Eq)]
pub enum StackError {
    /// All [`MAX_STACKS`] slots are in use.
    NoSlot,
    /// The frame allocator is not set up yet.
    NoFrameAllocator,
    /// No free frames.
    OutOfMemory,
    /// Mapping a stack page failed.
    Map(MapError),
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSlot => write!(f, "all {MAX_STACKS} task stack slots are in use"),
            Self::NoFrameAllocator => f.write_str("frame allocator not set up"),
            Self::OutOfMemory => f.write_str("out of physical memory for a task stack"),
            Self::Map(error) => write!(f, "cannot map a task stack page: {error}"),
        }
    }
}

/// A kernel stack ([`STACK_SIZE`]) in the stack window with an unmapped guard area
/// below it. Unmaps its pages and frees their frames when dropped.
pub struct KernelStack {
    slot: u64,
}

impl KernelStack {
    /// Allocates a slot and maps fresh frames for the stack.
    pub fn new() -> Result<Self, StackError> {
        let slot = loop {
            let used = SLOTS.load(Ordering::Relaxed);
            let free = u64::from((!used).trailing_zeros());
            if free >= MAX_STACKS {
                return Err(StackError::NoSlot);
            }
            let claimed = used | 1 << free;
            if SLOTS
                .compare_exchange(used, claimed, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break free;
            }
        };
        // From here on, dropping `stack` undoes whatever was mapped.
        let stack = Self { slot };
        let (bottom, top) = stack.bounds();
        let mut frames = crate::mm::frames();
        let frames = frames.as_mut().ok_or(StackError::NoFrameAllocator)?;
        for virt in (bottom..top).step_by(FRAME_SIZE as usize) {
            let frame = frames.alloc().map_err(|_| StackError::OutOfMemory)?;
            if let Err(error) =
                paging::map_kernel_page(virt, frame.addr(), PageSize::Size4K, Flags::DATA, frames)
            {
                let _ = frames.free(frame);
                return Err(StackError::Map(error));
            }
        }
        Ok(stack)
    }

    /// `(bottom, top)` of the usable stack; the guard area lies below `bottom`.
    pub fn bounds(&self) -> (u64, u64) {
        let top = STACK_WINDOW + (self.slot + 1) * SLOT_SIZE;
        (top - STACK_SIZE, top)
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let (bottom, top) = self.bounds();
        for virt in (bottom..top).step_by(FRAME_SIZE as usize) {
            // Pages that were never mapped (a failed `new`) are skipped.
            if let Ok(phys) = paging::unmap_kernel_page(virt) {
                let mut frames = crate::mm::frames();
                if let (Some(frames), Some(frame)) = (frames.as_mut(), Frame::from_addr(phys)) {
                    let _ = frames.free(frame);
                }
            }
        }
        SLOTS.fetch_and(!(1 << self.slot), Ordering::Relaxed);
    }
}

/// A thread's saved execution state, and the process address space it runs
/// in (none for kernel threads, which use the kernel address space).
pub struct Context {
    /// Saved stack pointer while not running.
    rsp: AtomicU64,
    running: AtomicBool,
    exited: AtomicBool,
    /// `None` for the boot context, which runs on the kernel stack.
    stack: Option<KernelStack>,
    /// Process address space, destroyed with the context (issue #38).
    space: Option<IrqMutex<AddressSpace>>,
    /// Root table of `space`; 0 for the kernel address space.
    root: u64,
}

/// Set once the boot context has been handed out.
static BOOT_TAKEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// Saves callee-saved registers and RSP to `*save`, loads `next`.
    fn pharos_switch_context(save: *mut u64, next: u64);
    /// First code a new context runs (see `global_asm!` below).
    fn pharos_task_trampoline();
    /// Enters ring 3 at `rip` with stack `rsp` and `arg` in `rdi`.
    fn pharos_enter_user(rip: u64, rsp: u64, arg: u64) -> !;
}

// Ring 3 entry: an `iretq` frame with the user selectors, interrupts enabled
// in user mode, and every other register cleared so no kernel value leaks.
global_asm!(
    ".global pharos_enter_user",
    "pharos_enter_user:",
    "push {user_data}",
    "push rsi",
    "push 0x202",
    "push {user_code}",
    "push rdi",
    "mov rdi, rdx",
    "xor eax, eax",
    "xor ebx, ebx",
    "xor ecx, ecx",
    "xor edx, edx",
    "xor esi, esi",
    "xor ebp, ebp",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "iretq",
    user_data = const super::gdt::USER_DATA,
    user_code = const super::gdt::USER_CODE,
);

/// Leaves the kernel for user mode: runs the calling thread at `rip` with
/// stack pointer `rsp` and `arg` in `rdi`, in ring 3 with interrupts
/// enabled. Interrupts, exceptions, and (from #40) system calls return to
/// the kernel on this thread's kernel stack. Call from a thread whose
/// process address space maps `rip` and the stack. Panics if either address
/// is outside the user half.
pub fn enter_user(rip: u64, rsp: u64, arg: u64) -> ! {
    let user = 0x1000..paging::USER_END;
    assert!(
        user.contains(&rip) && user.contains(&(rsp - 1)),
        "user entry point or stack outside the user half"
    );
    super::disable_interrupts();
    // SAFETY: `rip` and `rsp` are canonical user-half addresses (checked),
    // so `iretq` cannot fault in ring 0. The user selectors are valid GDT
    // entries; the CPU switches back to ring 0 only through gates, onto the
    // kernel stack that `do_switch` put in the TSS. User code cannot reach
    // kernel memory: kernel pages never have the user bit. This stack frame
    // is abandoned; the next entry from user mode starts at the stack top.
    unsafe { pharos_enter_user(rip, rsp, arg) }
}

// A new context's stack holds six zeroed callee-saved registers, with r12 =
// the start function, and the trampoline as the return address. The
// trampoline enables interrupts, aligns the stack for a call, and calls the
// start function, which never returns.
global_asm!(
    ".global pharos_switch_context",
    "pharos_switch_context:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rdi], rsp",
    "mov rsp, rsi",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    "",
    ".global pharos_task_trampoline",
    "pharos_task_trampoline:",
    "sti",
    "and rsp, -16",
    "call r12",
    "ud2",
);

/// Words in a new context's initial frame: r15, r14, r13, r12, rbx, rbp,
/// return address, and one word of padding.
const INITIAL_FRAME_WORDS: usize = 8;

impl Context {
    /// The context of the code running now on the kernel stack (the boot
    /// thread). Available once; `None` afterwards.
    pub fn boot() -> Option<Arc<Self>> {
        if BOOT_TAKEN.swap(true, Ordering::Relaxed) {
            return None;
        }
        Some(Arc::new(Self {
            rsp: AtomicU64::new(0),
            running: AtomicBool::new(true),
            exited: AtomicBool::new(false),
            stack: None,
            space: None,
            root: 0,
        }))
    }

    /// A context that, when first switched to, runs `start` on `stack` with
    /// interrupts enabled.
    pub fn new(stack: KernelStack, start: extern "C" fn() -> !) -> Arc<Self> {
        Self::build(stack, start, None)
    }

    /// Like [`Context::new`], but the thread runs in the process address
    /// space `space`, which the context owns and destroys when dropped.
    /// Panics if `space` is the kernel address space.
    pub fn with_space(
        stack: KernelStack,
        start: extern "C" fn() -> !,
        space: AddressSpace,
    ) -> Arc<Self> {
        assert!(space.is_user(), "a context needs a process address space");
        Self::build(stack, start, Some(space))
    }

    fn build(
        stack: KernelStack,
        start: extern "C" fn() -> !,
        space: Option<AddressSpace>,
    ) -> Arc<Self> {
        let (_, top) = stack.bounds();
        let frame = [
            0,                                          // r15
            0,                                          // r14
            0,                                          // r13
            start as *const () as u64,                  // r12: called by the trampoline
            0,                                          // rbx
            0,                                          // rbp
            pharos_task_trampoline as *const () as u64, // return address
            0,                                          // padding
        ];
        let rsp = top - (INITIAL_FRAME_WORDS as u64) * 8;
        // SAFETY: `stack` owns the mapped, writable pages in
        // [top - STACK_SIZE, top); the frame occupies the highest 64 bytes,
        // and nothing else uses this stack yet.
        unsafe { (rsp as *mut [u64; INITIAL_FRAME_WORDS]).write(frame) };
        Arc::new(Self {
            rsp: AtomicU64::new(rsp),
            running: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            stack: Some(stack),
            root: space.as_ref().map_or(0, AddressSpace::root),
            space: space.map(IrqMutex::new),
        })
    }

    /// The process address space, locked; `None` for kernel threads.
    pub fn space(&self) -> Option<IrqMutexGuard<'_, AddressSpace>> {
        self.space.as_ref().map(IrqMutex::lock)
    }

    /// `(bottom, top)` of this context's own stack (`None` for the boot
    /// context).
    pub fn stack_bounds(&self) -> Option<(u64, u64)> {
        self.stack.as_ref().map(KernelStack::bounds)
    }

    /// True while this context is the one executing.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // Unmapping the stack we run on would fault at once.
        assert!(!self.is_running(), "dropping the running context");
        // Not running, so not active either: a switch away from this
        // context loaded another root.
        if let Some(space) = self.space.take() {
            if let Some(frames) = crate::mm::frames().as_mut() {
                space.into_inner().destroy(frames);
            }
        }
    }
}

fn check_switch(from: &Arc<Context>, to: &Arc<Context>) {
    assert!(
        !super::interrupts_enabled(),
        "context switch with interrupts enabled"
    );
    assert!(
        from.is_running(),
        "switch from a context that is not running"
    );
    assert!(
        !to.is_running() && !to.exited.load(Ordering::Relaxed),
        "switch to a context that is running or has exited"
    );
    assert!(
        Arc::strong_count(from) > 1 && Arc::strong_count(to) > 1,
        "both contexts must stay referenced elsewhere during a switch"
    );
}

fn do_switch(from: Arc<Context>, to: Arc<Context>) {
    from.running.store(false, Ordering::Relaxed);
    to.running.store(true, Ordering::Relaxed);
    let save = from.rsp.as_ptr();
    let next = to.rsp.load(Ordering::Relaxed);
    // Kernel threads run on the kernel root; process threads on their own.
    // Both map the kernel half, so execution continues on `from`'s stack.
    let root = match to.root {
        0 => paging::kernel_root().unwrap_or(0),
        root => root,
    };
    if root != 0 && root != paging::active_root() {
        paging::load_root(root);
    }
    // Interrupts and exceptions taken in user mode arrive on the thread's
    // own kernel stack.
    if let Some((_, top)) = to.stack_bounds() {
        super::gdt::set_kernel_stack(top);
    }
    // Other references keep both contexts alive (checked), and nothing else
    // runs until the switch completes (interrupts are disabled, one CPU).
    drop(from);
    drop(to);
    // SAFETY: `save` points into a live `Context`; `next` is either the
    // initial frame written by `Context::new` on its own mapped stack or the
    // stack pointer this routine saved when that context last stopped, and
    // its stack has not been used since (only the running context's stack
    // is in use). The routine preserves callee-saved registers per the C
    // calling convention.
    unsafe { pharos_switch_context(save, next) };
}

/// Stops `from` (the running context) and runs `to`. Returns when something
/// switches back to `from`. Interrupts must be disabled; both contexts must
/// also be referenced elsewhere (for example by the scheduler). Panics if a
/// rule is broken.
pub fn switch(from: Arc<Context>, to: Arc<Context>) {
    check_switch(&from, &to);
    do_switch(from, to);
}

/// Like [`switch`], but `from` has exited and can never run again; it may be
/// dropped (freeing its stack) once `to` runs.
pub fn exit_to(from: Arc<Context>, to: Arc<Context>) -> ! {
    check_switch(&from, &to);
    from.exited.store(true, Ordering::Relaxed);
    do_switch(from, to);
    unreachable!("an exited context was resumed");
}

/// Test helper: calls `f` (which may switch tasks) with known values in all
/// callee-saved registers (`rbx`, `rbp`, `r12`–`r15`) and returns true if
/// every one survives. Checks that the switch restores them.
pub fn call_preserves_callee_saved(f: extern "C" fn()) -> bool {
    let ok: u64;
    // SAFETY: `rbx` and `rbp` cannot be operands, so the block saves and
    // restores them itself. It keeps the stack 16-byte aligned for the call
    // and restores RSP afterwards; `f` is an ordinary C-ABI function, so the
    // caller-saved registers are declared clobbered.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "push rbp",
            "mov rbp, rsp",
            "and rsp, -16",
            "push rbp",
            "push rbp",
            "mov rbx, 0x1111111111111111",
            "mov rbp, 0x2222222222222222",
            "mov r12, 0x3333333333333333",
            "mov r13, 0x4444444444444444",
            "mov r14, 0x5555555555555555",
            "mov r15, 0x6666666666666666",
            "call rax",
            "xor eax, eax",
            "mov rcx, 0x1111111111111111",
            "cmp rbx, rcx",
            "jne 2f",
            "mov rcx, 0x2222222222222222",
            "cmp rbp, rcx",
            "jne 2f",
            "mov rcx, 0x3333333333333333",
            "cmp r12, rcx",
            "jne 2f",
            "mov rcx, 0x4444444444444444",
            "cmp r13, rcx",
            "jne 2f",
            "mov rcx, 0x5555555555555555",
            "cmp r14, rcx",
            "jne 2f",
            "mov rcx, 0x6666666666666666",
            "cmp r15, rcx",
            "jne 2f",
            "mov eax, 1",
            "2:",
            "mov rsp, [rsp]",
            "pop rbp",
            "pop rbx",
            inout("rax") f as *const () as u64 => ok,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            clobber_abi("C"),
        )
    };
    ok == 1
}
