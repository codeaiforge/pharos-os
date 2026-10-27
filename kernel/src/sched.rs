//! Kernel task scheduler (D-013): round-robin on one CPU. Issue #33 adds
//! tasks and cooperative switching (`yield_now`, exit); preemption by the
//! timer follows in #34.
//!
//! Rules (D-013): switches happen with interrupts disabled and no
//! `IrqMutex` held (checked); the scheduler lock is released before the
//! switch. An exited task cannot free the stack it runs on, so the next
//! scheduling call reaps it. Lock order: scheduler, then frame allocator,
//! then kernel address space.
//!
//! The scheduler is a documented singleton (one CPU; D-004 constraint 6).
//! Queue logic ([`RunQueue`]) is generic over what a thread is (D-004
//! constraint 5) and host-tested.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::fmt;

use crate::arch::x86_64::context::{self, Context, KernelStack, StackError};
use crate::arch::x86_64::{disable_interrupts, without_interrupts};
use crate::mm::raw::{IrqMutex, irq_locks_held};

/// Task identifier; the boot thread is 0.
pub type TaskId = u64;

/// Round-robin order: the running thread and a first-in first-out ready
/// queue.
pub struct RunQueue<T> {
    current: T,
    ready: VecDeque<T>,
}

impl<T: Clone> RunQueue<T> {
    /// A queue whose running thread is `current`.
    pub fn new(current: T) -> Self {
        Self {
            current,
            ready: VecDeque::new(),
        }
    }

    /// The running thread.
    pub fn current(&self) -> &T {
        &self.current
    }

    /// Adds a ready thread at the back.
    pub fn push(&mut self, thread: T) {
        self.ready.push_back(thread);
    }

    /// Threads waiting to run.
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    /// Makes the first ready thread current. The previous one goes to the
    /// back of the queue if `requeue` (a yield), or leaves the queue (an
    /// exit). Returns `(previous, next)`, or `None` if nothing else is ready
    /// (the current thread keeps running).
    pub fn rotate(&mut self, requeue: bool) -> Option<(T, T)> {
        let next = self.ready.pop_front()?;
        let previous = core::mem::replace(&mut self.current, next.clone());
        if requeue {
            self.ready.push_back(previous.clone());
        }
        Some((previous, next))
    }
}

/// Why a scheduler call failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SchedError {
    /// [`init`] was called twice, or after the boot context was taken.
    AlreadyInitialized,
    /// [`init`] has not been called.
    NotInitialized,
    /// No stack for a new task.
    Stack(StackError),
}

impl fmt::Display for SchedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => f.write_str("scheduler already initialized"),
            Self::NotInitialized => f.write_str("scheduler not initialized"),
            Self::Stack(error) => write!(f, "cannot create a task stack: {error}"),
        }
    }
}

type Entry = Box<dyn FnOnce() + Send>;

struct Task {
    id: TaskId,
    context: Arc<Context>,
    /// Taken by the task when it starts.
    entry: IrqMutex<Option<Entry>>,
}

struct Scheduler {
    queue: RunQueue<Arc<Task>>,
    /// The last exited task, freed by the next scheduling call.
    exited: Option<Arc<Task>>,
    next_id: TaskId,
    live: usize,
}

static SCHEDULER: IrqMutex<Option<Scheduler>> = IrqMutex::new(None);

/// Makes the running code (on the kernel stack) task 0. Needs the heap.
pub fn init() -> Result<(), SchedError> {
    let mut scheduler = SCHEDULER.lock();
    if scheduler.is_some() {
        return Err(SchedError::AlreadyInitialized);
    }
    let context = Context::boot().ok_or(SchedError::AlreadyInitialized)?;
    let boot = Arc::new(Task {
        id: 0,
        context,
        entry: IrqMutex::new(None),
    });
    *scheduler = Some(Scheduler {
        queue: RunQueue::new(boot),
        exited: None,
        next_id: 1,
        live: 1,
    });
    Ok(())
}

/// Creates a task that runs `entry` on its own 16 KiB stack, and queues it
/// behind the ready tasks. It exits when `entry` returns.
pub fn spawn(entry: impl FnOnce() + Send + 'static) -> Result<TaskId, SchedError> {
    if SCHEDULER.lock().is_none() {
        return Err(SchedError::NotInitialized);
    }
    let stack = KernelStack::new().map_err(SchedError::Stack)?;
    let context = Context::new(stack, task_start);
    let mut scheduler = SCHEDULER.lock();
    let scheduler = scheduler.as_mut().ok_or(SchedError::NotInitialized)?;
    let id = scheduler.next_id;
    scheduler.next_id += 1;
    scheduler.live += 1;
    scheduler.queue.push(Arc::new(Task {
        id,
        context,
        entry: IrqMutex::new(Some(Box::new(entry))),
    }));
    Ok(id)
}

/// ID of the running task (`None` before [`init`]).
pub fn current_id() -> Option<TaskId> {
    SCHEDULER.lock().as_ref().map(|s| s.queue.current().id)
}

/// Tasks that have not exited, including the running one.
pub fn live_tasks() -> usize {
    SCHEDULER.lock().as_ref().map_or(0, |s| s.live)
}

/// Picks the next task. Reaps the previously exited task first. Returns
/// the contexts to switch between, or `None` if nothing else is ready.
fn pick_next(requeue: bool) -> Option<(Arc<Context>, Arc<Context>)> {
    // Declared before the guard, so it is dropped (stack unmapped, frames
    // freed) after the scheduler lock is released.
    let reaped;
    let mut guard = SCHEDULER.lock();
    let scheduler = guard.as_mut()?;
    reaped = scheduler.exited.take();
    let (previous, next) = scheduler.queue.rotate(requeue)?;
    if !requeue {
        scheduler.live -= 1;
        scheduler.exited = Some(previous.clone());
    }
    let contexts = (previous.context.clone(), next.context.clone());
    drop(guard);
    drop(reaped);
    Some(contexts)
}

/// No lock may be held across a switch (D-013).
fn check_no_locks() {
    assert_eq!(
        irq_locks_held(),
        0,
        "task switch while holding an IrqMutex (D-013 forbids it)"
    );
}

/// Lets the next ready task run; returns when this task is scheduled again
/// (at once if no other task is ready).
pub fn yield_now() {
    without_interrupts(|| {
        check_no_locks();
        if let Some((from, to)) = pick_next(true) {
            context::switch(from, to);
        }
    });
}

/// Ends the running task. Panics if no other task is ready.
pub fn exit() -> ! {
    disable_interrupts();
    check_no_locks();
    let Some((from, to)) = pick_next(false) else {
        panic!("the last ready task exited");
    };
    context::exit_to(from, to)
}

/// First function of every spawned task (called by the trampoline with
/// interrupts enabled).
extern "C" fn task_start() -> ! {
    let task = SCHEDULER.lock().as_ref().map(|s| s.queue.current().clone());
    let entry = task.and_then(|task| task.entry.lock().take());
    if let Some(entry) = entry {
        entry();
    }
    exit()
}

#[cfg(test)]
mod tests {
    use super::RunQueue;

    #[test]
    fn yields_rotate_in_order() {
        let mut q = RunQueue::new('m');
        for t in ['a', 'b', 'c'] {
            q.push(t);
        }
        let mut order = Vec::new();
        for _ in 0..8 {
            let (previous, next) = q.rotate(true).unwrap();
            assert_eq!(previous, *order.last().unwrap_or(&'m'));
            order.push(next);
        }
        assert_eq!(order, ['a', 'b', 'c', 'm', 'a', 'b', 'c', 'm']);
        assert_eq!(q.ready_len(), 3);
    }

    #[test]
    fn exit_leaves_the_queue() {
        let mut q = RunQueue::new('m');
        q.push('a');
        q.push('b');
        assert_eq!(q.rotate(true), Some(('m', 'a')));
        assert_eq!(q.rotate(false), Some(('a', 'b')), "a exits");
        assert_eq!(q.rotate(true), Some(('b', 'm')));
        assert_eq!(q.rotate(true), Some(('m', 'b')), "a is gone");
        assert_eq!(*q.current(), 'b');
    }

    #[test]
    fn alone_keeps_running() {
        let mut q = RunQueue::new('m');
        assert_eq!(q.rotate(true), None);
        assert_eq!(q.rotate(false), None);
        assert_eq!(*q.current(), 'm');
        assert_eq!(q.ready_len(), 0);
    }
}
