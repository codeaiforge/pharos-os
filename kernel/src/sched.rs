//! Kernel task scheduler (D-013): preemptive round-robin on one CPU with a
//! one-tick time slice (10 ms at 100 Hz). Tasks switch on `yield_now`,
//! `sleep`, exit, and, once [`enable_preemption`] has run, on every timer
//! tick. An idle task runs only when nothing else is ready.
//!
//! Rules (D-013): switches happen with interrupts disabled and no
//! `IrqMutex` held (checked); the scheduler lock is released before the
//! switch. A tick switches tasks from inside the timer interrupt handler:
//! the interrupted task's interrupt frame stays on its own stack until it
//! runs again. An exited task cannot free the stack it runs on, so the next
//! scheduling call reaps it. Lock order: scheduler, then frame allocator,
//! then kernel address space.
//!
//! The scheduler is a documented singleton (one CPU; D-004 constraint 6).
//! Queue logic ([`RunQueue`], [`SleepQueue`]) is generic over what a thread
//! is (D-004 constraint 5) and host-tested.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crate::arch::x86_64::context::{self, Context, KernelStack, StackError};
use crate::arch::x86_64::paging::AddressSpace;
use crate::arch::x86_64::{
    apic, disable_interrupts, enable_and_wait_for_interrupt, enable_interrupts, without_interrupts,
};
use crate::kprintln;
use crate::mm::raw::{IrqMutex, irq_locks_held};
use crate::time;

/// Task identifier; the boot thread is 0.
pub type TaskId = u64;

/// How the running thread leaves the CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leave {
    /// It stays runnable (a yield or a used-up time slice).
    Yield,
    /// It stops being runnable (sleep or exit).
    Block,
}

/// Round-robin order: the running thread, a first-in first-out ready
/// queue, and an optional idle thread that runs only when nothing else is
/// ready and is never queued.
pub struct RunQueue<T> {
    current: T,
    ready: VecDeque<T>,
    idle: Option<T>,
    idle_running: bool,
}

impl<T: Clone> RunQueue<T> {
    /// A queue whose running thread is `current`.
    pub fn new(current: T) -> Self {
        Self {
            current,
            ready: VecDeque::new(),
            idle: None,
            idle_running: false,
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

    /// Threads waiting to run (not counting the idle thread).
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    /// Sets the idle thread.
    pub fn set_idle(&mut self, idle: T) {
        self.idle = Some(idle);
    }

    /// True if an idle thread is set.
    pub fn has_idle(&self) -> bool {
        self.idle.is_some()
    }

    /// True while the idle thread is the running one.
    pub fn idle_running(&self) -> bool {
        self.idle_running
    }

    /// Makes the first ready thread current, or the idle thread if nothing
    /// is ready and the current thread blocks. A yielding thread goes to
    /// the back of the queue (the idle thread never does). Returns
    /// `(previous, next)`, or `None` if the current thread keeps running
    /// (nothing ready on a yield, or a block with no idle thread).
    pub fn rotate(&mut self, leave: Leave) -> Option<(T, T)> {
        let (next, next_is_idle) = match self.ready.pop_front() {
            Some(next) => (next, false),
            None if leave == Leave::Block && !self.idle_running => (self.idle.clone()?, true),
            None => return None,
        };
        let previous = core::mem::replace(&mut self.current, next.clone());
        if leave == Leave::Yield && !self.idle_running {
            self.ready.push_back(previous.clone());
        }
        self.idle_running = next_is_idle;
        Some((previous, next))
    }
}

/// Sleeping threads ordered by wake-up tick; equal deadlines wake in the
/// order they went to sleep.
pub struct SleepQueue<T> {
    // ponytail: sorted Vec, O(n) insert; a heap if many tasks sleep at once.
    sleepers: Vec<(u64, T)>,
}

impl<T> SleepQueue<T> {
    /// An empty queue.
    pub const fn new() -> Self {
        Self {
            sleepers: Vec::new(),
        }
    }

    /// Adds `thread`, to wake at tick `deadline`.
    pub fn insert(&mut self, deadline: u64, thread: T) {
        let at = self.sleepers.partition_point(|(d, _)| *d <= deadline);
        self.sleepers.insert(at, (deadline, thread));
    }

    /// Removes the next thread whose deadline is at or before `now`.
    pub fn pop_due(&mut self, now: u64) -> Option<T> {
        match self.sleepers.first() {
            Some((deadline, _)) if *deadline <= now => Some(self.sleepers.remove(0).1),
            _ => None,
        }
    }

    /// Removes and returns the first entry `matches` accepts.
    pub fn take(&mut self, matches: impl Fn(&T) -> bool) -> Option<T> {
        let at = self.sleepers.iter().position(|(_, t)| matches(t))?;
        Some(self.sleepers.remove(at).1)
    }

    /// Removes every entry for `thread`.
    pub fn remove(&mut self, thread: &T)
    where
        T: PartialEq,
    {
        self.sleepers.retain(|(_, t)| t != thread);
    }

    /// Threads sleeping.
    pub fn len(&self) -> usize {
        self.sleepers.len()
    }

    /// True if no thread sleeps.
    pub fn is_empty(&self) -> bool {
        self.sleepers.is_empty()
    }
}

impl<T> Default for SleepQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The tick at which a wait of `micros` microseconds that starts at tick
/// `now` ends (D-016): rounded up to whole ticks plus one, so no wait ends
/// early. `None` waits forever (`u64::MAX`, or a deadline that would
/// overflow); 0 has passed already (do not block).
pub fn deadline_at(now: u64, micros: u64) -> Option<u64> {
    match micros {
        u64::MAX => None,
        0 => Some(0),
        _ => {
            let per_tick = 1_000_000 / u64::from(time::TICK_HZ);
            now.checked_add(micros.div_ceil(per_tick))?.checked_add(1)
        }
    }
}

/// [`deadline_at`] from the current tick.
pub fn deadline(micros: u64) -> Option<u64> {
    deadline_at(ticks(), micros)
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
    /// The timer is not calibrated (`time::init`), so it cannot tick.
    NoTimer,
}

impl fmt::Display for SchedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => f.write_str("scheduler already initialized"),
            Self::NotInitialized => f.write_str("scheduler not initialized"),
            Self::Stack(error) => write!(f, "cannot create a task stack: {error}"),
            Self::NoTimer => f.write_str("timer not calibrated (call time::init first)"),
        }
    }
}

type Entry = Box<dyn FnOnce() + Send>;

struct Task {
    id: TaskId,
    context: Arc<Context>,
    /// Taken by the task when it starts.
    entry: IrqMutex<Option<Entry>>,
    /// Set when its last [`block_until`] ended at the deadline.
    timed_out: AtomicBool,
}

struct Scheduler {
    queue: RunQueue<Arc<Task>>,
    sleepers: SleepQueue<Arc<Task>>,
    /// Tasks waiting for [`wake`] (for example on an IPC endpoint).
    blocked: BTreeMap<TaskId, Arc<Task>>,
    /// Deadlines of blocked tasks that wait with a timeout.
    timeouts: SleepQueue<TaskId>,
    /// The last exited task, freed by the next scheduling call.
    exited: Option<Arc<Task>>,
    /// Tasks told to end ([`stop`]): they never block again, and end at
    /// their next return to user mode.
    stopping: BTreeSet<TaskId>,
    next_id: TaskId,
    live: usize,
    /// Timer ticks seen by the scheduler.
    ticks: u64,
}

static SCHEDULER: IrqMutex<Option<Scheduler>> = IrqMutex::new(None);
/// Print every task switch over serial (see the debugging guide).
static TRACE: AtomicBool = AtomicBool::new(false);

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
        timed_out: AtomicBool::new(false),
    });
    *scheduler = Some(Scheduler {
        queue: RunQueue::new(boot),
        sleepers: SleepQueue::new(),
        blocked: BTreeMap::new(),
        timeouts: SleepQueue::new(),
        exited: None,
        stopping: BTreeSet::new(),
        next_id: 1,
        live: 1,
        ticks: 0,
    });
    Ok(())
}

/// A new task with its own stack, not yet queued; it runs in `space` if
/// given, else in the kernel address space.
fn new_task(entry: Entry, space: Option<AddressSpace>) -> Result<Arc<Task>, SchedError> {
    if SCHEDULER.lock().is_none() {
        return Err(SchedError::NotInitialized);
    }
    let stack = KernelStack::new().map_err(SchedError::Stack)?;
    let context = match space {
        Some(space) => Context::with_space(stack, task_start, space),
        None => Context::new(stack, task_start),
    };
    let mut scheduler = SCHEDULER.lock();
    let scheduler = scheduler.as_mut().ok_or(SchedError::NotInitialized)?;
    let id = scheduler.next_id;
    scheduler.next_id += 1;
    Ok(Arc::new(Task {
        id,
        context,
        entry: IrqMutex::new(Some(entry)),
        timed_out: AtomicBool::new(false),
    }))
}

/// Creates a task that runs `entry` on its own 32 KiB stack, and queues it
/// behind the ready tasks. It exits when `entry` returns.
pub fn spawn(entry: impl FnOnce() + Send + 'static) -> Result<TaskId, SchedError> {
    queue(new_task(Box::new(entry), None)?)
}

/// Like [`spawn`], but the task runs in the process address space `space`
/// (CR3 switches with it). The task owns `space`; it is destroyed, with all
/// its user pages, when the task is reaped.
pub fn spawn_in(
    space: AddressSpace,
    entry: impl FnOnce() + Send + 'static,
) -> Result<TaskId, SchedError> {
    queue(new_task(Box::new(entry), Some(space))?)
}

fn queue(task: Arc<Task>) -> Result<TaskId, SchedError> {
    let id = task.id;
    let mut scheduler = SCHEDULER.lock();
    let scheduler = scheduler.as_mut().ok_or(SchedError::NotInitialized)?;
    scheduler.live += 1;
    scheduler.queue.push(task);
    Ok(id)
}

/// Creates the idle task, installs the tick handler, starts the 100 Hz
/// tick, and enables interrupts: from then on a task that does not yield
/// is preempted after one tick. Needs `time::init`.
pub fn enable_preemption() -> Result<(), SchedError> {
    let idle = new_task(
        Box::new(|| {
            // Halts until an interrupt, then runs whatever it made ready (a
            // driver its device woke) without waiting for the next tick.
            // Checked with interrupts disabled so no wake-up is missed.
            loop {
                disable_interrupts();
                let ready = SCHEDULER
                    .lock()
                    .as_ref()
                    .is_some_and(|s| s.queue.ready_len() > 0);
                if ready {
                    enable_interrupts();
                } else {
                    enable_and_wait_for_interrupt();
                }
                yield_now();
            }
        }),
        None,
    )?;
    SCHEDULER
        .lock()
        .as_mut()
        .ok_or(SchedError::NotInitialized)?
        .queue
        .set_idle(idle);
    apic::set_tick_handler(on_tick);
    if !time::start_tick() {
        return Err(SchedError::NoTimer);
    }
    enable_interrupts();
    Ok(())
}

/// ID of the running task (`None` before [`init`]).
pub fn current_id() -> Option<TaskId> {
    SCHEDULER.lock().as_ref().map(|s| s.queue.current().id)
}

/// Runs `f` on the running task's process address space, locked; `None`
/// for kernel tasks.
pub fn with_current_space<R>(f: impl FnOnce(&mut AddressSpace) -> R) -> Option<R> {
    let task = SCHEDULER
        .lock()
        .as_ref()
        .map(|s| s.queue.current().clone())?;
    let mut space = task.context.space()?;
    Some(f(&mut space))
}

/// Tasks that have not exited, including the running one (not the idle
/// task).
pub fn live_tasks() -> usize {
    SCHEDULER.lock().as_ref().map_or(0, |s| s.live)
}

/// Timer ticks the scheduler has handled.
pub fn ticks() -> u64 {
    SCHEDULER.lock().as_ref().map_or(0, |s| s.ticks)
}

/// Turns tracing of task switches over serial on or off.
pub fn set_trace(on: bool) {
    TRACE.store(on, Ordering::Relaxed);
}

/// A switch decided by [`pick_next`].
struct Switch {
    from: Arc<Context>,
    to: Arc<Context>,
    trace: (TaskId, TaskId, u64),
}

/// Runs `before` on the scheduler state, reaps the previously exited task,
/// and picks the next task. Returns the switch to make, or `None` if the
/// current task keeps running.
fn pick_next(leave: Leave, before: impl FnOnce(&mut Scheduler)) -> Option<Switch> {
    // Declared before the guard, so it is dropped (stack unmapped, frames
    // freed) after the scheduler lock is released.
    let reaped;
    let mut guard = SCHEDULER.lock();
    let scheduler = guard.as_mut()?;
    // Reap first: `before` may record the task that is exiting now.
    reaped = scheduler.exited.take();
    before(scheduler);
    let (previous, next) = scheduler.queue.rotate(leave)?;
    let switch = Switch {
        from: previous.context.clone(),
        to: next.context.clone(),
        trace: (previous.id, next.id, scheduler.ticks),
    };
    drop(guard);
    drop(reaped);
    Some(switch)
}

/// No lock may be held across a switch (D-013). Checked on every call
/// that may switch, even when it turns out not to.
fn check_no_locks() {
    assert_eq!(
        irq_locks_held(),
        0,
        "task switch while holding an IrqMutex (D-013 forbids it)"
    );
}

/// Checks the switch rules, traces, and switches.
fn run_switch(switch: Switch) {
    check_no_locks();
    if TRACE.load(Ordering::Relaxed) {
        let (from, to, tick) = switch.trace;
        kprintln!("sched: tick {tick}: task {from} -> task {to}");
    }
    context::switch(switch.from, switch.to);
}

/// Lets the next ready task run; returns when this task is scheduled again
/// (at once if no other task is ready).
pub fn yield_now() {
    without_interrupts(|| {
        check_no_locks();
        if let Some(switch) = pick_next(Leave::Yield, |_| {}) {
            run_switch(switch);
        }
    });
}

/// Takes the running task off the CPU until [`wake`] names it. The caller
/// must have recorded its ID where the waker will find it, with interrupts
/// disabled since then (system calls run that way), so the wake cannot be
/// missed. Needs [`enable_preemption`] (the idle task runs meanwhile).
pub fn block_current() {
    block_until(None);
}

/// [`block_current`] that also ends at tick `deadline` (`None`: never;
/// see [`deadline`]). Returns true if [`wake`] ended it, false if the
/// deadline did (or had passed already, in which case it does not block).
/// After a timeout the caller must still look for what it waited for: a
/// waker may have delivered it between the deadline and this thread
/// running again.
///
/// A task being stopped never blocks: it returns false at once, as if its
/// wait had timed out, so the caller takes its time-out path and cleans
/// up (leaves endpoint queues) before the task ends.
pub fn block_until(deadline: Option<u64>) -> bool {
    without_interrupts(|| {
        check_no_locks();
        let mut current = None;
        let switch = {
            let passed = SCHEDULER.lock().as_ref().is_none_or(|s| {
                s.stopping.contains(&s.queue.current().id)
                    || deadline.is_some_and(|deadline| deadline <= s.ticks)
            });
            if passed {
                return false;
            }
            pick_next(Leave::Block, |s| {
                assert!(s.queue.has_idle(), "blocking needs enable_preemption");
                let task = s.queue.current().clone();
                task.timed_out.store(false, Ordering::Relaxed);
                if let Some(deadline) = deadline {
                    s.timeouts.insert(deadline, task.id);
                }
                s.blocked.insert(task.id, task.clone());
                current = Some(task);
            })
        };
        if let Some(switch) = switch {
            run_switch(switch);
        }
        !current.is_some_and(|t| t.timed_out.load(Ordering::Relaxed))
    })
}

/// Makes the blocked task `id` ready again. Returns false if it was not
/// blocked.
pub fn wake(id: TaskId) -> bool {
    let mut scheduler = SCHEDULER.lock();
    let Some(scheduler) = scheduler.as_mut() else {
        return false;
    };
    match scheduler.blocked.remove(&id) {
        Some(task) => {
            scheduler.timeouts.remove(&id);
            scheduler.queue.push(task);
            true
        }
        None => false,
    }
}

/// Tells task `id` to end: it is marked, and if it waits it is made ready
/// at once, a blocked wait ending as timed out. It ends itself at its next
/// return to user mode (`process::end_stopped`). Returns false if the
/// scheduler is not running.
pub fn stop(id: TaskId) -> bool {
    let mut scheduler = SCHEDULER.lock();
    let Some(s) = scheduler.as_mut() else {
        return false;
    };
    s.stopping.insert(id);
    if let Some(task) = s.blocked.remove(&id) {
        s.timeouts.remove(&id);
        task.timed_out.store(true, Ordering::Relaxed);
        s.queue.push(task);
    } else if let Some(task) = s.sleepers.take(|t| t.id == id) {
        s.queue.push(task);
    }
    true
}

/// True if the running task was told to end ([`stop`]).
pub fn stopping() -> bool {
    SCHEDULER
        .lock()
        .as_ref()
        .is_some_and(|s| s.stopping.contains(&s.queue.current().id))
}

/// Sleeps for at least `duration`, rounded up to whole ticks (10 ms).
/// Before [`enable_preemption`] there is no tick to wake the task, so it
/// busy-waits instead.
pub fn sleep(duration: Duration) {
    let period = Duration::from_secs(1) / time::TICK_HZ;
    let ticks = u64::try_from(duration.as_nanos().div_ceil(period.as_nanos())).unwrap_or(u64::MAX);
    without_interrupts(|| {
        check_no_locks();
        let (preemptive, stopping) = SCHEDULER.lock().as_ref().map_or((false, false), |s| {
            (
                s.queue.has_idle(),
                s.stopping.contains(&s.queue.current().id),
            )
        });
        // A task being stopped returns at once, to end.
        if stopping {
            return;
        }
        if !preemptive {
            time::delay(duration);
            return;
        }
        let switch = pick_next(Leave::Block, |s| {
            // The next tick may be moments away, so wait one more to make
            // sure at least `duration` passes. Saturates: a huge duration
            // sleeps forever.
            let deadline = s.ticks.saturating_add(ticks).saturating_add(1);
            let current = s.queue.current().clone();
            s.sleepers.insert(deadline, current);
        });
        if let Some(switch) = switch {
            run_switch(switch);
        }
    });
}

/// Ends the running task. Panics if nothing else can run (no ready task
/// and no idle task).
pub fn exit() -> ! {
    disable_interrupts();
    check_no_locks();
    let Some(switch) = pick_next(Leave::Block, |s| {
        s.live -= 1;
        let current = s.queue.current().clone();
        s.stopping.remove(&current.id);
        s.exited = Some(current);
    }) else {
        panic!("the last ready task exited");
    };
    if TRACE.load(Ordering::Relaxed) {
        let (from, to, tick) = switch.trace;
        kprintln!("sched: tick {tick}: task {from} exited -> task {to}");
    }
    context::exit_to(switch.from, switch.to)
}

/// Timer tick (interrupt context, interrupts disabled): wakes due sleepers
/// and ends the running task's time slice.
fn on_tick() {
    let switch = pick_next(Leave::Yield, |s| {
        s.ticks += 1;
        while let Some(task) = s.sleepers.pop_due(s.ticks) {
            s.queue.push(task);
        }
        // Waits that reached their deadline: ready again, marked timed out.
        while let Some(id) = s.timeouts.pop_due(s.ticks) {
            if let Some(task) = s.blocked.remove(&id) {
                task.timed_out.store(true, Ordering::Relaxed);
                s.queue.push(task);
            }
        }
    });
    if let Some(switch) = switch {
        run_switch(switch);
    }
    // A process thread runs again here, interrupted in user mode: if it
    // was told to end, it ends now. Kernel tasks are never stopped.
    if stopping() {
        crate::process::end_stopped();
    }
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
    use super::{Leave, RunQueue, SleepQueue, deadline_at};

    #[test]
    fn deadlines_round_up_and_never_end_early() {
        assert_eq!(deadline_at(5, u64::MAX), None, "forever");
        assert_eq!(deadline_at(5, 0), Some(0), "already passed");
        assert_eq!(deadline_at(5, 1), Some(7), "1 µs: one tick, plus one");
        assert_eq!(deadline_at(5, 10_000), Some(7), "exactly one tick");
        assert_eq!(deadline_at(5, 10_001), Some(8));
        assert_eq!(deadline_at(u64::MAX - 1, 10_000), None, "overflow: forever");
        assert_eq!(
            deadline_at(0, u64::MAX - 1),
            Some((u64::MAX - 1).div_ceil(10_000) + 1)
        );
    }

    #[test]
    fn removed_sleepers_never_wake() {
        let mut s = SleepQueue::new();
        s.insert(10, 1);
        s.insert(20, 2);
        s.insert(30, 1);
        s.remove(&1);
        assert_eq!(s.pop_due(100), Some(2));
        assert!(s.is_empty());
    }

    #[test]
    fn yields_rotate_in_order() {
        let mut q = RunQueue::new('m');
        for t in ['a', 'b', 'c'] {
            q.push(t);
        }
        let mut order = Vec::new();
        for _ in 0..8 {
            let (previous, next) = q.rotate(Leave::Yield).unwrap();
            assert_eq!(previous, *order.last().unwrap_or(&'m'));
            order.push(next);
        }
        assert_eq!(order, ['a', 'b', 'c', 'm', 'a', 'b', 'c', 'm']);
        assert_eq!(q.ready_len(), 3);
    }

    #[test]
    fn blocking_leaves_the_queue() {
        let mut q = RunQueue::new('m');
        q.push('a');
        q.push('b');
        assert_eq!(q.rotate(Leave::Yield), Some(('m', 'a')));
        assert_eq!(q.rotate(Leave::Block), Some(('a', 'b')), "a blocks");
        assert_eq!(q.rotate(Leave::Yield), Some(('b', 'm')));
        assert_eq!(q.rotate(Leave::Yield), Some(('m', 'b')), "a is gone");
        assert_eq!(*q.current(), 'b');
    }

    #[test]
    fn alone_keeps_running_without_idle() {
        let mut q = RunQueue::new('m');
        assert_eq!(q.rotate(Leave::Yield), None);
        assert_eq!(q.rotate(Leave::Block), None);
        assert_eq!(*q.current(), 'm');
    }

    #[test]
    fn idle_runs_only_when_nothing_is_ready() {
        let mut q = RunQueue::new('m');
        q.set_idle('i');
        assert_eq!(q.rotate(Leave::Yield), None, "a yield never picks idle");
        assert_eq!(q.rotate(Leave::Block), Some(('m', 'i')), "m sleeps");
        assert!(q.idle_running());
        assert_eq!(q.rotate(Leave::Yield), None, "idle keeps running");
        assert_eq!(q.rotate(Leave::Block), None, "idle never blocks");
        q.push('m'); // m wakes
        assert_eq!(q.rotate(Leave::Yield), Some(('i', 'm')));
        assert!(!q.idle_running());
        assert_eq!(q.ready_len(), 0, "idle is never queued");
    }

    #[test]
    fn sleepers_wake_in_deadline_order() {
        let mut s = SleepQueue::new();
        s.insert(50, 'a');
        s.insert(10, 'b');
        s.insert(30, 'c');
        s.insert(30, 'd');
        assert_eq!(s.pop_due(9), None);
        assert_eq!(s.pop_due(10), Some('b'));
        assert_eq!(s.pop_due(40), Some('c'));
        assert_eq!(s.pop_due(40), Some('d'), "equal deadlines keep their order");
        assert_eq!(s.pop_due(40), None);
        assert_eq!(s.len(), 1);
        assert_eq!(s.pop_due(u64::MAX), Some('a'));
        assert!(s.is_empty());
    }
}
