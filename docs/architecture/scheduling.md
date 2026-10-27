# Scheduling

## 1. Status

- **Design:** Accepted with [D-013](../project/decision-log.md#d-013-scheduling-model) (2026-10-27); the timer is the 100 Hz tick from [D-006](../project/decision-log.md#d-006-interrupt-controller-and-timer-design).
- **Implementation:** kernel tasks on their own guarded stacks, the context switch, round-robin switching (`yield_now`, exit; #33), and preemption by the timer tick, the idle task, and sleeping (#34) are **implemented** (M2.6). The main kernel does not start tasks yet; test kernels do. SMP and user threads are out of scope for M2.6.

## 2. Context

M2.6 asks for several kernel tasks running interleaved, a preemptive scheduler, and a test that a busy task cannot starve others. The kernel uses one CPU, has a heap, a frame allocator, its own page tables, and interrupt-safe locks (`IrqMutex`). D-004 asks that the scheduler not assume every thread runs in the kernel (constraint 5) and that global state be limited to documented singletons (constraint 6).

## 3. Design

### Tasks (`sched`)

- `sched::init()` turns the running code (on the kernel stack) into task 0. It needs the heap.
- `sched::spawn(closure)` creates a task with its own stack and queues it behind the ready tasks; IDs count up from 1. The task runs the closure with interrupts enabled and exits when it returns.
- `sched::yield_now()` lets the next ready task run and returns when this task's turn comes again (at once if nothing else is ready). `sched::exit()` ends the running task.
- `sched::sleep(duration)` blocks the task for at least `duration`, rounded up to whole ticks plus one (the next tick may be moments away). Before preemption is enabled it busy-waits instead.
- `sched::spawn_in(space, closure)` runs the task in a process address space (#38). The switch loads that space's root into CR3, and back to the kernel root for kernel tasks. The task's context owns the space and destroys it when the task is reaped.
- Order: one first-in first-out ready queue (`RunQueue`, generic over the thread type and host-tested). A yielding or preempted task goes to the back. Sleepers wait in a `SleepQueue` ordered by wake-up tick (equal deadlines in sleep order) and rejoin the back of the ready queue when due.

### Preemption and idle

- `sched::enable_preemption()` (after `time::init`) creates the idle task, installs the scheduler as the APIC tick handler, starts the 100 Hz tick, and enables interrupts.
- **Time slice: one tick (10 ms).** On every tick the handler (interrupt context, interrupts disabled, after EOI) counts the tick, moves due sleepers to the ready queue, and switches to the next ready task if there is one. The switch happens inside the handler: the preempted task's interrupt frame stays on its own stack, and the task continues through the handler's `iretq` when it runs again.
- **Idle task:** runs only when no task is ready, never waits in the queue, and halts (`hlt`) with interrupts enabled. The next tick that finds a ready task switches away from it.
- `sched::set_trace(true)` prints each switch over serial ([debugging guide](../development/debugging.md#trace-task-switches)).
- The scheduler state is a singleton behind an `IrqMutex` (one CPU; allowed by D-004 constraint 6).

### Stacks and contexts (`arch::x86_64::context`)

- Each task stack is 16 KiB of fresh frames in a 32 KiB slot of the stack window at `0xffffc80000000000`; the lower 16 KiB of each slot stays unmapped as a guard area. A stack overflow faults on the guard and is reported as a double fault (IST1). At most 64 stacks for now.
- A `Context` is a saved stack pointer plus the stack it owns. The boot context (task 0) runs on the kernel stack and owns none.
- The switch routine (`global_asm!`) pushes `rbx`, `rbp`, `r12`–`r15`, stores RSP, loads the next RSP, pops, and returns. The kernel is soft-float, so no FPU or SSE state exists. A new context starts in a trampoline that enables interrupts and calls the scheduler's start function.
- `context::switch` is a safe function because it checks, and panics otherwise: interrupts are disabled; the source is the running context; the target is neither running nor exited; both are referenced elsewhere during the switch. A running context cannot be dropped.

### Exit and reaping

An exited task cannot unmap the stack it is running on. Its last switch marks its context exited (never resumed); the scheduler keeps the task until the next scheduling call (a yield or exit by any task), which drops it: the stack pages are unmapped and their frames freed.

### Locking rules

1. Switches happen with interrupts disabled and **no `IrqMutex` held**. `IrqMutex` counts held guards; `yield_now` and `exit` panic if any is held.
2. The scheduler takes its own lock to pick the next task and releases it before switching. Interrupt handlers can take the scheduler lock safely: nobody holds an `IrqMutex` with interrupts enabled, so a tick never finds it held.
3. Lock order: scheduler, then frame allocator, then kernel address space (reaping frees frames after the scheduler lock is released).
4. Interrupts are disabled only inside lock sections and the switch itself. A task that disables interrupts for long blocks preemption; this is a rule, not enforced.

## 4. Security

- `unsafe` code: the switch routine, the trampoline, and writing a new context's first frame, all in `arch::x86_64::context`. Scheduler logic is safe Rust.
- Every task stack has a guard area, so an overflow stops the kernel with a report instead of corrupting a neighbour's stack. Limit: one stack frame larger than 16 KiB could jump over it.
- All tasks are kernel code with full privileges; there is no isolation between them yet (M2.7 adds user processes).

## 5. Testing

- Host unit tests: round-robin order, blocking leaving the queue, a single task keeps running, the idle thread runs only when nothing is ready and is never queued, sleepers wake in deadline order.
- Test kernels: `tasks` (three tasks interleave as `abcabcabc`, own stacks in the stack window, interrupts enabled in tasks, IDs, callee-saved registers survive switches, exited tasks return their stack frames, closures run with captured values, yielding while holding a lock panics) `task_overflow` (a task's stack overflow is a double fault with RSP at the bottom of its stack), and `preemption` (sleepers wake in deadline order and never early; with a task that spins forever and two workers that never yield, task 0 still wakes from a 300 ms sleep within 2 s, every busy task keeps making progress, and workers see at most 10 ticks between turns, in practice 3–4). Each was checked to fail with a register lost in the switch, a mapped guard area, no reaping, unsorted sleepers, or no time slice (task 0 then never wakes and the run times out).

## 6. Alternatives

See D-013: cooperative-only scheduling, priority or fair-share scheduling, naked functions for the switch (need Rust 1.88, above the 1.85 minimum), and deferring the switch to the interrupt return path.

## 7. Open questions

- More than 64 tasks (a wider slot bitmap).
- Per-CPU run queues for SMP (separate decision).
- Address-space switching and the TSS ring-0 stack for user threads (M2.7).
