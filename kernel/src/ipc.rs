//! Synchronous IPC endpoints (D-014, syscalls-ipc.md, issue #41).
//!
//! A message is at most 256 bytes plus one capability. `send` copies the
//! message into the kernel (one buffer per waiting thread, held in the
//! endpoint's sender queue) and hands it straight to a waiting receiver,
//! or waits until a receiver takes it. `receive` takes the first waiting
//! sender's message, or waits until one arrives. Both queues are first in
//! first out. Each thread waits on at most one endpoint, so kernel memory
//! for IPC is bounded by the number of threads.
//!
//! Each endpoint also has a 32-bit notification word (services.md): the
//! kernel ORs bits into it (a child ended, an interrupt fired) without
//! blocking or allocating, and `receive` returns pending bits before any
//! message.
//!
//! Everything here runs inside system calls (or interrupt handlers, for
//! [`Endpoint::signal`]), with interrupts disabled from queueing to
//! blocking, so a wake cannot be missed. No lock is held while a thread
//! blocks.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::cap::Capability;
use crate::mm::raw::IrqMutex;
use crate::sched::TaskId;
use crate::syscall::MAX_MESSAGE;

/// A message in flight.
pub struct Message {
    pub data: [u8; MAX_MESSAGE],
    pub len: usize,
    /// A capability derived for the receiver, if one was passed.
    pub cap: Option<Arc<Capability>>,
    /// The badge of the capability the message was sent through.
    pub badge: u32,
}

/// What a receive got: a message, pending notification bits, or nothing
/// before the deadline.
// Returned once and consumed at once; boxing would allocate per message.
#[allow(clippy::large_enum_variant)]
pub enum Received {
    Message(Message),
    Notification(u32),
    TimedOut,
}

impl Message {
    /// The message bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// An IPC endpoint: the threads waiting to send (with their messages) and
/// to receive.
pub struct Endpoint {
    queues: IrqMutex<Queues>,
}

#[derive(Default)]
struct Queues {
    senders: VecDeque<(TaskId, Message)>,
    receivers: VecDeque<TaskId>,
    notifications: u32,
}

impl Endpoint {
    /// A new endpoint with nobody waiting.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queues: IrqMutex::new(Queues::default()),
        })
    }

    /// The send half: if a receiver waits, returns it with the message to
    /// hand over; otherwise queues `sender` with `message` and returns
    /// `None` (the sender then blocks).
    pub fn offer(&self, sender: TaskId, message: Message) -> Option<(TaskId, Message)> {
        let mut queues = self.queues.lock();
        match queues.receivers.pop_front() {
            Some(receiver) => Some((receiver, message)),
            None => {
                queues.senders.push_back((sender, message));
                None
            }
        }
    }

    /// The receive half: pending notification bits first (cleared); else
    /// the first waiting sender with its message (the sender is then
    /// woken); otherwise queues `receiver` and returns `None` (the receiver
    /// then blocks).
    pub fn take(&self, receiver: TaskId) -> Option<Taken> {
        let mut queues = self.queues.lock();
        if queues.notifications != 0 {
            return Some(Taken::Notification(core::mem::take(
                &mut queues.notifications,
            )));
        }
        match queues.senders.pop_front() {
            Some((sender, message)) => Some(Taken::Message(sender, message)),
            None => {
                queues.receivers.push_back(receiver);
                None
            }
        }
    }

    /// The first waiting sender with its message, without queueing as a
    /// receiver if there is none: for kernel tasks, which have no inbox and
    /// poll instead (the boot waits for `init`'s report this way).
    pub fn try_take(&self) -> Option<(TaskId, Message)> {
        self.queues.lock().senders.pop_front()
    }

    /// Takes pending notification bits (0 if none): a receiver woken by
    /// [`Self::signal`] collects them here.
    pub fn take_notifications(&self) -> u32 {
        core::mem::take(&mut self.queues.lock().notifications)
    }

    /// ORs `bits` into the notification word; returns a waiting receiver to
    /// wake, if any. Never blocks or allocates, so interrupt handlers may
    /// call it.
    pub fn signal(&self, bits: u32) -> Option<TaskId> {
        let mut queues = self.queues.lock();
        queues.notifications |= bits;
        queues.receivers.pop_front()
    }

    /// Hands `message` to a waiting receiver, returned with it; if none
    /// waits, drops the message without queueing it (non-blocking `send`).
    pub fn offer_now(&self, message: Message) -> Option<(TaskId, Message)> {
        let receiver = self.queues.lock().receivers.pop_front()?;
        Some((receiver, message))
    }

    /// True if no sender and no notification is pending (`call` needs its
    /// reply endpoint idle).
    pub fn is_idle(&self) -> bool {
        let queues = self.queues.lock();
        queues.senders.is_empty() && queues.notifications == 0
    }

    /// Takes `receiver` out of the receiver queue (its wait timed out);
    /// false if it is not there (a sender or a signal took it first).
    pub fn remove_receiver(&self, receiver: TaskId) -> bool {
        let mut queues = self.queues.lock();
        let at = queues.receivers.iter().position(|&r| r == receiver);
        at.map(|at| queues.receivers.remove(at)).is_some()
    }

    /// Takes `sender` and its message out of the sender queue (its wait
    /// timed out); `None` if a receiver took the message first.
    pub fn remove_sender(&self, sender: TaskId) -> Option<Message> {
        let mut queues = self.queues.lock();
        let at = queues.senders.iter().position(|(s, _)| *s == sender)?;
        queues.senders.remove(at).map(|(_, message)| message)
    }

    /// Threads waiting, `(senders, receivers)`.
    pub fn waiting(&self) -> (usize, usize) {
        let queues = self.queues.lock();
        (queues.senders.len(), queues.receivers.len())
    }
}

/// What [`Endpoint::take`] found.
// Returned once and consumed at once; boxing would allocate per message.
#[allow(clippy::large_enum_variant)]
pub enum Taken {
    Notification(u32),
    Message(TaskId, Message),
}

#[cfg(target_os = "none")]
pub use kernel::{call, call_now, notify, poll, receive, receive_now, send, send_now, try_send};

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::without_interrupts;
    use crate::{process, sched};

    // `send`, `call`, and `receive` turn interrupts off: a thread
    // preempted after it queued itself but before it blocked would miss its
    // waker's `wake` (a no-op for a thread not blocked) and block forever
    // (M3.4 review F2). Kernel threads (the test kernels) call them with
    // interrupts on. System calls, which run with interrupts off already,
    // call the `_now` forms and skip the cost.

    /// Sends `message` on `endpoint` from the running thread; returns once
    /// a receiver has it.
    pub fn send(endpoint: &Endpoint, message: Message) {
        without_interrupts(|| send_now(endpoint, message));
    }

    /// [`send`] for a caller with interrupts off.
    pub fn send_now(endpoint: &Endpoint, message: Message) {
        let me = sched::current_id().unwrap_or(0);
        match endpoint.offer(me, message) {
            Some((receiver, message)) => {
                if let Some(process) = process::by_id(receiver) {
                    *process.inbox.lock() = Some(message);
                }
                sched::wake(receiver);
            }
            // The receiver that takes the message wakes us. A thread being
            // stopped returns at once and takes its message back, so no
            // queue keeps a sender that has ended.
            None => {
                sched::block_current();
                if sched::stopping() {
                    endpoint.remove_sender(me);
                }
            }
        }
    }

    /// Sends `message` only if a receiver is waiting; returns false (and
    /// drops the message) otherwise.
    pub fn try_send(endpoint: &Endpoint, message: Message) -> bool {
        match endpoint.offer_now(message) {
            Some((receiver, message)) => {
                if let Some(process) = process::by_id(receiver) {
                    *process.inbox.lock() = Some(message);
                }
                sched::wake(receiver);
                true
            }
            None => false,
        }
    }

    /// After a receive-side wait on `endpoint` ended (`woken` false: at the
    /// deadline): a message in the inbox wins, even one that arrived after
    /// the deadline; else, if this thread is still queued, it leaves the
    /// queue and the wait timed out; else a signal took it, and the bits
    /// are on the endpoint. Interrupts are off, so nothing changes between
    /// these checks.
    fn finish_wait(endpoint: &Endpoint, me: TaskId, woken: bool) -> Option<Received> {
        if let Some(message) = process::current()?.inbox.lock().take() {
            return Some(Received::Message(message));
        }
        if !woken && endpoint.remove_receiver(me) {
            return Some(Received::TimedOut);
        }
        Some(Received::Notification(endpoint.take_notifications()))
    }

    /// Request and reply (networking.md): registers the running thread as
    /// a receiver on `reply` (which must be idle) before the request is
    /// delivered, so a reply can never come too early; sends `message` on
    /// `endpoint`; then waits for the first event on `reply`. Both waits
    /// end at tick `deadline` (`None`: never); a request not yet taken by
    /// then is withdrawn.
    pub fn call(
        endpoint: &Endpoint,
        message: Message,
        reply: &Endpoint,
        deadline: Option<u64>,
    ) -> Option<Received> {
        without_interrupts(|| call_now(endpoint, message, reply, deadline))
    }

    /// [`call`] for a caller with interrupts off.
    pub fn call_now(
        endpoint: &Endpoint,
        message: Message,
        reply: &Endpoint,
        deadline: Option<u64>,
    ) -> Option<Received> {
        let me = sched::current_id().unwrap_or(0);
        if let Some(taken) = reply.take(me) {
            // The caller checked `reply` is idle, with interrupts off since.
            return Some(match taken {
                Taken::Notification(bits) => Received::Notification(bits),
                Taken::Message(sender, message) => {
                    sched::wake(sender);
                    Received::Message(message)
                }
            });
        }
        match endpoint.offer(me, message) {
            Some((receiver, message)) => {
                if let Some(process) = process::by_id(receiver) {
                    *process.inbox.lock() = Some(message);
                }
                sched::wake(receiver);
            }
            None => {
                let woken = sched::block_until(deadline);
                // Still queued: no server took it, so the deadline passed or
                // an event on `reply` woke us first. Withdraw it either way,
                // or it stays queued for good (#204).
                if endpoint.remove_sender(me).is_some() {
                    if !woken {
                        reply.remove_receiver(me);
                        return Some(Received::TimedOut);
                    }
                    return finish_wait(reply, me, true);
                }
            }
        }
        if let Some(message) = process::current()?.inbox.lock().take() {
            return Some(Received::Message(message));
        }
        let woken = sched::block_until(deadline);
        finish_wait(reply, me, woken)
    }

    /// Receives the next event on `endpoint` for the running thread:
    /// pending notification bits, else a message, waiting if neither is
    /// there, until tick `deadline` (`None`: forever).
    pub fn receive(endpoint: &Endpoint, deadline: Option<u64>) -> Option<Received> {
        without_interrupts(|| receive_now(endpoint, deadline))
    }

    /// [`receive`] for a caller with interrupts off.
    pub fn receive_now(endpoint: &Endpoint, deadline: Option<u64>) -> Option<Received> {
        let me = sched::current_id().unwrap_or(0);
        match endpoint.take(me) {
            Some(Taken::Notification(bits)) => Some(Received::Notification(bits)),
            Some(Taken::Message(sender, message)) => {
                sched::wake(sender);
                Some(Received::Message(message))
            }
            None => {
                // A sender puts the message in our inbox, then wakes us; a
                // signal wakes us with the bits left on the endpoint.
                let woken = sched::block_until(deadline);
                finish_wait(endpoint, me, woken)
            }
        }
    }

    /// Polls `endpoint` from a kernel task for up to `limit`; returns the
    /// first message (its sender is woken) or `None` on time-out.
    pub fn poll(endpoint: &Endpoint, limit: core::time::Duration) -> Option<Message> {
        let step = core::time::Duration::from_millis(10);
        let mut waited = core::time::Duration::ZERO;
        loop {
            if let Some((sender, message)) = endpoint.try_take() {
                sched::wake(sender);
                return Some(message);
            }
            if waited >= limit {
                return None;
            }
            sched::sleep(step);
            waited += step;
        }
    }

    /// Sets `bits` on `endpoint` and wakes a waiting receiver.
    pub fn notify(endpoint: &Endpoint, bits: u32) {
        if let Some(receiver) = endpoint.signal(bits) {
            sched::wake(receiver);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(byte: u8) -> Message {
        Message {
            data: [byte; MAX_MESSAGE],
            len: 1,
            cap: None,
            badge: 0,
        }
    }

    fn sender_of(taken: Option<Taken>) -> (TaskId, Message) {
        match taken {
            Some(Taken::Message(sender, m)) => (sender, m),
            _ => panic!("expected a message"),
        }
    }

    #[test]
    fn notifications_come_first_coalesce_and_clear() {
        let e = Endpoint::new();
        assert!(e.offer(1, message(b'm')).is_none(), "a sender waits");
        assert_eq!(e.signal(1 << 3), None, "nobody receiving");
        assert_eq!(e.signal(1 << 3 | 1), None);
        assert!(matches!(e.take(9), Some(Taken::Notification(0b1001))));
        assert_eq!(sender_of(e.take(9)).0, 1, "then the message");
        assert!(e.take(9).is_none(), "9 now waits");
        assert_eq!(e.signal(1 << 31), Some(9), "a signal wakes the receiver");
        assert_eq!(e.take_notifications(), 1 << 31);
        assert_eq!(e.take_notifications(), 0, "cleared");
    }

    #[test]
    fn a_waiting_receiver_gets_the_message_at_once() {
        let e = Endpoint::new();
        assert!(e.take(7).is_none(), "nothing sent: receiver 7 waits");
        let (receiver, m) = e.offer(1, message(b'x')).unwrap();
        assert_eq!((receiver, m.bytes()), (7, &b"x"[..]));
        assert_eq!(e.waiting(), (0, 0));
    }

    #[test]
    fn senders_queue_in_order() {
        let e = Endpoint::new();
        for (sender, byte) in [(1, b'a'), (2, b'b'), (3, b'c')] {
            assert!(e.offer(sender, message(byte)).is_none());
        }
        assert_eq!(e.waiting(), (3, 0));
        let order: Vec<_> = (0..3)
            .map(|_| {
                let (sender, m) = sender_of(e.take(9));
                (sender, m.bytes()[0])
            })
            .collect();
        assert_eq!(order, [(1, b'a'), (2, b'b'), (3, b'c')]);
        assert_eq!(e.waiting(), (0, 0));
    }

    #[test]
    fn offer_now_never_queues_a_sender() {
        let e = Endpoint::new();
        assert!(e.offer_now(message(b'x')).is_none(), "nobody waiting");
        assert_eq!(e.waiting(), (0, 0));
        assert!(e.is_idle());
        assert!(e.take(6).is_none());
        assert_eq!(e.offer_now(message(b'y')).map(|(r, _)| r), Some(6));
        assert!(e.offer(1, message(b'z')).is_none());
        assert!(!e.is_idle(), "a sender waits");
        let f = Endpoint::new();
        f.signal(1);
        assert!(!f.is_idle(), "a notification is pending");
    }

    #[test]
    fn try_take_never_queues_a_receiver() {
        let e = Endpoint::new();
        assert!(e.try_take().is_none());
        assert_eq!(e.waiting(), (0, 0), "no receiver queued");
        assert!(e.offer(4, message(b'r')).is_none());
        assert_eq!(
            e.try_take().map(|(s, m)| (s, m.bytes()[0])),
            Some((4, b'r'))
        );
    }

    #[test]
    fn timed_out_waiters_leave_their_queue_only_if_still_there() {
        let e = Endpoint::new();
        assert!(e.take(4).is_none());
        assert!(e.take(5).is_none());
        assert!(e.remove_receiver(4));
        assert!(!e.remove_receiver(4), "gone already");
        assert_eq!(e.offer(1, message(1)).unwrap().0, 5, "5 keeps its place");
        assert!(e.offer(2, message(b'a')).is_none());
        assert!(e.offer(3, message(b'b')).is_none());
        assert_eq!(e.remove_sender(2).map(|m| m.bytes()[0]), Some(b'a'));
        assert!(e.remove_sender(2).is_none(), "withdrawn once");
        assert_eq!(sender_of(e.take(9)).0, 3);
        assert!(e.remove_sender(3).is_none(), "taken by a receiver first");
    }

    #[test]
    fn receivers_queue_in_order() {
        let e = Endpoint::new();
        assert!(e.take(4).is_none());
        assert!(e.take(5).is_none());
        assert_eq!(e.offer(1, message(1)).unwrap().0, 4);
        assert_eq!(e.offer(1, message(2)).unwrap().0, 5);
    }
}
