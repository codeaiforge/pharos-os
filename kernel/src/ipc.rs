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

/// What a receive got: a message, or pending notification bits.
// Returned once and consumed at once; boxing would allocate per message.
#[allow(clippy::large_enum_variant)]
pub enum Received {
    Message(Message),
    Notification(u32),
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
pub use kernel::{notify, poll, receive, send};

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::{process, sched};

    /// Sends `message` on `endpoint` from the running thread; returns once
    /// a receiver has it.
    pub fn send(endpoint: &Endpoint, message: Message) {
        let me = sched::current_id().unwrap_or(0);
        match endpoint.offer(me, message) {
            Some((receiver, message)) => {
                if let Some(process) = process::by_id(receiver) {
                    *process.inbox.lock() = Some(message);
                }
                sched::wake(receiver);
            }
            // The receiver that takes the message wakes us.
            None => sched::block_current(),
        }
    }

    /// Receives the next event on `endpoint` for the running thread:
    /// pending notification bits, else a message, waiting if neither is
    /// there.
    pub fn receive(endpoint: &Endpoint) -> Option<Received> {
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
                sched::block_current();
                if let Some(message) = process::current()?.inbox.lock().take() {
                    return Some(Received::Message(message));
                }
                Some(Received::Notification(endpoint.take_notifications()))
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
    fn receivers_queue_in_order() {
        let e = Endpoint::new();
        assert!(e.take(4).is_none());
        assert!(e.take(5).is_none());
        assert_eq!(e.offer(1, message(1)).unwrap().0, 4);
        assert_eq!(e.offer(1, message(2)).unwrap().0, 5);
    }
}
