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
//! Everything here runs inside system calls, with interrupts disabled from
//! queueing to blocking, so a wake cannot be missed. No lock is held while
//! a thread blocks.

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

    /// The receive half: if a sender waits, returns it with its message
    /// (the sender is then woken); otherwise queues `receiver` and returns
    /// `None` (the receiver then blocks).
    pub fn take(&self, receiver: TaskId) -> Option<(TaskId, Message)> {
        let mut queues = self.queues.lock();
        let first = queues.senders.pop_front();
        if first.is_none() {
            queues.receivers.push_back(receiver);
        }
        first
    }

    /// Threads waiting, `(senders, receivers)`.
    pub fn waiting(&self) -> (usize, usize) {
        let queues = self.queues.lock();
        (queues.senders.len(), queues.receivers.len())
    }
}

#[cfg(target_os = "none")]
pub use kernel::{receive, send};

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

    /// Receives the next message on `endpoint` for the running thread,
    /// waiting if none is there.
    pub fn receive(endpoint: &Endpoint) -> Option<Message> {
        let me = sched::current_id().unwrap_or(0);
        match endpoint.take(me) {
            Some((sender, message)) => {
                sched::wake(sender);
                Some(message)
            }
            None => {
                // A sender puts the message in our inbox, then wakes us.
                sched::block_current();
                process::current()?.inbox.lock().take()
            }
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
        }
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
                let (sender, m) = e.take(9).unwrap();
                (sender, m.bytes()[0])
            })
            .collect();
        assert_eq!(order, [(1, b'a'), (2, b'b'), (3, b'c')]);
        assert_eq!(e.waiting(), (0, 0));
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
