//! Messages waiting for agents (#133, coordination.md): one queue per
//! receiving agent name, in the runtime's memory, whether or not the agent
//! runs. A full queue refuses the next message; nothing is dropped.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Most messages waiting for one agent.
pub const MAX_WAITING: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub from: Vec<u8>,
    pub kind: u8,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct Mailboxes {
    boxes: Vec<(Vec<u8>, VecDeque<Message>)>,
}

impl Mailboxes {
    /// True if `to` has room for one more.
    pub fn has_room(&self, to: &[u8]) -> bool {
        self.boxes
            .iter()
            .find(|(n, _)| n == to)
            .is_none_or(|(_, q)| q.len() < MAX_WAITING)
    }

    /// Queues `m` for `to`; `false` (and nothing queued) if its queue is
    /// full.
    pub fn put(&mut self, to: &[u8], m: Message) -> bool {
        if !self.has_room(to) {
            return false;
        }
        match self.boxes.iter_mut().find(|(n, _)| n == to) {
            Some((_, q)) => q.push_back(m),
            None => self.boxes.push((to.to_vec(), VecDeque::from([m]))),
        }
        true
    }

    /// The oldest message waiting for `to`.
    pub fn take(&mut self, to: &[u8]) -> Option<Message> {
        let at = self.boxes.iter().position(|(n, _)| n == to)?;
        let m = self.boxes[at].1.pop_front();
        if self.boxes[at].1.is_empty() {
            self.boxes.swap_remove(at);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(from: &str, kind: u8) -> Message {
        Message {
            from: from.as_bytes().to_vec(),
            kind,
            bytes: alloc::vec![kind; usize::from(kind)],
        }
    }

    #[test]
    fn in_order_per_receiver() {
        let mut b = Mailboxes::default();
        assert!(b.put(b"listener", m("talker", 1)));
        assert!(b.put(b"other", m("talker", 9)));
        assert!(b.put(b"listener", m("talker", 2)));
        assert_eq!(b.take(b"listener"), Some(m("talker", 1)));
        assert_eq!(b.take(b"listener"), Some(m("talker", 2)));
        assert_eq!(b.take(b"listener"), None);
        assert_eq!(b.take(b"talker"), None, "nothing for the sender");
        assert_eq!(b.take(b"other"), Some(m("talker", 9)));
    }

    #[test]
    fn a_full_queue_refuses_and_keeps_what_it_has() {
        let mut b = Mailboxes::default();
        for k in 0..MAX_WAITING as u8 {
            assert!(b.put(b"listener", m("talker", k)));
        }
        assert!(!b.has_room(b"listener"));
        assert!(!b.put(b"listener", m("talker", 99)));
        assert!(b.put(b"other", m("talker", 1)), "another queue has room");
        assert_eq!(
            b.take(b"listener"),
            Some(m("talker", 0)),
            "the oldest is kept"
        );
        assert!(b.put(b"listener", m("talker", 50)), "room again");
        let rest: Vec<u8> = core::iter::from_fn(|| b.take(b"listener"))
            .map(|m| m.kind)
            .collect();
        assert_eq!(rest, [1, 2, 3, 4, 5, 6, 7, 50]);
    }
}
