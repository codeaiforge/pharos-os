//! Agent permissions (capabilities.md, D-012): what the agent runtime
//! grants an agent per task attempt, on the wire and as typed on the
//! trusted console. A permission is checked by the runtime; the agent holds
//! no kernel capability for it.

use crate::{Reader, Writer};

/// Highest model number (as in manifests).
pub const MAX_MODEL: u8 = 31;
/// Longest file name in a `file` permission (#127).
pub const MAX_FILE: usize = 32;
/// Most bytes on the wire: a kind and six bytes of value, or for a kind
/// that names something (`file`, `channel`, `knowledge`) a kind, a length,
/// and the name.
pub const WIRE: usize = 2 + MAX_FILE;
/// Bytes on the wire of every kind but `file`.
const FIXED: usize = 7;
/// Longest typed form (`knowledge write ` and a scope).
pub const TEXT: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Inference with manifest model `n` (1 to [`MAX_MODEL`]).
    Model(u8),
    /// Reading the agent's own files.
    DataRead,
    /// Writing them; includes reading.
    DataWrite,
    /// UDP datagrams to one IPv4 destination and its replies (port 1 or
    /// above).
    Net {
        addr: [u8; 4],
        port: u16,
    },
    /// Reading one file the user gives agents, in the store's `files`
    /// namespace (#127, tools.md); made with [`Permission::file`], so the
    /// name is valid and the unused bytes zero.
    File {
        name: [u8; MAX_FILE],
        len: u8,
    },
    /// Sending messages to one named agent (#133, coordination.md); made
    /// with [`Permission::channel`].
    Channel {
        name: [u8; MAX_FILE],
        len: u8,
    },
    /// Reading one knowledge scope (#144, knowledge.md); made with
    /// [`Permission::knowledge`]. Writing does not include it.
    KnowledgeRead {
        name: [u8; MAX_FILE],
        len: u8,
    },
    KnowledgeWrite {
        name: [u8; MAX_FILE],
        len: u8,
    },
    /// Proposing a system update (#165, boot.md section 8): copying one of
    /// the agent's own files to `system/incoming`, where only the user's
    /// `apply` on the trusted console can make it run.
    UpdatePropose,
}

/// A file name: 1 to [`MAX_FILE`] letters, digits, `-`, `_`, or `.`, not
/// starting with `.`. No `/`, so no name leaves its namespace.
pub fn valid_file(name: &[u8]) -> bool {
    (1..=MAX_FILE).contains(&name.len())
        && name[0] != b'.'
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
}

mod kind {
    pub const MODEL: u8 = 1;
    pub const DATA_READ: u8 = 2;
    pub const DATA_WRITE: u8 = 3;
    pub const NET: u8 = 4;
    pub const FILE: u8 = 5;
    pub const CHANNEL: u8 = 6;
    pub const KNOWLEDGE_READ: u8 = 7;
    pub const KNOWLEDGE_WRITE: u8 = 8;
    pub const UPDATE_PROPOSE: u8 = 9;
}

/// A name of agent-name rules, at most [`MAX_FILE`] bytes, zero-padded.
fn padded(name: &[u8]) -> Option<([u8; MAX_FILE], u8)> {
    if !crate::trust::valid_name(name) || name.len() > MAX_FILE {
        return None;
    }
    let mut n = [0u8; MAX_FILE];
    n[..name.len()].copy_from_slice(name);
    Some((n, name.len() as u8))
}

impl Permission {
    /// `file <name>`; `None` if `name` is not a valid file name.
    pub fn file(name: &[u8]) -> Option<Self> {
        if !valid_file(name) {
            return None;
        }
        let mut n = [0u8; MAX_FILE];
        n[..name.len()].copy_from_slice(name);
        Some(Self::File {
            name: n,
            len: name.len() as u8,
        })
    }

    /// The file a `file` permission names.
    pub fn file_name(&self) -> Option<&[u8]> {
        match self {
            Self::File { name, len } => name.get(..usize::from(*len)),
            _ => None,
        }
    }

    /// `channel <agent>`; `None` if `agent` is not a valid agent name.
    pub fn channel(agent: &[u8]) -> Option<Self> {
        let (name, len) = padded(agent)?;
        Some(Self::Channel { name, len })
    }

    /// `knowledge read <scope>`, or `knowledge write <scope>` if `write`;
    /// `None` if `scope` is not a valid agent name.
    pub fn knowledge(scope: &[u8], write: bool) -> Option<Self> {
        let (name, len) = padded(scope)?;
        Some(if write {
            Self::KnowledgeWrite { name, len }
        } else {
            Self::KnowledgeRead { name, len }
        })
    }

    /// The scope a `knowledge` permission names, and whether it writes.
    pub fn knowledge_scope(&self) -> Option<(&[u8], bool)> {
        match self {
            Self::KnowledgeRead { name, len } => Some((name.get(..usize::from(*len))?, false)),
            Self::KnowledgeWrite { name, len } => Some((name.get(..usize::from(*len))?, true)),
            _ => None,
        }
    }

    /// The agent a `channel` permission names.
    pub fn channel_to(&self) -> Option<&[u8]> {
        match self {
            Self::Channel { name, len } => name.get(..usize::from(*len)),
            _ => None,
        }
    }

    /// A name and its kind byte, for the kinds that carry one.
    fn name(&self) -> Option<(u8, &[u8])> {
        match self {
            Self::File { .. } => Some((kind::FILE, self.file_name()?)),
            Self::Channel { .. } => Some((kind::CHANNEL, self.channel_to()?)),
            Self::KnowledgeRead { .. } => Some((kind::KNOWLEDGE_READ, self.knowledge_scope()?.0)),
            Self::KnowledgeWrite { .. } => Some((kind::KNOWLEDGE_WRITE, self.knowledge_scope()?.0)),
            _ => None,
        }
    }

    /// True if holding `self` allows what `wanted` needs.
    pub fn covers(&self, wanted: &Self) -> bool {
        self == wanted || (*self == Self::DataWrite && *wanted == Self::DataRead)
    }

    fn valid(&self) -> bool {
        match *self {
            Self::Model(n) => (1..=MAX_MODEL).contains(&n),
            Self::Net { port, .. } => port != 0,
            Self::DataRead | Self::DataWrite | Self::UpdatePropose => true,
            Self::File { name, len } => {
                let n = usize::from(len);
                n <= MAX_FILE && valid_file(&name[..n]) && name[n..].iter().all(|b| *b == 0)
            }
            Self::Channel { name, len }
            | Self::KnowledgeRead { name, len }
            | Self::KnowledgeWrite { name, len } => {
                let n = usize::from(len);
                n <= MAX_FILE
                    && crate::trust::valid_name(&name[..n])
                    && name[n..].iter().all(|b| *b == 0)
            }
        }
    }

    /// Writes 7 bytes, or a `file` permission's 2 and its name; `None` if
    /// invalid or out of room.
    pub fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        if !self.valid() {
            return None;
        }
        if let Some((k, name)) = self.name() {
            w.bytes(&[k, name.len() as u8])?;
            return w.bytes(name);
        }
        let mut b = [0u8; FIXED];
        match *self {
            Self::Model(n) => b[..2].copy_from_slice(&[kind::MODEL, n]),
            Self::DataRead => b[0] = kind::DATA_READ,
            Self::DataWrite => b[0] = kind::DATA_WRITE,
            Self::UpdatePropose => b[0] = kind::UPDATE_PROPOSE,
            Self::Net { addr, port } => {
                b[0] = kind::NET;
                b[1..5].copy_from_slice(&addr);
                b[5..].copy_from_slice(&port.to_le_bytes());
            }
            Self::File { .. }
            | Self::Channel { .. }
            | Self::KnowledgeRead { .. }
            | Self::KnowledgeWrite { .. } => return None,
        }
        w.bytes(&b)
    }

    /// Reads what [`Permission::write`] wrote; unused bytes must be zero.
    pub fn read(r: &mut Reader<'_>) -> Option<Self> {
        if let Some(k @ kind::FILE..=kind::KNOWLEDGE_WRITE) = r.peek() {
            r.u8()?;
            let n = usize::from(r.u8()?);
            let name = r.take(n)?;
            return match k {
                kind::FILE => Self::file(name),
                kind::CHANNEL => Self::channel(name),
                _ => Self::knowledge(name, k == kind::KNOWLEDGE_WRITE),
            };
        }
        let b = r.take(FIXED)?;
        let zero = |from: usize| b[from..].iter().all(|x| *x == 0);
        let p = match b[0] {
            kind::MODEL if zero(2) => Self::Model(b[1]),
            kind::DATA_READ if zero(1) => Self::DataRead,
            kind::DATA_WRITE if zero(1) => Self::DataWrite,
            kind::UPDATE_PROPOSE if zero(1) => Self::UpdatePropose,
            kind::NET => Self::Net {
                addr: [b[1], b[2], b[3], b[4]],
                port: u16::from_le_bytes([b[5], b[6]]),
            },
            _ => return None,
        };
        p.valid().then_some(p)
    }

    /// Parses the typed form: `model <n>`, `data read`, `data write`,
    /// `update propose`, `net <a.b.c.d>:<port>`, `file <name>`, `channel <agent>`, or
    /// `knowledge read <scope>` or `knowledge write <scope>`.
    pub fn parse(words: &[&[u8]]) -> Option<Self> {
        let p = match words {
            [b"model", n] => Self::Model(u8::try_from(number(n, u32::from(MAX_MODEL))?).ok()?),
            [b"data", b"read"] => Self::DataRead,
            [b"data", b"write"] => Self::DataWrite,
            [b"update", b"propose"] => Self::UpdatePropose,
            [b"file", name] => Self::file(name)?,
            [b"channel", agent] => Self::channel(agent)?,
            [b"knowledge", b"read", scope] => Self::knowledge(scope, false)?,
            [b"knowledge", b"write", scope] => Self::knowledge(scope, true)?,
            [b"net", dest] => {
                let colon = dest.iter().position(|b| *b == b':')?;
                let mut addr = [0u8; 4];
                let mut parts = dest[..colon].split(|b| *b == b'.');
                for a in &mut addr {
                    *a = u8::try_from(zero_or_number(parts.next()?, 255)?).ok()?;
                }
                if parts.next().is_some() {
                    return None;
                }
                let port = u16::try_from(number(&dest[colon + 1..], 65_535)?).ok()?;
                Self::Net { addr, port }
            }
            _ => return None,
        };
        p.valid().then_some(p)
    }

    /// The typed form, into `out`.
    pub fn text<'o>(&self, out: &'o mut [u8; TEXT]) -> &'o [u8] {
        let mut w = Writer::new(out);
        let _ = match *self {
            Self::Model(n) => w.bytes(b"model ").and_then(|()| decimal(&mut w, n.into())),
            Self::DataRead => w.bytes(b"data read"),
            Self::DataWrite => w.bytes(b"data write"),
            Self::UpdatePropose => w.bytes(b"update propose"),
            Self::File { .. } => w.bytes(b"file ").and_then(|()| w.bytes(self.file_name()?)),
            Self::Channel { .. } => w
                .bytes(b"channel ")
                .and_then(|()| w.bytes(self.channel_to()?)),
            Self::KnowledgeRead { .. } | Self::KnowledgeWrite { .. } => (|| {
                let (scope, write) = self.knowledge_scope()?;
                w.bytes(if write {
                    b"knowledge write "
                } else {
                    b"knowledge read "
                })?;
                w.bytes(scope)
            })(),
            Self::Net { addr, port } => (|| {
                w.bytes(b"net ")?;
                for (i, a) in addr.iter().enumerate() {
                    if i > 0 {
                        w.bytes(b".")?;
                    }
                    decimal(&mut w, (*a).into())?;
                }
                w.bytes(b":")?;
                decimal(&mut w, port.into())
            })(),
        };
        let n = w.len();
        &out[..n]
    }
}

/// A decimal from 1 to `max`, digits only, no leading zero.
fn number(v: &[u8], max: u32) -> Option<u32> {
    if v.first() == Some(&b'0') {
        return None;
    }
    zero_or_number(v, max).filter(|n| *n > 0)
}

/// A decimal from 0 to `max`: `0`, or digits without a leading zero.
fn zero_or_number(v: &[u8], max: u32) -> Option<u32> {
    if v.is_empty() || v.len() > 5 || (v.len() > 1 && v[0] == b'0') {
        return None;
    }
    let mut n = 0u32;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u32::from(b - b'0');
    }
    (n <= max).then_some(n)
}

fn decimal(w: &mut Writer<'_>, mut n: u32) -> Option<()> {
    let mut d = [0u8; 10];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return w.bytes(&d[i..]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Permission; 10] = [
        Permission::Model(1),
        Permission::Model(MAX_MODEL),
        Permission::DataRead,
        Permission::DataWrite,
        Permission::Net {
            addr: [10, 0, 2, 2],
            port: 47_000,
        },
        Permission::File {
            name: *b"report.txt\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            len: 10,
        },
        Permission::Channel {
            name: *b"listener\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            len: 8,
        },
        Permission::KnowledgeRead {
            name: *b"notes\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            len: 5,
        },
        Permission::KnowledgeWrite {
            name: *b"notes\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            len: 5,
        },
        Permission::UpdatePropose,
    ];

    fn words(s: &str) -> std::vec::Vec<&[u8]> {
        s.split(' ').map(str::as_bytes).collect()
    }

    #[test]
    fn round_trips_on_the_wire_and_as_text() {
        for p in ALL {
            let mut buf = [0u8; WIRE];
            let mut w = Writer::new(&mut buf);
            p.write(&mut w).unwrap();
            let n = w.len();
            assert_eq!(Permission::read(&mut Reader::new(&buf[..n])), Some(p));
            for cut in 0..n {
                assert_eq!(
                    Permission::read(&mut Reader::new(&buf[..cut])),
                    None,
                    "{p:?}"
                );
            }
            let mut t = [0u8; TEXT];
            let text = std::string::String::from(std::str::from_utf8(p.text(&mut t)).unwrap());
            assert_eq!(Permission::parse(&words(&text)), Some(p), "{text}");
        }
        let mut t = [0u8; TEXT];
        assert_eq!(ALL[4].text(&mut t), b"net 10.0.2.2:47000");
        assert_eq!(ALL[5].text(&mut t), b"file report.txt");
        assert_eq!(Permission::file(b"report.txt"), Some(ALL[5]));
        assert_eq!(ALL[5].file_name(), Some(&b"report.txt"[..]));
        let long = [b'a'; MAX_FILE];
        let p = Permission::file(&long).unwrap();
        assert_eq!(p.text(&mut t).len(), 5 + MAX_FILE);
        assert_eq!(ALL[6].text(&mut t), b"channel listener");
        assert_eq!(Permission::channel(b"listener"), Some(ALL[6]));
        assert_eq!(ALL[6].channel_to(), Some(&b"listener"[..]));
        assert_eq!(ALL[6].file_name(), None, "a channel is not a file");
        let p = Permission::channel(&[b'a'; MAX_FILE]).unwrap();
        assert_eq!(p.text(&mut t).len(), 8 + MAX_FILE);
        assert!(!Permission::file(b"listener").unwrap().covers(&ALL[6]));
        assert_eq!(ALL[7].text(&mut t), b"knowledge read notes");
        assert_eq!(ALL[8].text(&mut t), b"knowledge write notes");
        assert_eq!(Permission::knowledge(b"notes", true), Some(ALL[8]));
        assert_eq!(ALL[7].knowledge_scope(), Some((&b"notes"[..], false)));
        let p = Permission::knowledge(&[b'a'; MAX_FILE], true).unwrap();
        assert_eq!(p.text(&mut t).len(), TEXT, "the longest typed form fits");
        assert!(!ALL[8].covers(&ALL[7]), "writing does not include reading");
        assert!(!ALL[7].covers(&ALL[8]));
    }

    #[test]
    fn bad_permissions_are_refused() {
        for s in [
            "model 0",
            "model 32",
            "model 02",
            "model",
            "model 1 2",
            "data",
            "data rw",
            "net 10.0.2.2:0",
            "net 10.0.2.2:65536",
            "net 10.0.2:1",
            "net 10.0.2.2.2:1",
            "net 256.0.0.1:1",
            "net 10.0.02.2:1",
            "net 10.0.2.2",
            "Model 1",
            "file",
            "file ../secrets.txt",
            "file a/b",
            "file .hidden",
            "file a b",
            "file aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "channel",
            "channel a.b",
            "channel a/b",
            "channel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "knowledge",
            "knowledge read",
            "knowledge notes",
            "knowledge append notes",
            "knowledge read a.b",
            "knowledge read a/b",
            "knowledge read notes ops",
            "knowledge write aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(Permission::parse(&words(s)), None, "{s}");
        }
        assert!(
            Permission::parse(&words("net 0.0.0.0:1")).is_some(),
            "zero octets"
        );
        assert_eq!(
            Permission::Model(0).write(&mut Writer::new(&mut [0; WIRE])),
            None
        );
        assert_eq!(ALL[9].text(&mut [0u8; TEXT]), b"update propose");
        for b in [
            [10, 0, 0, 0, 0, 0, 0],
            [9, 1, 0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0, 0, 0],
            [1, 1, 1, 0, 0, 0, 0],
            [2, 1, 0, 0, 0, 0, 0],
            [4, 1, 2, 3, 4, 0, 0],
        ] {
            assert_eq!(Permission::read(&mut Reader::new(&b)), None, "{b:?}");
        }
        for b in [
            &b"\x06\x00"[..],
            b"\x06\x02a.",
            b"\x06\x01",
            b"\x05\x00",
            b"\x05\x02a/",
            b"\x05\x02.a",
            b"\x05\x21aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"\x07\x00",
            b"\x07\x02a.",
            b"\x08\x02a/",
            b"\x08\x21aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"\x09\x01a",
        ] {
            assert_eq!(Permission::read(&mut Reader::new(b)), None, "{b:?}");
        }
        assert!(
            Permission::File {
                name: [b'a'; MAX_FILE],
                len: 0
            }
            .write(&mut Writer::new(&mut [0; WIRE]))
            .is_none()
        );
        crate::fuzz(100_000, 7, |m| {
            if let Some(p) = Permission::read(&mut Reader::new(m)) {
                assert!(p.valid());
            }
        });
        // `file` permissions: kind 5, a length up to one past the limit,
        // then name bytes, some of them not allowed.
        crate::fuzz(100_000, 255, |m| {
            let Some((len, name)) = m.split_first() else {
                return;
            };
            // Kinds 5 to 8 (`file`, `channel`, `knowledge`), by length.
            let mut msg = std::vec![5 + len % 4, len % 34];
            msg.extend(name.iter().map(|b| b"./ab0_-"[usize::from(*b) % 7]));
            if let Some(p) = Permission::read(&mut Reader::new(&msg)) {
                assert!(p.valid());
                assert!(
                    p.file_name().is_some_and(valid_file)
                        || p.channel_to().is_some_and(crate::trust::valid_name)
                        || p.knowledge_scope()
                            .is_some_and(|(s, _)| crate::trust::valid_name(s))
                );
            }
        });
    }

    #[test]
    fn write_covers_read() {
        assert!(Permission::DataWrite.covers(&Permission::DataRead));
        assert!(!Permission::DataRead.covers(&Permission::DataWrite));
        assert!(!Permission::Model(1).covers(&Permission::Model(2)));
    }
}
