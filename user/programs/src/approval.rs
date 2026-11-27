//! Payload approval on the trusted console (#324, approval.md, D-037):
//! the approved bytes of an action, shown by `trust` itself, every byte,
//! escaped and paged; their SHA-256, whose first 8 hex digits the
//! approver types. Host-tested.

use alloc::vec::Vec;

use pharos_proto::permission::Permission;
use pharos_proto::trust::Kind;

/// Approved bytes on one line.
pub const LINE: usize = 32;
/// Lines on one page.
pub const PAGE_LINES: usize = 16;
/// Approved bytes on one page.
pub const PAGE: usize = LINE * PAGE_LINES;
/// The longest line: `| `, 4 hex digits, a space, and 32 bytes of at most
/// 4 characters each (`\xNN`).
pub const LINE_TEXT: usize = 7 + LINE * 4;
/// Every line of a payload starts so, and no line of `trust`'s own does.
pub const MARK: &[u8] = b"| ";

/// Pages `len` approved bytes take.
pub const fn pages(len: usize) -> usize {
    len.div_ceil(PAGE)
}

/// Line `index` of `bytes` (at offset `index * LINE`), written into `out`:
/// printable ASCII as itself, `\` as `\\`, every other byte as `\xNN`, so
/// no payload byte can end a line or write a control sequence.
pub fn line<'a>(bytes: &[u8], index: usize, out: &'a mut [u8; LINE_TEXT]) -> &'a [u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let at = index * LINE;
    let mut n = 0;
    let mut put = |b: u8| {
        out[n] = b;
        n += 1;
    };
    MARK.iter().for_each(|&b| put(b));
    for shift in [12, 8, 4, 0] {
        put(HEX[(at >> shift) & 15]);
    }
    put(b' ');
    for &b in bytes.get(at..).unwrap_or_default().iter().take(LINE) {
        match b {
            b'\\' => {
                put(b'\\');
                put(b'\\');
            }
            0x20..=0x7e => put(b),
            _ => [
                b'\\',
                b'x',
                HEX[usize::from(b >> 4)],
                HEX[usize::from(b & 15)],
            ]
            .into_iter()
            .for_each(&mut put),
        }
    }
    &out[..n]
}

/// The approved bytes' parts, if they are well formed for `kind`: the
/// route and the target for [`Kind::Https`] (`route ‖ 0 ‖ target ‖ 0 ‖
/// body`), or the destination and an empty target for [`Kind::Send`]
/// (`address:port ‖ 0 ‖ data`), then the body or the data, which may hold
/// any byte.
pub fn parts(kind: Kind, bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let zero = |b: &[u8]| b.iter().position(|&c| c == 0);
    let first = zero(bytes)?;
    let (head, rest) = (&bytes[..first], &bytes[first + 1..]);
    let printable = |b: &[u8]| !b.is_empty() && b.iter().all(|c| c.is_ascii_graphic());
    match kind {
        Kind::Send => printable(head).then_some((head, &[][..], rest)),
        Kind::Https => {
            let second = zero(rest)?;
            let (target, body) = (&rest[..second], &rest[second + 1..]);
            (pharos_proto::trust::valid_name(head)
                && target.first() == Some(&b'/')
                && printable(target))
            .then_some((head, target, body))
        }
    }
}

/// `send`'s approved bytes: the destination as `net` writes it
/// (`10.0.2.2:47000`), a zero byte, and the data.
pub fn send_bytes(addr: [u8; 4], port: u16, data: &[u8]) -> Vec<u8> {
    let mut t = [0u8; pharos_proto::permission::TEXT];
    let net = Permission::Net { addr, port }.text(&mut t);
    [net.strip_prefix(b"net ").unwrap_or(net), &[0], data].concat()
}

/// The digest an approval names: SHA-256 over the approved bytes.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    pharos_crypto::sha256(&[bytes])
}

/// The digest's first 4 bytes as the 8 lowercase hex digits the approver
/// types.
pub fn hex8(digest: &[u8; 32]) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    for (i, b) in digest[..4].iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 15)];
    }
    out
}

/// Why `yes <n> <hash>` approves nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotApproved {
    /// The person logged in was not shown its hash line since their login.
    NotSeen,
    /// The digits are not the digest's first 8.
    Digits,
    /// Of an ask for two: the person is its requester, the agent's owner
    /// (#326, D-037).
    Requester,
    /// Of an ask for two: the person already approved it.
    Again,
}

/// Whether `person` may be one of the `needed` approvers of an ask whose
/// requester is `owner`, after those in `by` (#326, approval.md, "Answers
/// and approvers"): for two, distinct people, neither the requester, and
/// none at all while `trust` does not know who the requester is. For one,
/// anyone logged in, the owner too.
pub fn may_approve(
    needed: u8,
    owner: Option<&[u8]>,
    by: &[&[u8]],
    person: &[u8],
) -> Result<(), NotApproved> {
    if needed < 2 {
        Ok(())
    } else if owner.is_none_or(|o| o == person) {
        Err(NotApproved::Requester)
    } else if by.contains(&person) {
        Err(NotApproved::Again)
    } else {
        Ok(())
    }
}

/// Whether a `yes <n> <hash>` approves the ask whose bytes have `digest`
/// (approval.md, "Answers and approvers").
pub fn check_yes(seen: bool, digest: &[u8; 32], hash: [u8; 4]) -> Result<(), NotApproved> {
    if !seen {
        Err(NotApproved::NotSeen)
    } else if digest[..4] != hash {
        Err(NotApproved::Digits)
    } else {
        Ok(())
    }
}

/// Whether the runtime takes `trust`'s answer as a yes: a call's yes needs
/// the digest `trust` showed, equal to the digest of the runtime's own
/// copy (`own`); a permission's (no copy) carries none.
pub fn holds(yes: bool, own: Option<[u8; 32]>, given: Option<[u8; 32]>, call: bool) -> bool {
    yes && if call {
        given.is_some() && given == own
    } else {
        given.is_none()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_yes_needs_the_hash_line_seen_and_its_digits() {
        let d = digest(b"x");
        let mut h = [0u8; 4];
        h.copy_from_slice(&d[..4]);
        assert_eq!(check_yes(true, &d, h), Ok(()));
        assert_eq!(check_yes(false, &d, h), Err(NotApproved::NotSeen));
        h[3] ^= 1;
        assert_eq!(check_yes(true, &d, h), Err(NotApproved::Digits));
    }

    #[test]
    fn two_approvers_are_two_people_neither_the_requester() {
        let owner = Some(&b"admin"[..]);
        assert_eq!(
            may_approve(1, owner, &[], b"admin"),
            Ok(()),
            "one: the owner too"
        );
        assert_eq!(
            may_approve(2, owner, &[], b"admin"),
            Err(NotApproved::Requester)
        );
        assert_eq!(may_approve(2, owner, &[], b"bob"), Ok(()));
        assert_eq!(
            may_approve(2, owner, &[b"bob"], b"bob"),
            Err(NotApproved::Again)
        );
        assert_eq!(may_approve(2, owner, &[b"bob"], b"carol"), Ok(()));
        // With the requester unknown, no one can be shown not to be it.
        assert_eq!(
            may_approve(2, None, &[], b"bob"),
            Err(NotApproved::Requester)
        );
    }

    #[test]
    fn a_calls_yes_holds_only_with_its_own_digest() {
        let (a, b) = (Some(digest(b"a")), Some(digest(b"b")));
        assert!(holds(true, a, a, true));
        assert!(!holds(true, a, b, true), "other bytes shown");
        assert!(!holds(true, a, None, true), "no digest");
        assert!(!holds(true, None, None, true), "no copy");
        assert!(!holds(false, a, a, true));
        assert!(holds(true, None, None, false));
        assert!(!holds(true, None, a, false), "a permission names no bytes");
    }

    use super::*;

    fn text(bytes: &[u8], index: usize) -> std::string::String {
        let mut out = [0u8; LINE_TEXT];
        std::string::String::from_utf8(line(bytes, index, &mut out).to_vec()).unwrap()
    }

    #[test]
    fn every_byte_is_shown_and_none_ends_a_line() {
        let all: Vec<u8> = (0..=255).collect();
        let mut shown = std::string::String::new();
        for i in 0..pages(all.len()) * PAGE_LINES {
            let l = text(&all, i);
            if i * LINE >= all.len() {
                continue;
            }
            assert!(l.starts_with("| "), "{l}");
            assert!(l.bytes().all(|c| (0x20..=0x7e).contains(&c)), "{l}");
            assert!(l.len() <= LINE_TEXT);
            shown.push_str(&l[7..]);
        }
        // Undo the escaping: every byte comes back, in order.
        let mut back = Vec::new();
        let b = shown.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match (b[i], b.get(i + 1)) {
                (b'\\', Some(b'\\')) => {
                    back.push(b'\\');
                    i += 2;
                }
                (b'\\', Some(b'x')) => {
                    let h = core::str::from_utf8(&b[i + 2..i + 4]).unwrap();
                    back.push(u8::from_str_radix(h, 16).unwrap());
                    i += 4;
                }
                (c, _) => {
                    back.push(c);
                    i += 1;
                }
            }
        }
        assert_eq!(back, all);
    }

    #[test]
    fn lines_carry_their_offset_and_the_longest_fits() {
        let bytes = [0u8; 40];
        assert_eq!(
            text(&bytes, 1),
            std::format!("| 0020 {}", "\\x00".repeat(8))
        );
        assert_eq!(text(&bytes, 0).len(), LINE_TEXT);
        assert_eq!(text(b"a\\b\n", 0), "| 0000 a\\\\b\\x0a");
        assert_eq!(text(b"a", 1), "| 0020 ");
        assert_eq!(pages(1), 1);
        assert_eq!(pages(PAGE), 1);
        assert_eq!(pages(PAGE + 1), 2);
        assert_eq!(pages(pharos_proto::trust::MAX_PAYLOAD), 8);
    }

    #[test]
    fn parts_follow_each_kind() {
        let send = send_bytes([10, 0, 2, 2], 47_000, b"a\0b");
        assert_eq!(
            parts(Kind::Send, &send),
            Some((&b"10.0.2.2:47000"[..], &b""[..], &b"a\0b"[..]))
        );
        assert_eq!(parts(Kind::Send, b"\0data"), None, "no destination");
        assert_eq!(parts(Kind::Send, b"no zero"), None);
        let https = b"issues\0/repos/a/b?x=1\0{\"t\":0}\0";
        assert_eq!(
            parts(Kind::Https, https),
            Some((&b"issues"[..], &b"/repos/a/b?x=1"[..], &b"{\"t\":0}\0"[..]))
        );
        assert_eq!(parts(Kind::Https, b"issues\0repos\0"), None, "no /");
        assert_eq!(parts(Kind::Https, b"bad route\0/x\0"), None);
        assert_eq!(parts(Kind::Https, b"issues\0/x"), None, "one zero");
    }

    #[test]
    fn the_digest_is_sha256_and_its_prefix_lowercase_hex() {
        // The design's example (approval.md, "The display").
        let b = b"issues\0/repos/acme/demo/issues\0{\"title\":\"Disk full on build-3\",\"body\":\"C:\\logs\n\"}";
        let b = &b[..];
        assert_eq!(b.len(), 81);
        assert_eq!(&hex8(&digest(b)), b"ada84318");
        assert_eq!(&hex8(&[0xff; 32]), b"ffffffff");
    }
}
