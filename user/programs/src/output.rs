//! The trusted console's output lines (`trust`, agents.md): each line is
//! built from parts into one transmit buffer, its `\r\n` always kept, and
//! `stop all`'s last line says what it did not stop.

/// Copies `parts` into `out`, cut so that `\r\n` still fits, and appends
/// it (#226): a cut line never runs into the next one. Returns the length.
/// `out` must hold at least 2 bytes.
pub fn line(parts: &[&[u8]], out: &mut [u8]) -> usize {
    let room = out.len().saturating_sub(2);
    let mut n = 0;
    for p in parts {
        let take = p.len().min(room - n);
        out[n..n + take].copy_from_slice(&p[..take]);
        n += take;
    }
    out[n..n + 2].copy_from_slice(b"\r\n");
    n + 2
}

/// `stop all`'s last line (#227) as a start, the number of processes
/// still running if any, and an end: `stopped all` only when `trust` held
/// the runtime's capability and every stop ended.
pub fn stop_all(held: bool, running: usize) -> (&'static [u8], Option<usize>, &'static [u8]) {
    match (held, running) {
        (true, 0) => (b"stopped all", None, b""),
        (true, n) => (b"stop all: ", Some(n), b" still running"),
        (false, 0) => (
            b"stop all: no runtime capability held; every registered agent stopped",
            None,
            b"",
        ),
        (false, n) => (
            b"stop all: no runtime capability held; ",
            Some(n),
            b" still running",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_line_keeps_its_terminator() {
        let mut out = [0u8; 256];
        let n = line(&[b"stopped ", b"worker"], &mut out);
        assert_eq!(&out[..n], b"stopped worker\r\n");
        // Exactly full, then one byte over, then far over in several parts.
        let full = [b'a'; 254];
        assert_eq!(line(&[&full], &mut out), 256);
        assert_eq!(&out[252..], b"aa\r\n");
        let over = [b'b'; 255];
        let n = line(&[&over], &mut out);
        assert_eq!((n, &out[252..]), (256, &b"bb\r\n"[..]), "cut, terminated");
        let name = [b'c'; 32];
        let parts: [&[u8]; 9] = [
            b"service ",
            &name,
            b"; used by ",
            &name,
            b", ",
            &name,
            b", ",
            &name,
            b", ",
        ];
        let mut many = parts.to_vec();
        many.extend_from_slice(&[&name[..], b", ", &name, b", ", &name, b", ", &name]);
        let n = line(&many, &mut out);
        assert_eq!(
            (n, &out[254..]),
            (256, &b"\r\n"[..]),
            "many parts, terminated"
        );
        assert_eq!(line(&[], &mut out), 2, "an empty line");
        assert_eq!(&out[..2], b"\r\n");
    }

    #[test]
    fn stop_all_says_what_it_did_not_stop() {
        assert_eq!(stop_all(true, 0), (&b"stopped all"[..], None, &b""[..]));
        assert_eq!(
            stop_all(true, 2),
            (&b"stop all: "[..], Some(2), &b" still running"[..])
        );
        let (start, n, _) = stop_all(false, 0);
        assert!(start.starts_with(b"stop all: no runtime capability held") && n.is_none());
        let (start, n, end) = stop_all(false, 1);
        assert_eq!(
            (start, n, end),
            (
                &b"stop all: no runtime capability held; "[..],
                Some(1),
                &b" still running"[..]
            )
        );
    }
}
