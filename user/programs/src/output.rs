//! The trusted console's output lines (`trust`, agents.md): each line is
//! built from parts into one transmit buffer, its `\r\n` always kept.

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
}
