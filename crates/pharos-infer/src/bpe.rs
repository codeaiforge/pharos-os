//! Qwen2's tokenizer (#84, inference.md): GPT-2 byte-level BPE with
//! Qwen2's pre-tokenizer, read from a GGUF file's `tokenizer.ggml.*`
//! metadata.
//!
//! Text becomes tokens in three steps, as llama.cpp does:
//! 1. **Special tokens** (control and user-defined, token types 3 and 4)
//!    are matched as whole strings, longest first, and split the text.
//! 2. **Pre-tokenizing** splits each remaining fragment into pieces with
//!    Qwen2's pattern
//!    `(?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+`,
//!    implemented by hand ([`pieces`]) with the Unicode tables in
//!    [`crate::unicode`].
//! 3. **BPE:** each piece's bytes start as single-byte tokens and are
//!    merged by rank, lowest first (leftmost among equals), with a heap,
//!    so a long piece costs O(n log n), not O(n²).
//!
//! The vocabulary and merges are untrusted input: every merge must name
//! two tokens whose concatenation is a token, every byte must have a token,
//! and no input makes the tokenizer panic (fuzzed in the tests).

use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Reverse;

use crate::Error;
use crate::gguf::Gguf;
use crate::unicode::{LETTERS, NUMBERS};

/// Token types (llama.cpp's `tokenizer.ggml.token_type`).
const CONTROL: i128 = 3;
const USER_DEFINED: i128 = 4;

/// Largest vocabulary or merge list accepted (Qwen2: 151,936 and 151,387).
const MAX_ENTRIES: usize = 1 << 20;

pub struct Tokenizer<'a> {
    /// Token strings (byte-level encoded), sorted, with their IDs.
    vocab: Vec<(&'a [u8], u32)>,
    /// `(left, right) → (rank, merged)`, sorted by pair.
    merges: Vec<((u32, u32), (u32, u32))>,
    /// The token for each byte.
    bytes: [u32; 256],
    /// Special tokens' text and IDs, longest first.
    special: Vec<(&'a [u8], u32)>,
}

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let c = c as u32;
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                core::cmp::Ordering::Less
            } else if lo > c {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn is_letter(c: char) -> bool {
    in_table(&LETTERS, c)
}

fn is_number(c: char) -> bool {
    in_table(&NUMBERS, c)
}

fn is_newline(c: char) -> bool {
    c == '\r' || c == '\n'
}

/// Neither whitespace, letter, nor number (`[^\s\p{L}\p{N}]`).
fn is_other(c: char) -> bool {
    !c.is_whitespace() && !is_letter(c) && !is_number(c)
}

/// The GPT-2 byte-level character for byte `b`, UTF-8 encoded into `out`
/// (inverse of `qwen2::decode_byte_level`).
pub(crate) fn byte_char(b: u8, out: &mut [u8; 4]) -> &[u8] {
    let printable = matches!(b, 0x21..=0x7e | 0xa1..=0xac | 0xae..=0xff);
    let c = if printable {
        u32::from(b)
    } else {
        // The non-printable bytes, in increasing order, from U+0100.
        let rank = (0..b)
            .filter(|&x| !matches!(x, 0x21..=0x7e | 0xa1..=0xac | 0xae..=0xff))
            .count();
        0x100 + rank as u32
    };
    char::from_u32(c).map_or(&[][..], |ch| ch.encode_utf8(out).as_bytes())
}

/// Qwen2's pre-tokenizer: the byte ranges of `text`'s pieces, in order,
/// covering all of it.
pub fn pieces(text: &str) -> Vec<(usize, usize)> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let n = chars.len();
    let at = |i: usize| chars.get(i).map(|&(_, c)| c);
    let offset = |i: usize| chars.get(i).map_or(text.len(), |&(o, _)| o);
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = chars[i].1;
        let end = 'm: {
            // 's 't 're 've 'm 'll 'd (any case)
            if c == '\'' {
                let lower = |k: usize| at(i + k).map(|c| c.to_ascii_lowercase());
                match (lower(1), lower(2)) {
                    (Some('s' | 't' | 'm' | 'd'), _) => break 'm i + 2,
                    (Some('r'), Some('e')) | (Some('v'), Some('e')) | (Some('l'), Some('l')) => {
                        break 'm i + 3;
                    }
                    _ => {}
                }
            }
            // [^\r\n\p{L}\p{N}]?\p{L}+
            let first = if is_letter(c) {
                Some(i)
            } else if !is_newline(c) && !is_number(c) && at(i + 1).is_some_and(is_letter) {
                Some(i + 1)
            } else {
                None
            };
            if let Some(mut j) = first {
                while at(j).is_some_and(is_letter) {
                    j += 1;
                }
                break 'm j;
            }
            // \p{N}
            if is_number(c) {
                break 'm i + 1;
            }
            //  ?[^\s\p{L}\p{N}]+[\r\n]*
            let k = if c == ' ' && at(i + 1).is_some_and(is_other) {
                i + 1
            } else {
                i
            };
            if at(k).is_some_and(is_other) {
                let mut j = k;
                while at(j).is_some_and(is_other) {
                    j += 1;
                }
                while at(j).is_some_and(is_newline) {
                    j += 1;
                }
                break 'm j;
            }
            // Whitespace: \s*[\r\n]+ | \s+(?!\S) | \s+
            let mut e = i;
            while at(e).is_some_and(char::is_whitespace) {
                e += 1;
            }
            if let Some(last) = (i..e).rev().find(|&j| is_newline(chars[j].1)) {
                break 'm last + 1;
            }
            if e == n || e - i == 1 {
                break 'm e;
            }
            e - 1
        };
        out.push((offset(i), offset(end)));
        i = end;
    }
    out
}

impl<'a> Tokenizer<'a> {
    /// Reads the vocabulary, token types, and merges of a GGUF file.
    pub fn from_gguf(g: &Gguf<'a>) -> Result<Self, Error> {
        let tokens = g.strings(b"tokenizer.ggml.tokens")?;
        let types = g.ints(b"tokenizer.ggml.token_type")?;
        let merges = g.strings(b"tokenizer.ggml.merges")?;
        Self::new(&tokens, &types, &merges)
    }

    /// From the token strings, their types, and the merges as `"left
    /// right"` strings in rank order.
    pub fn new(tokens: &[&'a [u8]], types: &[i128], merges: &[&[u8]]) -> Result<Self, Error> {
        if tokens.is_empty()
            || tokens.len() > MAX_ENTRIES
            || merges.len() > MAX_ENTRIES
            || types.len() != tokens.len()
        {
            return Err(Error::BadTokenizer);
        }
        let mut vocab: Vec<(&[u8], u32)> =
            tokens.iter().zip(0u32..).map(|(&t, i)| (t, i)).collect();
        vocab.sort_unstable();
        if vocab.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::BadTokenizer); // duplicate token strings
        }
        let find = |s: &[u8]| -> Option<u32> {
            vocab
                .binary_search_by(|&(t, _)| t.cmp(s))
                .ok()
                .map(|k| vocab[k].1)
        };
        let mut bytes = [0u32; 256];
        for (b, slot) in bytes.iter_mut().enumerate() {
            let mut buf = [0u8; 4];
            *slot = find(byte_char(b as u8, &mut buf)).ok_or(Error::BadTokenizer)?;
        }
        let mut pairs = Vec::with_capacity(merges.len());
        let mut joined = Vec::new();
        for (rank, m) in (0u32..).zip(merges) {
            let space = m
                .iter()
                .position(|&b| b == b' ')
                .ok_or(Error::BadTokenizer)?;
            let (l, r) = (&m[..space], &m[space + 1..]);
            joined.clear();
            joined.extend_from_slice(l);
            joined.extend_from_slice(r);
            let (Some(l), Some(r), Some(merged)) = (find(l), find(r), find(&joined)) else {
                return Err(Error::BadTokenizer);
            };
            pairs.push(((l, r), (rank, merged)));
        }
        pairs.sort_unstable();
        // A pair listed twice keeps its lowest rank, as llama.cpp does.
        pairs.dedup_by_key(|p| p.0);
        let mut special: Vec<(&[u8], u32)> = tokens
            .iter()
            .zip(types)
            .zip(0u32..)
            // Valid UTF-8 only, so splitting a `str` at one keeps every
            // fragment on character boundaries.
            .filter(|((t, ty), _)| {
                matches!(**ty, CONTROL | USER_DEFINED)
                    && !t.is_empty()
                    && core::str::from_utf8(t).is_ok()
            })
            .map(|((t, _), i)| (*t, i))
            .collect();
        special.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.1.cmp(&b.1)));
        Ok(Self {
            vocab,
            merges: pairs,
            bytes,
            special,
        })
    }

    /// The tokens of `text`, with special tokens recognized.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        // (start, end, special token) fragments of `text`, in order.
        let mut parts: Vec<(usize, usize, Option<u32>)> = alloc::vec![(0, text.len(), None)];
        for &(s, id) in &self.special {
            let mut next = Vec::with_capacity(parts.len());
            for &(a, b, sp) in &parts {
                if sp.is_some() {
                    next.push((a, b, sp));
                    continue;
                }
                let raw = &text.as_bytes()[a..b];
                let mut from = 0;
                while let Some(k) = find_bytes(&raw[from..], s) {
                    let start = from + k;
                    if start > from {
                        next.push((a + from, a + start, None));
                    }
                    next.push((a + start, a + start + s.len(), Some(id)));
                    from = start + s.len();
                }
                if from < raw.len() {
                    next.push((a + from, b, None));
                }
            }
            parts = next;
        }
        let mut out = Vec::new();
        for (a, b, sp) in parts {
            match sp {
                Some(id) => out.push(id),
                None => {
                    let fragment = text.get(a..b).unwrap_or("");
                    for (p, q) in pieces(fragment) {
                        self.bpe(&fragment.as_bytes()[p..q], &mut out);
                    }
                }
            }
        }
        out
    }

    fn rank(&self, l: u32, r: u32) -> Option<(u32, u32)> {
        self.merges
            .binary_search_by(|p| p.0.cmp(&(l, r)))
            .ok()
            .map(|k| self.merges[k].1)
    }

    /// Byte-level BPE of one piece, appended to `out`.
    fn bpe(&self, piece: &[u8], out: &mut Vec<u32>) {
        const NONE: usize = usize::MAX;
        // Symbols as a linked list: (token, prev, next); token u32::MAX
        // once merged away.
        let mut sym: Vec<(u32, usize, usize)> = piece
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let prev = if i == 0 { NONE } else { i - 1 };
                let next = if i + 1 == piece.len() { NONE } else { i + 1 };
                (self.bytes[usize::from(b)], prev, next)
            })
            .collect();
        // (rank, left position, left token, right token, merged)
        let mut heap = BinaryHeap::new();
        let push = |heap: &mut BinaryHeap<_>, sym: &[(u32, usize, usize)], i: usize| {
            let j = sym[i].2;
            if j != NONE {
                if let Some((rank, merged)) = self.rank(sym[i].0, sym[j].0) {
                    heap.push(Reverse((rank, i, sym[i].0, sym[j].0, merged)));
                }
            }
        };
        for i in 0..sym.len() {
            push(&mut heap, &sym, i);
        }
        while let Some(Reverse((_, i, l, r, merged))) = heap.pop() {
            let j = sym[i].2;
            // Stale: either side changed since this entry was pushed.
            if sym[i].0 != l || j == NONE || sym[j].0 != r {
                continue;
            }
            sym[i].0 = merged;
            sym[i].2 = sym[j].2;
            if sym[j].2 != NONE {
                let k = sym[j].2;
                sym[k].1 = i;
            }
            sym[j].0 = u32::MAX;
            if sym[i].1 != NONE {
                push(&mut heap, &sym, sym[i].1);
            }
            push(&mut heap, &sym, i);
        }
        let mut i = if sym.is_empty() { NONE } else { 0 };
        while i != NONE {
            out.push(sym[i].0);
            i = sym[i].2;
        }
    }

    /// The token ID of a token string (byte-level encoded), if any.
    pub fn id(&self, token: &[u8]) -> Option<u32> {
        self.vocab
            .binary_search_by(|&(t, _)| t.cmp(token))
            .ok()
            .map(|k| self.vocab[k].1)
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
