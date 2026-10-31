//! Qwen2 tokenizer tests (#84) that run without a model file: the
//! pre-tokenizer's splits, BPE merge order, special tokens, refused
//! vocabularies, the Unicode tables, and fuzzing. The comparison with
//! llama.cpp on the real vocabulary is `scripts/compare-tokenizer.py`.

use std::string::String;
use std::vec::Vec;

use crate::Error;
use crate::bpe::{Tokenizer, pieces};
use crate::unicode::{LETTERS, NUMBERS};

fn split(text: &str) -> Vec<&str> {
    pieces(text).into_iter().map(|(a, b)| &text[a..b]).collect()
}

#[test]
fn pre_tokenizer_splits_as_qwen2s_pattern() {
    let cases: &[(&str, &[&str])] = &[
        (
            "Hello world, it's 2026!",
            &[
                "Hello", " world", ",", " it", "'s", " ", "2", "0", "2", "6", "!",
            ],
        ),
        ("I'M HE'LL we'Re", &["I", "'M", " HE", "'LL", " we", "'Re"]),
        ("'x", &["'x"]),
        // A contraction ends its piece even when letters follow, in any case.
        (
            "I'Ms THEY'REx it'sy",
            &["I", "'M", "s", " THEY", "'RE", "x", " it", "'s", "y"],
        ),
        ("a  b", &["a", " ", " b"]),
        ("a   b", &["a", "  ", " b"]),
        ("x   ", &["x", "   "]),
        ("a\n\nb", &["a", "\n\n", "b"]),
        ("a \n  b", &["a", " \n", " ", " b"]),
        ("a\r\n b", &["a", "\r\n", " b"]),
        // `[^\r\n\p{L}\p{N}]?\p{L}+`: one non-letter may lead a word.
        ("(yes) --x", &["(yes", ")", " --", "x"]),
        ("a!!\n\nb", &["a", "!!\n\n", "b"]),
        ("\tword", &["\tword"]),
        ("\nword", &["\n", "word"]),
        ("3.14", &["3", ".", "1", "4"]),
        ("Ⅻ½", &["Ⅻ", "½"]),
        ("Grüße", &["Grüße"]),
        ("", &[]),
    ];
    for (text, want) in cases {
        assert_eq!(split(text), *want, "{text:?}");
    }
}

#[test]
fn pieces_cover_the_text() {
    let text = "The café's 3 crêpes — naïvely,\r\n\t10% off!  😀 हिन्दी ";
    let p = pieces(text);
    assert_eq!(p.first().map(|x| x.0), Some(0));
    assert_eq!(p.last().map(|x| x.1), Some(text.len()));
    assert!(p.windows(2).all(|w| w[0].1 == w[1].0 && w[0].0 < w[0].1));
}

#[test]
fn unicode_tables_are_sorted_and_right() {
    for t in [&LETTERS[..], &NUMBERS[..]] {
        assert!(t.iter().all(|&(a, b)| a <= b));
        assert!(t.windows(2).all(|w| w[0].1 < w[1].0), "sorted, apart");
    }
    let letter = |c| split(c).len() == 1 && !c.chars().all(|c| c.is_numeric());
    assert!(letter("a") && letter("ก") && letter("é"));
    // A Thai vowel sign (Mn) and a Roman numeral (Nl) are alphabetic to
    // Rust but not letters to Qwen2: the reason for the tables.
    assert!('\u{0e31}'.is_alphabetic() && 'Ⅻ'.is_alphabetic());
    assert_eq!(split("ก\u{0e31}"), ["ก", "\u{0e31}"]);
    assert_eq!(split("aⅫ"), ["a", "Ⅻ"]);
}

/// Every byte as a token, then `extra` tokens; `merges` as "l r".
fn tokenizer<'a>(
    storage: &'a mut Vec<Vec<u8>>,
    extra: &[(&str, i128)],
    merges: &'a [&'a [u8]],
) -> Result<Tokenizer<'a>, Error> {
    for b in 0..=255u8 {
        let printable = matches!(b, 0x21..=0x7e | 0xa1..=0xac | 0xae..=0xff);
        let rank = (0..b)
            .filter(|&x| !matches!(x, 0x21..=0x7e | 0xa1..=0xac | 0xae..=0xff))
            .count() as u32;
        let c = if printable {
            char::from(b)
        } else {
            char::from_u32(0x100 + rank).unwrap()
        };
        storage.push(String::from(c).into_bytes());
    }
    for (t, _) in extra {
        storage.push(t.as_bytes().to_vec());
    }
    let tokens: Vec<&[u8]> = storage.iter().map(Vec::as_slice).collect();
    let mut types = std::vec![1i128; 256];
    types.extend(extra.iter().map(|&(_, ty)| ty));
    let tokens: &'a [&'a [u8]] = std::boxed::Box::leak(tokens.into_boxed_slice());
    Tokenizer::new(tokens, &types, merges)
}

#[test]
fn merges_apply_lowest_rank_first_then_leftmost() {
    let mut s = Vec::new();
    let m: &[&[u8]] = &[b"b c", b"a b", b"a a", b"aa aa"];
    let t = tokenizer(&mut s, &[("bc", 1), ("ab", 1), ("aa", 1), ("aaaa", 1)], m).unwrap();
    let (a, bc, aa, aaaa) = (u32::from(b'a'), 256, 258, 259);
    // "b c" outranks "a b": a + bc, never ab + c.
    assert_eq!(t.encode("abc"), [a, bc]);
    // "aaa": the leftmost pair merges first.
    assert_eq!(t.encode("aaa"), [aa, a]);
    assert_eq!(t.encode("aaaa"), [aaaa]);
    // Each piece separately: the space splits "a a".
    // The pieces "a" and " a"; no merge for the space's byte token (32).
    assert_eq!(t.encode("a a"), [a, 32, a]);
    // A long piece is fast (heap, not quadratic): 100,000 letters.
    let long = "a".repeat(100_000);
    assert_eq!(t.encode(&long), std::vec![aaaa; 25_000]);
}

#[test]
fn special_tokens_split_the_text_longest_first() {
    let mut s = Vec::new();
    let t = tokenizer(&mut s, &[("<s>", 3), ("<s>x", 4), ("<n>", 1)], &[]).unwrap();
    let (special, longer) = (256, 257);
    assert_eq!(t.encode("<s>"), [special]);
    assert_eq!(t.encode("<s>x<s>"), [longer, special]);
    let plain = t.encode("<n>");
    assert_eq!(
        plain.len(),
        3,
        "a normal token's text is not special: {plain:?}"
    );
    assert_eq!(t.encode("a<s>b").len(), 3);
}

#[test]
fn bad_vocabularies_are_refused() {
    let mut s = Vec::new();
    assert!(
        tokenizer(&mut s, &[], &[b"a b"]).is_err(),
        "merge result missing"
    );
    let mut s = Vec::new();
    assert!(
        tokenizer(&mut s, &[("ab", 1)], &[b"ab"]).is_err(),
        "no space"
    );
    let mut s = Vec::new();
    assert!(
        tokenizer(&mut s, &[("a", 1)], &[]).is_err(),
        "duplicate token"
    );
    let tokens: &[&[u8]] = &[b"a"];
    assert_eq!(
        Tokenizer::new(tokens, &[1], &[]).err(),
        Some(Error::BadTokenizer),
        "bytes without tokens"
    );
    assert_eq!(
        Tokenizer::new(tokens, &[], &[]).err(),
        Some(Error::BadTokenizer),
        "types do not match"
    );
    assert_eq!(
        Tokenizer::new(&[], &[], &[]).err(),
        Some(Error::BadTokenizer)
    );
}

#[test]
fn fuzzed_text_and_merges_never_panic() {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let alphabet = [
        "a", "b", " ", "\n", "\r", "'", "s", "1", "é", "ก", "\u{0e31}", "!", "<s>", "\t", "😀",
    ];
    let mut s = Vec::new();
    let m: &[&[u8]] = &[b"a b", b"b a", "Ġ a".as_bytes()];
    let t = tokenizer(&mut s, &[("ab", 1), ("ba", 1), ("Ġa", 1), ("<s>", 3)], m).unwrap();
    for _ in 0..20_000 {
        let n = (next() % 40) as usize;
        let text: String = (0..n)
            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
            .collect();
        let ids = t.encode(&text);
        assert!(ids.iter().all(|&i| i < 260));
    }
    // Random merge strings never panic the constructor.
    for _ in 0..5_000 {
        let bytes: Vec<u8> = (0..(next() % 6))
            .map(|_| "ab Ġ".as_bytes()[(next() % 5) as usize])
            .collect();
        let merges: Vec<&[u8]> = std::vec![bytes.as_slice()];
        let mut s = Vec::new();
        let _ = tokenizer(&mut s, &[("ab", 1)], &merges);
    }
}
