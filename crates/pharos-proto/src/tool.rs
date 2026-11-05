//! Tool calls (tools.md, D-023): the text a model writes to call a tool,
//! parsed as a strict subset of JSON, then checked against the tool's
//! schema. The text is untrusted (it comes from a model, through an agent):
//! the parser checks every byte, refuses anything outside the subset, and
//! never panics.
//!
//! ```text
//! {"name": "read_file", "arguments": {"name": "report.txt"}}
//! ```
//!
//! One object with the keys `name` (a string) and `arguments` (an object of
//! string and integer values, not nested). Strings are UTF-8 with the escapes
//! `\"`, `\\`, `\/`, `\n`, `\r`, `\t`, and `\uXXXX` for any character but a
//! control character or a surrogate. Integers are decimal, unsigned, without
//! a leading zero, at most `u32::MAX`. Keys are names (1 to 32 letters,
//! digits, `-`, `_`), written without escapes, each at most once.

/// Longest call text.
pub const MAX_CALL: usize = 1024;
/// Most arguments.
pub const MAX_ARGS: usize = 8;
/// Longest string value, once unescaped.
pub const MAX_STRING: usize = 512;
/// Longest key or tool name.
pub const MAX_KEY: usize = 32;

/// Why a text is not a tool call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Longer than [`MAX_CALL`].
    TooLong,
    /// Not UTF-8 (overlong forms and surrogates included).
    Utf8,
    /// Not the grammar: a missing, unexpected, or unfinished token.
    Syntax,
    /// A control character (below U+0020, or U+007F) written in a string.
    Control,
    /// An escape outside the subset, or `\u` for a control character or
    /// surrogate.
    Escape,
    /// A string longer than [`MAX_STRING`] once unescaped.
    LongString,
    /// A number with a sign, a leading zero, a fraction, an exponent, or
    /// over `u32::MAX`.
    Number,
    /// A key that is not a name, or is written with an escape.
    Key,
    /// A key given twice in one object.
    Duplicate,
    /// A top-level key other than `name` and `arguments`, or one missing.
    Shape,
    /// The tool's name not a string that is a name.
    Name,
    /// A value that is not a string or an integer (`arguments` not an
    /// object; an object, array, `true`, `false`, or `null` as an argument).
    Value,
    /// More than [`MAX_ARGS`] arguments.
    TooMany,
    /// Anything but whitespace after the object.
    Trailing,
}

/// A refused text: the first fault and the byte offset where it was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub fault: Fault,
    pub at: usize,
}

/// An argument's value. Strings are unescaped, and valid UTF-8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Str(&'a [u8]),
    Int(u32),
}

/// A parsed call, borrowing the caller's scratch buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call<'a> {
    pub name: &'a [u8],
    args: [(&'a [u8], Value<'a>); MAX_ARGS],
    len: usize,
}

impl<'a> Call<'a> {
    /// The arguments, in the order written.
    pub fn args(&self) -> &[(&'a [u8], Value<'a>)] {
        &self.args[..self.len]
    }

    /// The argument `key`.
    pub fn get(&self, key: &[u8]) -> Option<Value<'a>> {
        self.args().iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// A name: 1 to [`MAX_KEY`] letters, digits, `-`, or `_`.
fn is_name(b: &[u8]) -> bool {
    (1..=MAX_KEY).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

/// Where a string or value sits in the scratch buffer while parsing.
#[derive(Clone, Copy)]
enum Slot {
    Str(usize, usize),
    Int(u32),
}

struct Parser<'t, 's> {
    text: &'t [u8],
    i: usize,
    out: &'s mut [u8; MAX_CALL],
    w: usize,
}

impl Parser<'_, '_> {
    fn refuse<T>(&self, fault: Fault) -> Result<T, Refusal> {
        Err(Refusal { fault, at: self.i })
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.i).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), Refusal> {
        if self.peek() != Some(c) {
            return self.refuse(Fault::Syntax);
        }
        self.i += 1;
        Ok(())
    }

    fn push(&mut self, b: u8) -> Result<(), Refusal> {
        // Never fails: each byte written consumed at least one byte of a
        // text of at most MAX_CALL bytes.
        let Some(slot) = self.out.get_mut(self.w) else {
            return self.refuse(Fault::TooLong);
        };
        *slot = b;
        self.w += 1;
        Ok(())
    }

    /// A string at `i`, unescaped into the scratch buffer: its place there,
    /// and whether it had an escape.
    fn string(&mut self) -> Result<((usize, usize), bool), Refusal> {
        let at = self.i;
        self.eat(b'"')?;
        let start = self.w;
        let mut escaped = false;
        loop {
            let Some(b) = self.peek() else {
                return self.refuse(Fault::Syntax);
            };
            match b {
                b'"' => break,
                b'\\' => {
                    escaped = true;
                    self.i += 1;
                    let e = match self.peek() {
                        Some(e @ (b'"' | b'\\' | b'/')) => e,
                        Some(b'n') => b'\n',
                        Some(b'r') => b'\r',
                        Some(b't') => b'\t',
                        Some(b'u') => {
                            self.unicode()?;
                            continue;
                        }
                        _ => return self.refuse(Fault::Escape),
                    };
                    self.push(e)?;
                }
                0..=0x1f | 0x7f => return self.refuse(Fault::Control),
                _ => self.push(b)?,
            }
            self.i += 1;
        }
        self.i += 1;
        if self.w - start > MAX_STRING {
            return Err(Refusal {
                fault: Fault::LongString,
                at,
            });
        }
        Ok(((start, self.w - start), escaped))
    }

    /// `\uXXXX` with `i` at the `u`; leaves `i` after the last digit.
    fn unicode(&mut self) -> Result<(), Refusal> {
        let digits = self.text.get(self.i + 1..self.i + 5);
        let code = digits.and_then(|d| {
            d.iter()
                .try_fold(0u32, |n, c| Some(n * 16 + char::from(*c).to_digit(16)?))
        });
        let c = match code {
            Some(c) if c >= 0x20 && c != 0x7f => char::from_u32(c),
            _ => None,
        };
        let Some(c) = c else {
            return self.refuse(Fault::Escape);
        };
        let mut buf = [0u8; 4];
        for b in c.encode_utf8(&mut buf).bytes() {
            self.push(b)?;
        }
        self.i += 5;
        Ok(())
    }

    fn number(&mut self) -> Result<u32, Refusal> {
        let start = self.i;
        let mut n: u32 = 0;
        while let Some(d @ b'0'..=b'9') = self.peek() {
            if self.i > start && n == 0 {
                return self.refuse(Fault::Number);
            }
            n = match n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u32::from(d - b'0')))
            {
                Some(n) => n,
                None => return self.refuse(Fault::Number),
            };
            self.i += 1;
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'-' | b'+')) {
            return self.refuse(Fault::Number);
        }
        Ok(n)
    }

    /// A key and its colon: its place in the scratch buffer.
    fn key(&mut self) -> Result<(usize, usize), Refusal> {
        let at = self.i;
        let ((start, len), escaped) = self.string()?;
        if escaped || !is_name(&self.out[start..start + len]) {
            return Err(Refusal {
                fault: Fault::Key,
                at,
            });
        }
        self.space();
        self.eat(b':')?;
        self.space();
        Ok((start, len))
    }

    /// After a member: `,` (another follows) or `}` (the object ends).
    fn more(&mut self) -> Result<bool, Refusal> {
        self.space();
        match self.peek() {
            Some(b',') => {
                self.i += 1;
                self.space();
                Ok(true)
            }
            Some(b'}') => {
                self.i += 1;
                Ok(false)
            }
            _ => self.refuse(Fault::Syntax),
        }
    }

    fn arguments(
        &mut self,
        args: &mut [((usize, usize), Slot); MAX_ARGS],
    ) -> Result<usize, Refusal> {
        if self.peek() != Some(b'{') {
            return self.refuse(Fault::Value);
        }
        self.i += 1;
        self.space();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(0);
        }
        let mut len = 0;
        loop {
            let at = self.i;
            let (ks, kl) = self.key()?;
            let key = &self.out[ks..ks + kl];
            if args[..len]
                .iter()
                .any(|((s, l), _)| &self.out[*s..*s + *l] == key)
            {
                return Err(Refusal {
                    fault: Fault::Duplicate,
                    at,
                });
            }
            if len == MAX_ARGS {
                return Err(Refusal {
                    fault: Fault::TooMany,
                    at,
                });
            }
            let value = match self.peek() {
                Some(b'"') => {
                    let ((s, l), _) = self.string()?;
                    Slot::Str(s, l)
                }
                Some(b'0'..=b'9' | b'-') => Slot::Int(self.number()?),
                Some(b'{' | b'[' | b't' | b'f' | b'n') => return self.refuse(Fault::Value),
                _ => return self.refuse(Fault::Syntax),
            };
            args[len] = ((ks, kl), value);
            len += 1;
            if !self.more()? {
                return Ok(len);
            }
        }
    }
}

/// Parses `text` as a tool call, unescaping into `scratch` (which the call
/// borrows).
pub fn parse<'s>(text: &[u8], scratch: &'s mut [u8; MAX_CALL]) -> Result<Call<'s>, Refusal> {
    if text.len() > MAX_CALL {
        return Err(Refusal {
            fault: Fault::TooLong,
            at: MAX_CALL,
        });
    }
    if let Err(e) = core::str::from_utf8(text) {
        return Err(Refusal {
            fault: Fault::Utf8,
            at: e.valid_up_to(),
        });
    }
    let mut p = Parser {
        text,
        i: 0,
        out: scratch,
        w: 0,
    };
    let mut name = None;
    let mut args = [((0, 0), Slot::Int(0)); MAX_ARGS];
    let mut len = None;
    p.space();
    p.eat(b'{')?;
    p.space();
    loop {
        let at = p.i;
        let (ks, kl) = p.key()?;
        let seen = match &p.out[ks..ks + kl] {
            b"name" => name.is_some(),
            b"arguments" => len.is_some(),
            _ => {
                return Err(Refusal {
                    fault: Fault::Shape,
                    at,
                });
            }
        };
        if seen {
            return Err(Refusal {
                fault: Fault::Duplicate,
                at,
            });
        }
        if &p.out[ks..ks + kl] == b"name" {
            let at = p.i;
            let ok = p.peek() == Some(b'"');
            let (place, escaped) = if ok { p.string()? } else { ((0, 0), true) };
            if escaped || !is_name(&p.out[place.0..place.0 + place.1]) {
                return Err(Refusal {
                    fault: Fault::Name,
                    at,
                });
            }
            name = Some(place);
        } else {
            len = Some(p.arguments(&mut args)?);
        }
        if !p.more()? {
            break;
        }
    }
    let (Some((ns, nl)), Some(len)) = (name, len) else {
        return p.refuse(Fault::Shape);
    };
    p.space();
    if p.i != text.len() {
        return p.refuse(Fault::Trailing);
    }
    let out: &'s [u8] = p.out;
    let mut call = Call {
        name: &out[ns..ns + nl],
        args: [(&[][..], Value::Int(0)); MAX_ARGS],
        len,
    };
    for (slot, ((ks, kl), v)) in call.args.iter_mut().zip(&args[..len]) {
        let value = match *v {
            Slot::Str(s, l) => Value::Str(&out[s..s + l]),
            Slot::Int(n) => Value::Int(n),
        };
        *slot = (&out[*ks..*ks + *kl], value);
    }
    Ok(call)
}

/// What an argument must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A string of 1 to this many bytes.
    Str(usize),
    /// An integer of at most this.
    Int(u32),
}

/// A tool's name and its arguments, all required.
#[derive(Clone, Copy, Debug)]
pub struct Schema {
    pub name: &'static [u8],
    pub args: &'static [(&'static [u8], Kind)],
}

/// Why a parsed call does not fit any tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// No tool of that name.
    Unknown,
    /// An argument the tool does not take.
    Extra,
    /// An argument of the wrong type.
    Type,
    /// A string empty or too long, or an integer too large.
    Range,
    /// An argument the tool needs is missing.
    Missing,
}

/// The tool `call` names in `tools`, as an index, if the call fits its
/// schema.
pub fn validate(call: &Call<'_>, tools: &[Schema]) -> Result<usize, Invalid> {
    let n = tools
        .iter()
        .position(|t| t.name == call.name)
        .ok_or(Invalid::Unknown)?;
    let schema = &tools[n];
    for (key, value) in call.args() {
        let (_, kind) = schema
            .args
            .iter()
            .find(|(k, _)| k == key)
            .ok_or(Invalid::Extra)?;
        let fits = match (*kind, *value) {
            (Kind::Str(max), Value::Str(s)) => (1..=max).contains(&s.len()),
            (Kind::Int(max), Value::Int(i)) => i <= max,
            _ => return Err(Invalid::Type),
        };
        if !fits {
            return Err(Invalid::Range);
        }
    }
    // No key twice (the parser refuses it) and none outside the schema, so
    // fewer than the schema's means one is missing.
    if call.args().len() < schema.args.len() {
        return Err(Invalid::Missing);
    }
    Ok(n)
}

/// Tool numbers (1 up; the index in [`TOOLS`] plus one).
pub mod number {
    pub const READ_FILE: u8 = 1;
    pub const SEND: u8 = 2;
}

/// M3.6's tools (D-023 item 4). What each needs and whether it is sensitive
/// is the agent runtime's table; the schemas are here, beside the parser.
pub const TOOLS: [Schema; 2] = [
    Schema {
        name: b"read_file",
        args: &[(b"name", Kind::Str(MAX_KEY))],
    },
    Schema {
        name: b"send",
        // `a.b.c.d:port` is at most 21 bytes; a datagram at most 248.
        args: &[(b"to", Kind::Str(21)), (b"data", Kind::Str(248))],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, vec::Vec};

    /// An argument as owned bytes: its key, and its string or integer.
    type Owned = (Vec<u8>, Option<Vec<u8>>, Option<u32>);

    fn ok(text: &str) -> (Vec<u8>, Vec<Owned>) {
        let mut s = [0u8; MAX_CALL];
        let c = parse(text.as_bytes(), &mut s).unwrap_or_else(|r| panic!("{text}: {r:?}"));
        let args = c
            .args()
            .iter()
            .map(|(k, v)| match v {
                Value::Str(s) => (k.to_vec(), Some(s.to_vec()), None),
                Value::Int(n) => (k.to_vec(), None, Some(*n)),
            })
            .collect();
        (c.name.to_vec(), args)
    }

    fn no(text: &[u8]) -> Fault {
        let mut s = [0u8; MAX_CALL];
        match parse(text, &mut s) {
            Ok(_) => panic!("accepted {:?}", std::string::String::from_utf8_lossy(text)),
            Err(r) => r.fault,
        }
    }

    const READ: &str = r#"{"name":"read_file","arguments":{"name":"report.txt"}}"#;

    #[test]
    fn accepts_the_subset() {
        let (name, args) = ok(READ);
        assert_eq!(name, b"read_file");
        assert_eq!(
            args,
            [(b"name".to_vec(), Some(b"report.txt".to_vec()), None)]
        );
        // Either order, whitespace between tokens, integers, no arguments.
        let (name, args) =
            ok(" \n{ \"arguments\" : { \"a\" : 0 , \"b_-1\":4294967295 } ,\t\"name\": \"x\" }\r\n");
        assert_eq!(name, b"x");
        assert_eq!(
            args,
            [
                (b"a".to_vec(), None, Some(0)),
                (b"b_-1".to_vec(), None, Some(u32::MAX))
            ]
        );
        assert!(ok(r#"{"name":"t","arguments":{}}"#).1.is_empty());
        // Escapes, and UTF-8 written or escaped.
        let (_, args) = ok(r#"{"name":"t","arguments":{"s":"a\"\\\/\n\r\t\u00e9\u20ACé€"}}"#);
        assert_eq!(args[0].1.as_deref(), Some("a\"\\/\n\r\té€é€".as_bytes()));
        // Limits: 8 arguments, a 512-byte string, a 32-byte key.
        let eight: std::string::String = (0..8).map(|i| format!(",\"k{i}\":1")).collect();
        assert_eq!(
            ok(&format!(
                "{{\"name\":\"t\",\"arguments\":{{{}}}}}",
                &eight[1..]
            ))
            .1
            .len(),
            8
        );
        let long = "x".repeat(MAX_STRING);
        assert_eq!(
            ok(&format!(r#"{{"name":"t","arguments":{{"s":"{long}"}}}}"#)).1[0]
                .1
                .as_ref()
                .unwrap()
                .len(),
            512
        );
        let key = "k".repeat(MAX_KEY);
        ok(&format!(r#"{{"name":"{key}","arguments":{{"{key}":1}}}}"#));
    }

    #[test]
    fn refuses_each_fault() {
        let a = |args: &str| format!(r#"{{"name":"t","arguments":{{{args}}}}}"#).into_bytes();
        let raw = |b: &[u8]| [&br#"{"name":"t","arguments":{"s":""#[..], b, br#""}}"#].concat();
        let cases: &[(Vec<u8>, Fault)] = &[
            (std::vec![b' '; MAX_CALL + 1], Fault::TooLong),
            (raw(b"\xc0\xaf"), Fault::Utf8),
            (raw(b"\xed\xa0\x80"), Fault::Utf8),
            (b"".to_vec(), Fault::Syntax),
            (b"[]".to_vec(), Fault::Syntax),
            (a("\"s\":'x'"), Fault::Syntax),
            (a("\"s\":1,"), Fault::Syntax),
            (a("\"s\" 1"), Fault::Syntax),
            (a("\"s\":\"\x01\""), Fault::Control),
            (a("\"s\":\"\x7f\""), Fault::Control),
            (a("\"s\":\"\n\""), Fault::Control),
            (a(r#""s":"\b""#), Fault::Escape),
            (a(r#""s":"\x41""#), Fault::Escape),
            (a(r#""s":"\u0000""#), Fault::Escape),
            (a(r#""s":"\u001b""#), Fault::Escape),
            (a(r#""s":"\ud83d\ude00""#), Fault::Escape),
            (a(r#""s":"\u12g4""#), Fault::Escape),
            (a(r#""s":"\u12""#), Fault::Escape),
            (
                a(&format!("\"s\":\"{}\"", "x".repeat(MAX_STRING + 1))),
                Fault::LongString,
            ),
            (
                a(&format!("\"s\":\"{}\"", r"é".repeat(MAX_STRING / 2 + 1))),
                Fault::LongString,
            ),
            (a("\"n\":-1"), Fault::Number),
            (a("\"n\":01"), Fault::Number),
            (a("\"n\":1.5"), Fault::Number),
            (a("\"n\":1e3"), Fault::Number),
            (a("\"n\":4294967296"), Fault::Number),
            (a("\"\":1"), Fault::Key),
            (a("\"a b\":1"), Fault::Key),
            (a(r#""\u0061":1"#), Fault::Key),
            (a(&format!("\"{}\":1", "k".repeat(MAX_KEY + 1))), Fault::Key),
            (a("\"a\":1,\"a\":2"), Fault::Duplicate),
            (
                br#"{"name":"t","name":"u","arguments":{}}"#.to_vec(),
                Fault::Duplicate,
            ),
            (
                br#"{"name":"t","arguments":{},"arguments":{}}"#.to_vec(),
                Fault::Duplicate,
            ),
            (br#"{"name":"t"}"#.to_vec(), Fault::Shape),
            (br#"{"arguments":{}}"#.to_vec(), Fault::Shape),
            (
                br#"{"name":"t","arguments":{},"extra":1}"#.to_vec(),
                Fault::Shape,
            ),
            (br#"{"Name":"t","arguments":{}}"#.to_vec(), Fault::Shape),
            (br#"{}"#.to_vec(), Fault::Syntax),
            (br#"{"name":1,"arguments":{}}"#.to_vec(), Fault::Name),
            (
                br#"{"name":"read file","arguments":{}}"#.to_vec(),
                Fault::Name,
            ),
            (
                br#"{"name":"r\u0065ad_file","arguments":{}}"#.to_vec(),
                Fault::Name,
            ),
            (br#"{"name":"t","arguments":[]}"#.to_vec(), Fault::Value),
            (br#"{"name":"t","arguments":"x"}"#.to_vec(), Fault::Value),
            (a("\"o\":{}"), Fault::Value),
            (a("\"o\":[1]"), Fault::Value),
            (a("\"o\":true"), Fault::Value),
            (a("\"o\":null"), Fault::Value),
            (
                a(&(0..9)
                    .map(|i| format!("\"k{i}\":1"))
                    .collect::<Vec<_>>()
                    .join(",")),
                Fault::TooMany,
            ),
            ([READ.as_bytes(), b"{}"].concat(), Fault::Trailing),
            ([READ.as_bytes(), b" x"].concat(), Fault::Trailing),
            ([READ.as_bytes(), b"\0"].concat(), Fault::Trailing),
            ([b"\xef\xbb\xbf", READ.as_bytes()].concat(), Fault::Syntax),
        ];
        for (text, fault) in cases {
            assert_eq!(
                no(text),
                *fault,
                "{:?}",
                std::string::String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn refusals_say_where() {
        let mut s = [0u8; MAX_CALL];
        let r = parse(br#"{"name":"t","arguments":{"n":01}}"#, &mut s).unwrap_err();
        assert_eq!(
            r,
            Refusal {
                fault: Fault::Number,
                at: 30
            }
        );
    }

    #[test]
    fn every_truncation_is_refused() {
        for text in [
            READ,
            r#"{"name":"send","arguments":{"to":"10.0.2.2:47000","data":"a\u00e9","n":12}}"#,
        ] {
            for n in 0..text.len() {
                no(&text.as_bytes()[..n]);
            }
        }
    }

    /// Writes a call the way a model would, escaping what must be.
    fn encode(name: &[u8], args: &[(&[u8], Value<'_>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let string = |out: &mut Vec<u8>, s: &[u8]| {
            out.push(b'"');
            for c in core::str::from_utf8(s).unwrap().chars() {
                match c {
                    '"' => out.extend_from_slice(b"\\\""),
                    '\\' => out.extend_from_slice(b"\\\\"),
                    '\n' => out.extend_from_slice(b"\\n"),
                    c if (c as u32) < 0x20 || c == '\x7f' => panic!("unencodable"),
                    c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                }
            }
            out.push(b'"');
        };
        out.extend_from_slice(b"{\"name\":");
        string(&mut out, name);
        out.extend_from_slice(b",\"arguments\":{");
        for (i, (k, v)) in args.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            string(&mut out, k);
            out.push(b':');
            match v {
                Value::Str(s) => string(&mut out, s),
                Value::Int(n) => out.extend_from_slice(format!("{n}").as_bytes()),
            }
        }
        out.extend_from_slice(b"}}");
        out
    }

    #[test]
    fn round_trips() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let pool = [
            "a", "\"", "\\", "\n", "é", "€", "😀", "/", " ", "{", "}", ":", ",",
        ];
        for _ in 0..10_000 {
            let keys: Vec<Vec<u8>> = (0..next() % 9)
                .map(|i| format!("k{i}").into_bytes())
                .collect();
            let strings: Vec<Vec<u8>> = keys
                .iter()
                .map(|_| {
                    (0..next() % 20)
                        .map(|_| pool[(next() % 13) as usize])
                        .collect::<std::string::String>()
                        .into_bytes()
                })
                .collect();
            let args: Vec<(&[u8], Value<'_>)> = keys
                .iter()
                .zip(&strings)
                .map(|(k, s)| {
                    let v = if next() % 2 == 0 {
                        Value::Str(s)
                    } else {
                        Value::Int(next() as u32)
                    };
                    (&k[..], v)
                })
                .collect();
            let text = encode(b"tool", &args);
            let mut s = [0u8; MAX_CALL];
            let call = parse(&text, &mut s).unwrap();
            assert_eq!(call.name, b"tool");
            assert_eq!(call.args(), &args[..]);
        }
    }

    fn check_accepted(c: &Call<'_>) {
        assert!(is_name(c.name) && c.args().len() <= MAX_ARGS);
        for (i, (k, v)) in c.args().iter().enumerate() {
            assert!(is_name(k));
            assert!(c.args()[..i].iter().all(|(o, _)| o != k));
            if let Value::Str(s) = v {
                assert!(s.len() <= MAX_STRING && core::str::from_utf8(s).is_ok());
                assert!(
                    !s.iter()
                        .any(|b| (*b < 0x20 && !b"\n\r\t".contains(b)) || *b == 0x7f)
                );
            }
        }
    }

    #[test]
    fn fuzzed() {
        // Bytes from a call's alphabet, then mutations of valid calls.
        let alphabet = b"{}[]:,\"\\ nameargumts_0129u-.e\x00\xc3\xa9\xff";
        let mut s = [0u8; MAX_CALL];
        crate::fuzz(500_000, alphabet.len() as u8, |m| {
            let text: Vec<u8> = m.iter().map(|b| alphabet[usize::from(*b)]).collect();
            if let Ok(c) = parse(&text, &mut s) {
                check_accepted(&c);
            }
            let _ = parse(m, &mut s);
        });
        let seeds = [
            READ.as_bytes(),
            br#"{"name":"send","arguments":{"to":"10.0.2.2:47000","data":"a\"\u00e9\n","n":7}}"#,
        ];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..500_000 {
            let mut text = seeds[round % 2].to_vec();
            for _ in 0..1 + x % 4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize >> 8) % text.len();
                match x % 3 {
                    0 => text[i] = alphabet[(x >> 40) as usize % alphabet.len()],
                    1 => text.insert(i, x as u8),
                    _ => {
                        text.remove(i);
                    }
                }
            }
            if let Ok(c) = parse(&text, &mut s) {
                check_accepted(&c);
                let _ = validate(&c, &TOOLS);
            }
        }
    }

    #[test]
    fn validates_against_the_schemas() {
        let check = |text: &str| {
            let mut s = [0u8; MAX_CALL];
            validate(&parse(text.as_bytes(), &mut s).unwrap(), &TOOLS)
        };
        assert_eq!(check(READ), Ok(0));
        assert_eq!(TOOLS[0].name, b"read_file");
        assert_eq!(usize::from(number::READ_FILE), 1);
        assert_eq!(
            check(r#"{"name":"send","arguments":{"data":"hi","to":"10.0.2.2:47000"}}"#),
            Ok(usize::from(number::SEND) - 1)
        );
        assert_eq!(
            check(r#"{"name":"exec","arguments":{}}"#),
            Err(Invalid::Unknown)
        );
        assert_eq!(
            check(r#"{"name":"Read_file","arguments":{"name":"a"}}"#),
            Err(Invalid::Unknown)
        );
        assert_eq!(
            check(r#"{"name":"read_file","arguments":{}}"#),
            Err(Invalid::Missing)
        );
        assert_eq!(
            check(r#"{"name":"read_file","arguments":{"name":"a","mode":"w"}}"#),
            Err(Invalid::Extra)
        );
        assert_eq!(
            check(r#"{"name":"read_file","arguments":{"name":7}}"#),
            Err(Invalid::Type)
        );
        assert_eq!(
            check(r#"{"name":"read_file","arguments":{"name":""}}"#),
            Err(Invalid::Range)
        );
        let long = "a".repeat(MAX_KEY + 1);
        assert_eq!(
            check(&format!(
                r#"{{"name":"read_file","arguments":{{"name":"{long}"}}}}"#
            )),
            Err(Invalid::Range)
        );
        let data = "a".repeat(249);
        assert_eq!(
            check(&format!(
                r#"{{"name":"send","arguments":{{"to":"x","data":"{data}"}}}}"#
            )),
            Err(Invalid::Range)
        );
        assert_eq!(
            check(r#"{"name":"send","arguments":{"to":"x"}}"#),
            Err(Invalid::Missing)
        );
    }
}
