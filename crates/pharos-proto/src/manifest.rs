//! Agent manifests, version 1 (agents.md, #97): what an agent asks for, as
//! a text file in the read-only filesystem image. At most 4 KiB, one
//! `key = value` per line, `#` lines are comments, blank lines are
//! ignored. Every key appears exactly once:
//!
//! ```text
//! manifest = 1
//! name = summarize
//! program = agents/summarize
//! pages = 2048
//! models = 1
//! attempts = 3
//! progress_ms = 30000
//! task_ms = 600000
//! data = read
//! net = 10.0.2.2:47000
//! ```
//!
//! `models` lists model numbers, comma-separated, or is empty for none.
//! `data` is `none`, `read`, or `write`: the agent's own files, kept by the
//! runtime (capabilities.md, #105); `write` includes reading.
//! `net` lists UDP destinations, `address:port`, comma-separated, at most
//! [`MAX_NET`], or is empty for none (#109).
//! A manifest is untrusted: [`parse`] refuses unknown, repeated, and
//! missing keys and values out of range, and never panics. It only asks:
//! [`Manifest::within`] checks it against the runtime's reviewed policy
//! entry, and a manifest asking for more is refused, never narrowed.

use crate::Writer;
use crate::permission::Permission;
use crate::trust::valid_name;

pub const VERSION: u32 = 1;
/// Largest manifest file.
pub const MAX_SIZE: usize = 4096;
/// Longest program path.
pub const MAX_PROGRAM: usize = 64;
/// Most pages a manifest may ask for (1 GiB).
pub const MAX_PAGES: u32 = 262_144;
/// Highest model number.
pub const MAX_MODEL: u8 = 31;
/// Most attempts per task.
pub const MAX_ATTEMPTS: u8 = 10;
/// Longest `progress_ms`: one hour.
pub const MAX_PROGRESS_MS: u32 = 3_600_000;
/// Longest `task_ms`: one day.
pub const MAX_TASK_MS: u32 = 86_400_000;
/// Most network destinations a manifest may list.
pub const MAX_NET: usize = 4;
/// Most files a manifest may list (#127).
pub const MAX_FILES: usize = 4;

/// The files a manifest lists (`file <name>` permissions, #127).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Files<'a> {
    list: [&'a [u8]; MAX_FILES],
    len: u8,
}

impl<'a> Files<'a> {
    /// `None` if more than [`MAX_FILES`], repeated, or not file names.
    pub fn new(names: &[&'a [u8]]) -> Option<Self> {
        Self::new_with(names, crate::permission::valid_file)
    }

    /// As [`Files::new`], with names checked by `valid`.
    pub fn new_with(names: &[&'a [u8]], valid: fn(&[u8]) -> bool) -> Option<Self> {
        let mut f = Self::default();
        for (i, n) in names.iter().enumerate() {
            if !valid(n) || names[..i].contains(n) {
                return None;
            }
            *f.list.get_mut(i)? = n;
        }
        f.len = names.len() as u8;
        Some(f)
    }

    pub fn as_slice(&self) -> &[&'a [u8]] {
        &self.list[..usize::from(self.len)]
    }
}

/// The tools a manifest or policy entry lists: bit `n` for tool number `n`
/// (`pharos_proto::tool::number`).
pub fn tool_bit(name: &[u8]) -> Option<u32> {
    crate::tool::TOOLS
        .iter()
        .position(|t| t.name == name)
        .map(|i| 1 << (i + 1))
}

/// A UDP destination: IPv4 address and port (1 or above).
pub type Dest = ([u8; 4], u16);

/// The destinations a manifest lists; unused entries are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Net {
    list: [Dest; MAX_NET],
    len: u8,
}

impl Net {
    /// `None` if more than [`MAX_NET`], repeated, or with port 0.
    pub fn new(dests: &[Dest]) -> Option<Self> {
        let mut n = Self::default();
        for (i, d) in dests.iter().enumerate() {
            if d.1 == 0 || dests[..i].contains(d) {
                return None;
            }
            *n.list.get_mut(i)? = *d;
        }
        n.len = dests.len() as u8;
        Some(n)
    }

    pub fn as_slice(&self) -> &[Dest] {
        &self.list[..usize::from(self.len)]
    }
}

/// Access to the agent's own files; `Write` includes reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Data {
    None,
    Read,
    Write,
}

/// A parsed manifest, borrowing its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest<'a> {
    pub name: &'a [u8],
    pub program: &'a [u8],
    pub pages: u32,
    /// Bit `n` set: model `n` may be used.
    pub models: u32,
    pub attempts: u8,
    pub progress_ms: u32,
    pub task_ms: u32,
    pub data: Data,
    pub net: Net,
    /// Optional keys (#126, #127): the tools it may call, a bit per tool
    /// number, and the files it gets; none when absent.
    pub tools: u32,
    pub files: Files<'a>,
    /// Optional (#133): the agents it may send messages to.
    pub channels: Files<'a>,
}

/// What the runtime's policy table allows one agent: the most it may get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: &'static [u8],
    pub program: &'static [u8],
    pub pages: u32,
    pub models: u32,
    pub attempts: u8,
    pub progress_ms: u32,
    pub task_ms: u32,
    pub data: Data,
    /// What the agent may ask the user for on top (#106): models, and data
    /// access up to this level. A manifest cannot ask for these; the agent
    /// asks while it runs, and gets each only with the user's approval.
    pub ask_models: u32,
    pub ask_data: Data,
    /// UDP destinations it may get (#109); the network service lets the
    /// runtime reach only the union of every entry's `net` and `ask_net`.
    pub net: &'static [Dest],
    pub ask_net: &'static [Dest],
    /// What each attempt may use, and its group (D-022, #116).
    pub budget: Budget,
    /// The tools it may call, a bit per tool number (#126; never askable),
    /// and the files of the store's `files` namespace it may get and ask
    /// for (#127).
    pub tools: u32,
    pub files: &'static [&'static [u8]],
    pub ask_files: &'static [&'static [u8]],
    /// The agents it may send messages to (#133; not askable).
    pub channels: &'static [&'static [u8]],
}

/// What one attempt of an agent may use (D-022, resources.md). Each limit
/// is per attempt except `data_kb`, the agent's stored files in total.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// CPU time; over it, the attempt is stopped.
    pub cpu_ms: u32,
    /// Inference tokens, prompt and generated.
    pub tokens: u32,
    pub net_sends: u32,
    pub net_bytes: u32,
    pub data_kb: u32,
    /// Granted files read with `read_file` (#127), in KiB.
    pub file_kb: u32,
    /// Messages sent to other agents (#133).
    pub messages: u32,
    /// Requests per second, with a burst of as many; one past it is held
    /// until the rate allows (#117).
    pub rate: u32,
    /// The [`Group`] it belongs to; empty for none.
    pub group: &'static [u8],
}

impl Budget {
    /// No limit on anything, no group.
    pub const UNLIMITED: Self = Self {
        cpu_ms: u32::MAX,
        tokens: u32::MAX,
        net_sends: u32::MAX,
        net_bytes: u32::MAX,
        data_kb: u32::MAX,
        file_kb: u32::MAX,
        messages: u32::MAX,
        rate: u32::MAX,
        group: b"",
    };
}

/// Totals shared by the agents of one group (D-022 item 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: &'static [u8],
    /// Attempts running at once; another waits to start.
    pub agents: u32,
    /// Their page limits together; an attempt that would exceed it waits.
    pub pages: u32,
    /// Inference tokens and network payload bytes, per minute.
    pub tokens_per_min: u32,
    pub net_bytes_per_min: u32,
    /// Coordination (#134, coordination.md): the agent that submits
    /// subtasks to `workers` (empty for a budget-only group), and the check
    /// its results pass before they count as done.
    pub supervisor: &'static [u8],
    pub workers: &'static [&'static [u8]],
    pub verifier: Verifier,
}

/// A compiled-in check of a group's results (#137, coordination.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verifier {
    /// No check: a budget-only group, which cannot have a supervisor.
    None,
    /// Text of at most this many bytes.
    Text(u32),
}

/// Why a manifest was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    TooLarge,
    /// A byte other than printable ASCII or `\n`.
    BadByte,
    /// A line that is not `key = value`.
    BadLine,
    UnknownKey,
    RepeatedKey,
    MissingKey,
    /// `manifest` is not [`VERSION`].
    Version,
    /// A value that is malformed or out of range.
    BadValue,
    /// `progress_ms` above `task_ms`.
    ProgressOverTask,
    /// [`Manifest::within`]: no policy entry for this name.
    NoEntry,
    /// [`Manifest::within`]: a different program than the entry's.
    WrongProgram,
    /// [`Manifest::within`]: more than the entry allows.
    OverPolicy,
}

/// A refusal and the line it happened on (1-based; 0 for the whole file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub line: usize,
    pub why: Why,
}

/// The keys; the last three are optional.
const KEYS: [&[u8]; 13] = [
    b"manifest",
    b"name",
    b"program",
    b"pages",
    b"models",
    b"attempts",
    b"progress_ms",
    b"task_ms",
    b"data",
    b"net",
    b"tools",
    b"files",
    b"channels",
];
const REQUIRED: usize = 10;

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| *b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|b| *b != b' ').map_or(start, |i| i + 1);
    &s[start..end]
}

/// A decimal number from 1 to `max`, digits only, no leading zero.
fn number(v: &[u8], max: u32) -> Option<u32> {
    if v.is_empty() || v.len() > 10 || v[0] == b'0' {
        return None;
    }
    let mut n: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    (n <= max).then_some(n)
}

/// A program path: `/`-separated parts of letters, digits, `-`, `_`, `.`,
/// none empty, `.`, or `..`.
fn valid_program(p: &[u8]) -> bool {
    (1..=MAX_PROGRAM).contains(&p.len())
        && p.split(|b| *b == b'/').all(|part| {
            !part.is_empty()
                && part != b"."
                && part != b".."
                && part
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
        })
}

/// Model numbers, comma-separated (spaces allowed around them), each at
/// most once; empty for none.
fn models(v: &[u8]) -> Option<u32> {
    let mut mask = 0u32;
    if v.is_empty() {
        return Some(0);
    }
    for part in v.split(|b| *b == b',') {
        let bit = 1u32 << number(trim(part), u32::from(MAX_MODEL))?;
        if mask & bit != 0 {
            return None;
        }
        mask |= bit;
    }
    Some(mask)
}

/// Destinations, comma-separated (spaces allowed around them), as the
/// trusted console types them after `net `; empty for none.
fn destinations(v: &[u8]) -> Option<Net> {
    let mut list = [([0u8; 4], 0u16); MAX_NET + 1];
    let mut n = 0;
    if !v.is_empty() {
        for part in v.split(|b| *b == b',') {
            let Permission::Net { addr, port } = Permission::parse(&[b"net", trim(part)])? else {
                return None;
            };
            *list.get_mut(n)? = (addr, port);
            n += 1;
        }
    }
    Net::new(&list[..n])
}

/// A comma-separated list (spaces allowed around each); empty for none.
fn list<'a>(v: &'a [u8], out: &mut [&'a [u8]; MAX_FILES + 1]) -> Option<usize> {
    if v.is_empty() {
        return Some(0);
    }
    let mut n = 0;
    for part in v.split(|b| *b == b',') {
        *out.get_mut(n)? = trim(part);
        n += 1;
    }
    Some(n)
}

/// Tool names, each at most once.
fn tools(v: &[u8]) -> Option<u32> {
    let mut names = [&b""[..]; MAX_FILES + 1];
    let n = list(v, &mut names)?;
    let mut mask = 0;
    for name in &names[..n] {
        let bit = tool_bit(name)?;
        if mask & bit != 0 {
            return None;
        }
        mask |= bit;
    }
    Some(mask)
}

/// Agent names, each at most once.
fn channels(v: &[u8]) -> Option<Files<'_>> {
    let mut names = [&b""[..]; MAX_FILES + 1];
    let n = list(v, &mut names)?;
    Files::new_with(&names[..n], valid_name)
}

fn files(v: &[u8]) -> Option<Files<'_>> {
    let mut names = [&b""[..]; MAX_FILES + 1];
    let n = list(v, &mut names)?;
    Files::new(&names[..n])
}

pub fn parse(text: &[u8]) -> Result<Manifest<'_>, Refusal> {
    let whole = |why| Refusal { line: 0, why };
    if text.len() > MAX_SIZE {
        return Err(whole(Why::TooLarge));
    }
    let mut values: [Option<&[u8]>; 13] = [None; 13];
    for (i, line) in text.split(|b| *b == b'\n').enumerate() {
        let at = |why| Refusal { line: i + 1, why };
        if !line.iter().all(|b| (b' '..=b'~').contains(b)) {
            return Err(at(Why::BadByte));
        }
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let eq = line
            .iter()
            .position(|b| *b == b'=')
            .ok_or(at(Why::BadLine))?;
        let (key, value) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        let k = KEYS
            .iter()
            .position(|k| *k == key)
            .ok_or(at(Why::UnknownKey))?;
        if values[k].replace(value).is_some() {
            return Err(at(Why::RepeatedKey));
        }
    }
    let mut v = [&b""[..]; 13];
    for (k, (out, value)) in v.iter_mut().zip(values).enumerate() {
        *out = match value {
            Some(value) => value,
            None if k >= REQUIRED => b"",
            None => return Err(whole(Why::MissingKey)),
        };
    }
    let [
        version,
        name,
        program,
        pages,
        model_list,
        attempts,
        progress,
        task,
        data,
        net,
        tool_list,
        file_list,
        channel_list,
    ] = v;
    let bad = whole(Why::BadValue);
    if number(version, u32::MAX) != Some(VERSION) {
        return Err(whole(Why::Version));
    }
    let m = Manifest {
        name: Some(name).filter(|n| valid_name(n)).ok_or(bad)?,
        program: Some(program).filter(|p| valid_program(p)).ok_or(bad)?,
        pages: number(pages, MAX_PAGES).ok_or(bad)?,
        models: models(model_list).ok_or(bad)?,
        attempts: number(attempts, u32::from(MAX_ATTEMPTS)).ok_or(bad)? as u8,
        progress_ms: number(progress, MAX_PROGRESS_MS).ok_or(bad)?,
        task_ms: number(task, MAX_TASK_MS).ok_or(bad)?,
        data: match data {
            b"none" => Data::None,
            b"read" => Data::Read,
            b"write" => Data::Write,
            _ => return Err(bad),
        },
        net: destinations(net).ok_or(bad)?,
        tools: tools(tool_list).ok_or(bad)?,
        files: files(file_list).ok_or(bad)?,
        channels: channels(channel_list).ok_or(bad)?,
    };
    if m.progress_ms > m.task_ms {
        return Err(whole(Why::ProgressOverTask));
    }
    Ok(m)
}

/// Writes `n` in decimal.
fn decimal(w: &mut Writer<'_>, mut n: u32) -> Option<()> {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    w.bytes(&digits[i..])
}

impl Manifest<'_> {
    /// Checks this manifest against the policy `table`: its name's entry
    /// must exist, name the same program, and allow at least everything
    /// asked for. Returns the entry.
    pub fn within<'t>(&self, table: &'t [Entry]) -> Result<&'t Entry, Why> {
        let e = table
            .iter()
            .find(|e| e.name == self.name)
            .ok_or(Why::NoEntry)?;
        if e.program != self.program {
            return Err(Why::WrongProgram);
        }
        let fits = self.pages <= e.pages
            && self.models & !e.models == 0
            && self.attempts <= e.attempts
            && self.progress_ms <= e.progress_ms
            && self.task_ms <= e.task_ms
            && self.data <= e.data
            && self.net.as_slice().iter().all(|d| e.net.contains(d))
            && self.tools & !e.tools == 0
            && self.files.as_slice().iter().all(|f| e.files.contains(f))
            && self
                .channels
                .as_slice()
                .iter()
                .all(|c| e.channels.contains(c));
        if fits { Ok(e) } else { Err(Why::OverPolicy) }
    }

    /// Writes the manifest in its canonical form; `None` if `out` is too
    /// small.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(b"manifest = 1\nname = ")?;
        w.bytes(self.name)?;
        w.bytes(b"\nprogram = ")?;
        w.bytes(self.program)?;
        w.bytes(b"\npages = ")?;
        decimal(&mut w, self.pages)?;
        w.bytes(b"\nmodels =")?;
        let mut sep = &b" "[..];
        for n in 1..=MAX_MODEL {
            if self.models & (1 << n) != 0 {
                w.bytes(sep)?;
                decimal(&mut w, u32::from(n))?;
                sep = b", ";
            }
        }
        w.bytes(b"\nattempts = ")?;
        decimal(&mut w, u32::from(self.attempts))?;
        w.bytes(b"\nprogress_ms = ")?;
        decimal(&mut w, self.progress_ms)?;
        w.bytes(b"\ntask_ms = ")?;
        decimal(&mut w, self.task_ms)?;
        w.bytes(match self.data {
            Data::None => b"\ndata = none",
            Data::Read => b"\ndata = read",
            Data::Write => b"\ndata = write",
        })?;
        w.bytes(b"\nnet =")?;
        let mut sep = &b" "[..];
        for &(addr, port) in self.net.as_slice() {
            let mut text = [0u8; crate::permission::TEXT];
            w.bytes(sep)?;
            // Without the `net ` the typed form starts with.
            w.bytes(&Permission::Net { addr, port }.text(&mut text)[4..])?;
            sep = b", ";
        }
        if self.tools != 0 {
            w.bytes(b"\ntools =")?;
            let mut sep = &b" "[..];
            for (i, t) in crate::tool::TOOLS.iter().enumerate() {
                if self.tools & 1 << (i + 1) != 0 {
                    w.bytes(sep)?;
                    w.bytes(t.name)?;
                    sep = b", ";
                }
            }
        }
        for (key, list) in [
            (&b"\nfiles ="[..], &self.files),
            (b"\nchannels =", &self.channels),
        ] {
            if list.as_slice().is_empty() {
                continue;
            }
            w.bytes(key)?;
            let mut sep = &b" "[..];
            for f in list.as_slice() {
                w.bytes(sep)?;
                w.bytes(f)?;
                sep = b", ";
            }
        }
        w.bytes(b"\n")?;
        Some(w.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &[u8] = b"manifest = 1\nname = summarize\nprogram = agents/summarize\n\
pages = 2048\nmodels = 1\nattempts = 3\nprogress_ms = 30000\ntask_ms = 600000\ndata = read\nnet = 10.0.2.2:47000\n";

    const TABLE: &[Entry] = &[Entry {
        name: b"summarize",
        program: b"agents/summarize",
        pages: 4096,
        models: 1 << 1 | 1 << 2,
        attempts: 3,
        progress_ms: 30_000,
        task_ms: 600_000,
        data: Data::Read,
        ask_models: 0,
        ask_data: Data::None,
        net: &[([10, 0, 2, 2], 47_000), ([10, 0, 2, 3], 53)],
        ask_net: &[],
        budget: Budget::UNLIMITED,
        tools: 1 << 1,
        files: &[b"report.txt", b"notes"],
        ask_files: &[],
        channels: &[b"listener"],
    }];

    fn with(key: &str, value: &str) -> std::string::String {
        let text = std::str::from_utf8(S).unwrap();
        text.lines()
            .map(|l| {
                if l.split(" = ").next() == Some(key) {
                    std::format!("{key} = {value}\n")
                } else {
                    std::format!("{l}\n")
                }
            })
            .collect()
    }

    /// `S` with one more line.
    fn plus(line: &str) -> std::string::String {
        std::format!("{}{line}\n", std::str::from_utf8(S).unwrap())
    }

    fn why(text: &[u8]) -> Option<Why> {
        parse(text).err().map(|r| r.why)
    }

    #[test]
    fn every_field_parses() {
        let m = parse(S).unwrap();
        assert_eq!(
            m,
            Manifest {
                name: b"summarize",
                program: b"agents/summarize",
                pages: 2048,
                models: 1 << 1,
                attempts: 3,
                progress_ms: 30_000,
                task_ms: 600_000,
                data: Data::Read,
                net: Net::new(&[([10, 0, 2, 2], 47_000)]).unwrap(),
                tools: 0,
                files: Files::default(),
                channels: Files::default(),
            }
        );
        let text = plus("tools = send , read_file\nfiles = report.txt,a-b_c.1");
        let m = parse(text.as_bytes()).unwrap();
        assert_eq!(m.tools, 1 << 1 | 1 << 2);
        assert_eq!(m.files.as_slice(), &[&b"report.txt"[..], b"a-b_c.1"]);
        let text = plus("tools =\nfiles =");
        let m = parse(text.as_bytes()).unwrap();
        assert_eq!(
            (m.tools, m.files.as_slice().len()),
            (0, 0),
            "empty for none"
        );
        let text = "# an agent\n\n  manifest=1  \nname =summarize\nprogram= agents/summarize\n\
pages = 262144\nmodels = 31 , 2,1\nattempts = 10\n   # comment\nprogress_ms = 1\ntask_ms = 86400000\ndata=write\nnet=";
        let m = parse(text.as_bytes()).unwrap();
        assert_eq!(
            (m.pages, m.models, m.attempts, m.progress_ms, m.task_ms),
            (MAX_PAGES, 1 << 31 | 1 << 2 | 1 << 1, 10, 1, MAX_TASK_MS),
            "spaces, comments, maxima, no final newline"
        );
        assert_eq!(parse(with("models", "").as_bytes()).unwrap().models, 0);
        let four = "1.2.3.4:1 , 10.0.2.2:47000,0.0.0.0:65535, 255.255.255.255:9";
        assert_eq!(
            parse(with("net", four).as_bytes()).unwrap().net.as_slice(),
            &[
                ([1, 2, 3, 4], 1),
                ([10, 0, 2, 2], 47_000),
                ([0, 0, 0, 0], 65_535),
                ([255, 255, 255, 255], 9)
            ]
        );
        assert_eq!(parse(with("pages", "1").as_bytes()).unwrap().pages, 1);
        let program = std::format!("a/{}", "b".repeat(MAX_PROGRAM - 2));
        assert!(parse(with("program", &program).as_bytes()).is_ok());
    }

    #[test]
    fn manifests_round_trip() {
        for text in [
            std::string::String::from_utf8(S.to_vec()).unwrap(),
            with("models", ""),
            with("models", "3, 1, 31"),
            with("name", &"n".repeat(32)),
            with("net", ""),
            with("net", "10.0.2.3:53, 10.0.2.2:47000"),
            std::format!(
                "{}tools = read_file, send\nfiles = a, b, c, d\nchannels = x-1, y_2\n",
                std::str::from_utf8(S).unwrap()
            ),
        ] {
            let m = parse(text.as_bytes()).unwrap();
            let mut out = [0u8; MAX_SIZE];
            let n = m.encode(&mut out).unwrap();
            assert_eq!(parse(&out[..n]), Ok(m), "{text}");
            assert_eq!(m.encode(&mut out[..n - 1]), None, "too small");
        }
        let mut out = [0u8; MAX_SIZE];
        let n = parse(S).unwrap().encode(&mut out).unwrap();
        assert_eq!(&out[..n], S, "the canonical form");
    }

    #[test]
    fn every_refusal() {
        let at = |text: &str| parse(text.as_bytes()).err();
        assert_eq!(
            at(&std::format!(
                "{}\n{}",
                std::str::from_utf8(S).unwrap(),
                "#".repeat(MAX_SIZE)
            )),
            Some(Refusal {
                line: 0,
                why: Why::TooLarge
            })
        );
        assert_eq!(
            at("manifest = 1\nname = a\tb\n"),
            Some(Refusal {
                line: 2,
                why: Why::BadByte
            }),
            "tab"
        );
        assert_eq!(why(b"manifest = 1\r\n"), Some(Why::BadByte), "CR");
        assert_eq!(
            why("name = é\n".as_bytes()),
            Some(Why::BadByte),
            "non-ASCII"
        );
        assert_eq!(why(b"\0"), Some(Why::BadByte));
        assert_eq!(
            at("# x\nmanifest 1\n"),
            Some(Refusal {
                line: 2,
                why: Why::BadLine
            })
        );
        let extra = std::format!("{}colour = red\n", std::str::from_utf8(S).unwrap());
        assert_eq!(
            at(&extra),
            Some(Refusal {
                line: 11,
                why: Why::UnknownKey
            })
        );
        assert_eq!(
            why(b"Name = x\n"),
            Some(Why::UnknownKey),
            "keys are case-sensitive"
        );
        let twice = std::format!("{}pages = 1\n", std::str::from_utf8(S).unwrap());
        assert_eq!(
            at(&twice),
            Some(Refusal {
                line: 11,
                why: Why::RepeatedKey
            })
        );
        for key in &KEYS[..REQUIRED] {
            let key = std::str::from_utf8(key).unwrap();
            let missing: std::string::String = std::str::from_utf8(S)
                .unwrap()
                .lines()
                .filter(|l| !l.starts_with(&std::format!("{key} ")))
                .map(|l| std::format!("{l}\n"))
                .collect();
            assert_eq!(why(missing.as_bytes()), Some(Why::MissingKey), "{key}");
        }
        for v in ["2", "0", "01", "", "one"] {
            assert_eq!(
                why(with("manifest", v).as_bytes()),
                Some(Why::Version),
                "{v:?}"
            );
        }
        for (key, value) in [
            ("name", ""),
            ("name", "a b"),
            ("name", &"n".repeat(33)),
            ("program", ""),
            ("program", "/agents/x"),
            ("program", "agents//x"),
            ("program", "agents/../init"),
            ("program", "agents/./x"),
            ("program", "agents/x/"),
            ("program", "agents/x y"),
            (
                "program",
                &std::format!("a/{}", "b".repeat(MAX_PROGRAM - 1)),
            ),
            ("pages", "0"),
            ("pages", "262145"),
            ("pages", "-1"),
            ("pages", "+1"),
            ("pages", "1 2"),
            ("pages", "4294967296"),
            ("pages", "99999999999"),
            ("pages", "02"),
            ("models", "0"),
            ("models", "32"),
            ("models", "1,1"),
            ("models", "1,"),
            ("models", ",1"),
            ("models", "1 2"),
            ("attempts", "0"),
            ("attempts", "11"),
            ("progress_ms", "0"),
            ("progress_ms", "3600001"),
            ("task_ms", "0"),
            ("task_ms", "86400001"),
            ("data", ""),
            ("data", "Read"),
            ("data", "rw"),
            ("net", "10.0.2.2"),
            ("net", "10.0.2.2:0"),
            ("net", "10.0.2.2:65536"),
            ("net", "10.0.2.256:1"),
            ("net", "10.0.2:1"),
            ("net", "10.0.2.2.1:1"),
            ("net", "10.0.2.2:01"),
            ("net", "10.0.2.2:1,"),
            ("net", "10.0.2.2:1,10.0.2.2:1"),
            ("net", "1.1.1.1:1,1.1.1.1:2,1.1.1.1:3,1.1.1.1:4,1.1.1.1:5"),
            ("net", "net 10.0.2.2:1"),
        ] {
            assert_eq!(
                why(with(key, value).as_bytes()),
                Some(Why::BadValue),
                "{key} = {value:?}"
            );
        }
        for line in [
            "tools = shell",
            "tools = read_file, read_file",
            "tools = read_file,",
            "tools = Read_file",
            "files = ../secrets.txt",
            "files = a/b",
            "files = .hidden",
            "files = a, a",
            "files = a,",
            "files = a, b, c, d, e",
            "files = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "channels = a.b",
            "channels = a, a",
            "channels = a b",
        ] {
            assert_eq!(why(plus(line).as_bytes()), Some(Why::BadValue), "{line}");
        }
        assert_eq!(
            why(std::format!("{}tools =\ntools =\n", std::str::from_utf8(S).unwrap()).as_bytes()),
            Some(Why::RepeatedKey)
        );
        assert_eq!(
            why(with("progress_ms", "600001").as_bytes()),
            Some(Why::ProgressOverTask)
        );
        assert!(
            parse(with("progress_ms", "600000").as_bytes()).is_ok(),
            "equal"
        );
    }

    #[test]
    fn checked_against_the_policy() {
        let check = |key: &str, value: &str| {
            let text = with(key, value);
            parse(text.as_bytes()).unwrap().within(TABLE).map(|_| ())
        };
        assert_eq!(parse(S).unwrap().within(TABLE), Ok(&TABLE[0]));
        assert_eq!(check("pages", "4096"), Ok(()), "the entry's maximum");
        assert_eq!(check("models", "2, 1"), Ok(()));
        assert_eq!(check("models", ""), Ok(()));
        assert_eq!(check("data", "none"), Ok(()), "less than the entry");
        assert_eq!(check("net", ""), Ok(()));
        assert_eq!(check("net", "10.0.2.3:53, 10.0.2.2:47000"), Ok(()));
        assert_eq!(check("name", "other"), Err(Why::NoEntry));
        assert_eq!(check("program", "agents/other"), Err(Why::WrongProgram));
        for (key, value) in [
            ("pages", "4097"),
            ("models", "3"),
            ("models", "1, 3"),
            ("attempts", "4"),
            ("progress_ms", "30001"),
            ("task_ms", "600001"),
            ("data", "write"),
            ("net", "10.0.2.2:47001"),
            ("net", "10.0.2.2:47000, 10.0.2.4:53"),
        ] {
            assert_eq!(check(key, value), Err(Why::OverPolicy), "{key} = {value}");
        }
        assert_eq!(parse(S).unwrap().within(&[]), Err(Why::NoEntry));
        let check = |line: &str| {
            parse(plus(line).as_bytes())
                .unwrap()
                .within(TABLE)
                .map(|_| ())
        };
        assert_eq!(check("tools = read_file"), Ok(()));
        assert_eq!(check("files = notes, report.txt"), Ok(()));
        assert_eq!(
            check("tools = send"),
            Err(Why::OverPolicy),
            "a tool not listed"
        );
        assert_eq!(
            check("files = secrets.txt"),
            Err(Why::OverPolicy),
            "a file not listed"
        );
        assert_eq!(check("channels = listener"), Ok(()));
        assert_eq!(
            check("channels = boss"),
            Err(Why::OverPolicy),
            "a channel not listed"
        );
    }

    #[test]
    fn fuzzed() {
        // Bytes from a manifest's alphabet, then mutations of a valid one.
        let alphabet = b"manifest=1\n #,.0/_-pgsoidkr:";
        crate::fuzz(100_000, alphabet.len() as u8, |m| {
            let text: std::vec::Vec<u8> = m.iter().map(|b| alphabet[usize::from(*b)]).collect();
            let _ = parse(&text);
            let _ = parse(m);
        });
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..100_000 {
            let mut text = S.to_vec();
            for _ in 0..1 + x % 4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize >> 8) % text.len();
                text[i] = x as u8;
            }
            if let Ok(m) = parse(&text) {
                assert!(valid_name(m.name) && valid_program(m.program));
                assert!(m.attempts <= MAX_ATTEMPTS && m.progress_ms <= m.task_ms);
                assert_eq!(m.models & 1, 0, "no model 0");
                let mut out = [0u8; MAX_SIZE];
                let n = m.encode(&mut out).unwrap();
                assert_eq!(parse(&out[..n]), Ok(m));
                let _ = m.within(TABLE);
            }
        }
    }
}
