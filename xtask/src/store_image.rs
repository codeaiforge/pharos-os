//! `cargo xtask store`: build and list writable-store images (storage.md
//! part 8), with the same `pharos-store` code the storage service runs.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use pharos_store::{BLOCK, Block, Device, IoError, Kind, Store};

use crate::Result;

/// A store image file as a block device.
pub struct FileDevice {
    file: File,
    blocks: u64,
}

impl FileDevice {
    /// Creates `path` (replacing it) with `blocks` zeroed blocks.
    pub fn create(path: &Path, blocks: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        file.set_len(blocks * BLOCK as u64)
            .map_err(|e| format!("cannot size {}: {e}", path.display()))?;
        Ok(Self { file, blocks })
    }

    /// Opens an existing image.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let len = file
            .metadata()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .len();
        Ok(Self {
            file,
            blocks: len / BLOCK as u64,
        })
    }
}

impl Device for FileDevice {
    fn blocks(&self) -> u64 {
        self.blocks
    }
    fn read(&mut self, block: u64, buf: &mut Block) -> std::result::Result<(), IoError> {
        self.file
            .seek(SeekFrom::Start(block * BLOCK as u64))
            .and_then(|_| self.file.read_exact(buf))
            .map_err(|_| IoError)
    }
    fn write(&mut self, block: u64, buf: &Block) -> std::result::Result<(), IoError> {
        self.file
            .seek(SeekFrom::Start(block * BLOCK as u64))
            .and_then(|_| self.file.write_all(buf))
            .map_err(|_| IoError)
    }
    fn flush(&mut self) -> std::result::Result<(), IoError> {
        self.file.sync_data().map_err(|_| IoError)
    }
}

/// Writes an empty, formatted store of `blocks` blocks at `path`.
pub fn fresh(path: &Path, blocks: u64) -> Result<()> {
    Store::format(FileDevice::create(path, blocks)?)
        .map(drop)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Regular files under `dir` as (store path, host path), sorted. Links and
/// special files are refused, as for `fs build`.
fn files(dir: &Path, prefix: &str, out: &mut Vec<(String, std::path::PathBuf)>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("{}: name is not UTF-8: {n:?}", dir.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if kind.is_dir() {
            files(&path, &format!("{prefix}{name}/"), out)?;
        } else if kind.is_file() {
            out.push((format!("{prefix}{name}"), path));
        } else {
            return Err(format!(
                "{}: only regular files and directories can go into a store",
                path.display()
            ));
        }
    }
    out.sort();
    Ok(())
}

/// `cargo xtask store build <dir> <image> --blocks <n>`: a fresh store of
/// `blocks` blocks holding every regular file under `dir`.
pub fn build(dir: &Path, image: &Path, blocks: u64) -> Result<()> {
    let mut list = Vec::new();
    files(dir, "", &mut list)?;
    let mut store = Store::format(FileDevice::create(image, blocks)?)
        .map_err(|e| format!("{}: {e}", image.display()))?;
    for (path, host) in &list {
        let data = fs::read(host).map_err(|e| format!("cannot read {}: {e}", host.display()))?;
        store
            .write(path.as_bytes(), &data)
            .map_err(|e| format!("{path}: {e}"))?;
    }
    println!(
        "Store: {} ({} objects, {} of {blocks} blocks free)",
        image.display(),
        list.len(),
        store.free_blocks()
    );
    Ok(())
}

/// `cargo xtask store ls <image>`: mounts with the service's code, checks
/// every object, and lists them. Fails on the first problem.
pub fn ls(image: &Path) -> Result<()> {
    let mut store =
        Store::mount(FileDevice::open(image)?).map_err(|e| format!("{}: {e}", image.display()))?;
    println!(
        "generation {}, {} blocks free",
        store.generation(),
        store.free_blocks()
    );
    println!("{:<6}  {:>10}  {:>7}  path", "kind", "bytes", "records");
    let paths: Vec<Vec<u8>> = store.list(b"").map(<[u8]>::to_vec).collect();
    for path in paths {
        let name = String::from_utf8_lossy(&path).into_owned();
        let info = store.stat(&path).map_err(|e| format!("{name}: {e}"))?;
        match info.kind {
            Kind::File => {
                let mut data = vec![0u8; info.len as usize];
                store
                    .read(&path, 0, &mut data)
                    .map_err(|e| format!("{name}: {e}"))?;
                println!("{:<6}  {:>10}  {:>7}  {name}", "file", info.len, "-");
            }
            Kind::Stream => {
                store
                    .records(&path, |_| {})
                    .map_err(|e| format!("{name}: {e}"))?;
                println!(
                    "{:<6}  {:>10}  {:>7}  {name}",
                    "stream", info.len, info.records
                );
            }
        }
    }
    Ok(())
}

/// `cargo xtask store audit <image>`: every audit stream, `audit/log/<n>`,
/// read with the store's checks (each record's CRC-32 and chain value, the
/// head), then each record checked as `pharos_proto::audit` defines it:
/// it parses, sequence numbers run from 0, and record 0 is the audit
/// service's `boot` event. Returns each stream's name and its records as
/// text lines, or the first problem.
pub fn audit(image: &Path) -> Result<Vec<(String, Vec<String>)>> {
    use pharos_proto::audit::{Kind as RecordKind, Record, action, client};
    let mut store =
        Store::mount(FileDevice::open(image)?).map_err(|e| format!("{}: {e}", image.display()))?;
    let paths: Vec<Vec<u8>> = store.list(b"audit/log/").map(<[u8]>::to_vec).collect();
    let mut out = Vec::new();
    for path in paths {
        let name = String::from_utf8_lossy(&path).into_owned();
        let mut lines = Vec::new();
        let mut problem = None;
        store
            .records(&path, |bytes| {
                let n = lines.len() as u64;
                let Some(r) = Record::parse(bytes) else {
                    problem.get_or_insert(format!("record {n} is not an audit record"));
                    return;
                };
                if r.sequence != n {
                    problem.get_or_insert(format!("record {n} has sequence number {}", r.sequence));
                }
                let boot = r.client == client::AUDIT
                    && r.entry.action == action::BOOT
                    && r.entry.kind == RecordKind::Event;
                if (n == 0) != boot {
                    problem.get_or_insert(format!("record {n}: a boot record only comes first"));
                }
                let e = r.entry;
                let mut t = [0u8; 32];
                let permission = e
                    .permission
                    .map(|p| String::from_utf8_lossy(p.text(&mut t)).into_owned())
                    .unwrap_or_default();
                lines.push(format!(
                    "#{} {:.3} s client {} {:?}{} {} {} task {}/{} {} {} outcome {} {}",
                    r.sequence,
                    r.time as f64 / 1e6,
                    r.client,
                    e.kind,
                    if e.refers != 0 {
                        format!(" of #{}", e.refers)
                    } else {
                        String::new()
                    },
                    action::name(e.action),
                    String::from_utf8_lossy(e.actor),
                    e.task,
                    e.attempt,
                    permission,
                    String::from_utf8_lossy(e.service),
                    e.outcome,
                    String::from_utf8_lossy(e.detail),
                ));
            })
            .map_err(|e| format!("{name}: {e}"))?;
        if let Some(p) = problem {
            return Err(format!("{name}: {p}"));
        }
        out.push((name, lines));
    }
    Ok(out)
}

/// The chain value after the first record of the stream at `path`:
/// SHA-256 of 32 zero bytes and the record (D-017).
pub fn first_chain_value(image: &Path, path: &[u8]) -> Result<[u8; 32]> {
    let mut store =
        Store::mount(FileDevice::open(image)?).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut first = None;
    store
        .records(path, |bytes| {
            first.get_or_insert_with(|| pharos_store::sha256(&[&[0u8; 32], bytes]));
        })
        .map_err(|e| format!("{}: {e}", String::from_utf8_lossy(path)))?;
    first.ok_or_else(|| format!("{} is empty", String::from_utf8_lossy(path)))
}

/// Size of the M3.1 target model, Qwen2.5-0.5B-Instruct q8_0
/// (inference-evaluation.md).
pub const MODEL_LEN: usize = 675_710_816;

/// A GGUF file of at least [`MODEL_LEN`] bytes: one Q8_0 tensor of
/// pseudo-random bytes (not zeros, which fresh memory already holds).
pub fn synthetic_gguf() -> Vec<u8> {
    fn string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend((s.len() as u64).to_le_bytes());
        out.extend(s);
    }
    let blocks = MODEL_LEN.div_ceil(34) as u64;
    let mut out = b"GGUF".to_vec();
    out.extend(3u32.to_le_bytes());
    out.extend(1u64.to_le_bytes()); // tensors
    out.extend(1u64.to_le_bytes()); // metadata keys
    string(&mut out, b"general.architecture");
    out.extend(8u32.to_le_bytes()); // string
    string(&mut out, b"pharos-test");
    string(&mut out, b"data");
    out.extend(1u32.to_le_bytes()); // dimensions
    out.extend((blocks * 32).to_le_bytes());
    out.extend(8u32.to_le_bytes()); // Q8_0
    out.extend(0u64.to_le_bytes()); // offset
    out.resize(out.len().div_ceil(32) * 32, 0);
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    out.extend((0..blocks * 34 / 8).flat_map(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x.to_le_bytes()
    }));
    out.resize(out.len() + (blocks * 34 % 8) as usize, 0x5a);
    out
}

/// Writes a store at `path` holding `models/model.gguf` (`model`, or
/// [`synthetic_gguf`]) and `models/model.sha256`, its raw hash.
pub fn model(path: &Path, model: Option<&Path>) -> Result<()> {
    let data = match model {
        Some(m) => fs::read(m).map_err(|e| format!("cannot read {}: {e}", m.display()))?,
        None => synthetic_gguf(),
    };
    let hash = pharos_store::sha256(&[&data]);
    write_files(
        path,
        &[
            (b"models/model.gguf", &data),
            (b"models/model.sha256", &hash),
        ],
    )?;
    let source = model.map_or("generated".to_owned(), |m| m.display().to_string());
    println!("  model store: {} bytes from {source}", data.len());
    Ok(())
}

/// A fresh store at `path`, just big enough, holding `files`.
fn write_files(path: &Path, files: &[(&[u8], &[u8])]) -> Result<()> {
    let len: usize = files.iter().map(|(_, d)| d.len()).sum();
    let blocks = (len as u64).div_ceil(BLOCK as u64) + 256;
    let mut store = Store::format(FileDevice::create(path, blocks)?)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    for (name, bytes) in files {
        store
            .write(name, bytes)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

/// `pharos-infer`'s math functions from `libm`, as user programs supply
/// them (`pharos_programs::fp::Libm`), so the host's reference output
/// comes from the same arithmetic as Pharos's.
struct Libm;

impl pharos_infer::Math for Libm {
    fn sqrt(&self, x: f32) -> f32 {
        libm::sqrtf(x)
    }
    fn exp(&self, x: f32) -> f32 {
        libm::expf(x)
    }
    fn sin(&self, x: f32) -> f32 {
        libm::sinf(x)
    }
    fn cos(&self, x: f32) -> f32 {
        libm::cosf(x)
    }
    fn powf(&self, x: f32, y: f32) -> f32 {
        libm::powf(x, y)
    }
}

/// The host's output for the tiny model: the logit hash, then each
/// generated token as a little-endian `u32`.
pub fn expected_tiny(model: &[u8]) -> Result<Vec<u8>> {
    let (tokens, hash) =
        pharos_infer::synth::run_tiny(model, &Libm).map_err(|e| format!("tiny model: {e}"))?;
    let mut out = hash.to_le_bytes().to_vec();
    for t in tokens {
        out.extend((t as u32).to_le_bytes());
    }
    Ok(out)
}

/// Writes a store at `path` holding the tiny Qwen2 model
/// (`pharos_infer::synth::tiny_model`) as `models/tiny.gguf` and the host's
/// output for it as `models/tiny.expected` (`inference_tiny` test kernel, #87).
pub fn tiny(path: &Path) -> Result<()> {
    let model = pharos_infer::synth::tiny_model(pharos_infer::synth::TINY_SEED, false, false);
    let expected = expected_tiny(&model)?;
    write_files(
        path,
        &[
            (b"models/tiny.gguf", &model),
            (b"models/tiny.expected", &expected),
        ],
    )?;
    println!(
        "  tiny model store: {} bytes, host output {}",
        model.len(),
        hex(&expected)
    );
    Ok(())
}

/// The inference service test's prompt and token count (`inferclient`).
pub const SERVICE_PROMPT: &str = "hello hello";
pub const SERVICE_NEW: usize = 20;

/// The text the service must return for [`SERVICE_PROMPT`] with the test
/// model: the same `pharos-infer` session code and `libm` math.
pub fn expected_service(model: &[u8]) -> Result<Vec<u8>> {
    use pharos_infer::session::{Engine, Session};
    let g = pharos_infer::gguf::Gguf::parse(model).map_err(|e| format!("test model: {e}"))?;
    let e = Engine::load(&g).map_err(|e| format!("test model: {e}"))?;
    let prompt = e.tokenizer.encode(SERVICE_PROMPT);
    let mut s =
        Session::new(&e, &prompt, SERVICE_NEW, &Libm).map_err(|e| format!("test model: {e}"))?;
    let mut text = Vec::new();
    while s.step(&mut text, &Libm) {}
    Ok(text)
}

/// Writes a store at `path` holding the inference service's test model as
/// `models/test.gguf`, the text it must generate as `models/test.expected`
/// (`inference` test kernel, #88), and two broken copies for manifest
/// models 3 and 4 (#89): `corrupt.gguf`, one byte changed, and
/// `short.gguf`, 32 bytes short.
pub fn service(path: &Path) -> Result<()> {
    let model = pharos_infer::synth::test_model();
    let expected = expected_service(&model)?;
    let mut corrupt = model.clone();
    corrupt[model.len() / 2] ^= 1;
    write_files(
        path,
        &[
            (b"models/test.gguf", &model),
            (b"models/test.expected", &expected),
            (b"models/corrupt.gguf", &corrupt),
            (b"models/short.gguf", &model[..model.len() - 32]),
        ],
    )?;
    println!(
        "  service test store: {} bytes, expected text {}",
        model.len(),
        hex(&expected)
    );
    Ok(())
}

/// Writes the `supervision` test kernel's store (#100): the service's test
/// model as `models/staged.gguf`, not under its manifest path, so the
/// first load fails at the read step until the client copies it, and
/// `models/test.expected`.
pub fn supervision(path: &Path) -> Result<()> {
    let model = pharos_infer::synth::test_model();
    let expected = expected_service(&model)?;
    write_files(
        path,
        &[
            (b"models/staged.gguf", &model),
            (b"models/test.expected", &expected),
        ],
    )
}

/// Scenario S1's prompt and token count, as `scripts/bench-inference.py`'s
/// `summary` prompt (a host test checks they match).
pub const S1_REPORT: &str = include_str!("s1-report.txt");
pub const S1_NEW: usize = 128;

pub fn s1_prompt() -> String {
    format!("Summarize the following report in three sentences.\n\n{S1_REPORT}")
}

/// Writes a store at `path` holding the S1 model from `model` under its
/// manifest path, `models/s1.prompt`, and `models/s1.expected`: the text
/// `pharos-infer` generates on the host with `libm`, as on Pharos (#90).
/// Prints the host's own times for comparison.
pub fn s1(path: &Path, model: &Path) -> Result<()> {
    use pharos_infer::session::{Engine, Session};
    use std::time::Instant;
    let data = fs::read(model).map_err(|e| format!("cannot read {}: {e}", model.display()))?;
    println!(
        "  S1 model: {} bytes, SHA-256 {}",
        data.len(),
        hex(&pharos_store::sha256(&[&data]))
    );
    let start = Instant::now();
    let g = pharos_infer::gguf::Gguf::parse(&data).map_err(|e| format!("S1 model: {e}"))?;
    let e = Engine::load(&g).map_err(|e| format!("S1 model: {e}"))?;
    let load = start.elapsed();
    let prompt = s1_prompt();
    let tokens = e.tokenizer.encode(&prompt);
    let start = Instant::now();
    let mut s = Session::new(&e, &tokens, S1_NEW, &Libm).map_err(|e| format!("S1 model: {e}"))?;
    let prompt_time = start.elapsed();
    let start = Instant::now();
    let mut text = Vec::new();
    while s.step(&mut text, &Libm) {}
    let gen_time = start.elapsed();
    println!(
        "  host reference (1 thread, libm): load {:.2} s, prompt {} tokens in {:.2} s, {} tokens at {:.1} tokens/s",
        load.as_secs_f64(),
        tokens.len(),
        prompt_time.as_secs_f64(),
        s.generated(),
        s.generated() as f64 / gen_time.as_secs_f64()
    );
    println!("  host text: {:?}", String::from_utf8_lossy(&text));
    write_files(
        path,
        &[
            (b"models/qwen2.5-0.5b-instruct-q8_0.gguf", &data),
            (b"models/s1.prompt", prompt.as_bytes()),
            (b"models/s1.expected", &text),
        ],
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s1_prompt_is_the_benchmarks() {
        let script = include_str!("../../scripts/bench-inference.py");
        let report = script.split("REPORT = \"\"\"\\\n").nth(1).unwrap();
        assert_eq!(report.split("\"\"\"").next().unwrap(), S1_REPORT);
        assert!(script.contains(
            "(\"summary\", \"Summarize the following report in three sentences.\\n\\n\" + REPORT)"
        ));
        assert!(s1_prompt().len() < 4096, "fits the client's buffer");
    }

    #[test]
    fn tiny_model_and_its_output_are_pinned() {
        let model = pharos_infer::synth::tiny_model(pharos_infer::synth::TINY_SEED, false, false);
        assert_eq!(
            hex(&pharos_store::sha256(&[&model])),
            "f0df1f79c7e184e83430528b1c65e0a0db8456831168cf83b6fbec8c58b60ad3"
        );
        let expected = expected_tiny(&model).unwrap();
        assert_eq!(hex(&expected[..8]), "797e6c31bd5bd65b", "logit hash");
    }

    #[test]
    fn build_then_ls_round_trips_and_detects_damage() {
        // Under target/, like every xtask output.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/xtask")
            .join(format!("store-test-{}", std::process::id()));
        let dir = root.join("in");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::write(dir.join("models/m.bin"), vec![7u8; 10_000]).unwrap();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        let image = root.join("store.img");
        build(&dir, &image, 64).unwrap();
        ls(&image).unwrap();
        let mut store = Store::mount(FileDevice::open(&image).unwrap()).unwrap();
        let mut buf = vec![0u8; 10_000];
        assert_eq!(store.read(b"models/m.bin", 0, &mut buf), Ok(10_000));
        assert_eq!(store.list(b"").count(), 2);
        assert!(build(&dir, &image, 2).is_err(), "too small");
        // A store too small for its files is refused, not truncated.
        fs::write(dir.join("big"), vec![1u8; 100 * BLOCK]).unwrap();
        assert!(build(&dir, &image, 64).unwrap_err().contains("big"));
        // Damage both superblocks: ls reports it.
        build(&root.join("in/models"), &image, 16).unwrap();
        let mut bytes = fs::read(&image).unwrap();
        bytes[0] ^= 1;
        bytes[BLOCK] ^= 1;
        fs::write(&image, &bytes).unwrap();
        assert!(ls(&image).unwrap_err().contains("no valid superblock"));
        fs::remove_dir_all(&root).unwrap();
    }

    /// A store holding `audit/log/1` with these records, at `image`.
    fn audit_store(image: &Path, records: &[std::vec::Vec<u8>]) {
        let mut store = Store::format(FileDevice::create(image, 32).unwrap()).unwrap();
        for r in records {
            store.append(b"audit/log/1", r).unwrap();
        }
    }

    fn record(sequence: u64, client: u8, action: u8, detail: &'static [u8]) -> std::vec::Vec<u8> {
        use pharos_proto::audit::{Entry, Kind, Record, outcome};
        let rec = Record {
            sequence,
            time: 1,
            client,
            entry: Entry {
                kind: Kind::Event,
                refers: 0,
                actor: b"",
                task: 0,
                attempt: 0,
                action,
                permission: None,
                service: b"",
                outcome: outcome::OK,
                detail,
            },
        };
        let mut buf = [0u8; 256];
        let n = rec.encode(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn audit_trails_are_checked() {
        use pharos_proto::audit::{action, client};
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/xtask")
            .join(format!("audit-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let image = root.join("store.img");
        let boot = record(0, client::AUDIT, action::BOOT, b"");
        audit_store(
            &image,
            &[boot.clone(), record(1, 4, action::SUBMIT, b"MARK")],
        );
        let streams = audit(&image).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].1.len(), 2);
        assert!(streams[0].1[1].contains("client 4") && streams[0].1[1].contains("MARK"));
        let first = first_chain_value(&image, b"audit/log/1").unwrap();
        assert_eq!(first, pharos_store::sha256(&[&[0u8; 32], &boot]));
        // A changed byte in a stored record breaks its CRC and chain.
        let mut bytes = fs::read(&image).unwrap();
        let at = bytes.windows(4).position(|w| w == b"MARK").unwrap();
        bytes[at] ^= 1;
        fs::write(&image, &bytes).unwrap();
        assert!(audit(&image).is_err(), "tampered");
        // A gap in sequence numbers, a missing or late boot record, and a
        // record that is not one are each reported.
        for (records, problem) in [
            (
                std::vec![boot.clone(), record(2, 4, action::SUBMIT, b"")],
                "sequence number",
            ),
            (std::vec![record(0, 4, action::SUBMIT, b"")], "boot record"),
            (
                std::vec![boot.clone(), record(1, client::AUDIT, action::BOOT, b"")],
                "boot record",
            ),
            (
                std::vec![boot.clone(), b"junk".to_vec()],
                "not an audit record",
            ),
        ] {
            audit_store(&image, &records);
            let err = audit(&image).unwrap_err();
            assert!(err.contains(problem), "{err}");
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
