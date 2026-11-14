//! Host tests: SHA-256 vectors, round trips, every slot corruption, the
//! allocation rule, crash consistency at every write, and fuzzing.

extern crate std;

use super::*;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

/// A write or a flush, in order.
#[derive(Clone)]
enum Op {
    Write(u64, Box<Block>),
    Flush,
}

/// A RAM device that logs every write and flush.
#[derive(Clone)]
struct Mem {
    data: Vec<u8>,
    log: Vec<Op>,
}

impl Mem {
    fn new(blocks: u64) -> Self {
        Self {
            data: vec![0; blocks as usize * BLOCK],
            log: Vec::new(),
        }
    }
}

impl Device for Mem {
    fn blocks(&self) -> u64 {
        (self.data.len() / BLOCK) as u64
    }
    fn read(&mut self, block: u64, buf: &mut Block) -> Result<(), IoError> {
        let at = block as usize * BLOCK;
        buf.copy_from_slice(self.data.get(at..at + BLOCK).ok_or(IoError)?);
        Ok(())
    }
    fn write(&mut self, block: u64, buf: &Block) -> Result<(), IoError> {
        let at = block as usize * BLOCK;
        self.data
            .get_mut(at..at + BLOCK)
            .ok_or(IoError)?
            .copy_from_slice(buf);
        self.log.push(Op::Write(block, Box::new(*buf)));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), IoError> {
        self.log.push(Op::Flush);
        Ok(())
    }
}

/// Everything a store holds: file contents, and each stream's records.
type State = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

fn state(store: &mut Store<Mem>) -> Result<State, Error> {
    let paths: Vec<Vec<u8>> = store.list(b"").map(<[u8]>::to_vec).collect();
    let mut out = State::new();
    for p in paths {
        let info = store.stat(&p)?;
        let mut items = Vec::new();
        match info.kind {
            Kind::File => {
                let mut buf = vec![0u8; info.len as usize];
                store.read(&p, 0, &mut buf)?;
                items.push(buf);
            }
            Kind::Stream => store.records(&p, |r| items.push(r.to_vec()))?,
        }
        out.insert(p, items);
    }
    Ok(out)
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A store with two files and a stream of three records.
fn sample() -> Store<Mem> {
    let mut s = Store::format(Mem::new(64)).unwrap();
    s.write(b"models/a.bin", &bytes(10_000, 1)).unwrap();
    s.write(b"notes.txt", b"hello").unwrap();
    for r in [&b"one"[..], b"two", &bytes(3000, 9)] {
        s.append(b"audit/log", r).unwrap();
    }
    s
}

#[test]
fn sha256_matches_fips_180_4_vectors() {
    let hex = |h: [u8; 32]| {
        h.iter()
            .map(|b| std::format!("{b:02x}"))
            .collect::<std::string::String>()
    };
    assert_eq!(
        hex(sha256(&[b"abc"])),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(sha256(&[])),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(sha256(&[
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        ])),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let million = vec![b'a'; 1_000_000];
    assert_eq!(
        hex(sha256(&[&million[..400_001], &million[400_001..]])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn objects_round_trip_through_a_remount() {
    let s = sample();
    let generation = s.generation();
    let before_free = s.free_blocks();
    let mut s = Store::mount(s.into_device()).unwrap();
    assert_eq!(s.generation(), generation);
    assert_eq!(
        s.free_blocks(),
        before_free,
        "both generations still reserved"
    );
    let st = state(&mut s).unwrap();
    assert_eq!(st[&b"models/a.bin"[..]], [bytes(10_000, 1)]);
    assert_eq!(st[&b"notes.txt"[..]], [b"hello".to_vec()]);
    assert_eq!(
        st[&b"audit/log"[..]],
        [b"one".to_vec(), b"two".to_vec(), bytes(3000, 9)]
    );
    let info = s.stat(b"audit/log").unwrap();
    assert_eq!(info.records, 3);
    let h1 = sha256(&[&[0; 32], b"one"]);
    let h2 = sha256(&[&h1, b"two"]);
    assert_eq!(info.head, sha256(&[&h2, &bytes(3000, 9)]), "the chain");
    let mut part = [0u8; 100];
    assert_eq!(s.read(b"models/a.bin", 9_950, &mut part), Ok(50));
    assert_eq!(part[..50], bytes(10_000, 1)[9_950..]);
    assert_eq!(
        s.list(b"models/").collect::<Vec<_>>(),
        [&b"models/a.bin"[..]]
    );
    // Replace, delete, and the errors.
    s.write(b"notes.txt", b"bye").unwrap();
    s.delete(b"models/a.bin").unwrap();
    assert_eq!(s.stat(b"models/a.bin"), Err(Error::NotFound));
    assert_eq!(s.delete(b"models/a.bin"), Err(Error::NotFound));
    assert_eq!(s.write(b"audit/log", b"x"), Err(Error::WrongKind));
    assert_eq!(s.append(b"notes.txt", b"x"), Err(Error::WrongKind));
    assert_eq!(s.append(b"audit/log", b""), Err(Error::TooLarge));
    assert_eq!(
        s.append(b"audit/log", &[1; MAX_RECORD + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(s.write(b"../x", b"x"), Err(Error::BadPath));
    assert_eq!(s.read(b"audit/log", 0, &mut part), Err(Error::WrongKind));
    let mut s = Store::mount(s.into_device()).unwrap();
    assert_eq!(state(&mut s).unwrap()[&b"notes.txt"[..]], [b"bye".to_vec()]);
    assert_eq!(
        s.write(b"empty", b""),
        Ok(()),
        "an empty file has no blocks"
    );
    assert_eq!(s.read(b"empty", 0, &mut part), Ok(0));
}

#[test]
fn a_full_store_refuses_before_writing_anything() {
    let mut s = Store::format(Mem::new(8)).unwrap();
    let mut dev = s.into_device();
    dev.log.clear();
    s = Store::mount(dev).unwrap();
    // 4 free data blocks after the index: 5 blocks cannot fit.
    assert_eq!(s.write(b"big", &[7; 5 * BLOCK]), Err(Error::NoSpace));
    let dev = s.into_device();
    assert!(dev.log.is_empty(), "nothing written");
    let mut s = Store::mount(dev).unwrap();
    assert_eq!(s.write(b"fits", &[7; 2 * BLOCK]), Ok(()));
}

#[test]
fn long_streams_stay_within_the_extent_limit() {
    let mut s = Store::format(Mem::new(600)).unwrap();
    // Interleave two streams so their tails fragment.
    for i in 0..400u32 {
        let r = bytes(1500, i as u8);
        s.append(b"a", &r).unwrap();
        s.append(b"b", &i.to_le_bytes()).unwrap();
    }
    let mut s = Store::mount(s.into_device()).unwrap();
    let mut n = 0;
    s.records(b"a", |r| {
        assert_eq!(r, bytes(1500, n as u8));
        n += 1;
    })
    .unwrap();
    assert_eq!(n, 400);
    let o = s.object(b"a").unwrap();
    assert!(o.extents.len() <= MAX_EXTENTS);
}

/// Rewrites slot `slot` of `dev` through `f`; `fix` recomputes its CRC.
fn edit_slot(dev: &mut Mem, slot: u64, fix: bool, f: impl FnOnce(&mut [u8])) {
    let at = slot as usize * BLOCK;
    f(&mut dev.data[at..at + BLOCK]);
    if fix {
        let crc = crc32(&dev.data[at..at + SB_CRC]);
        dev.data[at + SB_CRC..at + SB_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    }
}

/// Replaces the index of the current slot with `f(index)`, fixing both
/// CRCs, so the corruption reaches the index checks.
fn edit_index(dev: &mut Mem, slot: u64, f: impl FnOnce(&mut Vec<u8>)) {
    let sb = slot as usize * BLOCK;
    let start = u64_at(&dev.data, sb + 32) as usize;
    let len = u32_at(&dev.data, sb + 44) as usize;
    let mut index = dev.data[start * BLOCK..start * BLOCK + len].to_vec();
    f(&mut index);
    assert!(index.len() <= BLOCK, "test indexes fit one block");
    dev.data[start * BLOCK..start * BLOCK + BLOCK].fill(0);
    dev.data[start * BLOCK..start * BLOCK + index.len()].copy_from_slice(&index);
    let crc = crc32(&index);
    edit_slot(dev, slot, true, |b| {
        b[44..48].copy_from_slice(&(index.len() as u32).to_le_bytes());
        b[48..52].copy_from_slice(&crc.to_le_bytes());
    });
}

#[test]
fn every_slot_corruption_is_detected_with_its_error() {
    use SlotError::*;
    let s = sample();
    let slot = s.slot;
    let good = s.into_device();
    let check = |what: &str, want: SlotError, f: &dyn Fn(&mut Mem)| {
        let mut dev = good.clone();
        f(&mut dev);
        assert_eq!(read_slot(&mut dev, slot).map(|_| ()), Err(want), "{what}");
    };
    check("magic", BadMagic, &|d| {
        edit_slot(d, slot, true, |b| b[0] = b'X')
    });
    check("version", BadVersion, &|d| {
        edit_slot(d, slot, true, |b| b[8] = 2)
    });
    check("block size", BadBlockSize, &|d| {
        edit_slot(d, slot, true, |b| b[13] = 0x20)
    });
    check("slot CRC", SlotCrc, &|d| {
        edit_slot(d, slot, false, |b| b[20] ^= 1)
    });
    check("total blocks", OutOfRange, &|d| {
        edit_slot(d, slot, true, |b| {
            b[24..32].copy_from_slice(&1000u64.to_le_bytes())
        })
    });
    check("index start", OutOfRange, &|d| {
        edit_slot(d, slot, true, |b| {
            b[32..40].copy_from_slice(&1u64.to_le_bytes())
        })
    });
    check("index length", OutOfRange, &|d| {
        edit_slot(d, slot, true, |b| {
            b[44..48].copy_from_slice(&5000u32.to_le_bytes())
        })
    });
    check("index CRC", IndexCrc, &|d| {
        edit_slot(d, slot, true, |b| b[48] ^= 1)
    });
    check("index truncated", Truncated, &|d| {
        edit_index(d, slot, |i| i.truncate(i.len() - 3))
    });
    check("index trailing bytes", Truncated, &|d| {
        edit_index(d, slot, |i| i.extend_from_slice(&[0; 4]))
    });
    check("object count", TooManyObjects, &|d| {
        edit_index(d, slot, |i| i[..4].copy_from_slice(&5000u32.to_le_bytes()))
    });
    // Entries are sorted: "audit/log", "models/a.bin", "notes.txt".
    let first_path = 5;
    check("path", BadPath, &|d| {
        edit_index(d, slot, |i| i[first_path] = b'/')
    });
    check("order", Unsorted, &|d| {
        edit_index(d, slot, |i| i[first_path] = b'z')
    });
    let kind = first_path + 9;
    check("kind", BadKind, &|d| edit_index(d, slot, |i| i[kind] = 3));
    // Stream entry: kind, len 8, crc 4, records 8, head 32, extent count.
    let extents = kind + 1 + 8 + 4 + 8 + 32;
    check("extent count", TooManyExtents, &|d| {
        edit_index(d, slot, |i| {
            i[extents..extents + 2].copy_from_slice(&65u16.to_le_bytes())
        })
    });
    let first = extents + 2;
    check("extent in a superblock", BadExtent, &|d| {
        edit_index(d, slot, |i| {
            i[first..first + 8].copy_from_slice(&1u64.to_le_bytes())
        })
    });
    check("extent past the end", BadExtent, &|d| {
        edit_index(d, slot, |i| {
            i[first..first + 8].copy_from_slice(&64u64.to_le_bytes())
        })
    });
    check("empty extent", BadExtent, &|d| {
        edit_index(d, slot, |i| i[first + 8..first + 12].fill(0))
    });
    check("length", LengthMismatch, &|d| {
        edit_index(d, slot, |i| {
            i[kind + 1..kind + 9].copy_from_slice(&50_000u64.to_le_bytes())
        })
    });
    let index_start = u64_at(&good.data, slot as usize * BLOCK + 32);
    check("block shared with the index", SharedBlock, &|d| {
        edit_index(d, slot, |i| {
            i[first..first + 8].copy_from_slice(&index_start.to_le_bytes())
        })
    });
    // Mount reports both slots when neither is valid.
    let mut dev = good.clone();
    edit_slot(&mut dev, 0, false, |b| b[0] = 0);
    edit_slot(&mut dev, 1, false, |b| b[0] = 0);
    assert!(matches!(
        Store::mount(dev),
        Err(Error::NoStore(BadMagic, BadMagic))
    ));
}

#[test]
fn an_altered_chain_value_is_detected() {
    let mut s = Store::format(Mem::new(16)).unwrap();
    // Two blocks: the first record's block is not the tail.
    s.append(b"log", &bytes(3000, 1)).unwrap();
    s.append(b"log", &bytes(3000, 2)).unwrap();
    let first = s.object(b"log").unwrap().extents[0].start as usize;
    let mut dev = s.into_device();
    dev.data[first * BLOCK + 8] ^= 1; // the first record's stored chain value
    let mut s = Store::mount(dev).unwrap();
    assert_eq!(s.records(b"log", |_| {}), Err(Error::Corrupt));
}

#[test]
fn corrupted_content_fails_its_checks() {
    let s = sample();
    let o = s.object(b"models/a.bin").unwrap().extents[0];
    let tail = *s.object(b"audit/log").unwrap().extents.last().unwrap();
    let mut dev = s.into_device();
    dev.data[o.start as usize * BLOCK + 7] ^= 1;
    dev.data[(tail.start + u64::from(tail.count) - 1) as usize * BLOCK + 45] ^= 1;
    let mut s = Store::mount(dev).unwrap();
    let mut buf = vec![0u8; 10_000];
    assert_eq!(s.read(b"models/a.bin", 0, &mut buf), Err(Error::Corrupt));
    assert_eq!(s.records(b"audit/log", |_| {}), Err(Error::Corrupt));
    assert_eq!(
        s.append(b"audit/log", b"more"),
        Err(Error::Corrupt),
        "a bad tail is not copied"
    );
    let mut buf = [0u8; 10];
    assert_eq!(
        s.read(b"models/a.bin", 0, &mut buf),
        Ok(10),
        "partial reads are not checked"
    );
}

#[test]
fn commits_never_write_blocks_of_the_two_newest_generations() {
    let mut s = Store::format(Mem::new(200)).unwrap();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..300 {
        let protected: BTreeSet<u64> = (0..s.used.len() as u64)
            .filter(|&b| s.used[b as usize])
            .collect();
        let mut dev = s.into_device();
        dev.log.clear();
        s = Store::mount(dev).unwrap();
        let path = [b'a' + (next() % 6) as u8];
        let result = match next() % 4 {
            0 => s.write(&path, &bytes((next() % 20_000) as usize, round as u8)),
            1 | 2 => s
                .append(b"log", &bytes(1 + (next() % 2000) as usize, round as u8))
                .map(|_| ()),
            _ => s.delete(&path),
        };
        assert!(
            matches!(result, Ok(()) | Err(Error::NotFound | Error::NoSpace)),
            "{result:?}"
        );
        let dev = s.into_device();
        for op in &dev.log {
            if let Op::Write(b, _) = op {
                assert!(
                    *b < 2 || !protected.contains(b),
                    "round {round}: block {b} was live"
                );
            }
        }
        s = Store::mount(dev).unwrap();
    }
}

/// The image after a crash during `log` (applied to `base`) at write
/// `cut`: writes before the last flush before `cut` are durable; of the
/// writes after it, `mode` picks which reached the disk: all, none, the
/// last, the first, all but the first (a cache that reordered), or all with
/// the last torn (its first half lands).
fn crashed(base: &Mem, log: &[Op], cut: usize, mode: u8) -> Mem {
    let mut dev = base.clone();
    let writes: Vec<(usize, &Op)> = log
        .iter()
        .enumerate()
        .filter(|(_, o)| matches!(o, Op::Write(..)))
        .collect();
    let cut_at = writes.get(cut).map_or(log.len(), |(i, _)| *i);
    let last_flush = log[..cut_at]
        .iter()
        .rposition(|o| matches!(o, Op::Flush))
        .map_or(0, |i| i + 1);
    let put = |dev: &mut Mem, op: &Op, half: bool| {
        if let Op::Write(b, data) = op {
            let at = *b as usize * BLOCK;
            let n = if half { BLOCK / 2 } else { BLOCK };
            dev.data[at..at + n].copy_from_slice(&data[..n]);
        }
    };
    for op in &log[..last_flush] {
        put(&mut dev, op, false);
    }
    let pending: Vec<&Op> = log[last_flush..cut_at]
        .iter()
        .filter(|o| matches!(o, Op::Write(..)))
        .collect();
    match mode {
        0 => pending.iter().for_each(|op| put(&mut dev, op, false)),
        1 => {}
        2 => pending
            .last()
            .into_iter()
            .for_each(|op| put(&mut dev, op, false)),
        3 => pending
            .first()
            .into_iter()
            .for_each(|op| put(&mut dev, op, false)),
        4 => pending
            .iter()
            .skip(1)
            .for_each(|op| put(&mut dev, op, false)),
        _ => {
            if let Some((last, rest)) = pending.split_last() {
                rest.iter().for_each(|op| put(&mut dev, op, false));
                put(&mut dev, last, true);
            }
        }
    }
    dev
}

/// Runs `op` on a store holding `sample()`'s contents and checks that a
/// crash at every write, in every mode, mounts as the old or new state.
fn check_crashes(name: &str, op: impl Fn(&mut Store<Mem>) -> Result<(), Error>) {
    let base = sample().into_device();
    let mut s = Store::mount(base.clone()).unwrap();
    let old = state(&mut s).unwrap();
    let mut dev = s.into_device();
    dev.log.clear();
    let mut s = Store::mount(dev).unwrap();
    op(&mut s).unwrap();
    let new = state(&mut s).unwrap();
    assert_ne!(old, new, "{name}: the operation changes something");
    let log = s.into_device().log;
    let writes = log.iter().filter(|o| matches!(o, Op::Write(..))).count();
    assert!(
        log.iter().filter(|o| matches!(o, Op::Flush)).count() >= 2,
        "{name}: two flushes"
    );
    for cut in 0..=writes {
        for mode in 0..6 {
            let mut s = Store::mount(crashed(&base, &log, cut, mode))
                .unwrap_or_else(|e| panic!("{name}: cut {cut} mode {mode}: {e}"));
            let got =
                state(&mut s).unwrap_or_else(|e| panic!("{name}: cut {cut} mode {mode}: {e}"));
            assert!(
                got == old || got == new,
                "{name}: cut {cut} mode {mode}: a mixed state"
            );
            // After recovery the store keeps working.
            s.write(b"after", b"ok").unwrap();
            let s = Store::mount(s.into_device()).unwrap();
            assert!(s.stat(b"after").is_ok());
        }
    }
}

#[test]
fn a_crash_at_any_write_leaves_the_old_or_the_new_state() {
    check_crashes("write a new file", |s| s.write(b"new", &bytes(9000, 3)));
    check_crashes("replace a file", |s| s.write(b"notes.txt", &bytes(5000, 4)));
    check_crashes("append into the tail", |s| {
        s.append(b"audit/log", b"four").map(|_| ())
    });
    check_crashes("append a new block", |s| {
        s.append(b"audit/log", &bytes(3500, 5)).map(|_| ())
    });
    check_crashes("delete", |s| s.delete(b"models/a.bin"));
}

#[test]
fn fuzzed_images_never_panic() {
    let mut s = Store::format(Mem::new(10)).unwrap();
    s.write(b"f", &bytes(5000, 1)).unwrap();
    s.append(b"s", b"record").unwrap();
    let good = s.into_device().data;
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut mounted = 0;
    for _ in 0..100_000 {
        let mut data = good.clone();
        for _ in 0..1 + next() % 8 {
            // Mostly the superblocks and the index blocks.
            let block = if next() % 4 == 0 {
                next() % 10
            } else {
                next() % 6
            };
            let at = block as usize * BLOCK + (next() % 64) as usize;
            data[at] = next() as u8;
        }
        if let Ok(mut s) = Store::mount(Mem {
            data,
            log: Vec::new(),
        }) {
            mounted += 1;
            let _ = state(&mut s);
            let _ = s.append(b"s", b"x");
        }
    }
    assert!(mounted > 0, "some mutations leave a valid slot");
}

#[test]
fn writes_leave_the_audit_reserve() {
    // 64 blocks: 62 after the superblocks, 7 kept (D-046).
    let mut s = Store::format(Mem::new(64)).unwrap();
    let block = [7u8; BLOCK];
    let mut n = 0;
    while s.leaves_reserve(format!("data/{n}").as_bytes(), BLOCK as u64) {
        s.write(format!("data/{n}").as_bytes(), &block).unwrap();
        n += 1;
    }
    assert!(n > 10, "most of the store is usable: {n}");
    assert!(s.free_blocks() >= 62 / RESERVE_PART, "the reserve is free");
    // The audit trail may still use it.
    assert!(s.append(b"audit/log/1", b"record").is_ok());
    // Rewriting an existing file adds no object; a smaller one still fits.
    assert!(!s.leaves_reserve(b"data/0", BLOCK as u64 * 8));
}
