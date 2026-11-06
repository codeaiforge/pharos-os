# Storage and the filesystem

## 1. Status

- **Part 8 (writable store, M3.0):** **Accepted**: approved by the maintainer on 2026-10-29 (#73); follows [D-017](../project/decision-log.md#d-017-writable-persistent-storage-and-audit-integrity). **Implemented** (#77): the format crate and host tool (`crates/pharos-store`, `cargo xtask store build` and `store ls`), virtio-blk writes and flushes (`virtio::Blk::write`, `flush`, `init_flushing`), the storage service (`user/programs/src/bin/store.rs`, protocol in `pharos_proto::store` since #92 (`pharos_programs::store_proto` before), started by `init` at boot), the second, writable disk (`store.img`), and the tests (`store`, and crash injection in `store_crash`). Where the implementation differs from the approved text, it says so below. Parts 1–7 below describe the read-only format and are unchanged.
- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-27 (M2.8, #44). It follows [D-007](../project/decision-log.md#d-007-filesystem-and-persistent-storage) (read-only RAM disk, custom checked format, files through capabilities).
- **Implementation:** the image format, parser, and host tool are **implemented** (#45: `crates/pharos-fs`, `cargo xtask fs build` and `fs ls`). So is the RAM disk (#46: the Limine module request, `storage::record_modules` and `storage::ram_disk`, the slice from `mm::raw::module_bytes`, and the modules in the boot image). So is the kernel filesystem (#47: `fs::mount`, and `fs::mount_root` at boot). So are file capabilities with the `open` and `read` system calls (#48). Every M2.8 interface in this document is now implemented.

## 2. Context

M2.8 must read files from an image built on the host, and reject corrupt images without crashing the kernel ([roadmap](../project/implementation-roadmap.md#m28--storage-abstractions-and-filesystem)). D-007 sets the shape:
- a Limine module is the first block device;
- a small custom read-only format with CRC-32 checksums;
- one safe `no_std` parser shared by the kernel and the host tool;
- the filesystem runs in the kernel for now;
- processes reach files only through capabilities.

This document fixes the interfaces and the on-disk layout. The layout is the part that is hard to change later.

## 3. Design

### Components

| Component | Where | `unsafe` |
| --- | --- | --- |
| Format, builder, parser, `BlockDevice` trait | New crate `crates/pharos-fs`: `no_std`, no dependencies, `unsafe` forbidden | none |
| Host tool | `cargo xtask fs build` and `cargo xtask fs ls` (uses `pharos-fs` with `std`) | none |
| Module request | `kernel/src/limine.rs` | existing module |
| RAM disk | `kernel/src/storage.rs`; the slice over module memory comes from `mm::raw` | only in `mm::raw` |
| Kernel filesystem and file capabilities | `kernel/src/fs.rs`, `cap.rs`, `syscall.rs` | none |

### Block devices

```rust
pub const BLOCK_SIZE: usize = 512;

pub trait BlockDevice {
    /// Number of 512-byte blocks.
    fn block_count(&self) -> u64;
    /// Reads `buf.len() / BLOCK_SIZE` blocks starting at `block`.
    /// `buf.len()` must be a non-zero multiple of BLOCK_SIZE.
    fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), BlockError>;
}

pub enum BlockError { OutOfRange, BadLength }
```

- 512-byte blocks match virtio-blk sectors (M2.9), so the same trait fits both devices.
- The filesystem reads only through this trait. It handles reads that do not start or end on a block boundary itself.
- **RAM disk:** the module's bytes, rounded down to whole blocks. Any tail shorter than a block is ignored, and the builder pads images to a multiple of 512.
  - `read` checks `block + count ≤ block_count` with overflow checks, then copies.
  - Module memory is already mapped read-only and no-execute, and the frame allocator never gets it ([memory.md](memory.md)), so nothing can change the bytes after mount.

### On-disk format, version 1

All integers are little-endian. The image is three regions: the header at offset 0, the directory right after it, then file data.

**Header (64 bytes, offset 0):**

| Offset | Size | Field | Rule |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | `PHAROSFS` (ASCII) |
| 8 | 4 | `version` | `1` |
| 12 | 4 | `entry_count` | `0 ≤ n ≤ 1024` |
| 16 | 8 | `image_size` | multiple of 512, `≥ 64 + 128·n`, `≤ 16 MiB`, `≤` the device size |
| 24 | 4 | `dir_crc` | CRC-32 of the directory's `128·n` bytes |
| 28 | 32 | reserved | all zero |
| 60 | 4 | `header_crc` | CRC-32 of bytes 0–59 |

**Directory (`n` entries of 128 bytes, offset 64):**

| Offset | Size | Field | Rule |
| --- | --- | --- | --- |
| 0 | 8 | `offset` | where the file's data starts in the image |
| 8 | 8 | `size` | bytes; `offset + size ≤ image_size` without overflow |
| 16 | 4 | `crc` | CRC-32 of the file's data |
| 20 | 2 | `path_len` | `1 ≤ len ≤ 104` |
| 22 | 2 | reserved | zero |
| 24 | 104 | `path` | `path_len` bytes of path, then zeros |

- **Paths** are full paths with no leading slash, for example `etc/motd`.
  - Allowed bytes: `A–Z a–z 0–9 . _ -` and `/`.
  - `/` separates components. There are no empty components, no `.` or `..`, and no slash at the start or end.
  - Directories exist only as prefixes of file paths; there are no directory entries.
  - Entries are sorted by path in byte order, with no duplicates, so lookup is a binary search.
  - No path may also be a directory prefix of another: `a` and `a/b` cannot both exist.
- **File data:**
  - each file starts at or after the end of the directory, and at or after the end of the previous entry's data;
  - data regions therefore never overlap, and they appear in directory order;
  - empty files have `size = 0`, and their `offset` follows the same rule.
- **CRC-32:** the IEEE polynomial (reflected `0xEDB88320`, initial and final XOR `0xFFFFFFFF`), as in zlib, so `python3 -c "import zlib"` can check an image by hand. It detects corruption; it does not prove where an image came from.

### Validation

`pharos_fs::Image::mount(device)` runs every check before returning, in this order:
1. Read the header block and check every header rule, including `header_crc`.
2. Read the directory (at most 128 KiB, allocated only after `entry_count` passed its check) and check `dir_crc`.
3. Check every entry rule: path syntax, order, prefixes, ranges, and reserved bytes.
4. Read each file and check its `crc`.

- Any failure returns a typed `FsError` naming the check, such as `BadMagic`, `HeaderCrc`, or `EntryRange { index }`. The parser never panics, on any input.
- After a successful mount, the image is never parsed again: lookups use the validated directory, and reads use validated ranges.
- **Reading every file at mount** is affordable while images are at most 16 MiB and in memory. For virtio-blk (M2.9), where the device can change underneath, file checksums move to read time.
- **Memory:** at most 128 KiB for the directory, plus one block buffer. Nothing is allocated based on a size before that size has passed its check.

### Kernel interface

```rust
let fs = pharos_fs::Image::mount(&ram_disk)?;    // all checks run here
let file = fs.lookup("etc/motd")?;               // FsError::NotFound for no match
let n = fs.read(file, offset, &mut buf)?;        // 0 at the end of the file
fs.entries();                                    // iterator, for xtask and tests
```

- `lookup` accepts any byte string. A path that breaks the syntax rules simply matches nothing.
- At boot, the kernel mounts the module whose string is `root`, if one exists. Without a module, it logs `storage: none`. A corrupt image is logged with its `FsError`, and the kernel keeps running without storage.

### User interface: capabilities and system calls

Two new kernel objects, and one new right (`READ = 1 << 4`):

| Object | Rights used | Who holds it |
| --- | --- | --- |
| `Filesystem(Arc<Image>)` | `READ` (open files for reading), `GRANT` | Given to a process at start by the kernel; can be passed over IPC |
| `File { fs, index }` | `READ`, `GRANT` | Returned by `open` |

**New system calls:**

| No. | Call | Arguments | Result (`rdx`) | Capability needed |
| --- | --- | --- | --- | --- |
| 7 | `open` | fs handle, path buffer, path len (≤ 104) | new file handle | filesystem, `READ` |
| 8 | `read` | file handle, buffer, len (≤ 4096), file offset | bytes read (0 at end of file) | file, `READ` |

**New error code:** `8 NOT_FOUND` (no file with this path).

- **`open` derives the file capability from the filesystem capability** in the derivation tree, with rights `READ | GRANT` masked by the parent's. Revoking a granted filesystem capability therefore also cuts off every file opened through it.
- **Paths are copied in** with `read_user` (at most 104 bytes); data is copied out with `write_user`. The checks run in the same order as for `send` and `receive`, and no state changes on an error.
- **File handles stay valid until deleted or revoked.** Holding one keeps the image alive (`Arc`).
- `syscall::decode` gains both calls, and its host fuzz test covers them.

### Host tool and the boot image

- `cargo xtask fs build <dir> <image>` packs a directory: files only, sorted, with paths checked against the rules above. `cargo xtask fs ls <image>` mounts the image with the same parser and lists paths, sizes, and CRCs.
- `cargo xtask build` packs `kernel/root/` (a few small files) into `pharos.fs`, and adds it to the ISO with `module_path: boot():/boot/pharos.fs` and `module_string: root`. Builds stay byte-identical: files sorted, no timestamps in the image.
- **Test kernels:** the runner adds every test image as a module, each with its name as the module string. A test kernel picks the one it needs by name. xtask builds these images:
  - a good image with known contents;
  - corrupted images, one per check: bad magic, bad version, bad header CRC, entry count too big, image size larger than the module, bad directory CRC, bad path syntax, unsorted or duplicate entries, overlapping data, data out of range, bad file CRC, truncated image.

## 4. Security

- **Trust boundary:** the image is untrusted input, added to the [threat model](../security/threat-model.md). A corrupt or hostile image must at worst fail to mount.
- **Parser:**
  - safe Rust with `unsafe` forbidden, no dependencies;
  - every offset and size checked with overflow checks before use;
  - fixed limits: 1024 entries, 104-byte paths, 16 MiB images;
  - fuzzed on the host with at least 100,000 mutated images, expecting no panic.
- **Kernel memory:** the module memory is read-only and outside the frame allocator, and mounting allocates at most 128 KiB, after the size check.
- **Processes:** no ambient authority. A process reaches files only with a filesystem capability with `READ`. File capabilities narrow rights, pass over IPC only with `GRANT`, and can be revoked. User buffers go through the M2.7 copy paths.
- **`unsafe`:** only the slice over module memory, in `mm::raw`, and the module request structures, in `limine.rs`.
- **Limits:**
  - images are not authenticated: CRC-32 catches corruption, not tampering;
  - the filesystem runs in the kernel and is part of the trusted computing base until it moves to a server.

## 5. Testing

| Where | What |
| --- | --- |
| Host, `pharos-fs` | Round trips; each corruption type returns its `FsError`; lookup edge cases (missing, empty file, 104-byte path, deepest path, prefix rules); CRC-32 against known values; at least 100,000 mutated images through `mount` without a panic |
| Host, `syscall` | The fuzz test covers `open` and `read` |
| QEMU, `ramdisk` | Module found, size and SHA-256 match xtask's values, block reads at the start, middle, end, and one past the end |
| QEMU, `fs` | Known files read back with the right contents; one check per corrupted image, each rejected with the expected error while the kernel keeps running |
| QEMU, `files` | A process with the capability reads a file; without it, with a missing `READ` right, with a bad buffer, or after revocation it is refused; a capability passed over IPC works for the receiver |

## 6. Alternatives

- **FAT or ext2:** existing tools could read the images, but the parser would be much larger, harder to validate, and without checksums. Rejected in D-007.
- **Directory entries for directories (a tree):** listing becomes natural, but there is more to validate. Flat sorted paths cover lookup, and listing can come with a prefix search later.
- **Byte-addressed device interface:** simpler for a RAM disk, but virtio-blk works in sectors, so the trait uses blocks from the start.
- **Checking file CRCs at read time:** less work at mount, but every read then needs the whole file. It moves to read time with virtio-blk.

## 7. Open questions

- **Writes:** designed in part 8 (M3.0, D-017): a separate copy-on-write store in user space; this read-only format stays for boot modules.
- **Moving the filesystem to a user-space server:** needs program loading from storage, shared memory, and bulk IPC.
- **Image authentication:** signatures or hashes checked by the bootloader, with secure boot.
- **Listing directories from user space:** a `list` call or a prefix search, when a service needs it.
- **Larger images:** more than 16 MiB, or more than 1024 entries, needs a new format version.

## 8. The writable store (M3.0)

Follows [D-017](../project/decision-log.md#d-017-writable-persistent-storage-and-audit-integrity). Durable task state (M3.3), the audit trail (M3.4), the knowledge service (M3.8), and model files (D-010) need storage that is written at run time and survives crashes. The read-only format above stays for boot modules; the store is separate.

### Components

| Component | Where | `unsafe` |
| --- | --- | --- |
| Format, commit logic, mount and recovery, SHA-256 | New crate `crates/pharos-store`: `no_std` with `alloc`, no third-party dependencies (it uses `pharos-fs` for CRC-32 and the path rules), `unsafe` forbidden; generic over a block-device trait with `read`, `write`, and `flush` | none |
| Storage service | The virtio-blk driver's process (`user/programs/src/bin/store.rs`, built on `pharos_programs::virtio`), as D-015 put the network stack in its driver | none (programs use none) |
| Host tool | `cargo xtask store build <dir> <image> --blocks <n>` and `store ls <image>` | none |
| Shared memory for file data | Kernel `Memory` capabilities ([user-environment.md](user-environment.md#shared-memory-d-017-item-7)) | in the kernel's existing modules |

### On-disk format, version 1

All integers are little-endian. Blocks are 4 KiB (8 virtio-blk sectors).

- **Superblock slots: blocks 0 and 1.** Each holds: magic `PHAROSST` (8 bytes); version (u32, 1); block size (u32, 4096); generation (u64); total blocks (u64); index start block (u64), block count (u32), byte length (u32), and CRC-32 (u32); and the slot's own CRC-32 over everything before it. A slot is **valid** if its magic, version, block size, and CRC are right, its numbers are in range, and its index's CRC verifies.
- **Index:** a header (object count, u32) and one entry per object, sorted by path: path length (u8) and path (at most 104 bytes, the same rules as `pharos-fs`: no empty segments, no `.` or `..`, no NUL); kind (u8: 1 file, 2 stream); length in bytes (u64); content CRC-32 (u32; for streams, of the last block); for streams, the record count (u64) and the chain head (32 bytes); extent count (u16) and extents (start block u64, block count u32). At most 4,096 objects, 64 extents per object, and a 1 MiB index.
- **Files** are written whole: a write puts the new content in free blocks, and the commit makes the index point to it. Model files are stored this way, normally by the host tool when the image is built.
- **Streams** hold records of 1 to 4,032 bytes (a zero length marks the unused end of a block): length (u32), CRC-32 (u32), and the record's SHA-256 chain value `H(prev ‖ payload)` (32 bytes; `prev` is all zeros for the first record), then the payload. Records do not cross blocks. Appending copies the stream's last block, adds the record, and writes it to a free block (live blocks are never written), preferably the block after the one before it; a stream that would pass 64 extents is moved into one run in the same commit. A stream's length counts whole earlier blocks plus the used part of the last.

### Commit and recovery

1. Write new data blocks (and a copied stream tail) and the new index to free blocks; **flush**.
2. Write the superblock into the **older** slot with generation + 1; **flush**.

(The approved design had a third flush between data and index. Implementing it showed it adds nothing: a superblock is valid only if its index's CRC verifies, and the flush before the superblock makes data and index durable together. The crash tests include a write cache that reorders: every pending write landing except the first.)

- **Free blocks** are those referenced by neither of the two valid generations, so the newest commit can always fall back to the previous one. The service builds a bitmap of them at mount.
- **Mount:** read both slots; take the valid one with the higher generation, or the other if it is not valid; if neither is valid, the store is refused. Then check every extent is in range and no two objects share a block.
- **Reads** check each object's CRC-32 (files: the whole content when read from start to end; streams: each record's CRC and chain value).
- **A crash at any point** leaves either the old generation (step 1, or a torn step-2 write that fails its CRC) or the new one (step 2 complete). Nothing else is reachable.
- **Full store:** a write that does not fit is refused (`NO_SPACE`) before anything is written. A device error fails the operation and the service stops accepting writes until restarted (reads continue).

### The storage service

- **Started by `init`** with the writable virtio-blk device, a console, and its endpoint; it reports ready after mounting.
- **Clients** hold a `SEND` capability on its endpoint, badged by `init`: bits 0–15 a namespace number, bit 16 read-only. The service maps namespace numbers to path prefixes from a table in its source (reviewed code, like `init`'s service table); a client sees only paths under its prefix, given relative to it. Badge 0 and unknown namespaces are refused. The table (`pharos_proto::store::NAMESPACES`): 1 `test`, 2 `spare`, 3 `models`, 4 `crash`, 5 `agents`, the agent runtime's tasks (#99), 6 `audit`, the audit trail (#107), and 7 `files`, the files the user gives agents, which the runtime reads read-only (#127, tools.md).
- **File data moves through one shared buffer per client** (changed in #77). The approved design passed a `Memory` capability with each `read` and `write`, but a `call` carries exactly one capability, its one-shot reply capability. So a client maps a buffer, shares it (`mem_share`), and attaches it once with a plain `send` carrying the capability and the buffer's size; the service maps it writable (replacing an earlier one) and deletes the capability. `read` and `write` then name a range of that buffer. Without a buffer, or with a range outside it, they return the new status `NO_BUFFER`.
- **Requests** (by `call`, replies non-blocking, as the network service; little-endian fields, a path as a length byte and at most 80 bytes, relative to the namespace). Since #92 this is interface `store`, version 1 (D-019): the codec is `pharos_proto::store`, and every request starts with the version (1) and the operation; the tables give what follows:

  | Op | Request | Reply |
  | --- | --- | --- |
  | 1 `stat` | path | status, kind (u8), length (u64), records (u64) |
  | 2 `read` | path, file offset, length, buffer offset (u64 each) | status, bytes copied into the buffer (u64) |
  | 3 `write` | path, length, buffer offset | status (the file is replaced atomically) |
  | 4 `append` | stream path, record (1–200 bytes, inline; larger records later, when a client needs them) | status, record number (u64), chain head (32 bytes) |
  | 5 `list` | path prefix (may be empty), start index (u32) | status, count (u8), more (u8), then each name as a length byte and bytes |
  | 6 `delete` | path | status |
  | 0xF1 `ATTACH` (common, a `send`; 7 before #92) | buffer size (u64, at most 32 MiB: `MAX_BUFFER`, so 16 clients fit in the service's limit; larger ones are dropped and the earlier buffer stays; M3.0 review), with the `Memory` capability (`READ` and `WRITE`) | none |
  | 8 `buffer` | — | status, attached buffer size (u64; 0 if none) |
  | 9 `release` (#100) | client badge (u32); only from `init`, with no badge | status (`NO_ACCESS` from anyone else); the client's buffer is unmapped |
  | 0xF0 `INFO` (common) | — | status, versions 1 to 1, the name `store`, no details; answered for any badge, since it names only the interface |

  Status codes: the common ones (D-019): 0 OK, 1 BAD_REQUEST, 2 VERSION (another version; the reply carries the supported range, 1 to 1), 3 NO_ACCESS, 6 NO_BUFFER, 7 NOT_FOUND; and the interface's own: 32 NO_SPACE, 33 READ_ONLY, 34 IO_ERROR, 35 CORRUPT. (Before #92: 2 NOT_FOUND, 3 NO_SPACE, 4 READ_ONLY, 5 NO_ACCESS, 6 IO_ERROR, 7 CORRUPT, 8 NO_BUFFER.)
- **Namespaces** (the table in `pharos_proto::store`): 1 `test`, 2 `spare`, 3 `models`, 4 `crash`, 5 `agents` (the runtime's tasks, #99), 6 `audit` (the audit trail, held only by the audit service, #107), 7 `files` (granted files, read-only for the runtime, #127), 8 `knowledge` (#143). Planned (M4.3, D-028, [boot.md](boot.md#8-recovery-and-updates-m43-d-028)): 9 `system` (the update slots and their record, held only by `init`) and 10 `incoming` (signed images not yet approved: `WRITE` for the runtime, read and delete for `init`). `init` does not give clients store capabilities yet; the first is the inference service (M3.2). It starts the service with a 1 GiB page limit, for the buffers clients attach (it maps each one). Large files are read through a window of the client's choosing (#78, user-environment.md).
- **Streaming:** `read` and `write` move data a block at a time between the disk and the buffer (`Store::read_with`, `write_with`), so a file never has to fit in the service's memory. A whole-file `read` checks the CRC-32 at the end and returns `CORRUPT` after copying, so the client must not use the bytes then.
- **One commit at a time**; each write, append, or delete is its own commit (batching later, if measured to matter).

### QEMU

`cargo xtask` attaches a second virtio-blk disk, writable: `store.img` next to each image, an empty, formatted store of 16 MiB (a sparse file), fresh whenever the image is built. The read-only `disk.img` stays first for the M2.9 tests. `init` takes the second virtio-blk device in PCI order for the storage service (`Cap::SecondDevice`); the driver negotiates `VIRTIO_BLK_F_FLUSH`.

### Security

- **Media are untrusted:** every superblock, index, extent, and record is checked before use; the parser is shared with the host tool and fuzzed.
- **Tamper evidence:** CRC-32 detects accidental corruption only; the SHA-256 chain makes changes to a stream's records detectable relative to a known chain head. Keeping that head where someone holding the disk cannot rewrite it (or signing it) is M3.4.
- **Access:** namespaces from `init`'s badges; read-only clients cannot write; paths cannot escape a prefix (no `..`, checked like `pharos-fs`).
- **Limits (accepted):** one commit at a time; the index is rewritten on each commit (fine for thousands of objects); no encryption at rest; the chain head is not anchored until M3.4; the storage service has DMA through its device, as every driver (no IOMMU, D-008).

### Testing

| Test | What it checks |
| --- | --- |
| Host, `pharos-store` | Format round trips; each corruption of a superblock, index, extent, or record detected with its error; SHA-256 against the FIPS 180-4 test vectors; allocation never reuses a block of the two newest generations; **crash consistency: the write sequence of each commit cut at every block write, including a torn last write, then mounted: the old or the new state, never a mix**; 100,000 fuzzed images that never panic |
| Host, `xtask` | `store build` and `store ls`; the store disk in QEMU's arguments |
| Host, `pharos-proto` | Every request round-trips through `pharos_proto::store`; truncated, trailing, unknown, and oversized requests refused; another version refused with `VERSION`; 200,000 random messages never panic; namespaces and joined paths (no escape) |
| QEMU, `store` | The service mounts the store on the second disk and reports ready; a client attaches a buffer and writes, stats, reads back, partially reads, replaces, appends (record numbers and chain head checked against SHA-256), lists, and deletes; bad paths and ranges are refused; a 17 MiB write gets `NO_SPACE` with nothing written; a read-only client reads but cannot write; another namespace sees nothing; badge 0 and unknown namespaces get `NO_ACCESS` |
| QEMU, crash injection (`store_crash`) | `cargo xtask runner` boots the crash writer 20 times on one store disk and kills QEMU at a random moment (up to 1.5 s, printed seed `PHAROS_CRASH_SEED`) after it starts writing; each boot first checks the store (a counter file and a log stream that must agree, every CRC and chain value), then a last boot checks, writes, and checks again. Killing QEMU keeps what it already gave the host, so this tests the real driver and device path under interruption; losing unflushed writes is covered by the host crash tests |

