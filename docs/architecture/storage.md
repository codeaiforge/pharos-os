# Storage and the filesystem

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-27 (M2.8, #44). It follows [D-007](../project/decision-log.md#d-007-filesystem-and-persistent-storage) (read-only RAM disk, custom checked format, files through capabilities).
- **Implementation:** the image format, parser, and host tool are **implemented** (#45: `crates/pharos-fs`, `cargo xtask fs build` and `fs ls`). The RAM disk (#46), the kernel filesystem (#47), and file capabilities (#48) are **planned**.

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

- **Writes:** the direction is copy-on-write (D-007). It needs a design before any write code, and a writable device (virtio-blk, M2.9).
- **Moving the filesystem to a user-space server:** needs program loading from storage, shared memory, and bulk IPC.
- **Image authentication:** signatures or hashes checked by the bootloader, with secure boot.
- **Listing directories from user space:** a `list` call or a prefix search, when a service needs it.
- **Larger images:** more than 16 MiB, or more than 1024 entries, needs a new format version.
