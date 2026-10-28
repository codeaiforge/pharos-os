# Drivers and device access

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-27 (M2.9, #51). It follows [D-008](../project/decision-log.md#d-008-driver-strategy) (user-space drivers with device capabilities, virtio-blk only, MSI-X, no IOMMU yet) and [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries).
- **Implementation:** Rust user programs and the ELF loader are **implemented** (#52: `user/pharos-user`, `user/programs`, `crates/pharos-elf`, `process::load_elf` and `spawn_elf`; programs are in the boot filesystem as `bin/<name>`). So is PCI discovery (#53: `arch::x86_64::pci` for configuration access and BAR probing, `pci::enumerate` with decoding and a bounded capability walk, the boot log listing devices; every QEMU run attaches `disk.img` as `virtio-blk-pci,disable-legacy=on` and has no network card). So are the `Device` capability with `config_read`, `mmio_map`, and `dma_alloc` (#55: `device::DeviceHandle`, `device::mmio_range`, the `DEVICE` page-table bit, `Mapped` in `pharos-user`, and the `devprobe` test program). So are device interrupts (#54: `irq::Irq` and the vector table in `kernel/src/irq.rs`, IDT stubs for vectors 48–63, MSI-X table writes through a kernel-only mapping, `irq_create` and `irq_wait`, and the `irqprobe` test program with a minimal virtio-blk queue in `user/programs/src/virtio.rs`). So is the virtio-blk driver (#56: `user/programs/src/bin/virtio-blk.rs` on the shared `pharos_programs::virtio` module, mounting the disk's `pharos-fs` image with the kernel's parser; tested in `virtio_blk`). To run that parser, `pharos-user` has a heap: a 256 KiB bump allocator in its `syscall` module that never frees memory. The M2.9 security review ([review-m2.9-drivers.md](../security/review-m2.9-drivers.md), #57) found and fixed four issues (F1–F4), recorded below where they apply.

## 2. Context

M2.9 must run drivers for QEMU devices, each with QEMU tests, without a driver error crashing the kernel ([roadmap](../project/implementation-roadmap.md#m29--hardware-abstraction-and-selected-drivers)). D-008 puts drivers in user processes. Four things are missing:
- user programs that are more than a few assembly instructions;
- a way to find devices;
- a way for a process to receive a device's interrupts;
- a way for a process to reach a device's registers and give it memory for DMA.

This document fixes the interfaces for all four, and the virtio-blk subset the first driver implements.

## 3. Design

### Components

| Component | Where | `unsafe` |
| --- | --- | --- |
| System-call library | New crate `user/pharos-user`: `no_std`, safe wrappers | only its `syscall` module (the `syscall` instruction) |
| User programs | `user/programs/` (binaries for `x86_64-unknown-none`, linked at `USER_BASE`) | none |
| ELF parser | New crate `crates/pharos-elf`: `no_std`, no dependencies, `unsafe` forbidden, fuzzed | none |
| Program loading | `kernel/src/process.rs` (`spawn_elf`) | none |
| PCI configuration access | `kernel/src/arch/x86_64/pci.rs` (ports `0xCF8`/`0xCFC`) | hardware layer |
| PCI enumeration, BARs, MSI-X capability | `kernel/src/pci.rs`, host-tested | none |
| Device-interrupt entry stubs | `arch::x86_64::idt`, vectors 48–63 | hardware layer |
| MMIO mappings | `arch::x86_64::paging` (device pages, never freed as RAM) | hardware layer |
| Device, interrupt, and DMA capabilities; new system calls | `cap.rs`, `syscall.rs`, new `kernel/src/device.rs` | none |
| virtio-blk driver | `user/programs/src/bin/virtio-blk.rs`, `user/programs/src/virtio.rs` | none |

Adding `user/pharos-user`'s `syscall` module to the list of places allowed to use `unsafe` is a change to AGENTS.md section 5. It is made with #52 and reviewed then.

### User programs

- **Build:** `cargo xtask` builds `user/programs/*` for `x86_64-unknown-none` with `panic = "abort"` and a linker script that places the image at `USER_BASE` (`0x400000`). The executables go into the boot filesystem image as `bin/<name>`. The user crates are workspace members, checked for the bare-metal target like the kernel, and excluded from host builds.
- **Start-up contract:** unchanged from M2.7 (syscalls-ipc.md):
  - entry with `rdi` = the argument the starter chose;
  - the stack top below `0x7fff_ff80_0000`, 64 KiB;
  - capabilities under handles 1, 2, … in the order the starter gave them.
- **Library:** `pharos-user` wraps each system call in a safe function returning `Result<u64, Error>`, plus `exit`, a `debug_write`-based print macro, and a panic handler that exits with a fixed code.

### ELF loader

`pharos_elf::parse(bytes)` accepts only:
- ELF64, little-endian, `ET_EXEC`, machine x86-64, version 1, and the standard header and program-header sizes;
- at most 8 `PT_LOAD` segments, plus `PT_GNU_STACK`. Any `PT_INTERP`, `PT_DYNAMIC`, or `PT_TLS` is refused; other types are ignored;
- per segment:
  - `p_vaddr % 4096 == p_offset % 4096`;
  - `p_filesz ≤ p_memsz`, and the file range inside the file, with overflow checks;
  - the virtual range inside `[USER_BASE, USER_BASE + 16 MiB)`;
  - not writable and executable at once;
- segments that do not overlap, even at page granularity;
- an entry point inside an executable segment.

`process::spawn_elf(fs, path, arg, caps)` reads the file through the M2.8 filesystem (at most 4 MiB). It parses the file completely before allocating anything, then maps fresh zeroed frames per segment, with `USER_CODE` for executable segments, read-only data as user read-only, and `USER_DATA` for writable ones. It copies the file bytes and starts the process. Any failure frees everything and returns an error, with no process created.

### PCI discovery

- **Configuration access:** mechanism #1 through ports `0xCF8`/`0xCFC`, 32-bit aligned reads and writes, in the hardware layer, under one lock.
- **Enumeration:** buses 0–255, devices 0–31, functions 0–7 (only function 0 unless the header says multi-function). For each function the kernel records:
  - vendor and device ID, class, and header type (only type 0 devices get a `Device`);
  - BARs: memory or I/O, 32- or 64-bit, prefetchable, and size, probed by writing all ones with decoding disabled in the command register, then restoring;
  - the capability list, walked with a step limit (48) and a check that each pointer is at or above `0x40` and 4-byte aligned. The MSI-X capability is recorded: table size, table BAR and offset, PBA BAR and offset.
- **BARs are untrusted:** a memory BAR that overlaps any entry of the boot memory map, or runs past the end of the address space, is ignored and logged. It would otherwise expose RAM (or the framebuffer) to a driver and to the kernel's MSI-X writes (security review F1). In QEMU this drops the VGA framebuffer BAR.
- **The boot log** lists the devices found. QEMU runs for tests attach `virtio-blk-pci,disable-legacy=on` (vendor `0x1af4`, device `0x1042`) with a disk image built by xtask.

### Device capabilities

| Object | Rights | Created by |
| --- | --- | --- |
| `Device(Arc<Device>)`: one PCI function | `MAP` (map BARs, allocate DMA), `IRQ` (create interrupts), `CONFIG` (read config space), `GRANT` | The kernel, when it starts a driver |
| `Interrupt(Arc<Irq>)`: one MSI-X vector of one device | `WAIT`, `GRANT` | `irq_create`, derived from the device capability |

- **Driver lifecycle:**
  - when the kernel hands out a `Device`, it enables memory decoding and bus mastering in the PCI command register. A device is granted to one driver at a time: `grant` refuses it until the previous handle's last reference is gone (F2);
  - a process that maps a device's registers (`mmio_map`) or buffers (`dma_alloc`) pins the device until it ends, even if it deletes its handles (F2);
  - when the `Device` object's last reference goes (the driver exits or is killed, and nothing else holds it or pins it), the kernel disables bus mastering and memory decoding and masks MSI-X (function mask). Only then are the device's DMA buffers freed.
  - So a device can never DMA into freed memory. Firmware may leave a device enabled before it is granted; granting sets a known state.
- **New rights:** `MAP = 1 << 5`, `IRQ = 1 << 6`, `CONFIG = 1 << 7`, `WAIT = 1 << 8`.

### New system calls

| No. | Call | Arguments | Result (`rdx`) | Capability needed |
| --- | --- | --- | --- | --- |
| 9 | `config_read` | device, offset (< 256, aligned to width), width (1, 2, 4) | the value | device, `CONFIG` |
| 10 | `mmio_map` | device, BAR index, offset in BAR, length, user address | 0 | device, `MAP` |
| 11 | `dma_alloc` | device, pages (1–16), user address | physical address of the first page | device, `MAP` |
| 12 | `irq_create` | device, MSI-X entry index | new interrupt handle | device, `IRQ` |
| 13 | `irq_wait` | interrupt handle | interrupts since the last wait (≥ 1) | interrupt, `WAIT` |

**New error code:** `9 IN_USE` (the address is already mapped, the MSI-X entry is already taken, or another thread is waiting).

- **`config_read`** is read-only. Drivers never write configuration space; the kernel sets the command register and MSI-X.
- **`mmio_map`:**
  - offset and length are page-aligned, and the range lies inside a memory BAR;
  - the user address is page-aligned, in the user half, and below the last user page, and nothing is mapped there yet;
  - at most 256 register pages per process in all (`NO_MEMORY` beyond; F4);
  - **pages that overlap the MSI-X table or PBA are refused,** so a driver cannot aim interrupts at arbitrary vectors;
  - the mapping is user, writable, no-execute, and uncached. Its page-table entries carry a software bit (`DEVICE`) so `destroy` unmaps them without freeing the frames.
- **`dma_alloc`:**
  - physically contiguous fresh zeroed frames, mapped user, writable, no-execute at the given address, with the `DEVICE` bit (the address space does not own them);
  - at most 64 pages per device at a time;
  - **the device handle owns them,** not the address space, and frees them only after bus mastering is off. The process records the device as pinned, so even if it deletes every device handle, the buffers it still has mapped stay allocated until the process ends. (Tightened during #55: an address space freeing them could race a device still granted to another process.)
  - the result is the physical address the driver writes into descriptors.
- **`irq_create`:**
  - allocates a free vector from 48–63 (at most 4 per device, F3) and programs MSI-X entry `index` to target the bootstrap CPU's local APIC (message address `0xFEE00000`, data = the vector), then unmasks it and enables MSI-X (function mask off);
  - the interrupt capability is derived from the device capability, so revoking the device revokes it. It gets `WAIT`, plus `GRANT` if the device capability has it;
  - the interrupt object holds the device, so the device stays enabled while any interrupt for it exists.
- **`irq_wait`:**
  - returns at once if interrupts arrived since the last wait, otherwise blocks the thread;
  - one waiter per interrupt;
  - the handler only increments a counter, wakes the waiter, and sends the local APIC EOI. MSI is edge-triggered, so drivers acknowledge nothing at the CPU; they acknowledge at the device, as virtio requires.
- **When the interrupt object goes,** the entry is masked and the vector freed. A revoked-but-held handle returns `REVOKED`.
- **Every argument is checked as in syscalls-ipc.md,** and `syscall::decode` and its fuzz test cover the new numbers.

### virtio-blk driver (virtio 1.x, modern PCI)

- **Transport:** the driver checks the device ID (`0x1af4:0x1042`) and finds the vendor-specific capabilities (ID `0x09`) with `config_read`: `COMMON_CFG`, `NOTIFY_CFG`, and `DEVICE_CFG` (for the capacity), each with BAR, offset, and length. It maps those pages with `mmio_map`. `ISR_CFG` is not needed: with MSI-X the ISR status is unused.
- **Initialisation:**
  1. reset;
  2. `ACKNOWLEDGE`, then `DRIVER`;
  3. read features, accept only `VIRTIO_F_VERSION_1` (bit 32), and require it;
  4. `FEATURES_OK`, read back to confirm;
  5. set up queue 0;
  6. `DRIVER_OK`.

  Any unexpected value sets `FAILED` and exits.
- **Queue:** one split virtqueue, size min(device maximum, 16), in one 2-page `dma_alloc` buffer: descriptor table (16-byte aligned), available ring, used ring (4-byte aligned), and the request header and status in the first page, data in the second. The queue's MSI-X vector is set through `queue_msix_vector` from an `irq_create` interrupt, and the configuration vector is `NO_VECTOR`.
- **Requests:** read only. A chain of three descriptors:
  - the header (`type = IN`, sector);
  - the data (device-writable, 512 to 4096 bytes);
  - the status byte (device-writable).

  Then a notify write, `irq_wait`, and a check of the used ring.
- **Device values are untrusted:**
  - used-ring index advances at most the number outstanding;
  - descriptor ID in range and outstanding;
  - status must be `OK`;
  - the length is checked against the request (data plus the status byte);
  - reads past the disk's capacity are refused before submission.

  These checks are one pure function (`virtio::check_used`), unit-tested on the host.
- **Test service:** the driver reads the disk's blocks into a `pharos-fs` `BlockDevice`, mounts the image with the same parser as the kernel, and reports a file's contents with `debug_write`. It then exits with a code that encodes the outcome (0 success, 1 not virtio-blk, 2 setup failed, 3 read failed, 4 mount failed, 5 file missing or wrong).

### Startup

In M2.9 test kernels start drivers. The main kernel enumerates PCI and logs devices; it starts no driver until there is a service manager.

## 4. Security

- **Trust boundary:** a driver is an untrusted process. It reaches only the device it was given, through capabilities:
  - it cannot write PCI configuration space;
  - it cannot map RAM, other devices, or the MSI-X table;
  - its faults kill only the driver.
- **DMA (limit, no IOMMU):** a driver can program its device to read or write **any physical memory**, so in M2.9 a driver is trusted with all memory through its device. Mitigations until an IOMMU:
  - only the kernel starts drivers;
  - drivers stay small;
  - bus mastering is turned off before a dead driver's buffers are freed.

  The IOMMU (VT-d, emulated by QEMU as `intel-iommu`) is evaluated before real-hardware use.
- **Interrupts:** a driver cannot choose vectors (the kernel programs MSI-X, and its pages are never mapped). The handler does no driver work. Spurious vectors are counted.
- **Devices are untrusted input** to the driver: every ring index, ID, length, and status is checked. The kernel itself reads only configuration space from devices, and it bounds the capability-list walk.
- **ELF files are untrusted input:** the safe parser checks everything before any allocation, and it is fuzzed.
- **Kernel memory:** DMA is at most 64 pages per device; register mappings at most 256 pages per process (F4); programs at most 4 MiB; interrupt vectors are a fixed set of 16, at most 4 per device.
- **`unsafe`:**
  - port I/O for PCI configuration, IDT stubs for vectors 48–63, the device-page bit in page tables, and kernel MMIO access to MSI-X tables, all in the hardware layer;
  - in `pharos-user`'s `syscall` module: the `syscall` instruction and entry stub, volatile access to mapped device memory (`Mapped`), and the bump heap allocator (added with #56; the shared filesystem parser needs `alloc`);
  - nothing else.
- The threat model gains a "Drivers and devices" section with these mitigations and limits.

## 5. Testing

| Where | What |
| --- | --- |
| Host, `pharos-elf` | Valid programs; each refusal (magic, class, endianness, type, machine, header sizes, segment ranges, overlap, W+X, entry, interpreter, too many segments); a mutation fuzz test of at least 100,000 inputs |
| Host, `pci` | BAR decoding (32/64-bit, I/O, prefetchable, sizes from probe values); capability walks, including loops and bad pointers; MSI-X field decoding |
| Host, `syscall` | Decoding and the fuzz test cover calls 9–13 |
| QEMU, `user_elf` | A Rust program from the filesystem image prints and exits; malformed ELF files are refused with no process created and no frames lost |
| QEMU, `pci` | The host bridge and the virtio-blk device are found with the expected IDs, BARs, and MSI-X capability |
| QEMU, `device_caps` | `config_read`, `mmio_map` (the device's BAR works; RAM, another device, past the BAR, the MSI-X table, an already-mapped address are refused), `dma_alloc` (physical address matches, frames return on exit), and rights checks |
| QEMU, `device_irq` | An interrupt reaches a waiting process; without the capability, waiting is refused; after revocation it returns `REVOKED`; masked on drop |
| QEMU, `virtio_blk` | The driver reads known blocks, mounts the `pharos-fs` image on the disk, and reports a file; a driver killed mid-run leaves the kernel running and bus mastering off |

## 6. Alternatives

- **In-kernel drivers:** far less code now, but against D-004, and a DMA-capable driver would sit inside the kernel. Rejected in D-008, and kept as D-004's documented fallback.
- **IOMMU in M2.9:** real DMA isolation, but it adds DMA-remapping tables and ACPI DMAR parsing as a second hard piece. Deferred and tracked.
- **IOAPIC with ACPI routing:** needed for legacy devices, but virtio-blk does MSI-X, which needs no routing tables.
- **Interrupts as IPC messages:** they reuse endpoints, but a message per interrupt needs buffering in the kernel. A counter plus a blocking wait is bounded and simpler.
- **Letting drivers write configuration space:** they could enable MSI and bus mastering themselves, but also re-point BARs onto RAM. Kernel-only writes close that.

## 7. Open questions

- **IOMMU:** VT-d evaluation, needed before real hardware.
- **A service manager** that starts drivers at boot and hands them capabilities, and moving the M2.8 filesystem into a user-space server on top of the driver.
- **More devices:** virtio-net (networking milestone), a framebuffer, input.
- **SMP:** MSI-X targets the bootstrap CPU only.
- **Writes:** a writable virtio-blk queue waits for the copy-on-write design (D-007).
