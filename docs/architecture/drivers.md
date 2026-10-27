# Drivers and device access

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-27 (M2.9, #51). It follows [D-008](../project/decision-log.md#d-008-driver-strategy) (user-space drivers with device capabilities, virtio-blk only, MSI-X, no IOMMU yet) and [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries).
- **Implementation:** **planned**: Rust user programs and the ELF loader (#52), PCI discovery (#53), device interrupts (#54), MMIO and DMA capabilities (#55), and the virtio-blk driver (#56).

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
| virtio-blk driver | `user/programs/virtio-blk` | none |

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
- **The boot log** lists the devices found. QEMU runs for tests attach `virtio-blk-pci,disable-legacy=on` (vendor `0x1af4`, device `0x1042`) with a disk image built by xtask.

### Device capabilities

| Object | Rights | Created by |
| --- | --- | --- |
| `Device(Arc<Device>)`: one PCI function | `MAP` (map BARs, allocate DMA), `IRQ` (create interrupts), `CONFIG` (read config space), `GRANT` | The kernel, when it starts a driver |
| `Interrupt(Arc<Irq>)`: one MSI-X vector of one device | `WAIT`, `GRANT` | `irq_create`, derived from the device capability |

- **Driver lifecycle:**
  - when the kernel hands out a `Device`, it enables memory decoding and bus mastering in the PCI command register;
  - when the `Device` object's last reference goes (the driver exits or is killed, and nothing else holds it), the kernel disables bus mastering and memory decoding and masks every MSI-X entry. Only then are the driver's frames freed.
  - So a device can never DMA into freed memory. Process teardown drops the capability table before destroying the address space; this order is a tested rule.
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
  - **pages that overlap the MSI-X table or PBA are refused,** so a driver cannot aim interrupts at arbitrary vectors;
  - the mapping is user, writable, no-execute, and uncached. Its page-table entries carry a software bit (`DEVICE`) so `destroy` unmaps them without freeing the frames.
- **`dma_alloc`:**
  - physically contiguous fresh zeroed frames, mapped user, writable, no-execute at the given address;
  - at most 64 pages per device at a time; the address space owns them, and they are freed with it after bus mastering is off;
  - the result is the physical address the driver writes into descriptors.
- **`irq_create`:**
  - allocates a free vector from 48–63 and programs MSI-X entry `index` to target the bootstrap CPU's local APIC (message address `0xFEE00000`, data = the vector), then unmasks it and enables MSI-X (function mask off);
  - the interrupt capability is derived from the device capability, so revoking the device revokes it.
- **`irq_wait`:**
  - returns at once if interrupts arrived since the last wait, otherwise blocks the thread;
  - one waiter per interrupt;
  - the handler only increments a counter, wakes the waiter, and sends the local APIC EOI. MSI is edge-triggered, so drivers acknowledge nothing at the CPU; they acknowledge at the device, as virtio requires.
- **When the interrupt object goes,** the entry is masked and the vector freed. A revoked-but-held handle returns `REVOKED`.
- **Every argument is checked as in syscalls-ipc.md,** and `syscall::decode` and its fuzz test cover the new numbers.

### virtio-blk driver (virtio 1.x, modern PCI)

- **Transport:** the driver finds the vendor-specific capabilities (ID `0x09`) with `config_read`: `COMMON_CFG`, `NOTIFY_CFG`, `ISR_CFG`, and `DEVICE_CFG`, each with BAR, offset, and length. It maps those ranges with `mmio_map`.
- **Initialisation:**
  1. reset;
  2. `ACKNOWLEDGE`, then `DRIVER`;
  3. read features, accept only `VIRTIO_F_VERSION_1` (bit 32), and require it;
  4. `FEATURES_OK`, read back to confirm;
  5. set up queue 0;
  6. `DRIVER_OK`.

  Any unexpected value sets `FAILED` and exits.
- **Queue:** one split virtqueue, size min(device maximum, 16), in one `dma_alloc` buffer: descriptor table (16-byte aligned), available ring, and used ring (4-byte aligned). The queue's MSI-X vector is set through `queue_msix_vector` from an `irq_create` interrupt, and the configuration vector is `NO_VECTOR`.
- **Requests:** read only. A chain of three descriptors:
  - the header (`type = IN`, sector);
  - the data (device-writable, 512 to 4096 bytes);
  - the status byte (device-writable).

  Then a notify write, `irq_wait`, and a check of the used ring.
- **Device values are untrusted:**
  - used-ring index advances at most the number outstanding;
  - descriptor ID in range and outstanding;
  - status must be `OK`;
  - the length is checked against the request.
- **Test service:** the driver reads the disk's blocks into a `pharos-fs` `BlockDevice`, mounts the image with the same parser as the kernel, and reports a file's contents with `debug_write`. It then exits with a code that encodes the outcome.

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
- **Kernel memory:** DMA is at most 64 pages per device; programs at most 4 MiB; interrupt vectors are a fixed set of 16.
- **`unsafe`:**
  - port I/O for PCI configuration, IDT stubs for vectors 48–63, and the device-page bit in page tables, all in the hardware layer;
  - the `syscall` instruction in `pharos-user`;
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
