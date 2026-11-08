# Drivers and device access

## 1. Status

- **M4.4 (D-029):** hotplug below is **planned**; design **approved** (#169, 2026-11-08).
- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-27 (M2.9, #51). It follows [D-008](../project/decision-log.md#d-008-driver-strategy) (user-space drivers with device capabilities, virtio-blk only, MSI-X, no IOMMU yet) and [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries).
- **Implementation:** Rust user programs and the ELF loader are **implemented** (#52: `user/pharos-user`, `user/programs`, `crates/pharos-elf`, `process::load_elf` and `spawn_elf`; programs are in the boot filesystem as `bin/<name>`). So is PCI discovery (#53: `arch::x86_64::pci` for configuration access and BAR probing, `pci::enumerate` with decoding and a bounded capability walk, the boot log listing devices; every QEMU run attaches `disk.img` as `virtio-blk-pci,disable-legacy=on`; since #62 it also has one modern virtio-net card on user-mode networking). So are the `Device` capability with `config_read`, `mmio_map`, and `dma_alloc` (#55: `device::DeviceHandle`, `device::mmio_range`, the `DEVICE` page-table bit, `Mapped` in `pharos-user`, and the `devprobe` test program). So are device interrupts (#54: `irq::Irq` and the vector table in `kernel/src/irq.rs`, IDT stubs for vectors 48–63, MSI-X table writes through a kernel-only mapping, `irq_create` and `irq_wait`, and the `irqprobe` test program with a minimal virtio-blk queue in `user/programs/src/virtio.rs`). So is the virtio-blk driver (#56: `user/programs/src/bin/virtio-blk.rs` on the shared `pharos_programs::virtio` module, mounting the disk's `pharos-fs` image with the kernel's parser; tested in `virtio_blk`). To run that parser, `pharos-user` has a heap in its `syscall` module: a 256 KiB bump allocator that never freed memory until M3.0 replaced it with a size-class allocator over `mem_map` (#75, [user-environment.md](user-environment.md#the-user-allocator)). The M2.9 security review ([review-m2.9-drivers.md](../security/review-m2.9-drivers.md), #57) found and fixed four issues (F1–F4), recorded below where they apply.

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
| User programs | `user/programs/` (`no_std` static programs for `x86_64-unknown-linux-gnu` since M3.0, linked at `USER_BASE`; [user-environment.md](user-environment.md)) | none |
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

- **Build:** `cargo xtask` builds `user/programs/*` for `x86_64-unknown-none` with `panic = "abort"` and a linker script that places the image at `USER_BASE` (`0x400000`). The executables go into the boot filesystem image as `bin/<name>`. The user crates are workspace members, checked for the bare-metal target like the kernel, and excluded from host builds. Since M3.0 they are built for `x86_64-unknown-linux-gnu` instead, with hardware floating point (user-environment.md).
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
| 13 | `irq_wait` | interrupt handle, timeout (since M3.0, [user-environment.md](user-environment.md#timeouts)) | interrupts since the last wait (≥ 1) | interrupt, `WAIT` |

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
- **Writes and flushes (M3.0, #77):** `Blk::write` (request type `OUT`, the data descriptor device-readable) and `Blk::flush` (type `FLUSH`, no data; needs `VIRTIO_BLK_F_FLUSH`, negotiated by `Blk::init_flushing`). For both the device writes only the status byte, so `check_used` expects a used length of 1 (`Op::used_len`). The storage service is the only writer ([storage.md](storage.md#8-the-writable-store-m30)).
- **Test service:** the driver reads the disk's blocks into a `pharos-fs` `BlockDevice`, mounts the image with the same parser as the kernel, and reports a file's contents with `debug_write`. It then exits with a code that encodes the outcome (0 success, 1 not virtio-blk, 2 setup failed, 3 read failed, 4 mount failed, 5 file missing or wrong).

### Startup

In M2.9 test kernels started drivers. Since M2.10 (#61) the main kernel grants the supported devices to `init`, which starts the virtio-blk driver at boot ([services.md](services.md#init)).

### Hotplug (M4.4, D-029)

**Planned, not implemented.** Design approved (#169, 2026-11-08). D-029 (#168): native PCIe hotplug on q35 root ports, ACPI hotplug off; the kernel polls each slot on its timer, gives an arriving device BARs inside its port's window, and tells `init`, which starts the driver its table names; on the attention button `init` stops the driver and the kernel revokes the device and powers the slot off. Hotplug slots only; the boot disks and the trusted console stay on bus 0.

**The experiment (2026-11-08, QEMU 8.2.2, q35, `-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off`, two `pcie-root-port`s at `00:10.0` and `00:11.0`, chassis and slot 1 and 2).** D-029 made hotplug subject to it; it passed, so the fallback (driver restart only) is not needed.
- **Both firmwares reserve windows for an empty port**, from `info pci`. OVMF: 2 MiB of memory (`0x80200000`–`0x803fffff` for slot 1) and 512 MiB of 64-bit prefetchable memory above 4 GiB (`0xc000000000`–`0xc01fffffff`); SeaBIOS: 2 MiB of memory and 2 MiB of prefetchable memory below 4 GiB. Neither reserves I/O ports (the I/O window is closed). A port given `mem-reserve` and `pref64-reserve` gets those sizes. Bus numbers are assigned: one secondary bus per port.
- **The slot** (PCIe capability at `0x54`): Slot Capabilities `0x000a007b`, so attention button, power controller, attention and power indicators, hot-plug surprise, and hot-plug capable, physical slot 1, and command completion is signalled. Firmware hands an empty slot over powered off with every event disabled (Slot Control `0x07c0`, from OVMF's shell and SeaBIOS alike); a slot holding a device at boot is powered on (`0x03c0`), its device's BARs set by firmware.
- **`device_add`** sets both Presence Detect Changed and Attention Button Pressed (Slot Status `0x0059`). The device reads as absent (`ffffffff`) until the slot is powered on; once on, it appears at once with every BAR unassigned. Writing BARs inside the port's windows and enabling memory decoding makes QEMU show them assigned.
- **`device_del`** sets Attention Button Pressed and waits; the device is removed only when the guest powers the slot off. A second `device_add` into the same slot then works the same way, and the same window bases can be reused.
- **How:** `info pci` from the monitor for the windows (the monitor cannot read configuration space through ECAM); a throwaway multiboot guest under SeaBIOS that reads the slot registers through ports `0xCF8`/`0xCFC`, powers the slot on and off, and writes the BARs; and OVMF's shell (`pci 00 10 00 -i`) for OVMF's slot state. Not kept in the repository.

**QEMU command line.** Every `cargo xtask run` and test run gains the two root ports and the ACPI global above, with the firmware's default reservations; the `hotplug` test's runner adds a QMP channel ([Tests](#hotplug-tests)). The root ports hold no type 0 device, so devices' PCI order and every `Device(id, nth)` stay as they are.

**The kernel** (`kernel/src/hotplug.rs`, safe and host-tested; register access in `arch::x86_64::pci`):
- **Finding slots:** `pci::enumerate` records each type 1 header (bridge) on bus 0 whose PCI Express capability says slot implemented and hot-plug capable: its address, capability offset, secondary bus, and windows (memory base and limit at `0x20`; prefetchable at `0x24`, `0x28`, `0x2c`; a window whose base is above its limit is closed). A window that overlaps the boot memory map is closed, as a BAR over memory is ignored today. At most 8 slots; more are logged and ignored. A device behind a slot at boot is enumerated as today and marked removable (its slot recorded).
- **Polling:** every 10th timer tick (100 ms), the tick handler reads each slot's Slot Control and Status (one configuration read each, under the configuration lock, which is interrupt-safe), and if any event bit is set or a slot is mid-transition, sets `init`'s bound notification bit. The tick does nothing else: no allocation, no writes.
- **The slot state machine,** run when `init` calls `slot_next`, one slot at a time:

  | State | On | Does | Next |
  | --- | --- | --- | --- |
  | `Empty` | presence detected (from either event bit) | power on: Power Controller on, power indicator on, events enabled (button, presence) | `Powering` |
  | `Powering` | the function reads present, within 1 s | scan bus *secondary*, device 0 (and its functions if multi-function), assign BARs, scan as at boot, add to the device list | `Occupied`, event `ADDED` |
  | `Powering` | 1 s without the function | power off | `Empty`, logged |
  | `Occupied` | attention button | ask `init` | `Removing`, event `REMOVE` |
  | `Removing` | `slot_answer(release)` | revoke the device's root capability (stops it, masks MSI-X, zeroes the driver's mappings, #104), remove it from the device list, power off, indicators off | `Empty`, event `REMOVED` |
  | `Removing` | `slot_answer(keep)` | attention indicator blinks; QEMU's `device_del` stays pending | `Occupied` |
  | `Occupied` | presence lost (surprise removal) | as for `release`, without asking | `Empty`, event `REMOVED` |

  Each write to Slot Control waits for Command Completed before the next one (QEMU completes at once; at most 1 s, else the slot is logged as stuck and left alone). Event bits are cleared by writing them back. A button press while `Powering` or `Removing` is ignored. At most one arrival per slot per second: presence that flaps faster waits.
- **BAR assignment,** the first kernel code that writes a BAR: probe each BAR's size as at boot; memory BARs only (an I/O BAR is left unassigned and I/O decoding stays off, as no window has ports); largest first, each aligned to its size, in a bump allocation from the window's base: 64-bit prefetchable BARs in the prefetchable window, others in the memory window (a 32-bit prefetchable BAR in the prefetchable window only if that window is below 4 GiB). Each value is written and read back. A device whose BARs do not fit is logged (`pci: slot 1: 1af4:1042 does not fit its window`) and its slot powered off. The windows are freed whole on removal, as one device sits behind each port.
- **The device's MSI-X, capability walk, and BAR-over-memory checks** are the boot ones; the device is untrusted input exactly as at boot.

**`init`'s view.** A new object `Hotplug`, one per system, with a new right `HOTPLUG` (`1 << 11`); the kernel gives it to `init` only, after its device handles. New calls:

| No. | Call | Arguments | Result (`rdx`) | Capability needed |
| --- | --- | --- | --- | --- |
| 28 | `slot_notify` | hotplug, endpoint, bit | 0 | hotplug `HOTPLUG`; endpoint `RECEIVE` |
| 29 | `slot_next` | hotplug | 0 if nothing changed; else slot (bits 0–7), event (8–15: `ADDED` 1, `REMOVE` 2, `REMOVED` 3), handle (16–31, `ADDED` only), PCI ID (32–63) | hotplug `HOTPLUG` |
| 30 | `slot_answer` | hotplug, slot, release (0 or 1) | 0, or `NOT_FOUND` if the slot is not `Removing` | hotplug `HOTPLUG` |

`ADDED` puts a `Device` capability (`MAP | CONFIG | IRQ | GRANT`) in `init`'s table, derived from one the slot keeps, so revoking the slot's revokes `init`'s and every driver's. If the function's previous handle is still alive when a device arrives (`grant` refuses it), the arrival is logged (`pci: slot 1: previous device still in use`) and the slot powered off; `init` deletes its handle on `REMOVED`, and a driver's pins end with the driver, so this does not happen in the normal order. `slot_next` runs the state machine for the first slot with work and returns its event; `init` calls it until it returns 0 after each notification. Events are per-slot state, not a queue, so a device cannot fill kernel memory with them.

**Driver entries** (`pharos-services`): a new kind `Driver(id)`: a daemon started when a device with PCI ID `id` arrives, never at boot, with a new object `Arrived` in its `caps` (the device that arrived; device rights only). Rules, host-tested with the others: `Arrived` only in `Driver` entries and only there; a `Driver` entry is in no other entry's `after` and is not protected; at most one `Driver` entry per PCI ID. One device per entry: a second device of that ID while the first is in use is logged (`init: slot 2: 1af4:1042 has no free driver`) and left powered, unused, until it is removed. The capability audit matches `Arrived` to the device that entry was started with.

**What `init` does:**
- `ADDED`: record the slot and handle against the `Driver` entry for its ID and start it (`service <name> started`, as any start). An entry stopped by the user stays stopped; `start <name>` starts it on the device that is there (`NO_DEVICE` if none).
- `REMOVE`: if the device's driver is protected (none is in M4.4, as protected services' devices are on bus 0), answer `keep` and say `device in slot <n> cannot be removed: used by <service>`. Otherwise stop the driver, wait for its end notification (at most 1 s, then answer anyway: revocation stops the device), answer `release`.
- `REMOVED`: delete its handle, mark the entry `pending` (no device), and say `device <id> removed from slot <n>`.
- Every event is a debug line, an audit record (new action `device`, 22: actor `init`, detail `slot <n> added <id>`, `slot <n> remove requested`, `slot <n> kept`, `slot <n> removed <id>`), and a `trust` line (`SERVICE` gains `DeviceAdded`, `DeviceRemoved`, and `DeviceKept`, event codes 13 to 15, from `init` only; 11 is `Image` and 12 `ByUser`).

**The test driver:** `virtio-blk` with argument 1 runs as a daemon: it mounts the disk's image as today, prints the file it finds, sends `ready`, and waits until stopped. The `hotplug` test table has one `Driver(VIRTIO_BLK)` entry for it.

#### Hotplug tests

| Where | What |
| --- | --- |
| Host, `hotplug` | Slot capability and window decoding (closed, 32-bit, 64-bit, over memory); the state machine on every row above, including a stuck command, a flapping slot, and a button while `Powering`; BAR assignment (largest first, aligned, 64-bit prefetchable, does not fit, I/O left) |
| Host, `syscall` | Decoding and the fuzz test cover calls 28–30 |
| Host, `pharos-services` | The `Driver` and `Arrived` rules on the boot and test tables, and a table breaking each |
| QEMU, `hotplug` | `init` with the boot table plus the driver entry, under OVMF; the runner, over QMP, adds `virtio-blk-pci,disable-legacy=on` with a small disk image to slot 1, then: the driver starts and reads its file; `device_del` stops it and QEMU reports `DEVICE_DELETED`; a second add starts it again; a removal while the driver is stopped by the user is answered at once; every event one audit record and one `trust` line |

The runner's QMP channel is a pair of FIFOs (`qmp.in`, `qmp.out`) made like the trusted console's, so no socket path is involved; a console script step can carry a QMP command instead of a line to type.

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
- **Hotplug (M4.4, planned):**
  - only `init` holds `Hotplug`; no service or agent sees slot events or answers a removal;
  - a hot-added device is untrusted exactly as a boot device: the capability walk, MSI-X decoding, and BAR checks are the same, and the kernel, not the device, picks its BARs, inside a window firmware reserved and the kernel checked against the memory map;
  - a device cannot make the kernel allocate without bound: slot state is fixed per slot (at most 8), arrivals are limited to one per slot per second, and the tick handler only reads;
  - removal is cooperative: the device is revoked (stopped, MSI-X masked) before its slot is powered off, so no driver keeps a live mapping of a device that is gone; a surprise removal revokes at once. DMA from a hot-added device has the same limit as any device until an IOMMU.
- **`unsafe`:**
  - port I/O for PCI configuration, IDT stubs for vectors 48–63, the device-page bit in page tables, and kernel MMIO access to MSI-X tables, all in the hardware layer;
  - in `pharos-user`'s `syscall` module: the `syscall` instruction and entry stub, volatile access to mapped device memory (`Mapped`), and the heap allocator (added with #56 as a bump allocator, since #75 a size-class allocator; the shared filesystem parser needs `alloc`);
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
- **Revocation that unmaps:** revoking a device capability stops new calls, but existing register and DMA mappings stay until the process ends (security review limit). Unmapping on revoke needs a record of each capability's mappings.
- **Timeouts:** a thread waiting on a revoked or silent interrupt waits until the next interrupt.
- **A heap that frees:** done in M3.0 (#75): size classes up to 32 KiB, larger blocks as their own `mem_map` mapping.
