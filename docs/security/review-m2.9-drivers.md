# Security review: M2.9 drivers and device access

- **Scope:** everything M2.9 added at the boundary between user-space drivers, devices, and the kernel (since commit `6eb12c5`, the M2.8 gate):
  - the ELF loader;
  - system calls 9–13 and the `Device` and `Interrupt` capabilities;
  - the MMIO, MSI-X, and DMA paths;
  - every new `unsafe` block;
  - the no-IOMMU limit.
- **Design under review:** [drivers.md](../architecture/drivers.md), D-008, D-004.
- **Date:** 2026-10-28, issue #57. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim; findings fixed in the same issue.
- **Status:** **approved** by the maintainer on 2026-10-28 (M2.9 gate, #57).

## Method

1. Read every changed file under `kernel/src`, `user/`, and `crates/pharos-elf` since the M2.8 gate, and list each `unsafe` block with the invariant it relies on.
2. For each new system call, follow every argument from the register to its last use, and check every error path for state changes.
3. For each value that comes from a device (configuration space, BARs, the used ring), find where it is trusted.
4. Check every kernel structure and every kernel allocation that a driver can make grow.
5. Follow a device's life: grant, use, handle deletion, revocation, process exit and kill, and grant again.
6. Turn each finding into a check that fails without the fix: a test-kernel check, or a host unit test where QEMU's device cannot misbehave. Each fix was mutation-checked.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | The kernel trusted the BAR addresses a device reports. A hostile or misconfigured device whose memory BAR overlaps RAM would let its driver map that RAM with `mmio_map`. It would also make the kernel write MSI-X entries into RAM, because the kernel's MMIO path writes through `HHDM + physical`, which for RAM is the direct map. | **Fixed:** `pci::enumerate` removes every memory BAR that overlaps an entry of the boot memory map or wraps around, and logs it; with a truncated memory map it trusts no memory BAR. Host test `bars_over_memory_are_removed`; the `pci`, `device_caps`, `device_irq`, and `virtio_blk` kernels confirm the virtio-blk BARs are kept. In QEMU the check already fires on real input: the VGA framebuffer BAR (00:01.0, BAR0) overlaps the memory map's framebuffer entry and is ignored, which is right, because the bootloader handed the framebuffer to the kernel. |
| F2 | Medium | A register mapping did not keep its device alive, and a device could be granted twice. A driver that mapped registers and deleted its handles had the device stopped under it. Worse, the kernel could grant the device again while the first driver still had its registers mapped. Two drivers would then share one device, or the old one would keep register access after the device was handed on. | **Fixed:** `mmio_map` pins the device to the process, as `dma_alloc` already did, and `DeviceHandle::grant` refuses a device that still has a live handle. `device_caps` checks that a second grant is refused, and that a process holding only a register mapping keeps the device enabled and ungrantable until it ends. Then the device is stopped and can be granted again. Mutation-checked (no pin, non-exclusive grant). |
| F3 | Low | One driver could take all 16 interrupt vectors through a device with a large MSI-X table, starving other drivers. | **Fixed:** at most 4 vectors per device (`irq::MAX_PER_DEVICE`). Host test; mutation-checked. |
| F4 | Medium | `mmio_map` had no limit. A driver could map its registers again and again at new addresses, and each mapping can make the kernel allocate page-table frames, held until the process ends. Before M2.9 processes could not map memory themselves, so this is new. | **Fixed:** at most 256 register pages per process (`device::MAX_MMIO_PAGES`), checked before mapping; error `NO_MEMORY`. `devprobe` maps until refused: exactly 256 pages. Mutation-checked. |

## System calls

Every call goes through the M2.7 path: `syscall::decode` (fuzzed with 200,000 random calls, now covering numbers 0–14), then the handle and its rights, then the work.

| Call | User input | Checks | State changed on error | Verdict |
| --- | --- | --- | --- | --- |
| `open`, `read` (M2.8) | — | Reviewed at M2.8; unchanged except that `open` now passes the child's rights explicitly (`READ` and `GRANT`, masked by the parent's) | none | OK |
| `config_read` | device, offset, width | width 1, 2, or 4; offset < 256 and aligned; `CONFIG` on a `Device`. Read-only: no call writes configuration space | none | OK |
| `mmio_map` | device, BAR, offset, length, address | page-aligned user range below the last user page; `MAP` on a `Device`; a memory BAR (F1: never over RAM); range inside the BAR; never a page of the MSI-X table or PBA; the address range free (`IN_USE`); at most 256 pages per process (F4). Pages: user, writable, uncached, no-execute, `DEVICE` bit | none: a partial mapping is undone | OK (F1, F2, F4 fixed) |
| `dma_alloc` | device, pages, address | 1–16 pages; page-aligned user range, free; `MAP`; at most 64 pages per device. Fresh frames, zeroed, contiguous, owned by the device handle; the device is pinned to the process | none: frames freed if mapping fails | OK |
| `irq_create` | device, MSI-X entry | entry < 2048 (decode), < the device's table size; `IRQ` on a `Device`; a free handle slot; the entry not already routed (`IN_USE`); a free vector, at most 4 per device (F3). The kernel writes the table entry; the child capability gets `WAIT` plus the parent's `GRANT` | none: a failed table write drops the object, which masks the entry and frees the vector | OK (F3 fixed) |
| `irq_wait` | interrupt | `WAIT` on an `Interrupt`; one waiter per interrupt (`IN_USE`); revoked → `REVOKED`. Counts are taken under the vector lock with interrupts disabled, so no wake is lost | none | OK |

## Device paths

- **Configuration space:** the kernel alone writes it: the command register (grant and release), the MSI-X control word, and BAR size probes that restore every register with decoding off and interrupts disabled. The capability walk is bounded (48 steps, pointers ≥ `0x40` and aligned).
- **BARs:** decoded with checked arithmetic; since F1, removed if they overlap the memory map or wrap. Drivers map only whole pages inside a remaining memory BAR.
- **MSI-X:** drivers never map the table or PBA pages. The kernel writes an entry masked first, then address and data, then unmasks. Vectors come from a fixed set of 16. The handler counts, sends EOI, and wakes; it runs no driver code. An interrupt on a free device vector is counted as spurious. Deleting an interrupt masks its entry before freeing the vector.
- **DMA:** buffers belong to the device handle and are freed only after bus mastering and memory decoding are off and MSI-X is masked. Any process that maps the device's registers or buffers pins the handle until it ends (F2), and a pinned device cannot be granted again.
- **Release:** checked after a clean exit (`device_caps`, `device_irq`, `virtio_blk`) and after a driver is killed with a read in flight (`virtio_blk`): decoding and bus mastering off, vector freed, entry masked, every frame back.
- **Device values in the driver:** the virtio-blk driver checks the device ID, feature negotiation, queue size, notify offset, capacity, and every used-ring value (index advance, descriptor ID, length, status) before use. The used-ring checks are host-tested (`virtio::check_used`).

## The ELF loader

- `pharos-elf` is safe Rust (`unsafe` forbidden) and checks the whole file before the kernel allocates anything:
  - static ELF64 x86-64 `ET_EXEC` only;
  - at most 8 segments, inside `USER_BASE` + 16 MiB;
  - W^X, no two segments sharing a page;
  - the entry point inside an executable segment.

  It is fuzzed with 100,000 inputs, and the `user_elf` kernel boots ten malformed files with no process created and no frame lost.
- Files are at most 4 MiB. Each page is filled from the file through the bounds-checked filesystem read, and a short read fails the load.
- On any failure the half-built address space is destroyed.

## `unsafe` added in M2.9

All of it stays in the allowed modules (AGENTS.md) and has a `// SAFETY:` comment (enforced by Clippy).

| Location | What | Invariant | Verdict |
| --- | --- | --- | --- |
| `arch::x86_64::pci` `outl`, `inl` | Port I/O | Only ports `0xCF8`/`0xCFC`, under a lock with interrupts off; writes limited to the command register, MSI-X control, and restored BAR probes | OK |
| `paging::map_dma` | `write_bytes` zeroing | The frames were just allocated and are reached through the direct map | OK |
| `paging::mmio_write32`, `mmio_read32` | Volatile access at `HHDM + physical` | Callers pass only MSI-X table entries of memory BARs that do not overlap RAM (F1), mapped uncached on first use | OK (F1) |
| `idt` device stubs and gates | Vectors 48–63 | Same common entry path as every other vector; gates written before `lidt` | OK |
| `pharos-user` `_start`, `raw` | Entry stub, `syscall` | Aligns the stack and calls the safe `pharos_main`; `syscall` clobbers only `rcx`, `r11`, and the declared registers | OK |
| `pharos-user` `Mapped` | Volatile reads and writes | Built only by the wrappers after the kernel confirmed the mapping, which lasts for the process's life; every access is bounds-checked and aligned | OK |
| `pharos-user` heap (`Bump`) | `GlobalAlloc`, a static arena | Hands out disjoint, aligned ranges claimed atomically; never frees. Host-tested | OK (replaced in M3.0, #75; reviewed at the M3.0 gate) |
| `pharos-user` `entry!` | `#[unsafe(no_mangle)]` | Names the entry symbol; the function body is safe | OK |

## Accepted limits (tracked)

- **No IOMMU (D-008):** a driver can program its device to read or write any physical memory, so in M2.9 a driver is trusted with all memory through its device. Only the kernel starts drivers. The IOMMU (VT-d) is evaluated before real-hardware use.
- **Revocation does not unmap:** revoking or deleting a device capability stops new calls, but registers and DMA buffers already mapped stay mapped until the process ends (the pin keeps the device consistent meanwhile). Ending the process is the full revocation. Unmapping on revoke needs a record of each capability's mappings.
- **A thread waiting on a revoked interrupt** stays blocked until the next interrupt on that vector; there are no timeouts.
- **Vector reuse:** an interrupt already in flight when its vector is freed can wake the next owner once. Drivers must re-check their device after every wake, as the virtio-blk driver does.
- **Program size:** a program's segments may reserve up to 16 MiB of frames. Programs come only from the kernel's boot image.
- **SMP:** MSI-X targets the bootstrap CPU, and the locking assumes one CPU.

## Approval

Approved by the maintainer on 2026-10-28, as part of the M2.9 gate (#57). The accepted limits above are tracked in [drivers.md](../architecture/drivers.md) (open questions and security) and as limits in the [threat model](threat-model.md).
