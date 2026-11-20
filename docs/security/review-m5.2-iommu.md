# Security review: M5.2 VT-d driver

- **Scope:** the new privileged code DMA isolation depends on (D-044, [iommu.md](../architecture/iommu.md)):
  - `kernel/src/iommu.rs`: the tables, the domains, capability and fault decoding, and the global module (`init`, `attach`, `map`, `unmap`, `detach`, `take_faults`);
  - `kernel/src/arch/x86_64/iommu.rs`: the unit's registers, the enable sequence, the invalidations, and `KernelMemory` (`unsafe`);
  - `kernel/src/device.rs`: grant, DMA buffers, release, and drop;
  - `DmaAlloc` in `kernel/src/syscall.rs`, and the DMAR lookup before PCI enumeration in `kernel/src/main.rs`.
- **Design under review:** iommu.md, the threat model's DMA rows, D-044, and AGENTS.md sections 5 and 7. The roadmap's M5.2 risks ask for this review, held as M5.4 reviewed the trusted base.
- **Threat model:** a compromised user-space driver controls its virtio device fully, and makes any system call its capabilities allow, in any order. It wins if any DMA reaches memory outside its buffers, or the kernel hangs, crashes, or runs out of memory.
- **Dates:** 2026-11-18, milestone M5.2. Code under review: `main` at `39141ca`.
- **Status:** **signed off** by the maintainer on 2026-11-18 (the M5.2 gate), with the severities as proposed and #246–#251 filed rather than fixed before the gate.

## Reviewers and their independence

Neither reviewer was given the M5.4 report, the CHANGELOG, the roadmap, or the main session's view. Both followed one written method:
1. attack surface;
2. every input traced to its use;
3. every `unsafe` invariant;
4. the order of unmap, invalidation, and free on every path;
5. the VT-d entry formats and commands against the specification;
6. denial of service.

Each finding had to quote code with `file:line` and give a trigger, or be marked unconfirmed.

| Reviewer | Family | Independence |
| --- | --- | --- |
| gemini-3.8-flash (GitHub Copilot CLI, read-only: shell, write, and network tools denied) | Different family (Google) | **Independent of the authoring model**, as M5.4's minimum asks |
| Claude (a separate agent, Claude Code; it may run host tests, not edit) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method |

The main session (Claude Code, which wrote the driver) checked every finding against the code before filing it.

## Findings fixed

| Issue | Proposed severity | Found by | Finding | Test (fails without the fix) |
| --- | --- | --- | --- | --- |
| #252 | Critical (Gemini), Medium (Claude: trigger unconfirmed) | both, as V-1 | `DmaAlloc` mapped the buffer into the driver and recorded it on the device handle, then returned `NO_MEMORY` when the IOMMU mapping failed, before pinning the handle for the process. If the driver deleted its device handle and the kernel dropped its own, the handle's drop freed the buffer while the driver still mapped it writable. Reaching it needs `iommu::map` to fail: a table frame not allocated, which the trusted reserve makes hard, or a buffer beyond the tables' 512 GiB reach. Fixed: the buffer is recorded and pinned before the mapping, so a failed one ends as the others do (unmap, invalidate, free) | `device_caps`: `iommu::fail_next_map` (a test-kernel hook) fails the mapping; the driver deletes its handle and the kernel drops its own; no frame may be freed before the driver ends |

## Findings filed

| Issue | Proposed severity | Found by | Finding |
| --- | --- | --- | --- |
| #246 (fixed: faults logged and counted on device stop, release, and drop, 2026-11-20) | Low (Gemini), Info (Claude) | both (Claude V-8, Gemini V-4) | Fault records are read only by the test kernel; a blocked DMA in production is not logged, and after the first fault the single fault register overflows. iommu.md said otherwise and is corrected |
| #247 (fixed: the context entry removed and the ID retired, 2026-11-20) | High (Gemini), Info (Claude) | both (Claude V-6, Gemini V-2) | A failed context invalidation in `attach` leaves the entry and the domain installed: the function can never be granted again. Fails closed; not triggerable by a driver |
| #248 (fixed: the ID retired, the tables leaked, 2026-11-20) | Low | Claude V-5 | After a failed invalidation in `detach`, the domain ID and the function can be reused while the unit's caches may hold old entries. Needs a unit timeout, which a driver cannot cause on QEMU |
| #249 (fixed: reserved under one lock, 2026-11-20) | Low | Claude V-2 | `DmaAlloc` checks the 64-page limit and records the buffer under different locks: drivers sharing a device can exceed it. Bounded by the trusted reserve |
| #250 (fixed: a 10 ms clock timeout, one invalidation per driver end, 2026-11-20) | Info | Claude V-9 | Status polling counts reads, not time, with interrupts off, and a driver's end invalidates once per buffer |
| #251 | Medium (Gemini), Low (Claude) | both (V-3; V-4 and V-7 Claude, V-5 Gemini) | For bare metal (M8.1), not reachable on QEMU's topology:<ul><li>requester-ID aliasing behind conventional PCI bridges;</li><li>bridge scopes trusting live bus numbers;</li><li>table levels and the domain count taken from the first unit only</li></ul> |

## Checked and found correct (both reviewers)

- **Order before a free:** an unmap clears the entries, then invalidates the IOTLB with drain and waits, and only then frees the tables it left empty. A driver's end turns bus mastering off before its buffers are unmapped. A drop stops the device, then detaches it (context, then IOTLB invalidation), then frees. On any failed invalidation, frames are leaked, never reused.
- **No entry points at a freed frame:** an emptied table is unlinked from its parent before it is freed.
- **`KernelMemory`:** its ownership asserts are not reachable from user input. Physical addresses come from the kernel's allocator, and indices stay below 512.
- **Entry formats and commands** match the specification:
  - root, context (AW = levels − 2, DID in bits 23:8), and second-level entries;
  - the enable sequence, with one-shot `GSTS` bits masked;
  - low-then-high 64-bit writes;
  - fault-record fields;
  - `clflush` for a non-coherent unit.
- **Fail closed:**
  - translation is on before PCI enumeration;
  - the boot is refused without a DMAR, with reserved regions, or on another segment;
  - a device no scope covers is not granted.

## Sign-off

The maintainer signed off on 2026-11-18, closing the M5.2 gate.
