# Memory management

## 1. Status

- **Design:** Accepted with [D-005](../project/decision-log.md#d-005-memory-management-strategy) (2026-10-27).
- **Implementation:** the frame allocator (#26) and the kernel's own page tables with guard pages (#27) are **implemented**. Reclaiming bootloader memory (#28) and the kernel heap (#29) are **planned** ([M2.5](../project/implementation-roadmap.md#m25--physical-and-virtual-memory-management)). This document is completed and reviewed at the M2.5 gate (#30).

## 2. Context

Limine hands over its own page tables (in bootloader-reclaimable memory), a direct map of selected memory-map regions (HHDM), and a memory map. The kernel needs to allocate physical memory, control its own mappings and their permissions, catch stack overflows, and later free the bootloader's memory and give itself a heap. D-004 constraint 3 asks for address spaces as first-class objects and a frame allocator whose regions can later be granted and revoked.

## 3. Design

### Boot order

After the GDT and IDT, `kmain` (and test kernels through `testing::init_memory`):

1. builds the frame allocator from the memory map (`mm::init_frames`);
2. builds the kernel address space and switches CR3 to it (`mm::init_paging`);
3. maps the local APIC registers through it (`apic::init`).

### Physical frames (`mm::frame`, `mm::bitmap`)

- One bitmap per usable region, one bit per 4 KiB frame, set = used. Only usable regions at or above 1 MiB are managed today; at most 64 regions (more are counted and reported as skipped).
- The bitmaps live at the start of the largest usable region, reached through the direct map; those frames are reserved. About 8 KiB covers 256 MiB.
- Single frames use next fit; contiguous runs use a linear scan with physical alignment. Double frees and frees of unknown frames are errors; out of memory is an error value.
- The allocator sits behind `IrqMutex` (`mm::raw`), which disables interrupts while held.

### Page tables (`arch::x86_64::paging`)

- `AddressSpace` owns a 4-level tree; table frames come from the frame allocator and are zeroed through the direct map. It maps 4 KiB and 2 MiB pages, unmaps (with `invlpg` when active), and translates. Permissions live in leaf entries; table entries allow everything.
- NX bits are set only when `EFER.NXE` is on.
- Lock order: the frame allocator first, then the kernel address space.

### Kernel address space

| Range | Maps | Access |
| --- | --- | --- |
| `HHDM + phys` | Usable, bootloader-reclaimable, ACPI reclaimable and NVS, reserved-mapped regions | Writable, no-execute |
| `HHDM + phys` | Executable and modules (the kernel image's physical frames) | Read-only, no-execute |
| `HHDM + phys` | Framebuffer | Writable, no-execute, uncached |
| `HHDM + 0xfee00000` (usually) | Local APIC registers | Writable, no-execute, uncached |
| `0xffffffff80000000`… | Limine requests and GOT | Writable, no-execute |
| | Text | Read + execute |
| | Rodata | Read-only, no-execute |
| | Data and bss | Writable, no-execute |
| | Kernel stack (64 KiB), guard page below | Writable, no-execute |
| | Double-fault stack (16 KiB, IST1), guard page below | Writable, no-execute |
| `0xffffc00000000000` | Kernel heap (planned, #29) | — |
| `0xffffd00000000000` | Test page used by test kernels | — |

The HHDM offset is Limine's (`0xffff800000000000` in QEMU), so addresses computed before the switch stay valid. The direct map uses 2 MiB pages where a region's virtual and physical addresses are 2 MiB-aligned and enough of the region remains, 4 KiB elsewhere; edge pages shared by neighbouring regions are mapped once. Segment boundaries come from `linker.ld` symbols; the kernel's physical base comes from Limine's executable-address response. Guard pages are gaps that `linker.ld` leaves between segments and that the kernel never maps.

In QEMU with 256 MiB the kernel tables take 19 frames under UEFI and 10 under BIOS.

## 4. Security

- Write protection (CR0.WP, enabled by Limine) and NX make the kernel's code read-only and its data non-executable, and remove the writable alias of the kernel image from the direct map.
- Stack overflows hit a guard page and are reported as double faults; the double-fault stack has its own guard page.
- `unsafe` code: page-table and CR3 writes in `arch::x86_64::paging`; raw memory (bitmap storage, the lock cell) in `mm::raw`. Allocator logic is safe Rust.
- Limits: there is still only one address space and no user mode; all kernel memory is reachable through the writable direct map; one stack frame larger than a guard page could jump over it.

## 5. Testing

- Host unit tests: bitmap and frame allocation (alignment, edges, double frees, exhaustion), page-table entry encoding, page splitting, and direct-map kinds.
- Test kernels: `frames` (allocation, freeing, exhaustion), `paging` (segment permissions, guard pages, direct map with 2 MiB pages, map/write/alias/unmap, page fault after unmap), `write_protect` (writing rodata faults with a protection-violation write), `no_execute` (executing data faults with an instruction-fetch error), and `double_fault` (stack overflow on the kernel's own tables). Each was checked once to fail when the property it tests is broken.

## 6. Alternatives

See D-005: free-list and buddy frame allocators, extending Limine's page tables, a different direct-map offset, 1 GiB pages (not available on QEMU's default CPU), and allocator crates.

## 7. Open questions

- Reclaiming bootloader memory and copying Limine responses first (#28).
- Heap size and growth (#29).
- Freeing empty page tables when address spaces come and go (M2.7).
- KASLR.
