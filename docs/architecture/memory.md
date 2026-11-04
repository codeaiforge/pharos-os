# Memory management

## 1. Status

- **Design:** Accepted with [D-005](../project/decision-log.md#d-005-memory-management-strategy) (2026-10-27).
- **Implementation:** the frame allocator (#26), the kernel's own page tables with guard pages (#27), reclaiming bootloader memory (#28), and the kernel heap with `alloc` (#29) are **implemented** ([M2.5](../project/implementation-roadmap.md#m25--physical-and-virtual-memory-management)), and so are process address spaces (M2.7, #38). Reviewed and approved by the maintainer on 2026-10-27 (M2.5 gate).

## 2. Context

Limine hands over its own page tables (in bootloader-reclaimable memory), a direct map of selected memory-map regions (HHDM), and a memory map. The kernel needs to allocate physical memory, control its own mappings and their permissions, catch stack overflows, and later free the bootloader's memory and give itself a heap. D-004 constraint 3 asks for address spaces as first-class objects and a frame allocator whose regions can later be granted and revoked.

## 3. Design

### Boot order

After the GDT and IDT, `kmain` (and test kernels through `testing::init_memory`):

1. copies the memory map into kernel memory and builds the frame allocator from it (`mm::init_frames`);
2. builds the kernel address space and switches CR3 to it (`mm::init_paging`);
3. maps the local APIC registers through it (`apic::init`);
4. after its last read of a Limine response, reclaims bootloader memory (`mm::reclaim_bootloader_memory`; `kmain` only, as its last step before `PHAROS: boot ok`).

### Kernel heap (`mm::heap`, `mm::raw`)

- A fixed 4 MiB window at `0xffffc00000000000`, mapped writable and no-execute with 1,024 fresh frames by `mm::init_heap` (after the switch to the kernel's own page tables; `kmain` calls it after reclaim).
- The shared bitmap allocator over 16-byte units: every block is 16-byte aligned or more, larger alignments are honoured, and sizes come from the `Layout` on free, so allocated memory holds no headers. The bitmap (32 KiB) is a kernel static.
- `mm::raw::KernelAllocator` is Rust's `#[global_allocator]` on the kernel target; it locks the heap with `IrqMutex`, so code may allocate with interrupts enabled. A free of something the heap did not hand out panics (memory is already corrupt at that point).
- Out of memory: the allocator returns null and Rust's `alloc` calls the panic handler with `memory allocation of N bytes failed`.
- `kmain` runs a smoke test (collect and sum a `Vec`) after setting up the heap, so the boot check covers `alloc` under UEFI and BIOS.

### Reclaiming bootloader memory

Bootloader-reclaimable regions hold Limine's boot stack, GDT, page tables, and its responses (including the memory map). The kernel stops using each of them: it switches to its own stack (first thing in `kmain`), GDT (#20), and page tables (#27), and copies the memory map into a kernel static (`mm::memory_map()`, up to 128 entries; more are counted as truncated). The frame allocator is built over usable **and** reclaimable regions from the start (their bitmap storage is planned up front), with reclaimable frames marked used. Reclaim then:

1. refuses to run unless the kernel's own page tables are active;
2. retires Limine's responses: from then on every `Request::response()` returns `None`;
3. frees the reclaimable frames (once; later calls gain nothing).

References to responses obtained before reclaim must not be used afterwards; this is a documented rule, not enforced by the type system. In QEMU with 256 MiB, reclaim adds 41 MiB under UEFI and 144 frames under BIOS.

### Physical frames (`mm::frame`, `mm::bitmap`)

- One bitmap per usable or bootloader-reclaimable region, one bit per 4 KiB frame, set = used. Only regions at or above 1 MiB are managed; at most 64 regions (more are counted and reported as skipped).
- The bitmaps live at the start of the largest usable region, reached through the direct map; those frames are reserved. About 8 KiB covers 256 MiB.
- Single frames use next fit; contiguous runs use a linear scan with physical alignment. Double frees and frees of unknown frames are errors; out of memory is an error value.
- The allocator sits behind `IrqMutex` (`mm::raw`), which disables interrupts while held.

### Page tables (`arch::x86_64::paging`)

- `AddressSpace` owns a 4-level tree; table frames come from the frame allocator and are zeroed through the direct map. It maps 4 KiB and 2 MiB pages, unmaps (with `invlpg` when active), and translates. Permissions live in leaf entries, including the user bit; table entries allow everything.
- NX bits are set only when `EFER.NXE` is on.
- **Global pages (#41):** kernel-half leaf entries have the global bit and `CR4.PGE` is on (enabled after the switch to the kernel's tables, which flushes the whole TLB). So kernel translations survive CR3 switches between process address spaces. User-half entries are never global.
- **TLB flushes:** unmapping from the kernel address space always flushes the page (`invlpg`), even while a process space is active, because the kernel half is shared by every space.
  - Before #41, the flush happened only when the kernel space was active. A task stack freed while a user thread ran could then stay reachable through a stale TLB entry.
  - The `address_spaces` test kernel now checks a kernel remap made while a process space is active.
- Lock order: the frame allocator first, then the kernel address space.

### Process address spaces (M2.7, #38)

- `AddressSpace::new_user` creates an empty user half (below `0x0000800000000000`) and copies the kernel-half PML4 entries (256–511) of the kernel address space, so every kernel mapping is shared.
- To keep the copies valid, the kernel creates a table behind every kernel-half PML4 entry at boot. Those entries never change afterwards (1 MiB of tables).
- **Mapping rules (`MapError::WrongHalf`):** a process space maps only its user half; the kernel space never maps user pages. User pages use `Flags::USER_DATA` (read + write, no-execute) or `Flags::USER_CODE` (read + execute).
- **Ownership:** every frame mapped into a process space belongs to it, except pages marked with the software `DEVICE` bit (bit 9, ignored by the MMU): device registers and DMA buffers (M2.9), and shared memory (M3.0, #80: `AddressSpace::disown` marks a `mem_map` mapping's pages when `mem_share` hands their frames to a `Memory` object, and `mem_map_cap` maps them with the bit). `destroy` frees the owned frames, then the user half's page tables and the root (never the shared kernel half), and refuses to run while the space is active.
- **Process memory (M3.0):** `mem_map` maps owned, zeroed pages in the map region under a per-process page limit (#75); a `SharedMemory` object owns shared frames and frees them when the last capability and mapping referencing it are gone (#80). Both are described in [user-environment.md](user-environment.md#user-memory).
- **Tasks:** `sched::spawn_in(space, closure)` runs a task in a process space. Its context owns the space, destroys it when the task is reaped, and the switch loads its root into CR3; kernel tasks run on the kernel root ([scheduling.md](scheduling.md)). Since #122 an ending process first leaves its space (`Context::leave_space`, then the kernel root) and frees it 4 page tables at a time with interrupts let in between (`AddressSpace::free_user_part`), so the reap finds it empty.

### Kernel address space

| Range | Maps | Access |
| --- | --- | --- |
| `HHDM + phys` | Usable, bootloader-reclaimable, ACPI reclaimable and NVS, reserved-mapped regions | Writable, no-execute |
| `HHDM + phys` | Executable and modules (the kernel image's physical frames, and boot modules used as RAM disks; never given to the frame allocator) | Read-only, no-execute |
| `HHDM + phys` | Framebuffer | Writable, no-execute, uncached |
| `HHDM + 0xfee00000` (usually) | Local APIC registers | Writable, no-execute, uncached |
| `0xffffffff80000000`… | Limine requests and GOT | Writable, no-execute |
| | Text | Read + execute |
| | Rodata | Read-only, no-execute |
| | Data and bss | Writable, no-execute |
| | Kernel stack (64 KiB), guard page below | Writable, no-execute |
| | Double-fault stack (16 KiB, IST1), guard page below | Writable, no-execute |
| `0xffffc00000000000` | Kernel heap (4 MiB) | Writable, no-execute |
| `0x0` – `0x7fffffffffff` | User half: empty in the kernel address space; private in each process address space ([syscalls-ipc.md](syscalls-ipc.md#address-space-layout-per-process)) | Process pages only |
| `0xffffc80000000000` | Task stacks: 64 slots of 64 KiB, each a 32 KiB stack above an unmapped 32 KiB guard area ([scheduling.md](scheduling.md)) | Writable, no-execute |
| `0xffffd00000000000` | Test page used by test kernels | — |

The HHDM offset is Limine's (`0xffff800000000000` in QEMU), so addresses computed before the switch stay valid. The direct map uses 2 MiB pages where a region's virtual and physical addresses are 2 MiB-aligned and enough of the region remains, 4 KiB elsewhere; edge pages shared by neighbouring regions are mapped once. Segment boundaries come from `linker.ld` symbols; the kernel's physical base comes from Limine's executable-address response. Guard pages are gaps that `linker.ld` leaves between segments and that the kernel never maps.

In QEMU with 256 MiB the kernel tables take 273 frames under UEFI and 264 under BIOS. Of these, 254 are the tables pre-created behind kernel-half PML4 entries; before #38 the counts were 19 and 10.

## 4. Security

- Write protection (CR0.WP, enabled by Limine) and NX make the kernel's code read-only and its data non-executable, and remove the writable alias of the kernel image from the direct map.
- SMEP and SMAP are enabled after the switch to the kernel's tables when CPUID reports them (#39). QEMU's default CPU does not, so CI runs without them; all test kernels also passed locally with `-cpu max` (both on).
- Stack overflows hit a guard page and are reported as double faults; the double-fault stack has its own guard page.
- `unsafe` code: page-table and CR3 writes in `arch::x86_64::paging`; raw memory (bitmap storage, the lock cell) in `mm::raw`. Allocator logic is safe Rust.
- Limits: there is still only one address space and no user mode; all kernel memory is reachable through the writable direct map; one stack frame larger than a guard page could jump over it.

## 5. Testing

- Host unit tests: heap allocation (rounding, alignment, coalescing, bad and double frees, exhaustion), bitmap and frame allocation (alignment, edges, double frees, exhaustion), page-table entry encoding, page splitting, and direct-map kinds.
- Test kernels: `frames` (allocation, freeing, exhaustion), `reclaim` (reclaimed frame count, retired responses, every frame written afterwards with the copied memory map intact), `paging` (segment permissions, guard pages, direct map with 2 MiB pages, map/write/alias/unmap, page fault after unmap), `heap` (collections, 4 KiB alignment, a 20,000-operation fragmentation run with contents checked, usage back to zero, allocation with interrupts on), `heap_oom` (exhaustion reported by the panic handler), `write_protect` (writing rodata faults with a protection-violation write), `no_execute` (executing data faults with an instruction-fetch error), and `double_fault` (stack overflow on the kernel's own tables). Each was checked once to fail when the property it tests is broken.

## 6. Alternatives

See D-005: free-list and buddy frame allocators, extending Limine's page tables, a different direct-map offset, 1 GiB pages (not available on QEMU's default CPU), and allocator crates.

## 7. Open questions

- Enforcing the end of Limine responses in the type system instead of by rule.
- Heap growth beyond the fixed 4 MiB, and a faster search than a linear bitmap scan if profiling shows a need.
- Freeing empty page tables in the kernel address space (process spaces free all of theirs on `destroy`).
- KASLR.
