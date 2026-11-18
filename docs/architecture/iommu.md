# DMA isolation: a VT-d driver for QEMU's `intel-iommu`

## 1. Status

- **Design:** **Accepted**: approved by the maintainer on 2026-11-15 (#239), with each open question decided as recommended (section 7). It follows [D-044](../project/decision-log.md#d-044-reference-platform-and-the-limits-required-on-a-real-host) item 3 (accepted 2026-11-15) and [D-008](../project/decision-log.md) (user-space drivers, the IOMMU left open).
- **Implementation:** **implemented** for the KVM reference platform: the ACPI and DMAR parsers (#241); the VT-d registers and tables, with translation on at boot and nothing attached (#242); the device hooks, `VIRTIO_F_ACCESS_PLATFORM`, and `iommu_platform=on` on every virtio device, so each granted device's DMA reaches only its own buffers (#243); and the `iommu` test kernel's DMA attack on a kernel canary and the threat model's rows (#244). Identity-mapping the first 16 MiB in every domain failed CI on the throwaway branch `mutation/iommu-identity-map` ([run 43745306163](https://github.com/codeaiforge/pharos-os/actions/runs/43745306163)): only the `iommu` kernel failed, at the canary and fault checks; the host tests, Rust 1.85, and the other kernels passed.

## 2. Context

A driver reaches its device through capabilities: registers, interrupts, and DMA buffers from `dma_alloc` ([drivers.md](drivers.md)). Nothing stops it from writing any physical address into a descriptor, and the device then reads or writes that address: a compromised driver controls all guest memory, kernel included. The threat model carries this as a limit (no IOMMU); on a KVM host it is real. The network service is the realistic attacker, since it parses packets from untrusted peers.

What the kernel already does that this builds on (`kernel/src/device.rs`):

- one `DeviceHandle` per granted PCI function, at most one driver at a time;
- every DMA buffer allocated by the kernel (`dma_alloc`, at most 64 pages per device), recorded with its owner;
- bus mastering off before a device's buffers are freed (on the handle's drop and when the owning process ends), on again at the next `dma_alloc`.

What it lacks: any ACPI parsing (PCI configuration goes through ports `0xcf8`/`0xcfc`), and any way to make the device itself unable to reach memory it was not given.

Facts about the platform (QEMU 8.2 on the development host):

- `-device intel-iommu` needs `q35`, which every image already uses. Defaults: legacy (not scalable) mode, 39-bit guest addresses (3-level second-level tables), `caching-mode=off`, interrupt remapping `auto`.
- A virtio-pci device bypasses the IOMMU unless it is created with `iommu_platform=on`, and then its driver must accept `VIRTIO_F_ACCESS_PLATFORM` (feature bit 33). The drivers accept it when offered (#243). **QEMU refuses `FEATURES_OK` when the driver does not accept bit 33** (verified in #243: the `virtio_blk` test kernel fails without it), so a driver cannot fall back to untranslated DMA.
- **QEMU 8.2's DMAR does not set INCLUDE_PCI_ALL** (found by the `acpi` test kernel, #241): its one unit, at `0xfed9_0000`, names each function on bus 0 in a device scope (endpoints, the root-port bridges, the I/O APIC). A function no unit names is not translated, so the driver must refuse to grant a device that no unit covers (#242, #243).
- **QEMU's unit is not coherent** (`ECAP` `0xf42`: `C` is 0; found by the `iommu` test kernel, #242): it reads the tables from memory without snooping the CPU's caches, so the kernel flushes each table write (`clflush`, then `mfence`) before telling the unit. Its `CAP` (`0x00d2008c22260206`): 39-bit tables only (3 levels), 65,536 domain IDs, one fault-recording register at `0x220`, no write-buffer flush; the IOTLB register is at `0xf8`. Register-based invalidation works in legacy mode.
- VT-d does not translate writes to the interrupt range `0xfee0_0000`–`0xfeef_ffff`; they are MSIs.

## 3. Design

### Overview

```mermaid
flowchart LR
    classDef kernel fill:#1e3a5f,stroke:#0f1f33,color:#ffffff
    classDef service fill:#eceff1,stroke:#607d8b,color:#1c262b
    classDef device fill:#fff8e1,stroke:#8d6e63,color:#3e2723
    classDef mem fill:#d8f0dc,stroke:#2e7d32,color:#10301a
    classDef bad fill:#ffebee,stroke:#c62828,color:#4a0d0d

    driver["net driver<br/>(user space)"]:::service
    dev[["virtio-net<br/>iommu_platform=on"]]:::device
    iommu["VT-d unit<br/>context entry for 00:03.0<br/>→ domain 3"]:::kernel
    own[("the device's own<br/>DMA pages")]:::mem
    other[("any other memory:<br/>kernel, other processes")]:::bad

    driver -->|"descriptor: any address"| dev
    dev -->|"DMA"| iommu
    iommu -->|"mapped: IOVA = physical"| own
    iommu -. "not mapped: blocked,<br/>fault recorded" .-> other
```

- **One domain per granted device.** Each `DeviceHandle` gets its own second-level page table. It maps exactly that device's DMA buffers, at I/O virtual address = physical address (identity), so drivers and descriptors do not change. Everything else is unmapped, so the device's access to it faults.
- **Blocked by default.** Translation is turned on at boot, before any driver runs, with every context entry not present: a device no driver holds can reach nothing.
- **Order of operations,** the invariant the review checks:
  - `grant`: attach the device (context entry → its empty domain, context-cache invalidation) **before** bus mastering goes on;
  - `dma_alloc`: map the new pages (and flush the write buffer if `CAP.RWBF`) **before** returning them to the driver;
  - process end or handle drop: bus mastering off, unmap the pages, **invalidate the IOTLB for the domain and wait for it to finish**, and only then free the frames;
  - handle drop: detach the context entry (invalidate) before the function can be granted again.

### Pieces

| Piece | Where | `unsafe` | Does |
| --- | --- | --- | --- |
| Limine RSDP request | `kernel/src/limine.rs` (already an `unsafe` module) | a new request static, as the others | gives the RSDP's physical address, read before bootloader memory is reclaimed (#223's `BootMemory`) |
| ACPI walk and DMAR parser | `kernel/src/acpi.rs`, safe | none | RSDP → XSDT → `DMAR`; each table's length and checksum checked; returns the DRHD units (register base, `INCLUDE_PCI_ALL`, device scopes), and the count of reserved regions (RMRR), which the driver must not ignore. **Implemented (#241).** Reads physical memory through the existing safe direct-map reads. Host-tested and fuzzed |
| VT-d registers | `kernel/src/arch/x86_64/iommu.rs` (hardware layer, already allowed) | none new for registers (the existing `mmio_read32`/`mmio_write32`); the table frames' direct-map reads and writes, and `clflush` | `CAP`, `ECAP`, `GCMD`/`GSTS`, `RTADDR`, `CCMD`, `IOTLB` (at `ECAP.IRO`), fault status and recording registers; `KernelMemory` writes only frames it allocated. **Implemented (#242)** |
| Tables | `kernel/src/iommu.rs`, safe | none | root table (256 buses), context tables, second-level tables (3 levels for 39-bit, 4 for 48-bit by `CAP.SAGAW`), domain IDs (`CAP.ND`); `iommu::init` turns translation on. **Implemented (#242)**, host-tested; attach and map are used from #243 |
| Hooks | `kernel/src/device.rs` | none | attach on `grant` (a function no unit's scope covers is not granted), map in `give_dma` (from `dma_alloc`), unmap and invalidate before `free`, detach on drop; on an invalidation that does not complete, the buffers are kept, never reused. **Implemented (#243)** |
| Driver feature | `user/programs/src/virtio.rs` | none | accept `VIRTIO_F_ACCESS_PLATFORM` when the device offers it. **Implemented (#243)** |
| QEMU settings | `xtask` | none | `-device intel-iommu,intremap=off` and `iommu_platform=on` on every virtio device (hot-added ones too), in every boot and test kernel; test kernels that grant devices start the IOMMU with `testing::init_iommu`. **Implemented (#242, #243)** |

- **Frames:** bus 0's context table is made with the root table and kept; a domain's tables that an unmap leaves empty are freed only after the IOTLB invalidation completes (until then the unit may still walk them). So a driver's exit returns every frame it took, as the existing `virtio_blk` and `device_caps` tests require.
- **Invalidation is register-based** (`CCMD`, `IOTLB`), not the invalidation queue: one unit, a few invalidations per `dma_alloc` or driver exit, so a queue's speed is not needed and its code is avoided. Both are global for now. Verified on QEMU (#242).
- **Faults** are read from the fault-recording registers and cleared by `iommu::take_faults`, which only the `iommu` test kernel calls today (**implemented**). Reading them on each device stop, printing and counting them per device, is **planned** (#246, M5.2 review). The fault interrupt is not used.
- **No IOMMU found:** the boot fails with `no IOMMU (DMAR) found; drivers cannot be isolated (D-044)`. Fail closed, as the CPU check (#237). `cargo xtask` adds the IOMMU everywhere, so every test still boots (decided, open question 1). **Implemented (#242)**, and so is refusing a DMAR that lists reserved regions (RMRR, which QEMU's has none of) or a unit outside PCI segment 0.

## 4. Security

- **Closes:** a driver programming its device to read or write memory it was not given (kernel, other processes, freed frames). The device faults instead.
- **Trusted code added:** the VT-d register layer (volatile MMIO in the hardware layer), the table builder, and the ACPI and DMAR parsers, which read firmware tables (trusted, as the firmware is) but are still checked for length and checksum and fuzzed.
- **Not closed (stated in the threat model):**
  - **MSI injection:** without interrupt remapping, a device can write to `0xfee0_0000` and raise any vector on the CPU. That is a denial of service (spurious interrupts), not memory access. Interrupt remapping needs QEMU's `kernel-irqchip=split` under KVM and a remapping table; carried to M8.1 with bare-metal VT-d. (Open question 2.)
  - **Peer-to-peer DMA** between devices behind the same bridge, which QEMU's root bus does not have.
  - **The IOMMU's own correctness** in QEMU: trusted, as the VMM is.
- **ATS and device-IOTLB** stay off (`device-iotlb=off`), so a device cannot cache translations the kernel has removed.

## 5. Testing

- **Host:** the DMAR and ACPI parsers (every field, wrong lengths and checksums, scopes), fuzzed like the other parsers; the table builder (entries, levels, identity mapping, unmapping); context-entry and page-entry encodings against the VT-d specification.
- **A new test kernel, `iommu`:** translation on; a driver test program asks for a DMA buffer, then writes a virtio-blk read descriptor pointing at a kernel canary frame. Passes only if the canary is unchanged, a fault is recorded for that device and address, and an ordinary read into its own buffer still works. A second case: after the driver ends, the old buffer's frames are unmapped (a stale descriptor faults).
- **Mutation:** identity-mapping all memory in the domain, or leaving translation off, must fail `iommu` (a throwaway branch in CI, as M5.2's validation asks).
- **Everything else with the IOMMU on:** the full suite, the matrix (the `kvm` cell included), and S1. S1 loads a 676 MB model through virtio-blk, and every DMA is now translated by QEMU, so its timings are measured against today's (risk below). **Measured (#243, `cargo xtask bench-infer` under KVM on the development host):** with every DMA translated, the model loads in a median of 7.11 s over 5 runs, against 6.81 s over 3 at `7b2a248`, where virtio DMA still bypassed the IOMMU (+4%). First token 6.54 s against 6.55 s. Generation, which does no DMA, varied from 9.7 to 13.3 tokens/s between runs of one build: noise. Both S1 targets (10 s, 5 tokens/s) are met, so the 2 MiB mappings (open question 3) are not needed.

## 6. Alternatives

- **`virtio-iommu`:** needs a virtqueue in the kernel (every virtio driver is in user space today), and no bare-metal machine has it. Rejected in D-044.
- **Keep drivers in the trusted base:** the network service stays one bug from kernel memory. Rejected in D-044.
- **Map DMA pages at an I/O virtual address chosen by the kernel** instead of identity: hides physical addresses from drivers, but every driver must translate, and drivers already see physical addresses today. Identity first; revisit if physical addresses become a secret.
- **The invalidation queue:** faster for many invalidations; not needed at today's rate.

## 7. Open questions

1. **No IOMMU:** refuse to boot (recommended, fail closed), or boot with the limit printed and stated?
2. **Interrupt remapping:** carry MSI injection to M8.1 as stated (recommended for M5.2's size), or add it now?
3. **S1's cost:** if translated DMA slows model loading beyond what S1 allows, is a larger mapping granularity (2 MiB pages for large buffers) acceptable, or a longer S1 limit?

**Decided (2026-11-15, #239):** 1. refuse to boot without an IOMMU; 2. interrupt remapping carried to M8.1, MSI injection stated in the threat model; 3. 2 MiB mappings for large buffers if S1 needs them.

## Implementation issues

1. #241: ACPI walk and DMAR parser, host-tested (`acpi.rs`, the Limine RSDP request).
2. #242: VT-d registers and tables, translation on at boot with nothing attached (`arch/x86_64/iommu.rs`, `iommu.rs`).
3. #243: device hooks and `VIRTIO_F_ACCESS_PLATFORM`, `iommu_platform=on` on every virtio device, and refusing to grant a device no unit's scope names. (`xtask` adds the IOMMU everywhere since #242.)
4. #244: the `iommu` test kernel's attack, its mutations, and the threat model's rows (S1 measured in #243). Found: QEMU's virtio-blk completes the blocked request (status OK, nothing written), so a driver cannot tell from the device that its DMA was blocked; the unit's fault record says so.
