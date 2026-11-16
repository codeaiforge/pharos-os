# Reference platform: QEMU with KVM

## Status

**Implemented** (M5.2, #240). The reference platform is set by [D-044](../project/decision-log.md#d-044-reference-platform-and-the-limits-required-on-a-real-host) item 4 (accepted 2026-11-15). Pharos OS is tested, and supported, on this platform only. Other VMMs (Cloud Hypervisor, Firecracker) and bare metal are **untested**; bare metal is M8.1.

## The platform

| Part | Requirement | Why |
| --- | --- | --- |
| VMM | QEMU with KVM (`-enable-kvm`), machine `q35` | what every test and the release matrix run (D-044) |
| QEMU version | 8.2 tested (8.2.2) | `intel-iommu` behaviour checked on it: legacy mode, register-based invalidation, a non-coherent unit ([iommu.md](../architecture/iommu.md)) |
| IOMMU | `-device intel-iommu,intremap=off`, before the other devices | without a DMAR table the kernel refuses to boot (#242); interrupt remapping is carried to M8.1 |
| Devices | virtio-pci only, modern (`disable-legacy=on`), each with `iommu_platform=on` | the drivers are virtio; without `iommu_platform=on` a device's DMA bypasses the IOMMU |
| Firmware | UEFI (OVMF) or BIOS (SeaBIOS), booting Limine | both are tested in every boot check |
| Memory | 256 MiB to boot; 2 GiB for S1 (the 676 MB model) | the matrix's `mem-min`, `mem-2g`, `mem-4g` cells |
| Guest CPU | `-cpu host` | the kernel's CPU check (#237) must see the host's real `IA32_ARCH_CAPABILITIES` |
| Host CPU | AMD or Hygon, or Intel reporting `RDCL_NO` and `MDS_NO` | the kernel has no KPTI: on a CPU affected by Meltdown or MDS it refuses to boot (D-044 item 1) |
| Host OS | Linux with KVM, `/dev/kvm` readable and writable by the user | tested on Linux 6.8 |

`cargo xtask run`, `cargo xtask test`, and `cargo xtask matrix kvm` start QEMU with these settings ([testing.md](testing.md)).

## Checking a host

1. **KVM:** `test -r /dev/kvm -a -w /dev/kvm && echo ok`. If this fails, add the user to the `kvm` group (the maintainer's action; it needs `sudo`).
2. **CPU:** `cat /sys/devices/system/cpu/vulnerabilities/meltdown /sys/devices/system/cpu/vulnerabilities/mds` should print `Not affected` twice. This is Linux's view; the kernel's own check is decisive.
3. **QEMU and firmware:** `qemu-system-x86_64 --version` (8.2 tested), and `/usr/share/OVMF/OVMF_CODE_4M.fd` present (Ubuntu or Mint package `ovmf`).
4. **The kernel's check:** `cargo xtask matrix kvm`. Its boot logs (`target/xtask/logs/kvm/boot-uefi.log`) must show `cpu: not affected by Meltdown or MDS (AMD)` or `(IntelNotAffected)`, and `iommu: 1 unit(s) translating`. On an affected CPU the boot stops with `PHAROS: boot failed: this CPU may leak kernel memory to processes (D-044): …`.
5. **S1:** `PHAROS_MODEL=<qwen2.5-0.5b-instruct-q8_0.gguf> cargo xtask s1`, and `cargo xtask bench-infer` for the timings.

## Host reports

A report records the host, the versions, and the results of the release matrix and S1, run on that host from one commit.

### 2026-11-16: the development host

Run by the maintainer's assistant on the maintainer's development host, at commit `fd16c38`, on 2026-11-16.

| | |
| --- | --- |
| CPU | Intel Core i9-10900K (Comet Lake), 10 cores, 20 threads; Linux reports Meltdown and MDS "Not affected" |
| Memory | 125 GiB |
| Host OS | Linux Mint 22.3, kernel 6.8.0-149-generic; `/dev/kvm` read-write through an ACL |
| QEMU | 8.2.2 (Ubuntu package `1:8.2.2+ds-0ubuntu1.18`) |
| Firmware | OVMF 2024.02 (`2024.02-2ubuntu0.10`); SeaBIOS from QEMU |
| Kernel's CPU check | `cpu: not affected by Meltdown or MDS (IntelNotAffected)` under KVM (`-cpu host`) |
| Kernel's IOMMU | `iommu: 1 unit(s) translating, 3-level tables, nothing attached` |

**Release matrix** (`cargo xtask matrix <cell>`, one cell after another; each runs the four boot checks and every test kernel):

| Cell | Result | Time | Kernels |
| --- | --- | --- | --- |
| `push` | pass | 925 s | 79 passed, `s1` skipped |
| `bios` | pass | 589 s | 77 passed; `boot_info` and `recovery` (UEFI only) and `s1` skipped |
| `mem-min` (144 MiB) | pass | 928 s | 79 passed |
| `mem-2g` | pass | 936 s | 79 passed |
| `mem-4g` | pass | 950 s | 79 passed |
| `cpu-skylake` | pass | 880 s | 79 passed |
| `cpu-max` | **fail** (once) | 877 s | 78 passed; `exhaustion` failed one timing check: its trusted task was 40,037 µs late against a 40 ms limit. Rerun three times in the same cell: passed each time, worst 21.3 ms late |
| `kvm` | pass | 728 s | 79 passed |

**S1** under KVM, same commit:

- `cargo xtask s1`: pass in 39.5 s; the agent's result identical to the host's (708 bytes), and the audit trail as expected.
- `cargo xtask bench-infer --runs 3`: model load 6.82 s, first token 6.44 s (target 10 s), 13.9 tokens/s (target 5), service peak 686 MiB, text identical to the host's in every run.

**Before this run:** on `main`, the weekly matrix (run 43666360518, at `a298350`) had failed the three memory cells and S1. The cause was in the tests, the frame allocator's run search, and the store images' sizing, not in the platform; fixed in `c288a65` and `fd16c38`.

**Open:** the `exhaustion` timing check's margin under TCG on `-cpu max` (one wake 40.04 ms late in this run; three reruns passed). It is not a KVM result, and the `kvm` cell passed.
