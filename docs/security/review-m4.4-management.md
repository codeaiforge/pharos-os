# Security review: M4.4 device and service management

- **Scope:** everything M4.4 added since commit `18c4dc2` (the M4.3 gate):
  - D-029 and the design: [services.md, runtime management](../architecture/services.md#runtime-management-m44-d-029) and [drivers.md, hotplug](../architecture/drivers.md#hotplug-m44-d-029) (#168, #169), with the hotplug experiment;
  - `init`'s `START`, `STOP`, `RESTART`, and `RUNTIME`, `pharos_programs::manage`, and `trust`'s `start`, `restart`, and `stop service` (#170);
  - the kernel's hotplug: `kernel/src/hotplug.rs`, `arch::x86_64::pci::{write_slot, write_bar}`, `pci::{add, remove, scan_function}`, the `Hotplug` object and `HOTPLUG` right, calls 28–30, and the tick hook (#171);
  - `init`'s slot handling, driver entries (`Arrived`, `Broken::Driver`), the `disk` entry, and `virtio-blk` argument 2 (#171);
  - `pharos_user::try_send_cap`, the new audit actions `manage` (21) and `device` (22), and every new `unsafe` block.
- **Design under review:** services.md, drivers.md, D-029, D-026, D-027, D-018, D-008, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-08, issue #173. Reviewer: AI-assisted (Claude Code), from reading the code; F1 was reproduced in QEMU. All four findings are fixed (2026-11-08), each with a test that fails without its fix except F4 (below).
- **Status:** **approved** by the maintainer on 2026-11-09 (M4.4 gate, #173), with F1–F4 fixed.

## Method

1. Listed every changed file since `18c4dc2` and searched the diff for new `unsafe` blocks: none. `write_slot` and `write_bar` are safe functions over the existing port I/O helpers in `arch::x86_64::pci`.
2. Followed each way a request reaches `init`'s management handlers, and each way a slot call reaches the kernel.
3. Followed a device from arrival to removal: power, BAR assignment, scan, grant, `init`'s handle, the driver's handle and mappings, revocation, power off.
4. Followed what a restart costs and gives back: processes, capabilities, page charges, and device resources.
5. Checked the locks the hotplug code takes, in the tick (interrupt context) and in `slot_next`.
6. Checked each acceptance criterion of M4.4 against a test that runs in CI.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | **Restarting a driver uses up its device's DMA pages; after 16 restarts `trust` cannot start, and the trusted console (with `stop all`) is gone until reboot.** A device's DMA buffers belong to its `DeviceHandle` and are freed only when the handle is dropped (`device.rs`). `init` holds the handle for the whole boot and passes it to each new driver process, so every start allocates fresh buffers on top of the old ones, up to `MAX_DMA_PAGES` (64). The virtio-console driver takes 4 pages, so `trust`'s 17th start fails (`exit 3`), then its 3 policy restarts fail, and `init` gives up. Before M4.4 a service started at most 4 times a boot (`Up(3)`); `restart` resets the count, so any number of restarts is now one command each. Reproduced in QEMU: 16 `restart trust` lines, then `init: trust exited 3` and `not restarted: restarts used up`. The same holds for `store` (its disk) and `net`, and the frames are not returned (a leak of up to 64 pages per device). | **Fixed:** each DMA buffer records the process that allocated it. When a process ends, after its address space is freed and before its end is signalled (so before `init` starts another), the kernel turns bus mastering off on each device it pinned that holds buffers of its, then frees them (`DeviceHandle::release_from`, `take_owned`); `dma_alloc` turns bus mastering on again (`master`, new `arch::x86_64::pci::set_bus_master`). Memory decoding stays on, so the next driver can reset the device through its registers first. The `manage` kernel now restarts `trust` 21 times (one `manage` record and one console line each) and ends with `stop all` working; with `release_from` doing nothing it fails at the 16th. Host test `an_ended_process_gives_back_only_its_own_buffers` (20 starts of 4 pages). |
| F2 | Low (test) | **The capability audit accepts any device with the right PCI ID as `Arrived`.** `common/manifests.rs` matches `Give(Arrived(id))` to a held `Device` whose ID is `id`, so a mistake that gave the `disk` driver the boot disk (`1af4:1042`, bus 0) would pass. | **Fixed:** a held device off bus 0 is `Arrived(id)`, one on bus 0 the `nth` of its ID among bus 0 devices; the special case is gone. The audit was also never seeing the driver: it counts only what is in three snapshots 100 ms apart, and the driver was removed sooner. The runner now reads the kernel's serial log too, and removes the first disk only after the `hotplug` kernel has audited the running driver and checked it holds exactly one device, on bus 1. With `init` giving `disk` the boot disk, both checks fail. |
| F3 | Low | **A device that arrives with no free driver stays powered with bus mastering on.** `probe` grants it (`DeviceHandle::grant` enables memory decoding and bus mastering) before `init` decides. If no driver entry is free (a second disk, or a device of another kind), `init` deletes its handle, but the kernel's handle keeps the device enabled until it is removed. Without an IOMMU a device can reach all memory anyway (drivers.md, an accepted limit), but a device no one drives should not be bus master. The same holds while the user has stopped a device's driver. | **Fixed:** `probe` turns bus mastering off right after the grant (`DeviceHandle::unmaster`); the driver's first `dma_alloc` turns it on (F1's `master`). With F1, a device whose driver ended (stopped by the user, or crashed) is not bus master either once that driver's buffers are freed. The `hotplug` kernel's drivers start, mount, and stop as before; no test reads the command register of an unclaimed device. |
| F4 | Info | **`slot_next` works with interrupts off.** It holds the slots lock (an `IrqMutex`) while it probes a function, inserts `init`'s capability, and on removal revokes (sweeping every process). The lock order is the slots, then processes, frames, and `init`'s capabilities; nothing takes them in the other order, and the tick takes only the slots lock, so there is no deadlock on one CPU. The cost is latency, bounded by one slot's step. | **Fixed (the lock):** the tick reads a fixed list of slot ports made at boot (`POLLED`) and a bit per powering slot (`POWERING`, atomic), never the slots; `slot_next` and `slot_answer` take one slot out of the table, work on it with no lock held, and put it back (only `init` calls them, one at a time). The work itself still runs in a system call with interrupts off, as every system call does. No test measures interrupt latency; the `hotplug` kernel shows the flow still works. |

## Who can reach what

- **Only `trust` manages services.** `init` answers `START`, `STOP`, `RESTART`, and `RUNTIME` only on the kernel-set badge of its `bin/trust` entry, as it does `SERVICES`. The `manage` kernel sends `STOP agents` and `RESTART audit` on `init`'s report endpoint under the knowledge service's badge and an unknown one, and neither happens; a mutation that accepted any badge failed it.
- **Only compiled entries start, with their manifests.** A start is `init`'s existing `start(i)`; the live capability audit (D-027) runs in the `system`, `manage`, and `hotplug` kernels.
- **Nothing ends the console or the trail by command.** `pharos_services::PROTECTED` (`trust`, `audit`, `store`) refuse `stop`; a restart of `trust` reports first, then gives `trust` 100 ms before stopping it, and the new `trust` asks for the runtime (`RUNTIME`) before it reads the console, so `stop all` works at once (the `manage` kernel ends with it). Restarts give their DMA pages back (F1), so any number of them leaves the console working.
- **Only `init` holds `Hotplug`.** The kernel creates it once, in `init_capabilities`, with `HOTPLUG`; no manifest can name it, so the audit would report any service holding it. Each slot call checks `HOTPLUG` on a `Hotplug` object (`hotplug_cap`).
- **The kernel, not the device, chooses a hot-added device's BARs,** inside windows the firmware reserved and the kernel checked against the boot memory map (a window over memory is closed). The function is then scanned as at boot, so the BAR-over-memory check and the bounded capability walk apply. Only function 0 is used; a bridge or other header type is refused.
- **A driver is stopped before its device goes.** On the button, `init` stops the driver (waiting up to 1 s), then answers `release`; the kernel revokes the slot's root capability (stopping the device, masking MSI-X, and turning the driver's mappings into zeroed pages, #104) before powering off. The `hotplug` kernel checks that no driver runs and no process holds a capability on a device behind a slot afterwards; a mutation in which `init` did not stop the driver failed it.
- **Slot events cannot grow kernel memory.** State is fixed per slot (at most 8), arrivals are limited to one per slot per second, and the tick only reads.

## Accepted limits

- **No IOMMU** (drivers.md): a hot-added device, like any device, can reach all memory once bus mastering is on.
- **Firmware's windows are trusted** apart from the memory-map check: they are not checked against other devices' BARs.
- **Surprise removal** (presence lost without the button) is host-tested only: QEMU's `device_del` is cooperative.
- **A restarted `trust` loses the runtime's channel and its agents' registrations** (names, groups, open approvals) until the runtime restarts (services.md, #170). `stop all` does not need them.
- **The `keep` answer** (removal refused, attention indicator blinking) has no caller: a table rule keeps every driver entry unprotected.

## Acceptance criteria

| Criterion | Shown by (in CI) |
| --- | --- |
| Services can be restarted without reboot | `manage`: `restart knowledge` (dependents named, still running), `restart trust` (a new `trust` with the emergency stop), `stop service` and `start` of `net` and `knowledge`; `services` after them |
| Device add/remove (where QEMU supports it) is handled | `hotplug`: a virtio-blk disk added to slot 1 twice and removed twice over QMP, its driver started each time and stopped before the slot powered off, once while stopped by the user; each event one audit record |
| The management interface is capability-protected | `manage`'s forged requests (mutation-checked); only `init` holds `Hotplug`, checked by the capability audit; host tests of `needed_rights` for calls 28–30 |

## Measured

The IPC round trip: 1,874 ns median (1,798–1,933 ns over 5 runs of 100,000, KVM), within D-004's 2 µs budget (M4.3: 1,820 ns at its gate). M4.4 adds work to every tenth timer tick (one configuration read per slot), not to the system-call path.
