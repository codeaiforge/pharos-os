# Exceptions and interrupts

## 1. Status

- **Design:** Accepted with [D-006](../project/decision-log.md#d-006-interrupt-controller-and-timer-design) (controller part, 2026-10-27).
- **Implementation:** CPU exceptions, the double-fault stack, and the local APIC timer are **implemented** ([M2.4](../project/implementation-roadmap.md#m24--exceptions-interrupts-and-debugging), issues #19–#23), and so are timer calibration and the kernel clock (M2.6, #32), and preemptive scheduling on the tick ([scheduling.md](scheduling.md), #34). Interrupts and exceptions from user mode are implemented too (M2.7, #39). Device interrupts (IOAPIC) and SMP are **planned**.

## 2. Context

The kernel must report CPU exceptions instead of rebooting, survive a stack overflow, and receive hardware interrupts, all tested in QEMU under TCG (no KVM in CI). Limine (base revision 6) hands over with interrupts disabled, no IDT or TSS, the legacy PICs masked, and the local APIC enabled with every local interrupt masked. Its higher-half direct map (HHDM) does not cover the local APIC registers.

## 3. Design

### Boot order

`kmain` (and every test kernel, through `test_kernel!`) runs in this order:

1. Switch from Limine's boot stack to the 64 KiB kernel stack, which has an unmapped guard page below it (`linker.ld`; kept unmapped by the kernel's own page tables).
2. Load the kernel's GDT and TSS (`arch::x86_64::gdt`): kernel code and data, the TSS, then user data (`0x28`) and user code (`0x30`), in the order `sysret` needs (D-014). TSS IST1 is a 16 KiB double-fault stack. TSS `rsp0` is set on every task switch to the incoming thread's kernel stack top, so interrupts and exceptions from user mode land there.
3. Load the IDT (`arch::x86_64::idt`).
4. Build the frame allocator and the kernel's own page tables ([memory.md](memory.md)).
5. Map and enable the local APIC (`arch::x86_64::apic::init`).
6. Calibrate the APIC timer and the TSC against the PIT (`time::init`, about 50 ms).

The main kernel then reports boot information and halts with interrupts still disabled. Only test kernels enable interrupts so far (directly, or through `sched::enable_preemption`).

### Exception and interrupt entry

All IDT entries are 64-bit interrupt gates (interrupts disabled on entry) using the kernel code selector. Entry stubs are written with `global_asm!` (stable Rust; the `x86-interrupt` ABI is nightly-only). Each stub pushes a dummy error code where the CPU pushes none and its vector, saves the general-purpose registers, and calls one Rust dispatcher with the saved frame. The kernel is soft-float, so no SSE state is saved.

| Vector | Source | Handling |
| --- | --- | --- |
| 3 | Breakpoint (`int3`) | Report, continue |
| 8 | Double fault | Runs on IST1; fatal report |
| 0–31 (others), from ring 0 | CPU exceptions | Fatal: report vector, decoded error code, CR2 for page faults, registers; signal failure to QEMU; halt |
| 0–31, from ring 3 | CPU exceptions in user mode | The user-fault handler (`idt::set_user_fault_handler`, installed by `process::init`) prints `PHAROS: process <id> killed: <report>` and ends the process; the kernel continues |
| 32 | Local APIC timer | Count the tick, send EOI, then call the tick handler (the scheduler, once preemption is enabled), which may switch tasks |
| 255 | Local APIC spurious interrupt | Count it, no EOI |
| 33–254 | Not present | Arriving there raises a general-protection fault (fatal) |

Fatal reports go through the panic print path, which releases the console lock first, because an exception can hit while the lock is held. Test kernels can install a fatal hook to turn an expected exception into test results.

### Local APIC

- **Mode:** xAPIC (memory-mapped registers). QEMU under TCG cannot provide x2APIC, and the legacy PIC cannot deliver past Limine's masked LINT0 (D-006 evidence).
- **Mapping:** the 4 KiB register page (physical base from `IA32_APIC_BASE`, normally `0xfee00000`) is mapped at `HHDM + physical address`, uncached (PCD, PWT), writable, and no-execute when `EFER.NXE` is on. Since #27 it is an ordinary mapping in the kernel address space ([memory.md](memory.md)); the M2.4 stopgap that added it to Limine's page tables is gone.
- **Setup:** task priority 0; software-enabled through the spurious-interrupt vector register with vector 255.
- **Timer:** periodic mode on vector 32, divide by 16. `time::start_tick()` sets the initial count for 100 Hz from the calibration (D-006 timer part).

### Calibration and the kernel clock (`time`)

- `time::init` runs five 10 ms measurements with interrupts disabled. Each arms PIT channel 2 (mode 0, gate on, speaker off, no PIT interrupt), starts the APIC timer (one-shot, masked, maximum count) and reads the TSC, then starts the PIT and polls its output bit in port `0x61`. The APIC and TSC counters start before the PIT, so a delay can only make a run read high; the smallest run counts.
- Rates are rejected with a boot error when the APIC timer runs below 100 ticks per ms (a tick period would have fewer than 1,000 counts) or so fast that a tick period overflows the 32-bit count, or when the TSC runs below 1 MHz.
- `time::uptime()` is TSC cycles since calibration, converted with the calibrated rate (nanosecond resolution). It does not count ticks, which can be lost when the host is busy. `time::delay()` busy-waits on it.
- In QEMU under TCG: about 62,500 APIC ticks per ms (QEMU's 1 GHz timer clock divided by 16) and a TSC at the host's rate (3.7 GHz on the development machine).
- Limits: QEMU's default CPU reports no invariant TSC, and the kernel does not check for one; on real hardware a TSC that changes with CPU frequency would make the clock drift.

### Console

`kprint!`/`kprintln!` hold the console lock with interrupts disabled and restore the previous state, so an interrupt handler never waits for code it interrupted.

## 4. Security

All of this is ring-0 code in the hardware layer (`arch::x86_64` and its submodules), the only place besides the Limine module where `unsafe` is allowed. Page-table writes are limited to one MMIO page at a fixed, HHDM-relative address and refuse to replace an existing mapping. Since M2.7 (#39) user code runs in ring 3. Every IDT gate has DPL 0, so `int n` from user mode, including `int3`, raises a general-protection fault, and the process is killed. Interrupts and exceptions from ring 3 switch to the thread's own kernel stack through TSS `rsp0`. See the kernel/user boundary in the [threat model](../security/threat-model.md).

## 5. Testing

Test kernels in `kernel/tests/`, run by `cargo xtask test` locally and in CI ([testing guide](../development/testing.md#kernel-tests-qemu)):

- `interrupt_state`: printing restores the interrupt flag.
- `gdt`: our GDT, segment selectors, task register, and IST1 stack.
- `exceptions`: breakpoints continue with registers intact; a page fault on an unmapped page reports the right CR2 and error code.
- `double_fault`: unbounded recursion hits the guard page and is reported as a double fault on IST1.
- `apic_timer`: the local APIC is mapped and the timer delivers at least 20 interrupts.
- `timer`: calibration is accepted; the TSC clock agrees with the PIT, `delay` waits long enough, uptime never goes backwards, and 20 ticks take about 200 ms (wide bounds for TCG). Checked to fail with a tick period or TSC rate off by a factor of 10.

Each was checked once to fail when the feature it tests is broken. The boot check also maps the local APIC under UEFI and BIOS. Gate, IDT, and page-table entry encoding and the exception report text are unit-tested on the host.

## 6. Alternatives

- **x2APIC:** register access through MSRs, no mapping needed, SMP-ready; not available in QEMU 8.2 under TCG.
- **Legacy 8259 PIC with the PIT:** blocked by Limine's masked LINT0, even with the local APIC globally disabled (in QEMU).
- **Nightly `x86-interrupt` ABI or naked functions:** nightly, or a minimum Rust of 1.88; `global_asm!` works on 1.85.

## 7. Open questions

- IOAPIC and ACPI MADT parsing for device interrupts.
- Per-CPU stacks and their guard pages (SMP). The kernel and double-fault stacks have guard pages since #27.
