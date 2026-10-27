# Exceptions and interrupts

## 1. Status

- **Design:** Accepted with [D-006](../project/decision-log.md#d-006-interrupt-controller-and-timer-design) (controller part, 2026-10-27).
- **Implementation:** CPU exceptions, the double-fault stack, and the local APIC timer are **implemented** ([M2.4](../project/implementation-roadmap.md#m24--exceptions-interrupts-and-debugging), issues #19–#23). Device interrupts (IOAPIC), the scheduler tick (M2.6), and SMP are **planned**.

## 2. Context

The kernel must report CPU exceptions instead of rebooting, survive a stack overflow, and receive hardware interrupts, all tested in QEMU under TCG (no KVM in CI). Limine (base revision 6) hands over with interrupts disabled, no IDT or TSS, the legacy PICs masked, and the local APIC enabled with every local interrupt masked. Its higher-half direct map (HHDM) does not cover the local APIC registers.

## 3. Design

### Boot order

`kmain` (and every test kernel, through `test_kernel!`) runs in this order:

1. Switch from Limine's boot stack to the 64 KiB kernel stack, which has an unmapped guard page below it (`linker.ld`).
2. Load the kernel's GDT and TSS (`arch::x86_64::gdt`). TSS IST1 is a 16 KiB double-fault stack.
3. Load the IDT (`arch::x86_64::idt`).
4. Map and enable the local APIC (`arch::x86_64::apic::init`).

The main kernel then reports boot information and halts with interrupts still disabled. Only test kernels enable interrupts so far.

### Exception and interrupt entry

All IDT entries are 64-bit interrupt gates (interrupts disabled on entry) using the kernel code selector. Entry stubs are written with `global_asm!` (stable Rust; the `x86-interrupt` ABI is nightly-only). Each stub pushes a dummy error code where the CPU pushes none and its vector, saves the general-purpose registers, and calls one Rust dispatcher with the saved frame. The kernel is soft-float, so no SSE state is saved.

| Vector | Source | Handling |
| --- | --- | --- |
| 3 | Breakpoint (`int3`) | Report, continue |
| 8 | Double fault | Runs on IST1; fatal report |
| 0–31 (others) | CPU exceptions | Fatal: report vector, decoded error code, CR2 for page faults, registers; signal failure to QEMU; halt |
| 32 | Local APIC timer | Count the tick, send EOI |
| 255 | Local APIC spurious interrupt | Count it, no EOI |
| 33–254 | Not present | Arriving there raises a general-protection fault (fatal) |

Fatal reports go through the panic print path, which releases the console lock first, because an exception can hit while the lock is held. Test kernels can install a fatal hook to turn an expected exception into test results.

### Local APIC

- **Mode:** xAPIC (memory-mapped registers). QEMU under TCG cannot provide x2APIC, and the legacy PIC cannot deliver past Limine's masked LINT0 (D-006 evidence).
- **Mapping:** the 4 KiB register page (physical base from `IA32_APIC_BASE`, normally `0xfee00000`) is mapped at `HHDM + physical address`, uncached (PCD, PWT), writable, and no-execute when `EFER.NXE` is on. The mapping is added to Limine's page tables using up to three page-table pages reserved in the kernel image; their physical addresses come from a page-table walk. M2.5 takes this mapping over when it builds its own tables.
- **Setup:** task priority 0; software-enabled through the spurious-interrupt vector register with vector 255.
- **Timer:** periodic mode on vector 32, divide by 16, initial count chosen by the caller. Not calibrated yet; M2.6 decides the scheduler timer.

### Console

`kprint!`/`kprintln!` hold the console lock with interrupts disabled and restore the previous state, so an interrupt handler never waits for code it interrupted.

## 4. Security

All of this is ring-0 code in the hardware layer (`arch::x86_64` and its submodules), the only place besides the Limine module where `unsafe` is allowed. Page-table writes are limited to one MMIO page at a fixed, HHDM-relative address and refuse to replace an existing mapping. No user mode exists yet, so no gate is reachable from ring 3, and the TSS ring-0 stack pointer is unused until M2.7. The trust boundary in the [threat model](../security/threat-model.md) is unchanged.

## 5. Testing

Test kernels in `kernel/tests/`, run by `cargo xtask test` locally and in CI ([testing guide](../development/testing.md#kernel-tests-qemu)):

- `interrupt_state`: printing restores the interrupt flag.
- `gdt`: our GDT, segment selectors, task register, and IST1 stack.
- `exceptions`: breakpoints continue with registers intact; a page fault on an unmapped page reports the right CR2 and error code.
- `double_fault`: unbounded recursion hits the guard page and is reported as a double fault on IST1.
- `apic_timer`: the local APIC is mapped and the timer delivers at least 20 interrupts.

Each was checked once to fail when the feature it tests is broken. The boot check also maps the local APIC under UEFI and BIOS. Gate, IDT, and page-table entry encoding and the exception report text are unit-tested on the host.

## 6. Alternatives

- **x2APIC:** register access through MSRs, no mapping needed, SMP-ready; not available in QEMU 8.2 under TCG.
- **Legacy 8259 PIC with the PIT:** blocked by Limine's masked LINT0, even with the local APIC globally disabled (in QEMU).
- **Nightly `x86-interrupt` ABI or naked functions:** nightly, or a minimum Rust of 1.88; `global_asm!` works on 1.85.

## 7. Open questions

- Timer source and calibration for the scheduler (D-006 timer part, M2.6).
- IOAPIC and ACPI MADT parsing for device interrupts.
- Guard pages for the double-fault stack and per-CPU stacks (M2.5, SMP).
