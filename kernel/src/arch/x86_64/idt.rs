//! IDT and CPU exception handlers (issue #21).
//!
//! Each of the 32 CPU exception vectors has an assembly entry stub
//! (`global_asm!`, stable Rust; the `x86-interrupt` ABI is nightly-only). A
//! stub pushes a dummy error code where the CPU pushes none, then the vector,
//! saves the general-purpose registers, and calls `dispatch` with a pointer
//! to the resulting [`ExceptionFrame`]. The kernel is built soft-float, so no
//! SSE state needs saving.
//!
//! Breakpoints (`int3`) are reported and execution continues. Every other
//! exception is fatal: it is reported over serial, QEMU is told the run
//! failed, and the CPU halts. Vector 32 (local APIC timer) and 255 (APIC
//! spurious interrupt) go to the `apic` module, and 48–63 (device
//! interrupts for user-space drivers, MSI-X) to `crate::irq`. Test kernels
//! can install a fatal hook to turn an
//! expected exception into a test result. Other vectors from 33 to 254 are not
//! present, so an interrupt on them raises a general-protection fault. The double fault
//! runs on its own stack (TSS IST1), so a kernel stack overflow is reported.

// The dispatcher and its helpers are reached only from the kernel-target
// entry stubs; host builds compile them for unit tests of the pure parts.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::fmt;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

/// Vector numbers used by name elsewhere.
pub const BREAKPOINT: u8 = 3;
pub const DOUBLE_FAULT: u8 = 8;
pub const GENERAL_PROTECTION: u8 = 13;
pub const PAGE_FAULT: u8 = 14;

/// Saved state at exception entry, in stack order (lowest address first).
/// Must match the push order in the entry stubs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExceptionFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    /// The CPU's error code, or 0 for vectors without one.
    pub error_code: u64,
    // Pushed by the CPU.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Mnemonic and name of a CPU exception vector (Intel SDM vol. 3A, table 7-1).
pub fn vector_name(vector: u64) -> (&'static str, &'static str) {
    match vector {
        0 => ("#DE", "divide error"),
        1 => ("#DB", "debug"),
        2 => ("NMI", "non-maskable interrupt"),
        3 => ("#BP", "breakpoint"),
        4 => ("#OF", "overflow"),
        5 => ("#BR", "bound range exceeded"),
        6 => ("#UD", "invalid opcode"),
        7 => ("#NM", "device not available"),
        8 => ("#DF", "double fault"),
        9 => ("--", "coprocessor segment overrun"),
        10 => ("#TS", "invalid TSS"),
        11 => ("#NP", "segment not present"),
        12 => ("#SS", "stack-segment fault"),
        13 => ("#GP", "general protection"),
        14 => ("#PF", "page fault"),
        16 => ("#MF", "x87 floating-point error"),
        17 => ("#AC", "alignment check"),
        18 => ("#MC", "machine check"),
        19 => ("#XM", "SIMD floating-point exception"),
        20 => ("#VE", "virtualization exception"),
        21 => ("#CP", "control protection"),
        28 => ("#HV", "hypervisor injection"),
        29 => ("#VC", "VMM communication"),
        30 => ("#SX", "security exception"),
        _ => ("--", "reserved"),
    }
}

/// True if the CPU pushes an error code for `vector`.
pub const fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

/// Decoded page-fault error code (Intel SDM vol. 3A, figure 5-12).
pub struct PageFaultError(pub u64);

impl fmt::Display for PageFaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self.0;
        let cause = if e & 1 != 0 {
            "protection violation"
        } else {
            "not-present page"
        };
        let access = if e & (1 << 4) != 0 {
            "instruction fetch"
        } else if e & (1 << 1) != 0 {
            "write"
        } else {
            "read"
        };
        let mode = if e & (1 << 2) != 0 { "user" } else { "kernel" };
        write!(f, "{cause}, {access}, {mode} mode")?;
        if e & (1 << 3) != 0 {
            write!(f, ", reserved bit set")?;
        }
        Ok(())
    }
}

/// The serial report of an exception. `cr2` is the faulting address, shown
/// for page faults.
pub struct Report<'a> {
    pub frame: &'a ExceptionFrame,
    pub cr2: u64,
}

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fr = self.frame;
        let (mnemonic, name) = vector_name(fr.vector);
        write!(f, "{mnemonic} {name} (vector {})", fr.vector)?;
        if fr.vector < 32 && has_error_code(fr.vector as u8) {
            write!(f, ", error code {:#x}", fr.error_code)?;
            if fr.vector == PAGE_FAULT as u64 {
                write!(f, " ({})", PageFaultError(fr.error_code))?;
            }
        }
        writeln!(f)?;
        if fr.vector == PAGE_FAULT as u64 {
            writeln!(f, "  CR2 (address) {:#018x}", self.cr2)?;
        }
        writeln!(
            f,
            "  RIP {:#018x}  CS {:#06x}  RFLAGS {:#010x}",
            fr.rip, fr.cs, fr.rflags
        )?;
        writeln!(f, "  RSP {:#018x}  SS {:#06x}", fr.rsp, fr.ss)?;
        writeln!(
            f,
            "  RAX {:#018x}  RBX {:#018x}  RCX {:#018x}",
            fr.rax, fr.rbx, fr.rcx
        )?;
        writeln!(
            f,
            "  RDX {:#018x}  RSI {:#018x}  RDI {:#018x}",
            fr.rdx, fr.rsi, fr.rdi
        )?;
        write!(f, "  RBP {:#018x}", fr.rbp)
    }
}

/// Encodes a 16-byte IDT gate: present, ring 0, 64-bit interrupt gate
/// (interrupts disabled on entry), `ist` 0 for the current stack.
pub const fn gate(handler: u64, selector: u16, ist: u8) -> [u64; 2] {
    let low = (handler & 0xffff)
        | (selector as u64) << 16
        | (ist as u64 & 0b111) << 32
        | 0x8e << 40
        | ((handler >> 16) & 0xffff) << 48;
    [low, handler >> 32]
}

/// Address the page-fault probe reads: the page just below the kernel's link
/// address (`linker.ld`). Limine maps the kernel image from its link address
/// upwards and the direct map lies far below, so this page is unmapped.
pub const UNMAPPED_PROBE: u64 = 0xffff_ffff_7fff_f000;

static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);
/// A `fn(&ExceptionFrame) -> !` stored as a pointer; null means none.
static FATAL_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Number of breakpoints handled so far.
pub fn breakpoint_count() -> u64 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

/// Routes fatal exceptions to `hook` instead of the default report-and-fail
/// path. For test kernels that expect an exception.
pub fn set_fatal_hook(hook: fn(&ExceptionFrame) -> !) {
    FATAL_HOOK.store(hook as *mut (), Ordering::Release);
}

fn fatal_hook() -> Option<fn(&ExceptionFrame) -> !> {
    let hook = FATAL_HOOK.load(Ordering::Acquire);
    if hook.is_null() {
        return None;
    }
    // SAFETY: the only non-null values stored in `FATAL_HOOK` come from
    // `set_fatal_hook`, which stores a `fn(&ExceptionFrame) -> !`. Function
    // and data pointers have the same size on x86-64.
    Some(unsafe { core::mem::transmute::<*mut (), fn(&ExceptionFrame) -> !>(hook) })
}

const RFLAGS_DF: u64 = 1 << 10;
const RFLAGS_AC: u64 = 1 << 18;

/// Handler for CPU exceptions raised in user mode; null if none.
static USER_FAULT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Routes CPU exceptions raised in user mode (CS ring 3) to `handler`
/// instead of the fatal report: the process module kills the faulting
/// process and the kernel continues (M2.7). Exceptions in ring 0 stay fatal.
pub fn set_user_fault_handler(handler: fn(&ExceptionFrame) -> !) {
    USER_FAULT_HOOK.store(handler as *mut (), Ordering::Release);
}

fn user_fault_hook() -> Option<fn(&ExceptionFrame) -> !> {
    let hook = USER_FAULT_HOOK.load(Ordering::Acquire);
    if hook.is_null() {
        return None;
    }
    // SAFETY: the only non-null values stored in `USER_FAULT_HOOK` come from
    // `set_user_fault_handler`, which stores a `fn(&ExceptionFrame) -> !`.
    // Function and data pointers have the same size on x86-64.
    Some(unsafe { core::mem::transmute::<*mut (), fn(&ExceptionFrame) -> !>(hook) })
}

/// Reads CR2, the address of the most recent page fault.
pub fn read_cr2() -> u64 {
    let cr2: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags))
    };
    cr2
}

/// Triggers a breakpoint exception (`int3`); returns once it is handled.
pub fn breakpoint() {
    // SAFETY: `int3` enters the breakpoint handler, which returns to the next
    // instruction with all registers restored. Without an IDT (before
    // `init`) the CPU triple-faults, which QEMU reports as a failed run.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}

/// Runs `int3` with known values in the general-purpose registers the
/// assembler lets us name and returns true if all survive. Checks that the
/// entry stubs restore registers (RBX and RBP are reserved by the compiler).
pub fn breakpoint_preserves_registers() -> bool {
    let mut regs: [u64; 13] = core::array::from_fn(|i| 0x0101_0101_0101_0101 * (i as u64 + 1));
    let expected = regs;
    let [a, c, d, si, di, r8, r9, r10, r11, r12, r13, r14, r15] = &mut regs;
    // SAFETY: as for `breakpoint`; the operands are plain register values.
    unsafe {
        core::arch::asm!(
            "int3",
            inout("rax") * a,
            inout("rcx") * c,
            inout("rdx") * d,
            inout("rsi") * si,
            inout("rdi") * di,
            inout("r8") * r8,
            inout("r9") * r9,
            inout("r10") * r10,
            inout("r11") * r11,
            inout("r12") * r12,
            inout("r13") * r13,
            inout("r14") * r14,
            inout("r15") * r15,
            options(nomem, nostack),
        )
    };
    regs == expected
}

/// Reads [`UNMAPPED_PROBE`] to trigger a page fault, for tests of the
/// exception path. Does not return unless the page is somehow mapped.
pub fn touch_unmapped_probe() {
    // SAFETY: the read targets a page that is unmapped (see `UNMAPPED_PROBE`)
    // and faults without touching memory. If it were mapped, it would be
    // ordinary kernel-range memory and a one-byte read changes nothing.
    unsafe {
        core::arch::asm!("mov al, byte ptr [{}]", in(reg) UNMAPPED_PROBE, out("al") _,
            options(readonly, nostack, preserves_flags))
    };
}

/// First vector for device interrupts (MSI-X, drivers.md).
pub const FIRST_DEVICE_VECTOR: u8 = 48;
/// Number of device-interrupt vectors (48–63).
pub const DEVICE_VECTORS: usize = 16;

/// Index (0–15) of a device-interrupt vector, if `vector` is one.
pub fn device_vector_index(vector: u64) -> Option<usize> {
    let index = vector.checked_sub(u64::from(FIRST_DEVICE_VECTOR))?;
    (index < DEVICE_VECTORS as u64).then_some(index as usize)
}

/// Called by the entry stubs with interrupts disabled.
extern "C" fn dispatch(frame: &mut ExceptionFrame) {
    debug_assert_eq!(
        super::rflags() & (RFLAGS_DF | RFLAGS_AC),
        0,
        "DF or AC set in the kernel"
    );
    if frame.vector == BREAKPOINT as u64 {
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        crate::kprintln!("PHAROS: breakpoint at {:#018x}, continuing", frame.rip - 1);
        return;
    }
    if frame.vector == u64::from(super::apic::TIMER_VECTOR) {
        super::apic::on_timer();
        return;
    }
    if frame.vector == u64::from(super::apic::SPURIOUS_VECTOR) {
        super::apic::on_spurious();
        return;
    }
    if let Some(index) = device_vector_index(frame.vector) {
        crate::irq::on_vector(index);
        return;
    }
    // (No let chains: the minimum supported Rust is 1.85.)
    if frame.cs & 3 == 3 {
        if let Some(hook) = user_fault_hook() {
            hook(frame);
        }
    }
    if let Some(hook) = fatal_hook() {
        hook(frame);
    }
    let report = Report {
        frame,
        cr2: read_cr2(),
    };
    super::_print_panic(format_args!("PHAROS: exception: {report}\n"));
    super::qemu_exit(super::QemuExit::Failure);
    super::halt()
}

#[cfg(target_os = "none")]
mod entry {
    use super::{ExceptionFrame, FIRST_DEVICE_VECTOR, dispatch, gate};
    use crate::arch::x86_64::apic;
    use crate::arch::x86_64::gdt::{DOUBLE_FAULT_IST, KERNEL_CODE};

    // One stub per vector, then the common path. `.quad` builds a table of
    // stub addresses; it needs the static relocation model, which only the
    // kernel target uses, hence `target_os = "none"`.
    core::arch::global_asm!(
        ".macro pharos_stub n, err",
        ".if \\err == 0",
        "push 0",
        ".endif",
        "push \\n",
        "jmp pharos_isr_common",
        ".endm",
        ".section .text.pharos_isr, \"ax\"",
        "pharos_isr_common:",
        "push rax", "push rbx", "push rcx", "push rdx", "push rsi", "push rdi", "push rbp",
        "push r8", "push r9", "push r10", "push r11", "push r12", "push r13", "push r14", "push r15",
        // 22 quadwords are on the stack (176 bytes) and the CPU aligned RSP
        // to 16 at entry, so RSP is 16-byte aligned for the call.
        // The interrupted code may be user code with DF or AC set (`std`,
        // `popf`). Rust needs DF clear; AC set would switch off SMAP checks.
        // `btr` on the saved flags works without SMAP support, unlike `clac`.
        // The user's flags come back with `iretq`.
        "cld",
        "pushfq",
        "btr qword ptr [rsp], 18",
        "popfq",
        "mov rdi, rsp",
        "call {dispatch}",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rbp", "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rbx", "pop rax",
        "add rsp, 16", // vector and error code
        "iretq",
        ".irp n, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31,32,255",
        "pharos_isr_\\n: pharos_stub \\n, 0",
        ".endr",
        ".irp n, 48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63",
        "pharos_isr_\\n: pharos_stub \\n, 0",
        ".endr",
        ".irp n, 8,10,11,12,13,14,17,21,29,30",
        "pharos_isr_\\n: pharos_stub \\n, 1",
        ".endr",
        ".section .rodata.pharos_isr_table, \"a\"",
        ".balign 8",
        ".global pharos_isr_table",
        "pharos_isr_table:",
        ".irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
        ".quad pharos_isr_\\n",
        ".endr",
        // Hardware interrupts: local APIC timer (32) and spurious (255).
        ".global pharos_irq_table",
        "pharos_irq_table:",
        ".quad pharos_isr_32, pharos_isr_255",
        // Device interrupts 48–63.
        ".global pharos_device_irq_table",
        "pharos_device_irq_table:",
        ".irp n, 48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63",
        ".quad pharos_isr_\\n",
        ".endr",
        ".text",
        dispatch = sym dispatch,
    );

    unsafe extern "C" {
        static pharos_isr_table: [u64; 32];
        static pharos_irq_table: [u64; 2];
        static pharos_device_irq_table: [u64; super::DEVICE_VECTORS];
    }

    /// Vectors of the entries in `pharos_irq_table`; must match the assembly.
    const IRQ_VECTORS: [u8; 2] = [apic::TIMER_VECTOR, apic::SPURIOUS_VECTOR];
    const _: () = assert!(apic::TIMER_VECTOR == 32 && apic::SPURIOUS_VECTOR == 255);

    #[repr(C, align(16))]
    struct Idt([[u64; 2]; 256]);
    static mut IDT: Idt = Idt([[0; 2]; 256]);

    /// Operand of `lidt`/`sidt`.
    #[repr(C, packed)]
    struct IdtPointer {
        limit: u16,
        base: u64,
    }

    pub fn init() {
        let idt = &raw mut IDT;
        // SAFETY: `pharos_isr_table` is the 32-entry table defined in the
        // assembly above; it is immutable.
        let handlers = unsafe { &pharos_isr_table };
        for (vector, &handler) in handlers.iter().enumerate() {
            // The double fault gets its own stack, so a stack overflow is
            // reported instead of escalating to a triple fault.
            let ist = if vector == super::DOUBLE_FAULT as usize {
                DOUBLE_FAULT_IST
            } else {
                0
            };
            // SAFETY: the IDT is only written here, before `lidt` makes the
            // CPU read it, and with interrupts disabled (`init` runs early).
            unsafe { (*idt).0[vector] = gate(handler, KERNEL_CODE, ist) };
        }
        // SAFETY: `pharos_irq_table` is the immutable 2-entry table above.
        let irq_handlers = unsafe { &pharos_irq_table };
        for (&vector, &handler) in IRQ_VECTORS.iter().zip(irq_handlers) {
            // SAFETY: as for the exception gates above.
            unsafe { (*idt).0[usize::from(vector)] = gate(handler, KERNEL_CODE, 0) };
        }
        // SAFETY: `pharos_device_irq_table` is the immutable 16-entry table
        // above, for vectors 48–63 in order.
        let device_handlers = unsafe { &pharos_device_irq_table };
        for (i, &handler) in device_handlers.iter().enumerate() {
            let vector = usize::from(FIRST_DEVICE_VECTOR) + i;
            // SAFETY: as for the exception gates above.
            unsafe { (*idt).0[vector] = gate(handler, KERNEL_CODE, 0) };
        }
        let pointer = IdtPointer {
            limit: (size_of::<Idt>() - 1) as u16,
            base: idt as u64,
        };
        // SAFETY: the IDT is static and its present gates point at the entry
        // stubs above, which preserve all registers and return with `iretq`.
        unsafe {
            core::arch::asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags))
        };
    }

    pub fn loaded() -> bool {
        let mut pointer = IdtPointer { limit: 0, base: 0 };
        // SAFETY: `sidt` writes 10 bytes into `pointer`, which is that size.
        unsafe {
            core::arch::asm!("sidt [{}]", in(reg) &raw mut pointer, options(nostack, preserves_flags))
        };
        pointer.base == (&raw const IDT) as u64 && pointer.limit as usize == size_of::<Idt>() - 1
    }

    // The dispatcher's frame type must match the 22 quadwords the stubs push.
    const _: () = assert!(size_of::<ExceptionFrame>() == 22 * 8);
}

/// Loads the IDT with handlers for CPU exceptions 0–31. Needs the kernel GDT
/// ([`super::gdt::init`]) first, because the gates use its code selector.
#[cfg(target_os = "none")]
pub fn init() {
    entry::init();
}

/// True if the kernel's IDT is loaded.
#[cfg(target_os = "none")]
pub fn loaded() -> bool {
    entry::loaded()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_matches_stub_layout() {
        assert_eq!(size_of::<ExceptionFrame>(), 22 * 8);
        assert_eq!(core::mem::offset_of!(ExceptionFrame, vector), 15 * 8);
        assert_eq!(core::mem::offset_of!(ExceptionFrame, rip), 17 * 8);
    }

    #[test]
    fn device_vectors() {
        assert_eq!(device_vector_index(47), None);
        assert_eq!(device_vector_index(48), Some(0));
        assert_eq!(device_vector_index(63), Some(15));
        assert_eq!(device_vector_index(64), None);
        assert_eq!(device_vector_index(u64::MAX), None);
    }

    #[test]
    fn error_code_vectors() {
        let with: Vec<u8> = (0..32).filter(|&v| has_error_code(v)).collect();
        assert_eq!(with, [8, 10, 11, 12, 13, 14, 17, 21, 29, 30]);
    }

    #[test]
    fn page_fault_error_decoding() {
        assert_eq!(
            PageFaultError(0).to_string(),
            "not-present page, read, kernel mode"
        );
        assert_eq!(
            PageFaultError(0b0111).to_string(),
            "protection violation, write, user mode"
        );
        assert_eq!(
            PageFaultError(0b1_1001).to_string(),
            "protection violation, instruction fetch, kernel mode, reserved bit set"
        );
    }

    #[test]
    fn gate_layout() {
        let [low, high] = gate(0x1122_3344_5566_7788, 0x08, 1);
        assert_eq!(low & 0xffff, 0x7788, "offset 15:0");
        assert_eq!((low >> 16) & 0xffff, 0x08, "selector");
        assert_eq!((low >> 32) & 0b111, 1, "IST");
        assert_eq!((low >> 40) & 0xff, 0x8e, "present 64-bit interrupt gate");
        assert_eq!(low >> 48, 0x5566, "offset 31:16");
        assert_eq!(high, 0x1122_3344, "offset 63:32");
    }

    #[test]
    fn page_fault_report() {
        let frame = ExceptionFrame {
            vector: 14,
            error_code: 0b10,
            rip: 0xffff_ffff_8000_1234,
            cs: 0x08,
            ..Default::default()
        };
        let text = Report {
            frame: &frame,
            cr2: 0xdead_b000,
        }
        .to_string();
        assert!(text.starts_with(
            "#PF page fault (vector 14), error code 0x2 (not-present page, write, kernel mode)\n"
        ));
        assert!(text.contains("CR2 (address) 0x00000000deadb000"));
        assert!(text.contains("RIP 0xffffffff80001234"));
    }

    #[test]
    fn report_without_error_code() {
        let frame = ExceptionFrame {
            vector: 6,
            ..Default::default()
        };
        let text = Report {
            frame: &frame,
            cr2: 0,
        }
        .to_string();
        assert!(text.starts_with("#UD invalid opcode (vector 6)\n"));
        assert!(!text.contains("error code"));
        assert!(!text.contains("CR2"));
    }
}
