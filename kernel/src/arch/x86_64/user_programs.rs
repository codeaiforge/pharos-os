//! Small user-mode test programs (M2.7, syscalls-ipc.md).
//!
//! Position-independent flat binaries written in assembly. They live in the
//! hardware layer because `global_asm!` counts as `unsafe` code, which only
//! this layer may use (AGENTS.md); test kernels load them as data. Each
//! starts at its first byte, receives its argument in `rdi`, and ends with
//! `ud2` in case the instruction meant to fault does not.

use core::arch::global_asm;

macro_rules! programs {
    ($($variant:ident, $start:ident, $end:ident, $doc:literal, $asm:literal;)*) => {
        global_asm!(
            ".section .rodata.pharos_user_programs, \"a\"",
            $(
                concat!(".global ", stringify!($start)),
                concat!(".global ", stringify!($end)),
                concat!(stringify!($start), ":"),
                $asm,
                "ud2",
                concat!(stringify!($end), ":"),
            )*
            ".previous",
        );

        unsafe extern "C" {
            $(
                safe static $start: u8;
                safe static $end: u8;
            )*
        }

        /// A user-mode test program.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum TestProgram {
            $(#[doc = $doc] $variant,)*
        }

        impl TestProgram {
            /// The program's machine code.
            pub fn bytes(self) -> &'static [u8] {
                let (start, end) = match self {
                    $(Self::$variant => (&raw const $start, &raw const $end),)*
                };
                let len = end as usize - start as usize;
                // SAFETY: `start..end` is one program's code, emitted above
                // into read-only data; it is never written.
                unsafe { core::slice::from_raw_parts(start, len) }
            }
        }
    };
}

programs! {
    Spin, pharos_up_spin, pharos_up_spin_end,
        "Increments the 8-byte counter at `rdi` forever, never yielding.",
        "2: inc qword ptr [rdi]\n jmp 2b";
    Read, pharos_up_read, pharos_up_read_end,
        "Reads 8 bytes at `rdi`.",
        "mov rax, qword ptr [rdi]";
    Write, pharos_up_write, pharos_up_write_end,
        "Writes 8 bytes at `rdi`.",
        "mov qword ptr [rdi], rax";
    Jump, pharos_up_jump, pharos_up_jump_end,
        "Jumps to `rdi`.",
        "jmp rdi";
    Cli, pharos_up_cli, pharos_up_cli_end,
        "Disables interrupts (privileged).",
        "cli";
    Hlt, pharos_up_hlt, pharos_up_hlt_end,
        "Halts the CPU (privileged).",
        "hlt";
    WriteCr3, pharos_up_cr3, pharos_up_cr3_end,
        "Loads `rdi` into CR3 (privileged).",
        "mov cr3, rdi";
}
