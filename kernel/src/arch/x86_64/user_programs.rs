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
    SyscallTable, pharos_up_table, pharos_up_table_end,
        "Runs the system calls in the table at `rdi`, then exits with code \
         `0x600d`. Table: a count, then entries of ten 8-byte words: `rax`, \
         `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` going in; status (`rax`), \
         value (`rdx`), and 1 if `rdi`, `rsi`, `r10`, `r8`, `r9`, and `rsp` \
         survived (else 0) coming out.",
        "mov rbx, rdi
         mov r12, [rbx]
         lea r13, [rbx + 8]
         mov r15, rsp
     2:  test r12, r12
         jz 4f
         mov rax, [r13]
         mov rdi, [r13 + 8]
         mov rsi, [r13 + 16]
         mov rdx, [r13 + 24]
         mov r10, [r13 + 32]
         mov r8, [r13 + 40]
         mov r9, [r13 + 48]
         syscall
         mov [r13 + 56], rax
         mov [r13 + 64], rdx
         mov r14, 1
         cmp rdi, [r13 + 8]
         jne 3f
         cmp rsi, [r13 + 16]
         jne 3f
         cmp r10, [r13 + 32]
         jne 3f
         cmp r8, [r13 + 40]
         jne 3f
         cmp r9, [r13 + 48]
         jne 3f
         cmp rsp, r15
         je 5f
     3:  xor r14, r14
     5:  mov [r13 + 72], r14
         add r13, 80
         dec r12
         jmp 2b
     4:  xor eax, eax
         mov edi, 0x600d
         syscall";
    Ping, pharos_up_ping, pharos_up_ping_end,
        "IPC ping: `rdi` times, sends an 8-byte counter on handle 1 and \
         receives on handle 2; each reply must be the counter plus one. Exits \
         with 0, with `0xbad0` plus the status of a failed call, or with \
         `0xbadd` for a wrong reply.",
        "mov r12, rdi
         xor r14d, r14d
         sub rsp, 256
         mov r13, rsp
     2:  test r12, r12
         jz 3f
         mov [r13], r14
         mov eax, 3
         mov edi, 1
         mov rsi, r13
         mov edx, 8
         xor r10d, r10d
         xor r8d, r8d
         syscall
         test rax, rax
         jnz 4f
         mov eax, 4
         mov edi, 2
         mov rsi, r13
         mov edx, 256
         syscall
         test rax, rax
         jnz 4f
         lea rax, [r14 + 1]
         cmp [r13], rax
         jne 5f
         inc r14
         dec r12
         jmp 2b
     3:  xor eax, eax
         xor edi, edi
         syscall
     4:  lea rdi, [rax + 0xbad0]
         xor eax, eax
         syscall
     5:  mov edi, 0xbadd
         xor eax, eax
         syscall";
    Pong, pharos_up_pong, pharos_up_pong_end,
        "IPC pong: forever, receives on handle 1, adds one to the first 8 \
         bytes, and sends them back on handle 2. Exits with `0xbad0` plus the \
         status of a failed call.",
        "sub rsp, 256
         mov r13, rsp
     2:  mov eax, 4
         mov edi, 1
         mov rsi, r13
         mov edx, 256
         syscall
         test rax, rax
         jnz 4f
         inc qword ptr [r13]
         mov eax, 3
         mov edi, 2
         mov rsi, r13
         mov edx, 8
         xor r10d, r10d
         xor r8d, r8d
         syscall
         test rax, rax
         jnz 4f
         jmp 2b
     4:  lea rdi, [rax + 0xbad0]
         xor eax, eax
         syscall";
}
