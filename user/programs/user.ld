/* Pharos OS user programs (drivers.md): static executables at USER_BASE
   (0x400000). The first page holds nothing; code starts at 0x401000. One
   segment per permission, page-aligned, so no page is writable and
   executable. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* RX */
    rodata PT_LOAD FLAGS(4); /* R  */
    data   PT_LOAD FLAGS(6); /* RW */
}

SECTIONS
{
    . = 0x401000;
    .text : { *(.text._start) *(.text .text.*) } :text

    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) *(.eh_frame*) } :rodata

    . = ALIGN(4096);
    .data : { *(.data .data.*) *(.got .got.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.comment) *(.note .note.*) }
}
