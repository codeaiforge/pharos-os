/* Pharos OS kernel layout (boot.md, D-003).
   Limine loads the kernel in the higher half at 0xffffffff80000000. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    limine_requests PT_LOAD FLAGS(6); /* RW: the bootloader fills in responses */
    text            PT_LOAD FLAGS(5); /* RX */
    rodata          PT_LOAD FLAGS(4); /* R  */
    data            PT_LOAD FLAGS(6); /* RW */
    stack           PT_LOAD FLAGS(6); /* RW: kernel stack, after a guard gap */
    df_stack        PT_LOAD FLAGS(6); /* RW: double-fault stack, after a guard gap */
}

SECTIONS
{
    . = 0xffffffff80000000;
    /* Segment boundaries (page-aligned) for the kernel's own page tables,
       which map each segment with its permissions (D-005). */
    __kernel_start = .;

    /* Limine only reads requests between the start and end markers. KEEP
       stops the linker from discarding them as unreferenced. */
    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :limine_requests
    .got : { *(.got .got.*) } :limine_requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __text_start = .;
    .text : { *(.text .text.*) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __rodata_start = .;
    .rodata : { *(.rodata .rodata.*) } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __data_start = .;
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data
    __data_end = .;

    /* Guard page: one page that no segment covers, so Limine leaves it
       unmapped. A kernel stack overflow faults here instead of silently
       overwriting .bss. */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    . += CONSTANT(MAXPAGESIZE);
    .kernel_stack (NOLOAD) : { *(.kernel_stack) } :stack

    /* Second guard page, below the double-fault stack. */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    . += CONSTANT(MAXPAGESIZE);
    .double_fault_stack (NOLOAD) : { *(.double_fault_stack) } :df_stack

    /DISCARD/ : { *(.eh_frame*) *(.note .note.*) }
}
