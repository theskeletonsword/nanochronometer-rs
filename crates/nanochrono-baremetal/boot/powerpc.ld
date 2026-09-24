/* SPDX-License-Identifier: Apache-2.0
 *
 * 32-bit e500 (QEMU `ppce500`), booted the ePAPR way: QEMU loads each
 * PT_LOAD at its physical address and enters at e_entry with a TLB1 entry
 * mapping RAM from 0 one-to-one. 1 MiB keeps clear of anything a loader
 * leaves at the bottom of memory.
 */

ENTRY(_start)

SECTIONS {
    . = 0x00100000;
    __kernel_start = .;

    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        /* IVPR supplies the upper 16 bits of every handler address, so the
           table sits on a 64 KiB boundary with the handlers within 64 KiB of
           it. Named before the `.text.*` wildcard, which would otherwise
           take the section first and place it unaligned. */
        . = ALIGN(65536);
        KEEP(*(.text.nc_ivors))
        *(.text .text.*)
    }

    .rodata : ALIGN(64) { *(.rodata .rodata.*) }
    .data   : ALIGN(64) { *(.data .data.*) *(.sdata .sdata.*) *(.got2) *(.got) }

    .bss : ALIGN(64) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
