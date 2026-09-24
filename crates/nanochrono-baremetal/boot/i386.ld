/* SPDX-License-Identifier: Apache-2.0
 *
 * The default linker layout assumes an OS loader that will place the image
 * wherever it likes. A multiboot image cannot: the loader scans the first
 * 32 KiB of the file for the header, so the header must come first, and the
 * whole image must sit above the 1 MiB mark that PC firmware leaves free.
 *
 * The i386 layout: the same as x86_64's, for a 32-bit image entered by
 * boot_i386.S.
 */

ENTRY(_start)

SECTIONS {
    /* 1 MiB. Everything below is firmware, legacy device windows and the
     * real-mode interrupt table. */
    . = 1M;

    /* Bounds for the image itself. The interface reports how much memory the
       kernel occupies, and the only honest source for that is the layout the
       linker produced — a figure typed into the source would be wrong the
       first time anything grew. */
    __kernel_start = .;

    /* The multiboot header first, so the loader finds it inside its 32 KiB
     * scan window. Keeping .boot in the same section places the 32-bit entry
     * next to it without a second alignment gap. */
    .boot : ALIGN(4K) {
        KEEP(*(.multiboot_header))
        *(.boot)
    }

    .text : ALIGN(4K) {
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        /* Bounds for the zeroing loop in boot_i386.S. A multiboot loader is
           not required to zero .bss. */
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        . = ALIGN(4);
        __bss_end = .;
    }

    __kernel_end = .;

    /* Rust emits these for a target with no unwinder; there is nothing to
     * unwind into, and keeping them would only inflate the image. */
    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
