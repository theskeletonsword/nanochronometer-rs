/* SPDX-License-Identifier: Apache-2.0
 *
 * OpenPOWER `powernv`, booted by skiboot.
 *
 * skiboot does not load ELF segments where they ask to go. QEMU (or the
 * platform's flash) places the whole file at 0x2000_0000 and skiboot runs it
 * *in place*: it finds the PT_LOAD segment containing e_entry and jumps to
 * load_base + p_offset + (e_entry - p_vaddr). So the image is linked such
 * that every byte's address is 0x2000_0000 plus its file offset — one
 * PT_LOAD that starts at the ELF header itself — and then the addresses the
 * code was linked for are the addresses it runs at, which static code needs.
 *
 * skiboot also decides whether a big-endian e_entry is a function descriptor
 * by whether it points into an executable *section*, so the section headers
 * must be kept (do not strip the image).
 */

ENTRY(_start)

PHDRS {
    image PT_LOAD FILEHDR PHDRS FLAGS(7);
}

SECTIONS {
    . = 0x20000000 + SIZEOF_HEADERS;
    __kernel_start = 0x20000000;

    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :image

    .rodata : ALIGN(64) { *(.rodata .rodata.*) } :image
    .data   : ALIGN(64) { *(.data .data.*) } :image

    /* The TOC. lld defines .TOC. as .got + 0x8000; the entry stub loads r2
       from it before any Rust runs. */
    .got    : ALIGN(256) { *(.got .toc) } :image

    .bss : ALIGN(64) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :image

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
