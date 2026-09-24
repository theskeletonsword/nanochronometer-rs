/* SPDX-License-Identifier: Apache-2.0
 *
 * RISC-V S-mode kernel under an SBI (QEMU `virt` + OpenSBI). QEMU loads each
 * PT_LOAD at its address and OpenSBI jumps to e_entry in S-mode with a0 = hart
 * ID and a1 = the device tree. Linked at 0x80400000: 4 MiB above RAM's base: the RV32 OpenSBI build reserves the first four.
 */

ENTRY(_start)

SECTIONS {
    . = 0x80400000;
    __kernel_start = .;

    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(64) { *(.srodata .srodata.*) *(.rodata .rodata.*) }

    .data : ALIGN(64) {
        *(.data .data.*)
        /* gp points 2 KiB into the small-data area so a signed 12-bit offset
           reaches both ends of it. */
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.*)
    }

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
