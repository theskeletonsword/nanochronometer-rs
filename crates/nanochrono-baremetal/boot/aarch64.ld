/* SPDX-License-Identifier: Apache-2.0
 *
 * QEMU's `virt` machine RAM starts at 0x4000_0000. The kernel is linked 2 MiB
 * above that, at 0x4020_0000, because QEMU puts the devicetree at the very
 * start of RAM for an ELF that leaves it free — and the tree is where the
 * UART, fw_cfg (and with it the ramfb framebuffer) and the memory size are
 * described. A `-kernel` image is loaded at the load addresses this script
 * names, so there is no header to
 * place and no loader protocol to satisfy — which is why AArch64 needs no
 * equivalent of boot32.S. The entry stub is `global_asm!` in Rust; this script
 * only fixes the load address and the section order.
 */

ENTRY(_start)

SECTIONS {
    . = 0x40200000;

    /* Bounds for the image, so the same footprint reporting works on both
       architectures rather than being an x86 special case. */
    __kernel_start = .;

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) { *(.rodata .rodata.*) }
    .data   : ALIGN(4K) { *(.data .data.*) }

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        /* The zeroing loop in the entry stub stores 8 bytes at a time and
           stops at the first address >= __bss_end; an unaligned end would
           let the last store run past the section. */
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
