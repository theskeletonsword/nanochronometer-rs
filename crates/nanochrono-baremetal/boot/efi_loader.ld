/* SPDX-License-Identifier: Apache-2.0
 *
 * Links the EFI loader (efi_loader.c + kernel_blob.S) as one flat image at
 * EFI_BASE — 0x1000, where tools/mkefi.py's PE header puts its first section —
 * for tools/mkefi.py to wrap. The code is position independent; the build
 * links it at a second base as well and checks the two images are the same.
 */
ENTRY(efi_main)

/* Two segments, without the ELF headers in them — code and read-only data
 * (the embedded kernel too), then data and .bss on a page of their own — so
 * firmware that maps an image W^X (edk2 does) gets one PE section of each. */
PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = EFI_BASE;
    __image_start = .;
    .text : { *(.text .text.*) } :text
    .rodata : ALIGN(16) { *(.rodata .rodata.* .srodata .srodata.*) } :text
    . = ALIGN(4096);
    .data : { *(.data .data.* .sdata .sdata.*) } :data
    .bss : ALIGN(16) { *(.bss .bss.* .sbss .sbss.* COMMON) } :data
    __image_end = .;

    /DISCARD/ : {
        *(.comment) *(.note .note.*) *(.ARM.exidx*) *(.ARM.extab*)
        *(.ARM.attributes) *(.riscv.attributes) *(.eh_frame*)
    }
}
