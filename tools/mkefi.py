#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Wraps an EFI program linked as an ELF into a PE/COFF EFI application, for
the targets lld links no PE for: 32-bit ARM and RISC-V.

    tools/mkefi.py loader.elf BOOTRISCV64.EFI

The ELF is the EFI loader (crates/nanochrono-baremetal/boot/efi_loader.c),
linked at 0x1000 by boot/efi_loader.ld with no absolute address in it. Each
PT_LOAD segment becomes a PE section at the same address, with the segment's
permissions — code read and execute, data read and write (its virtual size
covering .bss, which the firmware zeroes), as firmware that maps an image W^X
requires — the ELF's entry is the entry point, there are no relocations (none
are needed), and the subsystem is the EFI application's.
The machine is UEFI's for the ELF's: ARM (Thumb mixed, 0x01C2), RISC-V 32
(0x5032) or RISC-V 64 (0x5064); PE32 for the 32-bit ones, PE32+ for RISC-V 64.

Written from the PE/COFF specification and the machine types the UEFI
specification lists.
"""

import struct
import sys

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
EFI_BASE = 0x1000
EM_ARM, EM_RISCV = 40, 243


def align(x, a):
    return (x + a - 1) & ~(a - 1)


def load_elf(data):
    """(PE machine, PE32+?, entry, [(vaddr, bytes, memsz, flags)]) from the ELF."""
    if data[:4] != b"\x7fELF" or data[5] != 1:
        sys.exit("not a little-endian ELF")
    wide = data[4] == 2
    if wide:
        machine, entry, phoff = struct.unpack_from("<2xHxxxxQQ", data, 16)
        phentsize, phnum = struct.unpack_from("<HH", data, 54)
    else:
        machine, entry, phoff = struct.unpack_from("<2xHxxxxII", data, 16)
        phentsize, phnum = struct.unpack_from("<HH", data, 42)
    if machine == EM_ARM and not wide:
        pe_machine = 0x01C2
    elif machine == EM_RISCV:
        pe_machine = 0x5064 if wide else 0x5032
    else:
        sys.exit(f"no EFI machine for ELF machine {machine}")
    segments = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if wide:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<IIQQQQQ", data, off)
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags = struct.unpack_from("<IIIIIII", data, off)
        if p_type == 1 and p_memsz:
            segments.append((p_vaddr, data[p_offset:p_offset + p_filesz], p_memsz, p_flags))
    segments.sort()
    if not segments or segments[0][0] != EFI_BASE:
        sys.exit(f"the image must start at {EFI_BASE:#x} (boot/efi_loader.ld)")
    if any(v % SECTION_ALIGN for v, _, _, _ in segments):
        sys.exit("every segment must start on a page (boot/efi_loader.ld)")
    return pe_machine, wide, entry, segments


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: tools/mkefi.py <loader.elf> <out.efi>")
    pe_machine, wide, entry, segments = load_elf(open(sys.argv[1], "rb").read())

    # One section per segment, its raw data in file order.
    sections, raw, pointer = [], b"", FILE_ALIGN
    code_size = data_size = bss_size = 0
    for vaddr, body, memsz, flags in segments:
        raw_size = align(len(body), FILE_ALIGN)
        if flags & 1:   # PF_X
            name, chars = b".text", 0x60000020           # code, execute, read
            code_size += raw_size
        else:
            name, chars = b".data", 0xC00000C0           # initialised and .bss, read, write
            data_size += raw_size
            bss_size += memsz - len(body)
        sections.append(struct.pack("<8sIIIIIIHHI", name, memsz, vaddr, raw_size,
                                    pointer if raw_size else 0, 0, 0, 0, 0, chars))
        raw += body + b"\0" * (raw_size - len(body))
        pointer += raw_size
    size_of_image = align(max(v + m for v, _, m, _ in segments), SECTION_ALIGN)

    # COFF file header.
    opt_size = 240 if wide else 224
    characteristics = 0x0002 | 0x0004 | 0x0008 | 0x0200  # executable; no lines, local symbols, debug
    characteristics |= 0x0020 if wide else 0x0100         # large address aware / 32-bit machine
    coff = struct.pack("<HHIIIHH", pe_machine, len(sections), 0, 0, 0, opt_size, characteristics)

    # Optional header: the EFI application subsystem (10), image base 0, and
    # all sixteen data directories present and empty — no relocations.
    head = struct.pack("<HBBIIIII", 0x20B if wide else 0x10B, 0, 0,
                       code_size, data_size, bss_size, entry, EFI_BASE)
    if wide:
        head += struct.pack("<Q", 0)                    # ImageBase
    else:
        head += struct.pack("<II", EFI_BASE, 0)         # BaseOfData, ImageBase
    head += struct.pack("<IIHHHHHHIIIIHH", SECTION_ALIGN, FILE_ALIGN, 0, 0, 0, 0, 0, 0, 0,
                        size_of_image, FILE_ALIGN, 0, 10, 0)
    head += struct.pack("<QQQQII" if wide else "<IIIIII", 0, 0, 0, 0, 0, 16)
    head += b"\0" * (16 * 8)
    assert len(head) == opt_size

    headers = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + head + b"".join(sections)
    assert len(headers) <= FILE_ALIGN
    with open(sys.argv[2], "wb") as f:
        f.write(headers + b"\0" * (FILE_ALIGN - len(headers)))
        f.write(raw)


if __name__ == "__main__":
    main()
