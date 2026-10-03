#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Packs position-independent shared objects into NanoChronometer modules,
and inspects them.

The kernel loader (crates/nanochrono-baremetal/src/ncplu.rs) has no ELF
parser and no dynamic linker: it copies flat sections into a fixed arena and
applies a tiny set of relocations. This turns a `.so` built for a
`<arch>-nanochrono-none-dylib` target into exactly that flat form — an app
(`.ncapp`), a driver (`.ncdri`), a shared library (`.ncdyn`) or an app
plugin (`.ncplu`), one architecture per module:

    tools/ncplu.py pack libsnake.so -o main.ncapp --caps screen,input,timer
    tools/ncplu.py pack libsnake-arm.so -o main.ncapp --arch aarch64
    tools/ncplu.py pack libvgm.so -o vgm.ncplu --kind plugin --caps none
    tools/ncplu.py dump main.ncapp

Packages — one `.ncpkg` holding the modules for every architecture, a signed
manifest and the shared assets — are built by the Rust host tool, from a
directory laid out the way the package installs:

    tools/ncpkg: ncpkg build mypkg/ -o mypkg.ncpkg   (docs/NCPKG.md)

Signing a module (ML-DSA-87 + P-521) is tools/ncplu-sign's; an unsigned
module loads as "community", in ring 3. The layout here is matched byte for
byte by crates/nanochrono-core/src/ncplu.rs. (The module magic still reads
NCPLU: the format began as the plugin format.)
"""

import argparse
import hashlib
import struct
import sys

# ---------------------------------------------------------------------------
# .ncplu layout (little-endian), mirrored from ncplu.rs
# ---------------------------------------------------------------------------

MAGIC = b"NCPLU\x1b\0\0"
FORMAT_VERSION = 1
ABI_VERSION = 1
HEADER_SIZE = 160

SECTION_TEXT, SECTION_RODATA, SECTION_DATA, SECTION_BSS = 1, 2, 3, 4
MF_R, MF_W, MF_X = 1, 2, 4
RELOC_RELATIVE, RELOC_IMPORT64 = 1, 2

# Signature block: magic then the two signatures over the digest. Reserved
# (zero-filled) by the packer; filled by tools/ncplu-sign. Sizes mirror
# ncplu.rs (ML-DSA-87 sig 4627, P-521 raw sig 132).
SIG_MAGIC = b"NCS1"
SIG_MLDSA_LEN = 4627
SIG_P521_LEN = 132
SIGNATURE_LEN = 8 + SIG_MLDSA_LEN + SIG_P521_LEN

FNV_OFFSET = 0xCBF29CE484222325

# Header flags and capability bits, in step with crates/nanochrono-core/src/ncplu.rs.
FLAG_HAS_CAPS = 1 << 1
CAP_BITS = {
    "screen": 1 << 0,  # fill_rect, clear, present
    "input": 1 << 1,   # poll_event
    "log": 1 << 2,     # log
    "timer": 1 << 3,   # ticks, timer_*
    "pmu": 1 << 4,     # pmu_*
    "rng": 1 << 5,     # rng_*
}
CAP_ALL = 0
for _b in CAP_BITS.values():
    CAP_ALL |= _b


def parse_caps(spec: str) -> int:
    """A capability spec: 'all', 'none', or a comma list of names."""
    spec = spec.strip().lower()
    if spec in ("all", ""):
        return CAP_ALL
    if spec == "none":
        return 0
    mask = 0
    for name in spec.split(","):
        name = name.strip()
        if name not in CAP_BITS:
            raise SystemExit(f"unknown capability {name!r}; known: {', '.join(CAP_BITS)}, all, none")
        mask |= CAP_BITS[name]
    return mask
# Architecture and module-kind codes, in step with
# crates/nanochrono-core/src/ncplu.rs (Arch, Kind: H_ARCH at 152, H_KIND
# at 154). Zero is x86-64 / app, so modules packed before either field
# existed already read correctly.
ARCHES = {
    "x86_64": 0, "x64": 0,
    "i386": 1, "x86": 1,
    "aarch64": 2, "arm64": 2,
    "arm32": 3, "arm": 3,
    "riscv64": 4, "riscv32": 5,
    "ppc64": 6, "ppc64le": 7, "ppc": 8,
}
ARCH_NAMES = {
    0: "x86_64", 1: "i386", 2: "aarch64", 3: "arm32", 4: "riscv64",
    5: "riscv32", 6: "ppc64", 7: "ppc64le", 8: "ppc",
}
KINDS = {"app": 0, "driver": 1, "library": 2, "plugin": 3}
KIND_NAMES = {0: "app", 1: "driver", 2: "library", 3: "plugin"}
# The extension each kind ships as: .ncapp (one app, one architecture),
# .ncdri (driver), .ncdyn (shared library: /usr/lib, or private to a
# package), .ncplu (an extension its host app loads).
KIND_EXTENSIONS = {0: ".ncapp", 1: ".ncdri", 2: ".ncdyn", 3: ".ncplu"}

FNV_PRIME = 0x100000001B3


def signed_digest(image: bytes, sig_off: int) -> bytes:
    """SHA-512 of the file up to the signature block, with the header's own
    digest field (offset 88..152) taken as zero. Both the packer and the
    kernel hash the same bytes, so the field can hold the result without
    hashing itself. The hybrid signature (phase 2) signs this digest."""
    body = bytearray(image[:sig_off])
    body[88:152] = b"\0" * 64
    return hashlib.sha512(bytes(body)).digest()


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# A hand-rolled ELF64 reader: only ET_DYN, only what the packer needs
# ---------------------------------------------------------------------------

# Section header types and flags.
SHT_NOBITS = 8
SHT_RELA = 4
SHT_DYNSYM = 11
SHF_ALLOC = 0x2
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4
SHF_TLS = 0x400

# x86-64 relocation types.
R_X86_64_64 = 1
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8

# Function imports a plugin may carry because the compiler, not its author,
# calls them: -fstack-protector's failure handler (the kernel provides it).
COMPILER_FUNCTION_IMPORTS = {"__stack_chk_fail"}


class Section:
    __slots__ = ("name", "type", "flags", "addr", "offset", "size", "link", "info", "entsize", "_name_off", "addralign")


class Sym:
    __slots__ = ("name", "value", "shndx", "info")


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 2 or data[5] != 1:
            raise ValueError("only 64-bit little-endian ELF is handled")
        self.data = data
        (self.e_type,) = struct.unpack_from("<H", data, 16)
        if self.e_type != 3:
            raise ValueError(
                f"expected a shared object (ET_DYN); got e_type={self.e_type}. "
                "Build the plugin as crate-type=cdylib on the -dylib target."
            )
        (self.e_shoff,) = struct.unpack_from("<Q", data, 40)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from("<HHH", data, 58)
        self._read_sections()

    def _read_sections(self):
        raw = []
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            s = Section()
            (name_off,) = struct.unpack_from("<I", self.data, base)
            (s.type,) = struct.unpack_from("<I", self.data, base + 4)
            (s.flags,) = struct.unpack_from("<Q", self.data, base + 8)
            (s.addr,) = struct.unpack_from("<Q", self.data, base + 16)
            (s.offset,) = struct.unpack_from("<Q", self.data, base + 24)
            (s.size,) = struct.unpack_from("<Q", self.data, base + 32)
            s.link, s.info = struct.unpack_from("<II", self.data, base + 40)
            (s.entsize,) = struct.unpack_from("<Q", self.data, base + 56)
            s._name_off = name_off
            raw.append(s)
        strtab = raw[self.e_shstrndx]
        for s in raw:
            s.name = self._cstr(strtab.offset + s._name_off)
        self.sections = raw

    def _cstr(self, off: int) -> str:
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("utf-8", "replace")

    def section(self, name: str):
        return next((s for s in self.sections if s.name == name), None)

    def dynsyms(self):
        sec = next((s for s in self.sections if s.type == SHT_DYNSYM), None)
        if sec is None:
            return []
        strtab = self.sections[sec.link]
        syms = []
        for off in range(sec.offset, sec.offset + sec.size, 24):
            sym = Sym()
            (name_off,) = struct.unpack_from("<I", self.data, off)
            sym.info = self.data[off + 4]
            (sym.shndx,) = struct.unpack_from("<H", self.data, off + 6)
            (sym.value,) = struct.unpack_from("<Q", self.data, off + 8)
            sym.name = self._cstr(strtab.offset + name_off) if name_off else ""
            syms.append(sym)
        return syms

    def relocations(self):
        """Every RELA entry in the file, as (r_offset, r_type, r_sym, r_addend)."""
        out = []
        for sec in self.sections:
            if sec.type != SHT_RELA:
                continue
            for off in range(sec.offset, sec.offset + sec.size, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
                out.append((r_offset, r_info & 0xFFFFFFFF, r_info >> 32, r_addend))
        return out


# ---------------------------------------------------------------------------
# Packing
# ---------------------------------------------------------------------------


def section_kind_flags(s: Section):
    """The .ncplu section kind and memory flags for an ELF alloc section."""
    if s.type == SHT_NOBITS:
        return SECTION_BSS, MF_R | MF_W
    if s.flags & SHF_EXECINSTR:
        return SECTION_TEXT, MF_R | MF_X
    if s.flags & SHF_WRITE:
        return SECTION_DATA, MF_R | MF_W
    return SECTION_RODATA, MF_R


def pack(elf: Elf, entry: str, caps: int = CAP_ALL, arch: str = "x86_64", kind: str = "app") -> bytes:
    # Allocated sections become the plugin's memory image, each kept at the
    # virtual address the linker gave it (the .so is linked at base 0, so the
    # address is the offset within the image). TLS is not supported.
    alloc = [
        s
        for s in elf.sections
        if (s.flags & SHF_ALLOC) and not (s.flags & SHF_TLS) and s.size > 0
    ]
    if not alloc:
        raise ValueError("no allocatable sections")
    arena_size = max(s.addr + s.size for s in alloc)
    arena_size = (arena_size + 15) & ~15

    # Undefined dynamic symbols are kernel imports, resolved by name at load.
    syms = elf.dynsyms()
    imports = []  # names, in order; index is the reloc's `sym`
    import_index = {}

    def import_of(name: str) -> int:
        if name not in import_index:
            import_index[name] = len(imports)
            imports.append(name)
        return import_index[name]

    relocs = []  # (kind, offset, sym, addend)
    for r_offset, r_type, r_sym, r_addend in elf.relocations():
        if r_type == R_X86_64_RELATIVE:
            # *(base + off) = base + addend
            relocs.append((RELOC_RELATIVE, r_offset, 0, r_addend))
        elif r_type in (R_X86_64_GLOB_DAT, R_X86_64_64, R_X86_64_JUMP_SLOT):
            sym = syms[r_sym]
            if sym.shndx == 0:
                # Undefined: a kernel import, resolved by nc_resolve_symbol.
                # Kernel services are called through the NcApi table, where
                # capabilities apply and which works at ring 3, so a function
                # import is refused — except what the compiler itself calls:
                # the stack canary's failure handler, which the kernel
                # provides at both tiers. The loader binds every slot at load
                # time, so the PLT stub's indirect jump needs no lazy binding.
                if r_type == R_X86_64_JUMP_SLOT and sym.name not in COMPILER_FUNCTION_IMPORTS:
                    raise ValueError(
                        f"function import '{sym.name}': call kernel services through the "
                        "NcApi table, not by linker import"
                    )
                relocs.append((RELOC_IMPORT64, r_offset, import_of(sym.name), r_addend))
            else:
                # Defined in the image: rebase like a RELATIVE.
                relocs.append((RELOC_RELATIVE, r_offset, 0, sym.value + r_addend))
        else:
            raise ValueError(f"unhandled relocation type {r_type} at {r_offset:#x}")

    # The entry export, plus any other ncplu_* (or, for a driver, ncdri_*:
    # ncdri_main, ncdri_fini) globals, as (name, mem_off).
    exports = []
    entry_index = None
    for sym in syms:
        if sym.shndx != 0 and sym.name.startswith(("ncplu_", "ncdri_")):
            if sym.name == entry:
                entry_index = len(exports)
            exports.append((sym.name, sym.value))
    if entry_index is None:
        raise ValueError(f"entry symbol '{entry}' not found (is it #[no_mangle] pub extern?)")

    # --- serialise ---------------------------------------------------------
    # String blob: import then export names.
    strings = bytearray()
    str_off = {}

    def intern(name: str) -> int:
        b = name.encode()
        if b not in str_off:
            str_off[b] = len(strings)
            strings.extend(b)
        return str_off[b]

    import_bytes = bytearray()
    for name in imports:
        b = name.encode()
        import_bytes += struct.pack("<IIQ", intern(name), len(b), fnv1a(b))

    export_bytes = bytearray()
    for name, mem_off in exports:
        b = name.encode()
        export_bytes += struct.pack("<IIQII", intern(name), len(b), fnv1a(b), mem_off, 0)

    reloc_bytes = bytearray()
    for rkind, offset, sym, addend in relocs:
        reloc_bytes += struct.pack("<IIQIIq", rkind, 0, offset, sym, 0, addend)

    # Lay out the file: header, then the section file-images, then tables.
    # The section file-images must come first so the loader can copy them by
    # absolute file offset; here they are packed contiguously and each
    # section's file_off is rewritten to point at them.
    body = bytearray(b"\0" * HEADER_SIZE)

    # Re-emit section file-images and fix their file_off.
    fixed_sections = bytearray()
    for i, s in enumerate(alloc):
        skind, mf = section_kind_flags(s)
        if s.type == SHT_NOBITS:
            file_off = 0
            file_size = 0
        else:
            file_off = len(body)
            file_size = s.size
            body += elf.data[s.offset:s.offset + s.size]
        fixed_sections += struct.pack(
            "<BBHIIIII", skind, mf, 0, s.addr, file_off, file_size, s.size, 0
        )
    # Pad to 8 for the tables.
    while len(body) % 8:
        body.append(0)

    sections_off = len(body)
    body += fixed_sections
    imports_off = len(body)
    body += import_bytes
    exports_off = len(body)
    body += export_bytes
    relocs_off = len(body)
    body += reloc_bytes
    strings_off = len(body)
    body += strings
    while len(body) % 8:
        body.append(0)
    signature_off = len(body)
    signature_len = SIGNATURE_LEN
    # Reserve the signature block, zero-filled: an unsigned plugin has zeros
    # here (magic mismatch => community); tools/ncplu-sign fills it without
    # changing anything the digest covers, since the digest is over the region
    # *before* this block.
    body += b"\0" * SIGNATURE_LEN
    total_size = len(body)

    # Header.
    struct.pack_into("<8s", body, 0, MAGIC)
    struct.pack_into("<HH", body, 8, FORMAT_VERSION, HEADER_SIZE)
    struct.pack_into("<I", body, 12, FLAG_HAS_CAPS)  # flags
    struct.pack_into("<Q", body, 16, total_size)
    struct.pack_into("<II", body, 24, ABI_VERSION, entry_index)
    struct.pack_into("<II", body, 32, sections_off, len(alloc))
    struct.pack_into("<II", body, 40, imports_off, len(imports))
    struct.pack_into("<II", body, 48, exports_off, len(exports))
    struct.pack_into("<II", body, 56, relocs_off, len(relocs))
    struct.pack_into("<II", body, 64, strings_off, len(strings))
    struct.pack_into("<II", body, 72, signature_off, signature_len)
    struct.pack_into("<I", body, 80, arena_size)
    struct.pack_into("<I", body, 84, caps)  # capabilities (FLAG_HAS_CAPS set)
    try:
        arch_code = ARCHES[arch.lower()]
    except KeyError:
        raise ValueError(f"unknown architecture {arch!r}; known: {', '.join(sorted(set(ARCHES)))}")
    try:
        kind_code = KINDS[kind.lower()]
    except KeyError:
        raise ValueError(f"unknown kind {kind!r}; known: app, driver, library, plugin")
    struct.pack_into("<HH", body, 152, arch_code, kind_code)

    struct.pack_into("<64s", body, 88, signed_digest(body, signature_off))

    return bytes(body)


# ---------------------------------------------------------------------------
# Dump
# ---------------------------------------------------------------------------


def dump(data: bytes):
    if data[:8] != MAGIC:
        sys.exit("not a NanoChronometer module (bad magic)")
    (fmt, hsize) = struct.unpack_from("<HH", data, 8)
    (flags,) = struct.unpack_from("<I", data, 12)
    (total,) = struct.unpack_from("<Q", data, 16)
    abi, entry = struct.unpack_from("<II", data, 24)
    sec_off, sec_n = struct.unpack_from("<II", data, 32)
    imp_off, imp_n = struct.unpack_from("<II", data, 40)
    exp_off, exp_n = struct.unpack_from("<II", data, 48)
    rel_off, rel_n = struct.unpack_from("<II", data, 56)
    str_off, str_len = struct.unpack_from("<II", data, 64)
    sig_off, sig_len = struct.unpack_from("<II", data, 72)
    (arena,) = struct.unpack_from("<I", data, 80)
    (caps,) = struct.unpack_from("<I", data, 84)
    digest = data[88:152]
    actual = signed_digest(data, sig_off)
    (arch, kind) = struct.unpack_from("<HH", data, 152)

    cap_names = "all" if (flags & FLAG_HAS_CAPS and caps == CAP_ALL) else (
        ",".join(n for n, bmask in CAP_BITS.items() if caps & bmask) or "none"
    ) if flags & FLAG_HAS_CAPS else "all (unset)"
    print(f"format {fmt}  abi {abi}  flags {flags:#x}  total {total}  arena {arena}  caps {cap_names}")
    print(f"arch {ARCH_NAMES.get(arch, arch)}  kind {KIND_NAMES.get(kind, kind)}")
    print(f"digest {'ok' if actual == digest else 'MISMATCH'}  signature {sig_len} bytes")
    strings = data[str_off:str_off + str_len]

    def name(o, n):
        return strings[o:o + n].decode("utf-8", "replace")

    kinds = {1: "text", 2: "rodata", 3: "data", 4: "bss"}
    print("sections:")
    for i in range(sec_n):
        b = data[sec_off + i * 24:]
        kind, mf, _, addr, foff, fsize, msize, _ = struct.unpack_from("<BBHIIIII", b, 0)
        print(f"  {kinds.get(kind, kind):6} mem@{addr:#06x} size {msize:5} file@{foff} ({fsize})")
    print(f"imports ({imp_n}):")
    for i in range(imp_n):
        no, nl, h = struct.unpack_from("<IIQ", data, imp_off + i * 16)
        print(f"  {name(no, nl)}")
    print(f"exports ({exp_n}):")
    for i in range(exp_n):
        no, nl, h, mem, _ = struct.unpack_from("<IIQII", data, exp_off + i * 24)
        mark = " <- entry" if i == entry else ""
        print(f"  {name(no, nl)} @ {mem:#06x}{mark}")
    rkinds = {1: "RELATIVE", 2: "IMPORT64"}
    print(f"relocs ({rel_n}):")
    for i in range(min(rel_n, 40)):
        kind, _, off, sym, _, add = struct.unpack_from("<IIQIIq", data, rel_off + i * 32)
        extra = f" import[{sym}]" if kind == RELOC_IMPORT64 else ""
        print(f"  {rkinds.get(kind, kind):9} @{off:#06x} addend {add:#x}{extra}")
    if rel_n > 40:
        print(f"  ... {rel_n - 40} more")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("pack", help="turn a .so into a module (.ncapp, .ncdri, .ncdyn, .ncplu)")
    pk.add_argument("shared_object")
    pk.add_argument("-o", "--output", required=True)
    pk.add_argument("--entry", default="ncplu_main")
    pk.add_argument("--caps", default="all",
                    help="capabilities the plugin may use: 'all', 'none', or a comma "
                         "list of screen,input,log,timer,pmu,rng")
    pk.add_argument("--arch", default="x86_64",
                    help="architecture the module was built for (default x86_64)")
    pk.add_argument("--kind", default="app",
                    help="what the module is: app, driver, library or plugin (default app)")
    dp = sub.add_parser("dump", help="inspect a module (.ncapp, .ncdri, .ncdyn, .ncplu)")
    dp.add_argument("ncplu")
    args = ap.parse_args()

    if args.cmd == "pack":
        with open(args.shared_object, "rb") as f:
            elf = Elf(f.read())
        out = pack(elf, args.entry, parse_caps(args.caps), args.arch, args.kind)
        with open(args.output, "wb") as f:
            f.write(out)
        print(f"{args.output}: {len(out)} bytes")
        dump(out)
    else:
        with open(args.ncplu, "rb") as f:
            dump(f.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
