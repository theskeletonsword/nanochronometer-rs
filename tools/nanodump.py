#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the crash dumps the bare-metal kernel sends over COM1.

The kernel writes a `.DMP` image (see `crates/nanochrono-baremetal/src/
crashdump.rs` for the format) as base64 between two marker lines. This cuts it
out of a serial log, checks it, and prints it — symbolised against the kernel
ELF when one is given.

    tools/nanodump.py extract serial.log -o CRASH.DMP   # the last dump in the log
    tools/nanodump.py extract-image stick.img -o CRASH.DMP  # CRASH.DMP off a stick
    tools/nanodump.py show CRASH.DMP --elf nanochrono-kernel.sym.elf
    tools/nanodump.py show serial.log --elf ...          # both at once

`extract-image` reads a whole-disk image or the device itself (/dev/sdX, as
root) the way the kernel does: MBR, GPT or superfloppy, FAT16 or FAT32. On a
normal PC the stick's NANOCRASH partition mounts by itself and CRASH.DMP can
be given to `show` directly.

Exit status: 0 for a dump that checks out, 1 for none found, 2 for a corrupt one.
"""

import argparse
import base64
import shutil
import struct
import subprocess
import sys
import zlib

BEGIN = "-----BEGIN NANOCHRONO DUMP-----"
END = "-----END NANOCHRONO DUMP-----"

HEADER = struct.Struct("<4sHHIIHHIII16sQQ")
SECTION = struct.Struct("<IIII")

# The order of `REGISTER_NAMES` in crashdump.rs.
REGISTERS = [
    "vector", "error", "rip", "cs", "rflags", "rsp", "ss", "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cr0",
    "cr2", "cr3", "cr4", "efer",
]
SECTION_NAMES = {
    1: "cpu state", 2: "reason", 3: "driver", 4: "stack trace",
    5: "stack scan", 6: "memory table", 7: "memory",
}
FLAGS = {1: "cpu exception", 2: "frame-pointer walk", 4: "truncated"}
EXCEPTIONS = [
    "#DE divide error", "#DB debug", "NMI", "#BP breakpoint", "#OF overflow",
    "#BR bound range", "#UD invalid opcode", "#NM device not available",
    "#DF double fault", "coprocessor segment overrun", "#TS invalid TSS",
    "#NP segment not present", "#SS stack fault", "#GP general protection",
    "#PF page fault", "reserved", "#MF x87 floating point", "#AC alignment check",
    "#MC machine check", "#XM SIMD floating point", "#VE virtualization",
    "#CP control protection",
]
SOFTWARE_PANIC = (1 << 64) - 1


class DumpError(Exception):
    pass


def extract(text):
    """The bytes of the last complete dump in a serial log, or None."""
    lines = [line.strip() for line in text.splitlines()]
    last = None
    inside = None
    for line in lines:
        if line == BEGIN:
            inside = []
        elif line == END and inside is not None:
            last = "".join(inside)
            inside = None
        elif inside is not None:
            inside.append(line)
    if last is None:
        return None
    try:
        return base64.b64decode(last, validate=True)
    except ValueError as err:
        raise DumpError(f"the base64 between the markers is damaged: {err}") from err


def load(path):
    """A dump from a `.DMP` file or from a serial log containing one."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"DUMP":
        return data
    dump = extract(data.decode("utf-8", errors="replace"))
    if dump is None:
        raise FileNotFoundError(f"{path}: no crash dump in it")
    return dump


def parse(data):
    if len(data) < HEADER.size:
        raise DumpError("shorter than the header")
    (magic, version, header_size, total, crc, machine, flags, count, table,
     _reserved, kernel, counter, _reserved2) = HEADER.unpack_from(data)
    if magic != b"DUMP":
        raise DumpError(f"bad magic {magic!r}")
    if version != 1:
        raise DumpError(f"format version {version}; this reader knows 1")
    if total > len(data):
        raise DumpError(f"header says {total} bytes, only {len(data)} present")
    actual = zlib.crc32(data[header_size:total]) & 0xFFFFFFFF
    if actual != crc:
        raise DumpError(f"CRC mismatch: header {crc:#010x}, contents {actual:#010x}")
    sections = {}
    for i in range(count):
        kind, offset, size, _ = SECTION.unpack_from(data, table + i * SECTION.size)
        if offset + size > total:
            raise DumpError(f"section {kind} runs past the end")
        sections[kind] = data[offset:offset + size]
    return {
        "machine": machine,
        "flags": flags,
        "kernel": kernel.rstrip(b"\0").decode("ascii", errors="replace"),
        "counter": counter,
        "size": total,
        "sections": sections,
    }


def _le(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


def _fat_volume(read, start):
    """Parses the FAT boot sector at `start`, as the kernel does: the type by
    cluster count. Returns a dict, or None for anything but FAT16/FAT32."""
    b = read(start, 1)
    if b[0] not in (0xEB, 0xE9) or b[510:512] != b"\x55\xaa" or _le(b, 11, 2) != 512:
        return None
    spc, reserved, nfats = b[13], _le(b, 14, 2), b[16]
    root_entries = _le(b, 17, 2)
    total = _le(b, 19, 2) or _le(b, 32, 4)
    fat_size = _le(b, 22, 2) or _le(b, 36, 4)
    if not spc or spc & (spc - 1) or not reserved or not nfats or not fat_size or not total:
        return None
    root_sectors = (root_entries * 32 + 511) // 512
    data_sectors = total - (reserved + nfats * fat_size + root_sectors)
    if data_sectors <= 0:
        return None
    clusters = data_sectors // spc
    # FAT32 by its boot sector (no 16-bit FAT size); FAT12/16 by cluster count.
    if _le(b, 22, 2) == 0:
        kind = 32
    elif 4085 <= clusters < 65525:
        kind = 16
    else:
        return None
    fat_start = start + reserved
    root_start = fat_start + nfats * fat_size
    return {
        "kind": kind, "spc": spc, "fat_start": fat_start, "root_start": root_start,
        "root_sectors": root_sectors, "data_start": root_start + root_sectors,
        "root_cluster": _le(b, 44, 4), "clusters": clusters,
    }


def _fat_read_file(read, vol, name83):
    """The bytes of `name83` in the volume's root directory, or None."""
    def lba(c):
        return vol["data_start"] + (c - 2) * vol["spc"]

    def next_cluster(c):
        width = 2 if vol["kind"] == 16 else 4
        off = c * width
        sector = read(vol["fat_start"] + off // 512, 1)
        v = _le(sector, off % 512, width)
        return v if vol["kind"] == 16 else v & 0x0FFFFFFF

    def is_data(c):
        return 2 <= c < vol["clusters"] + 2

    if vol["kind"] == 16:
        root = read(vol["root_start"], vol["root_sectors"])
    else:
        root, c = b"", vol["root_cluster"]
        for _ in range(64):
            if not is_data(c):
                break
            root += read(lba(c), vol["spc"])
            c = next_cluster(c)
    for i in range(0, len(root), 32):
        e = root[i:i + 32]
        if e[0] == 0:
            break
        if e[0] == 0xE5 or e[11] & 0x0F == 0x0F or e[11] & 0x08:
            continue
        if e[0:11] == name83:
            first = (_le(e, 20, 2) << 16) | _le(e, 26, 2)
            size = _le(e, 28, 4)
            data, c = b"", first
            while len(data) < size and is_data(c):
                data += read(lba(c), vol["spc"])
                c = next_cluster(c)
            return data[:size]
    return None


def extract_image(path):
    """CRASH.DMP from a whole-disk image or device, as the kernel finds it."""
    with open(path, "rb") as f:
        def read(sector, count):
            f.seek(sector * 512)
            return f.read(count * 512)

        s0 = read(0, 1)
        if len(s0) < 512 or s0[510:512] != b"\x55\xaa":
            return None
        starts = []
        if _fat_volume(read, 0):
            starts = [0]
        elif any(s0[0x1BE + i * 16 + 4] == 0xEE for i in range(4)):
            h = read(1, 1)
            if h[0:8] == b"EFI PART":
                entries, count, size = _le(h, 72, 8), min(_le(h, 80, 4), 128), _le(h, 84, 4)
                table = read(entries, (count * size + 511) // 512)
                for n in range(count):
                    e = table[n * size:(n + 1) * size]
                    if any(e[0:16]):
                        starts.append(_le(e, 32, 8))
        else:
            for i in range(4):
                e = s0[0x1BE + i * 16:0x1BE + i * 16 + 16]
                if e[4] in (0x04, 0x06, 0x0E, 0x0B, 0x0C):
                    starts.append(_le(e, 8, 4))
        for start in starts:
            vol = _fat_volume(read, start)
            if vol:
                data = _fat_read_file(read, vol, b"CRASH   DMP")
                if data is not None:
                    return data
    return None


class Symbols:
    """Address to `function (file:line)`: addr2line where the ELF has debug
    information, the nearest preceding symbol from `nm` where it has not."""

    def __init__(self, elf):
        self.elf = elf
        self.table = []
        if elf and shutil.which("nm"):
            out = subprocess.run(["nm", "-C", "--defined-only", elf],
                                 capture_output=True, text=True, check=False).stdout
            for line in out.splitlines():
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[1] in "tTwW":
                    self.table.append((int(parts[0], 16), parts[2]))
            self.table.sort()
        self.addr2line = next((t for t in ("llvm-addr2line", "addr2line") if shutil.which(t)), None)

    def name(self, address):
        if not self.elf:
            return ""
        if self.addr2line:
            # `-i`: an address inside inlined code gives the inlined function
            # first, then each caller it was inlined into, as pairs of lines.
            out = subprocess.run([self.addr2line, "-f", "-C", "-i", "-e", self.elf, hex(address)],
                                 capture_output=True, text=True, check=False).stdout.split("\n")
            pairs = [(out[i], out[i + 1]) for i in range(0, len(out) - 1, 2) if out[i]]
            # A build without debug information still names the function but
            # gives its compilation unit and line 0 as the place; the offset
            # into the symbol, below, says more than that.
            pairs = [(f, loc) for f, loc in pairs
                     if f != "??" and not loc.startswith("??") and not loc.endswith(":0")]
            if pairs:
                return "  <- inlined in ".join(f"{f} ({loc.rsplit('/', 1)[-1]})" for f, loc in pairs)
        best = None
        for start, name in self.table:
            if start > address:
                break
            best = (start, name)
        if best:
            return f"{best[1]}+{address - best[0]:#x}"
        return "?"


def show(dump, elf, out=sys.stdout):
    p = parse(dump)
    s = p["sections"]
    sym = Symbols(elf)
    w = out.write
    flags = ", ".join(n for bit, n in FLAGS.items() if p["flags"] & bit) or "none"
    w(f"NanoChronometer crash dump — kernel {p['kernel']}, {p['size']} bytes, CRC ok\n")
    w(f"machine {p['machine']:#06x}   flags: {flags}   counter {p['counter']}\n\n")

    w(f"reason:  {s.get(2, b'').decode('utf-8', errors='replace')}\n")
    w(f"driver:  {s.get(3, b'').decode('utf-8', errors='replace')}\n")

    if 1 in s:
        regs = dict(zip(REGISTERS, struct.unpack_from(f"<{len(REGISTERS)}Q", s[1])))
        vector = regs["vector"]
        if vector == SOFTWARE_PANIC:
            what = "software panic (no CPU exception)"
        else:
            what = EXCEPTIONS[vector] if vector < len(EXCEPTIONS) else "reserved"
            what = f"vector {vector}: {what}, error code {regs['error']:#x}"
        w(f"fault:   {what}\n\n")
        rows = [["rip", "cs", "rflags", "rsp", "ss"],
                ["rax", "rbx", "rcx", "rdx"], ["rsi", "rdi", "rbp"],
                ["r8", "r9", "r10", "r11"], ["r12", "r13", "r14", "r15"],
                ["cr0", "cr2", "cr3", "cr4", "efer"]]
        for row in rows:
            w("  " + "  ".join(f"{n.upper():>6}={regs[n]:016x}" for n in row) + "\n")
        w(f"\n  at {sym.name(regs['rip'])}\n" if elf else "")

    if 4 in s:
        trace = struct.unpack_from(f"<{len(s[4]) // 8}Q", s[4])
        w("\nstack trace (RIP, then the frame-pointer chain):\n")
        for i, a in enumerate(trace):
            w(f"  #{i:<2} {a:016x}  {sym.name(a)}\n")
        if len(trace) == 1:
            w("  (no frame-pointer chain: a build without frame pointers, or an RBP\n"
              "   outside the kernel's stacks; see the scan below)\n")
    if s.get(5):
        scan = struct.unpack_from(f"<{len(s[5]) // 8}Q", s[5])
        w("\nstack scan (values on the stack that point into .text, innermost first):\n")
        for a in scan:
            w(f"      {a:016x}  {sym.name(a)}\n")

    if s.get(6):
        memory = s.get(7, b"")
        w("\nmemory:\n")
        for i in range(len(s[6]) // 16):
            address, offset, size = struct.unpack_from("<QII", s[6], i * 16)
            w(f"  {address:016x}  {size} bytes\n")
            chunk = memory[offset:offset + size]
            for row in range(0, min(size, 256), 16):
                line = chunk[row:row + 16]
                w(f"    {address + row:016x}  {line.hex(' ')}\n")
            if size > 256:
                w(f"    ... {size - 256} more bytes in the file\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract", help="cut the last dump out of a serial log")
    ex.add_argument("log")
    ex.add_argument("-o", "--output", default="CRASH.DMP")
    xi = sub.add_parser("extract-image", help="read CRASH.DMP off a disk image or device")
    xi.add_argument("image")
    xi.add_argument("-o", "--output", default="CRASH.DMP")
    sh = sub.add_parser("show", help="print a dump (a .DMP file or a serial log)")
    sh.add_argument("dump")
    sh.add_argument("--elf", help="the kernel ELF, for symbols")
    args = ap.parse_args()

    try:
        if args.command == "extract":
            with open(args.log, "rb") as f:
                dump = extract(f.read().decode("utf-8", errors="replace"))
            if dump is None:
                print(f"{args.log}: no crash dump in it", file=sys.stderr)
                return 1
            parse(dump)
            with open(args.output, "wb") as f:
                f.write(dump)
            print(f"{args.output}: {len(dump)} bytes, CRC ok")
        elif args.command == "extract-image":
            data = extract_image(args.image)
            if data is None:
                print(f"{args.image}: no CRASH.DMP on a FAT16/FAT32 volume", file=sys.stderr)
                return 1
            if data[:4] != b"DUMP":
                print(f"{args.image}: CRASH.DMP holds no dump (nothing has crashed)", file=sys.stderr)
                return 1
            parse(data)
            total = _le(data, 8, 4)
            with open(args.output, "wb") as f:
                f.write(data[:total])
            print(f"{args.output}: {total} bytes, CRC ok")
        else:
            show(load(args.dump), args.elf)
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        return 1
    except DumpError as err:
        print(f"corrupt dump: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
