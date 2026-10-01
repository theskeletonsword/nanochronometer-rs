#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Removes the debug sections from every object in a COFF static library,
keeping everything else as it was: member order, repeated names, and the
import members.

`llvm-objcopy --strip-debug` does this for an ELF or Mach-O archive in one go,
but not for a Windows one: a Rust static library for Windows also holds short
import members (one per imported function, each named after its DLL), which
llvm-objcopy cannot read. Here each COFF object is stripped on its own, every
other member is kept byte for byte, and llvm-ar writes the archive back with a
new symbol index.

    tools/strip-archive-debug.py lib/libnanochrono.a

LLVM_OBJCOPY and LLVM_AR name the tools; the default is the ones on PATH.
"""

import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

# IMAGE_FILE_MACHINE_* for the architectures a COFF object here can be for.
COFF_MACHINES = {0x014C, 0x8664, 0xAA64, 0x01C4}  # i386, AMD64, ARM64, ARMNT


def members(data):
    """Yields (name, body) for each member, the symbol index left out."""
    if data[:8] != b"!<arch>\n":
        sys.exit("not an ar archive")
    off, longnames = 8, b""
    while off < len(data):
        hdr = data[off : off + 60]
        if len(hdr) < 60 or hdr[58:60] != b"`\n":
            sys.exit(f"bad member header at offset {off}")
        name = hdr[:16].decode("ascii").rstrip()
        size = int(hdr[48:58].decode("ascii"))
        body = data[off + 60 : off + 60 + size]
        off += 60 + size + (size & 1)
        if name == "//":
            longnames = body
        elif name in ("/", "/SYM64/"):
            pass  # the symbol index: llvm-ar writes a new one
        elif name.startswith("#1/"):
            sys.exit("a BSD archive: llvm-objcopy --strip-debug handles those")
        elif name.startswith("/") and name[1:].isdigit():
            # GNU ends a long name with "/\n"; Microsoft's form with a NUL.
            start = int(name[1:])
            ends = [i for i in (longnames.find(b"/\n", start), longnames.find(b"\0", start)) if i >= 0]
            yield longnames[start : min(ends)].decode(), body
        else:
            yield name[:-1] if name.endswith("/") else name, body


def is_object(body):
    """A COFF object (also a /bigobj one), not a short import member."""
    if len(body) < 20:
        return False
    sig1, sig2, version = struct.unpack_from("<HHH", body)
    if sig1 == 0 and sig2 == 0xFFFF:
        return version >= 1  # 0 is a short import; 1 and 2 are anonymous objects
    return sig1 in COFF_MACHINES


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: tools/strip-archive-debug.py <archive.a>")
    archive = sys.argv[1]
    objcopy = os.environ.get("LLVM_OBJCOPY", "llvm-objcopy")
    ar = os.environ.get("LLVM_AR", "llvm-ar")
    with open(archive, "rb") as f:
        data = f.read()
    with tempfile.TemporaryDirectory(prefix="strip-archive-") as tmp:
        paths, stripped = [], 0
        for i, (name, body) in enumerate(members(data)):
            # One directory per member, so repeated names stay apart and
            # llvm-ar still records each under its own name.
            d = os.path.join(tmp, f"{i:06d}")
            os.mkdir(d)
            path = os.path.join(d, name)
            with open(path, "wb") as f:
                f.write(body)
            if is_object(body):
                subprocess.run([objcopy, "--strip-debug", path], check=True)
                stripped += 1
            paths.append(path)
        rsp = os.path.join(tmp, "members.rsp")
        with open(rsp, "w") as f:
            f.write("\n".join(shlex.quote(p) for p in paths) + "\n")
        out = os.path.join(tmp, "out.a")
        # q: append in order, never replacing a member of the same name.
        subprocess.run([ar, "qcD", "--format=gnu", out, "@" + rsp], check=True)
        with open(out, "rb") as f:
            count = sum(1 for _ in members(f.read()))
        if count != len(paths):
            sys.exit(f"{archive}: rewrote {count} members of {len(paths)}")
        shutil.copyfile(out, archive)
    print(f"{archive}: {stripped} objects without debug sections, {len(paths) - stripped} other members kept")


if __name__ == "__main__":
    main()
