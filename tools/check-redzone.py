#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse ring-0 code that keeps data below its stack pointer.

    tools/check-redzone.py FILE...                    # ELF objects, shared objects, the kernel
    tools/check-redzone.py --allow SYMBOL FILE...     # SYMBOL may (the kernel's red-zone probe)

A red zone is memory below the stack pointer that a function uses without
moving the pointer: 128 bytes on x86-64, 288 on 64-bit PowerPC (ELFv2). User
code may have one — the kernel never writes below a ring-3 stack pointer
(docs/NCCALL.md). Ring-0 code may not: an exception or interrupt taken in
ring 0 can push its frame onto the very stack the function is using. The
build asks the compiler not to (-mno-red-zone, -C no-redzone=yes) — but
clang's driver silently drops -mno-red-zone on PowerPC and GCC has no such
switch there, so asking is not proof. This is: it disassembles every
function and reports each instruction that addresses memory below the stack
pointer at that point.

What counts, per architecture (llvm-objdump's syntax):

  x86-64, i386   any operand -N(%rsp) / -N(%esp); and an -N(%rbp)/-N(%ebp)
                 operand that lies below the stack pointer the function has
                 set up so far (frame-pointer code addresses its red zone
                 through RBP). Operands with an index register are not
                 judged: their address depends on the index
  AArch64, ARM   [sp, #-N] without writeback ("!", which allocates)
  PowerPC        any -N(1) / -N(r1) operand but on stwu/stdu, which allocate;
                 on 64-bit PowerPC only beyond the 288-byte ELFv2 protected
                 zone, which the kernel's interrupt entry steps over
  RISC-V         any -N(sp) operand

Exit status 0 when nothing is found, 1 when something is, 2 on bad input.
Uses llvm-objdump from PATH, or $LLVM_OBJDUMP.
"""
import os
import re
import shutil
import struct
import subprocess
import sys

EM = {3: "i386", 20: "ppc", 21: "ppc64", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}


def machine(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(20)
    if head[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    endian = "<" if head[5] == 1 else ">"
    (em,) = struct.unpack(endian + "H", head[18:20])
    if em not in EM:
        raise ValueError(f"unsupported ELF machine {em}")
    return EM[em]


def objdump() -> str:
    tool = os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump")
    if not tool:
        raise SystemExit("check-redzone: llvm-objdump not found (set LLVM_OBJDUMP)")
    return tool


FUNC = re.compile(r"^(?:[0-9a-f]+ )?<([^>]+)>:$")
INSN = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
NUM = r"(?:0x[0-9a-f]+|[0-9]+)"


def num(text: str) -> int:
    return int(text, 16) if text.startswith("0x") else int(text)


def functions(path: str):
    """Yields (name, [(address, instruction text), ...]) per symbol."""
    out = subprocess.run([objdump(), "-d", "--no-show-raw-insn", path], capture_output=True, text=True)
    if out.returncode != 0:
        raise ValueError(out.stderr.strip() or "llvm-objdump failed")
    name, body = None, []
    for line in out.stdout.splitlines():
        m = FUNC.match(line)
        if m:
            # Mapping and local labels ($x, $d, .Ltmp) continue a function.
            if m.group(1).startswith(("$", ".L")):
                continue
            if name is not None:
                yield name, body
            name, body = m.group(1), []
            continue
        m = INSN.match(line)
        if m and name is not None:
            # One space between fields, whatever objdump used (it tabs).
            body.append((int(m.group(1), 16), " ".join(m.group(2).split("#")[0].split())))
    if name is not None:
        yield name, body


# --- x86 -------------------------------------------------------------------

def x86_findings(body, bits: int):
    """-N(%rsp) anywhere; and -N(%rbp) below the stack pointer, tracking how
    deep the function has moved the stack pointer (`depth`, bytes below its
    entry value) and where it set the frame pointer (`fp_depth`). An access
    D(%rbp) is at entry - fp_depth + D, below the stack pointer (entry -
    depth) exactly when fp_depth - D > depth. After a ret or an
    unconditional jmp the depth goes back to the body's (the one the first
    branch saw): the usual shape of a prologue, a body, and epilogues."""
    sp, fp = ("%rsp", "%rbp") if bits == 64 else ("%esp", "%ebp")
    word = 8 if bits == 64 else 4
    # Base and displacement only: with an index register (-5(%rsp,%rdx))
    # the address depends on the index and is not judged.
    below_sp = re.compile(r"-(" + NUM + r")\(" + re.escape(sp) + r"\)")
    via_fp = re.compile(r"(-?" + NUM + r")\(" + re.escape(fp) + r"\)")
    imm = re.compile(r"\$(" + NUM + r")")
    found = []
    depth, fp_depth, body_depth = 0, None, None
    for i, (addr, text) in enumerate(body):
        op = text.split()[0] if text else ""
        if below_sp.search(text):
            found.append((addr, text))
            continue
        if fp_depth is not None and not op.startswith("lea"):
            m = via_fp.search(text)
            if m:
                d = m.group(1)
                offset = -num(d[1:]) if d.startswith("-") else num(d)
                if fp_depth - offset > depth:
                    found.append((addr, text))
        if op.startswith("push"):
            depth += word
        elif op.startswith("pop"):
            depth -= word
        elif re.match(r"sub[lqw]?$", op) and text.endswith(sp) and imm.search(text):
            depth += num(imm.search(text).group(1))
        elif re.match(r"add[lqw]?$", op) and text.endswith(sp) and imm.search(text):
            depth -= num(imm.search(text).group(1))
        elif re.match(r"mov[lq]?$", op) and text.replace(" ", "") == f"{op}{sp},{fp}":
            fp_depth = depth
        elif op.startswith("call") and i + 1 < len(body) and re.match(
            r"call[lq]? (0x)?" + format(body[i + 1][0], "x") + r"\b", text
        ):
            # i386 PIC: `call 1f; 1: pop %ebx` pushes a return address the
            # pop takes back. Count the push; the pop is counted as one.
            depth += word
        elif op.startswith("j") or op.startswith("call") or op.startswith("ret") or op == "leave":
            if body_depth is None:
                body_depth = depth
            if op.startswith("ret") or op in ("jmp", "jmpq"):
                depth = body_depth
    return found


# --- the rest ----------------------------------------------------------------

def arm_findings(body):
    pat = re.compile(r"\[sp, #-(" + NUM + r")\](?!!)")
    return [(a, t) for a, t in body if pat.search(t)]


def ppc_findings(body, tolerated: int):
    """Below r1. On 64-bit PowerPC the first `tolerated` (288) bytes are
    ELFv2's protected zone: LLVM saves callee-saved registers there before
    its stdu even in a function marked noredzone, so no compiler flag can
    keep ring-0 code out of it. It is safe because the ABI requires every
    interrupt handler to preserve 512 bytes below r1 and nckernel's entry
    skips them (docs/NCCALL.md §2); only what lies deeper is refused."""
    pat = re.compile(r"-(" + NUM + r")\((?:r)?1\)")
    allocating = ("stwu", "stdu", "stwux", "stdux")
    found = []
    for a, t in body:
        m = pat.search(t)
        if m and t.split()[0] not in allocating and num(m.group(1)) > tolerated:
            found.append((a, t))
    return found


def riscv_findings(body):
    pat = re.compile(r"-(" + NUM + r")\(sp\)")
    return [(a, t) for a, t in body if pat.search(t)]


def check(path: str, allow=()) -> int:
    arch = machine(path)
    total = 0
    for name, body in functions(path):
        if name in allow:
            continue
        if arch == "x86_64":
            found = x86_findings(body, 64)
        elif arch == "i386":
            found = x86_findings(body, 32)
        elif arch in ("aarch64", "arm"):
            found = arm_findings(body)
        elif arch == "ppc":
            found = ppc_findings(body, 0)
        elif arch == "ppc64":
            found = ppc_findings(body, 288)
        else:
            found = riscv_findings(body)
        for addr, text in found:
            print(f"{path}: {arch}: {name}+{addr:#x}: below the stack pointer: {text}")
        total += len(found)
    return total


def main(argv) -> int:
    allow = []
    while len(argv) >= 2 and argv[0] == "--allow":
        allow.append(argv[1])
        argv = argv[2:]
    if not argv:
        print(__doc__.strip().splitlines()[0])
        print("usage: check-redzone.py [--allow SYMBOL]... FILE...")
        return 2
    bad = 0
    for path in argv:
        try:
            n = check(path, allow)
        except (OSError, ValueError) as e:
            print(f"{path}: {e}", file=sys.stderr)
            return 2
        if n:
            print(f"{path}: {n} access(es) below the stack pointer: not ring-0 code")
            bad += 1
        else:
            print(f"{path}: no access below the stack pointer")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
