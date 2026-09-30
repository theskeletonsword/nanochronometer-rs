#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the C headers from the Rust source:
#
#   include/nanochrono.h            the hosted libnanochrono (Linux, macOS,
#                                   Windows, Android), from crates/nanochrono-ffi
#   include/baremetal/nanochrono.h  the bare-metal libnanochrono, from
#                                   crates/nanochrono-baremetal/src/abi.rs
#
# A release ships each one as include/nanochrono.h beside its libraries.
#
# The headers are generated, never edited: the Rust source is the single
# source of truth for each C ABI. Both can be #included from assembly: the
# constants stay plain #defines, and every C-only line — the includes, the
# types, the prototypes — is moved under #ifndef __ASSEMBLER__.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "error: cbindgen not found. Install it with:" >&2
    echo "         cargo install cbindgen --locked" >&2
    exit 1
fi

hosted="${repo_root}/include/nanochrono.h"
baremetal="${repo_root}/include/baremetal/nanochrono.h"
mkdir -p "$(dirname "${hosted}")" "$(dirname "${baremetal}")"

cbindgen \
    --config "${repo_root}/cbindgen.toml" \
    --crate nanochrono-ffi \
    --output "${hosted}" \
    "${repo_root}/crates/nanochrono-ffi"

# One source file, not the crate: abi.rs is the whole bare-metal C ABI, and
# the crate's other public constants are kernel internals.
cbindgen \
    --config "${repo_root}/cbindgen-baremetal.toml" \
    --output "${baremetal}" \
    "${repo_root}/crates/nanochrono-baremetal/src/abi.rs"

# cbindgen writes a header for C. For assembly, split its body at the blank
# lines between items: an item that is only a numeric #define (with its doc
# comment) stays visible, and everything else goes under __ASSEMBLER__.
python3 - "${hosted}" "${baremetal}" <<'PY'
import re
import sys

NUMERIC = re.compile(r"#define\s+\w+\s+([\s()0-9xXa-fA-F+\-~*/%<>&|^]+)$")


def code_lines(item):
    """The item's lines outside comments (cbindgen's doc comments are
    /* ... */ blocks whose inner lines carry no leading '*')."""
    code, in_block = [], False
    for line in item:
        s = line.strip()
        if in_block:
            in_block = "*/" not in s
            continue
        if s.startswith("/*"):
            in_block = "*/" not in s[2:]
            continue
        if not s.startswith("//"):
            code.append(s)
    return code


def asm_safe(item):
    code = code_lines(item)
    return bool(code) and all(NUMERIC.match(line) for line in code)


for path in sys.argv[1:]:
    lines = open(path).read().split("\n")
    guard = next(i for i, l in enumerate(lines) if re.match(r"#define NANOCHRONO_H\b", l))
    end = max(i for i, l in enumerate(lines) if l.startswith("#endif") and "NANOCHRONO_H" in l)
    items, cur = [], []
    for line in lines[guard + 1:end]:
        if line.strip():
            cur.append(line)
        elif cur:
            items.append(cur)
            cur = []
    if cur:
        items.append(cur)
    asm = [item for item in items if asm_safe(item)]
    c_only = [item for item in items if not asm_safe(item)]
    out = lines[:guard + 1] + [""]
    for item in asm:
        out += item + [""]
    out += ["#ifndef __ASSEMBLER__", ""]
    for item in c_only:
        out += item + [""]
    out += ["#endif  /* __ASSEMBLER__ */", ""] + lines[end:]
    open(path, "w").write("\n".join(out))
PY

for header in "${hosted}" "${baremetal}"; do
    echo "wrote ${header#"${repo_root}/"} ($(wc -l < "${header}") lines)"
done
