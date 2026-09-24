#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Produces a static library whose only global symbols are the nc_* C API.
#
# `cargo build -p nanochrono-ffi` emits libnanochrono.a with the whole Rust
# runtime (core, std, compiler_builtins) bundled in, and every one of those
# objects leaves its symbols global: ~3700 of them next to the 125 nc_* ones.
# They are harmless to link against, but they clutter `nm` and can clash with
# another Rust staticlib in the same link. This merges the archive into one
# object, demotes everything that is not part of the API to local, then strips
# the locals nothing refers to.
#
# GNU ld/objcopy, so ELF targets only (Linux, Android). The shared library
# needs none of this: it already exports nc_* and nothing else.
#
# Usage: tools/slim-staticlib.sh [input.a] [output.a]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
in="${1:-${repo_root}/target/release/libnanochrono.a}"
out="${2:-${repo_root}/target/release/libnanochrono_slim.a}"

[[ -f "${in}" ]] || { echo "error: ${in} not found; run cargo build --release -p nanochrono-ffi" >&2; exit 1; }
for tool in ld objcopy ar nm; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "error: ${tool} not found" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

nm -g --defined-only "${in}" | awk '$2 == "T" && $3 ~ /^nc_/ { print $3 }' | sort -u > "${work}/keep.txt"
[[ -s "${work}/keep.txt" ]] || { echo "error: no nc_* symbols in ${in}" >&2; exit 1; }

ld -r --whole-archive "${in}" -o "${work}/merged.o"
objcopy --keep-global-symbols="${work}/keep.txt" "${work}/merged.o" "${work}/localised.o"
# Demoting leaves thousands of local symbols (GCC_except_table*, .LCPI*, ...).
# Drop every one that no relocation refers to.
objcopy --strip-unneeded "${work}/localised.o" "${work}/slim.o"

rm -f "${out}"
ar rcs "${out}" "${work}/slim.o"

echo "wrote ${out}: $(wc -l < "${work}/keep.txt") exported symbols"
