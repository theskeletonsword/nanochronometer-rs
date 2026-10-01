# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the packaging scripts. A release ships light: each program and
# library keeps its code and its symbol table — nothing is stripped of its
# names — while its debug information moves to a file of its own beside it,
# which the release publishes in a separate -debug.zip:
#
#   ELF, PE      <file>.debug: the DWARF, which GDB and LLDB find through the
#                .gnu_debuglink section left in <file>. On Windows this is
#                what stands for a .pdb: a MinGW build carries DWARF, and a
#                .pdb holds CodeView, which only the MSVC targets produce.
#   Mach-O       <file>.dSYM, which dsymutil writes (packaging/remap-paths.sh).
#   static lib   debug/<libdir>/<name>.a, the archive as built, for linking
#                with debug information; the one in <libdir>/ goes without it.

_debuginfo_tools="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tools" && pwd)"

# The objcopy for every format here: LLVM's reads ELF, PE/COFF and Mach-O for
# any architecture.
debug_objcopy() {
    command -v "${LLVM_OBJCOPY:-llvm-objcopy}" ||
        { echo "error: no llvm-objcopy (set LLVM_OBJCOPY)" >&2; return 1; }
}

# split_debug <file>: moves <file>'s debug information into <file>.debug and
# leaves <file> its code, its symbol table and a .gnu_debuglink naming
# <file>.debug (by file name, so the two may move together anywhere).
split_debug() {
    local f="$1" oc
    [[ -f "${f}" ]] || return 0
    oc="$(debug_objcopy)" || return 1
    "${oc}" --only-keep-debug "${f}" "${f}.debug" &&
        (cd "$(dirname "${f}")" &&
            "${oc}" --strip-debug --add-gnu-debuglink="$(basename "${f}").debug" "$(basename "${f}")")
}

# split_debug_archive <prefix> <libdir> <name>: keeps the archive as built
# under <prefix>/debug/<libdir>/ and takes the debug sections out of the one
# in <prefix>/<libdir>/. llvm-objcopy rewrites an ELF or Mach-O archive in one
# go but cannot read the import members of a Windows one, which
# tools/strip-archive-debug.py handles member by member instead.
split_debug_archive() {
    local prefix="$1" libdir="$2" name="$3" oc
    local a="${prefix}/${libdir}/${name}"
    [[ -f "${a}" ]] || return 0
    oc="$(debug_objcopy)" || return 1
    mkdir -p "${prefix}/debug/${libdir}"
    command cp -f "${a}" "${prefix}/debug/${libdir}/${name}"
    "${oc}" --strip-debug "${a}" 2>/dev/null ||
        LLVM_OBJCOPY="${oc}" python3 "${_debuginfo_tools}/strip-archive-debug.py" "${a}" >/dev/null
}
