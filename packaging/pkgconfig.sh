# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the packaging scripts: a pkg-config file beside each set of
# libraries, so a C program finds the header and links the library — the
# shared one by default, or with `pkg-config --static --libs nanochrono` the
# static one together with the system libraries a Rust static library needs.

# The system libraries a static libnanochrono needs, as rustc reported them
# (`--print native-static-libs`) in the build log $1. Cargo replays the note
# for a build that was already up to date.
native_libs() {
    grep -o 'native-static-libs: .*' "$1" 2>/dev/null | tail -1 | sed 's/^native-static-libs: //'
}

# write_pc <prefix dir> <libdir name> <Libs.private> <version>: the file, at
# <prefix>/<libdir>/pkgconfig/nanochrono.pc, relocatable through
# ${pcfiledir} so it works wherever the directory is unpacked.
write_pc() {
    local dest="$1" libdir="$2" private="$3" version="$4"
    mkdir -p "${dest}/${libdir}/pkgconfig"
    cat > "${dest}/${libdir}/pkgconfig/nanochrono.pc" <<PC
prefix=\${pcfiledir}/../..
libdir=\${prefix}/${libdir}
includedir=\${prefix}/include

Name: nanochrono
Description: NanoChronometer C ABI
Version: ${version}
Cflags: -I\${includedir}
Libs: -L\${libdir} -lnanochrono
Libs.private: ${private}
PC
}
