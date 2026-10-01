# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the packaging scripts: rustc and C compiler flags that replace the build
# machine's directories in what a release carries — panic messages, debug
# info — with fixed names, so a binary names no home directory and comes out
# the same wherever it is built:
#
#   the repository                /nanochronometer
#   $CARGO_HOME/registry/src      /cargo/registry/src
#   $CARGO_HOME/git/checkouts     /cargo/git/checkouts
#   $RUSTUP_HOME                  /rustup   (std built from rust-src)
#   ~/.cache/nanochrono           /build    (the release build trees, where
#                                            generated code is compiled from)
#   anything else under $HOME     ~         (a cross toolchain's headers)
#
# Release builds only: a debug build keeps the real paths, for GDB to find the
# sources.

# The prefixes to replace, one tab-separated "from to" pair per line.
remap_pairs() {
    local repo="$1"
    local cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
    local rustup_home="${RUSTUP_HOME:-${HOME}/.rustup}"
    local cache="${NANOCHRONO_CACHE:-${HOME}/.cache/nanochrono}"
    # The catch-all comes first: rustc and the C compilers apply the *last*
    # prefix that matches, so the names below win and $HOME only takes what
    # they leave — in practice the include directories of a cross toolchain
    # kept under $HOME, which the C debug info names.
    if [[ -n "${HOME:-}" && "${HOME}" != / ]]; then
        printf '%s\t%s\n' "${HOME%/}" '~'
    fi
    printf '%s\t%s\n' \
        "${cargo_home}/registry/src" /cargo/registry/src \
        "${cargo_home}/git/checkouts" /cargo/git/checkouts \
        "${rustup_home}" /rustup \
        "${cache}" /build \
        "${repo}" /nanochronometer
}

# The flags as one space-separated string, for RUSTFLAGS and
# CARGO_TARGET_<triple>_RUSTFLAGS. Those are split on whitespace, so a path
# with a space in it cannot be remapped this way: refuse rather than build a
# release that leaks it.
remap_rustflags() {
    local from to flags=""
    while IFS=$'\t' read -r from to; do
        if [[ "${from}" == *[[:space:]]* ]]; then
            echo "error: cannot remap a path with whitespace: ${from}" >&2
            return 1
        fi
        flags+="--remap-path-prefix=${from}=${to} "
    done < <(remap_pairs "$1")
    echo "${flags% }"
}

# The C compiler's equivalent, for the C that `cc`-crate dependencies (ring,
# and the crypto backends) build: `-ffile-prefix-map` rewrites both the debug
# info and `__FILE__`, so the archived C objects name no build-machine path —
# without dropping the debug symbols, which are kept on purpose. Appended to a
# target's CFLAGS, so a sysroot flag already there survives.
remap_cflags() {
    local from to flags=""
    while IFS=$'\t' read -r from to; do
        flags+="-ffile-prefix-map=${from}=${to} "
    done < <(remap_pairs "$1")
    echo "${flags% }"
}

# The same flags as a TOML array, for `cargo --config 'target.<t>.rustflags=…'`,
# which appends to the rustflags a .cargo/config.toml already sets.
remap_toml_array() {
    local from to items=""
    while IFS=$'\t' read -r from to; do
        items+="\"--remap-path-prefix=${from}=${to}\","
    done < <(remap_pairs "$1")
    echo "[${items%,}]"
}

# macOS keeps a binary's debug information out of it: the binary carries a
# debug map naming the object files it was linked from, and dsymutil gathers
# their DWARF into a .dSYM bundle, which ships beside it. These rustflags have
# ld64 write that map relative to $HOME (-oso_prefix), so it names no path of
# this machine.
remap_macos_rustflags() {
    echo "-C link-arg=-Wl,-oso_prefix,${HOME%/}/"
}

# remap_dsymutil <dir> [toolchain bin dir]: writes <dir>/dsymutil, the one
# rustc runs for -C split-debuginfo=packed — the real dsymutil (or the
# toolchain's <triple>-dsymutil), run from $HOME with the paths under it made
# relative: it then finds the objects the debug map names, and the .dSYM
# records no path of this machine (dsymutil keeps the binary's own path in
# it). Put <dir> first on PATH.
remap_dsymutil() {
    local dir="$1" tc="${2:-}" real home="${HOME%/}"
    real="$(command -v dsymutil || ls "${tc}"/*-apple-darwin*-dsymutil 2>/dev/null | head -1)"
    [[ -n "${real}" ]] || return 1
    mkdir -p "${dir}"
    {
        echo '#!/usr/bin/env bash'
        echo '# Written by packaging/remap-paths.sh (remap_dsymutil).'
        printf 'cd %q || exit 1\n' "${home}"
        echo 'args=()'
        printf 'for a in "$@"; do args+=("${a#%q/}"); done\n' "${home}"
        printf 'exec %q "${args[@]}"\n' "${real}"
    } > "${dir}/dsymutil"
    chmod +x "${dir}/dsymutil"
}
