# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the packaging scripts: the optimisation level a build is asked
# for with OPT=, mapped onto Rust's opt-level (C code takes OPT as it is):
#
#   OPT      Rust opt-level   for
#   -O0      0                debugging; the debug builds' default
#   -Og      1                debugging what only optimised code shows (Rust
#                             has no -Og; opt-level 1 is its counterpart)
#   -O1      1
#   -O2      2                the release default: what is published
#   -O3      3
#   -Os      "s"              smaller code
#   -Oz      "z"              smallest code
#   -Ofast   3                not recommended: in C it means -ffast-math,
#                             which reassociates floating-point arithmetic
#                             and gives up IEEE 754 (NaN, infinities, signed
#                             zeros, exact rounding). Rust has no fast-math,
#                             so its code builds at -O3 and stays IEEE.
#
# Every level is a supported build, and the code must be correct at all of
# them. Without OPT each build keeps its own default.

# The opt-level for OPT ($1), or a failure naming the allowed values.
rust_opt_level() {
    case "$1" in
        -O0) echo 0 ;;
        -Og | -O1) echo 1 ;;
        -O2) echo 2 ;;
        -O3) echo 3 ;;
        -Os) echo '"s"' ;;
        -Oz) echo '"z"' ;;
        -Ofast)
            echo "note: OPT=-Ofast — Rust has no fast-math, so Rust code builds at -O3 (IEEE 754 kept)" >&2
            echo 3
            ;;
        *)
            echo "error: OPT must be one of -O0 -Og -O1 -O2 -O3 -Os -Oz -Ofast, not '$1'" >&2
            return 1
            ;;
    esac
}

# set_opt_args <cargo profile>: sets OPT_ARGS to the cargo arguments that
# build that profile at $OPT, or to nothing when OPT is unset.
set_opt_args() {
    OPT_ARGS=()
    [[ -n "${OPT:-}" ]] || return 0
    local level
    level="$(rust_opt_level "${OPT}")" || return 1
    OPT_ARGS=(--config "profile.$1.opt-level=${level}")
}
