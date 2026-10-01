# NanoChronometer — notes for Claude

## Licensing

The project is Apache-2.0. **Never copy or adapt Linux (GPLv2) code** — the
licences are incompatible. BSD-licensed code may be adapted; keep its copyright
notice and add it to `NOTICE`. Reference paths on the maintainer's machine are
in `CLAUDE.local.md`.

## Building

- Host workspace: `cargo build --workspace`, `cargo test --workspace`.
- Profiles: `release` is for development (thin LTO, 16 codegen units, fast);
  `dist` is what ships (fat LTO, 1 codegen unit, **-O2** — the published
  level). `bench` inherits `dist`. `debug-og` is the -Og build (dev plus
  opt-level 1; Rust has no -Og). Every packaging script builds `--profile
  dist` and takes `OPT=-O0|-Og|-O1|-O2|-O3|-Os|-Oz|-Ofast`
  (`packaging/opt-level.sh`); the code must be correct at every level.
- **Never strip symbols** from anything that ships (a stripped binary or
  kernel looks like it hides something): `dist` and the bare-metal release
  set `strip = "none"`. Debug information is built (full for the libraries
  and the bare-metal crate, line tables for the programs) and moved into
  files of its own — `<file>.debug` + `.gnu_debuglink` for ELF and PE, the
  `.dSYM` on macOS, `debug/<libdir>/libnanochrono.a` for static libraries —
  by `packaging/debuginfo.sh` (`tools/strip-archive-debug.py` for COFF
  archives). On Windows that `.debug` stands for a `.pdb` (MinGW = DWARF).
  Build-machine paths are remapped instead of stripped
  (`packaging/remap-paths.sh`: rustc, C, the macOS debug map), and the
  Windows link uses a copy of llvm-mingw whose runtime (mingw-w64 CRT,
  libunwind) `build-all.sh` rebuilt from `~/llvm-mingw` with the paths mapped.
- Release assets: `packaging/release/package.sh` → `build/release-<version>/`:
  one `.zip` per OS and arch, the APK and the ISOs, `SHA256SUMS` — only those
  go on the GitHub release. The `-debug.zip` files land in
  `build/release-<version>/debug/` and are **not published** (the
  maintainer's call). Each asset carries `LICENSE`, `NOTICE` and
  `THIRD-PARTY-LICENSES.txt` (`tools/third-party-licenses.py`).
- Debug before release, at **both -O0 and -Og** (the latter catches what only
  optimised code shows): `cargo test` and `cargo test --profile debug-og`;
  bare metal `build.sh debug` and `build.sh debug-og`; C SDK `make MODE=debug`
  and `MODE=debug-og`. Then build the release and test that too.
- Every release — desktop, Android (libraries, CLI, APK) and bare metal:
  `packaging/release/build-all.sh [name...]` → `build/` (nothing goes to
  `dist/` any more). Each platform is an install prefix: `bin/`, `lib64/` or
  `lib/`, and `include/nanochrono.h` beside it. Run it as the toolchains'
  owner; it builds in `~/.cache/nanochrono` (not in the repo) and uses
  Windows = llvm-mingw (UCRT), macOS = osxcross. `tools/gen-header.sh`
  (cbindgen) generates both headers: hosted from `nanochrono-ffi`, bare metal
  from `crates/nanochrono-baremetal/src/abi.rs` (the whole bare-metal C ABI).
- Bare-metal kernel (`crates/nanochrono-baremetal`, outside the workspace):
  `packaging/baremetal/build.sh [arch]`, `build.sh run <arch>`. Needs nightly
  plus `rust-src`; `RUST_TARGET_PATH` must point at the crate's `targets/`.
  A release also builds, per architecture, `libnanochrono.so`: the whole
  static library recompiled PIC on the arch's `targets/*-dylib.json` spec and
  linked `--whole-archive -Bsymbolic` — not a trimmed cdylib. Hand-written
  asm in the library must stay position independent (PC- or TOC-relative),
  or that link fails.
  Targets: x86_64, i386 (i686-nanochrono-none), aarch64, arm32
  (armv7a-none-eabihf), ppc64, ppc64le, ppc, riscv64, riscv32 — all with the
  same GUI (`gui_frame.rs`); `x86_any` (from build.rs) marks code shared by
  x86 and x86_64.

## Boot-testing under QEMU

Use KVM only when the guest ISA matches the **host's** ISA (`uname -m`) and
`/dev/kvm` is usable; use TCG for every other guest. Never hardcode an
architecture as "the KVM one" — `build.sh`'s `accel_for` detects the host.
The POWER guests (`powernv`, `ppce500`) stay on TCG even on a POWER host:
QEMU has no KVM path for those machines.

A kernel that reaches `selftest complete; halting` on the serial log has passed
its boot self-test; it then idles until the QEMU timeout, which is expected.

Faults (x86_64): `crashtest=<de|pf|gp|ud|so|df|panic>` on the kernel command
line raises one on purpose; passing means a crash dump on COM1 and the stop
screen, with QEMU still running — QEMU exiting under `-no-reboot` is a triple
fault. `build.sh debug` builds `-O0 -g` with frame pointers into
`build/baremetal-debug/` (`debug-og`: -Og into `build/baremetal-debug-og/`);
`build.sh gdb x86_64 [crashtest=…]` boots it stopped for
`gdb -x packaging/baremetal/gdb/x86_64.gdb` (`DEBUG_OPT=Og` for the -Og
kernel, which GDB then loads via `NC_GDB_ELF`, as the script prints). `tools/nanodump.py` reads the
dumps. See `docs/CRASH_DUMPS.md`. A PC with no 8042 is `-machine q35,i8042=off`.

## Logo and icons

`tools/gen-icons.py` (fontTools, cairosvg, Pillow) regenerates every logo and
icon from `assets/src/stopwatch-artwork.svg` and `assets/font/Nanoplex.ttf`:
`assets/icons/<platform>/`, the Android `res/` (launcher mipmaps and the
header wordmark) and the desktop GUI's `assets/nanochronometer_wordmark_dark.png`.

Bare metal embeds `assets/nanochronometer_logo_dark.png` itself:
`crates/nanochrono-baremetal/build.rs` decodes and scales it on the host into
raw RGBA in `OUT_DIR`, and `src/logo.rs` includes those bytes — no image
decoder in the kernel.

The bare-metal GUI follows the desktop GUI's design (`nanochrono-gui`):
`Palette::APP` in `draw.rs` is `style.rs` colour for colour, tabs are
desktop tab buttons, the readout sits in an inset box, and the BENCH tab is
the desktop benchmark panel (modes, feature rows, log) driven by
`bench::run_one`. Keep the two in step when either changes.
