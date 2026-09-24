# NanoChronometer — notes for Claude

## Licensing

The project is Apache-2.0. **Never copy or adapt Linux (GPLv2) code** — the
licences are incompatible. BSD-licensed code may be adapted; keep its copyright
notice and add it to `NOTICE`. Reference paths on the maintainer's machine are
in `CLAUDE.local.md`.

## Building

- Host workspace: `cargo build --workspace`, `cargo test --workspace`.
- Profiles: `release` is for development (thin LTO, 16 codegen units, fast);
  `dist` is what ships (fat LTO, 1 codegen unit). `bench` inherits `dist`.
  Every packaging script builds `--profile dist`.
- All desktop releases plus the Android APK:
  `packaging/release/build-all.sh [name...]` → `build/<os>-<arch>/`. Run it
  as the toolchains' owner; it builds in `~/.cache/nanochrono` (not in the
  repo) and uses Windows = llvm-mingw (UCRT), macOS = osxcross.
- Bare-metal kernel (`crates/nanochrono-baremetal`, outside the workspace):
  `packaging/baremetal/build.sh [arch]`, `build.sh run <arch>`. Needs nightly
  plus `rust-src`; `RUST_TARGET_PATH` must point at the crate's `targets/`.
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

## Logo and icons

`tools/gen-icons.py` (fontTools, cairosvg, Pillow) regenerates every logo and
icon from `assets/src/stopwatch-artwork.svg` and `assets/font/Nanoplex.ttf`:
`assets/icons/<platform>/`, the Android `res/` (launcher mipmaps and the
header wordmark), the desktop GUI's `assets/nanochronometer_wordmark_dark.png`,
and the bare-metal raw RGBA (`assets/icons/baremetal/*.rgba`, 8-byte
width/height header) that `crates/nanochrono-baremetal/src/logo.rs` embeds —
no image decoder in the kernel. Bare metal uses a black theme: lettering in
white or the logo green, nothing grey.
