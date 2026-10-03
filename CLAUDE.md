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
  one `.zip` per OS holding all its architectures (linux, windows, macos,
  android, baremetal — the ISOs inside it, in `iso/`: x86_64, i386, aarch64,
  ppc-openfirmware), the APK, `SHA256SUMS`
  — only those go on
  the GitHub release. The `-debug.zip` files land in
  `build/release-<version>/debug/` and are **not published** (the
  maintainer's call). Each asset carries `LICENSE`, `NOTICE` and
  `THIRD-PARTY-LICENSES.txt` (`tools/third-party-licenses.py`).
  The aarch64 ISO needs the arm64-efi GRUB modules: `dnf download
  grub2-efi-aa64-modules` unpacked (`rpm2cpio | cpio -idm`) in
  `~/.cache/nanochrono/grub` is enough; build.sh looks there.
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
- Packages (`.ncpkg`, docs/NCPKG.md): the format, manifest, database and
  transaction engine are `nanochrono-core::ncpkg` (`no_std`; the manager
  needs the `alloc` feature, which `std` implies and the kernel does not
  enable). The host tool is `tools/ncpkg` (outside the workspace, like
  `tools/ncplu-sign`): `cd tools/ncpkg && cargo test`. Modules are
  `.ncapp`/`.ncdri`/`.ncdyn`/`.ncplu`, packed by `tools/ncplu.py`.
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

Sessions (`mode=`): `gui` (the default; `desktop` is its old name) and `cli`
(plain text, always — its shell refuses `color on`) are the boot menu's. The
classic full-screen instrument (`mode=classic`) is off the menu but kept: it
holds the BENCH tab and it is the test harness — `crashtest=` and `plugin=`
are served there, so the crash-test entries and `build.sh gdb|boot` add
`mode=classic` (a later `mode=` overrides an earlier one).

Faults (x86_64): `crashtest=<de|pf|gp|ud|so|df|panic>` on the kernel command
line raises one on purpose; passing means a crash dump on COM1 and the stop
screen, with QEMU still running — QEMU exiting under `-no-reboot` is a triple
fault. `build.sh debug` builds `-O0 -g` with frame pointers into
`build/baremetal-debug/` (`debug-og`: -Og into `build/baremetal-debug-og/`);
`build.sh gdb x86_64 [crashtest=…]` boots it stopped for
`gdb -x packaging/baremetal/gdb/x86_64.gdb` (`DEBUG_OPT=Og` for the -Og
kernel, which GDB then loads via `NC_GDB_ELF`, as the script prints). `tools/nanodump.py` reads the
dumps. See `docs/CRASH_DUMPS.md`. A PC with no 8042 is `-machine q35,i8042=off`.

## Ring 3, ring 0 and the red zone

`docs/NCCALL.md` (the system-call boundary), `docs/NCDRI.md` (the driver
ABI), `docs/NCTOOLCHAIN.md` (toolchain, C library, OpenSSL/AWS-LC). The
rules the code relies on:

- The red zone is allowed in ring-3 artifacts (`.ncapp`, `.ncplu`, `.ncdyn`,
  `.ncar`; Rust targets in `sdk/targets/`, `disable-redzone: false`) and
  forbidden in `.ncdri` and the kernel. The x86-64 `SYSCALL` entry
  (`ring3.rs`) must not push before it has left the user stack; the selftest
  proves it (`red zone: ok`). `kstack.rs` puts #DF, #PF, NMI, #MC and #DB on
  IST stacks and checks the plan at boot.
- On PowerPC clang ignores `-mno-red-zone` (argument unused): use
  `-Xclang -disable-red-zone`. Even then LLVM saves callee-saved registers
  below r1 within ELFv2's 288 bytes, so a PPC64 kernel entry skips 512 bytes.
- `tools/check-redzone.py FILE…` reads the machine code (via
  `llvm-objdump`; `LLVM_OBJDUMP` overrides) and fails on any access below
  the stack pointer; `make -C sdk drivers` runs it on every `.ncdri` object
  for all nine ISAs, at the `MODE`'s level.
- `crates/nanochrono-sys` (workspace member, `no_std`) is the ring-3 side:
  `nccall!`, the POSIX-class calls with FreeBSD's numbers and errno,
  `NcAlloc`; `cargo test -p nanochrono-sys --all-features`. A ring-3 Rust
  module builds for `sdk/targets/<arch>-unknown-nanochronometer.json` with
  `-Z build-std` and `RUSTFLAGS=-Zunstable-options` (see
  `crates/nanochrono-plugins/ncsys-demo/.cargo/config.toml`);
  `build.sh boot x86_64 plugin=ncsys-demo` runs its checks at boot.
- One dispatcher for every ISA: `nanochrono-core::nccall` (what a call
  means, the per-ISA register maps; `cargo test -p nanochrono-core --lib
  nccall`) and the kernel's `src/nccall/` (the frames each trap entry saves,
  the glue, the boot proof). A new call is added there once, never per
  architecture; the selftest's `nccall HAL : ok` must hold on all nine.
  RISC-V proves it from U-mode (`nc_rv_user_run`, `satp` Bare for the run);
  QEMU's RV32 OpenSBI is not in every distribution — build one
  (`make LLVM=1 PLATFORM=generic PLATFORM_RISCV_XLEN=32`) and pass `-bios`.
- Every inline `nccall` asm block is `options(nostack)`, so the compiler
  keeps using the red zone around it, except i386's, which pushes its
  arguments onto the stack.

## Logo and icons

`tools/gen-icons.py` (fontTools, cairosvg, Pillow) regenerates every logo and
icon from `assets/src/stopwatch-artwork.svg` and `assets/font/Nanoplex.ttf`:
`assets/icons/<platform>/`, the Android `res/` (launcher mipmaps and the
header wordmark) and the desktop GUI's `assets/nanochronometer_wordmark_dark.png`.

Bare metal embeds `assets/nanochronometer_logo_dark.png` itself:
`crates/nanochrono-baremetal/build.rs` decodes and scales it on the host into
raw RGBA in `OUT_DIR`, and `src/logo.rs` includes those bytes — no image
decoder in the kernel.

The bare-metal classic interface (`gui_frame.rs`) follows the desktop GUI's design (`nanochrono-gui`):
`Palette::APP` in `draw.rs` is `style.rs` colour for colour, tabs are
desktop tab buttons, the readout sits in an inset box, and the BENCH tab is
the desktop benchmark panel (modes, feature rows, log) driven by
`bench::run_one`. Keep the two in step when either changes.
