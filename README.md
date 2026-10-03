<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/nanochronometer_logo_dark.svg">
  <img alt="NanoChronometer" src="./assets/nanochronometer_logo.svg">
</picture>


Nanosecond-resolution stopwatch, precision clock and ISA microbenchmark
toolkit, built directly on the architectural counters — `RDTSC`/`RDTSCP` on
x86, `CNTVCT_EL0` on AArch64, the time base on PowerPC, `rdtime` on RISC-V —
with the calibration, dispatch and drift tracking that make those counters
trustworthy. And, around that instrument, a small operating system of its own.

```
00:00:12:347:891:042
hh:mm:ss:mmm:uuu:nnn
```

Version 4.0. One Rust codebase, three ways to run it:

| | What | Where |
|---|---|---|
| **Hosted** | the library (C ABI, `include/nanochrono.h`), the `nanochrono` CLI, the desktop GUI (`iced`), the Android app, language wrappers | Linux, Windows, macOS, Android |
| **Bare metal** | a freestanding kernel booted straight from GRUB, UEFI, OpenSBI or Open Firmware: the **NanoChronometer GUI** (the default session) or the **NanoChronometer CLI** (plain text), the instrument, apps and drivers | nine ISAs: x86-64, i386, AArch64, ARM32, PPC64, PPC64LE, PPC, RISC-V 64 and 32 |
| **Optional ring 0 modules** | `nanochrono.ko` and `nanochrono.sys`, for counters a user process cannot reach | Linux, Windows |

### The bare-metal system today

| Piece | State | Documentation |
|---|---|---|
| Boot on nine ISAs, with a self-test on every boot | done | [docs/SYSTEM.md](docs/SYSTEM.md) |
| Sessions: NanoChronometer GUI (windows, taskbar, apps) and CLI (Unix-like shell) | done | [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md) §1 |
| `nccall`, one system call for every ISA and language (C, C++, assembly, Rust), with one dispatcher behind every trap | done, proven at boot on all nine | [docs/NCCALL.md](docs/NCCALL.md) |
| Ring 3 for apps, with the red zone kept intact across the boundary | done on x86-64 | [docs/NCCALL.md](docs/NCCALL.md) §3 |
| Apps and packages (`.ncapp`, `.ncpkg`), signed ML-DSA-87 + P-521 | done | [docs/NCPKG.md](docs/NCPKG.md) |
| NCFS, the copy-on-write filesystem, and the sealed `ncinitramdisk` | done | [docs/NCFS.md](docs/NCFS.md) |
| Drivers as modules (`.ncdri`): a stable ABI with no kernel headers, loaded at boot behind a ring-0 trust gate | done on x86-64 | [docs/NCDRI.md](docs/NCDRI.md) |
| Display: the firmware's framebuffer on any connector; the monitor's native mode from its EDID through a display driver; 4K composited | done (QEMU/Bochs VGA driver) | [docs/BAREMETAL_DRIVERS.md](docs/BAREMETAL_DRIVERS.md) |
| Keyboards and pointers: PS/2, USB (xHCI), I2C-HID touchpads | done | [docs/BAREMETAL_DRIVERS.md](docs/BAREMETAL_DRIVERS.md) |
| Crash dumps to serial and to the boot stick | done | [docs/CRASH_DUMPS.md](docs/CRASH_DUMPS.md) |
| Toolchain, C library, OpenSSL and AWS-LC | specified | [docs/NCTOOLCHAIN.md](docs/NCTOOLCHAIN.md) |
| Networking, the hypervisor, users, the installer | planned | [docs/SYSTEM.md](docs/SYSTEM.md) |

What it is built from: FreeBSD, OpenBSD and NetBSD where the problem has
already been solved well — register conventions, driver models, the
system-call boundary — with their licences kept and every file named in
[`NOTICE`](NOTICE). Never Linux: it is GPLv2, and this project is Apache-2.0.

Found a security problem? See [`SECURITY.md`](SECURITY.md).

---

## From 2.x to the Rust codebase

The 3.0 rewrite replaced the 2.x C/assembler codebase; the C ABI was
preserved, so the existing language wrappers keep working.

| Area | 2.x | 3.0 and later |
|---|---|---|
| Language | C99 + NASM + GNU as | Rust, one workspace |
| Assembly | 51 `.asm` / `.S` files, NASM required | `core::arch::asm!` inline; one `.S`, for the bare-metal boot stub |
| TLS | none | `rustls` (the only TLS implementation) |
| Crypto | OpenSSL **or** BoringSSL **and/or** libsodium, selected at CMake time | one provider: the rustls provider (`ring`) |
| Cycle counter | `PMCCNTR_EL0` behind an env-var opt-in | `perf_event_open`, per thread, hybrid-CPU aware |
| Dispatch | `switch` on a backend enum, per call | function pointers resolved once at startup |
| GUI | Win32 only | `iced`, one binary for Linux (Wayland + X11), Windows and macOS |
| Build | CMake + 10 shell/batch scripts + external libraries | `cargo build` |
| Targets | Windows x64/ARM64, Linux | + macOS, four Android ABIs, and bare metal |
| License | MIT OR Apache-2.0 | Apache-2.0 |

### Removed on purpose

* **libsodium and OpenSSL/BoringSSL.** Every primitive now comes from the
  rustls provider, so the AES-256-GCM that encrypts a TLS record and the one
  the benchmark panel times are the same code. No `externals/` tree, no
  `SODIUM_STATIC`, no per-platform system import libraries.
* **The loose assembler tree.** `./asm` is gone. Every instruction sequence it
  contained lives next to the CPUID gate that decides whether to run it.
* **`PMCCNTR_EL0`.** The register traps to EL1 unless a privileged write has
  enabled userspace access, and there is no way to probe that without taking
  the trap — so 2.x hid it behind `NANOCHRONO_USE_PMCCNTR_EL0`, an opt-in that
  asked the library to try an instruction that might kill the process. It is
  also not virtualised or context-switched: a preempted thread read cycles
  that belonged to someone else. See [Cycle counting](#cycle-counting).

---

## Build

```sh
cargo build --release
```

That is the whole build. No CMake, no NASM, no external libraries.

The one exception to "everything is inline assembly" is
`crates/nanochrono-baremetal/boot/boot32.S` and its linker scripts, which
exist because a multiboot loader enters before Rust's ABI holds — see
[Bare metal](#bare-metal-no-operating-system).

**There is no hand-written C anywhere in this project.** `include/nanochrono.h`
is generated from `crates/nanochrono-ffi/src/lib.rs` by `tools/gen-header.sh`
(cbindgen), which is why it is gitignored; the packaging scripts regenerate it.
The bare-metal library's header, `include/baremetal/nanochrono.h`, is generated
the same way from `crates/nanochrono-baremetal/src/abi.rs`. Both exist so C,
assembly, cgo and Zig consumers have declarations, and both can be `#include`d
from a `.S` file: the constants are plain `#define`s and the C declarations sit
under `#ifndef __ASSEMBLER__`. The Python, Java, C#, Node and Lua wrappers
declare their own bindings and do not need them. The kernel module is Rust too.

| Artifact | Path |
|---|---|
| Desktop app | `target/release/nanochrono-gui` |
| CLI | `target/release/nanochrono` |
| Shared library | `target/release/libnanochrono.so` (`.dll` / `.dylib`) |
| Static library | `target/release/libnanochrono.a` |
| C header | `include/nanochrono.h` (generated — see below) |

### Optimisation levels

The code is built and tested at every level a user may pick: `-O0`, `-Og`,
`-O1`, `-O2`, `-O3`, `-Os` and `-Oz`. Each packaging script takes `OPT=`
([`packaging/opt-level.sh`](packaging/opt-level.sh) maps it onto Rust's
`opt-level`; Rust has no `-Og`, so it is opt-level 1 with full debug info):

| Level | Used for |
|---|---|
| `-O0` | debugging: every `debug` build |
| `-Og` | debugging what only optimised code shows (`debug-og` builds) — debug with both |
| `-O2` | **releases** — what is published |
| `-O1`, `-O3`, `-Os`, `-Oz` | supported for anyone building from source |
| `-Ofast` | not recommended. In C it is `-ffast-math`, which reassociates floating-point arithmetic and gives up IEEE 754 (NaN, infinities, signed zeros, exact rounding); Rust has no fast-math, so Rust code builds at `-O3` and stays IEEE |

```sh
OPT=-Os packaging/release/build-all.sh          # every platform at -Os
OPT=-O3 packaging/baremetal/build.sh x86_64     # one kernel at -O3
packaging/baremetal/build.sh debug-og           # the -Og debug build
```

Nothing that ships is stripped of its symbols: every program, library and
kernel keeps its symbol table. Its debug information — full for the
libraries' own code (`nanochrono-core`, `-crypto`, `-ffi`, the Android JNI
library and the bare-metal crate), line tables for the programs' — is built
into a file of its own beside it ([`packaging/debuginfo.sh`](packaging/debuginfo.sh)),
which a release does not publish: the downloads stay light, and whoever keeps
the debug files can still debug a release exactly as it shipped:

| Platform | Debug file | Found by |
|---|---|---|
| Linux, Android, bare metal (ELF) | `<file>.debug` | GDB and LLDB, through the `.gnu_debuglink` section the binary keeps |
| Windows (PE) | `<file>.debug` | GDB and LLDB, the same way |
| macOS (Mach-O) | `<file>.dSYM` | LLDB, by the binary's UUID |
| static libraries | `debug/<libdir>/libnanochrono.a`, the archive with its debug sections | linking it instead of the light one |

On Windows the `.debug` file is what a `.pdb` is elsewhere: these builds use
LLVM-MinGW, whose debug information is DWARF, which GDB and LLDB read. A
`.pdb` holds CodeView, which rustc emits only for the MSVC targets; Visual
Studio and WinDbg need that.

Nor does a release carry a path of the machine that built it: the packaging
scripts remap the repository, the Cargo registry, the toolchains and the
build trees to fixed names ([`packaging/remap-paths.sh`](packaging/remap-paths.sh)),
write the macOS debug map relative to the home directory, and link the
Windows binaries against a MinGW runtime (the mingw-w64 CRT and libunwind)
rebuilt the same way from llvm-mingw's sources. The repository is
`/nanochronometer` in the debug information, so point the debugger at a
checkout of the same version to see the sources:

```
(gdb) set substitute-path /nanochronometer /path/to/nanochronometer
(lldb) settings set target.source-map /nanochronometer /path/to/nanochronometer
```

### Release builds

```sh
packaging/release/build-all.sh                        # everything
packaging/release/build-all.sh linux-aarch64 android  # some
```

Everything lands in `build/`, and every platform is laid out as an install
prefix — the libraries in `lib64/` or `lib/`, `include/nanochrono.h` beside
them — so C or assembly links with `-I include -L lib64 -lnanochrono` (or
`lib`) on each one:

| Directory | Contents |
|---|---|
| `build/linux-{x86_64,aarch64,riscv64}/` | `bin/` (CLI, GUI), `lib64/` (`.so`, `.a`), `include/`, `share/` (desktop entry, icons) |
| `build/linux-{i686,armv7}/` | the same, with `lib/` |
| `build/windows-{x86_64,aarch64,i686}/` | `bin/` (the `.exe`s and `nanochrono.dll`, which Windows finds beside them), `lib/` (`libnanochrono.a`, the `.dll.a` import library), `include/` |
| `build/macos-{aarch64,x86_64,universal}/` | `bin/`, `lib/` (`.dylib`, `.a`), `include/`, `NanoChronometer.app` |
| `build/android/<abi>/` | `bin/` (the CLI, dynamic and static), `lib64/` or `lib/` (`.so`, `.a`), `include/`; the universal APK in `build/android/` |
| `build/baremetal/<arch>/` | the kernel, `lib64/` or `lib/` (`libnanochrono.a` and the complete `libnanochrono.so`), `include/` with the bare-metal ABI; the ISOs and a README in `build/baremetal/` |

Each prefix also holds its debug files, where the debuggers look for them: a
`.debug` beside each program and library (a `.dSYM` on macOS) and
`debug/<libdir>/` with the static library as built. The JNI libraries' are in
`build/android/apk-debug/`.

Each library directory has a `pkgconfig/nanochrono.pc` that finds the header
and the library wherever the directory is unpacked:

```sh
export PKG_CONFIG_PATH=$PWD/linux-x86_64/lib64/pkgconfig
cc app.c $(pkg-config --cflags --libs nanochrono)              # the shared library
cc app.c $(pkg-config --cflags nanochrono) linux-x86_64/lib64/libnanochrono.a \
   $(pkg-config --static --libs-only-l nanochrono | sed 's/-lnanochrono//')  # static
```

A Rust static library needs the system libraries its standard library uses;
`Libs.private` lists exactly those, as rustc reported them for that build. On
Windows that names libunwind as the archive, so a C program does not come to
depend on `libunwind.dll` either; on Windows on Arm it also includes
`libwindows.0.52.0.a`, which ships beside it in `lib/` (MinGW has no such
import library).

The shared libraries carry a portable name, not the path they were built at:
`SONAME` `libnanochrono.so` on Linux and Android, and the install name
`@rpath/libnanochrono.dylib` on macOS — so a program that links the dylib adds
its own run path, e.g. `-Wl,-rpath,@executable_path/../lib`.

The toolchains it expects are listed at the top of the script. There is no
32-bit Arm Windows build: Windows 11 24H2 and later do not run 32-bit Arm
programs, and Rust has only tier-3 MSVC targets for them.

### Release assets

```sh
packaging/release/package.sh               # build/ -> build/release-<version>/
```

[`packaging/release/package.sh`](packaging/release/package.sh) packs `build/`
into what a release publishes — a `.zip` per operating system, holding every
architecture — and nothing else:

| Asset | Contents |
|---|---|
| `nanochronometer-<v>-linux.zip` | `x86_64/`, `i686/`, `aarch64/`, `armv7/`, `riscv64/` |
| `nanochronometer-<v>-windows.zip` | `x86_64/`, `aarch64/`, `i686/` |
| `nanochronometer-<v>-macos.zip` | `x86_64/`, `aarch64/`, `universal/` |
| `nanochronometer-<v>-android.zip` | `arm64-v8a/`, `armeabi-v7a/`, `x86_64/`, `x86/` (the NDK libraries and the terminal CLI) |
| `nanochronometer-<v>-baremetal.zip` | the nine architectures, the plugins, the documentation, and the bootable images in `iso/` (x86_64, i386, aarch64, ppc-openfirmware) |
| `nanochronometer-<v>.apk` | the Android app |
| `SHA256SUMS` | checksums of all of them |

Each architecture's directory is that platform's prefix from `build/`, light:
programs and libraries with their symbol tables, without debug information.
Every zip carries `LICENSE`, `NOTICE` and `THIRD-PARTY-LICENSES.txt` at the
top, and the Windows and Android ones the toolchain runtime's notices under
`licenses/` ([`docs/THIRD_PARTY_NOTICES.md`](docs/THIRD_PARTY_NOTICES.md)).

The debug information is packed apart, in `build/release-<v>/debug/`, and is
not published: a `-debug.zip` per operating system (each `.debug` or `.dSYM`,
and `<arch>/debug/<libdir>/libnanochrono.a`) and one for the app's JNI
libraries, with their own `SHA256SUMS`. A `-debug.zip` has the same top
directory as its release zip: unzip both in one place and each debug file
lands beside the binary it belongs to, where the debugger finds it.

### Android

```sh
packaging/android/build.sh                 # all four ABIs
packaging/android/build.sh arm64-v8a       # one ABI
ANDROID_API=24 packaging/android/build.sh  # raise the minimum API level
```

Needs an NDK (r27 tested). The path comes from `ANDROID_NDK_HOME`,
`ANDROID_NDK_ROOT` or `~/toolchains/android-ndk` — nothing is hardcoded in the
repository. Each ABI lands in `build/android/<abi>/`, laid out as an install
prefix — `lib64/` for the 64-bit ABIs, `lib/` for `armeabi-v7a` and `x86`:

| File | What it is |
|---|---|
| `lib64/libnanochrono.so` | Shared library, for an APK's `jniLibs/<abi>/` |
| `lib64/libnanochrono.a` | Static archive, for an `ndk-build`/CMake link |
| `include/nanochrono.h` | The C ABI, beside the libraries |
| `bin/nanochrono` | CLI, dynamically linked against bionic |
| `bin/nanochrono-static` | CLI, statically linked — `adb push` and run |

All four ABIs are built and exercised: `arm64-v8a`, `armeabi-v7a`, `x86_64`
and `x86`. The GUI is excluded — `iced` needs a windowing system that winit
does not drive from a plain Android executable.

```sh
adb push build/android/arm64-v8a/bin/nanochrono-static /data/local/tmp/nanochrono
adb shell chmod +x /data/local/tmp/nanochrono
adb shell /data/local/tmp/nanochrono dispatch
```

#### What each ABI actually gets

| ABI | Counter | ISA kernels and SIMD probes |
|---|---|---|
| `arm64-v8a` | `CNTVCT_EL0`, invariant | NEON, SVE, SVE2, SME; AES/SHA-2/PMULL |
| `x86_64` | `RDTSC`/`RDTSCP` | MMX through AVX-512; AES-NI, SHA-NI, PCLMULQDQ |
| `x86` | `RDTSC`/`RDTSCP` | none — see below |
| `armeabi-v7a` | monotonic clock | none — see below |

The counter layer is width-independent on x86: i686 reads the TSC exactly as
x86-64 does, which is the difference between roughly 30 cycles per read and
the ~15,000 a `clock_gettime` costs. What 32-bit x86 does *not* get is the
SIMD probes and ISA kernels — those are written against the 64-bit register
file. `Backend::is_available` and `SimdFamily::is_available` report them as
unavailable there rather than substituting a scalar loop and labelling it
SSE2.

ARMv7 has no unprivileged cycle counter at all: `PMCCNTR` needs
`PMUSERENR.EN` and `CNTVCT` needs `CNTKCTL.PL0VCTEN`, neither of which Android
sets. The monotonic clock is the honest answer there, and the dispatcher says
`fallback` rather than pretending otherwise.

### macOS

```sh
./packaging/macos/build.sh              # arm64, x86_64, and universal
./packaging/macos/build.sh arm64        # one architecture
```

Cross-compiles from Linux with [osxcross]. The toolchain path comes from
`OSXCROSS_ROOT`, or `~/toolchains/mac`, or `~/toolchains/osxcross`; the SDK
version and the Darwin release in the wrapper names are discovered from what is
installed rather than written down, so updating osxcross does not break the
script. Run on a Mac it falls through to the native toolchain. Building on a
Mac needs nothing but `cargo build --release`.

| Output | What it is |
|---|---|
| `build/macos-aarch64/` | Apple Silicon |
| `build/macos-x86_64/` | Intel |
| `build/macos-universal/` | Both slices in one file, via `lipo` |

Each is an install prefix: `bin/` (the CLI and the GUI), `lib/`
(`libnanochrono.dylib` and `libnanochrono.a`), `include/nanochrono.h`, and
`NanoChronometer.app` — the GUI as a bundle.

The deployment target is **macOS 11.0**, the first release that ran on Apple
Silicon — below that the arm64 slice would have no machine to run on.

The GUI is bundled rather than shipped as a bare executable because macOS gives
a loose binary no Dock icon and no keyboard focus, and this GUI is driven
almost entirely from the keyboard. `Info.plist` is generated from
`packaging/macos/Info.plist.in` with the workspace version substituted in.

Neither the binaries nor the bundle are signed or notarised. Gatekeeper will
refuse them on another machine until they are, which needs an Apple Developer
certificate and a Mac — this project cannot do it for you.

[osxcross]: https://github.com/tpoechtrager/osxcross

### Bare metal (no operating system)

Beyond the instrument, the freestanding build is growing into an operating
system: a sealed NCFS filesystem ([docs/NCFS.md](docs/NCFS.md)), a signed
package ecosystem ([docs/NCPKG.md](docs/NCPKG.md)), an `ncinitramdisk` the
kernel mounts and verifies at boot, and — adapting FreeBSD and OpenBSD for
the network stack, USB, the VFS, the driver model and the hypervisor, their
licences kept — drivers, networking and virtualization. The whole design,
and what of it is built today, is [docs/SYSTEM.md](docs/SYSTEM.md).

```sh
./packaging/baremetal/build.sh              # every architecture below (release)
./packaging/baremetal/build.sh run aarch64  # build and boot under QEMU
./packaging/baremetal/build.sh run ppc-g4   # the ppc build, via Open Firmware
./packaging/baremetal/build.sh test         # the host-side decoding tests
./packaging/baremetal/build.sh debug        # x86_64 at -O0 -g, frame pointers
./packaging/baremetal/build.sh debug-og     # the same at -Og (DEBUG_OPT=Og for gdb/boot)
./packaging/baremetal/build.sh gdb x86_64 [crashtest=df]  # the same, stopped for GDB
```

The output is `build/baremetal/` (`build/baremetal-debug/` for the debug
modes): per architecture the kernel, `lib64/` or `lib/` with `libnanochrono.a`
and `libnanochrono.so`, and `include/nanochrono.h`. The shared object is the
whole library, but bare metal has no dynamic linker, so using it means writing a
loader that resolves its symbols at run time — the `README.md` shipped beside it
says what that takes, and [docs/BAREMETAL_LIBRARIES.md](docs/BAREMETAL_LIBRARIES.md)
walks through it.

| Architecture | Rust target | Machine (QEMU) | Enters via | Console |
|---|---|---|---|---|
| x86-64 | `x86_64-nanochrono-none` | PC, **KVM** | multiboot 1/2 → `boot32.S` | 16550 (COM1), VGA |
| i386 | `i686-nanochrono-none` | PC | multiboot 1/2 → `boot_i386.S` | 16550 (COM1), VGA |
| AArch64 | `aarch64-unknown-none` | `virt` at EL1, EL2 or EL3 | ELF entry | PL011 |
| ARM32 | `armv7a-none-eabihf` | `virt`, Cortex-A15 | ELF entry, or UEFI (`BOOTARM.EFI`) | PL011 |
| ppc64 / ppc64le | `powerpc64{,le}-nanochrono-none` | `powernv8/9/10` (OpenPOWER) | skiboot, in place at `0x2000_0000` | OPAL |
| ppc (e500) | `powerpc-nanochrono-none` | `ppce500 -cpu e500mc` | ePAPR (device tree in r3) | 16550 in CCSR |
| ppc (G3/G4) | the same image | `mac99`, `g3beige`; real Macs | Open Firmware (client interface in r5) | OF `stdout` |
| RISC-V 64 / 32 | `riscv64gc-` / `riscv32imac-unknown-none-elf` | `virt` + OpenSBI | SBI, S-mode (a0 = hart, a1 = tree) | 16550, else SBI console |

KVM runs only guests of the host's own architecture (`build.sh` detects which
one that is); every other guest runs under TCG.

A freestanding build for these targets: no host operating system, no general
heap, no runtime — everything the kernel needs lives in its image, and a page
allocator (`src/palloc.rs`, on the loader's memory map) serves only what the
image cannot size in advance: a 4K screen's back buffer, a driver module. It
exists because the measurement floor a hosted process can reach is set by the
kernel underneath it — scheduling, interrupts, the syscall boundary — and the
only way to see past that floor is to own the kernel.

The boot menu offers two sessions (`mode=` on the command line): the
**NanoChronometer GUI**, the default — windows, a taskbar, the stopwatch,
terminal, task manager, files, settings and apps — and the
**NanoChronometer CLI**, a Unix-like shell that is plain text on purpose
(it refuses `color on`). With no framebuffer the GUI falls back to the CLI over
the serial line.

**The counter layer is the same code.** `nanochrono-baremetal` depends on
`nanochrono-core` with `default-features = false`, which keeps `arch`,
`backend`, `cpu`, `simd` and `redundancy` and drops everything needing an OS.
A freestanding kernel therefore executes the same inline assembly as a hosted
process rather than a copy that has drifted.

|  | Hosted | Bare metal |
|---|---|---|
| Counter | `RDTSC` / `CNTVCT_EL0` | the same instructions |
| PMU | `perf_event_open`, thread-profiling API | `RDPMC` / `PMCCNTR_EL0`, programmed directly |
| CPU features | HWCAP, sysctl, `IsProcessorFeaturePresent` | `CPUID`, or the `ID_AA64*` registers read at EL1 |
| Output | `write(2)` | 16550 UART / PL011 |

#### The few loose files, and why

Almost every instruction sequence lives in `core::arch::asm!` or
`global_asm!` next to the Rust that uses it. The files under
`crates/nanochrono-baremetal/boot/` exist because something has to run
before Rust's ABI assumptions hold, or outside the kernel image altogether:

| File | Why it is not Rust |
|---|---|
| `boot32.S` | x86_64 entry. A multiboot loader enters in 32-bit protected mode with no stack and no paging, and the multiboot header must land in the first 32 KiB of the image — a named section a linker script places. It builds a stack, identity-maps the first gigabyte, enables SSE and AVX state, switches to long mode, and jumps to `kmain`. |
| `boot_i386.S` | i386 entry: the same minus long mode — saves the loader's registers, zeroes `.bss`, sets a stack, enables SSE, loads its own GDT/IDT, and calls `kmain` cdecl. |
| `efi_loader.c` | The UEFI program the ARM32 and RISC-V ISOs boot (`BOOTARM.EFI`, `BOOTRISCV64.EFI`, `BOOTRISCV32.EFI`): copies the embedded kernel ELF to its link address, exits boot services and jumps. |
| `efi_loader_aarch64.c` + `kernel_blob.S` | The same for AArch64; `kernel_blob.S` `.incbin`s the kernel ELF into the loader. |

Plus the linker scripts. AArch64 and the other ISAs need no hand-written
entry file of their own: their entry stubs — park the secondary cores, enable
FP/SIMD, set a stack, zero `.bss` — are `global_asm!` inside the crate.

#### What the boot stub has to enable first

Three things must be true before Rust runs, and none of them is the default:

* **SSE.** `CR0.EM` cleared, `CR0.MP` and `CR4.OSFXSR` set. An SSE instruction
  without them is `#UD`, not a slow path.
* **`CR4.OSXSAVE`, then `XCR0`.** Everything wider than XMM needs the OS to
  declare that it will save the state. Without it `CPUID` still advertises AVX
  and AVX-512 while every VEX or EVEX instruction faults — the exact trap the
  hosted build's `XGETBV` check exists to *detect*, which here has to be made
  *true*. `OSXSAVE` is set whenever `XSAVE` exists rather than only when AVX
  does, because it is what makes `XGETBV` legal at all, and the feature
  detection reads `XCR0` to decide what is enabled.

  The wanted bits — 0 and 1 (x87, SSE), 2 (AVX), and 5, 6, 7 (opmask,
  ZMM_Hi256, Hi16_ZMM, all three of which AVX-512 needs) — are masked against
  `CPUID.0DH:EAX`, the set the processor actually implements. `XSETBV` raises
  `#GP` on any bit it does not, so the mask is not optional.
* **FP and SIMD on AArch64**: `CPACR_EL1.FPEN` — and the control at every
  level above: `CPTR_EL2` (whose layout depends on `HCR_EL2.E2H`) at EL2,
  `CPTR_EL3` at EL3, plus the SVE/SME enables where those exist. The compiler
  emits NEON freely on this target and every instruction traps until this is
  set — `ESR` `EC=0x07`, on the first Rust function that touches a `v`
  register.
* **PowerPC**: `MSR[FP]`, and `MSR[VEC]`/`MSR[VSX]` where the core has them;
  `r1` 16-byte aligned with a zero back chain; `r2` = `.TOC.` on 64-bit. A
  little-endian image switches itself out of the big-endian mode skiboot
  enters in, and back for every OPAL call.
* **RISC-V**: `sstatus.FS` and `sstatus.VS` out of Off; `gp` and a 16-byte
  aligned `sp`.

**Faults are reported, not fatal-and-silent.** Every architecture installs its
exception vectors before `kmain`: an IDT with the double fault, NMI, machine
check and page fault on their own stacks (x86), `VBAR_ELx` (AArch64), IVPR/IVOR
(e500), `stvec` (RISC-V). An exception prints its cause and address and stops.
The x86 stack has an unmapped guard page beneath it, so an overflow is
reported as one instead of corrupting the page tables below it.

**AArch64 runs with the MMU on**: an identity map in which only the kernel
image is Normal write-back and everything else Device. With the MMU off every
access is uncached, and a load probe would be measuring DRAM every time.

**The red zone is off.** Both freestanding targets set `disable-redzone` in
their spec, and `-C no-redzone=yes` is stated explicitly anyway: the 128 bytes
below `RSP` that a leaf function may use without adjusting the stack pointer
are, in kernel code, bytes an interrupt will push over. The corruption is
silent and a custom target spec would not inherit the setting.

#### RDPMC is right here and wrong everywhere else

Every hosted target in this project refuses to touch `RDPMC` or `PMCCNTR_EL0`,
because a raw counter read cannot see the kernel's multiplexing, does not
survive a context switch, and on a hybrid CPU silently reads whichever PMU it
landed on. **None of those hazards exist without a kernel**: nothing
multiplexes the counters, nothing deschedules this code, and it never migrates
because there is no scheduler. The instruction that is a trap in a hosted
build is the only correct option here.

There is no Rust intrinsic for it. `core::arch::x86_64` has `_rdtsc` and
`__rdtscp` but **not** `_rdpmc` — stdarch lists it in
`missing_x86_common.txt`, a known gap rather than a different name. `RDMSR`,
`WRMSR` and the AArch64 system registers have none either. All of it is
`core::arch::asm!`.

The kernel crate is unconditionally `#![no_std]`, including under `cargo
test`: there is no operating system to provide the library, and admitting it
even for a test build would let a dependency on it reach the kernel unnoticed.
The logic that needs testing therefore lives in `nanochrono_core::pmu_leaf` —
`no_std` too, but part of a crate that has a hosted test build.

#### The hybrid hazard does survive, in a different form

A P-core and an E-core are different microarchitectures sharing an instruction
set. They report **different `CPUID.0AH` values** — a different number of
general-purpose counters, a different counter width — so a PMU configuration
derived on one is not valid on the other, and a cycle count from each is not
comparable at all.

So `CorePmu::detect()` must run on the core it describes, every `Reading`
carries the `CoreType` it came from, and `Reading::delta_since` returns `None`
across types rather than a plausible wrong number. Nothing here averages
across core types.

That decoding is pure and lives in `nanochrono-core`, with tests, because it
is the one part a freestanding target cannot be driven through with the values
that matter: **one thread can only ever observe one of the two core types**.
Supplying both register sets is only possible from a hosted test.

```console
$ ./packaging/baremetal/build.sh run aarch64
NanoChronometer 4.0.0 — freestanding
arch: arm64

== CPU ==
  neon=true sve=true sve2=true
  aes=true sha2=true sme=true
  el=1
  backend: sme

== PMU (direct, no kernel) ==
  version        : 1
  general        : 6 counters, 32 bits
  fixed          : 1 counters, 64 bits
  100000 dependent ops
    cycles       : 121618
    cycles/op    : 1.21
```

On AArch64 the CPU features come from `ID_AA64ISAR0_EL1`, `ID_AA64PFR0_EL1`,
`ID_AA64PFR1_EL1` and `ID_AA64ZFR0_EL1`, read directly. `std::arch`'s
detection macro exists only because those registers *trap* at EL0 and a hosted
process has to ask the OS instead; at EL1 they are simply readable. This is
the one place where the privileged path is the easy one.

#### What is not built here

The `simd` feature of `nanochrono-core` is off for the freestanding x86 build.
`x86_64-unknown-none` has a soft-float ABI, so LLVM will not allocate an XMM
register at all; `-Ctarget-feature=-soft-float` appears to lift that but is
deprecated and slated to become a hard error ([rust-lang/rust#116344]), so the
stable fallback switches the feature off rather than overriding the ABI; the
default `x86_64-nanochrono-none` spec keeps SSE and builds it. Every other
architecture keeps everything.

[rust-lang/rust#116344]: https://github.com/rust-lang/rust/issues/116344

#### The serial console and the task manager

With no framebuffer (AArch64, RISC-V, PowerPC, x86 in text mode) the kernel
ends in an interactive console on the UART after the self-test:

* **`t` — task manager.** An htop for a machine that runs one program: CPU
  active time from the architecture's own activity counters — `APERF`/`MPERF`
  (x86), the Activity Monitors (AArch64 AMU), `PURR` (POWER) — effective
  frequency, IPC, and the time spent in each phase of the kernel's loop
  (render, present, input, measure, idle). The x86 GUI has the same view as
  the **TASKS** panel (key `T`).
* **`v` — hypervisor.** The report the boot-time negotiation produced, and
  a re-probe key (`p`) behind a 10-second cooldown — see
  [Hypercalls: once, and the vendor's own](#hypercalls-once-and-the-vendors-own).
  The x86 GUI has it as the **HYPERVISOR** panel (key `V` re-probes).
* **`s` — settings.** *Enable Physical Counter* (AArch64): `CNTPCT_EL0`
  instead of the default `CNTVCT_EL0`, with its warning always on screen,
  the measured cost of each read, and a stronger warning when a hypervisor
  is detected. It can be enabled in a VM; the warning is why it should not be.
  *Re-probe cooldown* (`c`; `K` in the x86 GUI): on by default, and off only
  with the warning that the provider-ban risk is then yours.

Idle is real where the architecture allows it without interrupts — `TPAUSE`
to a TSC deadline (x86 with WAITPKG), `WFE` woken by the generic timer's
event stream (AArch64) — so the activity counters show it. Elsewhere the wait
is a low-priority spin, and 100 % active is then the truth.

#### Keyboards on PCs with no 8042

The kernel polls its input with interrupts masked. That is deliberate: an
interrupt landing in a measurement is the noise it exists to exclude, so
there is no IRQ1 handler and no EOI to send. What broke keyboards on real
hardware was the 8042 itself. A UEFI PC with no legacy emulation has none,
its ports float and read `0xFF`, and the old driver waited out a minute of
timeouts at boot, then read `0xFF` forever without ever reaching the USB
keyboard. The controller is now probed and skipped when it is not there, and
USB and I2C are polled every frame regardless. `-machine q35,i8042=off` in
QEMU reproduces such a PC. See
[docs/BAREMETAL_DRIVERS.md](docs/BAREMETAL_DRIVERS.md).

#### Faults, crash dumps and the USB stick

On x86-64 every CPU exception has an IDT gate, and the double fault, NMI,
machine check and page fault run on stacks of their own (IST), so a fault on
a broken stack is reported instead of becoming a triple fault and a reset.
The kernel records every register, the driver that was running and a stack
trace, then writes a `.DMP` crash dump:

* over **COM1**, as base64;
* into **`CRASH.DMP` on a USB stick**. The x86-64 ISO carries a small
  `NANOCRASH` partition with that file, so a stick written from the ISO with
  `dd` holds the dump of its own crash. Any other FAT16/FAT32 stick with a
  `CRASH.DMP` in its root works too. The file is found at boot, and the crash
  only writes the blocks it already occupies;
* on the **stop screen**, which waits rather than restarting.

```sh
tools/nanodump.py show /run/media/$USER/NANOCRASH/CRASH.DMP \
    --elf build/baremetal/x86_64/nanochrono-kernel.elf
```

`crashtest=<de|pf|gp|ud|so|df|panic>` on the kernel command line raises a
fault on purpose, to check a machine end to end. `build.sh gdb` boots the
`-O0` build as a USB stick under QEMU, stopped for
`gdb -x packaging/baremetal/gdb/x86_64.gdb`. See
[docs/CRASH_DUMPS.md](docs/CRASH_DUMPS.md).

#### Apps, packages and plugins (`.ncapp`, `.ncpkg`, `.ncplu`)

The ecosystem's file types: an **`.ncapp`** is one app for one architecture;
an **`.ncdyn`** a shared library; an **`.ncplu`** a plugin of one app (a codec
pack for the players); an **`.ncdri`** a driver; and an **`.ncpkg`** a
package — one compressed download for every architecture, with a signed JSON
manifest (`ncpkg.meta`), the app per architecture, libraries, plugins and
assets. `tools/ncpkg` builds, signs (ML-DSA-87 + P-521 for the creator's four
roots, any of Ed25519, ECDSA, RSA-PSS or ML-DSA for self-signatures),
verifies, installs and removes packages, with the shared libraries in
`/usr/lib` reference-counted in `/var/lib/ncpkg/db.json` and every install
and removal one crash-safe transaction. The specification is
[docs/NCPKG.md](docs/NCPKG.md).

```sh
ncpkg build mypkg/ -o mypkg.ncpkg          # ncpkg.toml + ncapp/<arch>/ + lib/ + plugins/ + res/
ncpkg sign mypkg.ncpkg --role self --key ~/keys/me.ncpkg-key
sudo ncpkg install mypkg.ncpkg --root /mnt/ncfs --roots ~/keys/roots
sudo ncpkg remove org.example.app --root /mnt/ncfs
```

The x86-64 kernel loads apps — games, tools, anything that draws on the
screen — from the file tree or the boot stick's FAT partition at run time,
straight from a package too (the app for this architecture, checked against
the manifest's SHA-512). An app is an `.ncapp` file (modules packed as
`.ncplu` before the split still load): a position-independent `cdylib`
packed by `tools/ncplu.py` into sections, relocations and a symbol table,
loaded into a fixed 1 MiB arena with no allocator and no dynamic linker. It
reaches the kernel through a table of function pointers (`NcApi`) handed to
its entry point, and can import kernel data symbols by name
(`nc_resolve_symbol`). The loader still calls what it runs a "plugin"; the
rest of this section does too.

| Services | What |
|---|---|
| screen, input, log | `fill_rect`, `clear`, `present`, `poll_event`, `log` |
| NC_TIMER | serialised counter reads (`LFENCE; RDTSC` / `RDTSCP; LFENCE`), frequency, ticks to ns |
| NC_PMU | cycles and retired instructions, `perf_event_open`-style open/read/close |
| NC_RNG | `rng_fill`, `rng_status`, `rng_stir`: the entropy pool below |

##### Trust tiers and badges

Every plugin carries a reserved **ML-DSA-87 + P-521** signature block over the
SHA-512 digest of its image (a hybrid so a break in either the post-quantum or
the classical scheme alone is not enough). `tools/ncplu-sign` makes the keys
and signs; the private keys live outside the repository, and the kernel embeds
only the public halves. There are two trusted roots, and three tiers:

| Tier | Badge | When | Runs in |
|---|---|---|---|
| Creator | ✅ | signed by the creator's root (`NCPLU_ROOT_CREATOR`) | the kernel |
| Trusted root | 🌳 | signed by a root the machine's owner trusts (`NCPLU_ROOT_TREE`) | the kernel |
| Community | *(none)* | unsigned, or signed by no trusted root | ring 3 (user mode, isolated) |

The kernel checks the header digest first — a file changed after packing is
**refused**, at every tier — then both signatures against each root. The
launch card shows the tier, the signature, the file's SHA-512 and the root
fingerprints before the plugin runs; a community plugin waits five seconds in
which Esc cancels it. Verifying ML-DSA-87 needs about 768 KiB of stack, far
past the kernel's 64 KiB, so it runs on a dedicated guarded stack.

```sh
# One key directory is the creator's; another (per machine) is the tree root.
tools/ncplu-sign/... keygen --out ~/keys/creator     # ML-DSA-87 + P-521, prints a fingerprint
make -C sdk gdb PLUGIN=rng_demo KEYS=~/keys/creator   # signs, trusts that root, boots ✅
packaging/baremetal/build.sh gdb x86_64 plugin=snake  # unsigned → community, ring 3
```

##### A malformed `.ncplu` cannot reach the kernel

A plugin is untrusted input from a USB stick, and a community plugin runs
unsigned. The loader treats every byte as hostile:

* The format is validated **completely before anything is copied**, by a pure
  parser ([`nanochrono_core::ncplu`](crates/nanochrono-core/src/ncplu.rs))
  with no indexing that can panic: total size, the signature block, every
  table and section bound, section overlap and alignment, each relocation's
  8-byte write landing inside a non-code section, and the entry inside the
  code. The hosted build fuzzes it with tens of thousands of corrupted images
  under overflow checks; none escapes and none panics.
* The copy and relocations index the arena only through checked slices, so no
  file value can drive a write outside it.
* A running plugin gets its **own stack between two guard pages**; overflowing
  it faults instead of reaching kernel memory.
* Every buffer a plugin hands a kernel service (`nc_rng_fill`, `nc_log`, …)
  is checked to lie in the plugin's own arena or stack — the kernel never
  reads or writes where a plugin merely points it.
* A fault in a plugin — bad opcode, null write, stack overflow — is **caught
  and the plugin abandoned**; the kernel returns to the interface instead of
  triple-faulting. A fault in kernel code still crashes honestly.
* **Stack canaries** guard C plugins against overflowing a buffer on their own
  stack. The SDK builds with `-fstack-protector-strong`, and the kernel
  provides what that code imports: `__stack_chk_guard`, a canary drawn from
  NC_RNG for every run (low byte zero, so a string copy cannot write it back),
  and `__stack_chk_fail`, which stops the plugin before the smashed return
  address is used — in the kernel, or at ring 3 through its own `nccall`.
  `sdk/examples/smash.c` overflows a stack buffer on purpose to show it.

##### A community plugin runs at ring 3

A community plugin is untrusted, so it does not run with the kernel's
privilege. It runs at **ring 3** (CPL 3), with hardware between it and the
kernel:

* Its arena and a user stack are the only pages mapped user-accessible (the
  user bit set on their own 2 MiB pages); every kernel page has that bit clear
  at the leaf, so a ring-3 read or write into kernel memory **faults** — a
  plugin cannot even read the kernel image. The fault is delivered to the
  kernel, which ends the plugin.
* It reaches kernel services only through `nccall` (`SYSCALL`), the sole door
  from ring 3 to ring 0. The same `NcApi` table is built in the plugin's user
  memory, its function pointers aimed at stubs that each issue one `nccall`, so
  one plugin binary runs at either privilege unchanged — only its signature
  decides which. Every pointer a call carries is still checked to be the
  plugin's own before the kernel follows it.
* A creator (✅) or trusted-root (🌳) plugin has been vouched for, so it runs
  in the kernel (ring 0), called directly — the tier is the privilege boundary.

The GDT carries the ring-3 code and data segments and a TSS whose RSP0 is a
kernel stack for ring-3 traps (boot32.S); `crate::ring3` arms SYSCALL/SYSRET,
maps the user pages, and owns the entry, the `nccall` dispatcher and the
fault path.

##### Capabilities: least privilege per plugin

A plugin declares which service groups it needs — `screen`, `input`, `log`,
`timer`, `pmu`, `rng` — in its header (`tools/ncplu.py pack --caps ...`), and
the kernel grants no more. The launch card shows the granted set. A community
(ring-3) plugin that calls past what it declared is **stopped**; a kernel-tier
plugin's ungranted calls are refused (the service is a no-op), so even a
trusted plugin is held to what it asked for. So a plugin — or a bug or an
exploit inside one — is confined to the surface it declared, not the whole
`NcApi`.

The wall is also a licence boundary: Apache-2.0 plugins (Snake) live in
`crates/nanochrono-plugins/`; GPL programs such as DOOM are only ever loaded
from the user's own stick, never built into this tree.

Plugins can be written in C. [`sdk/`](sdk) has the ABI header
(`include/ncplu.h`, layout pinned by static asserts on both sides), the
freestanding runtime the compiler expects (`memcpy` & co.), examples (NC_RNG
and NC_TIMER, faults, a stack smash), and a Makefile with the exact clang/lld
flags — `--target=x86_64-unknown-none-elf -ffreestanding -fPIC
-fvisibility=hidden -mno-red-zone -fstack-protector-strong
-mstack-protector-guard=global`, linked `-shared` for the packer:

```sh
make -C sdk run PLUGIN=rng_demo        # C plugin + -O0 kernel + ISO, booted under QEMU
make -C sdk run MODE=debug-og          # plugins and kernel at -Og
make -C sdk MODE=release               # -O2, what gets signed and shipped
make -C sdk MODE=release OPT=-Os       # any level: -O0 -O1 -O2 -O3 -Os -Oz -Og -Ofast
```

### Linux on other architectures

The hosted crates build and are tested for x86-64, i686, AArch64, armv7,
ppc64le, ppc64, ppc (32-bit, run on a G4) and riscv64 Linux; Android (armv7,
i686) and Windows (i686) too. The cross toolchains come from their publishers
and are checked against the published checksums:

```sh
tools/fetch-cross-toolchains.sh        # Bootlin GCC+glibc per arch, llvm-mingw, the NDK
source tools/cross-env.sh              # CC, linker and a qemu-user/Wine runner per target
cargo test --release --workspace --target riscv64gc-unknown-linux-gnu
```

`--release` because the crypto benchmarks push hundreds of megabytes through
`ring`, which is hours of work under emulation in a debug build. Put
`CARGO_TARGET_DIR` on a native filesystem if the checkout lives on exFAT:
Cargo's artifact cache corrupts there.

### Linux desktop install

```sh
./packaging/linux/install.sh            # into ~/.local
./packaging/linux/install.sh --system   # into /usr/local, needs root
```

Installs the binaries, the shared library and header, a `.desktop` entry and
the icon. The window sets `application_id = io.nanochronometer.NanoChrono`,
which is both the Wayland app id and the X11 `WM_CLASS`, so the desktop entry
matches under either display server.

---

## The GUI

```sh
nanochrono-gui
```

Same structure as the Win32 build: navigation tabs, the large timer face, the
three readout panels, the benchmark panel with its mode rows and log, and the
status bar.

| Key | Action |
|---|---|
| `Space` / `P` | Start, pause, resume |
| `S` | Stop |
| `L` | Lap |
| `R` | Reset |
| `B` | Benchmark panel |
| `H` | Hypervisor panel |
| `C` | Digital / analogue clock face |
| `M` / `N` | Simple / nanosecond detail |
| `Esc` | Exit |

**Views.** `CLOCK` shows wall-clock time (digital or a canvas-drawn analogue
face), `STOPWATCH` counts up, `TIMER` counts down from a preset.

**Panels.** `BENCH` and `HYPERVISOR` replace the clock face; pressing the same
button again returns to it. The hypervisor panel leads with the verdict and
what it means for every other number in the window — green for native, amber
for hardware-assisted, red for emulated — then shows the ring 3 evidence and
the ring 0 evidence side by side, and finally which PMU interface is in use.
It shows the start-up probe; *RE-PROBE* repeats it at most every 10 seconds
(see [Hypercalls](#hypercalls-once-and-the-vendors-own)).
The status bar carries the same verdict at all times, so it is visible from
every view.

**Linux.** The binary runs on Wayland and X11 with no build flags. `winit`
prefers Wayland when `WAYLAND_DISPLAY` is set; force the other with
`WINIT_UNIX_BACKEND=x11` or `=wayland`.

**macOS.** The same GUI, on Cocoa. Iced draws through `winit`, which is AppKit
natively — the built binary links `AppKit`, `Foundation`, `QuartzCore` and
`CoreGraphics`, and renders with `wgpu` on Metal. It is Cocoa in the sense
that matters (a real `NSApplication` with native windowing and event
handling), not a hand-written Objective-C interface. Ship it as the `.app`
bundle the packaging script builds; see [macOS](#macos).

### Deliberate differences from the Win32 GUI

* **Native window decorations.** The C build drew its own title bar and
  reimplemented dragging and hit-testing in several hundred lines of
  `WM_NCHITTEST` handling that behaved differently under every window manager.
* **The NTP and calibration panels show measurements.** In the C build those
  numbers were string literals in `paint()` — `"+112 ns"`, `"Stratum: 2"`,
  `"0.38 ppm"` were hard-coded, not read from anything.
* **Benchmarks and NTP queries run off the UI thread**, so a three-pass run no
  longer freezes the window.
* **Saving the log** writes `nanochrono-bench-<unix>.log` to the working
  directory and reports the path, rather than opening a native file dialog.

---

## The physical counter (AArch64)

Every interface offers the same switch, off by default:

| | How |
|---|---|
| GUI | **SETTINGS** → *Enable Physical Counter* |
| CLI | `nanochrono --physical-counter <command>` |
| C ABI | `nc_set_physical_counter(1)`, `nc_physical_counter_warning()` |
| Bare metal | console **Settings** (`s`, then `p`) |
| Kernel module | `insmod nanochrono.ko physical_counter=1` |

`CNTVCT_EL0` is the default: what every OS hands user space, never trapped.
`CNTPCT_EL0` is what the hardware ticks — the same cost on bare metal, but
inside a VM the hypervisor may trap every read, and under nested
virtualization it is slow and unstable. **It is allowed in VMs anyway**, with
the warning shown; the only refusal is an OS that makes the instruction
illegal for user space (tested once, in a forked child on Linux/Android/
macOS, under a vectored exception handler on Windows). Switching resets the
stopwatch: in a VM the two counters differ by `CNTVOFF_EL2`.

## The CLI

```sh
nanochrono                       # live stopwatch until Ctrl+C
nanochrono once                  # one diagnostic sample
nanochrono dispatch              # what the ISA dispatcher selected, and why
nanochrono catalog               # every backend, SIMD family and clock route
nanochrono clock --nano --utc    # live precision clock
nanochrono ns-clock              # every raw counter route, live
nanochrono stable-calibrate --ms 500 --pin-cpu 3
nanochrono ntp pool.ntp.org
nanochrono tls www.rust-lang.org --suites
nanochrono bench --mode crypto
nanochrono asm-simd              # per-family SIMD probes
nanochrono sct-audit             # constant-time timing audit
nanochrono wrapper-overhead
```

Global flags: `--backend <name>` forces a timer backend, `--pin-cpu <n>` pins
the measuring thread before anything else runs.

```console
$ nanochrono dispatch
arch=x86 backend=avx-vnni (detected) simd=avx-vnni (detected) route=best-simd-counter (detected)
invariant_counter=true available=[legacy-asm mmx sse sse2 sse3 ssse3 sse4.1 sse4.2 avx f16c fma avx2 avx-vnni]
```

Android, cross-built and run under `qemu-user`:

```console
$ qemu-aarch64 build/android/arm64-v8a/bin/nanochrono-static dispatch
arch=arm64 backend=sme (detected) simd=sme (detected) route=best-simd-counter (detected)
invariant_counter=true available=[legacy-asm neon sve sve2 sme]
```

---

## Runtime dispatch

Detection runs once per process and resolves every hot path to a function
pointer, so a counter read is an indirect call rather than a `match` on a
backend enum — which is what the C version did on *every* read.

A pointer is installed only after both the CPUID bit and, on x86-64, the
`XCR0` bit for the register file are observed. That pairing is the whole game:
a CPU can advertise AVX-512 while the OS has not enabled ZMM state, and
executing a ZMM instruction then is `#UD`, not a slow path.

| Variable | Effect |
|---|---|
| `NANOCHRONO_BACKEND` | Force a timer backend, e.g. `avx2`, `sse2`, `legacy` |
| `NANOCHRONO_SIMD` | Force a SIMD probe family |
| `NANOCHRONO_CLOCK_ROUTE` | Force a clock route |

An unrecognised or unsupported value is ignored and reported as
`override-rejected` in `nanochrono dispatch`, rather than failing at startup.

---

## The PMU

The PMU is never touched directly. On every platform the kernel owns the
counters, schedules them per thread and corrects for multiplexing; going
around it produces numbers that look plausible and are wrong.

| Platform | Interface | Unit |
|---|---|---|
| Linux | `perf_event_open` | cycles |
| Windows | `EnableThreadProfiling` / `ReadThreadProfilingData`, with `QueryThreadCycleTime` as the always-available floor | cycles |
| macOS | `CLOCK_THREAD_CPUTIME_ID` | **nanoseconds** |
| Bare metal | `RDPMC` / `PMCCNTR_EL0`, programmed directly — see [Bare metal](#bare-metal-no-operating-system) | cycles |
| Elsewhere | unavailable, and it says so | — |

macOS has no hardware counter to reach: the PMU is behind `kperf`, a private
framework gated on an entitlement Apple does not grant. What is available is
the kernel's accounting of thread CPU time, which is a *duration* — so
`PmuBackend::unit()` reports nanoseconds there and cycles everywhere else, and
`is_hardware_counter()` is false. A caller that divided it by a clock rate
would be wrong by exactly that rate, which is why the unit travels with the
reading instead of being inferred from the platform.

There is deliberately **no `RDPMC` and no `PMCCNTR_EL0` in a hosted build** —
the freestanding target is the exception, and the reasons below are exactly
why it can be. A raw counter read
bypasses the kernel's accounting: it cannot see multiplexing, so a descheduled
event silently under-reports, and it has no idea which PMU it landed on — on a
hybrid CPU that means reading the wrong core type and getting zero. The
userspace path also needs a seqlock protocol, architecture-specific assembly
and a sign-extension dance, which is a lot of subtle machinery for a saving
that only shows up when reading the PMU in a hot loop. The hot-path counters
are the architectural ones (`RDTSC`, `CNTVCT_EL0`); the PMU is for attribution.

Windows uses the thread-profiling API rather than ETW on purpose: ETW is a
system-wide tracing pipeline needing a session and administrator rights, which
is the wrong shape for reading this thread's counters. The thread-profiling API
is the same kernel facility ETW's profile provider uses, reached directly.
`QueryThreadCycleTime` is reported distinctly because it is kernel accounting
rather than a programmable PMU event — [`PmuBackend::is_hardware_counter`]
makes the difference visible instead of blurring it.

## Cycle counting

`perf_event_open` replaces the raw PMU register. The kernel schedules the
counter per thread, saves and restores it across context switches, and exposes
it unprivileged (subject to `perf_event_paranoid`).

Two read paths:

* **`rdpmc`** — when the kernel maps the counter and sets `cap_user_rdpmc`, a
  read is one instruction plus a seqlock check: tens of cycles, no syscall.
  Wired up on x86-64.
* **`read`** — always available, around a microsecond. The fallback, and the
  only path on AArch64, where a userspace read would need `mrs` against a
  runtime-selected `PMEVCNTR<n>_EL0`.

**Hybrid CPUs.** On Intel P-core/E-core parts there is no single `cpu` PMU —
there are `cpu_core` and `cpu_atom`, with separate counters. A plain
`PERF_TYPE_HARDWARE` event binds to one of them and then silently reads
**zero** whenever the thread runs on the other core type. NanoChronometer opens
one event per PMU and sums them, so a thread that migrates is still counted.

A counter that opens but never gets scheduled reports itself as unavailable
rather than returning zero forever.

---

## Benchmark modes

The C build had *CPU intrinsics*, *OpenSSL EVP* and *libsodium*. The last two
existed to compare two independently linked crypto libraries; with a single
provider that comparison is gone, and keeping two identical modes would be
dishonest. The third slot now measures something the old build could not.

| Mode | Measures | Answers |
|---|---|---|
| 1 — CPU ISA | Inline-asm kernels per ISA family | What can this core's datapath do? |
| 2 — Crypto | rustls/`ring` primitives over real buffers | What does a byte of AEAD or hash cost? |
| 3 — TLS | End-to-end rustls handshakes | What does establishing a session cost? |
| 4 — Linux crypto API (ring 3) | The kernel's crypto through `AF_ALG` (Linux only) | What does the kernel's implementation cost from userspace? |
| 5 — Linux crypto API (ring 0) | The same, inside the kernel module (Linux only) | What is left once the syscall is removed? |
| 6 — Crypto RAW speed (4 off Linux) | The bare instructions: AES round, SHA-256 round, carry-less multiply, VAES, VPCLMULQDQ | How fast is the silicon, with no cipher around it? |

Crypto RAW is **speed only**: no key schedule, no mode, no authentication. It
is not a cipher and says nothing about security; Mode 2 is the number for
real crypto. `nanochrono bench --mode crypto-raw` on the CLI, key `6` (or the
mode's number) in the GUI. The bare-metal BENCH tab keeps the two apart as
well: *CRYPTO RAW SPEED* next to *RUSTCRYPTO*.

Every run does three passes with increasing iteration counts and reports
best/worst/mean. When the spread between passes exceeds 15% the log says so:
the workload is still warming up, and the last pass is more trustworthy than
the mean.

---

## Hypervisor and emulation detection

Virtualization changes what a counter reading *means*, so the toolkit detects
it and says so next to every measurement.

| Platform | What a nanosecond figure is worth |
|---|---|
| Bare metal | Physical. Trust it. |
| Hardware-assisted (KVM, VMware, Hyper-V, Xen) | Short intervals hold up; anything spanning a VM exit or steal time does not. |
| Emulated (QEMU TCG, an ISA simulator) | The counter is *synthesised*. The number describes the emulator, not the workload. |

```console
$ nanochrono hypervisor
hypervisor    : none
confidence    : none
timing impact : native
sources       : none
trap probe    : cpuid=58 cyc  baseline=12 cyc  ratio=4.8x  exit=no
kernel module : not loaded (optional; see kernel/linux/README.md)

Bare metal: counter readings are physical and nanosecond figures are meaningful.

$ qemu-x86_64 nanochrono hypervisor
hypervisor    : QEMU TCG
confidence    : confirmed
timing impact : emulated
cpuid vendor  : "TCGTCGTCGTCG"
sources       : cpuid-feature-bit cpuid-vendor-leaf

Emulated: the counter is synthesised, so nanosecond figures measure the
emulator, not the workload. Use these numbers for correctness checks only,
never for performance claims.
```

### NC_VM — the user-mode verdict in one call

The same detection is a C API, for a program that just wants to know whether it
is in a VM — no privileges, no kernel module, the result cached:

```c
#include "nanochrono.h"

nc_vm_t vm;
nc_vm_detect(&vm);              /* present, confidence, timing_emulated, name */
if (vm.present && vm.timing_emulated) {
    /* the counter is synthesised: correctness, not performance */
}
int in_vm = nc_vm_present();    /* or just the yes/no */
```

`nc_vm_detect` is a thin front to `nc_hypervisor_detect`, which returns the full
`nc_hypervisor_report_t` (CPUID signature, trap-cost cycles and ratio, declared
TSC kHz, the AArch64 ID registers). Both share one cached detection.

### Ring 3 / EL0 — always available, no privileges

* `CPUID.1:ECX[31]`, the architectural hypervisor bit
* The 12-byte vendor signature at `CPUID.40000000H`, scanned in `0x100` steps
  so a nested Hyper-V is still found — KVM, QEMU TCG, VMware, Hyper-V, Xen,
  VirtualBox, Parallels, bhyve, ACRN, Jailhouse, Apple VZ, QNX, WSL
* `CPUID.40000010H` for the TSC frequency the hypervisor declares
* On Windows, `IsProcessorFeaturePresent` is ANDed with CPUID for feature
  detection. Windows is authoritative there: the OS must have enabled the
  register state before an instruction is legal, so CPUID can say yes where
  Windows says no. ANDing can only ever remove a feature, never add one, which
  is the safe direction for something that gates instruction dispatch.
* On macOS, `kern.hv_vmm_present`. This is the whole answer there: the kernel
  knows whether it booted under a VMM and says so. It is a declaration rather
  than an inference, and unlike everything else it works identically on Intel
  and Apple Silicon — which matters, because Apple Silicon has no CPUID and
  none of the Linux files exist. `hw.model` then names it: Apple's own
  Virtualization.framework reports `VirtualMac2,1`
* DMI strings, `/sys/hypervisor/type`, the device tree (the AArch64 route),
  a paravirtual clocksource (`kvm-clock`, `hyperv_clocksource`, `xen`), and
  paravirtual buses (virtio, VMBus, Xen)
* On Windows, the registry: `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`
  exists only inside a Hyper-V guest, and `HARDWARE\DESCRIPTION\System\BIOS`
  carries the same firmware strings SMBIOS does. **This is the identification
  path on ARM64 Windows**, where there is no CPUID at all
* **A measured trap cost.** `CPUID` is serializing and exits to the VMM on
  essentially every hypervisor. Comparing it against a bare counter pair gives
  a signal no CPUID spoofing can suppress, *and* directly quantifies the
  per-exit latency you are worried about. A ratio above ~20 means the trap
  exits; native sits under 10.

#### AArch64 has no CPUID, so it reads the registers EL0 is allowed to read

`MRS` on an EL1 register traps, and Linux emulates some of those transparently
— so the cost of the trap says nothing about a hypervisor underneath, and a
guess about which registers are emulated is a `SIGILL` where it is wrong. Only
the architecturally unprivileged registers are read:

* **`CNTFRQ_EL0`** — the closest thing AArch64 has to a vendor leaf. A virtual
  machine has to invent a frequency for its virtual timer, and the ones it
  invents are not values physical SoCs use: QEMU's `virt` board picks 62.5 MHz,
  and `qemu-user` drives the counter off a nanosecond clock at exactly 1 GHz.
  Real parts cluster around 19.2, 24, 25 and 100 MHz.
* **`CTR_EL0`** — cache geometry, reported for diagnosis rather than matched.
* **`MIDR_EL1`** — read from sysfs, not by `MRS`. The register is EL1-only by
  architecture; sysfs publishes it without needing a trap.
* **An `ISB` cost ratio**, in place of the x86 trap probe. There is no
  unprivileged AArch64 instruction that exits to the hypervisor, so there is no
  exit to time; what can be timed is execution against *emulation*, since `ISB`
  costs an emulator a translation-block exit. This is the weakest signal here
  and is not load-bearing — under `qemu-user` the virtual counter is too coarse
  and it reports nothing at all.

A declared source yields `confirmed`. Anything inferred — the trap ratio, an
unusual `CNTFRQ_EL0`, a null `MIDR_EL1` — yields `suspected` and never
confirms on its own, because an unusual piece of silicon is not a VM.

### Host clock synchronisation (`nanochrono host-sync`)

Two different things, often confused:

* **`kvm-clock` needs nothing.** When the kernel has selected a paravirtual
  clocksource, `CLOCK_MONOTONIC` is *already* derived from the host's timebase,
  through a page the host maintains and the vDSO reads. No hypercall, no
  module. What matters is knowing: a TSC calibrated against `CLOCK_MONOTONIC`
  in that situation was calibrated against the host's notion of time rather
  than an independent one.
* **An absolute host/guest offset needs a pairing**, and that needs a
  hypercall — `KVM_HC_CLOCK_PAIRING` over `VMCALL`/`VMMCALL` on x86, the KVM
  PTP function over `HVC` on AArch64. Both are privileged: `VMCALL` at CPL 3
  raises `#UD`, `HVC` at EL0 is undefined. There is no unprivileged form.

That would put it in the kernel module, except Linux already ships a driver
that makes the call and publishes the answer. **`ptp_kvm` does the hypercall in
ring 0 and exposes the paired timestamps through a PTP character device**, so
the whole feature is reachable from ring 3 through `PTP_SYS_OFFSET_PRECISE` —
and this project needs no module of its own for it.

```console
$ nanochrono host-sync
paravirtual clocksource : kvm-clock
monotonic follows host  : yes
host clock pairing      : available (ptp_kvm)
  host is ahead by      : 1483 ns
```

It needs a KVM guest with `ptp_kvm` loaded and read access to `/dev/ptpN`
(usually `root:clock`). Any of those missing reports `unavailable` rather than
failing — including on bare metal, which is the common case.

### Hypercalls: once, and the vendor's own

Two rules hold in every ring-0 component — the Linux module, the Windows
driver and the bare-metal kernel:

**Once.** Everything that makes a guest exit to its hypervisor (the
hypercall, the `CPUID` exit-cost loop, the trapped `CNTPCT_EL0` read-cost
measurement) runs once — at module load, at driver start, at boot, where it
negotiates the host clock — and is cached. Reading the report never repeats
it. On a cloud host (Azure, GCP, AWS, Vultr…) a guest exiting in a loop reads
as abuse and gets throttled or banned; a panel refresh or a
`watch cat /proc/nanochrono` must not be able to cause that. The hosted
process's own `CPUID` trap probe is likewise run once per process.

A deliberate **re-probe** is allowed once every **10 seconds**:

| Where | Re-probe | Cooldown off |
|---|---|---|
| GUI | **HYPERVISOR** → *RE-PROBE* (shows the countdown) | **SETTINGS** → *Re-probe cooldown* |
| CLI | `nanochrono hypervisor --reprobe` | `nanochrono hypervisor --cooldown 0` |
| Linux module | `echo reprobe > /proc/nanochrono` (`EAGAIN` while cooling) | `echo cooldown=0 > /proc/nanochrono`, or `hypercall_cooldown=0` |
| Windows driver | IOCTL `0x22A008`, `tools\query.py --reprobe` (`ERROR_BUSY` while cooling) | IOCTL `0x22A00C`, `query.py --cooldown 0` |
| Bare metal | console `v` then `p`; x86 GUI `V` | console settings `c`; x86 GUI settings `K` |

The kernel module and the driver enforce the wait themselves, so no program
can skip it. **Turning it off is allowed, and the user then assumes the
provider's reaction** — every control that does it says so.

**The vendor's own instruction.** On x86-64 a mandatory hypercall HAL reads
`CPUID.0H` at every load and boot — never at build time, because one
installed system (an OS on an external SSD) moves between machines — and
executes the one instruction that vendor defines:

| Vendor | Instruction |
|---|---|
| Intel, Zhaoxin, VIA/Centaur | `VMCALL` |
| AMD, Hygon | `VMMCALL` |
| anything else | none |

The other one is `#UD` under most hypervisors, and an unhandled `#UD` in
ring 0 is a crash. The table is `nanochrono_core::hypercall_hal`; the module
and driver, built without the crate, carry the same one. Reports name the
choice (`hypercall_insn=`).

#### NC_HYPERCALL — the bare-metal ring 0 API

On bare metal the freestanding library exposes the hypervisor negotiation as a
C ABI (`include/baremetal/nanochrono.h`), so a kernel linking `libnanochrono`
does not write its own: `nc_hypercall_detect` fills an `nc_hv_report_t` (the
CPUID signature, whether a hypercall was *accepted* — proof, not inference —
and the host/guest clock pair), and `nc_hypercall_count` is the running total
that stays at 1. It is a **ring 0 / EL1** interface: the hypercall instruction
(`VMCALL`/`VMMCALL`, `HVC`) faults at ring 3 / EL0, and a hypercall is visible
to the host, which cloud platforms rate-limit — so a sandboxed community plugin
does not reach it, while a signed kernel-tier plugin, which runs in the kernel,
does.

### Ring 0 — the optional kernel module

`kernel/linux/nanochrono.ko` complements the above. **It is never
required**; without it detection still works, it is just less certain against
a hypervisor that hides its CPUID leaf. It is one module with one name; it
also publishes the system-wide perf counters (`perf_*` keys) that
`nanochrono perf` compares with the per-thread ones.

```sh
cd kernel/linux && make && sudo insmod nanochrono.ko
cat /proc/nanochrono
```

It adds what ring 3 cannot do at all: `VMCALL`, `VMMCALL` and `HVC` are only
valid inside a guest and require CPL 0 / EL1, so from userspace they fault
unconditionally whether or not a hypervisor is present. A hypercall that
*returns* is proof — and it holds even when the CPUID bit is cleared. Each
probe emits its own `__ex_table` entry, so a fault on bare metal resumes at
the fixup instead of oopsing.

The same probe exists for Windows as one driver, `nanochrono.sys`
(`kernel/windows/`, x64 and ARM64, cross-built with llvm-mingw). It is
test-signed with `osslsigncode`: `make sign` on Linux, or `autosign.bat` on
Windows, which creates a self-signed test certificate if there is none and
can trust it and enable test signing (`/trust`, `/testsigning`). See
[`kernel/windows/README.md`](kernel/windows/README.md).

On AArch64 the `HVC` carries real SMCCC function IDs rather than a bare `#0`:
`ARM_SMCCC_VERSION` (`0x80000000`), then the vendor hypervisor UID query
(`0x8600ff01`). The four UID words are reported **raw**, not matched against a
table, because the byte order that assembles them into a UUID has never been
testable here against a real AArch64 guest — printing them verbatim lets a
human identify the hypervisor without this code guessing.

The module is **written in Rust**, like the rest of the project. That needs
`CONFIG_RUST=y` and the exact `rustc` that built the kernel — Rust crate
metadata is version-locked, so a rustup toolchain fails with `E0514` even at
the same version number. The Makefile defaults to `/usr/bin/rustc`.

Its licence is **dual MIT / GPL-2.0**, not Apache-2.0. That is a constraint
the kernel imposes: `MODULE_LICENSE()` accepts only a fixed set of idents and
none is Apache, and anything outside that set taints the kernel and loses
access to GPL-only symbols. `Dual MIT/GPL` is the most permissive recognised
option. The directory shares no code with the rest of the tree.

The report is at `/proc/nanochrono`, mode 0644, so an unprivileged measuring
process can read it and only root can send it commands. The kernel's Rust crate exposes debugfs but not procfs,
and debugfs is 0700 — which would have defeated the point — so the module
declares the procfs ABI itself, guarded by a `CONFIG_RANDSTRUCT_NONE` check
that refuses to build where a hand-written struct mirror would be unsound.

---

## Bit-flip tolerance (ECC / TMR)

A single-event upset — a cosmic ray secondary, an alpha particle from package
decay — flips one bit. In most programs that surfaces as a crash. Here it can
be much quieter: flip one bit in the exponent of `cycles_per_ns` and every
duration the process reports is wrong by a factor of two, silently, for as
long as it runs. A stopwatch left running for a week is exactly the workload
where that matters and exactly the one where nobody re-checks the constant.

So every number the toolkit carries across time holds a Hamming(72,64) SECDED
code — the same construction ECC DRAM uses — beside two spare copies on
separate cache lines. What is covered:

| State | Where | Why it is worth protecting |
|---|---|---|
| Counter frequency | `Chronometer` | Divides every duration the process reports |
| Interval origin | `Chronometer` | Every elapsed reading is a subtraction from it |
| Accumulated total | `Stopwatch` | The longest-lived number here — a run can sit for hours |
| Live segment origin | `Stopwatch` | A flip offsets the segment in progress |
| Recorded laps | `Stopwatch` | Measurements someone chose to keep |
| Conversion factor | `StableClockState` | A flipped exponent rescales the whole session |

**TMR is an emergency tier, not part of measuring.** Three tiers, in cost order:

| Tier | When | Cost |
|---|---|---|
| Nothing | The hot path — every unit-to-nanosecond conversion | one load |
| **ECC** | Every stopwatch read, and at the once-a-second calibration checkpoint | seven ANDs and seven popcounts |
| **TMR** | Only when ECC detects damage it cannot repair | three loads and a vote |

The replicas are never consulted while the code still verifies, which is the
overwhelmingly common case.

Reads are self-healing: a damaged word never reaches a caller, because the
value handed back is the repaired one. Fixing the *storage* needs a mutable
borrow, so it happens at state transitions — pause, stop, lap, resume — and on
the GUI's one-second tick. Those are user actions and idle time, never the
measurement path.

Each copy carries its own code, so single-bit damage to a replica is repaired
by that replica rather than merely outvoted. That also stops two replicas
damaged at the same bit position from agreeing with each other and carrying a
wrong value to a 2-of-3 majority. Without a clean majority the result is
`unrecoverable` rather than a guess.

```console
$ nanochrono integrity --drill
INJECTED                           TIER                   RECOVERED
nothing                            clean                  yes
one data bit (40)                  corrected-by-ecc       yes
one check bit (66)                 corrected-by-ecc       yes
two data bits (5, 37)              corrected-by-tmr       yes
two data bits + one per replica    corrected-by-tmr       yes
two bits in all three copies       unrecoverable          no

Live state — the flip lands in a real stopwatch and a real calibration.

INJECTED                           TIER                   READING HELD
stopwatch total, one bit (40)      corrected-by-ecc       yes
stopwatch total, two bits          corrected-by-tmr       yes
clock factor, one exponent bit     corrected-by-ecc       yes
```

Corrections are counted process-wide and surfaced by `nanochrono integrity`,
in the GUI's hypervisor panel, and in the status bar — which stays silent
until the count stops being zero, because a permanent "0 corrections" readout
is noise.

### What this does not do

Being precise, because "radiation hardened" is a claim that gets overused:

* It protects **stored state**, not registers. A bit that flips inside the ALU
  mid-computation is gone before anything here can see it.
* It is **not a substitute for ECC memory**, which covers every byte of DRAM
  on every access. This covers a handful of values at checkpoints.
* Replicas sit on separate cache lines — usually separate DRAM rows — but
  software cannot guarantee physical separation. A strike energetic enough to
  corrupt all three copies defeats the vote.
* It does not make measurements radiation-tolerant. It makes a corrupted
  measurement **detectable** rather than silent, which is the achievable goal.

On a machine at sea level a non-zero correction count almost certainly means
failing memory rather than cosmic rays. Either way it is something to know
before trusting a long run, which is why it is reported rather than swallowed.

---

## Cryptography and TLS

One provider — [`ring`](https://crates.io/crates/ring), the same one rustls
uses — behind [`nanochrono-crypto`](crates/nanochrono-crypto):

* SHA-256, HMAC-SHA-256
* AES-256-GCM, ChaCha20-Poly1305
* System CSPRNG
* Constant-time comparison

TLS is rustls only, with roots compiled in from `webpki-roots` so a
measurement reproduces across machines. `nanochrono tls` splits a handshake
into DNS, TCP connect and TLS phases:

```console
$ nanochrono tls
provider: rustls/ring
protocol=TLSv1_3 cipher_suite=TLS13_AES_128_GCM_SHA256
peer_certificates=3 resumed=no
resolve=62.664 ms
tcp_connect=12.606 ms
tls_handshake=10.322 ms
total=85.724 ms (TLS is 12.0% of it)
```

---

## NC_RNG — random bytes

One C API for unpredictable bytes — `nc_rng_fill`, `nc_rng_status`,
`nc_rng_stir`, `nc_rng_selftest` — with two implementations behind it:

- **On a hosted OS** (Linux, Android, macOS, Windows) `libnanochrono` reads the
  **operating system's own generator**, through the
  [`getrandom`](https://docs.rs/getrandom) crate: `getrandom(2)` on Linux and
  Android, `getentropy(2)` on macOS, `ProcessPrng` on Windows. The kernel's
  CSPRNG is already seeded from everything the OS sees and is fit for
  long-term keys, so nothing is reinvented there: `NC_RNG_FAST` and
  `NC_RNG_TRUE` read it alike, `nc_rng_status` reports `NC_RNG_SOURCE_OS` and
  `NC_RNG_ENGINE_OS`, and `nc_rng_stir` does nothing (the OS gathers its own
  events). It is thread-safe and fork-safe because the generator is the
  kernel's, not the process's.
- **On bare metal**, where there is no OS to ask, it is NanoChronometer's own
  entropy pool, below — for the freestanding kernel, its `.ncplu` plugins, and
  any kernel linking the bare-metal library.

The names, constants and `nc_rng_status_t` are the same in both headers, so
the same C builds against either.

### The bare-metal entropy pool

[`nanochrono_core::rng`](crates/nanochrono-core/src/rng) is `no_std`,
allocation-free (the caller lends the memory it walks), and the same code on
all nine kernel architectures.

No single generator is trusted. Every source is absorbed into one Keccak
sponge; a broken or hostile source cannot cancel the others without knowing
them, and never sees them:

| Source | Credited |
|---|---|
| CPU timing jitter | 1/OSR bit per healthy sample — the primary source |
| `RDSEED` | ½ bit per bit, only if the timer fails its start-up test |
| An embedder's own source (`External`) | only if the timer fails |
| `RDRAND`, PMU cycle counts, events (keys, mouse, USB and storage transfers, frames) | never — additional input |

The jitter source follows the entropy manual the project uses as its
specification: a memory walk with stride 127 over a power-of-two region
(256 KiB by default) plus a hash loop, timed with the unserialised counter;
the triple-derivative stuck test; granularity learned by GCD; start-up with
100 + 1024 measurements (≤ 3 backward steps, < 90 % stuck); SP 800-90B
repetition-count, adaptive-proportion and lag-predictor tests at the
manual's cutoffs (the permanent lag cutoffs, which it does not tabulate, were
derived with the same formulas after reproducing its intermittent tables
exactly). A seed is `(256 + 65)·OSR` healthy samples — 963 at the default
OSR 3. An intermittent failure discards the block, raises the OSR and
re-validates; past OSR 20, or on a permanent failure, the pool stops and
every read fails. Never a partial buffer.

```
sources ──► Keccak-f[1600] sponge ──► XDRBG-256 ──► key ──► output stage ──► bytes
            (rate 136)                (seed, reseed,          VAES-512 │ VAES-256 │ AES-NI │ ARMv8 AES
                                       generate)              └──► ChaCha20 (software)
```

**The output stage is chosen at run time**, by CPUID and XCR0 on x86 and the
ID registers (or the OS) on ARM: AES-256-CTR with VAES on ZMM (four blocks per
instruction), VAES on YMM (parts with VAES but no AVX-512 — Alder Lake,
Raptor Lake, Zen 3), AES-NI on XMM, or the ARMv8 AES instructions; without
AES hardware — or by choice — ChaCha20 in portable 32-bit software. There is
no table-driven AES, and the key schedule runs on the AES instructions too.
Each engine passes its known-answer test before it is used; a hardware path
that fails is replaced by ChaCha20 and flagged. On x86 those paths stand on
CR4.OSFXSR (bit 9), OSXMMEXCPT (10) and OSXSAVE (18) plus XCR0, which the
boot stubs set before any Rust runs; the boot self-test reads them back.

**No nonce is ever reused.** The stage is fast-key-erasure: every request
takes the next value of a 64-bit counter that nothing resets — not a rekey,
not a reseed — and the first keystream block(s) become the next key, which is
never handed out. A key serves one request (at most 4 KiB) and is erased
before the caller sees the output. `NC_RNG_TRUE` bypasses the stage and
reseeds before every 32 bytes, for long-term keys.

```c
#include "nanochrono.h"            /* hosted or bare metal: the same calls */

uint8_t key[32];
if (nc_rng_fill(key, sizeof key, NC_RNG_TRUE) != sizeof key) { /* NC_RNG_E* */ }
nc_rng_stir(NC_RNG_EVENT_USER, my_event);    /* bare metal: mix in your timings */

nc_rng_status_t st = { .size = sizeof st };
nc_rng_status(&st);                           /* sources, engine, health, nonces */
```

The known answers come from an implementation that shares no code with this
one: `tools/nc_rng_kat.py` rebuilds them from OpenSSL (via `hashlib` and
`cryptography`) — FIPS 202, FIPS 197, RFC 8439, and XDRBG and the stage's
counter layout re-implemented in a few lines. Verified so far: VAES-256,
AES-NI and ChaCha20 natively (and under `qemu-x86_64`), AES-NI on the i386
kernel, ARMv8 AES on the aarch64 kernel under QEMU, ChaCha20 on every other
kernel architecture, big-endian PowerPC included. The VAES-512 path has not
run on AVX-512 hardware yet; until it does, its known-answer test is what
stands between it and the output.

---

## Language wrappers

`crates/nanochrono-ffi` exports the 2.x `nc_*` C ABI — same symbol names,
same `nc_backend_t` discriminants, byte-compatible struct layouts — so the
Python, Go, Java, C#, Node, Lua, Zig and Rust wrappers under `wrappers/` and
`python/` work unchanged:

```sh
cargo build --release -p nanochrono-ffi
NANOCHRONO_LIB=target/release/libnanochrono.so python3 -c "
import sys; sys.path.insert(0, 'python')
from nanochronometer.core import NanoChronometer
with NanoChronometer() as nc:
    print(nc.nanoclock_snapshot().unix_time_ns)"
```

The snapshot struct keeps its 2.x layout; only the four slots that held
`arm64_pmccntr_*` were renamed to `perf_*`, at identical offsets, and a
layout test pins every offset so a future edit cannot silently break a wrapper.

---

## Side-channel auditing

Scope, stated plainly: everything here measures buffers **the caller owns**, in
**this** process. There is no cross-process probing, no eviction-set
construction and no secret-recovery machinery. The purpose is to point the tool
at your own candidate routine and find out whether its timing depends on its
input.

```sh
nanochrono sct-audit --samples 4000
nanochrono asm-probe
```

The audit interleaves fixed and random inputs so that drift — thermal,
frequency, a busy neighbour — hits both classes equally instead of
masquerading as a signal, then applies Welch's t-test. `|t| >= 4.5` is
reported as a possible leak: evidence worth investigating, not proof.

---

## Accuracy

Formatting to nanoseconds does not make the OS nanosecond-accurate. Scheduling,
interrupts and frequency transitions all dwarf a counter tick. Direct counter
reads are trustworthy for short intervals and microbenchmarks; for wall-clock
time over minutes, the calibrated route against the monotonic clock is the
honest answer, and `drift_ppm` shows when calibration has gone stale.

For a stable calibration: pin CPU affinity, disable turbo, lock the performance
governor, prefer an invariant TSC or `CNTVCT_EL0`, isolate benchmark cores, and
consider disabling deep C-states. `nanochrono stable-calibrate` reports whether
the thread migrated during the window, which is the usual reason a number is
wrong.

**macOS cannot pin, and says so.** Darwin has no API that binds a thread to a
core: `THREAD_AFFINITY_POLICY` sets an affinity *tag* asking the scheduler to
co-locate threads that share one, and Apple documents it as unsupported on
Apple Silicon entirely. So `pin_thread_to_cpu` returns false there rather than
appearing to succeed. There is also no `sched_getcpu` equivalent, so migration
detection is off — `cpu_before`/`cpu_after` read as unknown instead of
inventing a core number. Both are reported rather than papered over, because a
calibration that silently went unpinned is worse than one known to be.

---

## Layout

```
Cargo.toml                  workspace (version 4.0.0)
crates/
  nanochrono-core/          counters, inline asm, dispatch, calibration, NTP, probes, NC_RNG,
                            modules (.ncapp/.ncdyn/.ncplu/.ncdri), .ncpkg and the package manager,
                            NCFS, nccall's dispatcher, the page-range allocator, EDID — all no_std
                            where the kernel uses them, and tested on the host
  nanochrono-sys/           the ring-3 side of nccall: nccall!, POSIX-class calls, errno, NcAlloc
  nanochrono-crypto/        rustls provider primitives + TLS handshake timing
  nanochrono-bench/         the three benchmark modes and the three-pass harness
  nanochrono-cli/           command-line front end
  nanochrono-gui/           iced desktop application
  nanochrono-ffi/           C ABI for the language wrappers
  nanochrono-android/       the Android app's native side
  nanochrono-baremetal/     the freestanding kernel (outside the workspace; packaging/baremetal/build.sh)
    boot/                     boot stubs (boot32.S, boot_i386.S), EFI loaders, linker scripts
    src/arch/                 per-ISA vectors and trap entries
    src/nccall/               nccall's frames, per-ISA glue and boot proof
    src/ring3.rs              ring 3 for apps: user mapping, SYSCALL, containment
    src/ncplu.rs              the app loader: packages, signature tiers, relocation
    src/ncdri.rs              the driver loader and nckernel_api_t
    src/palloc.rs             physical pages from the loader's memory map
    src/desktop/, cli.rs      the GUI and CLI sessions
    src/shell/                the CLI's shell and commands
  nanochrono-plugins/       Apache-2.0 apps (Snake, ncsys-demo), packed as .ncapp and .ncpkg
sdk/
  include/                  ncplu.h (apps), nccall.h (system calls), ncdri_api.h (drivers)
  examples/                 C apps, the hostile ones included (smash, faulter, peek, poke)
  drivers/                  .ncdri drivers: hello_ncdri (QEMU edu), qemu_stdvga (display)
  targets/                  ring-3 Rust targets, red zone on
include/nanochrono.h        hosted C header
kernel/linux/               optional ring 0 module, nanochrono.ko (Rust, MIT OR GPL-2.0-only)
kernel/windows/             the same for Windows, nanochrono.sys (Rust, MIT), osslsigncode signing
packaging/                  linux/, macos/, android/, baremetal/ (build.sh, QEMU, gdb), release/
tools/
  ncplu.py                  packs a cdylib into a module (.ncapp, .ncdri, .ncdyn, .ncplu)
  ncplu-sign/               module keys, ML-DSA-87 + P-521 signing and verifying (host tool)
  ncpkg/                    builds, signs, verifies, installs and removes .ncpkg packages (host tool)
  ncfs/                     makes, checks and seals NCFS images (host tool)
  check-redzone.py          reads machine code and fails on any access below the stack pointer
  nanodump.py               reads the bare-metal kernel's crash dumps
  nc_rng_kat.py             NC_RNG's known answers, from OpenSSL
  gen-*.py, rasterise-*.py  icons, wallpapers and fonts, regenerated from their sources
python/, wrappers/          language bindings
docs/                       the specifications (below)
assets/                     icons, logo, fonts, wallpapers
```

## Documentation

| Document | What |
|---|---|
| [SYSTEM.md](docs/SYSTEM.md) | the whole bare-metal system: boot, memory, drivers, network, status |
| [ECOSYSTEM.md](docs/ECOSYSTEM.md) | sessions, file types, trust and badges, apps |
| [NCCALL.md](docs/NCCALL.md) | the ring 3 ↔ ring 0 boundary on nine ISAs, the red zone |
| [NCDRI.md](docs/NCDRI.md) | the driver ABI, the loader, display drivers |
| [NCPKG.md](docs/NCPKG.md) | packages, manifests, signatures, the package manager |
| [NCFS.md](docs/NCFS.md) | the filesystem and the sealed initramdisk |
| [NCTOOLCHAIN.md](docs/NCTOOLCHAIN.md) | the toolchain package, the C library, OpenSSL and AWS-LC |
| [BAREMETAL_DRIVERS.md](docs/BAREMETAL_DRIVERS.md) | display, keyboards and pointers, the PMU |
| [BAREMETAL_LIBRARIES.md](docs/BAREMETAL_LIBRARIES.md) | using `libnanochrono.a` / `.so` in a kernel of your own |
| [CRASH_DUMPS.md](docs/CRASH_DUMPS.md) | crash dumps and reading them |
| [THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md) | what third-party code a release carries |

---

## Tests

```sh
cargo test --workspace                       # and --profile debug-og: the -Og build
cargo clippy --workspace --all-targets
packaging/baremetal/build.sh test            # the kernel's host-side tests (nanochrono-core)
make -C sdk drivers                          # every driver, nine ISAs, red-zone checked
(cd tools/ncpkg && cargo test)               # the package tool
```

More than 500 tests, all Rust — there is no C in the test code. The kernel
proves the rest at boot, on every architecture, before a session starts:
`selftest complete; halting` on the serial log. Network-dependent TLS tests are
opt-in:

```sh
NANOCHRONO_NETWORK_TESTS=1 cargo test -p nanochrono-crypto
```

The C ABI is covered from Rust two ways, because they catch different
failures. `crates/nanochrono-ffi/tests/abi.rs` links the crate and calls the
`extern "C"` functions, so it tests behaviour and the null-argument contract.
`tests/exported_symbols.rs` opens the built `libnanochrono.so` with `dlopen`
and resolves each symbol by name, the way a wrapper does at run time — a
renamed or dropped entry point passes the first test and fails the second.

Its expectations are read from the wrapper sources rather than typed out, so
the check is exactly "every symbol the shipped bindings will look up still
exists". That is not hypothetical: writing it found six entry points
(`nc_calibrate_clock_route`, `nc_clock_read_raw_route`,
`nc_stable_clock_default_config`, `nc_raw_delta_to_ns_calibrated`,
`nc_measure_kernel_timecall_overhead_cycles`,
`nc_measure_api_call_overhead_cycles`) that the Node.js and Lua wrappers
declare and the migration had dropped.

---

## Security

Report vulnerabilities privately on Signal to **`@theskeletonsword.46`**, with a
reproducible proof of concept and demonstrable impact. Not on Instagram,
Telegram or TikTok, and not in public issues. [`SECURITY.md`](SECURITY.md) has
the details, the rules and the safe harbor for good-faith research.

---

## License

Apache License 2.0. See [`LICENSE`](LICENSE) for the full text,
[`NOTICE`](NOTICE) for attribution, and
[`docs/THIRD_PARTY_NOTICES.md`](docs/THIRD_PARTY_NOTICES.md) for the licences of
the third-party code a release contains, which every download carries in
`THIRD-PARTY-LICENSES.txt`.
