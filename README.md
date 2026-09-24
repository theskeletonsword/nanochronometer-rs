<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/nanochronometer_logo.svg">
  <img alt="NanoChronometer" src="./assets/nanochronometer_logo.svg">
</picture>


Nanosecond-resolution stopwatch, precision clock and ISA microbenchmark
toolkit, built directly on the architectural counters — `RDTSC`/`RDTSCP` on
x86-64, `CNTVCT_EL0` on AArch64 — with the calibration, dispatch and drift
tracking that make those counters trustworthy.

```
00:00:12:347:891:042
hh:mm:ss:mmm:uuu:nnn
```

Version 3.0 is a complete rewrite in Rust of the 2.x C/assembler codebase.
The C ABI is preserved, so the existing language wrappers keep working.

---

## What changed from 2.x

| Area | 2.x | 3.0 |
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
It exists only so C, cgo and Zig consumers have declarations — the Python,
Java, C#, Node and Lua wrappers declare their own bindings and do not need it.
The kernel module is Rust too.

| Artifact | Path |
|---|---|
| Desktop app | `target/release/nanochrono-gui` |
| CLI | `target/release/nanochrono` |
| Shared library | `target/release/libnanochrono.so` (`.dll` / `.dylib`) |
| Static library | `target/release/libnanochrono.a` |
| C header | `include/nanochrono.h` (generated — see below) |

### Android

```sh
packaging/android/build.sh                 # all four ABIs
packaging/android/build.sh arm64-v8a       # one ABI
ANDROID_API=24 packaging/android/build.sh  # raise the minimum API level
```

Needs an NDK (r27 tested). The path comes from `ANDROID_NDK_HOME`,
`ANDROID_NDK_ROOT` or `~/toolchains/android-ndk` — nothing is hardcoded in the
repository. Output lands in `dist/android/<abi>/`:

| File | What it is |
|---|---|
| `libnanochrono.so` | Shared library, for an APK's `jniLibs/<abi>/` |
| `libnanochrono.a` | Static archive, for an `ndk-build`/CMake link |
| `nanochrono` | CLI, dynamically linked against bionic |
| `nanochrono-static` | CLI, statically linked — `adb push` and run |

All four ABIs are built and exercised: `arm64-v8a`, `armeabi-v7a`, `x86_64`
and `x86`. The GUI is excluded — `iced` needs a windowing system that winit
does not drive from a plain Android executable.

```sh
adb push dist/android/arm64-v8a/nanochrono-static /data/local/tmp/nanochrono
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
| `dist/macos/arm64/` | Apple Silicon |
| `dist/macos/x86_64/` | Intel |
| `dist/macos/universal/` | Both slices in one file, via `lipo` |
| `NanoChronometer.app` | The GUI as a bundle, in each of the three |

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

```sh
./packaging/baremetal/build.sh              # every architecture below
./packaging/baremetal/build.sh run aarch64  # build and boot under QEMU
./packaging/baremetal/build.sh run ppc-g4   # the ppc build, via Open Firmware
./packaging/baremetal/build.sh test         # the host-side decoding tests
```

| Architecture | Rust target | Machine (QEMU) | Enters via | Console |
|---|---|---|---|---|
| x86-64 | `x86_64-nanochrono-none` | PC, **KVM** | multiboot 1/2 → `boot32.S` | 16550 (COM1), VGA |
| AArch64 | `aarch64-unknown-none` | `virt` at EL1, EL2 or EL3 | ELF entry | PL011 |
| ppc64 / ppc64le | `powerpc64{,le}-nanochrono-none` | `powernv8/9/10` (OpenPOWER) | skiboot, in place at `0x2000_0000` | OPAL |
| ppc (e500) | `powerpc-nanochrono-none` | `ppce500 -cpu e500mc` | ePAPR (device tree in r3) | 16550 in CCSR |
| ppc (G3/G4) | the same image | `mac99`, `g3beige`; real Macs | Open Firmware (client interface in r5) | OF `stdout` |
| RISC-V 64 / 32 | `riscv64gc-` / `riscv32imac-unknown-none-elf` | `virt` + OpenSBI | SBI, S-mode (a0 = hart, a1 = tree) | 16550, else SBI console |

Every architecture other than x86-64 runs under TCG: KVM only runs guests of
the host's own architecture.

A freestanding build for these targets: no
syscalls, no allocator, no runtime. It exists because the measurement floor a
hosted process can reach is set by the kernel underneath it — scheduling,
interrupts, the syscall boundary — and the only way to see past that floor is
to remove the kernel.

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

#### Only two loose files, and why

`boot/boot32.S` and the linker scripts are the only assembly outside
`core::arch::asm!` in this entire project. `boot32.S` has to exist: a
multiboot loader enters in 32-bit protected mode with no stack and no paging,
which is before any of Rust's ABI assumptions hold, and the multiboot header
must land in the first 32 KiB of the image — which needs a named section a
linker script places. It builds a stack, identity-maps the first gigabyte,
enables SSE and AVX state, switches to long mode, and jumps to `kmain`.
Everything after that is Rust.

AArch64 needs no equivalent: the loader enters in 64-bit mode with the ABI
already valid, so its entry stub — park the secondary cores, enable FP/SIMD in
`CPACR_EL1`, set a stack, zero `.bss` — is `global_asm!` inside `main.rs`.

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
NanoChronometer 3.0.0 — freestanding
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
$ qemu-aarch64 dist/android/arm64-v8a/nanochrono-static dispatch
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
Cargo.toml                  workspace
crates/
  nanochrono-core/          counters, inline asm, dispatch, calibration, NTP, probes
  nanochrono-crypto/        rustls provider primitives + TLS handshake timing
  nanochrono-bench/         the three benchmark modes and the three-pass harness
  nanochrono-cli/           command-line front end
  nanochrono-gui/           iced desktop application
  nanochrono-ffi/           C ABI for the language wrappers
  nanochrono-baremetal/     freestanding kernel: direct PMU, no syscalls
    boot/boot32.S             the only loose assembly file in the project
    boot/*.ld                 linker scripts
include/nanochrono.h        C header
packaging/linux/            .desktop entry and installer
packaging/macos/            osxcross cross-build, lipo, .app bundle
packaging/baremetal/        freestanding kernel build and QEMU boot
packaging/android/          NDK cross-build for the four ABIs
kernel/linux/               optional ring 0 module, nanochrono.ko (Rust, Dual MIT/GPL)
kernel/windows/             the same for Windows, nanochrono.sys (Rust, MIT), osslsigncode signing
python/, wrappers/          language bindings (unchanged)
docs/                       design notes carried over from 2.x
assets/                     icon, logo, optional display font
```

---

## Tests

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
```

171 tests, all Rust — there is no C in this repository, test code included.
Network-dependent TLS tests are opt-in:

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

## License

Apache License 2.0. See [`LICENSE`](LICENSE) for the full text and
[`NOTICE`](NOTICE) for attribution, and `docs/THIRD_PARTY_NOTICES.md` for
dependency notices.
