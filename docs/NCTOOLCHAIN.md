# nctoolchain: the compiler, the C library and the crypto stack

What builds NanoChronometer programs — on another machine today, on
NanoChronometer itself once `sudo ncpkg install nctoolchain.ncpkg` has run —
and how OpenSSL and AWS-LC (with aws-lc-rs) are built with it, to end up as
the BENCH tab's hardware-crypto plugins.

The boundary those programs cross is [NCCALL.md](NCCALL.md), the driver side
[NCDRI.md](NCDRI.md), the package format [NCPKG.md](NCPKG.md). Status keys as
in [SYSTEM.md](SYSTEM.md). Every fact below about clang, rustc, LLVM, OpenSSL,
AWS-LC or aws-lc-sys was read from their sources or measured with the
toolchains named; where a step is a decision rather than a fact, it says so.

| Piece | Status |
|---|---|
| Ring-3 Rust targets [`sdk/targets/`](../sdk/targets) (red zone on) and [`nanochrono-sys`](../crates/nanochrono-sys) | **done**: all nine build; x86-64 runs `ncsys-demo` (NCCALL.md §9.2) |
| `nccall.h` (ring 3) and `ncdri_api.h` (ring 0) for C | **done**, nine ISAs |
| Cross builds from a host with clang + lld ([`sdk/Makefile`](../sdk/Makefile)) | **done** for C apps (x86-64) and drivers (all nine) |
| `nclibc` (§3) | planned — composition and what the kernel owes it fixed here |
| Rust `std` (§4) | planned — the work list measured on today's nightly |
| `nctoolchain.ncpkg` (§5) | planned — layout fixed and checked against the package format's limits |
| OpenSSL, AWS-LC, aws-lc-rs (§6, §7) | planned — targets, options and porting points fixed |
| The BENCH tab's crypto plugins (§8) | planned — interface and method fixed |

---

## 1. Not reinventing the wheel

| Taken | From | Licence | Used in |
|---|---|---|---|
| Compiler, linker and binutils as **one** multicall binary | LLVM `llvm/tools/llvm-driver` (`LLVM_TOOL_LLVM_DRIVER_BUILD`) | Apache-2.0 WITH LLVM-exception | §5.1 |
| A clang toolchain for a new OS | `clang/lib/Driver/ToolChains/FreeBSD.cpp`, and the small ones newer systems added (`Serenity.cpp`, `Managarm.cpp`, `Haiku.cpp`) | Apache-2.0 WITH LLVM-exception | §2.3 |
| Per-target defaults without patching clang | clang configuration files (`--config=`, `<triple>.cfg`, the `<CFGDIR>` token) | — | §2.3, §5.4 |
| C++ runtime, unwinder, builtins | LLVM libc++, libc++abi, libunwind, compiler-rt — FreeBSD's choice too | Apache-2.0 WITH LLVM-exception | §3.1 |
| libc above the system calls | FreeBSD `lib/libc` (`string`, `stdlib`, `stdio`, `gen`, `locale`, `stdtime`) | BSD-2/BSD-3-Clause, file by file | §3.1 |
| The system-call layer, generated | FreeBSD 15's `lib/libsys` split and its generator `sys/tools/syscalls` (Lua) | BSD-2-Clause | §3.1 |
| Start files; libm; malloc | FreeBSD `lib/csu`; `lib/msun`; jemalloc (`contrib/jemalloc`, FreeBSD's malloc) | BSD-2-Clause; Sun's notice / BSD-2; BSD-2-Clause | §3.1 |
| CPU features for user code | FreeBSD `elf_aux_info(3)` (`sys/sys/auxv.h`, `lib/libsys/auxv.c`), `AT_HWCAP` 25 / `AT_HWCAP2` 26 (`sys/sys/elf_common.h`), the `HWCAP_*` bits of `sys/<arch>/include/elf.h` | BSD-2-Clause | §3.2, §6.3, §7.2 |
| `getentropy(3)` over `getrandom(2)` | FreeBSD `lib/libc/gen/getentropy.c` | BSD-2-Clause | §3.2 |
| System calls only from libc | OpenBSD `pinsyscalls(2)`; Go calling libc on OpenBSD since Go 1.16 | *(model only)* | §3.3 |
| OpenSSL's BSD targets and perlasm schemes | OpenSSL `Configurations/10-main.conf` (`BSD-*`) | Apache-2.0 | §6.1 |
| Assembly generated on the build host, never on the target | FreeBSD `secure/lib/libcrypto/Makefile.asm` | BSD | §6.4 |
| OpenSSL's assembly measured in a kernel, between FPU brackets | FreeBSD `ossl(4)`, `sys/crypto/openssl/<arch>/` | BSD-2-Clause + OpenSSL's | §8.1 |
| AWS-LC's assembly without Perl or Go; its Rust bindings installed with it | AWS-LC `generated-src/`, CMake `GENERATE_RUST_BINDINGS` | Apache-2.0 OR ISC (+ its legacy notices) | §7.1 |
| aws-lc-sys linked to an installed AWS-LC | aws-lc-sys `AWS_LC_SYS_SYSTEM_DIR` | see §7.4 | §7.3 |

The BSD sources are adapted when they are written; this document copies no
code. Any BSD-4-Clause file among them is consulted, not reproduced — the
rule NOTICE already applies.

---

## 2. The targets

### 2.1 One target per ISA and side of the ring

| ISA | Ring 3, Rust (`sdk/targets/`) | Ring 3, C (the same ABI) | Ring 0, C: `.ncdri` (`sdk/Makefile`) | Ring 0, Rust: the kernel |
|---|---|---|---|---|
| x86-64 | `x86_64-unknown-nanochronometer` | `--target=x86_64-unknown-none-elf` | `--target=x86_64-unknown-none-elf -mno-red-zone -mgeneral-regs-only` | `x86_64-nanochrono-none` |
| i386 | `i686-unknown-nanochronometer` | `--target=i686-unknown-none-elf -march=pentium4` | `--target=i386-unknown-none-elf -mgeneral-regs-only` | `i686-nanochrono-none` |
| AArch64 | `aarch64-unknown-nanochronometer` | `--target=aarch64-unknown-none-elf -mstrict-align` | `--target=aarch64-unknown-none-elf -mgeneral-regs-only` | `aarch64-unknown-none` |
| ARM32 | `armv7a-unknown-nanochronometer-eabihf` | `--target=armv7a-unknown-none-eabihf -mfpu=vfpv3-d16 -mno-unaligned-access` | `--target=armv7a-unknown-none-eabi -mfloat-abi=soft` | `armv7a-none-eabihf` |
| PowerPC | `powerpc-unknown-nanochronometer` | `--target=powerpc-unknown-none-elf -mcpu=ppc -mno-altivec` | `--target=powerpc-unknown-none-elf -msoft-float -mno-altivec` | `powerpc-nanochrono-none` |
| PPC64 BE / LE | `powerpc64{,le}-unknown-nanochronometer` | `--target=powerpc64{,le}-unknown-none-elf -mabi=elfv2 -mcpu=power8` | the same triple, `-mabi=elfv2 -msoft-float -mno-altivec -mno-vsx -Xclang -disable-red-zone` | `powerpc64{,le}-nanochrono-none` |
| RISC-V 32 | `riscv32imac-unknown-nanochronometer` | `--target=riscv32-unknown-none-elf -march=rv32imac -mabi=ilp32` | the same | `riscv32imac-unknown-none-elf` |
| RISC-V 64 | `riscv64gc-unknown-nanochronometer` | `--target=riscv64-unknown-none-elf -march=rv64gc -mabi=lp64d` | `--target=riscv64-unknown-none-elf -march=rv64imac -mabi=lp64 -mcmodel=medany` | `riscv64gc-unknown-none-elf` |

The ring-3 columns are what `.ncapp`, `.ncplu`, `.ncdyn` and `.ncar` are
built for — red zone allowed, the psABI's floating point, C flags chosen to
match the Rust target's CPU, features and ABI name so both languages link
into one module. The ring-0 columns are `.ncdri` and the kernel: no red
zone, no FP/SIMD outside a bracket (NCCALL.md §2.4, NCDRI.md §5).

### 2.2 The C triple, measured

What clang 18 does with a triple naming this OS
(`--target=x86_64-unknown-nanochronometer`), read from `-###` and `-dM -E`:

* the triple is accepted (OS "unknown" to LLVM); `__ELF__`, `__GNUC__ 4`
  and `__STDC_HOSTED__ 1` are defined, `__unix__` is not;
* code is `-mrelocation-model static`, not PIC;
* linking runs **`/usr/bin/gcc`** (the generic GCC toolchain): nothing
  NanoChronometer-shaped is linked.

So until clang knows the OS, C for ring 3 is compiled for the `*-none-elf`
triples of §2.1 with the OS's defaults spelled out — exactly what
`sdk/Makefile` does today — and linked by `ld.lld` directly.

### 2.3 Teaching clang the OS — two steps

1. **A configuration file, with a stock clang** (on a host, today's
   clang). A file given with `--config=` holds command-line options;
   `<CFGDIR>` in it expands to the file's own directory, so an SDK stays
   relocatable. The SDK writes one per ISA,
   e.g. `etc/x86_64.cfg`:

   ```text
   --target=x86_64-unknown-none-elf
   -D__NanoChronometer__=1
   -fPIC -fvisibility=hidden
   -fstack-protector-strong
   --sysroot=<CFGDIR>/..
   -isystem <CFGDIR>/../include/x86_64-unknown-nanochronometer
   ```

   It is passed explicitly, never found by triple: the `*-none-elf` triples
   are also what ring-0 code is compiled for (§2.1), and a driver must not
   pick up ring 3's sysroot. Linking calls `ld.lld` itself (§2.2).

2. **A clang ToolChain** — `clang/lib/Driver/ToolChains/NanoChronometer.cpp`,
   modelled on `FreeBSD.cpp` (sysroot layout, start files, `-z relro`,
   PIE by default, lld, libc++, compiler-rt) — with an LLVM `Triple::OSType`
   for `nanochronometer`, so `<arch>-unknown-nanochronometer` is a real
   triple: `__NanoChronometer__` predefined, TLS and stack-protector
   defaults chosen, the link done by lld. It is carried as a patch in the
   LLVM that `nctoolchain` builds (§5.8) and proposed upstream, where it is
   of the size the newer systems' toolchains in that directory show. Native
   compilers always have it; their configuration file only says where the
   sysroot is (§5.4).

`__NanoChronometer__` is the one macro ported code tests. **The system never
claims to be FreeBSD** (`__FreeBSD__` stays undefined): code that sees
FreeBSD assumes sysctl, kqueue and Capsicum, which this system does not have.
Where a port needs FreeBSD's behaviour — `elf_aux_info`, `getentropy` — the
port adds `|| defined(__NanoChronometer__)` to the FreeBSD branch (§6.3,
§7.2).

---

## 3. nclibc

### 3.1 What it is made of

| Layer | Source | Notes |
|---|---|---|
| **libsys**: one stub per system call | generated by FreeBSD's `sys/tools/syscalls` from `sys/nanochronometer/syscalls.master` — the numbers of [`nr.rs`](../crates/nanochrono-sys/src/nr.rs), FreeBSD's for the POSIX class | each stub is the §4 sequence of NCCALL.md (`NCCALL()` of `nccall.h`), so each is one pinned site (§3.3) |
| libc | FreeBSD `lib/libc`: `string`, `stdlib`, `stdio`, `gen` (the parts above the stubs), `locale` (C and UTF-8), `stdtime` | the errno values are FreeBSD's already (`errno.rs`, `nccall.h`) |
| libm | FreeBSD `lib/msun` | per-arch `fenv` from the same tree |
| malloc | jemalloc over `mmap`/`munmap` | `NcAlloc` is the Rust side's stand-in until then |
| crt | FreeBSD `lib/csu` (`crt1`, `crti`, `crtn` per arch) | the module loader's entry (`ncplu_main`) for modules; `_start` with argv, envp and the aux vector for processes |
| C++ | libc++, libc++abi, libunwind; compiler-rt builtins | per-target runtime directories (`LLVM_ENABLE_PER_TARGET_RUNTIME_DIR`) |
| Headers | FreeBSD `include/`, the `sys/` subset the above needs, `machine/` per ISA | `<sys/auxv.h>` included |

### 3.2 What the kernel owes it

| libc needs | Served by | Status |
|---|---|---|
| `write`, `read`, `close`, `_exit`, `getpid`, `mmap`, `munmap`, `mprotect`, `clock_gettime`, `nanosleep`, `getrandom` | POSIX-class `nccall`s (NCCALL.md §6) | **done** on x86-64 (the subset there) |
| `getentropy(3)` | FreeBSD's, over `getrandom(2)` | libc only |
| `elf_aux_info(3)`: `AT_HWCAP`, `AT_HWCAP2`, `AT_PAGESZ`, … | FreeBSD libsys `auxv.c` over the aux vector the loader passes, with FreeBSD's `AT_*` numbers and `HWCAP_*` bits per ISA | planned; it is how OpenSSL and AWS-LC find AES/PMULL/SHA/vector crypto off x86 (§6.3) |
| `open`, `fstat`, `lseek`, `readdir` … | NCFS | planned (NCFS.md) |
| `posix_spawn` | `nc::SPAWN` (32), NetBSD's semantics | number fixed; returns `ENOSYS` |
| threads (`thr_new`, `_umtx_op` under FreeBSD's libthr) | processes and a scheduler | planned; single-threaded until then |
| signals | — | none: anything that probes the CPU by catching `SIGILL` must use `elf_aux_info` instead |

### 3.3 System calls come from libc

OpenBSD restricts every system call to the call sites `libc` declares
(`pinsyscalls(2)`); the kernel refuses one from anywhere else. NanoChronometer
already checks the site of NC-class calls, and every inline `nccall` records
its site in `nccall_pins` (NCCALL.md §7). When the loader registers those
sections (NCCALL.md §12), a module's system calls are exactly libsys's stubs
plus the sites it declared.

What that means for language runtimes that make raw system calls: they go
through nclibc, as Go has on OpenBSD since Go 1.16 for the same reason. A
`GOOS=nanochronometer` port takes OpenBSD's road, not FreeBSD's.

---

## 4. Rust: from `nanochrono-sys` to `std`

### 4.1 Now

`#![no_std]` with `nanochrono-sys` (`nccall!`, `posix::*`, `print!`,
`NcAlloc`), built with `-Zbuild-std=core,alloc,compiler_builtins` for the
targets of §2.1. `crates/nanochrono-plugins/ncsys-demo` is the example and
the test.

### 4.2 `std`, measured

`-Zbuild-std=std,panic_abort` for `x86_64-unknown-nanochronometer` on rustc
1.101 nightly (2026-10-02) fails first with "Using no_threads implementation
on a target with threads". With `"singlethread": true` in the target, four
`sys` modules are left with no arm for an unknown OS and stop the build; the
rest of the platform layer falls back to std's `unsupported` code, which
builds and answers `Unsupported` at run time:

| `library/std/src/sys/…` | Today | What fills it for NanoChronometer |
|---|---|---|
| `alloc` (`imp`) | build error | `GlobalAlloc` over `mmap`/`munmap` (today's `NcAlloc`; jemalloc's when nclibc exists) |
| `io/error` (`errno`, `decode_error_kind`, `is_interrupted`, `format_error`) | build error | FreeBSD's errno table — `nanochrono_sys::Errno` |
| `random` (`fill_bytes`), and so `HashMap`'s keys | build error | `getrandom` (POSIX class 563) |
| `thread_local` (`key`) | build error | `no_threads` while `singlethread`; a key on the thread pointer when threads exist |
| `pal` (fs, time, args, env, stdio, process, net) | `unsupported` | `sys/pal/nanochronometer` over `nanochrono-sys`: stdio and time now, fs with NCFS, process with `SPAWN` |

That is the work list of `std::sys::pal::nanochronometer` — the shape of
std's FreeBSD layer over `libc`, here over `nanochrono-sys` (NCCALL.md §10).
It starts `singlethread`, like the targets of the other systems that began
without threads. The target JSONs become a tier-3 rustc target when the PAL
is upstreamed; rustc itself runs on NanoChronometer only after that.

### 4.3 The other languages

| Language | Path |
|---|---|
| C, C++, assembly | nclibc and libc++ (§3); assembly needs nothing beyond NCCALL.md §4 |
| Rust | §4.1 now, §4.2 next |
| Zig | until Zig's target list knows the OS, `<arch>-freestanding` objects calling nclibc through `@cImport` of its headers, linked by the SDK |
| Go | a `GOOS` port whose runtime calls nclibc (§3.3) |

---

## 5. `nctoolchain.ncpkg`

The compiler is a package, not part of the system image: a machine that
never compiles never carries it.

```text
sudo ncpkg install nctoolchain.ncpkg
cc -O2 hello.c -o hello
```

### 5.1 One binary

A package has **one** app — `app.entry`, the same under every
`ncapp/<arch>/` — and its commands are launchers that all start that entry
(`#!ncapp /apps/<id>/<entry>`, NCPKG.md §5). A toolchain of separate
executables does not fit; LLVM's multicall build does exactly what the
format asks for:

* `LLVM_TOOL_LLVM_DRIVER_BUILD=ON` builds one executable, `llvm`, holding
  every tool built with `GENERATE_DRIVER` — clang, lld, llvm-ar, llvm-nm,
  llvm-objcopy, llvm-objdump, llvm-readobj, llvm-size, llvm-symbolizer,
  llvm-cxxfilt among them (llvm-strings is not).
* It dispatches on `argv[0]`'s stem — exact name first, then a name ending
  in a tool's (`x86_64-unknown-nanochronometer-clang` is clang) — or on its
  first argument (`llvm clang …`). A tool answers to its own name and its
  symlinks' names with `llvm-` dropped (`nm`, `ar`, `ranlib`, `objcopy`,
  `strip`, `readelf`, `addr2line`, …), plus the hidden aliases the driver
  build adds (`ld` for lld, `c++filt`).
* clang's aliases come from `CLANG_LINKS_TO_CREATE` (default
  `clang++ clang-cl clang-cpp`); the package builds with
  `clang++;clang-cpp;cc;c++;cpp`, and clang picks C, C++ or the
  preprocessor from the name (`cc`, `++`, `cpp`).

So the launcher's name must reach the program as `argv[0]` — a requirement on
the exec path, recorded here so `SPAWN` honours it.

`app.commands` (at most 16):

```text
cc  c++  cpp  clang  clang++  ld.lld  ld  ar  ranlib  nm  objcopy  objdump  readelf  size  addr2line  c++filt
```

### 5.2 Inside the package

Paths obey NCPKG.md §2: `ncapp/<arch>/`, `res/…`, at most **8 components**.
The C++ headers decide the shape: LLVM's `libcxx/include` holds 1,726 files
nested up to three directories deep, so `res/include/c++/v1/a/b/c/x.h` is
exactly 8 — a `res/sysroot/` level in front would push 25 of them to 9, and
the package would be refused.

```text
ncpkg.meta
icon.png
ncapp/<arch>/llvm.ncapp                      the multicall binary, one per machine type
res/etc/<triple>.cfg                         §2.3, one per target ISA
res/include/…                                nclibc headers (shared by every target)
res/include/c++/v1/…                         libc++ headers
res/include/<triple>/…                       machine/ headers; libc++'s __config_site
res/include/openssl/…                        OpenSSL's headers (§6.4)
res/lib/<triple>/crt1.o crti.o crtn.o        start files
res/lib/<triple>/libc.a libm.a               nclibc
res/lib/<triple>/libc++.a libc++abi.a libunwind.a
res/lib/<triple>/libcrypto.a libssl.a        OpenSSL (§6.4)
res/aws-lc/include/…                         AWS-LC's headers, its own prefix (§7.3)
res/aws-lc/lib/<triple>/libcrypto.a          AWS-LC, symbols prefixed
res/clang/include/…                          clang's own headers (237 in clang 18)
res/clang/lib/<triple>/libclang_rt.builtins.a
```

Headers and libraries are data to the compiler — the same bytes whatever
machine it runs on — so they live in `res/`, stored once. Every target's
sysroot ships, so every NanoChronometer machine cross-compiles for the other
eight with nothing more installed.

### 5.3 On disk

```text
/apps/org.nanochronometer.nctoolchain/llvm.ncapp      this machine's binary
/apps/org.nanochronometer.nctoolchain/res/…           §5.2's res/, unchanged
/usr/bin/cc … /usr/bin/c++filt                        16 launchers, "#!ncapp /apps/org.nanochronometer.nctoolchain/llvm.ncapp"
/var/lib/ncpkg/meta/org.nanochronometer.nctoolchain.meta
```

### 5.4 How clang finds its pieces

Built in, so nothing depends on the working directory or the environment:

| CMake | Value | Effect |
|---|---|---|
| `LLVM_DEFAULT_TARGET_TRIPLE` | the machine's own triple (§2.1) | `cc` builds for this machine |
| `CLANG_RESOURCE_DIR` | `res/clang` (relative to the binary) | `/apps/<id>/res/clang`: its headers and builtins |
| `CLANG_CONFIG_FILE_SYSTEM_DIR` | `/apps/org.nanochronometer.nctoolchain/res/etc` | clang loads `<triple>.cfg` from there by itself; each holds `--sysroot=<CFGDIR>/..` (`res/`) |
| `CLANG_DEFAULT_LINKER`, `CLANG_DEFAULT_RTLIB`, `CLANG_DEFAULT_CXX_STDLIB`, `CLANG_DEFAULT_UNWINDLIB` | `lld`, `compiler-rt`, `libc++`, `libunwind` | no GCC anywhere |
| `LLVM_TARGETS_TO_BUILD` | `X86;AArch64;ARM;PowerPC;RISCV` | the nine ISAs, nothing else |

### 5.5 The manifest

```toml
id = "org.nanochronometer.nctoolchain"
name = "NanoChronometer toolchain"
version = "1.0.0"                       # its own; the LLVM version is in the summary
type = "cli"
license = "Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND ISC AND MIT AND SunPro"
summary = "clang, lld and the LLVM binutils; nclibc, libc++, OpenSSL and AWS-LC for all nine ISAs"

[creator]
name = "NanoChronometer"

[app]
entry = "llvm.ncapp"
ring = 3
capabilities = ["log"]
commands = ["cc", "c++", "cpp", "clang", "clang++", "ld.lld", "ld", "ar", "ranlib",
            "nm", "objcopy", "objdump", "readelf", "size", "addr2line", "c++filt"]
categories = ["Development"]

[permissions]
fs = [{ path = "$HOME", access = "rw" }, { path = "$TMP", access = "rw" }]
```

Ring 3, signed `creator-ring3`. A compiler needs no privilege: a `.ncdri` it
builds gets its own ring-0 signature (NCPKG.md §4); compiling one does not
make the toolchain a ring-0 program.

`license` is every licence of every file, joined by `AND` — the manifest's
grammar (NCPKG.md §3) is identifiers joined by `OR`/`AND`, with no
parentheses and no SPDX `WITH`. LLVM's exact terms are
`Apache-2.0 WITH LLVM-exception`; the exception only adds permissions, so
`Apache-2.0` is the stricter reading, and `THIRD-PARTY-LICENSES.txt` inside
the package carries every text exactly. Accepting `WITH` would change what a
signed manifest may say, so it is a format decision, listed in §9.

### 5.6 Against the format's limits

| Limit (NCPKG.md §10) | The package |
|---|---|
| 4,096 files | ≈ 2,500: libc++ ~1,700, clang's 237, nclibc and OpenSSL/AWS-LC headers some hundreds, ~15 files × 9 targets, one binary per architecture carried |
| 256 MiB per file, decoded | the `llvm` binary: Ubuntu's clang 18 is 123 MB of libLLVM (every backend) + 65 MB of libclang-cpp + lld; one static binary with five backends fits, and its debug information goes to the `-debug` archive (CLAUDE.md), not here |
| 1 GiB package, 2 GiB decoded | nine copies of `llvm` would press on it; the release builds **one package per machine type** (`arch = ["<one>"]`, which the format allows) with every target's sysroot in each |
| 8 components, 255 bytes | §5.2 |

### 5.7 What the system needs first

`SPAWN` (`cc` runs the compile in-process, but `ld.lld` is a second process),
NCFS read-write, file-backed `mmap` (what LLVM and lld use for their inputs
and outputs where the system has it), and nclibc with C++ support. Until then everything here runs on a host, and the package is
built the same way the rest of a release is.

### 5.8 How it is built

`packaging/nctoolchain/build.sh` (planned), by the rules every release
follows (CLAUDE.md): `-O2` by default, any `OPT=` level, symbols never
stripped, debug information moved into the `-debug` archive, build paths
remapped.

1. On the build host, for each target: nclibc, then compiler-rt builtins,
   libunwind, libc++abi, libc++ (LLVM's runtimes build, per-target
   directories) — the sysroot.
2. OpenSSL and AWS-LC for each target against it (§6, §7).
3. LLVM itself, as a canadian cross: built on the host, **for** each
   machine type, linked against that machine's sysroot.
4. `ncpkg build` per machine type; `ncpkg sign --role creator-ring3`.

---

## 6. OpenSSL

OpenSSL 3 is Apache-2.0, the project's own licence: it is built, linked and
shipped as is, its notices with it.

### 6.1 The target

`Configurations/50-nanochronometer.conf`, loaded through
`OPENSSL_LOCAL_CONFIG_DIR` (no patch to OpenSSL's tree), declares one target
per ISA inheriting OpenSSL's BSD targets — the system's errno, `mmap` and
ELF conventions are FreeBSD's — and changes compiler, flags and threads:

| NanoChronometer target | Inherits | `asm_arch` | `perlasm_scheme` |
|---|---|---|---|
| `nanochronometer-x86_64` | `BSD-x86_64` | `x86_64` | `elf` |
| `nanochronometer-x86` | `BSD-x86-elf` | `x86` | `elf` |
| `nanochronometer-aarch64` | `BSD-aarch64` | `aarch64` | `linux64` |
| `nanochronometer-armv7` | `BSD-armv4` (`-march=armv7-a`) | `armv4` | `linux32` |
| `nanochronometer-ppc` | `BSD-ppc` | `ppc32` | `linux32` |
| `nanochronometer-ppc64` | `BSD-ppc64` (+ `-mabi=elfv2`) | `ppc64` | `linux64v2` |
| `nanochronometer-ppc64le` | `BSD-ppc64le` | `ppc64` | `linux64le` |
| `nanochronometer-riscv32` | `BSD-riscv32` | `riscv32` | `linux32` |
| `nanochronometer-riscv64` | `BSD-riscv64` | `riscv64` | `linux64` |

PPC64 BE is the one change of scheme: `BSD-ppc64` emits ELFv1
(`linux64`), and NanoChronometer's ring 3 is ELFv2 on both endiannesses
(§2.1), which perlasm writes as `linux64v2`. OpenSSL's `Configure` makes
that switch by itself only for a target named exactly `linux-ppc64` or
`BSD-ppc64` whose compiler predefines `_CALL_ELF == 2`; a target of another
name sets the scheme itself.

### 6.2 Options

| Build | Options |
|---|---|
| Today (single-threaded processes, no sockets, no `dlopen`) | `no-threads no-sock no-dso no-module no-shared no-apps no-ui-console no-tests` |
| The BENCH plugins (§8) | the above + `no-stdio no-posix-io`: libcrypto alone, no `FILE`, no file descriptors |
| Later | drop `no-threads` with threads, `no-sock` with the network stack (SYSTEM.md §5), `no-shared` with `.ncdyn` loading |

`no-asm` is never used: the assembly is the point.

### 6.3 Three porting points

1. **Entropy — no change.** With the default `OPENSSL_RAND_SEED_OS`,
   `providers/implementations/rands/seeding/rand_unix.c` calls a weak
   `getentropy()` on any `__GNUC__` + `__ELF__` system that is not FreeBSD,
   NetBSD or DragonFly. clang defines both (§2.2) and nclibc provides it
   (§3.2): OpenSSL seeds from the kernel's RNG unchanged.
2. **CPU capabilities.** x86 needs nothing: `OPENSSL_ia32_cpuid` uses
   `CPUID` and `XGETBV`, legal at ring 3. Elsewhere OpenSSL asks the OS:
   `crypto/armcap.c` and `crypto/ppccap.c` call `elf_aux_info()` only
   under `__FreeBSD__`/`__OpenBSD__` and otherwise fall back to catching
   `SIGILL` — which needs signals (§3.2). The port adds
   `__NanoChronometer__` to that branch. `crypto/riscvcap.c` reads the
   `OPENSSL_riscvcap` variable or Linux's hwprobe; the port reads
   `elf_aux_info()` there too (RISC-V's Z-extensions — Zkn, Zvkned, Zvkg,
   Zvknha/b — in `AT_HWCAP2`, bits NanoChronometer assigns from the device
   tree's `riscv,isa-extensions`).
3. **Threads.** `no-threads` until the system has them (§6.2).

### 6.4 Built and shipped

The perlasm scripts run on the build host — FreeBSD's
`secure/lib/libcrypto/Makefile.asm` is the recipe, script by script and
flavour by flavour — so neither the target nor `nctoolchain` needs Perl. The
static libraries and headers go into every target's sysroot (§5.2), as
FreeBSD ships OpenSSL in its base system: anything the toolchain builds can
link `-lcrypto` with no other package. A shared `libcrypto.ncdyn` follows
when `.ncdyn` loading exists, as an `openssl` package of type `lib`
(NCPKG.md §6).

---

## 7. AWS-LC and aws-lc-rs

### 7.1 AWS-LC

Built with CMake from a toolchain file per target (§2.1, the sysroot of
§5.2). `generated-src/` carries the pre-generated assembly, so neither Go
nor Perl is needed — for `linux-x86_64`, `linux-x86`, `linux-aarch64`,
`linux-arm` and `linux-ppc64le` (the ELF flavours are what NanoChronometer
links). On PPC64 BE, PPC32 and RISC-V, AWS-LC compiles its C
implementations: `include/openssl/target.h` recognises all nine ISAs, but
ships no assembly for those four. `GENERATE_RUST_BINDINGS=ON` (it runs
`bindgen-cli`) installs the Rust bindings beside the library, as
`share/rust/aws_lc_bindings.rs`. `BORINGSSL_PREFIX` with
`BORINGSSL_PREFIX_SYMBOLS` (the list of symbols) prefixes them, so a program
may link AWS-LC and OpenSSL together; making the prefix headers runs Go on
the build host, unless ready-made ones are given with
`BORINGSSL_PREFIX_HEADERS`. Prefixing excludes AWS-LC's symbol versioning,
which NanoChronometer does not use.

### 7.2 Porting points

1. **The OS.** `target.h` maps `__FreeBSD__` to `OPENSSL_FREEBSD`, and so
   on; an OS it does not know gets no macro. Add `OPENSSL_NANOCHRONOMETER`
   from `__NanoChronometer__`.
2. **Entropy.** `crypto/rand_extra/internal.h` picks
   `OPENSSL_RAND_GETENTROPY` for macOS, the BSDs, Solaris and WASM, and
   **`/dev/urandom`** for an OS it does not know — which NanoChronometer has
   not got. Add `OPENSSL_NANOCHRONOMETER` to the `getentropy` list.
3. **CPU capabilities.** `crypto/fipsmodule/cpucap/` has one file per OS
   (`cpu_aarch64_freebsd.c` with `elf_aux_info`, `cpu_aarch64_linux.c`, …;
   `cpu_ppc64le.c` uses `elf_aux_info` off Linux); NanoChronometer takes
   FreeBSD's. (`cpu_aarch64_sysreg.c` reads the ID registers directly and is
   for `ANDROID_BAREMETAL`: an `MRS` of an ID register traps at EL0.)
4. **Threads.** `OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED`
   while processes are single-threaded — and its name is the reminder to
   take it out the day they are not.

### 7.3 aws-lc-sys and aws-lc-rs

Measured on aws-lc-rs 1.18.1 / aws-lc-sys 0.45.0:

* **aws-lc-rs needs `std`** ("We currently do not support a `#![no_std]`
  build"), and aws-lc-sys uses `std::os::raw`. Both wait on §4.2; until
  then a `no_std` Rust plugin declares the few AWS-LC functions it calls
  itself and links the same `libcrypto.a`.
* **No source build on the target.** `AWS_LC_SYS_SYSTEM_DIR` (or
  `AWS_LC_SYS_SYSTEM_DIR_<target>`, the triple with `_`) links an installed
  AWS-LC instead of compiling one: headers in `<prefix>/include`
  (`openssl/base.h` must be there; version at least 5.7.0, else
  `AWS_LC_SYS_SYSTEM_SKIP_VERSION_CHECK=1`), the library in
  `<prefix>/lib64` (64-bit targets, if present) or `<prefix>/lib`, the
  bindings in `<prefix>/share/rust/aws_lc_bindings.rs` (or
  `AWS_LC_SYS_SYSTEM_BINDINGS`). With a system install, bindgen is never
  run.
* **Bindings for a new target.** Without a system install, a non-FIPS
  build on a target with no pre-generated bindings uses aws-lc-sys's
  *universal* bindings — no bindgen either.

So once §4.2's `std` exists, a Rust crate using aws-lc-rs cross-compiles
from a host with

```sh
export AWS_LC_SYS_SYSTEM_DIR_x86_64_unknown_nanochronometer=$SDK/x86_64-unknown-nanochronometer/aws-lc
cargo build --target x86_64-unknown-nanochronometer -Zbuild-std=std,panic_abort
```

where the SDK's per-target prefix is laid out as aws-lc-sys expects
(`include/`, `lib/`, `share/rust/`) — AWS-LC's own `cmake --install` with
`GENERATE_RUST_BINDINGS`. On the system itself, the same prefix is
`res/aws-lc/` of §5.2, one directory of libraries per target.

### 7.4 Licences

AWS-LC: Apache-2.0 OR ISC for its own files, plus the OpenSSL and BoringSSL
notices it inherits. aws-lc-rs: `ISC AND (Apache-2.0 OR ISC)`. aws-lc-sys:
`ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND
(Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)`. All of them
go into `THIRD-PARTY-LICENSES.txt` (`tools/third-party-licenses.py`) with
everything else a release ships.

---

## 8. The BENCH tab's crypto plugins

Two `.ncplu` plugins of the built-in BENCH app (`nc.bench`): one built
on OpenSSL's libcrypto, one on AWS-LC. Each adds a mode to the tab, beside
RustCrypto's:

| Mode | Rows |
|---|---|
| 2: Crypto (RustCrypto) — today | SHA-256, SHA-512, HMAC-SHA256, AES-256-GCM, CHACHA20-POLY1305 |
| 4: Crypto (OpenSSL) | the same five, through EVP |
| 5: Crypto (AWS-LC) | the same five, through EVP and `EVP_AEAD` |

The same algorithms on the same machine with the same method: three crypto
libraries, compared row by row.

### 8.1 Where they run, and why that is still bare metal

A plugin is a ring-3 module (NCCALL.md §2.4): red zone allowed, built for
§2.1's ring-3 target. Ring 3 does not cost the measurement anything the
kernel's own modes avoid:

* **No interrupts.** The kernel enters ring 3 with `RFLAGS = 2` — IF clear,
  IOPL 0 (`ring3.rs`) — so a plugin runs as uninterrupted as Mode 2 does
  with interrupts masked, and cannot change that: at ring 3 `STI` raises
  `#GP` and `POPF` leaves IF alone.
* **The same clocks.** `TIMER_NOW`/`TIMER_NOW_END` and `PMU_OPEN`/`PMU_READ`
  are `nccall`s (`nr::nc` 7–8, 13–14): the counter Mode 2 reads, read for
  the plugin.
* **The same instructions.** AES-NI, VAES, PCLMULQDQ, SHA-NI and AVX-512
  run at ring 3 as they do at ring 0; the kernel has enabled the XSAVE state
  they need, and starts every ring-3 run from the clean state (`clean_fpu`).

FreeBSD runs OpenSSL's assembly in its kernel (`ossl(4)`, with
pre-generated `.S` for amd64, i386, aarch64, arm, powerpc, powerpc64 and
powerpc64le under `sys/crypto/openssl/`), bracketed by
`fpu_kern_enter`/`fpu_kern_leave`. A `.ncdri` doing that here would use
`fpu_begin`/`fpu_end` (NCDRI.md §6) — the right design for an in-kernel
crypto *provider*; for a benchmark, ring 3 gives the same numbers without a
ring-0 signature.

### 8.2 The interface (planned: `sdk/include/ncbench.h`)

The kernel runs the plugin once per row, as it runs any ring-3 module. Today
a ring-3 entry gets one argument (`ncplu_main(api)`); a module exporting
`ncbench_main` gets a second, a request the kernel writes into the plugin's
own writable memory before the run and reads back after it (the shared page
is read-only at ring 3):

```c
#define NCBENCH_ABI        1u
#define NCBENCH_MAX_PASSES 4u

enum {
    NCBENCH_SHA256 = 0, NCBENCH_SHA512 = 1, NCBENCH_HMAC_SHA256 = 2,
    NCBENCH_AES256_GCM = 3, NCBENCH_CHACHA20_POLY1305 = 4,
};

typedef struct {
    uint32_t size;            /* sizeof(ncbench_req_t): the table only grows */
    uint32_t abi;             /* NCBENCH_ABI */
    uint32_t alg;             /* NCBENCH_* */
    uint32_t passes;          /* 3, at most NCBENCH_MAX_PASSES */
    uint64_t buffers[NCBENCH_MAX_PASSES]; /* 16 KiB buffers per pass: {8, 16, 24}, as Mode 2 */
    /* out */
    uint64_t ticks[NCBENCH_MAX_PASSES];   /* timer ticks of each pass's timed loop */
    uint64_t cycles[NCBENCH_MAX_PASSES];  /* PMU cycles of the same window, if open */
    uint64_t overhead_ticks;  /* the same window around no work */
    uint32_t cycles_valid;
    int32_t  status;          /* 0, or why it could not run */
    char     path[64];        /* "aesni+vpclmulqdq (avx512)", "armv8-ce+pmull", "p8 vcipher", "soft" */
    char     library[64];     /* "OpenSSL 3.x.y", "AWS-LC x.y.z" */
} ncbench_req_t;

NCPLU_EXPORT int32_t ncbench_main(const nc_api_t *api, ncbench_req_t *req);
```

The plugin sets up keys and contexts **outside** the timed window, times
each pass's loop between two counter reads, and measures the same pair of
reads around an empty loop (`overhead_ticks`: two `nccall`s, reported and
subtracted). The kernel turns the result into the log `bench::run_one`
prints, so the three modes read alike.

### 8.3 What is reported

As Mode 2, per row: each pass's time, rate (MiB/s), cycles per 16 KiB call
and ns per call; mean, best and worst; the warm-up note when passes differ
by more than 15 %; plus

* **cycles per byte** = cycles ÷ (buffers × 16,384), the figure crypto
  libraries publish, when the PMU counts cycles;
* **the path that ran**, from the library's own decision —
  `OPENSSL_ia32cap_P` / `OPENSSL_armcap_P` / `OPENSSL_ppccap_P` /
  `OPENSSL_riscvcap_P`, AWS-LC's `CRYPTO_is_*_capable()` — so a number
  is never compared across different code without saying so;
* the library and its version.

### 8.4 The hardware each path uses

| ISA | AES | GHASH | SHA-2 | ChaCha20 / Poly1305 |
|---|---|---|---|---|
| x86-64 | AES-NI; VAES (AVX2, AVX-512) | PCLMULQDQ; VPCLMULQDQ | SHA-NI (SHA-256) | AVX2, AVX-512 |
| i386 | AES-NI | PCLMULQDQ | SHA-NI; SSSE3 | SSSE3 |
| AArch64 | ARMv8 Crypto Extension (`AESE`/`AESMC`) | `PMULL` | `SHA256H`, `SHA512H` | NEON, SVE |
| ARM32 | ARMv8 CE in AArch32; NEON bit-sliced | `VMULL.P64`; NEON | ARMv8 `SHA256H`; NEON | NEON |
| PowerPC 32/64 | POWER8 `vcipher` | `vpmsumd` | `vshasigmaw`/`vshasigmad` | VMX/VSX; POWER10 (ChaCha20) |
| RISC-V 64 | Zkne/Zknd (scalar), Zvkned (vector) | Zbc; Zvkg, Zvbc | Zbb (scalar), Zvknha/Zvknhb | V + Zbb (ChaCha20) |
| RISC-V 32 | Zkne/Zknd (scalar) | portable C | portable C | portable C |

OpenSSL has assembly for every cell but the "portable C" ones
(`crypto/*/asm/`); AWS-LC for the x86, Arm and PPC64LE rows (§7.1). A
machine without the extension runs the portable path, and the row says
`soft` — not a fault, as in Mode 2.

### 8.5 Packages

`org.nanochronometer.bench-openssl` and `org.nanochronometer.bench-awslc`,
type `cli`, each carrying

* `plugins/<arch>/<name>.ncplu`, registered with `host = "nc.bench"` and
  `provides = ["crypto/openssl"]` or `["crypto/aws-lc"]` — the BENCH tab
  lists a mode for every plugin under `/usr/lib/ncplu/nc.bench/`;
* an app with one command (`bench-openssl`, `bench-awslc`) that runs the
  same five rows from the terminal and prints the same log;

both with capabilities `timer` and `pmu` and libcrypto linked in statically
(`no-shared`, §6.2). The format has no package of plugins alone — `lib`
must carry a library, `gui` and `cli` an app — and the command is worth
having anyway, so no format change is needed.

---

## 9. Order of work

1. nclibc's first cut on x86-64: libsys generated from the existing
   numbers, libc, crt, `getentropy`, `elf_aux_info` with the aux vector from
   the module loader.
2. OpenSSL's libcrypto for x86-64 against it (§6), then the OpenSSL plugin
   and Mode 4 (§8) — the first number to compare with Mode 2.
3. AWS-LC and Mode 5; the other ISAs as their ring 3 arrives (NCCALL.md
   §12).
4. `std::sys::pal::nanochronometer` (§4.2); aws-lc-rs on it.
5. `SPAWN`, NCFS read-write, file `mmap`: then `nctoolchain.ncpkg` (§5).
6. The clang toolchain and the rustc target upstream (§2.3, §4.2).
7. A format decision for the maintainer: SPDX `WITH` in the manifest's
   `license` (§5.5).
