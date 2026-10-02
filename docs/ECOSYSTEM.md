# The NanoChronometer bare-metal system: design and status

What the freestanding kernel grows into beyond the instrument: three
sessions, an app and driver ecosystem with its own file types and trust
model, users, an installer and a filesystem. This is the specification the
code follows; each section says what is built and what is not yet.

Status keys: **done** (built and booted under QEMU), **partial**, **planned**.

## 1. Sessions — done

One kernel, chosen on the command line (`mode=`), one GRUB entry each:

| GRUB entry | `mode=` | What runs |
|---|---|---|
| NanoChronometer | `classic` (default) | the instrument, full screen |
| NanoChronometer Desktop Experience | `desktop` | windows, taskbar, apps (`src/desktop/`) |
| NanoChronometer CLI | `cli` | a plain text terminal and a Unix-like shell (`src/cli.rs`, `src/shell/`) |
| … CLI, Spanish keyboard | `cli kbd=es` | the same with the `es` layout |

Off x86 the command line is the device tree's `/chosen/bootargs`.

The CLI is **plain text by default**: light grey on black, no colours, no
coloured prompt — a console, not a GUI dressed as one. `color on` opts in.
Its `nanochrono` command is the hosted CLI's command set with the same
options and output; what needs an operating system (`ntp`, `tls`) says so.
`top` shows CPU activity (APERF/MPERF, AMU, PURR), effective frequency, IPC,
the loop's phases and the desktop's apps, and memory pool by pool.

The **stopwatch is essential**: built in, never an app to install; a CLI
command and a desktop app that cannot be removed. The desktop's taskbar
clock reads `hh:mm:ss:mmm:uuu:nnn` — a NanoChronometer, not a phone clock.

## 2. File types — planned (the format work is next)

| Type | What it is |
|---|---|
| `.ncplu` | A **package**, like an XAPK: a manifest, one `.ncapp` per architecture, `.nsdyn` libraries, shared assets (icon, data). One download for every architecture: assets are stored once, code per architecture. Installs as an **app** (a VM manager, a browser), an **extension** of a built-in app (a codec pack for the players: "ffmpeg plugin for NanoChronometer players", vgmstream for console formats), or **terminal commands** (NanoSSL, a BoringSSL fork). |
| `.ncapp` | One app for one architecture: the flat module format the loader maps (today's `.ncplu` single module, with an architecture and a kind added). |
| `.nsdyn` | A shared library loaded at run time; installed in `/usr/lib` or carried inside a package. Libraries such as forks of BoringSSL, FFmpeg, libvirt, liboqs or wolfSSL are the intended kind. |
| `.ncar` | A static library archive (LLVM `llvm-ar`), linked into an `.ncapp` by the SDK. |
| `.ncdri` | A driver module for hardware the kernel does not build in (Intel ME/HECI, Android MTP, …). Essential drivers stay in the kernel. No licence header is required (no `MODULE_LICENSE`). |

### Package metadata

* **Licences**: SPDX identifiers — `CC0-1.0`, `MIT`, `Apache-2.0`,
  `BSD-2-Clause`, `BSD-3-Clause`, `GPL-2.0`/`GPL-3.0`, `AGPL-3.0`,
  `LGPL-2.1`/`LGPL-3.0`, `Proprietary` — and dual licences (`MIT OR
  Apache-2.0`), each shown with a plain-language explanation for newcomers.
* **Icon**, title, description, version.
* **Creator**. None given: anonymous, which the launch card flags as
  suspicious for a ring-0 plugin or an `.ncdri`; it still runs.
* **Badge status**, from the signatures (below).

### The SDK — partial

LLVM throughout: clang, ld.lld, llvm-ar, llvm-objcopy, for every
architecture from one toolchain (`sdk/`). C plugins build today
(`sdk/Makefile`); packages, libraries, static archives and drivers are the
format work above.

## 3. Trust — planned (today: two roots, creator ✅ and tree 🌳)

Four creator-held roots, each a hybrid **ML-DSA-87 + P-521** key pair, and
a signature from one grants only its own ring:

| Badge | Signature | Grants |
|---|---|---|
| ✅ green check | creator, ring 3 | a plugin or driver made by the creator, ring 3 |
| 🌳 tree root | creator, ring 0 | a ring-0 plugin or driver made by the creator |
| 🔵 blue check | verification, ring 3 | a third party's plugin, certified by the creator, ring 3 |
| 🔵 blue check | verification, ring 0 | a third party's ring-0 plugin or driver, certified — runs in ring 0 without the community switch |

A ring-3 signature never grants ring 0: a music plugin signed for ring 3
cannot become kernel code, however it is signed.

**Owner keys (MOK)**: the machine owner's own keys, enrolled in UEFI NVRAM
the way shim's MOK list is (a file on the state partition without UEFI).
Self-signatures accept Ed25519, RSA-2048+, ECDSA P-256/P-384/P-521, ML-DSA-65
and ML-DSA-87, and hybrids of them.

**Enable Ring0 Community Modules and Drivers**: off by default; without it an
unsigned or self-signed ring-0 plugin or driver is refused.

**No private key is ever in the repository** — not hard-coded, not
committed: `.gitignore` keeps key files out, the build reads only public
keys, from outside the tree.

## 4. NCVBS — planned

NanoChronometer Virtualization-Based Security: kernel integrity in the
spirit of Windows VBS/HVCI. **On by default**; Settings has **Disable
NCVBS**, off by default. Layers: W^X over the kernel image (text read-only
and executable, data never executable) with CR0.WP, SMEP and SMAP; a
measured image checked against its boot-time hash; and with VT-x, the same
permissions enforced from a hypervisor's EPT, so even ring 0 cannot write
kernel code.

## 5. Processor controls — done

`src/cpu_control.rs` with the policy in `nanochrono_core::cpu_control`
(host-tested): every control bit is switched on only where CPUID or the ID
registers say the feature exists. x86: CR4.TSD cleared; PSE, PGE, PCE,
OSFXSR, OSXMMEXCPT, UMIP, VMXE, SMXE, FSGSBASE, PCIDE set where supported;
OSXSAVE only with AVX; CR0.PG (i386 now pages, with a PSE identity map).
AArch64: FP/AdvSIMD, SVE and SME traps off and ZCR/SMCR lengths at the
maximum at every level, EL0 counter and PMU access, HCE at EL3, 16-bit
ASIDs. ARM32: HYP traps cleared and HYP left for SVC, VFP/NEON on, exception
vectors, the MMU and caches on. RISC-V: Sv39/Sv32 paging, U-mode counters.
`cat /proc/cpuctl` shows every decision and why.

## 6. Users — planned

A first-boot (installer) wizard creates the administrator (`sudo`) user.
Passwords are **always hashed**; there is no plain-text format at all.

| Method | Parameters |
|---|---|
| **Argon2id** (default) | m = 64 MiB, t = 3, p = 1 (OWASP minimum m = 19 MiB, t = 2 on small machines) |
| PBKDF2-HMAC-SHA-512 | 210 000 iterations |
| bcrypt | cost 12; the password pre-hashed with HMAC-SHA-512, since bcrypt reads 72 bytes |

A random salt (16 bytes, NC_RNG in TRUE mode) is mandatory; a pepper (32
bytes, kept in NVRAM or the state partition, never with the hashes) is
applied — Argon2id's own secret input, an HMAC key for the others. The
method is chosen under the wizard's advanced options.

## 7. Installation and disks — planned

* Root filesystem: **NCFS** (NanoChronometer's own filesystem) by default,
  for speed; exFAT or FAT32 on request. The ESP is always FAT32.
* NCFS elsewhere, to read the crash dumps it holds: on Linux through FUSE
  (ring 3, from the GUI — the **recommended** way) or the `nanochrono`
  kernel module (ring 0, `mount -t ncfs`); on Windows through the `.sys` or,
  recommended because of driver signing, the GUI's own reader; natively on
  bare metal, where NCFS is the system's own filesystem.
* Paging: a page **file** (Windows style: on the root filesystem, resizable,
  no repartitioning) or a swap **partition** (Linux style: contiguous, no
  filesystem overhead, fixed size), with the trade-offs explained in the
  installer.

## 8. Apps — partial

Built in (essential): Stopwatch, Terminal, Task Manager, Settings, Files,
Gallery (**JPEG and PNG only**), Player (**WAV, MP3, MP4** — mainstream
formats only), Benchmark. Anything beyond — other image formats, exotic or
console audio formats — is an extension package, so the ISO stays small.

Apps as packages: VM manager (VT-x; NanoChronometer inside NanoChronometer),
browser, games (Snake in tree; DOOM is GPL and stays out of the tree, as an
external package the loader supports).
