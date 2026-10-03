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

## 2. File types — done (formats and the package manager: docs/NCPKG.md)

| Type | What |
|---|---|
| `.ncpkg` | A **package**, like an XAPK: one compressed download for every architecture — `ncpkg.meta` (the signed manifest), `ncapp/<arch>/` (the app), `lib/<arch>/` (`.ncdyn`), `plugins/<arch>/` (`.ncplu`), `res/` (assets, stored once). Types `gui`, `cli`, `lib`. Built, signed, verified, installed and removed by `ncpkg` (`tools/ncpkg` on a host; read-only `ncpkg` in the kernel's shell until NCFS). |
| `.ncapp` | One app for one architecture, ring 3 (`gui` or `cli`): the flat module format the loader maps. |
| `.ncdyn` | A shared library loaded at run time: in `/usr/lib`, counted by `ncpkg` (`ref_count`, `required_by` in `/var/lib/ncpkg/db.json`) and deleted only at zero; a package that needs a version the global copy is not keeps its own, private. Forks of BoringSSL, FFmpeg, libvirt, liboqs or wolfSSL are the intended kind. |
| `.ncplu` | A **plugin of one app**: a codec pack for the players ("FFmpeg for NanoChronometer players", vgmstream for console formats), registered with its host app by `ncpkg`, loaded by the app, never run alone. |
| `.ncar` | A static library archive (LLVM `llvm-ar`), linked into an `.ncapp` by the SDK. |
| `.ncdri` | A driver module for hardware the kernel does not build in (Intel ME/HECI, Android MTP, NCHV, …). Essential drivers stay in the kernel. No licence header is required (no `MODULE_LICENSE`): none means proprietary, and nothing is ever marked "tainted". (Loading at boot: planned.) |

### Package metadata

* **Licences**: SPDX identifiers — `CC0-1.0`, `MIT`, `Apache-2.0`,
  `BSD-2-Clause`, `BSD-3-Clause`, `GPL-2.0`/`GPL-3.0`, `AGPL-3.0`,
  `LGPL-2.1`/`LGPL-3.0`, `Proprietary` — and dual licences (`MIT OR
  Apache-2.0`), each shown with a plain-language explanation for newcomers.
  None given reads as `Proprietary`: all rights reserved, not "tainted".
* **Icon**, title, description, version.
* **Creator**. None given: anonymous, which the launch card flags as
  suspicious for a ring-0 plugin or an `.ncdri`; it still runs.
* **Badge status**, from the signatures (below).

### The SDK — partial

LLVM throughout: clang, ld.lld, llvm-ar, llvm-objcopy, for every
architecture from one toolchain (`sdk/`). C apps build today
(`sdk/Makefile`, as `.ncapp`), any module kind packs with `tools/ncplu.py
pack --kind app|driver|library|plugin`, and packages build from a directory
with `ncpkg build` (an `ncpkg.toml` and the tree). Static archives and
driver loading are next.

## 3. Trust — partial (packages: the four roots, checked by `ncpkg` at install; the module loader: two roots, creator ✅ and tree 🌳)

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

Packages implement this today (docs/NCPKG.md §4): every signature signs
`"NCPKG-SIG-2" ‖ role ‖ SHA-512(the manifest's signed bytes)`, so it covers
every file and cannot move between roles; a signature present and failing
refuses the package; `ncpkg install` refuses ring 0 without `creator-ring0`
or `verify-ring0` unless the community switch is on. The module loader still
decides a running module's privilege from the module's own signature, with
the two roots it embeds; moving it to the four roles is the next step.

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

### NCHV, the hypervisor — planned

`nchv.ncdri`, exposing `/dev/nchv`: the accelerator a QEMU port runs guests
with (as `/dev/kvm` is on Linux, NVMM on NetBSD), and the layer NCVBS
stands on. Based on bhyve — FreeBSD's `sys/amd64/vmm` (BSD-2-Clause,
NetApp and Joyent; about 28 000 lines of C, adapted with its notices kept and
listed in NOTICE) and `sys/dev/vmm`, its machine-independent half — rather
than written from nothing:

1. **Prerequisites**: loading `.ncdri` drivers at boot (signed, ring 0) and a
   physical page allocator (VMCS regions, EPT tables, guest memory) — the
   kernel has neither yet.
2. **VT-x core**: VMXON, a VMCS per vCPU, EPT, the VM-exit loop for HLT,
   port I/O, CPUID, MSRs and EPT faults (`vmx.c`, `vmcs.c`, `ept.c`,
   `vmx_msr.c`, `x86.c`, `vmm.c`).
3. **`/dev/nchv`**: bhyve's `vmm_dev` surface as `nccall`s — create a VM,
   map memory, set and get registers, run, inject interrupts — and the
   `libvmmapi` counterpart in the SDK. Packages ask for it with the `nchv`
   device permission (docs/NCPKG.md §3).
4. **Devices and emulation**: vLAPIC, vIOAPIC, vATPIC, vATPIT, vHPET, vRTC
   (`io/`), and the instruction emulator for MMIO
   (`vmm_instruction_emul.c`).
5. **AMD SVM** (`amd/svm.c`, `vmcb.c`); IOMMU passthrough later.
6. **NCVBS on NCHV**: the kernel itself run as NCHV's first guest, its text
   write-protected by EPT, which needs NCHV loaded at boot as an essential
   driver rather than an optional module.

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
* Packages go into a root with the host's `ncpkg --root <dir> install …`
  (an NCFS volume through FUSE, or the staging tree an image is built from);
  on the system itself, `sudo ncpkg install` once NCFS is writable. Paths
  inside packages use an alphabet every one of these volumes accepts, and no
  two of them differ only by case.
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
