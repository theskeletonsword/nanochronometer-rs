# NanoChronometer: the system

How the instrument becomes an operating system — the boot sequence, the
memory filesystems, the driver model, the network and USB stacks, the
hypervisor and the security stack, and what of FreeBSD and OpenBSD is
adapted so none of it is written from nothing. This is the specification
the code grows into; each section says what is **done** (built and booted
under QEMU), **partial**, or **planned**, and the companion documents go
deeper: the filesystem is [NCFS.md](NCFS.md), the packages
[NCPKG.md](NCPKG.md), the broader ecosystem [ECOSYSTEM.md](ECOSYSTEM.md),
the drivers that exist today [BAREMETAL_DRIVERS.md](BAREMETAL_DRIVERS.md),
the ring 3 ↔ ring 0 boundary [NCCALL.md](NCCALL.md), the driver ABI
[NCDRI.md](NCDRI.md), and the toolchain, C library and crypto stack
[NCTOOLCHAIN.md](NCTOOLCHAIN.md).

## 1. Not reinventing the wheel

The timing core, the filesystem, the package format and the trust model are
NanoChronometer's own, written from their specifications. The parts where a
correct implementation is enormous and well understood — the TCP/IP stack,
the USB stack, the 802.11 state machine, the VFS interface, the driver
framework, the system-call surface — are **adapted from FreeBSD and
OpenBSD**, whose sources sit in the maintainer's tree (`CLAUDE.local.md`)
and are the reference this document cites by file.

Why those two, and how adaptation stays honest:

* **Licences are compatible with Apache-2.0** and are kept. FreeBSD's core
  is BSD-2-Clause/BSD-3-Clause (`sys/net80211/ieee80211.c` BSD-2-Clause,
  `sys/netinet/tcp_input.c` BSD-3-Clause, `sys/kern/subr_bus.c` and
  `sys/amd64/vmm/vmm.c` BSD-2-Clause); much of OpenBSD, and the wireless
  drivers both ship, are the ISC "Permission to use, copy, modify, and
  distribute" licence. Every file adapted keeps its copyright notice and is
  listed in `NOTICE`. **Linux (GPLv2) is never copied** — the licences are
  incompatible (`CLAUDE.md`) — which is also why NCFS is not ext4/btrfs
  code and the Linux module in `kernel/linux` is a thin original shim.
* **UNIX ancestry, truthfully.** BSD descends from Unix; a system that
  adapts BSD code descends from it too. NanoChronometer can call itself a
  Unix descendant without the lie that a from-scratch kernel would be.
* **Adaptation, not vendoring.** The BSD subsystems assume `malloc(9)`,
  `mbuf`s, `spl`/mutexes, `newbus`, `VOP_*`. NanoChronometer gives each a
  thin shim in Rust and brings the C in behind it, file by file as the
  driver or protocol is needed, rather than forking a whole kernel. The
  rule of thumb: if it speaks to hardware or to a wire format the world
  already fixed, adapt BSD; if it is NanoChronometer's own idea (the
  instrument, NCFS, `.ncpkg`, the badges), write it.

| Subsystem | Adapted from | Licence | Reference |
|---|---|---|---|
| TCP/IP (v4/v6) | FreeBSD `sys/netinet`, `sys/netinet6` | BSD-3-Clause | `tcp_input.c`, `ip_input.c` |
| Sockets, mbufs | FreeBSD `sys/kern/uipc_*`, `sys/sys/mbuf.h` | BSD-3-Clause | `uipc_socket.c`, `uipc_mbuf.c` |
| Packet filter | OpenBSD `sys/net/pf*.c` | BSD-2-Clause | `pf.c`, `pf_norm.c` |
| 802.11 | FreeBSD `sys/net80211` | BSD-2-Clause | `ieee80211*.c` (+ its `*.md` notes) |
| WiFi drivers | OpenBSD `if_iwx`/`if_iwm`, FreeBSD `iwlwifi` | ISC | `sys/dev/pci/if_iwx.c` |
| USB stack | OpenBSD `sys/dev/usb` | ISC | `usbdi.c`, `xhci.c`, `uhidev.c` |
| VFS interface | FreeBSD `sys/kern/vfs_*`, `vnode_if.src` | BSD-3-Clause | 83 `VOP_*` operations |
| Driver model | FreeBSD newbus (`subr_bus.c`, `*_if.m`) | BSD-2-Clause | `device_if.m`, `bus_if.m` |
| Hypervisor | FreeBSD bhyve `sys/amd64/vmm`, `sys/dev/vmm` | BSD-2-Clause | `vmx.c`, `vmcs.c`, `ept.c` |
| Sandboxing | OpenBSD `pledge`/`unveil` (as a model) | ISC | `kern_pledge.c`, `kern_unveil.c` |
| System-call convention, entry and exit | FreeBSD `lib/libsys/<arch>/SYS.h`, `sys/amd64/amd64/exception.S`; OpenBSD `PINSYSCALL`, `pin_check` | BSD-3-Clause, BSD-2-Clause, ISC | NCCALL.md §1 |
| Driver ABI | NetBSD `rumpuser.h`; FreeBSD newbus, `bus_space`/`bus_dma`, `fpu_kern_enter` | BSD-2-Clause | NCDRI.md §2 |
| C library (planned) | FreeBSD `lib/libc`, `lib/libsys`, `lib/csu`, `lib/msun`; jemalloc | BSD-2/3-Clause | NCTOOLCHAIN.md §3 |

## 2. The kernel and the boot sequence — partial

* **`nckernel`** is the Ring 0 core: the freestanding
  `nanochrono-baremetal` crate. It brings up the processor
  (`cpu_control.rs`, §6), the framebuffer, the input stacks
  (BAREMETAL_DRIVERS.md), the counters and PMU, the file tree
  (`vfs.rs`), and the session the command line asks for.
* **`ncinitramdisk`** is a sealed NCFS image the loader hands over, merged
  into the file tree before any session starts (`initramdisk.rs`, NCFS.md
  §9). It carries what the first user process needs before the root is
  mounted: the verification roots' public material, the essential
  configuration (`/etc/ncinit.conf`), and — planned — `init.ncapp`, the
  first Ring 3 process, which mounts NCFS and starts the session. Its seal
  is checked against the roots the kernel embeds; `ncinitramdisk=strict`
  refuses anything but a verified ring-0 signature. **Done:** the image is
  built, sealed, shipped on every x86 ISO, and mounted and verified at
  boot. **Planned:** `init.ncapp` itself, once Ring 3 hosts a full process.

The sequence (⇒ = done today):

```
firmware ⇒ GRUB (multiboot2) ⇒ nckernel entry (boot32.S / arch entry)
  ⇒ cpu_control: enable the features the ISA actually has (§6)
  ⇒ framebuffer, serial, input, counters, PMU, NC_RNG
  ⇒ vfs::init: built-in files, /proc, /dev, loader modules,
       ncinitramdisk (seal judged, files BLAKE3-checked)
  ⇒ session::start(mode=)   [gui (default) | cli | classic]
  → (planned) init.ncapp: mount NCFS root, spawn the session in Ring 3
```

Off x86 the command line is the device tree's `/chosen/bootargs`; the
loader handover (`module2`, or the FDT initrd) is the same path.

## 3. Memory and caches — planned (design fixed)

Before the root is mounted the system runs out of RAM, and some mounts
stay in RAM for their whole life:

| Mount | What | Backed by |
|---|---|---|
| `tmpfs` | a sized, swappable in-memory filesystem (`/tmp`, `/run`) | NCFS's item trees over anonymous pages |
| `ramfs` | unswappable, for what must never page out (`/var/volatile`, early boot) | pinned pages |
| `zram` | a compressed RAM block device, used as swap first | LZ4 over a page pool (the codec is already in `nanochrono-core::lz4`) |

`tmpfs` and `ramfs` are the same VFS a disk NCFS presents (§8), with a
page-backed block device instead of a disk; `zram` is a block device that
compresses each page with the kernel's own LZ4. `/etc/ncinit.conf` in the
`ncinitramdisk` configures all three before the root mounts.

## 4. Drivers — partial

A strict split, by whether a machine can boot and be used without the
driver:

**Essential — built into `nckernel`.** The machine must reach a usable
state with only these, so they are never modules:

* **Filesystems:** NCFS, exFAT, FAT32 (the ESP).
* **Storage:** SATA (AHCI), NVMe, SCSI, CD/DVD. (Adapted from FreeBSD
  `sys/dev/{ahci,nvme}` and `sys/cam`.)
* **Low-latency input:** USB and PS/2 keyboards, mice, touchpads, I2C-HID
  — **done** (BAREMETAL_DRIVERS.md), the USB HID path adapted from
  OpenBSD `uhidev.c`/`ums.c`/`ukbd.c`.
* **Display:** the firmware framebuffer (VBE/GOP) — **done**; no vendor GPU
  driver, by design.
* **Network:** a generic low-latency WiFi path and common wired NICs, for
  the installer and updates.

**Non-essential — `.ncdri` modules, loadable into Ring 0.** Everything a
particular machine may want but need not boot with: Intel ME/HECI, Android
MTP, Wiimotes, Blu-ray, and read/write drivers for foreign filesystems
(ext4, btrfs, NTFS). An `.ncdri` is the flat module format (NCPKG.md §1):
no `MODULE_LICENSE` header is required, and a module without one is
proprietary, never "tainted". Its binary interface is **done**:
[`sdk/include/ncdri_api.h`](../sdk/include/ncdri_api.h) — one versioned
table of kernel services and opaque handles, no kernel header and no kernel
symbol, built for all nine ISAs without a red zone (NCDRI.md). Loading an
`.ncdri` at boot is signed, ring-0 work (trust, below); it is **planned**,
waiting on the physical page allocator the hypervisor also needs.

### The driver model — planned, after FreeBSD newbus

Rather than invent a device framework, NanoChronometer adapts FreeBSD's
**newbus** (`sys/kern/subr_bus.c`, the interfaces in `device_if.m`,
`bus_if.m`): a tree of devices, each a `device_t` with `probe`, `attach`,
`detach`, `suspend`, `resume`; buses that enumerate children and hand out
resources (memory, I/O, interrupts, DMA tags). The `.ncdri` loader is the
Rust counterpart of `kern_linker.c`/`link_elf_obj.c` — it relocates a
module (`ncplu.rs` already does this for Ring 3 plugins), resolves nothing
but the two stack-canary symbols, and calls `ncdri_main` with the kernel's
`nckernel_api_t`: newbus's methods, `bus_space` and `bus_dma` are reached
through that table, never by symbol, so a driver built today loads on every
kernel of the same major version (NCDRI.md §3). A driver written for
NanoChronometer implements the methods of `ncdri_driver_t`; a driver adapted
from BSD keeps its C and links a shim that presents `device_t` and
`bus_space` on top of the table.

## 5. The network stack — planned (adapted)

Bare-metal networking is what turns the instrument into a system that can
browse, update and host: the plugins the ecosystem wants (a browser, DOOM's
network play, Proton/Wine, NanoChronometer-in-NanoChronometer) all need it.
It is adapted, not written:

* **TCP/IP** from FreeBSD `sys/netinet` (IPv4) and `sys/netinet6` (IPv6):
  `ip_input.c`, `tcp_input.c`/`tcp_output.c`, `udp_usrreq.c`, the
  congestion-control modules. ~350 000 lines that are not worth rewriting.
* **mbufs and sockets** from `sys/kern/uipc_*` and `sys/sys/mbuf.h`: the
  packet-buffer and socket layer the protocols sit on.
* **802.11** from FreeBSD `sys/net80211` — the state machine, node
  management, crypto key management, virtual APs — with its own design
  notes (`DATAPATH_RECEIVE.md`, `PROTOCOL.md`) as the guide. Device
  drivers from OpenBSD (`if_iwx.c`, `if_iwm.c`) and FreeBSD's `iwlwifi`.
* **DNS and DHCP** as Ring 3 services (`.ncapp`), not kernel code.
* **The firewall** from OpenBSD **`pf`** (`sys/net/pf.c`), whose rule
  language and `pf_norm.c` scrubber are the natural fit for the hardening
  below.

### Zero-click hardening — planned, designed in from the start

A packet or a USB descriptor must never reach code that trusts it. The
defences, at the boundaries BSD already draws them:

* **Strict packet and descriptor sanitisation.** `pf`'s normaliser
  (`pf_norm.c`) reassembles and scrubs before anything parses; USB
  descriptors are bounds-checked the way `usbdi.c` and `uhidev.c` do, which
  the existing HID path already follows (`hid_report.rs` is written for
  hostile descriptors and fuzzed).
* **Isolated boundaries.** The WiFi and USB parsers run contained — the
  same fault-contained path community plugins run in today (`ring3.rs`,
  `ncplu.rs`): a crash in a descriptor parser is caught, not a kernel
  panic. Where NCHV exists (§7), the network stack can run in a microVM.
* **Sandboxed services.** Ring 3 network services are confined on the
  **pledge/unveil** model (`kern_pledge.c`, `kern_unveil.c`): a service
  declares the system calls and the paths it will use, and the kernel
  enforces it — the capability set a package already declares (NCPKG.md §3)
  is the same idea, extended to syscalls.

### System calls — partial (adapted surface)

The Ring 3 ABI is `nccall`, specified in [NCCALL.md](NCCALL.md): one
register convention per ISA, fixed for all nine and taken from FreeBSD's
libsys (OpenBSD's for ARM32's number register), with FreeBSD's call numbers
and errno values. **Done** on x86-64 (`ring3.rs`, `kstack.rs`): the
`SYSCALL` entry leaves the user stack before it pushes anything, so a
program's red zone survives every call — proven at boot, in the selftest —
the exceptions run on their own IST stacks, and the POSIX-class subset
(`write`, `mmap`, `munmap`, `clock_gettime`, `getrandom`, …) is served
beside the plugin API's calls. On **every** ISA the trap — `syscall`,
`int $0x80`, `svc`, `sc`, `ecall` — ends in one dispatcher
(`nanochrono-core::nccall`, host-tested) through a per-ISA glue that reads
the frame by the convention's register map (`src/nccall/hal.rs`); each of the
nine kernels proves it at boot through its own trap (NCCALL.md §9.5). Rust
reaches it through `nanochrono-sys`, C and C++ through
`sdk/include/nccall.h`, assembly through the same header's numbers. The full surface is modelled on the POSIX
subset FreeBSD (569 calls) and OpenBSD (349) expose — `open`, `read`,
`write`, `mmap`, `socket`, … — so adapted BSD code and ported Unix programs
find what they expect, with `pledge`-style restriction over the top. The
VFS behind the file calls is §8; the C library above the calls is
NCTOOLCHAIN.md §3.

## 6. Processor control — done

`cpu_control.rs`, policy in `nanochrono_core::cpu_control` (host-tested):
every control bit is turned on **only where CPUID or the ID registers say
the feature exists**, so the same kernel runs on a 2008 laptop and a 2025
server without a `#UD`. This is a dispatcher, not a fixed sequence
(`cat /proc/cpuctl` prints every decision and why):

* **x86:** CR4.TSD cleared (the TSC stays readable — the whole instrument
  depends on it); PSE, PGE, PCE, OSFXSR, OSXMMEXCPT, UMIP, VMXE, SMXE,
  FSGSBASE, PCIDE where supported; OSXSAVE only with AVX; the AVX feature
  bits enabled per a **CPUID dispatch** so a machine with SSE but no AVX
  never advertises AVX. CR0.NE, CR0.WP, CR4.SMEP/SMAP for W^X (§7); CR0.PG
  on i386 with a PSE identity map.
* **AArch64:** FP/AdvSIMD, SVE, SME traps cleared and ZCR/SMCR lengths at
  maximum at every level; EL0 counter and PMU access; 16-bit ASIDs.
* **ARM32:** VFP/NEON on, HYP left for SVC, exception vectors installed,
  MMU and caches on.
* **RISC-V:** Sv39/Sv32 paging, U-mode counters; (vector/`V` where present).
* **PowerPC:** the equivalents through the MSR and SPRs.

## 7. The hypervisor and the security stack — planned

* **NCHV** — a type-1/hybrid hypervisor, the accelerator a QEMU port runs
  guests with (as `/dev/kvm` on Linux, NVMM on NetBSD), exposed as
  `/dev/nchv` and asked for with the `nchv` device permission (NCPKG.md §3).
  **Adapted from bhyve** — FreeBSD's `sys/amd64/vmm` (BSD-2-Clause, ~7 800
  lines) and its machine-independent `sys/dev/vmm` — rather than written
  from nothing: VMXON and a VMCS per vCPU, EPT, the VM-exit loop
  (`vmx.c`, `vmcs.c`, `ept.c`, `x86.c`), the `vmm_dev` surface as `nccall`s,
  the device models (`vlapic`, `vioapic`, `vatpit`, `vhpet`, `vrtc`), then
  AMD SVM (`amd/svm.c`). Prerequisites: loading `.ncdri` at boot and a
  physical page allocator (ECOSYSTEM.md §4).
* **NCVBS** — Virtualization-Based Security, **on by default** (Settings
  has *Disable NCVBS*, off by default): W^X over the kernel image with
  CR0.WP/SMEP/SMAP, a measured image checked against its boot-time hash,
  and, with NCHV, the same permissions enforced from the hypervisor's EPT
  so even Ring 0 cannot rewrite kernel text.
* **NCTEE** — a Trusted Execution Environment. It prefers hardware enclaves
  (Intel TXT, AMD SEV, ARM TrustZone) and falls back to a software TEE
  (`NCTEE-SW`) backed by NCHV when there is none, for DRM playback and for
  sealing keys (NCFS encryption, §NCFS.md 12).

## 8. The filesystem — see NCFS.md

NCFS is the root by default (exFAT or FAT32 on request; the ESP is always
FAT32). It is copy-on-write, a BLAKE3 Merkle tree, with snapshots,
deduplication and LZ4/ZSTD compression, crash-safe without a journal, and
sealable (the `ncinitramdisk`). Its **VFS** — the `VOP_*` surface a mount
presents (lookup, read, write, readdir, …) — follows FreeBSD's
`sys/kern/vnode_if.src` (83 operations) so that `tmpfs`, `ramfs`, `zram`,
exFAT, FAT32 and the foreign-filesystem `.ncdri`s all present one
interface, and so adapted BSD filesystem code slots in behind it. NCFS
mounts elsewhere for forensics — on Linux through FUSE (`tools/ncfs`, the
recommended way) or a ring-0 module, on Windows through the GUI or a
`.sys`, natively on bare metal. The reader, the writer, `fsck`/scrub, the
host tool and the seal are **done**; the kernel writer and in-kernel
`ncpkg install` wait on the disk drivers and the heap.

## 9. Users and installation — planned

A first-boot wizard creates the administrator (`sudo`) user. Passwords are
**always salted and hashed** — there is no plain-text path — with a
mandatory 16-byte random salt (NC_RNG) and an optional pepper kept apart:

| Method | Parameters |
|---|---|
| **Argon2id** (default) | m = 64 MiB, t = 3, p = 1 (OWASP floor on small machines) |
| PBKDF2-HMAC-SHA-512 | 210 000 iterations |
| bcrypt | cost 12, the password pre-hashed with HMAC-SHA-512 |

Argon2id is the default because it resists GPU and ASIC cracking best; the
method is chosen under the wizard's advanced options. The installer
(`install NanoChronometer`) writes the system anywhere, choosing NCFS /
exFAT / FAT32 for the root and a page **file** (resizable, no
repartitioning) or a swap **partition** (contiguous, no filesystem
overhead), each explained. Packages are laid down with the host's
`ncpkg --root` (NCPKG.md §11).

## 10. The user environment — partial

Two sessions in the boot menu, one kernel, chosen by `mode=` (ECOSYSTEM.md
§1): the **NanoChronometer GUI** (`gui`, the default — windows, a taskbar,
apps) and the **CLI** (`cli` — a plain-text Unix-like shell, never in
colour). The classic full-screen instrument (`classic`) is off the menu but
kept, for its BENCH tab and as the test harness. The taskbar clock reads
`hh:mm:ss:mmm:uuu:nnn`; the stopwatch is essential and unremovable. **Done:**
the sessions, the
built-in apps (Stopwatch, Terminal, Task Manager, Settings, Files, Gallery
— JPEG/PNG, Player — WAV/MP3/MP4, Benchmark), the `top` and `lspmc`
commands. **Planned:** refresh-rate adaptation (Settings › Display),
multiple languages, and a terminal that accepts both Unix (`ls`, `cp`) and
DOS-style (`dir`, `copy`) syntax. Icons and wallpapers are embedded
(`tools/gen-icons.py`, `gen-wallpapers.py`); the wallpaper is changeable.
Anything beyond the mainstream formats is an extension package, so the ISO
stays small.

## 11. Status at a glance

| Area | State |
|---|---|
| Sessions, apps, instrument | done |
| Processor control (all ISAs) | done |
| NCFS: format, reader, writer, fsck, host tool, FUSE, seal | done |
| Packages: `.ncpkg`, `ncpkg`, trust, install into NCFS | done |
| `ncinitramdisk`: sealed image, kernel mount, verify | done |
| Ring 3 for community plugins (x86-64) | done |
| `nccall` convention (nine ISAs), `nanochrono-sys`, `nccall.h` | done |
| x86-64 entry: IST plan, red zone proven at boot, POSIX-class subset | done |
| Ring 3 on the other ISAs (sequences in NCCALL.md §11) | planned |
| `.ncdri` binary interface (`ncdri_api.h`), red-zone checker | done |
| `nclibc`, `std` port, `nctoolchain.ncpkg`, OpenSSL/AWS-LC crypto plugins | planned (NCTOOLCHAIN.md) |
| Codecs: BLAKE3, LZ4, ZSTD, QOI, PNG, DEFLATE | done |
| Driver loading (`.ncdri` at boot), newbus model | planned |
| Network (TCP/IP, 802.11, pf), zero-click hardening | planned |
| NCHV, NCVBS, NCTEE | planned |
| `init.ncapp`, kernel NCFS writer, installer, users | planned |
| tmpfs/ramfs/zram | planned |

The through-line: what the world already standardised — wire protocols,
bus enumeration, the VFS, the syscall surface — is adapted from BSD with
its licences kept; what is NanoChronometer's (the instrument, NCFS,
`.ncpkg`, the badges, the nanosecond everything) is its own, written from
its specification and tested against an independent implementation.
