# `nanochrono.ko` — optional ring 0 hypervisor detection and perf counters

**You do not need this module.** NanoChronometer detects hypervisors from
userspace through CPUID and platform signatures, and that works without any
privileges. This module only sharpens the answer.

There is **one** module, `nanochrono.ko`, and one file, `/proc/nanochrono`.
The system-wide perf counters that used to be a second module live in it too
(the `perf_*` keys below).

## What it adds

| Probe | Why ring 3 cannot do it |
|---|---|
| `VMCALL` or `VMMCALL` (x86-64), `HVC #0` (AArch64) | The instructions are only valid inside a guest. Outside one they raise an undefined-instruction fault, which userspace cannot recover from safely. A hypercall that *returns* is proof of a hypervisor — and it holds even against one that clears the CPUID hypervisor bit. |
| VMX / SVM feature MSRs | Distinguishes "not virtualized" from "not virtualized, but this CPU can host a guest". |
| Trap cost with preemption disabled | Removes the scheduling noise that makes the userspace estimate fuzzy. |
| System-wide PMU counters | One kernel perf event per CPU, summed and corrected for multiplexing. |

Every x86 probe recovers from its fault through the kernel exception tables,
so loading this on bare metal is safe: the instruction faults, the fixup marks
it unsupported, and execution continues.

## The hypercall HAL (x86-64)

Intel VMX defines `VMCALL`, AMD SVM defines `VMMCALL`, and each is `#UD` on
the other vendor's silicon unless the hypervisor chooses to emulate it. The
module never guesses and never tries both: at every load it reads `CPUID.0H`
and executes the one instruction that vendor defines.

| Vendor | Instruction |
|---|---|
| Intel (`GenuineIntel`), Zhaoxin (`  Shanghai  `), VIA/Centaur (`CentaurHauls`) | `VMCALL` |
| AMD (`AuthenticAMD`), Hygon (`HygonGenuine`) | `VMMCALL` |
| anything else | none (`hypercall_insn=none`) |

The choice is made at run time, not build time, because one installed
system — an OS on an external SSD — boots on an Intel machine one day and an
AMD one the next. The Windows driver and the bare-metal kernel apply the
same table (`crates/nanochrono-core/src/hypercall_hal.rs` is the reference).

## Once per load: the anti-DoS rule

Everything that makes a guest exit to its hypervisor — the hypercall, the
`CPUID` exit-cost loop, the `CNTPCT_EL0` read-cost measurement, and the crypto
timings that run alongside them — runs **once, when the module loads**, and
is cached. Reading `/proc/nanochrono` returns the cache (plus the live perf
counters, which are the kernel's own bookkeeping, not probes) and never makes
the guest exit. On a cloud host (Azure, GCP, AWS, Vultr…) a guest exiting in a
loop reads as abuse and gets throttled or banned; `watch cat /proc/nanochrono`
must not be able to do that.

To probe again deliberately (root):

```sh
echo reprobe > /proc/nanochrono      # EAGAIN until 10 s after the last probe
echo cooldown=30 > /proc/nanochrono  # change the wait
echo cooldown=0 > /proc/nanochrono   # remove it — YOU assume the provider's reaction
sudo insmod nanochrono.ko hypercall_cooldown=0   # the same, at load
```

The limit is enforced in the kernel, so no program can skip it. The report
says how often the probes ran and when the next is allowed:
`hypercall_probes`, `hypercall_age_ms`, `hypercall_cooldown_s`,
`hypercall_next_ms`, and `hypercall_warning=` while the wait is off. The CLI
(`nanochrono hypervisor --reprobe`, `--cooldown N`) and the GUI (RE-PROBE
button, Settings › Re-probe cooldown) write the same commands.

## Perf counters

`perf_event`, `perf_enabled`, `perf_npmu`, `perf_raw`, `perf_enabled_ns`,
`perf_running_ns`, `perf_scaled` (the multiplexing-corrected count — the one
to use). `perf_available=0` on a machine or VM without PMU events; the module
still loads. Commands (root): `echo cycles`, `echo instr`, `echo enable`,
`echo disable` into `/proc/nanochrono`. `nanochrono perf` shows them next to
the per-thread ring-3 counters.

## It is written in Rust

Like the rest of the project. That needs three things, all of which this
Makefile handles or checks:

- `CONFIG_RUST=y` in the running kernel.
- The kernel's `rust/*.rmeta` metadata, shipped with the kernel headers.
- **The exact `rustc` that built the kernel.** Rust crate metadata is version-
  locked, so a rustup toolchain will fail with `E0514` even at the same version
  number. The Makefile defaults to `/usr/bin/rustc`, the distribution compiler.
  Check with `grep CONFIG_RUSTC_VERSION_TEXT /boot/config-$(uname -r)`.

There is no Rust abstraction for kernel exception tables, so the module emits
its own `__ex_table` entries from `asm!`, in the layout
`arch/x86/include/asm/asm.h` defines. You can confirm they were emitted:

```sh
objdump -h nanochrono.ko | grep __ex_table   # 12 bytes per probe
```

## Build and load

```sh
cd kernel/linux
make                     # needs kernel headers: /lib/modules/$(uname -r)/build
sudo insmod nanochrono.ko
cat /proc/nanochrono
```

`make load` does the last two steps. `sudo rmmod nanochrono` unloads it.

The report is at `/proc/nanochrono`, mode 0644: any process can read it, and
only root can write the commands above.
The kernel's Rust crate exposes debugfs but not procfs, and debugfs is mode
0700 — which would have limited the report to root, defeating the point. So
the module declares the procfs ABI itself. That means a hand-written
`#[repr(C)]` mirror of `struct proc_ops`, which is sound only without struct
randomisation; the module refuses to build otherwise:

```rust
#[cfg(not(CONFIG_RANDSTRUCT_NONE))]
compile_error!(...);
```

The library picks the module up automatically on its next detection — nothing
to configure:

```sh
nanochrono hypervisor
```

The report line changes from `kernel module : not loaded` to `loaded (v4)`
with the hypercall results underneath and how many times the probes ran.

## The counter it times with

| Architecture | Counter | Parameter |
|---|---|---|
| x86-64 | TSC (`RDTSC`/`RDTSCP`) | — |
| AArch64 | `CNTVCT_EL0` by default; `CNTPCT_EL0` with `physical_counter=1` | `insmod nanochrono.ko physical_counter=1` |
| RISC-V 64 | `RDCYCLE`; `RDTIME` if firmware (or the hypervisor) forbids it | — |

**`physical_counter=1` works inside a VM too** — it is not refused there. It
is meant for real hardware: in a guest the hypervisor may trap every
`CNTPCT_EL0` read (KVM does whenever it must apply an offset the hardware
cannot), and under nested virtualization the trap is forwarded through a
second hypervisor, which makes it slow and unstable. The report measures it
instead of guessing:

```
counter=cntpct_el0
counter_hz=1000000000
counter_virtual_read_ns=58
counter_physical_read_ns=65
counter_physical_trapped=0
```

`counter_physical_trapped=1` (and a `counter_warning=` line when it is the
selected counter) means every read is an exit to the hypervisor.

**RDCYCLE and VMs.** S-mode may read `cycle` only if M-mode firmware set
`mcounteren.CY` (OpenSBI does on most boards) and, inside a KVM guest, only
if the host set `hcounteren.CY`. Where it is clear the read traps; the first
read carries an `__ex_table` entry (`EX_TYPE_FIXUP`), RISC-V consults the
table for illegal instructions in kernel mode, and the module falls back to
`RDTIME`, reported as `counter=rdtime` / `rdcycle_ok=0`. A guest that may
read `cycle` reads the physical hart's count — not offset like `time` — so
it is right for short intervals and meaningless across a vCPU migration.

**The AArch64 hypercall probe** runs only at EL1 with an HVC SMCCC conduit
(`smccc_conduit=hvc`). At EL2 (a VHE host) `HVC` would trap to this very
kernel and panic it, and at EL1 without EL2 it is undefined — which arm64
does *not* recover through `__ex_table`. Earlier versions relied on that
table and were unsafe on both.

Report format version 3 added the `counter*` keys; version 4 made the probes
once-per-load (`hypercall_*`), added `hypercall_insn`, and merged in the perf
counters (`perf_*`).

## Output format

One `key=value` per line at `/proc/nanochrono`. Keys are stable; the parser
ignores ones it does not know, so an older library keeps working against a
newer module.

```
version=4
arch=x86
cpu_vendor=GenuineIntel
cpu_family=intel
hypercall_insn=vmcall
vmcall_ok=0
exit_cycles=58
baseline_cycles=12
...
hypercall_probes=1
hypercall_age_ms=41230
hypercall_cooldown_s=10
hypercall_next_ms=0
perf_available=1
perf_event=cycles
perf_npmu=8
perf_scaled=123456
```

## Windows port

The same detection logic — probes, gate, report format — is ported to a
Windows kernel driver (WDM, Rust) in [`../windows/`](../windows), built for
x86_64 and ARM64 with the `*-pc-windows-gnullvm` rustc targets, as one
`nanochrono.sys`. It follows the same rules — probe once at start, re-probe
behind the 10-second cooldown, the vendor's own hypercall instruction. The
Windows build cannot rely on `__ex_table` fixups (SEH fault recovery is
unavailable under the MinGW ABI), so its hypercall probes are detection-gated
instead; the
porting guide ([`../windows/docs/PORTING_LINUX_TO_WDM.md`](../windows/docs/PORTING_LINUX_TO_WDM.md))
maps every primitive and records the verified ABI offsets.

## Licensing

This directory is **dual MIT / GPL-2.0**, not Apache-2.0 like the rest of the
project. That is a constraint the kernel imposes, not a preference:
`MODULE_LICENSE()` accepts only a fixed set of idents — `GPL`, `GPL v2`,
`GPL and additional rights`, `Dual BSD/GPL`, `Dual MIT/GPL`, `Dual MPL/GPL`,
`Proprietary` — and none of them is Apache. Anything outside that set is
treated as proprietary, taints the kernel on load, and loses access to
`EXPORT_SYMBOL_GPL` symbols. Apache-2.0 is also generally held to be
incompatible with GPLv2, which the kernel is.

`Dual MIT/GPL` is the most permissive recognised option: it loads without
tainting, and an Apache-2.0 project can redistribute it without friction. See
[`LICENSE-MIT`](LICENSE-MIT) for the MIT text and [`LICENSE-GPL`](LICENSE-GPL)
for the GPL-2.0 text.

The boundary is clean: this directory shares no code with the rest of the tree
and communicates only through the text format above.

## Caveats

- Kernel headers matching the running kernel are required to build, plus the
  distribution `rustc` that built it.
- The C version disabled preemption around the trap measurement. The Rust
  kernel crate exports no preemption abstraction, so the module takes the
  minimum over 128 rounds instead — which discards exactly the samples a
  scheduling decision would have inflated.
- Secure Boot will refuse an unsigned module. Sign it, or disable Secure Boot,
  or simply skip the module — userspace detection still works.
- `hvc` on AArch64 is only meaningful from EL1. On a host kernel running at EL2
  (VHE) the instruction has different semantics; the module reports
  `current_el` so the reading can be interpreted.

## The crypto benchmark (ring 0)

The module also times the kernel's hash algorithms and publishes what it
measured. This is the optional half of a two-part measurement:

| Half | How it reaches the algorithm | Needs |
|---|---|---|
| Ring 3 | `AF_ALG` socket: `sendmsg` + `read` per operation | nothing — always built |
| Ring 0 | a direct call, no socket, no syscall, no copy | this module |

The ring-3 half is the honest cost of *using* kernel crypto from a program,
and it is what the benchmark reports by default. It cannot separate the
primitive from the transport. This half can: the same algorithm over the same
16 KiB buffer, with none of the boundary crossing. **The difference between
the two numbers is what `AF_ALG` costs.**

Hashes only. A `shash` is one exported call over a flat buffer; a symmetric
cipher needs a request object, scatterlists and a completion, and a benchmark
that got any of those wrong would report a number for something other than
what it named.

Published as repeated `crypto=` keys, because a kernel algorithm name can
contain characters — `cbc(aes)` — with no business on the left of an `=`:

```console
$ grep crypto /proc/nanochrono
crypto_payload_bytes=16384
crypto_rounds=64
crypto=sha256,10431
crypto=sha512,24887
```

The value is **cycles**, best of `crypto_rounds`, not nanoseconds: the module
reads the same counter the userspace side does, and it has no calibration of
its own to convert with. Best rather than mean for the reason every other
measurement in this project takes a minimum — the fastest observed run is the
one least disturbed by everything else the machine was doing.

`nanochrono bench --mode kernel` picks this up automatically when the module
is loaded and says `ring 0 module: not loaded` when it is not. Nothing
requires it.
