# Porting Linux kernel primitives to Windows (WDM)—NanoChronometer

This guide documents how the Linux module at `../linux/nanochrono.rs` was
ported to `kernel/windows`, and is the reference for porting other Linux
primitives to a MinGW-built Rust WDM driver. Every offset and limitation
recorded here was **verified** against the actual toolchain compilers in this
repository (see `defs/offsets-check.c`, which the Makefile compiles for both
architectures, and `defs/armddk-shim/`).

---

## 1. Build system in one glance

| Linux module (`kernel/linux`)          | Windows driver (`kernel/windows`)                     |
|----------------------------------------|-------------------------------------------------------|
| `Makefile` + `.rust` kbuild with `CONFIG_RUST=y` | `Makefile` driving `rustc` + clang mingw linker |
| `cd kernel/linux && make`              | `cd kernel/windows && make all`                       |
| x86_64 + arm64 from the host kernel    | `x86_64-pc-windows-gnullvm` / `aarch64-pc-windows-gnullvm` |
| `insmod` / `rmmod`                     | `sc create` / `sc start` / `sc delete` (see §7)       |

Toolchain (this workstation): clang-based mingw-w64 drivers in
`/home/skels/toolchains/windows-crosscompilers/bin/` at clang 23.1.0-rc3, with
`rustc 1.98` + the `*-pc-windows-gnullvm` targets installed via rustup.
Fedora's own packages provide a *GCC*-based `x86_64-w64-mingw32` but no ARM64
toolchain (`dnf` has none), hence the private toolchain path.

The Makefile performs three independent checks before linking:

1. `offsets-check` — compiles `defs/offsets-check.c` against the **real**
   mingw DDK headers for both architectures (x64 native `wdm.h`; ARM64 with
   `-D_M_ARM=100` + the `armddk-shim` include), aborting if any Rust constant
   disagrees with the ABI.
2. `dlltool` — regenerates `build/imports/ntoskrnl-{x64,arm64}.a` from
   `defs/ntoskrnl.def`.
3. `rustc` — links with `-Wl,--subsystem,native -Wl,--entry,DriverEntry`,
   `-C panic=abort`, `-C linker=<clang mingw>`, and the import lib.

The output is native `PE32+` kernel images importing **only** `ntoskrnl.exe`.

### Rust-side necessities for a kernel binary

- `#![no_std] #![no_main]`, `#[panic_handler]`, `#[no_mangle] extern "system"`
  `DriverEntry`.
- `-C panic=abort`.
- A minimal `rust_eh_personality` stub: the *distributed* `core` for the
  gnullvm targets references it even under `panic=abort`.
- Local `memcpy/memset/memmove/memcmp` (`src/mem.rs`): the prebuilt
  `compiler_builtins` pulls `memcpy` from the **CRT** (`api-ms-win-crt*.dll`),
  which kernel mode cannot import. Defining the symbols in the driver keeps
  every import inside `ntoskrnl.exe`. (rustc emits a "suspicious definition"
  warning — expected and harmless for drivers.)
- Do **not** add `-C link-arg=-lmingw32/-lmingwex/-lmsvcrt`; `-nostdlib` plus
  the local mem primitives is enough.

---

## 2. The one big difference: fault recovery (`__ex_table` vs SEH)

The Linux probes are wrapped in exception-table fixups:

```
1: vmcally
   .pushsection __ex_table      # 12-byte entries: fault insn, fixup, type
fixup:
   movq $0, faulted
```

On bare metal the probe faults (#UD / #NV), the kernel resumes at the fixup
label, and the report says "no hypervisor". This lets the module still report
VMX/SVM capability bits even when *no* hypervisor is present.

**Windows / MinGW reality (verified by disassembly):** a driver compiled with
the GCC or clang `windows-gnu` ABI has **no** usable kernel fault recovery:

- Fedora's GCC mingw does not accept `__try/__except` at all.
- clang#windows-gnu *parses* `__try/__except` but emits no funclet, no
  `.pdata/.xdata` handler, and no `_C_specific_handler` — the handler is
  silently dropped. Executing `vmcall` on bare metal would bugcheck the
  system irrecoverably.

**Consequence:** the Windows build gates every hypercall behind detection that
cannot fault:

| Probe                  | Gate (never executes on bare metal)     |
|------------------------|-----------------------------------------|
| x64 `vmcall`/`vmmcall` | CPUID leaf-1 hypervisor-present bit **or** `KeIsHypervisorPresent()` |
| arm64 `hvc #0`         | `KeIsHypervisorPresent()` (and prints `CurrentEL`) |

If you need true fault recovery (execute regardless and recover), you must
build with **MSVC/WDK**, where `__try`/`__except` under `drivers` compiles to a
real `_C_specific_handler` exception. The equivalent of the faulting-probe
abstraction is sketched in `src/hypercall.rs`'s docs; the *semantics* of the
Linux fixup are: "resume at X, eax=fault code". With SEH you would
`__try { vmcall … } __except (EXCEPTION_EXECUTE_HANDLER) { status=0 }`.

---

## 3. Primitive-by-primitive mapping

### Module lifetime

| Linux                                      | WDM                                                        |
|--------------------------------------------|------------------------------------------------------------|
| `module_init` / `module_exit`              | `DriverEntry` / `DriverObject.DriverUnload` (offset 104)   |
| `static` kernel data (`.data`/`.rodata`)   | `const` and `static mut`; reloader never swaps them        |
| version macros in `MODULE_VERSION`         | `DriverVer` in the INF                                     |

`DriverEntry` stores `DriverUnload` and the `MajorFunction[28]` dispatch
table (offset 112). `DEVICE_OBJECT` is created with `IoCreateDevice` and
`DO_DEVICE_INITIALIZING` (Flags bit 0x80) is cleared on it.

### Userspace interface

| Linux                                     | WDM                                                   |
|-------------------------------------------|-------------------------------------------------------|
| `proc_create("/proc/nanochrono", …)`      | `IoCreateDevice` + `IoCreateSymbolicLink("\DosDevices\NanoChronometer")` |
| `proc_read` → `simple_read_from_buffer`   | `IRP_MJ_DEVICE_CONTROL`, METHOD_BUFFERED              |
| off/len bookkeeping in the proc file      | `IRP.AssociatedIrp.SystemBuffer` + `IoStatus.Information` (I/O manager copies) |
| write path (`proc_write`)                 | input buffer = same `SystemBuffer` (I/O manager sizes it to max(in,out)) |
| recompute on every read                   | recompute on every IOCTL (no cached static, no locks) |

The METHOD_BUFFERED contract checked in `device_control`:

```
IRP + 184  → CurrentStackLocation             (verified offset, both arches)
  + {x64:8 ,arm64:4}  → Parameters.DeviceIoControl.OutputBufferLength
  + {x64:24,arm64:12} → .IoControlCode
IRP + 24   → SystemBuffer
IRP + 48   → IoStatus  (write Status + Information)
```

**Key ARM64 finding:** in the mingw headers `IO_STACK_LOCATION` has *different*
parameter offsets on ARM64 (4/12/16) than on x64 (8/24/32) because
`POINTER_ALIGNMENT` expands to nothing on ARM64 and the header packs the union.
The Rust code therefore keeps these as arch-specific `const` offsets (in
`src/nt.rs`) rather than `#[repr(C)]` mirrors; the C check certifies them.

### Memory

| Linux                | WDM                                                       |
|----------------------|-----------------------------------------------------------|
| `kmalloc(size, GFP_KERNEL)` | `ExAllocatePoolWithTag(POOL_NON_PAGED_NX, size, 'Nano')` (NoPaged, tag required) |
| `kfree(p)`           | `ExFreePoolWithTag(p, 'Nano')`                            |
| `virt_to_phys(p)`    | `MmGetPhysicalAddress(p)` (returns `LARGE_INTEGER`)       |
| `ioremap(phys, n)`   | `MmMapIoSpace(phys, n, MmNonCached)`                      |
| `iounmap(v, n)`      | `MmUnmapIoSpace(v, n)`                                    |
| `*(volatile u32*)(va)` | `READ_REGISTER_ULONG`/`WRITE_REGISTER_ULONG` (or a volatile raw pointer; the driver uses the volatile-pointer form for the demo readback) |
| `GFP_ATOMIC` context | PASSIVE/DISPATCH IRQL rules; allocate Nx pool at load time instead |

`ExAllocatePool2` is *not* in the mingw DDK headers — use
`ExAllocatePoolWithTag` (declared manually in `src/nt.rs`).

### Synchronization and IRQL

| Linux                     | WDM                                                            |
|---------------------------|----------------------------------------------------------------|
| `spin_lock`/`spin_unlock` | `KeAcquireSpinLock` + `KeRaiseIrql`; `KSPIN_LOCK` is `ULONG_PTR`, `KIRQL` is `UCHAR` |
| `mutex` / `down()`        | `FAST_MUTEX` via `ExAcquireFastMutex`/`ExReleaseFastMutex`     |
| per-CPU data              | `KPCR`/`IoGetCurrentProcessorNumber` or `KeGetCurrentProcessorIndexEx` |

Contention-free case: this driver keeps **no** shared mutable report state, so
it needs neither spinlocks nor fast mutexes. If you do need a `FAST_MUTEX`,
remember its actual size is **56 bytes** (not 48): `Count 4 + pad + Owner 8 +
Contention 4 + pad + KEVENT 24 + OldIrql 4 + pad = 56`.

### Logging

| Linux          | WDM                                  |
|----------------|--------------------------------------|
| `pr_info/printk` | `DbgPrintEx(DPFLTR_DRIVER0_ID, …)` or `WPP/SETUPAPI` logging |
| per-module prefix `nanochrono:` | the driver prints `NanoChronometer: …` |

Dbg output is visible with DebugView / WinDbg kernel debugging; not in the
normal event log.

### Timing

| Linux                        | WDM                                   |
|------------------------------|---------------------------------------|
| `rdtsc`/`rdtscp` delta       | `KeQueryPerformanceCounter`          |
| `read_current_timer`         | `KeQueryPerformanceCounterFrequency` |

`KeQueryPerformanceCounter` is the portable WDM choice (no TSC-frequency
guesswork); the raw `rdtsc` helpers exist in the Linux module only.

### Error-code mapping

| Linux errno           | NTSTATUS                          |
|-----------------------|-----------------------------------|
| `-EIO`                | `STATUS_IO_DEVICE_ERROR` (0xC0000185) |
| `-EFAULT`             | `STATUS_INVALID_USER_BUFFER`      |
| `-ENOSPC`             | `STATUS_BUFFER_TOO_SMALL` (0xC0000023) |
| `-ENOTTY` (bad ioctl) | `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010) |
| `0`                   | `STATUS_SUCCESS` (0)              |
| `-EINVAL`             | `STATUS_INVALID_PARAMETER` (0xC000000D) |

`NTSTATUS` is a signed `i32`; negative statuses are written as
`0xC000_XXXXu32 as i32`.

---

## 4. ABI/offsets cheat sheet (verified, both architectures)

| Symbol                                    | x64   | ARM64 |
|-------------------------------------------|-------|-------|
| `IRP.AssociatedIrp.SystemBuffer`          | 24    | 24    |
| `IRP.IoStatus.Status`                     | 48    | 48    |
| `IRP.IoStatus.Information`                | 56    | 56    |
| `IRP.Tail.Overlay.CurrentStackLocation`   | 184   | 184   |
| `IRP` size                                | 208   | 208   |
| `ISL Parameters.DeviceIoControl.OutputBufferLength` | 8  | 4 |
| `ISL … IoControlCode`                     | 24    | 12    |
| `ISL … Type3InputBuffer`                  | 32    | 16    |
| `ISL` size                                | 72    | 68    |
| `DRIVER_OBJECT.DriverUnload`              | 104   | 104   |
| `DRIVER_OBJECT.MajorFunction`             | 112   | 112   |
| `DRIVER_OBJECT` size                      | 336   | 336   |
| `DEVICE_OBJECT.Flags`                     | 48    | 48    |
| `DEVICE_OBJECT.DeviceExtension`           | 64    | 64    |
| `DEVICE_OBJECT` size                      | 328   | 328   |
| `UNICODE_STRING` / `IO_STATUS_BLOCK`      | 16/16 | 16/16 |

`KIRQL=UCHAR` (wdm.h:502), `KSPIN_LOCK=ULONG_PTR` (wdm.h:1091), both in the
common section.

The `DriverObject`/`DeviceObject`/`Irp`/`IO_STACK_LOCATION` mirrors in
`src/nt.rs` carry `const` asserts so any drift breaks the build; the C check
(`defs/offsets-check.c`) double-blinds those asserts against the real headers.

---

## 5. ARM64 `wdm.h` workaround (`_M_ARM` + `armddk-shim`)

The mingw `wdm.h` architecture chain has branches for `_M_IX86`, `_M_AMD64`
and `_M_ARM` (the last `#include <armddk.h>`), but **no `_M_ARM64` branch** —
it falls to `#error Unknown Architecture`. The Linux-side build needs:

1. `-D_M_ARM=100` (selects the ARM branch of the header);
2. `-I defs/armddk-shim` providing the `armddk.h` the header asks for (its
   real types are gated on `__aarch64__`/`_ARM64_`).

Side effects that turn out to be harmless: `ntdef.h` sets
`ALIGNMENT_MACHINE`, and `wdm.h` excludes the spinlock declarations under
`_M_ARM` (that is why the driver prefers `FAST_MUTEX`/KPC everywhere). This is
**only** needed for the C *checks* — the Rust driver declares its own ABI from
scratch and never `#include`s a DDK header.

---

## 6. Signing and deployment

Flow (Linux): `certs/make-test-cert.sh` → commits **only**
`certs/nanochrono-test.crt` (DER) while `certs-private/` (key/pem/pfx) is
gitignored. `sign.sh` signs `build/{x64,arm64}/nanochrono.sys` into
`build/signed/{x64,arm64}/` with `osslsigncode`, then `verify -CAfile` the
self-signed pair. On Windows, `autosign.bat` does the whole job: it reuses that
PFX or creates a self-signed code-signing certificate with PowerShell, signs
with `osslsigncode.exe` (WDK `signtool` as fallback), and optionally trusts the
certificate (`/trust`) and turns test signing on (`/testsigning`). `sign.bat`
calls it.

Test-signed driver lifecycle on the target:

```
autosign.bat /testsigning            # Administrator; then reboot
sc create nanochrono type= kernel binPath= C:\...\build\signed\x64\nanochrono.sys
sc start  nanochrono
python tools\query.py --wait         # prints the key=value report
sc stop   nanochrono && sc delete nanochrono
```

There is one driver and one name, `nanochrono.sys`; the directory
(`x64\` or `arm64\`) says the architecture. ARM64 Surface devices (Pro X /
Pro 9 World Edition) take `build\signed\arm64\nanochrono.sys`, signed by the
same flow.

---

## 7. Reproducing the verification (source of truth)

- `make all` — offset checks (C), dlltool import libs, two `.sys` images.
- `file build/*/nanochrono.sys` → `PE32+ … native, x86-64` / `native, ARM64`.
- `objdump -p` → `Subsystem: NT native`, `DLL Name: ntoskrnl.exe` only.
- `objdump -d` → `vmcall`/`vmmcall`/`cpuid` present on x64,
  `hvc #0` + `mrs …, CurrentEL` present on arm64.
- `make sign` → both images signed, `Signature verification: ok`.