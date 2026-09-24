# NanoChronometer — Windows kernel driver (WDM, Rust)

Cross-platform companion to the Linux module at [`../linux/`](../linux). A
ring-0 hypervisor detector for **x86_64 and ARM64** Windows, optimized for
Microsoft Surface ARM64 devices, exposing a `key=value` report — the same
output shape as the Linux `/proc/nanochrono` — through `METHOD_BUFFERED`
IOCTLs on `\\.\NanoChronometer`.

One driver, one name: `nanochrono.sys`. The build directory says the
architecture (`build/x64/`, `build/arm64/`).

```
\\.\NanoChronometer  --IOCTL 0x222004-->  version=2 arch=x86 hypercall_insn=vmcall ...
```

## Layout

```
kernel/windows/
├── src/
│   ├── main.rs        DriverEntry, dispatch table, the three IOCTLs
│   ├── nt.rs          WDM types/imports + verified offset constants (compile-time asserts)
│   ├── hypercall.rs   x64 hypercall HAL (vmcall/vmmcall by vendor), cpuid; arm64 hvc/CurrentEL
│   ├── report.rs      once-per-load probe, cache, cooldown, physical-memory demo
│   └── mem.rs         self-contained memcpy/memset/memmove/memcmp (no CRT imports)
├── defs/
│   ├── ntoskrnl.def        import library descriptor (dlltool)
│   ├── offsets-check.c     C floor-check of every Rust offset constant (both arches)
│   └── armddk-shim/        _M_ARM shim so arm64 can compile the C checks
├── certs/                  nanochrono-test.crt (public, committed)
├── certs-private/          key/pem/pfx — GITIGNORED, never commit
├── packaging/nanochrono.inf
├── tools/query.py          user-mode client (ctypes): report, --reprobe, --cooldown
├── docs/PORTING_LINUX_TO_WDM.md
├── Makefile  sign.sh (Linux)  autosign.bat + sign.bat (Windows)
```

## Build (from Linux)

```sh
tools/fetch-cross-toolchains.sh mingw   # once: llvm-mingw into ~/.cache/nanochrono/toolchains
rustup target add x86_64-pc-windows-gnullvm aarch64-pc-windows-gnullvm
cd kernel/windows
make all      # offsets checks + build/x64/nanochrono.sys + build/arm64/nanochrono.sys
make sign     # test-sign with osslsigncode -> build/signed/{x64,arm64}/nanochrono.sys
```

`TOOLCHAIN` defaults to the llvm-mingw under `~/.cache/nanochrono/toolchains`;
`make TOOLCHAIN=/path/to/bin all` points elsewhere. The images import from
`ntoskrnl.exe` only (`llvm-objdump -p` shows it).

## Signing

The certificate is **self-signed and test-only**. Windows loads a driver
signed with it only with test signing on; production signing needs an EV
certificate and Microsoft's attestation signing, which no script here can do.

**Linux** — `make sign` (`sign.sh`): creates the key pair with
`certs/make-test-cert.sh` on first use, signs both images with `osslsigncode`
and verifies them.

**Windows** — `autosign.bat` does it all in one go:

```bat
autosign.bat                   :: create or reuse the test certificate, sign both images
autosign.bat /trust            :: + install the cert in LocalMachine Root/TrustedPublisher (Admin)
autosign.bat /testsigning      :: + bcdedit /set testsigning on (Admin, reboot, Secure Boot off)
```

It reuses `certs-private\nanochrono-test.pfx` when present (from `sign.sh`),
otherwise creates a code-signing certificate with PowerShell's
`New-SelfSignedCertificate` and exports it there. It signs with
`osslsigncode` (`winget install osslsigncode`), falling back to the WDK's
`signtool`. `/trust` adds a root certificate whose private key lives in
`certs-private\` — keep that directory private and remove the certificate
(`certmgr.msc`) when you are done. `sign.bat` is kept and simply calls
`autosign.bat`.

## Hypercalls: once per load, the vendor's own instruction

**Once.** Every probe that makes the guest exit to its hypervisor — the
hypercall and the `CPUID` exit-cost loop — runs once, in `DriverEntry`, and
is cached. The report IOCTL copies the cache and never probes. A guest that
exits in a loop on a cloud host (Azure, GCP, AWS, Vultr…) reads as abuse and
gets throttled or banned; a program polling the driver must not be able to
cause that.

| IOCTL | Code | Access | Does |
|---|---|---|---|
| `REPORT` | `0x222004` | any (Admin to open) | the cached report + `hypercall_probes`, `hypercall_age_ms`, `hypercall_cooldown_s`, `hypercall_next_ms` |
| `REPROBE` | `0x22A008` | write (Admin) | runs the probes again; `ERROR_BUSY` until 10 s since the last one |
| `SET_COOLDOWN` | `0x22A00C` | write (Admin) | input: `u32` seconds, little endian. **0 removes the wait — the user assumes the provider's reaction** |

The device opens only for an elevated Administrator (or kernel code): the
create handler checks the caller's token with `SeTokenIsAdmin`, so a UAC-filtered
token is refused too. Run these from an elevated prompt.

```bat
python tools\query.py               :: the cached report
python tools\query.py --reprobe     :: once per 10 s
python tools\query.py --cooldown 0  :: no wait: YOUR risk of a provider ban
```

**The right instruction.** On x86-64 the hypercall instruction is chosen by
a mandatory HAL from `CPUID.0H` at every driver start, never at build time —
the same Windows installation (on an external SSD, say) boots on Intel one day
and AMD the next:

| Vendor | Instruction |
|---|---|
| Intel (`GenuineIntel`), Zhaoxin (`  Shanghai  `), VIA/Centaur (`CentaurHauls`) | `VMCALL` |
| AMD (`AuthenticAMD`), Hygon (`HygonGenuine`) | `VMMCALL` |
| anything else | none |

The other vendor's instruction is never executed: under most hypervisors it
is `#UD`, and an unhandled `#UD` in a driver is a bugcheck. The report says
which was chosen (`hypercall_insn=`).

## Safety model (read before loading)

The MinGW build has no kernel fault recovery (SEH is a no-op under
clang#windows-gnu — verified), so a hypercall runs only when all of these hold:

- x64: a hypervisor is reported (CPUID bit **or** `KeIsHypervisorPresent()`),
  the HAL knows the vendor, and the hypervisor is one documented to *return*
  from an unknown hypercall (KVM, Hyper-V, Xen). Otherwise the report says
  `hypercall_skipped=` and why.
- arm64: `KeIsHypervisorPresent()` and `CurrentEL == 1`; `HVC #0` with the
  SMCCC vendor-UID function, which SMCCC defines to return −1 when unknown.

Full fault recovery (executing probes unconditionally) needs an MSVC/WDK
build; the porting guide explains the mapping.

## Deployment (target machine, admin shell)

```bat
autosign.bat /testsigning                 & reboot once
sc create nanochrono type= kernel binPath= C:\path\to\build\signed\x64\nanochrono.sys
sc start  nanochrono
python tools\query.py --wait
sc stop   nanochrono
sc delete nanochrono
```

On ARM64 machines (Surface Pro X / Pro 9 World Edition) use
`build\signed\arm64\nanochrono.sys` — same name, other directory.

## License

`SPDX-License-Identifier: MIT` (distributed under the same MIT license
document used by the Linux twin; see [LICENSE-MIT](../linux/LICENSE-MIT)).
