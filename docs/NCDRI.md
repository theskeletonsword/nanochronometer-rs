# .ncdri: a stable driver ABI with no kernel headers

How a driver module talks to `nckernel` without including a single kernel
header or linking against a single kernel symbol — so a driver built today
loads on every kernel of the same major version, and a kernel update never
breaks a driver it has not changed the meaning of.

The interface is one public header, [`sdk/include/ncdri_api.h`](../sdk/include/ncdri_api.h);
the example is [`sdk/drivers/hello_ncdri.c`](../sdk/drivers/hello_ncdri.c);
`make -C sdk drivers` builds it for every architecture. Ring-0 code shares
the red-zone rules of [NCCALL.md](NCCALL.md) §2.

| Piece | Status |
|---|---|
| `ncdri_api.h`: the tables, handles, versioning, layout pins | **done** (compiles for all nine architectures, `-Wall -Wextra -Werror`) |
| Build rules, `tools/check-redzone.py` on every object | **done** |
| Packing (`tools/ncplu.py pack --kind driver --entry ncdri_main`) | **done** for x86-64 (the packer's relocations are x86-64's) |
| The kernel side: `nckernel_api_t` implemented, `.ncdri` loaded at boot | planned — waits on the physical page allocator (SYSTEM.md §4) |

---

## 1. Why no headers

A driver that includes the kernel's private headers compiles against the
kernel's private structure layouts and calls its internal functions by name.
Any change to either — a field added in the middle of a struct, a function
that gains an argument — silently breaks every driver built before it, or,
worse, does not break it visibly. Kernels that work that way can only offer
"rebuild your drivers against each release", which is exactly what a
third-party or proprietary driver cannot do.

NanoChronometer's answer is the one Windows NDIS and NetBSD's rump kernels
give: **the driver sees an interface, never an implementation.**

* No structure of the kernel's is visible to a driver: every object it
  handles is an opaque handle (`ncdri_device_t`, `ncdri_dma_t`, …) that it
  stores and passes back, never dereferences.
* No kernel symbol is linked: the only symbol a driver exports is
  `ncdri_main` (and optionally `ncdri_fini`), and the only symbols it may
  import are the two the compiler itself emits for stack canaries
  (`__stack_chk_guard`, `__stack_chk_fail`), which the loader resolves as it
  does for every module.
* Everything the driver can do comes through one table of function pointers
  the kernel hands it, `nckernel_api_t`, whose layout only ever grows.

## 2. What it is modelled on

| Model | From | What is taken |
|---|---|---|
| Version handshake; a table of services with reserved slots; opaque lock types; explicit sizes on free | NetBSD `sys/rump/include/rump/rumpuser.h` (BSD-2-Clause): `RUMPUSER_VERSION`, `rumpuser_init(version, hyp)`, `struct rumpuser_hyperup { …; void *hyp__extra[8]; }`, `struct rumpuser_mtx` | `nckernel_api_t`'s shape, `reserved[32]`, `mem_alloc`/`mem_free(p, size)`, `ncdri_mtx_t` |
| Device methods and probe priorities | FreeBSD newbus, `sys/kern/device_if.m`, `BUS_PROBE_*` | `ncdri_driver_t`'s `probe`/`attach`/`detach`/`suspend`/`resume`/`shutdown`, `NCDRI_PROBE_*` |
| Register access through accessors only; DMA memory with a bus address and explicit syncs | FreeBSD `bus_space(9)`, `bus_dma(9)` | `resource_map` + `read_N`/`write_N`/`barrier`; `dma_alloc`/`dma_bus_addr`/`dma_sync` |
| Floating point in the kernel only inside a bracket that saves the interrupted context | FreeBSD `fpu_kern_enter`/`fpu_kern_leave` (`sys/amd64/include/fpu.h`, `sys/arm64/include/vfp.h`, `sys/powerpc/include/fpu.h`) | `fpu_alloc`/`fpu_begin`/`fpu_end`, `NCDRI_FPU_NOCTX` |
| SIMD crypto inside the bracket | FreeBSD `ossl(4)`, `sys/crypto/openssl/ossl.c` (BSD-2-Clause) | the pattern for crypto drivers (§6) |

## 3. The handshake and the versioning rules

```c
NCDRI_EXPORT int ncdri_main(const nckernel_api_t *k, uint32_t k_size);
```

1. The loader relocates the module, resolves its two canary imports, and
   calls `ncdri_main` with the kernel's table and that table's size.
2. The driver checks `k->api_major == NCDRI_API_MAJOR` and that `k_size`
   reaches every service it calls unconditionally; otherwise it returns
   `NCDRI_ENOTSUP` and is unloaded.
3. It keeps `k` (in `ncdri_k`, which the inline wrappers use) and registers
   its drivers with `ncdri_register_device(&drv)`.

The rules both sides follow:

* **Major** (`NCDRI_API_MAJOR`) changes only for an incompatible change: a
  field removed or reordered, a service whose meaning changed. The loader
  refuses a module of another major.
* **Within a major, tables only grow at the end.** New services take the
  place of `reserved[]` slots, so the table's total size stays the same until
  those run out, and a driver built against an older minor reads exactly the
  fields it knows. A kernel zeroes every slot it does not implement.
* **Every table and structure that crosses carries its own size**
  (`nckernel_api_t.size`, `ncdri_driver_t.size`, `ncdri_devinfo_t.size`). A
  reader touches only fields inside the size the writer reported:
  `NCDRI_HAS(k, rng_fill)` is `k->size` reaching that field *and* the slot
  being non-NULL. A driver built against a newer minor therefore still loads
  on an older kernel and finds the newer services absent.
* **The first fields never move.** `_Static_assert`s in the header pin
  `size` at offset 0 and the version fields after it, on every architecture,
  and `ncdri_devinfo_t` at 84 bytes.
* **Errors are FreeBSD errno values**, positive, 0 for success — the same
  numbers `nccall` returns to ring 3.

## 4. Handles and contexts

| Handle | What | Model |
|---|---|---|
| `ncdri_device_t` | one device node offered to the driver | newbus `device_t` |
| `ncdri_resource_t` | a mapped register window (MMIO or ports) | `bus_space_handle_t` |
| `ncdri_dma_t` | a DMA buffer: kernel address, bus address, syncs | `bus_dmamap_t` |
| `ncdri_irq_t` | an established interrupt handler | `bus_setup_intr` cookie |
| `ncdri_mtx_t` | a lock, spin or sleep | `struct rumpuser_mtx`, `mtx(9)` |
| `ncdri_fpu_t` | a saved floating-point context | `struct fpu_kern_ctx` |
| `ncdri_module_t` | the module itself | the loader's record |

Every service is marked in the header with the context it may be called
from: **any** (interrupt handlers included) or **sleep** (probe, attach,
detach, suspend, resume, and threads). A spin lock may be taken anywhere and
never sleeps; a sleep lock never in interrupt context; `mem_alloc` in
interrupt context only with `NCDRI_MEM_NOWAIT`.

## 5. How a driver is built

Ring 0, so (the `drivers` target of [`sdk/Makefile`](../sdk/Makefile)):

| Rule | Flags | Why |
|---|---|---|
| No red zone | x86-64 `-mno-red-zone`; PPC64 `-Xclang -disable-red-zone` | an interrupt in the driver pushes onto its stack (NCCALL.md §2) |
| No FP/SIMD outside the bracket | `-mgeneral-regs-only` (x86, AArch64), `-mfloat-abi=soft` (ARM32), `-msoft-float -mno-altivec [-mno-vsx]` (PowerPC), `-march=rv{32,64}imac` (RISC-V) | the kernel does not save the FP state of what a driver interrupts unless asked (§6) |
| No C library | `-ffreestanding -fno-builtin -nostdinc` + the compiler's own headers | the table carries `memcpy`/`memset`/`memcmp` |
| Position independent, one export | `-fPIC -fvisibility=hidden`, `NCDRI_EXPORT` on `ncdri_main`/`ncdri_fini` | the loader picks the address; nothing else is visible |
| Stack canaries | `-fstack-protector-strong`, a global guard (`-mstack-protector-guard=global` where clang has it; PPC64 as `powerpc64*-unknown-none-elf -mabi=elfv2`, whose default is global, not the TLS guard of `*-linux-gnu`) | the two compiler imports the loader resolves |

Every object then goes through `tools/check-redzone.py`, which reads the
machine code instead of trusting the flags (NCCALL.md §9.3). All nine
architectures pass, at -O0 and -O2. On 64-bit PowerPC the checker tolerates
the 288-byte ELFv2 zone: LLVM saves callee-saved registers there before its
`stdu` whatever it is told (NCCALL.md §2.2), and the kernel's interrupt entry
steps over 512 bytes for exactly that reason.

```
$ make -C sdk drivers
… build/debug/drivers/x86_64/hello_ncdri.o: no access below the stack pointer
… build/debug/drivers/ppc64le/hello_ncdri.o: no access below the stack pointer
… (all nine)
… tools/ncplu.py pack build/debug/drivers/hello_ncdri.so -o …/HELLO_NCDRI.NCDRI --kind driver --entry ncdri_main
imports (2):
  __stack_chk_guard
  __stack_chk_fail
exports (2):
  ncdri_main @ 0x13d0 <- entry
  ncdri_fini @ 0x14f0
```

## 6. Floating point and SIMD in a driver

Drivers are built without FP/SIMD registers, so the compiler never puts a
value in one behind the driver's back. Code that needs them — a crypto
driver, a checksum — lives in its own translation units (or OpenSSL's
generated assembly, as FreeBSD's `ossl(4)` does), built with SIMD, and runs
only between

```c
ncdri_k->fpu_begin(ctx, NCDRI_FPU_NORMAL);
/* AES-NI, NEON, VSX, RVV … */
ncdri_k->fpu_end(ctx);
```

which saves whatever context those registers belonged to and restores it
afterwards (`fpu_kern_enter`/`fpu_kern_leave`). `NCDRI_FPU_NOCTX` skips the
save and disables preemption instead, for short sections.

## 7. Loading — planned

What the loader will do, in the order the kernel's module loader already does
it for apps (`ncplu.rs`):

1. **Read and verify.** `.ncdri` is `Kind::Driver` in the module format
   (NCPKG.md §1). Ring 0 is signed work: the creator-ring0 or verify-ring0
   role, or the owner's community switch (ECOSYSTEM.md §3). An unsigned
   driver is refused by default.
2. **Inspect.** Imports must be exactly the canary pair — anything else is a
   kernel symbol, which this ABI does not have. The module's flag says it was
   built for ring 0 (no red zone); a module built for a ring-3 target is
   refused (NCCALL.md §2.4).
3. **Relocate** into memory from the page allocator, text read-only and
   executable, data non-executable.
4. **Call `ncdri_main(&nckernel_api, sizeof nckernel_api)`.**
5. **Match**: for every device a bus enumerates (PCI, ACPI, FDT, USB), each
   registered driver's `probe` is offered an `ncdri_devinfo_t`; the best
   offer (`NCDRI_PROBE_*`) wins and gets `attach` with a zeroed softc of
   `softc_size`.
6. **Unload** (if `ncdri_fini` exists): `detach` on every device, then
   `ncdri_fini`, then the memory goes.

## 8. The example

`hello_ncdri.c` claims QEMU's `edu` teaching device (PCI 1234:11e8): maps BAR
0 through `resource_map`, checks the liveness register (it reads back the
inverse of what is written), allocates a coherent DMA buffer below 4 GiB,
establishes its interrupt, turns bus mastering on, and undoes every step in
`detach`. It shows a newer service used only when `NCDRI_HAS` says the
kernel has it. When the loader exists, `qemu-system-x86_64 -device edu` is
its test.
