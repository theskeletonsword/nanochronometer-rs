# .ncdri: a stable driver ABI with no kernel headers

How a driver module talks to `nckernel` without including a single kernel
header or linking against a single kernel symbol — so a driver built today
loads on every kernel of the same major version, and a kernel update never
breaks a driver it has not changed the meaning of.

The interface is one public header, [`sdk/include/ncdri_api.h`](../sdk/include/ncdri_api.h);
the drivers are [`sdk/drivers/hello_ncdri.c`](../sdk/drivers/hello_ncdri.c)
(the example) and [`sdk/drivers/qemu_stdvga.c`](../sdk/drivers/qemu_stdvga.c)
(the first display driver); `make -C sdk drivers` builds them for every
architecture. The kernel's side is [`src/ncdri.rs`](../crates/nanochrono-baremetal/src/ncdri.rs).
Ring-0 code shares the red-zone rules of [NCCALL.md](NCCALL.md) §2.

| Piece | Status |
|---|---|
| `ncdri_api.h`: the tables, handles, versioning, layout pins | **done** (compiles for all nine architectures, `-Wall -Wextra -Werror`); minor 1 adds the display services (§9) |
| Build rules, `tools/check-redzone.py` on every object | **done** |
| Packing (`tools/ncplu.py pack --kind driver --entry ncdri_main`) | **done** for x86-64 (the packer's relocations are x86-64's) |
| The kernel side: `nckernel_api_t`, the trust gate, `.ncdri` loaded at boot, PCI probe/attach | **done** on x86-64 (`src/ncdri.rs`, on the page allocator `src/palloc.rs`) |
| Interrupts for drivers, a saved FPU context, unloading, newbus beyond PCI | planned (§7) |
| `qemu_stdvga.c`: EDID → the monitor's native mode, the scanout to the kernel | **done** (§9) |

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

## 7. Loading — done on x86-64

The kernel's loader (`src/ncdri.rs`) takes every module the boot loader
placed under `/boot/drivers/` (`NCDRI_EXTRA=` puts SDK-built ones on the ISO,
`packaging/baremetal/build.sh`), in the order the app launcher already uses:

1. **Read and verify** with the launcher's checks (`ncplu::inspect`): the
   format, the architecture, the digest, the hybrid signature.
2. **Trust.** Ring 0 is signed work. A module signed by a root the kernel
   trusts for ring 0 loads; an unsigned or untrusted one is refused, unless
   the machine's owner has turned on *Enable Ring0 Community Modules and
   Drivers* (ECOSYSTEM.md §3) — for one boot, `ncdri.community=on` on the
   kernel command line. Off by default:

   ```
   ncdri: /boot/drivers/QEMU_STDVGA.NCDRI: community (not signed)
   ncdri: /boot/drivers/QEMU_STDVGA.NCDRI: refused: a ring-0 driver must be signed for ring 0; ncdri.community=on allows an unsigned one for this boot
   ```

   `NCPLU_SIGN_KEYS` signs the drivers on the ISO with the apps, and a
   kernel built with the matching `NCPLU_ROOT_CREATOR` loads them as
   `creator` without the switch.
3. **Inspect.** It must be `Kind::Driver`, and its only imports the stack
   canary pair (resolved to a driver-wide random guard and a
   `__stack_chk_fail` that stops the kernel: a corrupt ring-0 stack has
   nothing to unwind to).
4. **Place** in pages from the allocator, relocated with the launcher's own
   code (`ncplu::copy_and_relocate`). The boot page tables map all RAM
   writable and executable with 1 GiB and 2 MiB pages, so the module's text
   is not made read-only nor its data non-executable yet; per-page W^X for
   modules comes with 4 KiB mappings.
5. **`ncdri_main(&table, sizeof table)`**, with a table of the module's own
   (its `self`). An error unloads it again.
6. **Match**: every PCI device the kernel does not drive itself (bridges and
   USB host controllers are its own) is offered to each registered driver's
   `probe` with its `ncdri_devinfo_t`; the best offer gets `attach` with a
   zeroed softc. A failed attach gets everything back — windows, DMA memory,
   softc — even what the driver forgot to undo.

Every handle a driver holds is a pointer into one of the kernel's fixed
pools; each call checks that it names a live entry before using it, and
every register access is bounds- and alignment-checked against the window
the kernel sized. A driver is ring-0 code and could ignore all of this with
its own instructions; the checks are there so a *buggy* driver fails
loudly instead of corrupting memory quietly.

What is not there yet, and what a driver gets instead:

| Service | Today |
|---|---|
| `irq_establish` | `NCDRI_ENOTSUP`: the kernel runs with interrupts masked; a driver polls |
| `fpu_alloc` | `NCDRI_ENOTSUP`; `fpu_begin(NULL, NCDRI_FPU_NOCTX)` works (it saves MXCSR and the x87 control word) |
| DMA | memory below 1 GiB, coherent; the bus address is the physical one (no IOMMU programmed) |
| Unloading (`ncdri_fini`) | not done: a boot driver stays |
| Buses | PCI; ACPI, FDT and USB devices are not offered yet |
| Architectures | x86-64; the others need the packer's relocations and big-endian accessors (PCI is little-endian) |

## 8. The example

`hello_ncdri.c` claims QEMU's `edu` teaching device (PCI 1234:11e8): maps BAR
0 through `resource_map`, checks the liveness register (it reads back the
inverse of what is written), allocates a coherent DMA buffer below 4 GiB,
establishes its interrupt, turns bus mastering on, and undoes every step in
`detach`. It shows a newer service used only when `NCDRI_HAS` says the
kernel has it. Under `qemu-system-x86_64 -device edu` it maps the window,
passes the liveness check, takes its DMA buffer — and stops at
`irq_establish`, which says `ENOTSUP` today, so the attach fails and the
kernel takes the rest back:

```
ncdri: edu0: attach failed (ENOTSUP, 45) at PCI 00:04.0 (1234:11e8)
```

## 9. Display drivers (minor 1)

Two services, from `reserved[]` slots — the table keeps its size, and a
minor-0 driver never sees them:

* `display_scanout(dev, &scanout, edid, edid_len)`: a driver that has set a
  mode says where the picture is — which memory window of its device (a
  BAR, by `resource_map` index), where in it, its width, height, pitch and
  format (`NCDRI_FORMAT_XRGB8888` today). The kernel maps the window itself,
  checks the surface lies inside it, gives it a back buffer of its size, and
  the session draws there instead of on the firmware's framebuffer. The
  EDID, when given, names the monitor in the log.
* `edid_preferred(edid, len, &w, &h, &refresh_mhz)`: the monitor's native
  mode, through the kernel's parser (`nanochrono_core::edid`, host-tested):
  the base block's first detailed timing, or a DisplayID extension's
  preferred timing when the mode's pixel clock does not fit a descriptor
  (4K above 60 Hz, 5K, 8K).

`qemu_stdvga.c` is the first user: QEMU's and Bochs' standard VGA (PCI
1234:1111). It reads the EDID out of BAR 2, asks the kernel for the native
mode, checks it against the VRAM and the largest mode the device reports,
sets it through the Bochs "dispi" registers, and hands over BAR 0 as the
scanout — written from QEMU's own description of the device
(`docs/specs/standard-vga.rst` in QEMU), not from another driver.

```
ncdri: stdvga0: EDID native mode 2560x1440 at 74 Hz; 32 MiB of VRAM, at most 16000x12000
ncdri: stdvga0: native mode set; scanout handed to the kernel
ncdri: stdvga0: attached at PCI 00:03.0 (1234:1111)
display: monitor QEMU Monitor (RHT), native 2560x1440 at 74.998 Hz
display: 2560x1440 from stdvga0, composited
```

A native driver for real hardware — Intel, AMD, NVIDIA — is the same shape
with a larger middle: its own EDID over DDC (GMBUS, the DisplayPort AUX
channel), its own modeset, and the same two calls at the ends.
