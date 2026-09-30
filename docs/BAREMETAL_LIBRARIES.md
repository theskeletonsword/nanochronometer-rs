# Using NanoChronometer from your own freestanding kernel

Two artifacts, and one of them needs work from you before it does anything.

```sh
./packaging/baremetal/build.sh
```

```
build/baremetal/x86_64/          every architecture has the same layout
  lib64/                         lib/ on i386, arm32, ppc and riscv32
    libnanochrono.a              static: link it and you are done
    libnanochrono.so             dynamic: read the second half of this file
  include/nanochrono.h           the C ABI, for C and for assembly
  nanochrono-kernel.elf          the demo kernel
  nanochrono-kernel.mb.elf       x86_64: the same, as ELF32 for QEMU's -kernel
```

Both libraries hold the same code and export the same C ABI, which
`include/nanochrono.h` declares: the PMU (`nc_bm_pmu_*`), the counter
(`nc_bm_counter*`) and NC_RNG (`nc_rng_*`, identical to the hosted
libnanochrono's). The header is generated from
`crates/nanochrono-baremetal/src/abi.rs`, is freestanding, and can be
`#include`d from a `.S` file — the constants are plain `#define`s and the C
declarations sit under `#ifndef __ASSEMBLER__`.

---

## Static — the one that just works

```sh
cc -ffreestanding -I build/baremetal/x86_64/include -c your-kernel.c
ld -T your-linker.ld your-kernel.o -L build/baremetal/x86_64/lib64 -lnanochrono
```

The archive carries the counter routes, the direct PMU, the ECC/TMR machinery,
the framebuffer and the PS/2 input driver. Your linker resolves every symbol at
link time and drops what you do not call.

Two things must match, or the result miscompiles rather than failing to link:

* **Target.** `x86_64-nanochrono-none` if you want the SIMD probes,
  `x86_64-unknown-none` otherwise. They differ in ABI — the second is
  soft-float — and linking objects built for one against a library built for
  the other passes floats in different places.
* **Red zone off.** Both targets set `disable-redzone`; if you use a custom
  spec, set it there too. An interrupt writes over the red zone, and the
  corruption is silent.

Before calling anything that touches a vector register, your boot code must
enable the state: `CR0.EM` clear, `CR0.MP` and `CR4.OSFXSR` set, then
`CR4.OSXSAVE` and `XCR0` for AVX. `crates/nanochrono-baremetal/boot/boot32.S`
does all of it and is a working reference. Without it every SIMD instruction is
`#UD`, not a slow path.

---

## Dynamic — you must supply the runtime

**`libnanochrono.so` will not load itself.** There is no
`ld.so` on bare metal, so nothing exists to map the segments, apply the
relocations and bind the symbols. Shipping the file without saying so would be
shipping something that cannot work.

If you want dynamic linking in your kernel, here is what you are signing up
for.

### 1. Load the segments

Walk the ELF program headers and map each `PT_LOAD` at
`p_vaddr + load_bias`, with `p_memsz` bytes, zeroing the tail beyond
`p_filesz`. Honour `p_flags`: a page that does not need to be executable
should not be.

`load_bias` is yours to choose. The library is position-independent, which is
what makes that possible.

### 2. Apply the relocations

`PT_DYNAMIC` points at the tables. On x86-64 you will see:

| Relocation | What to write |
|---|---|
| `R_X86_64_RELATIVE` | `load_bias + addend` — the bulk of them |
| `R_X86_64_GLOB_DAT` | The symbol's address |
| `R_X86_64_JUMP_SLOT` | The symbol's address, or a resolver stub |
| `R_X86_64_64` | `symbol + addend` |

Relocations live in `DT_RELA` with `DT_RELASZ` bytes, and `DT_JMPREL` with
`DT_PLTRELSZ` for the PLT. **Do not skip `R_X86_64_RELATIVE`**: every absolute
address in the library is wrong until you have applied them, and the failure is
a jump into nothing rather than a diagnostic.

The other architectures carry the same four kinds under their own names —
`R_386_*`, `R_AARCH64_*`, `R_ARM_*`, `R_PPC_*`, `R_PPC64_*`, `R_RISCV_*`
(`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT` or `JMP_SLOT`, and the plain absolute
`_64`/`_32`/`ABS32`); i386 and 32-bit ARM use `DT_REL`, whose addend is the word
already at the target. `readelf -r` shows exactly what a given object needs.

Every object is flagged `TEXTREL`: the hand-written boot and trap assembly keeps
a few absolute addresses in its text. Keep the text writable while you relocate
it, then make it read-only and executable.

### 3. Resolve symbols

`DT_SYMTAB` and `DT_STRTAB` give the symbol table and its strings;
`DT_GNU_HASH` (or `DT_HASH`) gives the lookup structure. You can walk the
symbol table linearly instead — it is slower and much shorter to write, and a
kernel resolving a few dozen symbols once will not notice.

The library was linked with `-Bsymbolic`, so its references to its own
symbols are already bound inside it; your resolver satisfies lookups *into*
the library, and a handful of imports. Those are symbols the NanoChronometer
kernel image defines for itself — the image's bounds (`__kernel_start`,
`__kernel_end`) everywhere; on x86_64 its stacks and text bounds; `kmain` on
PowerPC and RISC-V; `__global_pointer$` on RISC-V — named only by the boot,
trap and crash-dump code, which a loaded module does not run.
`readelf --dyn-syms --wide libnanochrono.so | grep UND` lists them; bind each to
your kernel's equivalent, or to a harmless address if you never call that
code. That is what keeps this a tractable first loader.

### 4. Flush the instruction cache

On AArch64, after writing relocations into memory you are about to execute:
`dc cvau` on each line, `dsb ish`, `ic ivau`, `dsb ish`, `isb`. Skipping this
works right up until it does not, on a machine with a larger cache than yours.

32-bit ARM needs the same maintenance for its caches; PowerPC `dcbst`, `sync`,
`icbi`, `isync`; RISC-V `fence.i`. x86 keeps its caches coherent with
instruction fetch and needs none of this.

On ppc64 and ppc64le (ELFv2), call a function through its global entry point
with `r12` holding that address, so it can find its TOC.

### 5. Then call it

```rust
type AbiVersion = unsafe extern "C" fn() -> u32;
let version: AbiVersion = core::mem::transmute(resolve(b"nc_bm_abi_version\0")?);
assert_eq!(version(), 1); // NC_BM_ABI_VERSION in nanochrono.h
```

### Why you might not want to

The static archive gives you the same code with none of that, and a kernel
rarely needs to swap an implementation at run time. The dynamic library is
here because it was asked for and because loadable modules are a legitimate
design — not because it is the easier path.

If you build the loader, the ELF header parsing in
`crates/nanochrono-baremetal/src/multiboot.rs` is a working example of reading
a structure out of raw physical memory safely in this codebase's style.
