# NanoChronometer for bare metal

The freestanding kernel, and the same code as a library for your own kernel,
for nine architectures. Each architecture's directory is laid out as an
install prefix:

```
<arch>/
  lib64/                      lib/ on the 32-bit targets (i386, arm32, ppc, riscv32)
    libnanochrono.a           static library: link it and you are done
    libnanochrono.so          shared library: the same code, but it needs a
                              runtime loader of yours (read below)
  include/
    nanochrono.h              the C ABI, for C and for assembly
  nanochrono-kernel.elf       the NanoChronometer kernel (stripped)
  nanochrono-kernel.sym.elf   its symbols, for GDB and tools/nanodump.py
  nanochrono-kernel.mb.elf    x86_64: the same kernel as ELF32, for QEMU -kernel

nanochronometer_x86_64.iso    bootable (BIOS and UEFI) from a USB stick or CD
nanochronometer_i386.iso
nanochronometer_ppc_of.iso    G3/G4 Macs through Open Firmware
plugins/                      the .ncplu plugins the ISOs carry
BAREMETAL_LIBRARIES.md        the libraries in depth
BAREMETAL_DRIVERS.md          the drivers in the kernel
```

## `include/nanochrono.h`

The C ABI that both libraries export, generated from the Rust source: the PMU
(`nc_bm_pmu_*`), the architectural counter (`nc_bm_counter*`) and the entropy
pool (`nc_rng_*`, with the same functions, constants and `nc_rng_status_t` as
the hosted libnanochrono, so the same C builds against either).

It is freestanding — only `<stdbool.h>`, `<stddef.h>` and `<stdint.h>` — and
it can be `#include`d from a `.S` file: the constants are plain `#define`s, and
the C declarations sit under `#ifndef __ASSEMBLER__`. From assembly, call a
function by its name with the target's C calling convention.

Every function is a **ring 0 / EL1** interface.

```sh
cc -ffreestanding -I x86_64/include -c kernel.c
ld -T kernel.ld kernel.o -L x86_64/lib64 -lnanochrono
```

## The static library

`libnanochrono.a` needs nothing more: the linker resolves every symbol when
your kernel is linked, and keeps only what you call.

## The shared library needs a symbol resolver that you write

`libnanochrono.so` is the **complete** library, not a trimmed one: every object
of the static archive, compiled position independent, with every global symbol
exported. But bare metal has no dynamic linker — no `ld.so` exists to map the
file, relocate it and **resolve its symbols at run time**. The `.so` cannot
load itself. **Before your kernel calls anything in it, you must implement that
loader and runtime symbol resolver yourself.** It has to:

1. **Map the segments.** Each `PT_LOAD` at `load_bias + p_vaddr`, `p_memsz`
   bytes, zeroed past `p_filesz`. The load address is yours to choose.

2. **Apply every relocation** in `DT_RELA` or `DT_REL`, and in `DT_JMPREL`:

   | Kind | What to write |
   |---|---|
   | `*_RELATIVE` (most of them) | `load_bias + addend` |
   | `*_GLOB_DAT`, `*_JUMP_SLOT` / `*_JMP_SLOT` | the resolved symbol's address |
   | `R_X86_64_64`, `R_386_32`, `R_ARM_ABS32`, `R_PPC64_ADDR64`, `R_PPC_ADDR32`, `R_RISCV_64` / `R_RISCV_32` | the symbol's address + addend |

   The object is flagged `TEXTREL`: a few relocations land in its text, where
   the hand-written boot and trap assembly keeps absolute addresses. Keep the
   text writable while you relocate, then make it read-only and executable.
   Skip a `RELATIVE` relocation and an absolute address in the library stays
   wrong — the failure is a jump into nothing, not a diagnostic.

3. **Resolve symbols by name at run time** through `DT_SYMTAB`, `DT_STRTAB` and
   `DT_HASH` or `DT_GNU_HASH` (both are there; a linear walk of the symbol
   table also works). That is how you find `nc_rng_fill` and everything else
   in `nanochrono.h`. The library was linked with `-Bsymbolic`: its calls into
   itself are already bound inside it, so your resolver does not have to
   handle them.

4. **Bind its few imports.** The library's boot, trap and crash-dump code
   refers to symbols the NanoChronometer kernel image defines for itself: the
   image's bounds (`__kernel_start`, `__kernel_end`) on every architecture,
   and on x86_64 its stacks and text bounds, `kmain` on PowerPC and RISC-V,
   `__global_pointer$` on RISC-V. A module you load never runs the boot code,
   but the relocations still name them. List them with

   ```sh
   readelf --dyn-syms --wide <arch>/lib64/libnanochrono.so | grep UND
   ```

   and bind each to your kernel's equivalent, or to a harmless address when
   you never call the code that uses it.

5. **Make the new code visible to instruction fetch** where the architecture
   requires it before you jump to it: AArch64 `dc cvau` / `dsb ish` /
   `ic ivau` / `dsb ish` / `isb`; 32-bit ARM the same maintenance for its
   caches; PowerPC `dcbst` / `sync` / `icbi` / `isync`; RISC-V `fence.i`.
   x86 keeps its caches coherent and needs nothing.

6. **Call with the target's C calling convention.** On ppc64 and ppc64le
   (ELFv2), enter a function through its global entry point with `r12` holding
   that address, so it can find its TOC.

`BAREMETAL_LIBRARIES.md` walks through the loader step by step. If you do not
need to swap the implementation at run time, link the static library instead:
it is the same code with none of this.
