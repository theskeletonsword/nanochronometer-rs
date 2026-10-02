/* SPDX-License-Identifier: Apache-2.0
 *
 * The rest of libnanochrono's symbol table, spliced into
 * include/baremetal/nanochrono.h by tools/gen-header.sh after what cbindgen
 * derives from abi.rs. cbindgen sees Rust items only; these are the symbols
 * defined in assembly, the trap entry points, and the symbols the library
 * imports from the kernel that loads it — every C-named entry of
 * `nm -D libnanochrono.so` on each architecture is declared either above or
 * here, and packaging/baremetal/build.sh checks that it stays so.
 */

/*
 Bounds of the library's zeroed data. `_end` and `__bss_end` are the same
 address; a loader that maps libnanochrono.so zeroes up to it.
 */
extern char __bss_end[];
extern char _end[];

/*
 Imported: the kernel image that links or loads the library defines its own
 bounds, which the crash-dump and boot code read. A kernel of your own binds
 them to its image (or to a harmless address when it never uses that code).
 */
extern char __kernel_start[];
extern char __kernel_end[];

#if defined(__x86_64__)
/*
 The plugin ABI version as a data symbol: what a `.ncplu` plugin's IMPORT64
 relocation resolves (its address, not its value, is the import).
 */
extern const uint32_t NC_ABI_VERSION;

/* The register frame the trap entry stubs push; opaque outside the kernel. */
struct nc_trap_frame;

/*
 First-level trap handler, called by the vector stubs: returns 1 when it
 contained a fault of the running plugin (the frame then resumes on the
 kernel's stack), 0 to go on to nanochrono_x86_exception.
 */
uint64_t nanochrono_x86_trap(struct nc_trap_frame *frame);

/* The fatal path: the crash dump and the stop screen. Never returns. */
void nanochrono_x86_exception(const struct nc_trap_frame *frame) __attribute__((noreturn));

/*
 Runs a kernel-tier plugin: calls `entry(api)` on the stack that ends at
 `stack_top` and returns its result, or the abort code nc_plugin_abort set.
 */
int64_t nc_plugin_call(uintptr_t entry, const void *api, uintptr_t stack_top);

/* Ends the running kernel-tier plugin from inside it; returns through nc_plugin_call. */
void nc_plugin_abort(void);

/* Calls `func(arg)` on the stack that ends at `stack_top`, then returns. */
void nc_run_on_stack(void (*func)(uint8_t *arg), uint8_t *arg, uintptr_t stack_top);

/*
 Looks up a symbol a plugin imports, by name (`len` bytes, not
 NUL-terminated); its address, or 0.
 */
uintptr_t nc_resolve_symbol_c(const uint8_t *name, uintptr_t len);

/* Drops to ring 3 at `entry_rip` on `user_stack`; returns the plugin's result. */
int64_t nc_ring3_enter(uintptr_t entry_rip, uintptr_t user_stack, uintptr_t api);

/* Gate entry points, reached by `syscall` and by the ring-3 return path — not called from C. */
void nc_ring3_return(void);
void nc_ring3_syscall(void);

/* Imported: the kernel image's text and stacks (its linker script defines them). */
extern char __text_start[];
extern char __text_end[];
extern char nc_stack_bottom[];
extern char nc_stack_top[];
extern char nc_stack_guard[];
extern char nc_ist1_bottom[];
extern char nc_ist1_top[];
extern char nc_ist2_bottom[];
extern char nc_ist2_top[];
#endif /* __x86_64__ */

#if defined(__i386__)
/* The register frame the i386 exception stubs build; opaque outside the kernel. */
struct nc_trap_frame32;

/*
 The handler the kernel's IDT stubs and double-fault task call, for every
 architectural exception: the report and the stop screen. Never returns.
 */
void nanochrono_i386_exception(const struct nc_trap_frame32 *frame) __attribute__((noreturn));
#endif /* __i386__ */

#if defined(__aarch64__)
/* Exception vector tables (2 KiB aligned), for VBAR_EL1, VBAR_EL2 and VBAR_EL3. */
extern const uint8_t nanochrono_vectors_el1[];
extern const uint8_t nanochrono_vectors_el2[];
extern const uint8_t nanochrono_vectors_el3[];

/* Points VBAR at the tables above for the current level and EL1. */
void nanochrono_install_vectors(void);

/*
 The vectors' handler: syndrome, return address, fault address, which vector
 (`kind`) and from which exception level. Never returns.
 */
void nanochrono_exception(uint64_t esr, uint64_t elr, uint64_t far, uint64_t kind, uint64_t el)
    __attribute__((noreturn));

/* An SMCCC call through HVC: x0..x3 on return go to `out`. */
void nanochrono_hvc(uint64_t function, uint64_t arg, uint64_t out[4]);

/* The HVC instruction inside nanochrono_hvc, which the vectors recognise when it faults. */
extern const uint32_t nanochrono_hvc_insn[];
#endif /* __aarch64__ */

#if defined(__arm__)
/* The ARM run-time ABI's unaligned accesses, which strict-alignment code calls. */
uint32_t __aeabi_uread4(const void *address);
uint64_t __aeabi_uread8(const void *address);
uint32_t __aeabi_uwrite4(uint32_t value, void *address);
uint64_t __aeabi_uwrite8(uint64_t value, void *address);
#endif /* __arm__ */

#if defined(__powerpc__) || defined(__riscv)
/* The image's entry point and the start of its zeroed data. */
void _start(void);
extern char __bss_start[];
#endif

#if defined(__powerpc64__)
/* OPAL's base and entry, as skiboot passed them; and the call into it. */
extern uint64_t nc_opal_base;
extern uint64_t nc_opal_entry;
int64_t nc_opal_call(uint64_t token, uint64_t a0, uint64_t a1, uint64_t a2);

/*
 Imported: the kernel's Rust entry, which _start calls with the loader's
 registers — r3, r8 and r9, and r6: the ePAPR magic 0x65504150 when the
 loader is skiboot, not a kexec.
 */
void kmain(uintptr_t fdt, uint64_t opal_base, uint64_t opal_entry, uint64_t r6)
    __attribute__((noreturn));
#elif defined(__powerpc__)
/* The exception handler the vectors call with the vector's offset. Never returns. */
void nanochrono_ppc_exception(uint32_t vector) __attribute__((noreturn));

/* Imported: the kernel's Rust entry — the device tree, or Open Firmware's client interface. */
void kmain(uintptr_t fdt, uintptr_t of_entry) __attribute__((noreturn));
#endif

#if defined(__riscv)
/* The trap handler: scause, sepc and stval. Never returns. */
void nanochrono_riscv_exception(uintptr_t scause, uintptr_t sepc, uintptr_t stval)
    __attribute__((noreturn));

/* What a counter probe returns: the counter's low word, and 1 if S-mode could read it. */
typedef struct {
    uintptr_t low;
    uintptr_t readable;
} nc_rv_probe_t;

/* Reads `cycle` / `instret` once; a fault there comes back as readable = 0. */
nc_rv_probe_t nc_rv_try_cycle(void);
nc_rv_probe_t nc_rv_try_instret(void);

/* The reading instructions inside them, which the trap handler recognises. */
extern const uint8_t nc_rv_probe_site_cycle[];
extern const uint8_t nc_rv_probe_site_instret[];

/* Imported: the kernel's Rust entry (hart ID, device tree), and its gp. */
void kmain(uintptr_t hart, uintptr_t fdt) __attribute__((noreturn));
extern char nc_global_pointer[] __asm__("__global_pointer$");
#endif /* __riscv */
