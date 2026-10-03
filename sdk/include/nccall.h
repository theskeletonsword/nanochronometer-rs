/* SPDX-License-Identifier: Apache-2.0 */
/* nccall.h — the ring 3 -> ring 0 system call, for C, C++ and assembly-
 * adjacent code, on every architecture NanoChronometer runs on.
 *
 * Mirrors crates/nanochrono-sys (src/abi.rs, src/nr.rs, src/raw.rs) register
 * for register and number for number; docs/NCCALL.md is the specification.
 *
 *   ISA        trap        number  arguments (6 words)        results  error flag
 *   x86-64     syscall     rax     rdi rsi rdx r10 r8 r9       rax rdx  CF
 *   i386       int $0x80   eax     4(%esp) .. 24(%esp)         eax edx  CF
 *   AArch64    svc #0      x8      x0 .. x5                    x0  x1   C
 *   ARM32      svc #0      r12     r0 .. r5                    r0  r1   C
 *   PowerPC    sc          r0      r3 .. r8                    r3  r4   CR0[SO]
 *   RISC-V     ecall       t0      a0 .. a5                    a0  a1   t0 != 0
 *
 * A call behaves like a call to an external C function: it may change every
 * register the psABI calls caller-saved (and the FP/vector registers), and
 * keeps the rest and the stack pointer. It never writes below the stack
 * pointer: code calling it keeps whatever red zone its psABI grants (128
 * bytes on x86-64, 288 on 64-bit PowerPC).
 *
 * NCCALL(nr, ...) takes a constant number and records the call site in the
 * `nccall_pins` section (OpenBSD's PINSYSCALL; see docs/NCCALL.md §7);
 * nccall_dyn() takes one known only at run time and records NCCALL_NR_ANY.
 *
 * Not for kernel code: .ncdri drivers reach the kernel through ncdri_api.h,
 * never through a trap.
 *
 * C, C++ (extern "C"; C++20 for NCCALL's variadic form) and assembly: a .S
 * file that includes this header gets every number, errno and flag below
 * as a plain constant (no C suffixes under __ASSEMBLER__) and writes the
 * trap itself with the registers in the table above. NC_SYS_echo checks a
 * binding: all six argument registers in, both result registers out.
 */
#ifndef NCCALL_H
#define NCCALL_H

/* Unsigned in C and C++; bare in assembly, which takes no suffix. */
#ifdef __ASSEMBLER__
#define NCCALL_U_(x) x
#else
#define NCCALL_U_(x) x##u
#endif

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#endif /* !__ASSEMBLER__ */

/* ---- Call numbers (crates/nanochrono-sys/src/nr.rs) --------------------- */
#define NCCALL_CLASS_SHIFT 16
#define NCCALL_CLASS_NC    NCCALL_U_(0)   /* NanoChronometer services */
#define NCCALL_CLASS_POSIX NCCALL_U_(1)   /* POSIX/BSD, indexed by FreeBSD's syscalls.master */
#define NCCALL_CLASS_DIAG  NCCALL_U_(2)   /* the ABI's self-check */
#define NCCALL_MAKE(cls, idx) (((cls) << NCCALL_CLASS_SHIFT) | ((idx) & NCCALL_U_(0xFFFF)))
#define NCCALL_FREEBSD(idx)   NCCALL_MAKE(NCCALL_CLASS_POSIX, idx)
#define NCCALL_NR_ANY      NCCALL_U_(0xFFFFFFFF)
#define NCCALL_MAX_ARGS    6

/* Class 0: the services behind the plugin's nc_api_t (ncplu.h). */
#define NC_SYS_EXIT              NCCALL_U_(0)
#define NC_SYS_FILL_RECT         NCCALL_U_(1)
#define NC_SYS_CLEAR             NCCALL_U_(2)
#define NC_SYS_PRESENT           NCCALL_U_(3)
#define NC_SYS_POLL_EVENT        NCCALL_U_(4)
#define NC_SYS_TICKS             NCCALL_U_(5)
#define NC_SYS_LOG               NCCALL_U_(6)
#define NC_SYS_TIMER_NOW         NCCALL_U_(7)
#define NC_SYS_TIMER_NOW_END     NCCALL_U_(8)
#define NC_SYS_TIMER_HZ          NCCALL_U_(9)
#define NC_SYS_TIMER_SOURCE      NCCALL_U_(10)
#define NC_SYS_TIMER_TICKS_TO_NS NCCALL_U_(11)
#define NC_SYS_PMU_CAPS          NCCALL_U_(12)
#define NC_SYS_PMU_OPEN          NCCALL_U_(13)
#define NC_SYS_PMU_READ          NCCALL_U_(14)
#define NC_SYS_PMU_CLOSE         NCCALL_U_(15)
#define NC_SYS_RNG_FILL          NCCALL_U_(16)
#define NC_SYS_RNG_STATUS        NCCALL_U_(17)
#define NC_SYS_RNG_STIR          NCCALL_U_(18)
#define NC_SYS_RNG_SELFTEST      NCCALL_U_(19)
#define NC_SYS_STACK_CHK_FAIL    NCCALL_U_(20)
#define NC_SYS_SPAWN             NCCALL_U_(32)  /* reserved: NetBSD posix_spawn(2) model; ENOSYS today */

/* Class 1: FreeBSD's numbers plus the class bit. */
#define NC_SYS_exit          NCCALL_FREEBSD(1)
#define NC_SYS_read          NCCALL_FREEBSD(3)
#define NC_SYS_write         NCCALL_FREEBSD(4)
#define NC_SYS_open          NCCALL_FREEBSD(5)
#define NC_SYS_close         NCCALL_FREEBSD(6)
#define NC_SYS_getpid        NCCALL_FREEBSD(20)
#define NC_SYS_munmap        NCCALL_FREEBSD(73)
#define NC_SYS_mprotect      NCCALL_FREEBSD(74)
#define NC_SYS_socket        NCCALL_FREEBSD(97)
#define NC_SYS_clock_gettime NCCALL_FREEBSD(232)
#define NC_SYS_nanosleep     NCCALL_FREEBSD(240)
#define NC_SYS_mmap          NCCALL_FREEBSD(477) /* offset in 4 KiB units */
#define NC_SYS_getrandom     NCCALL_FREEBSD(563)

/* Class 2: echo(a0..a5) returns { Σ (i+1)·aᵢ (wrapping), a5 } and never fails. */
#define NC_SYS_echo          NCCALL_MAKE(NCCALL_CLASS_DIAG, 0)

/* errno values (FreeBSD sys/sys/errno.h) the kernel returns today. */
#define NC_EPERM        1
#define NC_ENOENT       2
#define NC_EIO          5
#define NC_EBADF        9
#define NC_ENOMEM       12
#define NC_EACCES       13
#define NC_EFAULT       14
#define NC_EINVAL       22
#define NC_EAGAIN       35
#define NC_ENOTSUP      45
#define NC_ENOSYS       78
#define NC_EOVERFLOW    84
#define NC_ENOTCAPABLE  93

/* mmap/mprotect, clock_gettime, getrandom (FreeBSD values). */
#define NC_PROT_READ   0x01
#define NC_PROT_WRITE  0x02
#define NC_PROT_EXEC   0x04
#define NC_MAP_SHARED  0x0001
#define NC_MAP_PRIVATE 0x0002
#define NC_MAP_FIXED   0x0010
#define NC_MAP_ANON    0x1000
#define NC_CLOCK_REALTIME  0
#define NC_CLOCK_MONOTONIC 4
#define NC_CLOCK_UPTIME    5
#define NC_GRND_NONBLOCK 0x1
#define NC_GRND_RANDOM   0x2

#ifndef __ASSEMBLER__
/* What clock_gettime fills: 64-bit fields on every architecture. */
typedef struct nc_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
} nc_timespec_t;

/* What one call returned. */
typedef struct nccall_ret {
    uintptr_t value;  /* the result, or the errno when failed */
    uintptr_t value2; /* second word: high half of a 64-bit result on 32-bit */
    int failed;       /* the error flag */
} nccall_ret_t;

/* The pin record, in the template of every call below. The site is local
 * label 2 ("2:"); `nr` is an "i" operand, printed bare with %c. */
#define NCCALL_PIN_ASM(nrop)                               \
    ".pushsection nccall_pins,\"aR\",%%progbits\n\t"       \
    ".balign 4\n\t"                                        \
    ".long 2b - .\n\t"                                     \
    ".long %c" nrop "\n\t"                                 \
    ".popsection\n\t"

/* ======================================================================== */
#if defined(__x86_64__)
#define NCCALL_VEC_CLOBBERS_ "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", \
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",                    \
    "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"
#define NCCALL_IMPL_(pin, nrv, a)                                                       \
    __extension__({                                                                    \
        register uintptr_t r_rax __asm__("rax") = (uintptr_t)(nrv);                    \
        register uintptr_t r_rdi __asm__("rdi") = (a)[0];                              \
        register uintptr_t r_rsi __asm__("rsi") = (a)[1];                              \
        register uintptr_t r_rdx __asm__("rdx") = (a)[2];                              \
        register uintptr_t r_r10 __asm__("r10") = (a)[3];                              \
        register uintptr_t r_r8 __asm__("r8") = (a)[4];                                \
        register uintptr_t r_r9 __asm__("r9") = (a)[5];                                \
        uint8_t f_;                                                                    \
        __asm__ volatile("2: syscall\n\t"                                              \
                         "setc %[f]\n\t" NCCALL_PIN_ASM("[nr]")                        \
                         : "+r"(r_rax), "+r"(r_rdi), "+r"(r_rsi), "+r"(r_rdx),         \
                           "+r"(r_r10), "+r"(r_r8), "+r"(r_r9), [f] "=c"(f_)           \
                         : [nr] "i"(pin)                                               \
                         : "r11", "memory", "cc", NCCALL_VEC_CLOBBERS_);               \
        (nccall_ret_t){ r_rax, r_rdx, f_ };                                            \
    })

/* ======================================================================== */
#elif defined(__i386__)
#define NCCALL_IMPL_(pin, nrv, a)                                                       \
    __extension__({                                                                    \
        const uintptr_t *p_ = (a);                                                     \
        uintptr_t eax_ = (uintptr_t)(nrv), edx_;                                       \
        uint8_t f_;                                                                    \
        __asm__ volatile("pushl 20(%[p])\n\t"                                          \
                         "pushl 16(%[p])\n\t"                                          \
                         "pushl 12(%[p])\n\t"                                          \
                         "pushl 8(%[p])\n\t"                                           \
                         "pushl 4(%[p])\n\t"                                           \
                         "pushl (%[p])\n\t"                                            \
                         "pushl %%eax\n\t" /* the return-address slot */               \
                         "2: int $0x80\n\t"                                            \
                         "setc %[f]\n\t"                                               \
                         "addl $28, %%esp\n\t" NCCALL_PIN_ASM("[nr]")                  \
                         : "+a"(eax_), "=d"(edx_), [f] "=c"(f_)                        \
                         : [p] "r"(p_), [nr] "i"(pin)                                  \
                         : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",     \
                           "xmm5", "xmm6", "xmm7", "st", "st(1)", "st(2)", "st(3)",    \
                           "st(4)", "st(5)", "st(6)", "st(7)");                        \
        (nccall_ret_t){ eax_, edx_, f_ };                                              \
    })

/* ======================================================================== */
#elif defined(__aarch64__)
#define NCCALL_IMPL_(pin, nrv, a)                                                       \
    __extension__({                                                                    \
        register uintptr_t r_x8 __asm__("x8") = (uintptr_t)(nrv);                      \
        register uintptr_t r_x0 __asm__("x0") = (a)[0];                                \
        register uintptr_t r_x1 __asm__("x1") = (a)[1];                                \
        register uintptr_t r_x2 __asm__("x2") = (a)[2];                                \
        register uintptr_t r_x3 __asm__("x3") = (a)[3];                                \
        register uintptr_t r_x4 __asm__("x4") = (a)[4];                                \
        register uintptr_t r_x5 __asm__("x5") = (a)[5];                                \
        register uintptr_t r_x9 __asm__("x9");                                         \
        __asm__ volatile("2: svc #0\n\t"                                               \
                         "dsb nsh\n\t"                                                 \
                         "isb\n\t"                                                     \
                         "cset w9, cs\n\t" NCCALL_PIN_ASM("[nr]")                      \
                         : "+r"(r_x8), "+r"(r_x0), "+r"(r_x1), "+r"(r_x2),             \
                           "+r"(r_x3), "+r"(r_x4), "+r"(r_x5), "=r"(r_x9)              \
                         : [nr] "i"(pin)                                               \
                         : "x6", "x7", "x10", "x11", "x12", "x13", "x14", "x15",       \
                           "x16", "x17", "x30", "memory", "cc",                        \
                           "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",             \
                           "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",       \
                           "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",     \
                           "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");    \
        (nccall_ret_t){ r_x0, r_x1, (int)r_x9 };                                       \
    })

/* ======================================================================== */
#elif defined(__arm__)
#if defined(__ARM_NEON) || defined(__ARM_FP)
#if defined(__ARM_NEON)
#define NCCALL_VFP_CLOBBERS_ , "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",        \
    "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",                          \
    "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"
#else
#define NCCALL_VFP_CLOBBERS_ , "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"
#endif
#else
#define NCCALL_VFP_CLOBBERS_
#endif
#define NCCALL_IMPL_(pin, nrv, a)                                                       \
    __extension__({                                                                    \
        register uintptr_t r_r12 __asm__("r12") = (uintptr_t)(nrv);                    \
        register uintptr_t r_r0 __asm__("r0") = (a)[0];                                \
        register uintptr_t r_r1 __asm__("r1") = (a)[1];                                \
        register uintptr_t r_r2 __asm__("r2") = (a)[2];                                \
        register uintptr_t r_r3 __asm__("r3") = (a)[3];                                \
        register uintptr_t r_r4 __asm__("r4") = (a)[4];                                \
        register uintptr_t r_r5 __asm__("r5") = (a)[5];                                \
        __asm__ volatile("2: svc #0\n\t"                                               \
                         "dsb nsh\n\t"                                                 \
                         "isb\n\t"                                                     \
                         "mov r2, #0\n\t"                                              \
                         "it cs\n\t"                                                   \
                         "movcs r2, #1\n\t" NCCALL_PIN_ASM("[nr]")                     \
                         : "+r"(r_r12), "+r"(r_r0), "+r"(r_r1), "+r"(r_r2),            \
                           "+r"(r_r3)                                                  \
                         : "r"(r_r4), "r"(r_r5), [nr] "i"(pin)                         \
                         : "lr", "memory", "cc" NCCALL_VFP_CLOBBERS_);                 \
        (nccall_ret_t){ r_r0, r_r1, (int)r_r2 };                                       \
    })

/* ======================================================================== */
#elif defined(__powerpc__) || defined(__powerpc64__)
#if defined(__ALTIVEC__)
#define NCCALL_VMX_CLOBBERS_ , "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",        \
    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",  \
    "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#else
#define NCCALL_VMX_CLOBBERS_
#endif
#if defined(__NO_FPRS__) || defined(_SOFT_FLOAT)
#define NCCALL_FPR_CLOBBERS_
#else
#define NCCALL_FPR_CLOBBERS_ , "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8",   \
    "f9", "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19", "f20", \
    "f21", "f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31"
#endif
#define NCCALL_IMPL_(pin, nrv, a)                                                       \
    __extension__({                                                                    \
        register uintptr_t r_r0 __asm__("r0") = (uintptr_t)(nrv);                      \
        register uintptr_t r_r3 __asm__("r3") = (a)[0];                                \
        register uintptr_t r_r4 __asm__("r4") = (a)[1];                                \
        register uintptr_t r_r5 __asm__("r5") = (a)[2];                                \
        register uintptr_t r_r6 __asm__("r6") = (a)[3];                                \
        register uintptr_t r_r7 __asm__("r7") = (a)[4];                                \
        register uintptr_t r_r8 __asm__("r8") = (a)[5];                                \
        register uintptr_t r_r9 __asm__("r9");                                         \
        __asm__ volatile("2: sc\n\t"                                                   \
                         "mfcr 9\n\t"                                                  \
                         "rlwinm 9, 9, 4, 31, 31\n\t" NCCALL_PIN_ASM("[nr]")           \
                         : "+r"(r_r0), "+r"(r_r3), "+r"(r_r4), "+r"(r_r5),             \
                           "+r"(r_r6), "+r"(r_r7), "+r"(r_r8), "=r"(r_r9)              \
                         : [nr] "i"(pin)                                               \
                         : "r10", "r11", "r12", "ctr", "xer", "lr", "cr0", "cr1",      \
                           "cr5", "cr6", "cr7", "memory" NCCALL_FPR_CLOBBERS_          \
                           NCCALL_VMX_CLOBBERS_);                                      \
        (nccall_ret_t){ r_r3, r_r4, (int)r_r9 };                                       \
    })

/* ======================================================================== */
#elif defined(__riscv)
#if defined(__riscv_flen)
#define NCCALL_FP_CLOBBERS_ , "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",   \
    "ft8", "ft9", "ft10", "ft11", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"
#else
#define NCCALL_FP_CLOBBERS_
#endif
#define NCCALL_IMPL_(pin, nrv, a)                                                       \
    __extension__({                                                                    \
        register uintptr_t r_t0 __asm__("t0") = (uintptr_t)(nrv);                      \
        register uintptr_t r_a0 __asm__("a0") = (a)[0];                                \
        register uintptr_t r_a1 __asm__("a1") = (a)[1];                                \
        register uintptr_t r_a2 __asm__("a2") = (a)[2];                                \
        register uintptr_t r_a3 __asm__("a3") = (a)[3];                                \
        register uintptr_t r_a4 __asm__("a4") = (a)[4];                                \
        register uintptr_t r_a5 __asm__("a5") = (a)[5];                                \
        __asm__ volatile("2: ecall\n\t" NCCALL_PIN_ASM("[nr]")                         \
                         : "+r"(r_t0), "+r"(r_a0), "+r"(r_a1), "+r"(r_a2),             \
                           "+r"(r_a3), "+r"(r_a4), "+r"(r_a5)                          \
                         : [nr] "i"(pin)                                               \
                         : "t1", "t2", "t3", "t4", "t5", "t6", "a6", "a7", "ra",       \
                           "memory" NCCALL_FP_CLOBBERS_);                              \
        (nccall_ret_t){ r_a0, r_a1, r_t0 != 0 };                                       \
    })

#else
#error "nccall.h: an architecture NanoChronometer does not run on"
#endif

/* NCCALL(nr, args...): `nr` a constant expression, up to six arguments,
 * each converted to a word. Pinned. */
#define NCCALL_ARGS_(a1, a2, a3, a4, a5, a6, ...) \
    { (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), (uintptr_t)(a4), (uintptr_t)(a5), (uintptr_t)(a6) }
#define NCCALL(nr, ...)                                                               \
    __extension__({                                                                   \
        const uintptr_t nccall_a_[6] = NCCALL_ARGS_(__VA_ARGS__ __VA_OPT__(,) 0, 0, 0, 0, 0, 0); \
        NCCALL_IMPL_((nr), (nr), nccall_a_);                                          \
    })

/* A call whose number is known only at run time; its pin says "any". */
static inline __attribute__((always_inline)) nccall_ret_t nccall_dyn(uint32_t nr, const uintptr_t args[6]) {
    return NCCALL_IMPL_(NCCALL_NR_ANY, nr, args);
}

/* The value, or -1 with the errno in *err (when err is not NULL): the shape
 * a libc wrapper returns. */
static inline intptr_t nccall_result(nccall_ret_t r, int *err) {
    if (r.failed) {
        if (err) *err = (int)r.value;
        return -1;
    }
    return (intptr_t)r.value;
}

/* ---- A few POSIX-class calls, as functions ----------------------------- */
static inline intptr_t nc_write(int fd, const void *buf, size_t len, int *err) {
    return nccall_result(NCCALL(NC_SYS_write, fd, buf, len), err);
}

static inline void *nc_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off, int *err) {
    if (off % 4096u) {
        if (err) *err = NC_EINVAL;
        return (void *)-1;
    }
    nccall_ret_t r = NCCALL(NC_SYS_mmap, addr, len, prot, flags, fd, (uintptr_t)(off / 4096u));
    return r.failed ? (nccall_result(r, err), (void *)-1) : (void *)r.value;
}

static inline int nc_munmap(void *addr, size_t len, int *err) {
    return (int)nccall_result(NCCALL(NC_SYS_munmap, addr, len), err);
}

static inline intptr_t nc_getrandom(void *buf, size_t len, unsigned flags, int *err) {
    return nccall_result(NCCALL(NC_SYS_getrandom, buf, len, flags), err);
}

static inline int nc_clock_gettime(int clock, nc_timespec_t *ts, int *err) {
    return (int)nccall_result(NCCALL(NC_SYS_clock_gettime, clock, ts), err);
}

static inline __attribute__((noreturn)) void nc_exit(int status) {
    (void)NCCALL(NC_SYS_exit, status);
    for (;;) {
    }
}

/* The ABI's self-check: what NC_SYS_echo must return for these arguments. */
static inline nccall_ret_t nc_echo(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                                   uintptr_t a5) {
    return NCCALL(NC_SYS_echo, a0, a1, a2, a3, a4, a5);
}

static inline uintptr_t nc_echo_expect(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                                       uintptr_t a5) {
    return a0 + 2 * a1 + 3 * a2 + 4 * a3 + 5 * a4 + 6 * a5;
}

#ifdef __cplusplus
}
#endif
#endif /* !__ASSEMBLER__ */

#endif /* NCCALL_H */
