/* SPDX-License-Identifier: Apache-2.0 */
/* ncplu.h — the NanoChronometer plugin ABI, for plugins written in C.
 *
 * Mirrors NcApi in crates/nanochrono-baremetal/src/ncplu.rs and the NC_RNG
 * status in crates/nanochrono-core/src/rng/mod.rs, field for field. The
 * table is append-only: a service is only ever added at the end, so a plugin
 * built against a shorter table keeps working. The static asserts at the end
 * pin the layout; ncplu.rs asserts the same size from the Rust side.
 *
 * A plugin exports one function,
 *
 *     NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api);
 *
 * and reaches the kernel only through `api`: there is no libc, no PLT and no
 * dynamic linker. Kernel *data* may be imported by name (see nc_abi_version).
 *
 * Stack canaries: the SDK builds with -fstack-protector-strong and
 * -mstack-protector-guard=global, and the kernel provides the two symbols
 * that code imports — `__stack_chk_guard`, a canary drawn from NC_RNG for
 * every run (its low byte zero), and `__stack_chk_fail`, which stops the
 * plugin, in the kernel or at ring 3, before a smashed return address is
 * used. A plugin needs to declare neither.
 */
#ifndef NCPLU_H
#define NCPLU_H

#include <stddef.h>
#include <stdint.h>

#define NCPLU_ABI_VERSION 1u

/* The one symbol a plugin exports. Everything else stays hidden
 * (-fvisibility=hidden), which keeps the image free of dynamic relocations. */
#define NCPLU_EXPORT __attribute__((visibility("default")))

/* Capabilities: the service groups a plugin declares it needs, packed into the
 * .ncplu header by `tools/ncplu.py pack --caps ...`. The kernel grants no more
 * than the plugin asked for, so a community (ring-3) plugin that calls past its
 * set is stopped, and a kernel-tier plugin's ungranted calls are refused. Pass
 * `--caps screen,input,log,timer,pmu,rng` (or `all` / `none`) at pack time.
 * These are documentation of the bit values; a plugin does not read them. */
#define NC_CAP_SCREEN (1u << 0) /* fill_rect, clear, present */
#define NC_CAP_INPUT  (1u << 1) /* poll_event */
#define NC_CAP_LOG    (1u << 2) /* log */
#define NC_CAP_TIMER  (1u << 3) /* ticks, timer_* */
#define NC_CAP_PMU    (1u << 4) /* pmu_* */
#define NC_CAP_RNG    (1u << 5) /* rng_* */

/* ---- poll_event -------------------------------------------------------- */
/* 0 = no event; otherwise bit 31 set, bit 8 = pressed, bits 7..0 = set-1
 * scancode. */
#define NC_EVENT_VALID      (1u << 31)
#define NC_EVENT_PRESSED    (1u << 8)
#define NC_EVENT_SCANCODE(e) ((uint8_t)((e) & 0xFFu))
#define NC_SC_ESC           0x01u

/* ---- NC_TIMER ---------------------------------------------------------- */
#define NC_TIMER_OTHER  0u
#define NC_TIMER_TSC    1u /* x86 RDTSC/RDTSCP */
#define NC_TIMER_CNTVCT 2u /* AArch64 virtual count */
#define NC_TIMER_CNTPCT 3u /* AArch64 physical count */

/* ---- NC_PMU ------------------------------------------------------------ */
#define NC_PMU_CYCLES       0u
#define NC_PMU_INSTRUCTIONS 1u
#define NC_PMU_CACHE_MISSES 2u

/* ---- NC_RNG ------------------------------------------------------------ */
#define NC_RNG_FAST 0u /* the output stage (AES-256-CTR / ChaCha20) */
#define NC_RNG_TRUE 1u /* a fresh credited seed before every 32 bytes */

#define NC_RNG_EMISUSE           (-1)
#define NC_RNG_ERCT              (-2)
#define NC_RNG_EAPT              (-3)
#define NC_RNG_ETIMER            (-4)
#define NC_RNG_ELAG              (-5)
#define NC_RNG_ERCT_PERMANENT    (-6)
#define NC_RNG_EAPT_PERMANENT    (-7)
#define NC_RNG_ELAG_PERMANENT    (-8)
#define NC_RNG_EMEMORY           (-9)
#define NC_RNG_EMEMORY_PERMANENT (-10)
#define NC_RNG_ESELFTEST         (-11)
#define NC_RNG_ENOSOURCE         (-12)

#define NC_RNG_READY           (1u << 0)
#define NC_RNG_DEGRADED        (1u << 1)
#define NC_RNG_FAILED          (1u << 2)
#define NC_RNG_SELFTEST_PASSED (1u << 3)
#define NC_RNG_ENGINE_FALLBACK (1u << 4)

#define NC_RNG_SOURCE_JITTER   (1u << 0)
#define NC_RNG_SOURCE_RDSEED   (1u << 1)
#define NC_RNG_SOURCE_RDRAND   (1u << 2)
#define NC_RNG_SOURCE_PMU      (1u << 3)
#define NC_RNG_SOURCE_EVENTS   (1u << 4)
#define NC_RNG_SOURCE_EXTERNAL (1u << 5)

#define NC_RNG_ENGINE_VAES512  1u
#define NC_RNG_ENGINE_VAES256  2u
#define NC_RNG_ENGINE_AESNI    3u
#define NC_RNG_ENGINE_ARM_AES  4u
#define NC_RNG_ENGINE_CHACHA20 5u

#define NC_RNG_EVENT_USER 0x100u /* first rng_stir tag a plugin may use */

/* Set `size` to sizeof(nc_rng_status_t) before calling rng_status. */
typedef struct nc_rng_status {
    uint32_t size;
    uint32_t flags;     /* NC_RNG_READY, ... */
    uint32_t sources;   /* NC_RNG_SOURCE_* that fed the last seed */
    uint32_t available; /* NC_RNG_SOURCE_* this machine offers */
    uint32_t health;    /* latched health-test failures */
    int32_t last_error; /* NC_RNG_E*, 0 if none */
    uint32_t osr;
    uint32_t startup_stuck_permille;
    uint32_t engine; /* NC_RNG_ENGINE_* */
    uint32_t reserved;
    uint64_t granularity;
    uint64_t reseeds;
    uint64_t bytes_out;
    uint64_t jitter_samples;
    uint64_t jitter_stuck;
    uint64_t events;
    uint64_t hw_words;
    uint64_t nonces; /* output-stage nonces used, never reused */
} nc_rng_status_t;

/* ---- the service table ------------------------------------------------- */
typedef struct nc_api {
    uint32_t abi_version;
    uint32_t screen_w;
    uint32_t screen_h;
    uint32_t reserved;
    uint64_t ticks_per_sec;
    /* screen, input, log */
    void (*fill_rect)(int32_t x, int32_t y, int32_t w, int32_t h, uint32_t rgb);
    void (*clear)(uint32_t rgb);
    void (*present)(void);
    uint32_t (*poll_event)(void);
    uint64_t (*ticks)(void);
    void (*log)(const uint8_t *msg, size_t len);
    /* NC_TIMER: serialised reads, start (LFENCE;RDTSC) and end (RDTSCP;LFENCE) */
    uint64_t (*timer_now)(void);
    uint64_t (*timer_now_end)(void);
    uint64_t (*timer_hz)(void);
    uint32_t (*timer_source)(void);
    uint64_t (*timer_ticks_to_ns)(uint64_t ticks);
    /* NC_PMU */
    uint32_t (*pmu_caps)(void);
    int32_t (*pmu_open)(uint32_t event);
    uint64_t (*pmu_read)(int32_t handle);
    void (*pmu_close)(int32_t handle);
    /* NC_RNG */
    int64_t (*rng_fill)(void *buf, size_t len, uint32_t flags);
    int32_t (*rng_status)(nc_rng_status_t *out);
    void (*rng_stir)(uint64_t tag, uint64_t value);
} nc_api_t;

/* Trust tiers, decided by the plugin's signature (see the kernel loader). A
 * plugin cannot ask for a tier; the kernel assigns it. For information only —
 * a plugin does not read this.
 *   - Creator (✅): signed by the creator's key; runs in the kernel.
 *   - TreeRoot (🌳): signed by a root the machine's owner trusts; runs in the
 *     kernel.
 *   - Community (no badge): unsigned or untrusted; bound for ring 3.
 * Sign a plugin with tools/ncplu-sign; keys come from `ncplu-sign keygen` and
 * live outside the repository. */
#define NC_TIER_CREATOR   0u
#define NC_TIER_TREE_ROOT 1u
#define NC_TIER_COMMUNITY 2u

/* A kernel data symbol, imported by name through an IMPORT64 relocation. */
extern const uint32_t nc_abi_version;

NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api);

/* The freestanding runtime (runtime/ncplu_rt.c): the compiler may emit calls
 * to these for struct copies and zeroing even with -ffreestanding. */
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

/* Layout pins: must match the kernel (x86-64, LP64). */
_Static_assert(sizeof(nc_rng_status_t) == 104, "nc_rng_status_t layout");
_Static_assert(offsetof(nc_api_t, fill_rect) == 24, "NcApi header");
_Static_assert(offsetof(nc_api_t, timer_now) == 72, "NcApi NC_TIMER");
_Static_assert(offsetof(nc_api_t, pmu_caps) == 112, "NcApi NC_PMU");
_Static_assert(offsetof(nc_api_t, rng_fill) == 144, "NcApi NC_RNG");
_Static_assert(sizeof(nc_api_t) == 168, "NcApi size");

#endif /* NCPLU_H */
