/* SPDX-License-Identifier: Apache-2.0 */
/* poke.c — a hostile plugin: it aims kernel services at kernel memory. Every
 * such call must be refused (a negative code, or a no-op), the kernel memory
 * left untouched, and nothing must crash. Proves the pointer checks on the
 * NcApi boundary. */
#include "ncplu.h"

static void log_str(const nc_api_t *api, const char *s) {
    api->log((const uint8_t *)s, strlen(s));
}
static void log_i64(const nc_api_t *api, const char *name, int64_t v) {
    char buf[64]; size_t n = 0;
    while (name[n] && n < 40) { buf[n] = name[n]; n++; }
    if (v < 0) { buf[n++] = '-'; v = -v; }
    char d[20]; size_t k = 0;
    do { d[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (k) buf[n++] = d[--k];
    buf[n++] = '\n';
    api->log((const uint8_t *)buf, n);
}

NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api) {
    log_str(api, "poke: aiming kernel services at kernel memory\n");

    /* The kernel image loads at 1 MiB; its .text/.data are up there. Ask the
     * RNG to overwrite it. The kernel must refuse: the buffer is not ours. */
    void *kernel = (void *)0x00100000ULL;
    int64_t r1 = api->rng_fill(kernel, 64, NC_RNG_FAST);
    log_i64(api, "rng_fill(kernel .text) -> ", r1);

    /* A status write into the kernel's own stack region (near the top of low
     * memory). Refused the same way. */
    int64_t r2 = api->rng_status((nc_rng_status_t *)0x000f0000ULL);
    log_i64(api, "rng_status(kernel mem) -> ", (int64_t)r2);

    /* Log from a kernel address: a read the kernel must not make on our say-so
     * (it would leak kernel memory to the serial port). A no-op if refused. */
    api->log((const uint8_t *)0x00100000ULL, 32);
    log_str(api, "log(kernel mem) returned (nothing above if refused)\n");

    /* A buffer that starts in our arena but runs off its end into kernel
     * memory: the length check, not just the base, must catch it. */
    static uint8_t mine[16];
    int64_t r3 = api->rng_fill(mine, 1 << 20, NC_RNG_FAST); /* 1 MiB from a 16 B buffer */
    log_i64(api, "rng_fill(overrun) -> ", r3);

    /* And a legitimate call still works. */
    uint8_t ok[16];
    int64_t r4 = api->rng_fill(ok, sizeof ok, NC_RNG_FAST);
    log_i64(api, "rng_fill(our buffer) -> ", r4);
    log_str(api, "poke: done, kernel still alive\n");
    return 0;
}
