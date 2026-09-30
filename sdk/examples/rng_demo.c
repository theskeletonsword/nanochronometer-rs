/* SPDX-License-Identifier: Apache-2.0 */
/* rng_demo.c — a C plugin: NC_RNG, NC_TIMER and a kernel data import.
 *
 * Logs the pool's state, times one NC_RNG_TRUE read, then fills the screen
 * with rectangles whose position and colour come from NC_RNG_FAST, stirring
 * each key press back in. Esc (or ~5 s) returns to the interface. */
#include "ncplu.h"

static void log_str(const nc_api_t *api, const char *s) {
    api->log((const uint8_t *)s, strlen(s));
}

/* "name value\n" with the value in decimal, no libc. */
static void log_u64(const nc_api_t *api, const char *name, uint64_t v) {
    char buf[64];
    size_t n = 0;
    while (name[n] && n < 40) {
        buf[n] = name[n];
        n++;
    }
    char digits[20];
    size_t d = 0;
    do {
        digits[d++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (d) buf[n++] = digits[--d];
    buf[n++] = '\n';
    api->log((const uint8_t *)buf, n);
}

static void log_hex(const nc_api_t *api, const char *name, const uint8_t *b, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char buf[128];
    size_t n = 0;
    while (name[n] && n < 40) {
        buf[n] = name[n];
        n++;
    }
    for (size_t i = 0; i < len && n + 3 < sizeof buf; i++) {
        buf[n++] = hex[b[i] >> 4];
        buf[n++] = hex[b[i] & 15];
    }
    buf[n++] = '\n';
    api->log((const uint8_t *)buf, n);
}

NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api) {
    log_str(api, "rng_demo: starting (C plugin)\n");
    log_u64(api, "rng_demo: kernel ABI ", nc_abi_version); /* IMPORT64 */

    nc_rng_status_t st;
    memset(&st, 0, sizeof st);
    st.size = sizeof st;
    if (api->rng_status(&st) == 0) {
        log_u64(api, "rng_demo: engine ", st.engine);
        log_u64(api, "rng_demo: sources ", st.sources);
        log_u64(api, "rng_demo: nonces ", st.nonces);
    }

    /* One credited 32-byte block, timed with the serialised timer. */
    uint8_t key[32];
    uint64_t t0 = api->timer_now();
    int64_t got = api->rng_fill(key, sizeof key, NC_RNG_TRUE);
    uint64_t t1 = api->timer_now_end();
    if (got != (int64_t)sizeof key) {
        log_u64(api, "rng_demo: NC_RNG refused, code -", (uint64_t)-got);
        return 1;
    }
    log_hex(api, "rng_demo: TRUE block ", key, sizeof key);
    log_u64(api, "rng_demo: TRUE block ns ", api->timer_ticks_to_ns(t1 - t0));

    uint64_t deadline = api->ticks() + 5 * api->ticks_per_sec;
    uint32_t w = api->screen_w, h = api->screen_h;
    api->clear(0x000000);
    while (api->ticks() < deadline) {
        uint32_t ev;
        while ((ev = api->poll_event()) != 0) {
            api->rng_stir(NC_RNG_EVENT_USER, ev); /* the key's timing, into the pool */
            if ((ev & NC_EVENT_PRESSED) && NC_EVENT_SCANCODE(ev) == NC_SC_ESC) {
                log_str(api, "rng_demo: esc\n");
                return 0;
            }
        }
        uint32_t r[4];
        if (api->rng_fill(r, sizeof r, NC_RNG_FAST) != (int64_t)sizeof r) return 2;
        int32_t x = (int32_t)(r[0] % w), y = (int32_t)(r[1] % h);
        int32_t s = 8 + (int32_t)(r[2] % 48);
        api->fill_rect(x, y, s, s, r[3] & 0xFFFFFF);
        api->present();
    }
    log_str(api, "rng_demo: done\n");
    return 0;
}
