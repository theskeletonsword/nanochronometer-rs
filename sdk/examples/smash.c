/* SPDX-License-Identifier: Apache-2.0 */
/* smash.c — a plugin that overflows a buffer on its own stack, to prove the
 * stack canary catches it. Built with -fstack-protector-strong (sdk/Makefile),
 * copy_unchecked gets a canary between its buffer and its return address; the
 * overflow overwrites it, and the check on the way out calls
 * __stack_chk_fail, which the kernel provides: the plugin is stopped and the
 * kernel says so, before the corrupted return address is ever used. */
#include "ncplu.h"

static void log_str(const nc_api_t *api, const char *s) {
    api->log((const uint8_t *)s, strlen(s));
}

/* The classic bug: a length from outside, a fixed buffer, no check. */
static __attribute__((noinline)) void copy_unchecked(const uint8_t *src, size_t len) {
    char buf[16];
    volatile char *dst = buf; /* volatile: every byte really is written */
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)src[i];
    }
    __asm__ volatile("" : : "r"(dst) : "memory");
}

NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api) {
    static const uint8_t attack[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    log_str(api, "smash: copying 64 bytes into a 16-byte stack buffer\n");
    copy_unchecked(attack, 64);
    log_str(api, "smash: returned; the canary did not fire\n");
    return 1;
}
