/* SPDX-License-Identifier: Apache-2.0 */
/* faulter.c — a plugin that deliberately faults, to prove the kernel contains
 * it. `plugin=faulter mode=<ud|null|div|stack>` picks how; default null.
 * The kernel should stop it, say so, and return to the interface. */
#include "ncplu.h"

static void log_str(const nc_api_t *api, const char *s) {
    api->log((const uint8_t *)s, strlen(s));
}

static volatile int recurse(volatile int x) {
    volatile char eat[4096];
    for (int i = 0; i < 4096; i++) eat[i] = (char)(x + i);
    return recurse(x + eat[x & 4095]) + 1; /* unbounded: runs off the stack */
}

NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api) {
    log_str(api, "faulter: about to fault on purpose\n");
    /* No command line reaches a plugin, so pick by the low bit of the clock:
     * a null write most of the time, an invalid opcode sometimes, and a stack
     * overflow occasionally, so repeated runs exercise several paths. */
    uint64_t pick = api->ticks() % 3;
    if (pick == 0) {
        volatile uint32_t *p = (uint32_t *)0; /* #PF: unmapped page 0 */
        *p = 0xdead;
    } else if (pick == 1) {
        __asm__ volatile("ud2"); /* #UD: invalid opcode */
    } else {
        return recurse(1); /* runs off its stack into the guard page */
    }
    log_str(api, "faulter: still here (should not happen)\n");
    return 0;
}
