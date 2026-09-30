/* SPDX-License-Identifier: Apache-2.0 */
/* peek.c — reads kernel memory directly (not through a service). At ring 3
 * this faults on the very first access and the kernel contains it; a plugin
 * cannot reach kernel memory at all. (A kernel-tier plugin would succeed —
 * which is exactly why only signed plugins get the kernel.) */
#include "ncplu.h"

NCPLU_EXPORT int32_t ncplu_main(const nc_api_t *api) {
    const char *msg = "peek: reading kernel memory at 0x100000 directly\n";
    api->log((const uint8_t *)msg, strlen(msg));
    /* The kernel image loads at 1 MiB. Read one byte of it. */
    volatile const uint8_t *kernel = (const uint8_t *)0x00100000ULL;
    uint8_t stolen = *kernel;                 /* #PF at ring 3 */
    /* If we get here we are NOT isolated — report the byte we read. */
    char out[48];
    size_t n = 0;
    const char *p = "peek: READ kernel byte = 0x";
    while (p[n]) { out[n] = p[n]; n++; }
    const char h[] = "0123456789abcdef";
    out[n++] = h[stolen >> 4]; out[n++] = h[stolen & 15]; out[n++] = '\n';
    api->log((const uint8_t *)out, n);
    return 0;
}
