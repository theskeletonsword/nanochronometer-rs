/* SPDX-License-Identifier: Apache-2.0 */
/* ncplu_rt.c — the freestanding C runtime a plugin links in.
 *
 * Even with -ffreestanding the compiler emits calls to memcpy, memmove,
 * memset and memcmp (struct copies, zeroing large locals), and the plugin
 * loader resolves no function imports. So they live in the plugin, hidden.
 * Byte loops: correct at -O0 and small; -ffreestanding keeps the compiler
 * from turning them back into calls to themselves. */
#include "ncplu.h"

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    uint8_t *d = dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    for (; n; n--, x++, y++)
        if (*x != *y) return *x - *y;
    return 0;
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}
