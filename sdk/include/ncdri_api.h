/* SPDX-License-Identifier: Apache-2.0 */
/* ncdri_api.h — the stable, opaque binary interface between nckernel and a
 * .ncdri driver module. The only header a driver includes besides the
 * compiler's own freestanding ones (<stddef.h>, <stdint.h>, <stdbool.h>).
 *
 * docs/NCDRI.md is the specification. In one paragraph:
 *
 *   A driver never sees a kernel structure and never links against a kernel
 *   symbol. It exports one function, ncdri_main(), which the loader calls
 *   with a pointer to the kernel's service table (nckernel_api_t) and that
 *   table's size. Everything the driver can do goes through that table, on
 *   handles whose layout only the kernel knows (ncdri_device_t, ncdri_dma_t,
 *   ...). The driver hands back its own table (ncdri_driver_t): FreeBSD
 *   newbus's probe/attach/detach/suspend/resume. Both tables are versioned
 *   by a major number (incompatible change: the loader refuses the module)
 *   and by their size (append-only growth within a major): a field a
 *   driver reads must lie inside the size the kernel reported, which
 *   NCDRI_HAS() checks. A kernel update that adds services therefore never
 *   breaks a built driver, and a driver built against a newer minor still
 *   loads on an older kernel and simply finds the newer services absent.
 *
 * Models: NetBSD's rump hypercall interface (sys/rump/include/rump/
 * rumpuser.h: a version handshake, a function table with reserved slots,
 * opaque lock types), FreeBSD's newbus device methods (sys/kern/device_if.m)
 * and bus_space/bus_dma access discipline, and FreeBSD's fpu_kern_enter()
 * bracket for floating point in the kernel. See NOTICE.
 *
 * Built how (sdk/Makefile, `make drivers`): ring 0, so
 *   - no red zone: -mno-red-zone (x86-64); on 64-bit PowerPC the driver flag
 *     is ignored by clang and absent from GCC, so -Xclang -disable-red-zone
 *     — and the kernel's interrupt entry skips the ELFv2 protected zone
 *     anyway (docs/NCCALL.md §2); tools/check-redzone.py refuses a module
 *     that stores below its stack pointer;
 *   - no floating point or SIMD outside ncdri_fpu_begin()/ncdri_fpu_end():
 *     -mgeneral-regs-only (AArch64, ARM), -mno-sse -mno-mmx -mno-avx
 *     -msoft-float (x86), -msoft-float (PowerPC), -march=..._no F/D (RISC-V);
 *     code that needs SIMD (crypto, checksums) sits in its own translation
 *     units, built with it, and runs only inside the bracket;
 *   - no C library: -ffreestanding -nostdlib; memcpy and friends come from
 *     the kernel table (or the driver's own copies);
 *   - position independent (-fPIC), visibility hidden but for ncdri_main.
 */
#ifndef NCDRI_API_H
#define NCDRI_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Versions ----------------------------------------------------------- */

/* Bumped only for an incompatible change: a field removed or reordered, a
 * function's meaning changed. The loader refuses a driver whose major is not
 * the kernel's. */
#define NCDRI_API_MAJOR 1
/* Bumped when services are appended. Informational: what a driver may use
 * is decided by the size the kernel reports (NCDRI_HAS), not by this. */
#define NCDRI_API_MINOR 1

/* The one symbol a driver exports. */
#define NCDRI_EXPORT __attribute__((visibility("default")))

/* ---- Results -------------------------------------------------------------
 * 0 is success; a failure is a positive errno, FreeBSD's values (the same
 * ones nccall returns to ring 3, crates/nanochrono-sys/src/errno.rs). */
#define NCDRI_OK          0
#define NCDRI_EPERM       1
#define NCDRI_ENOENT      2
#define NCDRI_EIO         5
#define NCDRI_ENXIO       6
#define NCDRI_ENOMEM      12
#define NCDRI_EACCES      13
#define NCDRI_EFAULT      14
#define NCDRI_EBUSY       16
#define NCDRI_EEXIST      17
#define NCDRI_ENODEV      19
#define NCDRI_EINVAL      22
#define NCDRI_ENOSPC      28
#define NCDRI_EAGAIN      35
#define NCDRI_ETIMEDOUT   60
#define NCDRI_ENOSYS      78
#define NCDRI_ENOTSUP     45

/* ---- Opaque handles ------------------------------------------------------
 * Pointers to structures this header never defines. A driver stores them,
 * passes them back, and compares them; it never dereferences them. */
typedef struct ncdri_device   *ncdri_device_t;   /* one device node (newbus device_t) */
typedef struct ncdri_resource *ncdri_resource_t; /* a mapped MMIO or port window (bus_space) */
typedef struct ncdri_dma      *ncdri_dma_t;      /* a DMA-able buffer (bus_dma) */
typedef struct ncdri_irq      *ncdri_irq_t;      /* an established interrupt handler */
typedef struct ncdri_mtx      *ncdri_mtx_t;      /* a lock */
typedef struct ncdri_fpu      *ncdri_fpu_t;      /* a saved floating-point context */
typedef struct ncdri_module   *ncdri_module_t;   /* this module, as the kernel tracks it */

/* ---- What the kernel says about a device it offers a driver ------------- */
#define NCDRI_BUS_PCI      1u
#define NCDRI_BUS_ACPI     2u
#define NCDRI_BUS_FDT      3u
#define NCDRI_BUS_USB      4u
#define NCDRI_BUS_PLATFORM 5u

typedef struct ncdri_devinfo {
    uint32_t size;        /* sizeof as the kernel built it; read fields within it only */
    uint32_t bus;         /* NCDRI_BUS_* */
    /* PCI (and USB vendor/product in the low halves) */
    uint16_t vendor, device, subvendor, subdevice;
    uint8_t  class_code, subclass, progif, revision;
    /* ACPI _HID / FDT "compatible", NUL-terminated, or "" */
    char     hid[32];
    uint32_t reserved[8];
} ncdri_devinfo_t;

/* Probe results (newbus BUS_PROBE_*): the best offer wins. Negative values
 * are offers, lower magnitude better; a positive errno declines. */
#define NCDRI_PROBE_SPECIFIC  0      /* this driver is the only one for it */
#define NCDRI_PROBE_VENDOR    (-10)  /* the vendor's own driver */
#define NCDRI_PROBE_DEFAULT   (-20)  /* a generic driver for a class */
#define NCDRI_PROBE_GENERIC   (-100) /* works, but anything better wins */

/* ---- What the driver hands back: its newbus methods --------------------- */
typedef struct ncdri_driver {
    uint32_t size;          /* sizeof(ncdri_driver_t) the driver was built with */
    uint16_t api_major;     /* NCDRI_API_MAJOR it was built against */
    uint16_t api_minor;     /* NCDRI_API_MINOR it was built against */
    const char *name;       /* "nchv", "mtp", ... */
    size_t softc_size;      /* per-device state the kernel allocates, zeroed */
    /* device_if.m: probe may run several times and must not touch hardware
     * beyond identification; attach brings the device up, detach takes it
     * down and must undo everything attach did. */
    int (*probe)(ncdri_device_t dev, const ncdri_devinfo_t *info);
    int (*attach)(ncdri_device_t dev, void *softc);
    int (*detach)(ncdri_device_t dev, void *softc);
    int (*suspend)(ncdri_device_t dev, void *softc);
    int (*resume)(ncdri_device_t dev, void *softc);
    int (*shutdown)(ncdri_device_t dev, void *softc);
    void *reserved[8];      /* zero */
} ncdri_driver_t;

/* ---- Constants the services take ---------------------------------------- */
/* Log levels */
#define NCDRI_LOG_ERROR 0
#define NCDRI_LOG_WARN  1
#define NCDRI_LOG_INFO  2
#define NCDRI_LOG_DEBUG 3

/* mem_alloc flags */
#define NCDRI_MEM_ZERO   0x1u   /* zero the memory */
#define NCDRI_MEM_NOWAIT 0x2u   /* fail rather than wait (required in interrupt context) */

/* resource_map kinds */
#define NCDRI_RES_MEMORY 1u     /* a BAR / reg window of memory-mapped registers */
#define NCDRI_RES_IOPORT 2u     /* an x86 I/O port range */

/* dma_alloc flags and dma_sync operations (bus_dmamap_sync) */
#define NCDRI_DMA_COHERENT 0x1u /* uncached or snooped: sync is a barrier only */
#define NCDRI_DMA_32BIT    0x2u /* the device addresses only the low 4 GiB */
#define NCDRI_DMA_PREREAD   0x1u
#define NCDRI_DMA_POSTREAD  0x2u
#define NCDRI_DMA_PREWRITE  0x4u
#define NCDRI_DMA_POSTWRITE 0x8u

/* Interrupt handler results */
#define NCDRI_IRQ_NOT_MINE 0
#define NCDRI_IRQ_HANDLED  1

/* mtx_init kinds */
#define NCDRI_MTX_SPIN  1u      /* may be taken in interrupt context; never sleeps */
#define NCDRI_MTX_SLEEP 2u      /* may sleep while waiting; never in interrupt context */

/* ---- Display (minor 1) ---------------------------------------------------
 * A display driver that has set a mode tells the kernel where the picture
 * is: which of the device's memory windows (resource_map's
 * NCDRI_RES_MEMORY index, a BAR) holds it, where in it, and its geometry.
 * The kernel maps the window itself — no raw device pointer crosses — checks
 * that the surface lies inside it, and draws the session there from then on.
 * All fields fixed-width: the same layout on every architecture. */
#define NCDRI_FORMAT_XRGB8888 0x34325258u /* DRM fourcc 'XR24': 32-bit 0x00RRGGBB, little-endian */

typedef struct ncdri_scanout {
    uint32_t size;       /* sizeof(ncdri_scanout_t) the driver was built with */
    uint32_t res_index;  /* the memory window (BAR) holding the surface */
    uint64_t offset;     /* where in that window the first pixel is */
    uint32_t width;
    uint32_t height;
    uint32_t pitch;      /* bytes from one row to the next */
    uint32_t format;     /* NCDRI_FORMAT_* */
    uint32_t reserved[6];
} ncdri_scanout_t;

/* fpu_begin flags (FreeBSD FPU_KERN_*) */
#define NCDRI_FPU_NORMAL 0x0u
#define NCDRI_FPU_NOCTX  0x4u   /* no saved context: preemption off, short sections only */

/* ---- The kernel's table --------------------------------------------------
 * Context column: "any" = also in interrupt context; "sleep" = only where
 * the caller may sleep (probe, attach, detach, suspend, resume, threads). */
typedef struct nckernel_api {
    uint32_t size;          /* sizeof(nckernel_api_t) as the kernel built it */
    uint16_t api_major;     /* NCDRI_API_MAJOR the kernel implements */
    uint16_t api_minor;     /* NCDRI_API_MINOR the kernel implements */
    const char *kernel_version; /* "4.0.0", for logs */

    /* Identity and registration (sleep) */
    ncdri_module_t self;
    int (*driver_register)(ncdri_module_t self, const ncdri_driver_t *drv);
    int (*driver_unregister)(ncdri_module_t self, const ncdri_driver_t *drv);
    const char *(*device_name)(ncdri_device_t dev);           /* "nchv0" (any) */
    void *(*device_softc)(ncdri_device_t dev);                 /* (any) */

    /* Log (any): one line, not NUL-terminated, no format processing. */
    void (*log)(ncdri_device_t dev, int level, const char *msg, size_t len);

    /* Wired kernel memory, never paged. Sizes are explicit both ways, as in
     * rumpuser_malloc/rumpuser_free. (sleep, or any with NOWAIT) */
    int  (*mem_alloc)(size_t size, size_t align, uint32_t flags, void **out);
    void (*mem_free)(void *p, size_t size);

    /* Device registers: map a window, then read and write it only through
     * these accessors, which carry the ordering and the barriers the
     * architecture needs. No raw pointer to device memory ever reaches a
     * driver. (map/unmap: sleep; accessors: any) */
    int  (*resource_map)(ncdri_device_t dev, uint32_t kind, uint32_t index, ncdri_resource_t *out, uint64_t *len);
    void (*resource_unmap)(ncdri_resource_t res);
    uint8_t  (*read_1)(ncdri_resource_t res, uint64_t off);
    uint16_t (*read_2)(ncdri_resource_t res, uint64_t off);
    uint32_t (*read_4)(ncdri_resource_t res, uint64_t off);
    uint64_t (*read_8)(ncdri_resource_t res, uint64_t off);
    void (*write_1)(ncdri_resource_t res, uint64_t off, uint8_t v);
    void (*write_2)(ncdri_resource_t res, uint64_t off, uint16_t v);
    void (*write_4)(ncdri_resource_t res, uint64_t off, uint32_t v);
    void (*write_8)(ncdri_resource_t res, uint64_t off, uint64_t v);
    void (*barrier)(ncdri_resource_t res, uint64_t off, uint64_t len, uint32_t flags);

    /* PCI configuration space (any) */
    int (*pci_cfg_read)(ncdri_device_t dev, uint32_t off, uint32_t width, uint32_t *out);
    int (*pci_cfg_write)(ncdri_device_t dev, uint32_t off, uint32_t width, uint32_t v);
    int (*pci_enable_busmaster)(ncdri_device_t dev, int on);

    /* DMA (bus_dma): memory a device may read and write, its address as the
     * device sees it (behind the IOMMU, when there is one), and the syncs
     * that make CPU and device views agree. (alloc/free: sleep; rest: any) */
    int      (*dma_alloc)(ncdri_device_t dev, size_t size, size_t align, uint64_t boundary, uint32_t flags, ncdri_dma_t *out);
    void     (*dma_free)(ncdri_dma_t dma);
    void    *(*dma_kva)(ncdri_dma_t dma);
    uint64_t (*dma_bus_addr)(ncdri_dma_t dma);
    void     (*dma_sync)(ncdri_dma_t dma, size_t off, size_t len, uint32_t ops);

    /* Interrupts (sleep). The handler runs in interrupt context, on the
     * kernel's interrupt stack, with this header's "any" services only. */
    int  (*irq_establish)(ncdri_device_t dev, uint32_t index, int (*handler)(void *arg), void *arg, ncdri_irq_t *out);
    void (*irq_disestablish)(ncdri_irq_t irq);

    /* Locks (init/destroy: sleep; enter/exit: per kind) */
    int  (*mtx_init)(ncdri_mtx_t *out, uint32_t kind, const char *name);
    void (*mtx_enter)(ncdri_mtx_t m);
    int  (*mtx_tryenter)(ncdri_mtx_t m);
    void (*mtx_exit)(ncdri_mtx_t m);
    void (*mtx_destroy)(ncdri_mtx_t m);

    /* Time (any): the kernel's monotonic nanoseconds; a busy wait. */
    uint64_t (*time_ns)(void);
    void (*delay_ns)(uint64_t ns);

    /* Floating point and SIMD (any). Between begin and end the driver may
     * use the FP/SIMD registers; the kernel has saved whatever context they
     * belonged to and restores it at end. Nowhere else. (FreeBSD
     * fpu_kern_enter/fpu_kern_leave.) A NULL ctx with NCDRI_FPU_NOCTX
     * disables preemption instead of saving into a context. */
    int  (*fpu_alloc)(ncdri_fpu_t *out);
    void (*fpu_free)(ncdri_fpu_t ctx);
    void (*fpu_begin)(ncdri_fpu_t ctx, uint32_t flags);
    void (*fpu_end)(ncdri_fpu_t ctx);

    /* Memory helpers (any), so a driver need carry none of its own. */
    void *(*memcpy)(void *dst, const void *src, size_t n);
    void *(*memset)(void *dst, int c, size_t n);
    int   (*memcmp)(const void *a, const void *b, size_t n);

    /* Entropy (any): NC_RNG, the kernel's pool. */
    int (*rng_fill)(void *buf, size_t len, uint32_t flags);

    /* ---- Minor 1 ---- */

    /* Display (sleep: attach). Hands the kernel the scanout of a mode the
     * driver has set (ncdri_scanout_t, above); `edid` (or NULL) is the
     * monitor's EDID, which the kernel names the monitor from. Only the
     * XRGB8888 format today. */
    int (*display_scanout)(ncdri_device_t dev, const ncdri_scanout_t *s, const uint8_t *edid, size_t edid_len);
    /* The native mode an EDID declares — its first detailed timing — through
     * the kernel's parser, which checks the header, the checksum and the
     * version. NCDRI_ENOENT when the EDID names no preferred mode. (any) */
    int (*edid_preferred)(const uint8_t *edid, size_t len, uint32_t *width, uint32_t *height, uint32_t *refresh_mhz);

    /* Growth: new services are appended here within a major version,
     * taking slots from the start of this array, so the table keeps its
     * size. A kernel always zeroes what it does not implement. */
    void *reserved[30];
} nckernel_api_t;

/* Whether the kernel's table `k` reaches field `f`: what a driver checks
 * before calling a service newer than NCDRI_API_MINOR 0. */
#define NCDRI_HAS(k, f) \
    ((k) != NULL && (k)->size >= offsetof(nckernel_api_t, f) + sizeof(((nckernel_api_t *)0)->f) && (k)->f != NULL)

/* ---- The entry point ----------------------------------------------------
 * Called once, after relocation, in a sleepable context, with the kernel's
 * table and its size. The driver checks the major version, keeps `k`, and
 * registers its drivers. Return NCDRI_OK, or an errno to have the module
 * unloaded again. (The table outlives the module; it is never freed.) */
typedef int (*ncdri_main_fn)(const nckernel_api_t *k, uint32_t k_size);
NCDRI_EXPORT int ncdri_main(const nckernel_api_t *k, uint32_t k_size);

/* Unloading: called (sleep) after every device has been detached, before
 * the module's memory goes. Optional: a module without it cannot be
 * unloaded. */
NCDRI_EXPORT void ncdri_fini(void);

/* ---- The names drivers write ---------------------------------------------
 * Thin inline wrappers over the table, so driver code reads as the API it
 * is (ncdri_log, ncdri_alloc_dma, ncdri_register_device ...) while the
 * binary interface stays the table. A driver defines the pointer once —
 *     const nckernel_api_t *ncdri_k;
 * — and sets it in ncdri_main. */
extern const nckernel_api_t *ncdri_k;

static inline int ncdri_register_device(const ncdri_driver_t *drv) {
    return ncdri_k->driver_register(ncdri_k->self, drv);
}
static inline void ncdri_log(ncdri_device_t dev, int level, const char *msg, size_t len) {
    ncdri_k->log(dev, level, msg, len);
}
static inline int ncdri_alloc_dma(ncdri_device_t dev, size_t size, size_t align, uint32_t flags, ncdri_dma_t *out) {
    return ncdri_k->dma_alloc(dev, size, align, 0, flags, out);
}
static inline void ncdri_free_dma(ncdri_dma_t dma) {
    ncdri_k->dma_free(dma);
}
static inline int ncdri_alloc(size_t size, uint32_t flags, void **out) {
    return ncdri_k->mem_alloc(size, sizeof(void *) * 2, flags, out);
}
static inline void ncdri_free(void *p, size_t size) {
    ncdri_k->mem_free(p, size);
}
static inline uint32_t ncdri_read_4(ncdri_resource_t r, uint64_t off) {
    return ncdri_k->read_4(r, off);
}
static inline void ncdri_write_4(ncdri_resource_t r, uint64_t off, uint32_t v) {
    ncdri_k->write_4(r, off, v);
}

/* ---- Layout pins -----------------------------------------------------------
 * The first fields never move: a loader of any version reads `size` and the
 * versions from the same offsets. */
_Static_assert(offsetof(nckernel_api_t, size) == 0, "nckernel_api_t.size moved");
_Static_assert(offsetof(nckernel_api_t, api_major) == 4, "nckernel_api_t.api_major moved");
_Static_assert(offsetof(nckernel_api_t, api_minor) == 6, "nckernel_api_t.api_minor moved");
_Static_assert(offsetof(ncdri_driver_t, size) == 0, "ncdri_driver_t.size moved");
_Static_assert(offsetof(ncdri_driver_t, api_major) == 4, "ncdri_driver_t.api_major moved");
_Static_assert(offsetof(ncdri_devinfo_t, size) == 0, "ncdri_devinfo_t.size moved");
_Static_assert(sizeof(ncdri_devinfo_t) == 84, "ncdri_devinfo_t is 84 bytes on every architecture");
/* The table keeps its size within a major: new services take reserved[]
 * slots (8 bytes of size and versions, then 77 pointer-sized slots). */
_Static_assert(sizeof(nckernel_api_t) == 8 + 77 * sizeof(void *), "nckernel_api_t changed size within a major");
_Static_assert(offsetof(nckernel_api_t, rng_fill) == 8 + 44 * sizeof(void *), "nckernel_api_t.rng_fill moved");
_Static_assert(offsetof(nckernel_api_t, display_scanout) == 8 + 45 * sizeof(void *), "nckernel_api_t.display_scanout moved");
_Static_assert(sizeof(ncdri_scanout_t) == 56, "ncdri_scanout_t is 56 bytes on every architecture");
_Static_assert(offsetof(ncdri_scanout_t, offset) == 8 && offsetof(ncdri_scanout_t, format) == 28,
               "ncdri_scanout_t's fields moved");

#ifdef __cplusplus
}
#endif

#endif /* NCDRI_API_H */
