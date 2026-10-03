/* SPDX-License-Identifier: Apache-2.0 */
/* hello_ncdri.c — the smallest complete .ncdri: it claims QEMU's "edu"
 * teaching device (PCI 1234:11e8), maps its registers, checks the
 * identification register, sets up a DMA buffer and an interrupt, and takes
 * everything down again on detach. Everything it does goes through
 * ncdri_api.h; it includes no kernel header and imports no kernel symbol.
 *
 * Built by `make -C sdk drivers` for every architecture, with the ring-0
 * flags (no red zone, no FP/SIMD outside ncdri_fpu_begin/end), and checked
 * by tools/check-redzone.py. Loading .ncdri modules at boot is the kernel's
 * next step (docs/NCDRI.md §7); this is what such a module looks like.
 */
#include <ncdri_api.h>

const nckernel_api_t *ncdri_k;

/* The edu device's registers (QEMU docs/specs/edu.rst). */
#define EDU_VENDOR     0x1234
#define EDU_DEVICE     0x11e8
#define EDU_REG_ID     0x00 /* 0xRRrr00ed: major and minor in the top bytes */
#define EDU_REG_LIVE   0x04 /* reads back the bitwise inverse of what is written */
#define EDU_REG_IRQ_ST 0x24
#define EDU_REG_IRQ_AK 0x64

struct hello_softc {
    ncdri_device_t dev;
    ncdri_resource_t regs;
    ncdri_dma_t buf;
    ncdri_irq_t irq;
    uint32_t irqs;
};

static void say(ncdri_device_t dev, const char *msg) {
    size_t n = 0;
    while (msg[n]) n++;
    ncdri_log(dev, NCDRI_LOG_INFO, msg, n);
}

static int hello_intr(void *arg) {
    struct hello_softc *sc = arg;
    uint32_t st = ncdri_read_4(sc->regs, EDU_REG_IRQ_ST);
    if (st == 0) return NCDRI_IRQ_NOT_MINE;
    ncdri_write_4(sc->regs, EDU_REG_IRQ_AK, st);
    sc->irqs++;
    return NCDRI_IRQ_HANDLED;
}

static int hello_probe(ncdri_device_t dev, const ncdri_devinfo_t *info) {
    (void)dev;
    if (info->bus != NCDRI_BUS_PCI) return NCDRI_ENXIO;
    if (info->vendor != EDU_VENDOR || info->device != EDU_DEVICE) return NCDRI_ENXIO;
    return NCDRI_PROBE_SPECIFIC;
}

static int hello_detach(ncdri_device_t dev, void *softc);

static int hello_attach(ncdri_device_t dev, void *softc) {
    struct hello_softc *sc = softc;
    uint64_t len = 0;
    int err;

    sc->dev = dev;
    err = ncdri_k->resource_map(dev, NCDRI_RES_MEMORY, 0, &sc->regs, &len);
    if (err) return err;

    /* The liveness register returns the inverse: proof the window is the
     * device and not a hole. */
    ncdri_write_4(sc->regs, EDU_REG_LIVE, 0x12345678u);
    if (ncdri_read_4(sc->regs, EDU_REG_LIVE) != ~0x12345678u) {
        say(dev, "edu: liveness check failed");
        hello_detach(dev, sc);
        return NCDRI_EIO;
    }
    err = ncdri_alloc_dma(dev, 4096, 4096, NCDRI_DMA_COHERENT | NCDRI_DMA_32BIT, &sc->buf);
    if (err) {
        hello_detach(dev, sc);
        return err;
    }
    ncdri_k->memset(ncdri_k->dma_kva(sc->buf), 0, 4096);
    ncdri_k->dma_sync(sc->buf, 0, 4096, NCDRI_DMA_PREWRITE);

    err = ncdri_k->irq_establish(dev, 0, hello_intr, sc, &sc->irq);
    if (err) {
        hello_detach(dev, sc);
        return err;
    }
    ncdri_k->pci_enable_busmaster(dev, 1);
    say(dev, "edu: attached");
    return NCDRI_OK;
}

static int hello_detach(ncdri_device_t dev, void *softc) {
    struct hello_softc *sc = softc;
    if (sc->irq) ncdri_k->irq_disestablish(sc->irq);
    ncdri_k->pci_enable_busmaster(dev, 0);
    if (sc->buf) ncdri_free_dma(sc->buf);
    if (sc->regs) ncdri_k->resource_unmap(sc->regs);
    sc->irq = 0;
    sc->buf = 0;
    sc->regs = 0;
    return NCDRI_OK;
}

static const ncdri_driver_t hello_driver = {
    .size = sizeof(ncdri_driver_t),
    .api_major = NCDRI_API_MAJOR,
    .api_minor = NCDRI_API_MINOR,
    .name = "edu",
    .softc_size = sizeof(struct hello_softc),
    .probe = hello_probe,
    .attach = hello_attach,
    .detach = hello_detach,
};

NCDRI_EXPORT int ncdri_main(const nckernel_api_t *k, uint32_t k_size) {
    /* Refuse a kernel of another major version, or a table too short to
     * hold what this driver calls unconditionally. */
    if (k == 0 || k_size < offsetof(nckernel_api_t, fpu_alloc) || k->api_major != NCDRI_API_MAJOR)
        return NCDRI_ENOTSUP;
    ncdri_k = k;
    /* A newer service, used only if this kernel has it. */
    if (NCDRI_HAS(k, rng_fill)) {
        uint32_t cookie = 0;
        k->rng_fill(&cookie, sizeof cookie, 0);
        (void)cookie;
    }
    return ncdri_register_device(&hello_driver);
}

NCDRI_EXPORT void ncdri_fini(void) {
    ncdri_k->driver_unregister(ncdri_k->self, &hello_driver);
}
