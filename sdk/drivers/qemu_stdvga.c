/* SPDX-License-Identifier: Apache-2.0 */
/* qemu_stdvga.c — a display driver for the standard VGA of QEMU and Bochs
 * (PCI 1234:1111: QEMU's `-vga std`, `-device VGA`, `secondary-vga` and
 * `bochs-display`). It reads the monitor's EDID from the device, sets the
 * native mode the EDID declares through the Bochs display interface
 * ("dispi"), and hands the kernel the new scanout — so the session runs at
 * the monitor's own resolution, not the one the firmware picked.
 *
 * The register interface, as QEMU documents it (docs/specs/standard-vga.rst
 * in QEMU's tree):
 *   BAR 0  the framebuffer (VRAM)
 *   BAR 2  4 KiB of MMIO:
 *     0x000-0x3ff  the EDID blob, when the device has edid=on (the default)
 *     0x400-0x41f  the VGA ports 0x3c0-0x3df
 *     0x500-0x515  the dispi registers, index i at 0x500 + 2 * i
 *     0x600-0x607  QEMU's extensions; 0x604 is the framebuffer's byte order
 *
 * Everything goes through ncdri_api.h: no kernel header, no kernel symbol.
 * It is the first display driver and the smallest real one: no interrupts,
 * no DMA, no acceleration — a mode and a framebuffer.
 */
#include <ncdri_api.h>

const nckernel_api_t *ncdri_k;

#define STDVGA_VENDOR 0x1234
#define STDVGA_DEVICE 0x1111

#define MMIO_BAR   2
#define MMIO_EDID  0x000
#define MMIO_DISPI 0x500
#define MMIO_QEXT  0x600

/* The dispi registers, by index. */
#define DISPI_ID           0x0
#define DISPI_XRES         0x1
#define DISPI_YRES         0x2
#define DISPI_BPP          0x3
#define DISPI_ENABLE       0x4
#define DISPI_BANK         0x5
#define DISPI_VIRT_WIDTH   0x6
#define DISPI_VIRT_HEIGHT  0x7
#define DISPI_X_OFFSET     0x8
#define DISPI_Y_OFFSET     0x9
#define DISPI_VIDEO_MEM_64K 0xa

/* ID 0xB0C0 .. 0xB0C5; 0xB0C2 and later have 32 bpp and the linear
 * framebuffer, which is all this uses. */
#define DISPI_ID_MIN 0xB0C2
#define DISPI_ID_MAX 0xB0CF

#define DISPI_ENABLED     0x01
#define DISPI_GETCAPS     0x02
#define DISPI_LFB_ENABLED 0x40

/* QEMU's extension region: its size at +0, the byte order at +4. */
#define QEXT_SIZE      0x0
#define QEXT_ENDIAN    0x4
#define QEXT_LITTLE    0x1e1e1e1eu
#define QEXT_BIG       0xbebebebeu

/* QEMU's EDID window: the base block and up to seven extensions. */
#define EDID_MAX 1024

struct stdvga_softc {
    ncdri_device_t dev;
    ncdri_resource_t mmio;
    uint8_t edid[EDID_MAX];
    uint32_t edid_len;
};

/* ---- A log line, built without a C library ------------------------------ */

struct line {
    char b[160];
    size_t n;
};

static void put(struct line *l, const char *s) {
    while (*s && l->n < sizeof l->b) l->b[l->n++] = *s++;
}

/* Decimal, without a division (a 32-bit ARM has no divide instruction and
 * a driver links no helper library). */
static void put_u32(struct line *l, uint32_t v) {
    static const uint32_t tens[] = {1000000000u, 100000000u, 10000000u, 1000000u, 100000u,
                                    10000u, 1000u, 100u, 10u, 1u};
    int started = 0;
    for (unsigned i = 0; i < sizeof tens / sizeof tens[0]; i++) {
        char d = '0';
        while (v >= tens[i]) {
            v -= tens[i];
            d++;
        }
        if (d != '0' || started || tens[i] == 1) {
            started = 1;
            if (l->n < sizeof l->b) l->b[l->n++] = d;
        }
    }
}

static void say(ncdri_device_t dev, int level, struct line *l) {
    ncdri_log(dev, level, l->b, l->n);
}

static void say_str(ncdri_device_t dev, int level, const char *s) {
    struct line l;
    l.n = 0; /* only the count: zeroing the buffer would be a memset call */
    put(&l, s);
    say(dev, level, &l);
}

/* ---- The dispi registers, through the MMIO window ----------------------- */

static uint16_t dispi_read(struct stdvga_softc *sc, unsigned index) {
    return ncdri_k->read_2(sc->mmio, MMIO_DISPI + 2 * index);
}

static void dispi_write(struct stdvga_softc *sc, unsigned index, uint16_t v) {
    ncdri_k->write_2(sc->mmio, MMIO_DISPI + 2 * index, v);
}

/* ---- newbus methods ----------------------------------------------------- */

static int stdvga_probe(ncdri_device_t dev, const ncdri_devinfo_t *info) {
    (void)dev;
    if (info->bus != NCDRI_BUS_PCI) return NCDRI_ENXIO;
    if (info->vendor != STDVGA_VENDOR || info->device != STDVGA_DEVICE) return NCDRI_ENXIO;
    return NCDRI_PROBE_VENDOR;
}

static int stdvga_detach(ncdri_device_t dev, void *softc);

static int stdvga_attach(ncdri_device_t dev, void *softc) {
    struct stdvga_softc *sc = softc;
    uint64_t mmio_len = 0;
    struct line l;
    int err;

    l.n = 0;

    sc->dev = dev;
    err = ncdri_k->resource_map(dev, NCDRI_RES_MEMORY, MMIO_BAR, &sc->mmio, &mmio_len);
    if (err || mmio_len < MMIO_QEXT) {
        say_str(dev, NCDRI_LOG_WARN, "no MMIO window in BAR 2 (a QEMU older than 1.3?); leaving the firmware's mode");
        if (!err) stdvga_detach(dev, sc);
        return err ? err : NCDRI_ENXIO;
    }
    uint16_t id = dispi_read(sc, DISPI_ID);
    if (id < DISPI_ID_MIN || id > DISPI_ID_MAX) {
        say_str(dev, NCDRI_LOG_WARN, "the dispi interface is too old for 32-bit modes");
        stdvga_detach(dev, sc);
        return NCDRI_ENXIO;
    }

    /* The monitor's EDID: the base block, then the extensions it announces
     * (byte 126) — a native mode past 655 MHz lives in a DisplayID one. */
    for (unsigned i = 0; i < 128; i++) sc->edid[i] = ncdri_k->read_1(sc->mmio, MMIO_EDID + i);
    sc->edid_len = 128u * (1u + sc->edid[126]);
    if (sc->edid_len > EDID_MAX) sc->edid_len = EDID_MAX;
    for (unsigned i = 128; i < sc->edid_len; i++) sc->edid[i] = ncdri_k->read_1(sc->mmio, MMIO_EDID + i);
    uint32_t w = 0, h = 0, mhz = 0;
    if (!NCDRI_HAS(ncdri_k, edid_preferred) || !NCDRI_HAS(ncdri_k, display_scanout)) {
        say_str(dev, NCDRI_LOG_INFO, "this kernel has no display services; leaving the firmware's mode");
        return NCDRI_OK;
    }
    if (ncdri_k->edid_preferred(sc->edid, sc->edid_len, &w, &h, &mhz) != NCDRI_OK) {
        say_str(dev, NCDRI_LOG_INFO, "no EDID with a native mode (edid=off?); leaving the firmware's mode");
        return NCDRI_OK;
    }

    /* The mode must fit the device: its VRAM, and the largest mode the
     * interface reports (GETCAPS turns XRES/YRES into the maxima). */
    uint32_t vram = (uint32_t)dispi_read(sc, DISPI_VIDEO_MEM_64K) << 16;
    uint16_t enable = dispi_read(sc, DISPI_ENABLE);
    dispi_write(sc, DISPI_ENABLE, DISPI_GETCAPS);
    uint32_t max_w = dispi_read(sc, DISPI_XRES), max_h = dispi_read(sc, DISPI_YRES);
    dispi_write(sc, DISPI_ENABLE, enable);
    put(&l, "EDID native mode ");
    put_u32(&l, w);
    put(&l, "x");
    put_u32(&l, h);
    put(&l, " at ");
    put_u32(&l, mhz / 1000);
    put(&l, " Hz; ");
    put_u32(&l, vram >> 20);
    put(&l, " MiB of VRAM, at most ");
    put_u32(&l, max_w);
    put(&l, "x");
    put_u32(&l, max_h);
    say(dev, NCDRI_LOG_INFO, &l);
    if ((uint64_t)w * h * 4 > vram || w > max_w || h > max_h || w > 0xFFFF || h > 0xFFFF) {
        say_str(dev, NCDRI_LOG_WARN, "the native mode does not fit this device (QEMU: vgamem_mb=); leaving the firmware's mode");
        return NCDRI_OK;
    }

    /* Off, the geometry, on again with the linear framebuffer. */
    dispi_write(sc, DISPI_ENABLE, 0);
    dispi_write(sc, DISPI_BPP, 32);
    dispi_write(sc, DISPI_XRES, (uint16_t)w);
    dispi_write(sc, DISPI_YRES, (uint16_t)h);
    dispi_write(sc, DISPI_BANK, 0);
    dispi_write(sc, DISPI_VIRT_WIDTH, (uint16_t)w);
    dispi_write(sc, DISPI_VIRT_HEIGHT, (uint16_t)h);
    dispi_write(sc, DISPI_X_OFFSET, 0);
    dispi_write(sc, DISPI_Y_OFFSET, 0);
    dispi_write(sc, DISPI_ENABLE, DISPI_ENABLED | DISPI_LFB_ENABLED);
    /* The framebuffer's byte order is the CPU's, where QEMU lets it be set. */
    if (ncdri_k->read_4(sc->mmio, MMIO_QEXT + QEXT_SIZE) >= 8) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        ncdri_k->write_4(sc->mmio, MMIO_QEXT + QEXT_ENDIAN, QEXT_BIG);
#else
        ncdri_k->write_4(sc->mmio, MMIO_QEXT + QEXT_ENDIAN, QEXT_LITTLE);
#endif
    }
    if (dispi_read(sc, DISPI_XRES) != w || dispi_read(sc, DISPI_YRES) != h || dispi_read(sc, DISPI_BPP) != 32) {
        say_str(dev, NCDRI_LOG_ERROR, "the device did not take the mode");
        return NCDRI_EIO;
    }

    /* The device may widen the virtual width; the pitch follows it. */
    uint32_t pitch = (uint32_t)dispi_read(sc, DISPI_VIRT_WIDTH) * 4;
    /* Zeroed through the table: an initializer would have the compiler
     * call a memset the driver does not link. */
    ncdri_scanout_t s;
    ncdri_k->memset(&s, 0, sizeof s);
    s.size = sizeof(ncdri_scanout_t);
    s.res_index = 0;
    s.offset = 0;
    s.width = w;
    s.height = h;
    s.pitch = pitch;
    s.format = NCDRI_FORMAT_XRGB8888;
    err = ncdri_k->display_scanout(dev, &s, sc->edid, sc->edid_len);
    if (err) {
        say_str(dev, NCDRI_LOG_ERROR, "the kernel refused the scanout");
        return err;
    }
    say_str(dev, NCDRI_LOG_INFO, "native mode set; scanout handed to the kernel");
    return NCDRI_OK;
}

static int stdvga_detach(ncdri_device_t dev, void *softc) {
    struct stdvga_softc *sc = softc;
    (void)dev;
    /* The mode stays: the kernel draws on it. Only the window goes. */
    if (sc->mmio) ncdri_k->resource_unmap(sc->mmio);
    sc->mmio = 0;
    return NCDRI_OK;
}

static const ncdri_driver_t stdvga_driver = {
    .size = sizeof(ncdri_driver_t),
    .api_major = NCDRI_API_MAJOR,
    .api_minor = NCDRI_API_MINOR,
    .name = "stdvga",
    .softc_size = sizeof(struct stdvga_softc),
    .probe = stdvga_probe,
    .attach = stdvga_attach,
    .detach = stdvga_detach,
};

NCDRI_EXPORT int ncdri_main(const nckernel_api_t *k, uint32_t k_size) {
    /* Everything up to the PCI services is called unconditionally; the
     * display services (minor 1) are checked with NCDRI_HAS where used. */
    if (k == 0 || k_size < offsetof(nckernel_api_t, pci_cfg_read) || k->api_major != NCDRI_API_MAJOR)
        return NCDRI_ENOTSUP;
    ncdri_k = k;
    return ncdri_register_device(&stdvga_driver);
}

NCDRI_EXPORT void ncdri_fini(void) {
    ncdri_k->driver_unregister(ncdri_k->self, &stdvga_driver);
}
