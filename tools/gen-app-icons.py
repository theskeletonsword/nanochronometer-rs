#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Draws the bare-metal desktop's app icons into assets/icons/apps/.

    python3 tools/gen-app-icons.py

Needs Pillow only. Each icon is a rounded tile with a vertical gradient and a
white glyph, drawn at 8x and reduced, so the edges are antialiased at every
size. Original artwork, Apache-2.0 like the rest of the tree.

Outputs, per icon and per size in SIZES:
  assets/icons/apps/<name>_<size>.png    to look at
  assets/icons/apps/<name>_<size>.rgba   what the kernel embeds: width and
                                         height as little-endian u32, then
                                         straight RGBA (the logo's format)

The kernel (crates/nanochrono-baremetal/build.rs) embeds every
`<name>_<size>.rgba` it finds there; the NanoChronometer icon itself comes
from assets/icons/baremetal/ (tools/gen-icons.py).
"""

import math
import struct
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "icons" / "apps"
SIZES = [16, 24, 32, 48, 64]
K = 8  # supersampling
WHITE = (255, 255, 255, 255)
GREEN = (0x39, 0xE8, 0x4A, 255)


def tile(size, top, bottom, radius=0.23):
    """The rounded tile: gradient fill, a faint top highlight, a soft rim."""
    s = size * K
    grad = Image.new("RGBA", (1, s))
    for y in range(s):
        t = y / (s - 1)
        grad.putpixel((0, y), tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    grad = grad.resize((s, s))
    mask = Image.new("L", (s, s), 0)
    m = ImageDraw.Draw(mask)
    inset = s * 0.04
    m.rounded_rectangle((inset, inset, s - inset, s - inset), radius=s * radius, fill=255)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)
    hl = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    h = ImageDraw.Draw(hl)
    h.rounded_rectangle((inset, inset, s - inset, s * 0.52), radius=s * radius, fill=(255, 255, 255, 34))
    img.alpha_composite(Image.composite(hl, Image.new("RGBA", (s, s)), mask))
    rim = ImageDraw.Draw(img)
    rim.rounded_rectangle((inset, inset, s - inset, s - inset), radius=s * radius,
                          outline=(0, 0, 0, 60), width=max(1, int(s * 0.012)))
    return img


def draw_terminal(d, s):
    w = s * 0.075
    d.line([(s * 0.26, s * 0.34), (s * 0.44, s * 0.50), (s * 0.26, s * 0.66)], fill=GREEN, width=int(w), joint="curve")
    d.line([(s * 0.50, s * 0.68), (s * 0.74, s * 0.68)], fill=WHITE, width=int(w))


def draw_tasks(d, s):
    w = int(s * 0.06)
    pts = [(0.22, 0.66), (0.36, 0.50), (0.48, 0.58), (0.62, 0.34), (0.78, 0.42)]
    d.line([(x * s, y * s) for x, y in pts], fill=WHITE, width=w, joint="curve")
    for x, y in pts:
        r = s * 0.035
        d.ellipse((x * s - r, y * s - r, x * s + r, y * s + r), fill=WHITE)
    d.line([(s * 0.2, s * 0.78), (s * 0.8, s * 0.78)], fill=(255, 255, 255, 150), width=int(s * 0.035))


def draw_settings(d, s):
    cx, cy, r = s / 2, s / 2, s * 0.25
    teeth = []
    for i in range(16):
        a = i / 16 * 2 * math.pi
        rr = r * (1.22 if i % 2 == 0 else 0.98)
        teeth.append((cx + rr * math.cos(a), cy + rr * math.sin(a)))
    d.polygon(teeth, fill=WHITE)
    d.ellipse((cx - r * 0.95, cy - r * 0.95, cx + r * 0.95, cy + r * 0.95), fill=WHITE)
    d.ellipse((cx - r * 0.42, cy - r * 0.42, cx + r * 0.42, cy + r * 0.42), fill=(255, 255, 255, 0))


def draw_bench(d, s):
    box = (s * 0.18, s * 0.24, s * 0.82, s * 0.88)
    d.arc(box, 180, 360, fill=WHITE, width=int(s * 0.07))
    a = math.radians(-35)
    cx, cy = s * 0.5, s * 0.56
    d.line([(cx, cy), (cx + s * 0.24 * math.cos(a), cy + s * 0.24 * math.sin(a))], fill=WHITE, width=int(s * 0.06))
    r = s * 0.06
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=WHITE)


def draw_snake(d, s):
    pts = []
    for i in range(40):
        t = i / 39
        pts.append((s * (0.22 + 0.56 * t), s * (0.55 + 0.14 * math.sin(t * 2.2 * math.pi))))
    d.line(pts, fill=WHITE, width=int(s * 0.11), joint="curve")
    hx, hy = pts[-1]
    r = s * 0.085
    d.ellipse((hx - r, hy - r, hx + r, hy + r), fill=WHITE)
    e = s * 0.022
    d.ellipse((hx + r * 0.1 - e, hy - r * 0.35 - e, hx + r * 0.1 + e, hy - r * 0.35 + e), fill=(30, 120, 60, 255))
    d.rectangle((s * 0.30, s * 0.24, s * 0.40, s * 0.34), fill=(255, 90, 90, 255))


def draw_vm(d, s):
    d.rounded_rectangle((s * 0.18, s * 0.24, s * 0.82, s * 0.68), radius=s * 0.04, outline=WHITE, width=int(s * 0.055))
    d.rectangle((s * 0.42, s * 0.68, s * 0.58, s * 0.76), fill=WHITE)
    d.rounded_rectangle((s * 0.32, s * 0.78, s * 0.68, s * 0.83), radius=s * 0.02, fill=WHITE)
    d.rounded_rectangle((s * 0.34, s * 0.36, s * 0.66, s * 0.58), radius=s * 0.02, fill=(255, 255, 255, 170))
    d.rectangle((s * 0.34, s * 0.36, s * 0.66, s * 0.41), fill=WHITE)


def draw_browser(d, s):
    cx, cy, r = s / 2, s / 2, s * 0.28
    w = int(s * 0.045)
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=WHITE, width=w)
    d.ellipse((cx - r * 0.45, cy - r, cx + r * 0.45, cy + r), outline=WHITE, width=w)
    d.line([(cx - r, cy), (cx + r, cy)], fill=WHITE, width=w)
    d.line([(cx, cy - r), (cx, cy + r)], fill=WHITE, width=w)
    d.arc((cx - r, cy - r * 1.55, cx + r, cy - r * 0.15), 30, 150, fill=WHITE, width=w)
    d.arc((cx - r, cy + r * 0.15, cx + r, cy + r * 1.55), 210, 330, fill=WHITE, width=w)


def draw_music(d, s):
    w = int(s * 0.06)
    d.line([(s * 0.42, s * 0.70), (s * 0.42, s * 0.26)], fill=WHITE, width=w)
    d.line([(s * 0.66, s * 0.62), (s * 0.66, s * 0.20)], fill=WHITE, width=w)
    d.polygon([(s * 0.40, s * 0.24), (s * 0.68, s * 0.17), (s * 0.68, s * 0.28), (s * 0.40, s * 0.35)], fill=WHITE)
    for x, y in [(0.35, 0.71), (0.59, 0.63)]:
        d.ellipse((s * (x - 0.09), s * (y - 0.065), s * (x + 0.09), s * (y + 0.065)), fill=WHITE)


def draw_video(d, s):
    d.rounded_rectangle((s * 0.2, s * 0.28, s * 0.8, s * 0.72), radius=s * 0.06, outline=WHITE, width=int(s * 0.05))
    d.polygon([(s * 0.43, s * 0.38), (s * 0.43, s * 0.62), (s * 0.62, s * 0.50)], fill=WHITE)


def draw_images(d, s):
    d.rounded_rectangle((s * 0.18, s * 0.24, s * 0.82, s * 0.76), radius=s * 0.05, outline=WHITE, width=int(s * 0.05))
    d.polygon([(s * 0.24, s * 0.70), (s * 0.42, s * 0.44), (s * 0.56, s * 0.62), (s * 0.64, s * 0.52),
               (s * 0.76, s * 0.70)], fill=WHITE)
    r = s * 0.06
    d.ellipse((s * 0.62 - r, s * 0.36 - r, s * 0.62 + r, s * 0.36 + r), fill=WHITE)


def draw_files(d, s):
    d.rounded_rectangle((s * 0.16, s * 0.28, s * 0.46, s * 0.40), radius=s * 0.04, fill=(255, 255, 255, 200))
    d.rounded_rectangle((s * 0.16, s * 0.34, s * 0.84, s * 0.74), radius=s * 0.05, fill=WHITE)


def draw_apps(d, s):
    for i in range(2):
        for j in range(2):
            x, y = s * (0.24 + i * 0.29), s * (0.24 + j * 0.29)
            d.rounded_rectangle((x, y, x + s * 0.23, y + s * 0.23), radius=s * 0.05, fill=WHITE)


def draw_drivers(d, s):
    d.rounded_rectangle((s * 0.30, s * 0.30, s * 0.70, s * 0.70), radius=s * 0.04, fill=WHITE)
    w = int(s * 0.04)
    for k in range(3):
        t = 0.38 + k * 0.12
        for a, b in [((t, 0.18), (t, 0.30)), ((t, 0.70), (t, 0.82)), ((0.18, t), (0.30, t)), ((0.70, t), (0.82, t))]:
            d.line([(a[0] * s, a[1] * s), (b[0] * s, b[1] * s)], fill=WHITE, width=w)
    d.rectangle((s * 0.42, s * 0.42, s * 0.58, s * 0.58), fill=(255, 255, 255, 0))


def draw_about(d, s):
    r = s * 0.06
    d.ellipse((s * 0.5 - r, s * 0.27 - r, s * 0.5 + r, s * 0.27 + r), fill=WHITE)
    d.rounded_rectangle((s * 0.44, s * 0.40, s * 0.56, s * 0.76), radius=s * 0.03, fill=WHITE)


def draw_maze(d, s):
    w = int(s * 0.055)
    lines = [((0.2, 0.2), (0.8, 0.2)), ((0.8, 0.2), (0.8, 0.8)), ((0.2, 0.8), (0.65, 0.8)),
             ((0.2, 0.2), (0.2, 0.65)), ((0.35, 0.35), (0.65, 0.35)), ((0.35, 0.35), (0.35, 0.65)),
             ((0.5, 0.5), (0.65, 0.5)), ((0.65, 0.5), (0.65, 0.65))]
    for (a, b) in lines:
        d.line([(a[0] * s, a[1] * s), (b[0] * s, b[1] * s)], fill=WHITE, width=w)
    r = s * 0.05
    d.ellipse((s * 0.5 - r, s * 0.65 - r, s * 0.5 + r, s * 0.65 + r), fill=(255, 220, 80, 255))


def draw_power(d, s):
    cx, cy, r = s / 2, s * 0.53, s * 0.25
    w = int(s * 0.07)
    d.arc((cx - r, cy - r, cx + r, cy + r), -60, 240, fill=WHITE, width=w)
    d.line([(cx, s * 0.20), (cx, s * 0.50)], fill=WHITE, width=w)


def draw_hypervisor(d, s):
    pts = [(0.5, 0.16), (0.78, 0.28), (0.74, 0.58), (0.5, 0.84), (0.26, 0.58), (0.22, 0.28)]
    d.polygon([(x * s, y * s) for x, y in pts], outline=WHITE, width=int(s * 0.05))
    d.line([(s * 0.38, s * 0.50), (s * 0.47, s * 0.60), (s * 0.64, s * 0.40)], fill=WHITE, width=int(s * 0.06))


def draw_cli(d, s):
    draw_terminal(d, s)


# name: (gradient top, gradient bottom, glyph)
ICONS = {
    "terminal": ((52, 58, 66), (20, 23, 28), draw_terminal),
    "tasks": ((32, 201, 151), (12, 120, 110), draw_tasks),
    "settings": ((134, 142, 150), (73, 80, 87), draw_settings),
    "bench": ((255, 169, 77), (232, 89, 12), draw_bench),
    "snake": ((81, 207, 102), (43, 138, 62), draw_snake),
    "vm": ((151, 117, 250), (95, 61, 196), draw_vm),
    "browser": ((77, 171, 247), (25, 113, 194), draw_browser),
    "music": ((255, 107, 157), (214, 51, 108), draw_music),
    "video": ((204, 93, 232), (134, 46, 156), draw_video),
    "images": ((255, 212, 59), (245, 159, 0), draw_images),
    "files": ((116, 192, 252), (28, 126, 214), draw_files),
    "apps": ((116, 143, 252), (66, 99, 235), draw_apps),
    "drivers": ((56, 217, 169), (9, 146, 104), draw_drivers),
    "about": ((92, 124, 250), (54, 79, 199), draw_about),
    "maze": ((255, 120, 120), (201, 42, 42), draw_maze),
    "power": ((250, 82, 82), (201, 42, 42), draw_power),
    "hypervisor": ((99, 230, 190), (12, 166, 120), draw_hypervisor),
}


def render(name, size):
    top, bottom, glyph = ICONS[name]
    img = tile(size, top, bottom)
    s = size * K
    glyph_layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    glyph(ImageDraw.Draw(glyph_layer), s)
    # Holes punched with alpha 0 (the gear's centre, the chip's die) show the
    # tile through: composite the glyph's alpha, not just paint it.
    img.alpha_composite(glyph_layer)
    return img.resize((size, size), Image.LANCZOS)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ICONS:
        for size in SIZES:
            img = render(name, size)
            img.save(OUT / f"{name}_{size}.png")
            (OUT / f"{name}_{size}.rgba").write_bytes(struct.pack("<II", size, size) + img.tobytes())
    print(f"{len(ICONS)} icons x {len(SIZES)} sizes in {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
