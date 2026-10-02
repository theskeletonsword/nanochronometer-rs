#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Draws the desktop wallpapers into assets/wallpapers/.

    python3 tools/gen-wallpapers.py [--size 1920x1080]

Needs Pillow only. Every picture is drawn here from gradients, curves and
blurred shapes — original artwork, Apache-2.0 like the rest of the tree — so
the wallpapers carry no third-party licence.

The kernel embeds every PNG in assets/wallpapers/ (crates/nanochrono-baremetal/
build.rs): drop another PNG there and the next kernel build carries it too,
listed under its file name minus the leading `NN-` and the extension. The
outputs are committed, so a kernel build needs neither Python nor Pillow.
"""

import argparse
import math
import random
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "wallpapers"

# The brand green (tools/gen-icons.py) and its darker shade.
GREEN = (0x39, 0xE8, 0x4A)
GREEN_DARK = (0x2F, 0xB8, 0x3C)


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    return tuple(int(round(lerp(x, y, t))) for x, y in zip(c1, c2))


def vertical_gradient(w, h, stops):
    """A top-to-bottom gradient through `stops`: [(position 0..1, (r, g, b))]."""
    column = Image.new("RGB", (1, h))
    px = column.load()
    for y in range(h):
        t = y / max(1, h - 1)
        for (p0, c0), (p1, c1) in zip(stops, stops[1:]):
            if p0 <= t <= p1:
                px[0, y] = mix(c0, c1, (t - p0) / max(1e-9, p1 - p0))
                break
    return column.resize((w, h), Image.NEAREST)


def radial_glow(w, h, cx, cy, radius, colour, strength=1.0):
    """A soft round light: an ellipse blurred far past its edge."""
    layer = Image.new("RGB", (w, h), (0, 0, 0))
    d = ImageDraw.Draw(layer)
    c = tuple(int(v * strength) for v in colour)
    d.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=c)
    return layer.filter(ImageFilter.GaussianBlur(radius * 0.9))


def screen(a, b):
    return ImageChops.screen(a, b)


def ribbon(w, h, base_y, amplitude, wavelength, phase, thickness, colour, blur):
    """A glowing sine ribbon across the picture (the aurora's curtains)."""
    layer = Image.new("RGB", (w, h), (0, 0, 0))
    d = ImageDraw.Draw(layer)
    points = []
    for x in range(-40, w + 41, 8):
        y = base_y + amplitude * math.sin(2 * math.pi * x / wavelength + phase) \
            + amplitude * 0.35 * math.sin(2 * math.pi * x / (wavelength * 0.37) + phase * 1.7)
        points.append((x, y))
    d.line(points, fill=colour, width=thickness, joint="curve")
    return layer.filter(ImageFilter.GaussianBlur(blur))


def stars(img, count, seed, area=None):
    rnd = random.Random(seed)
    d = ImageDraw.Draw(img)
    w, h = img.size
    x0, y0, x1, y1 = area or (0, 0, w, h)
    for _ in range(count):
        x = rnd.uniform(x0, x1)
        y = rnd.uniform(y0, y1)
        b = rnd.randint(110, 255)
        r = rnd.choice([0.6, 0.8, 1.0, 1.0, 1.4])
        d.ellipse((x - r, y - r, x + r, y + r), fill=(b, b, min(255, b + 20)))


def aurora(w, h):
    """Green and teal aurora curtains over a night sky, a dark ridge below."""
    s = 2  # the blurred layers are drawn at half size and enlarged
    lw, lh = w // s, h // s
    sky = vertical_gradient(lw, lh, [(0.0, (3, 6, 18)), (0.55, (6, 22, 36)), (1.0, (2, 10, 14))])
    glow = Image.new("RGB", (lw, lh))
    glow = screen(glow, ribbon(lw, lh, lh * 0.34, lh * 0.08, lw * 0.9, 0.4, lh // 9, (20, 160, 70), lh / 22))
    glow = screen(glow, ribbon(lw, lh, lh * 0.30, lh * 0.06, lw * 1.3, 2.1, lh // 22, GREEN, lh / 60))
    glow = screen(glow, ribbon(lw, lh, lh * 0.42, lh * 0.05, lw * 0.7, 4.0, lh // 14, (10, 120, 140), lh / 26))
    glow = screen(glow, ribbon(lw, lh, lh * 0.25, lh * 0.04, lw * 1.7, 1.2, lh // 30, (120, 255, 190), lh / 70))
    glow = screen(glow, radial_glow(lw, lh, lw * 0.7, lh * 0.35, lh * 0.25, (20, 90, 60), 0.7))
    img = screen(sky, glow).resize((w, h), Image.BICUBIC)
    stars(img, 380, 7, (0, 0, w, h * 0.6))
    # A ridge of hills, flat dark shapes in front.
    d = ImageDraw.Draw(img)
    for layer, (base, amp, colour) in enumerate([(0.80, 0.05, (6, 16, 20)), (0.88, 0.04, (3, 9, 12))]):
        pts = [(0, h)]
        for x in range(0, w + 1, 6):
            t = x / w
            y = h * (base + amp * math.sin(t * 7.1 + layer * 1.9) + amp * 0.5 * math.sin(t * 17.3 + layer))
            pts.append((x, y))
        pts.append((w, h))
        d.polygon(pts, fill=colour)
    return img


def nebula(w, h):
    """Soft violet, magenta and blue clouds with a scatter of stars."""
    s = 4
    lw, lh = w // s, h // s
    img = vertical_gradient(lw, lh, [(0.0, (10, 6, 26)), (1.0, (4, 4, 14))])
    for cx, cy, r, c, k in [
        (0.30, 0.40, 0.30, (120, 40, 170), 0.9),
        (0.62, 0.55, 0.34, (200, 50, 140), 0.7),
        (0.78, 0.30, 0.22, (40, 90, 220), 0.8),
        (0.45, 0.70, 0.25, (60, 30, 140), 0.8),
        (0.55, 0.45, 0.10, (255, 150, 210), 0.6),
    ]:
        img = screen(img, radial_glow(lw, lh, lw * cx, lh * cy, lh * r, c, k))
    img = img.resize((w, h), Image.BICUBIC)
    stars(img, 650, 21)
    return img


def dunes(w, h):
    """A sunset over layered dunes: warm sky, a low sun, flat dune bands."""
    sky = vertical_gradient(w, h, [(0.0, (34, 22, 64)), (0.35, (120, 48, 92)),
                                   (0.58, (240, 120, 80)), (0.70, (255, 190, 120)), (1.0, (255, 210, 150))])
    sun = radial_glow(w // 4, h // 4, w * 0.62 / 4, h * 0.60 / 4, h * 0.10 / 4, (255, 220, 160), 1.0)
    img = screen(sky, sun.resize((w, h), Image.BICUBIC))
    d = ImageDraw.Draw(img)
    d.ellipse((w * 0.62 - h * 0.06, h * 0.60 - h * 0.06, w * 0.62 + h * 0.06, h * 0.60 + h * 0.06),
              fill=(255, 236, 200))
    bands = [
        (0.66, 0.030, 2.2, (196, 92, 74)),
        (0.72, 0.035, 3.1, (150, 62, 66)),
        (0.79, 0.040, 1.7, (106, 40, 58)),
        (0.87, 0.045, 2.6, (66, 24, 46)),
        (0.94, 0.030, 3.7, (36, 14, 32)),
    ]
    for i, (base, amp, freq, colour) in enumerate(bands):
        pts = [(0, h)]
        for x in range(0, w + 1, 4):
            t = x / w
            y = h * (base + amp * math.sin(t * math.pi * freq + i * 1.3) * (0.6 + 0.4 * math.sin(t * 5 + i)))
            pts.append((x, y))
        pts.append((w, h))
        d.polygon(pts, fill=colour)
    return img


def chrono(w, h):
    """Graphite with a large dial: the stopwatch's face, rings and ticks, and
    the brand green on an arc of it."""
    img = vertical_gradient(w, h, [(0.0, (18, 20, 24)), (1.0, (8, 9, 11))])
    glow = radial_glow(w // 4, h // 4, w * 0.68 / 4, h * 0.5 / 4, h * 0.42 / 4, (20, 60, 30), 0.9)
    img = screen(img, glow.resize((w, h), Image.BICUBIC))
    # Supersampled overlay for clean thin lines.
    k = 2
    ov = Image.new("RGBA", (w * k, h * k), (0, 0, 0, 0))
    d = ImageDraw.Draw(ov)
    cx, cy, r = w * 0.68 * k, h * 0.5 * k, h * 0.40 * k
    for i, (rr, width, alpha) in enumerate([(1.0, 3, 70), (0.86, 2, 45), (0.62, 2, 30), (1.12, 2, 25)]):
        R = r * rr
        d.ellipse((cx - R, cy - R, cx + R, cy + R), outline=(200, 210, 220, alpha), width=width * k)
    for i in range(60):
        a = i / 60 * 2 * math.pi
        long = i % 5 == 0
        r0 = r * (0.90 if long else 0.94)
        r1 = r * 0.98
        d.line((cx + r0 * math.sin(a), cy - r0 * math.cos(a), cx + r1 * math.sin(a), cy - r1 * math.cos(a)),
               fill=(220, 230, 235, 120 if long else 55), width=(3 if long else 2) * k)
    # The green arc: two fifths of the dial, as if the hand had swept it.
    box = (cx - r * 1.05, cy - r * 1.05, cx + r * 1.05, cy + r * 1.05)
    d.arc(box, -90, 54, fill=GREEN + (230,), width=6 * k)
    d.arc(box, -90, 54, fill=GREEN + (60,), width=18 * k)
    # The hand, and the hub.
    a = math.radians(144)
    d.line((cx, cy, cx + r * 0.82 * math.sin(a), cy - r * 0.82 * math.cos(a)), fill=GREEN + (220,), width=4 * k)
    d.ellipse((cx - 14 * k, cy - 14 * k, cx + 14 * k, cy + 14 * k), fill=(30, 34, 38, 255),
              outline=GREEN + (230,), width=3 * k)
    ov = ov.resize((w, h), Image.LANCZOS)
    img = img.convert("RGBA")
    img.alpha_composite(ov)
    return img.convert("RGB")


def ridge(n, roughness, seed):
    """A mountain skyline by midpoint displacement: `n + 1` heights in 0..1."""
    rnd = random.Random(seed)
    pts = [rnd.uniform(0.2, 0.5), rnd.uniform(0.2, 0.5)]
    spread = 0.6
    while len(pts) < n + 1:
        out = []
        for a, b in zip(pts, pts[1:]):
            out += [a, (a + b) / 2 + rnd.uniform(-spread, spread)]
        out.append(pts[-1])
        pts = out
        spread *= roughness
    lo, hi = min(pts), max(pts)
    return [(p - lo) / max(1e-9, hi - lo) for p in pts[: n + 1]]


def lake(w, h):
    """Mountains mirrored in a still lake, in cool blue morning light."""
    img = vertical_gradient(w, h, [(0.0, (96, 146, 200)), (0.5, (204, 222, 236)), (1.0, (150, 190, 220))])
    img = screen(img, radial_glow(w // 4, h // 4, w * 0.30 / 4, h * 0.42 / 4, h * 0.12 / 4,
                                  (255, 236, 200), 0.8).resize((w, h), Image.BICUBIC))
    d = ImageDraw.Draw(img)
    horizon = h * 0.60
    ranges = [
        (0.34, 0.08, 0.55, 11, (128, 152, 184)),
        (0.25, 0.06, 0.52, 23, (86, 112, 146)),
        (0.15, 0.04, 0.50, 5, (48, 70, 98)),
    ]
    for height, floor, roughness, seed, colour in ranges:
        sky = ridge(512, roughness, seed)
        pts = [(0, horizon)]
        for i, v in enumerate(sky):
            pts.append((w * i / 512, horizon - h * (floor + height * v)))
        pts.append((w, horizon))
        d.polygon(pts, fill=colour)
    # The reflection: the upper half flipped, a little darker and softer.
    top = img.crop((0, 0, w, int(horizon)))
    refl = top.transpose(Image.FLIP_TOP_BOTTOM).filter(ImageFilter.GaussianBlur(3))
    refl = Image.blend(refl, Image.new("RGB", refl.size, (40, 70, 100)), 0.35)
    img.paste(refl.crop((0, 0, w, h - int(horizon))), (0, int(horizon)))
    d = ImageDraw.Draw(img)
    d.line((0, horizon, w, horizon), fill=(220, 232, 240), width=1)
    return img


WALLPAPERS = [
    ("01-aurora", aurora),
    ("02-chrono", chrono),
    ("03-nebula", nebula),
    ("04-dunes", dunes),
    ("05-lake", lake),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--size", default="1920x1080")
    args = ap.parse_args()
    w, h = (int(v) for v in args.size.split("x"))
    OUT.mkdir(parents=True, exist_ok=True)
    for name, draw in WALLPAPERS:
        img = draw(w, h).convert("RGB")
        path = OUT / f"{name}.png"
        img.save(path, optimize=True)
        print(f"{path.relative_to(ROOT)}: {w}x{h}, {path.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
