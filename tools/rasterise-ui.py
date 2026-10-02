#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rasterises the desktop's interface face for the freestanding kernel.

    python3 tools/rasterise-ui.py [font.ttf]

The instrument draws in Nanoplex, the brand's pixel face (typeface.rs). The
Desktop Experience needs a quieter, smoother sans for its windows, menus and
labels: Adwaita Sans (GNOME's interface face, derived from Inter; SIL Open
Font License 1.1 — assets/font/OFL-AdwaitaSans.txt). The outlines are turned
into 8-bit coverage bitmaps here, on the host; the kernel has no rasteriser.
As a rasterised derivative it is named "NC UI" in the kernel.

Output, per (size, weight): crates/nanochrono-baremetal/src/fonts/ui<px><w>.bin
    b"NCUF", u8 1, u8 px, u8 ascent, u8 line_height, u16 count (LE), u16 0,
    count x { u32 codepoint, u32 offset, u8 w, u8 h, i8 left, i8 top,
              u8 advance, u8 0, u8 0, u8 0 },   (16 bytes, ascending codepoint)
    the coverage blob.
`top` is the glyph's top above the baseline; `left` its offset from the pen.

The digits of the display sizes are made tabular (one advance for all ten,
centred in it) so a running readout does not jitter as its digits change.
"""
import struct
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONT = sys.argv[1] if len(sys.argv) > 1 else "/usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-Regular.ttf"
OUT = ROOT / "crates" / "nanochrono-baremetal" / "src" / "fonts"

TEXT = [chr(c) for c in range(0x20, 0x7F)] + [chr(c) for c in range(0xA0, 0x100)] + list("—–‘’“”•…€←↑→↓✓×−")
DIGITS = list("0123456789:.,-+ ")

# (px, weight name, characters, tabular digits)
FACES = [
    (13, "Regular", TEXT, False),
    (15, "Regular", TEXT, False),
    (15, "SemiBold", TEXT, False),
    (20, "SemiBold", TEXT, False),
    (28, "Light", TEXT, True),
    (56, "Light", DIGITS, True),
]


def rasterise(px, weight, chars, tabular):
    font = ImageFont.truetype(FONT, px)
    try:
        font.set_variation_by_name(weight)
    except Exception:
        pass
    ascent, descent = font.getmetrics()
    line = ascent + descent + max(1, px // 6)
    digit_adv = max(font.getlength(d) for d in "0123456789")
    entries = []
    blob = bytearray()
    for ch in sorted(set(chars), key=ord):
        bbox = font.getbbox(ch, anchor="ls")  # relative to the baseline
        adv = font.getlength(ch)
        if tabular and ch.isdigit():
            adv = digit_adv
        if bbox is None or bbox[2] <= bbox[0] or bbox[3] <= bbox[1]:
            w = h = 0
            left = top = 0
            cov = b""
        else:
            x0, y0, x1, y1 = bbox
            w, h = x1 - x0, y1 - y0
            img = Image.new("L", (w, h), 0)
            d = ImageDraw.Draw(img)
            d.text((-x0, -y0), ch, font=font, fill=255, anchor="ls")
            cov = img.tobytes()
            left = x0
            top = -y0
            if tabular and ch.isdigit():
                left += round((digit_adv - font.getlength(ch)) / 2)
        if w > 255 or h > 255 or not (-128 <= left < 128) or not (-128 <= top < 128):
            raise SystemExit(f"glyph {ch!r} at {px}px does not fit the table's fields")
        entries.append((ord(ch), len(blob), w, h, left, top, round(adv)))
        blob += cov
    head = b"NCUF" + bytes([1, px, ascent, line]) + struct.pack("<HH", len(entries), 0)
    table = b"".join(struct.pack("<IIBBbbBBBB", cp, off, w, h, left, top, adv, 0, 0, 0)
                     for cp, off, w, h, left, top, adv in entries)
    return head + table + bytes(blob), len(entries)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for px, weight, chars, tabular in FACES:
        data, n = rasterise(px, weight, chars, tabular)
        path = OUT / f"ui{px}{weight.lower()}.bin"
        path.write_bytes(data)
        print(f"{path.relative_to(ROOT)}: {n} glyphs, {len(data)} bytes")


if __name__ == "__main__":
    main()
