#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rasterises the terminal's monospaced face for the freestanding kernel.

    python3 tools/rasterise-mono.py [font.otf]

The bare-metal shell and the desktop's terminal draw text on a grid, which
needs a monospaced face; the interface's own face (typeface.rs) is
proportional. The outlines are turned into fixed-size coverage cells here, on
the host — the kernel has no rasteriser — and what ships is a table: one
`cell_w x cell_h` block of 8-bit coverage per character.

Source: Source Code Pro Medium (Adobe, SIL Open Font License 1.1). The OFL
allows the glyphs to be bundled with software under any licence; a
rasterised derivative may not carry the Reserved Font Name "Source", so the
tables are named "NC Terminal" and the OFL text travels with them
(assets/font/OFL-SourceCodePro.txt, NOTICE).

Covered: ASCII 0x20-0x7E, Latin-1 0xA0-0xFF (Spanish, Portuguese, French,
German...), and the symbols in EXTRAS. Box-drawing and block elements are not
taken from the font: the kernel draws them to fill the cell exactly, so lines
join and bars stack without gaps.

Output, per size: crates/nanochrono-baremetal/src/fonts/term<px>.bin:
    b"NCTF", u8 cell_w, u8 cell_h, u8 baseline, u8 0,
    u16 count (LE), u16 0,
    count x u32 codepoint (LE), ascending,
    count x (cell_w * cell_h) coverage bytes.
"""
import struct
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONT = sys.argv[1] if len(sys.argv) > 1 else "/usr/share/fonts/adobe-source-code-pro-fonts/SourceCodePro-Medium.otf"
OUT = ROOT / "crates" / "nanochrono-baremetal" / "src" / "fonts"
SIZES = [14, 18]
EXTRAS = "—–‘’“”•…→←↑↓✓✗€▶◀▲▼■□●○◆♪♫⌂∞≈≠≤≥±×÷√∑µΩπ°⚠✔✖"


def cps():
    out = list(range(0x20, 0x7F)) + list(range(0xA0, 0x100))
    out += sorted({ord(c) for c in EXTRAS} - set(out))
    return out


def rasterise(px):
    font = ImageFont.truetype(FONT, px)
    ascent, descent = font.getmetrics()
    cell_w = round(font.getlength("M"))
    cell_h = ascent + descent
    baseline = ascent
    codes = cps()
    blob = bytearray()
    for cp in codes:
        img = Image.new("L", (cell_w, cell_h), 0)
        d = ImageDraw.Draw(img)
        d.text((0, 0), chr(cp), font=font, fill=255)
        blob += img.tobytes()
    head = b"NCTF" + bytes([cell_w, cell_h, baseline, 0]) + struct.pack("<HH", len(codes), 0)
    head += b"".join(struct.pack("<I", c) for c in codes)
    return head + bytes(blob), cell_w, cell_h, len(codes)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for px in SIZES:
        data, w, h, n = rasterise(px)
        path = OUT / f"term{px}.bin"
        path.write_bytes(data)
        print(f"{path.relative_to(ROOT)}: {n} glyphs, cell {w}x{h}, {len(data)} bytes")


if __name__ == "__main__":
    main()
