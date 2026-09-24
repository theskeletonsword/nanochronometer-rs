#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerates the logo, the icon and every platform's copies of them.

    python3 tools/gen-icons.py

Needs fontTools, cairosvg and Pillow (`pip install fonttools cairosvg
pillow`, in a venv if you like).

The artwork source is the stopwatch drawn in `assets/src/stopwatch-artwork.svg`
(its `<defs>` and the STOPWATCH ICON section) — the original logo, kept as
the input so regenerating never reads its own output. Everything typographic — the
"N" on the face, "Nano", "Chronometer" and the subtitle — is set in
`assets/font/Nanoplex.ttf` and written out as outlines, so no SVG here
depends on the font being installed. The font is third-party: see
`assets/font/CREDITS.md`. Outlines of a few words are a rendering of the
font, not the font file, but check the listing's terms all the same.

Outputs:
  assets/nanochronometer_logo.svg / .png   the whole logo, for light backgrounds
  assets/nanochronometer_logo_dark.svg / .png   the same, white lettering
  assets/nanochronometer_icon.svg / .png   the stopwatch alone, square
  assets/nanochrono.ico                    multi-size, for the desktop GUI
  assets/icons/<platform>/...              per-platform copies
"""

import io
import re
import struct
import sys
from pathlib import Path

import cairosvg
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
SOURCE = ASSETS / "src" / "stopwatch-artwork.svg"
FONT = ASSETS / "font" / "Nanoplex.ttf"

GREEN = "#39E84A"
INK = "#111111"
GREY = "#555555"
# The same logo for dark backgrounds, where near-black lettering vanishes.
INK_DARK_BG = "#FFFFFF"
# On dark backgrounds nothing is grey: white lettering, green subtitle —
# the same logo the bare-metal interface draws on black.
GREY_BAREMETAL = "#2FB83C"
GREY_DARK_BG = GREY_BAREMETAL
SUBTITLE = "OPEN SOURCE HIGH PRECISION TIMER"

# The watch face: centre and bezel radius in the source drawing.
CX, CY = 108, 118


class Typesetter:
    """Turns strings into SVG path data in Nanoplex."""

    def __init__(self, path):
        self.font = TTFont(path)
        self.glyphs = self.font.getGlyphSet()
        self.cmap = self.font.getBestCmap()
        self.upm = self.font["head"].unitsPerEm
        self.hmtx = self.font["hmtx"]

    def width(self, text, size, tracking=0.0):
        s = size / self.upm
        total = sum(self.hmtx[self.cmap[ord(c)]][0] * s for c in text)
        return total + tracking * max(len(text) - 1, 0)

    def path(self, text, size, x, baseline, tracking=0.0):
        """Path data for `text` with its baseline at `baseline`."""
        s = size / self.upm
        out = []
        for c in text:
            name = self.cmap[ord(c)]
            pen = SVGPathPen(self.glyphs)
            # Font units are y-up; SVG is y-down.
            self.glyphs[name].draw(TransformPen(pen, (s, 0, 0, -s, x, baseline)))
            out.append(pen.getCommands())
            x += self.hmtx[name][0] * s + tracking
        return " ".join(p for p in out if p)

    def bounds(self, char):
        """(xMin, yMin, xMax, yMax) of one glyph, in font units."""
        g = self.font["glyf"][self.cmap[ord(char)]]
        return g.xMin, g.yMin, g.xMax, g.yMax


def source_parts():
    svg = SOURCE.read_text()
    defs = re.search(r"<defs>.*?</defs>", svg, re.S).group(0)
    icon = re.search(
        r"<!-- =+ STOPWATCH ICON.*?(?=<!-- =+ LOGO TEXT)", svg, re.S
    ).group(0)
    return defs, icon


def face_letter(t):
    """The "N" on the face, in Nanoplex, the size and place of the old one."""
    x0, y0, x1, y1 = t.bounds("N")
    height = 106.0  # the old letter's height
    size = height * t.upm / (y1 - y0)
    s = size / t.upm
    width = (x1 - x0) * s
    x = CX - width / 2 - x0 * s
    baseline = CY + height / 2 + y0 * s
    d = t.path("N", size, x, baseline)
    return (
        '  <!-- The large N letter (Nanoplex) -->\n'
        f'  <g filter="url(#neonGlow)"><path d="{d}" fill="url(#nGrad)"/></g>\n\n'
    )


def build_icon_body(t, icon):
    # Replace the old hand-drawn N (a <g> of two rects and a polygon).
    return re.sub(
        r"  <!-- The large N letter -->\n\s*<g filter=\"url\(#neonGlow\)\">.*?</g>\n\s*\n",
        face_letter(t),
        icon,
        flags=re.S,
    )


def cap_size(t, cap_px):
    """The font size whose capitals are `cap_px` tall. Nanoplex's capitals
    are short for their em, so sizing by em would set it small."""
    _, y0, _, y1 = t.bounds("N")
    return cap_px * t.upm / (y1 - y0)


def write_svgs(t, ink=INK, grey=GREY, subtitle=True):
    defs, icon = source_parts()
    body = build_icon_body(t, icon)

    # The whole logo: the watch, then "Nano" + "Chronometer" and the subtitle,
    # the block centred on the watch face.
    cap, sub_cap, gap = 70.0, 13.0, 26.0
    size, sub_size, tracking = cap_size(t, cap), cap_size(t, sub_cap), 5.0
    x_text = 232
    top = CY - ((cap + gap + sub_cap) if subtitle else cap) / 2
    baseline = top + cap
    nano_w = t.width("Nano", size)
    chrono_w = t.width("Chronometer", size)
    sub_w = t.width(SUBTITLE, sub_size, tracking) if subtitle else 0
    width = int(x_text + max(nano_w + chrono_w, sub_w) + 28)
    height = 228
    logo = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">\n'
        "<!-- Generated by tools/gen-icons.py. Lettering: Nanoplex, as outlines. -->\n"
        f"  {defs}\n{body}"
        '  <!-- ============ LOGO TEXT (Nanoplex outlines) ============ -->\n'
        f'  <path id="text-nano" d="{t.path("Nano", size, x_text, baseline)}" fill="{GREEN}"/>\n'
        f'  <path id="text-chronometer" d="{t.path("Chronometer", size, x_text + nano_w, baseline)}" '
        f'fill="{ink}"/>\n'
        + (
            f'  <path id="text-subtitle" d="{t.path(SUBTITLE, sub_size, x_text + 2, baseline + gap + sub_cap, tracking)}" '
            f'fill="{grey}"/>\n'
            if subtitle
            else ""
        )
        + "</svg>\n"
    )

    # The stopwatch alone, on a square canvas that holds the crown, the lugs
    # and the drop shadow.
    icon_svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-6 0 228 228" '
        'width="228" height="228">\n'
        "<!-- Generated by tools/gen-icons.py. The N is Nanoplex, as an outline. -->\n"
        f"  {defs}\n{body}</svg>\n"
    )
    return logo, icon_svg, width, height


def png(svg, width, height=None):
    data = cairosvg.svg2png(
        bytestring=svg.encode(), output_width=width, output_height=height or width
    )
    return Image.open(io.BytesIO(data)).convert("RGBA")


def main():
    t = Typesetter(FONT)
    logo, icon, lw, lh = write_svgs(t)
    logo_dark, _, _, _ = write_svgs(t, INK_DARK_BG, GREY_DARK_BG)

    ASSETS.joinpath("nanochronometer_logo.svg").write_text(logo)
    ASSETS.joinpath("nanochronometer_icon.svg").write_text(icon)
    ASSETS.joinpath("nanochronometer_logo_dark.svg").write_text(logo_dark)
    png(logo_dark, lw * 2, lh * 2).save(ASSETS / "nanochronometer_logo_dark.png")
    png(logo, lw * 2, lh * 2).save(ASSETS / "nanochronometer_logo.png")
    png(icon, 1024).save(ASSETS / "nanochronometer_icon.png")

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    master = png(icon, 1024)
    frames = {n: png(icon, n) for n in ico_sizes}

    def save_ico(path):
        # Each size rendered from the vector, not downscaled from one bitmap:
        # small sizes stay sharp.
        frames[256].save(path, format="ICO", sizes=[(n, n) for n in ico_sizes],
                         append_images=[frames[n] for n in ico_sizes if n != 256])

    save_ico(ASSETS / "nanochrono.ico")

    icons = ASSETS / "icons"
    common = lambda d: (  # noqa: E731 — every platform gets both vectors
        d.mkdir(parents=True, exist_ok=True),
        (d / "nanochronometer_logo.svg").write_text(logo),
        (d / "nanochronometer_icon.svg").write_text(icon),
        (d / "nanochronometer_logo_dark.svg").write_text(logo_dark),
        png(logo, lw * 2, lh * 2).save(d / "nanochronometer_logo.png"),
    )

    # Windows: the multi-size ICO the resource compiler embeds.
    d = icons / "windows"
    common(d)
    save_ico(d / "nanochrono.ico")
    png(icon, 256).save(d / "nanochronometer_icon_256.png")

    # macOS: an ICNS plus the iconset sizes.
    d = icons / "macos"
    common(d)
    for n in [16, 32, 64, 128, 256, 512, 1024]:
        png(icon, n).save(d / f"nanochronometer_icon_{n}.png")
    master.save(d / "nanochrono.icns", format="ICNS")

    # Linux: the hicolor theme layout install.sh copies from.
    d = icons / "linux"
    common(d)
    for n in [16, 22, 24, 32, 48, 64, 96, 128, 256, 512]:
        p = d / "hicolor" / f"{n}x{n}" / "apps"
        p.mkdir(parents=True, exist_ok=True)
        png(icon, n).save(p / "nanochronometer.png")
    p = d / "hicolor" / "scalable" / "apps"
    p.mkdir(parents=True, exist_ok=True)
    (p / "nanochronometer.svg").write_text(icon)
    save_ico(d / "nanochrono.ico")

    # Android: launcher mipmaps per density, and the 512 px store icon.
    d = icons / "android"
    common(d)
    for dpi, n in [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]:
        p = d / f"mipmap-{dpi}"
        p.mkdir(parents=True, exist_ok=True)
        png(icon, n).save(p / "ic_launcher.png")
    png(icon, 512).save(d / "ic_launcher-playstore.png")

    # Bare metal: PNGs and raw RGBA (width, height as u32 LE, then pixels), the
    # form a kernel with no image decoder can blit.
    d = icons / "baremetal"
    common(d)
    for n in [16, 32, 48, 64, 128]:
        im = png(icon, n)
        im.save(d / f"nanochronometer_icon_{n}.png")
        (d / f"nanochronometer_icon_{n}.rgba").write_bytes(
            struct.pack("<II", n, n) + im.tobytes()
        )
    save_ico(d / "nanochrono.ico")

    # The logo the kernel draws: white "Chronometer", green subtitle, on the
    # black interface. The header gets the wordmark without the subtitle
    # (at 40 px it would be two pixels tall); the boot screen gets it whole.
    # Straight (not premultiplied) RGBA, blended over the screen at draw time.
    def rgba(svg, w, h, name):
        im = png(svg, w, h)
        (d / name).write_bytes(struct.pack("<II", w, h) + im.tobytes())
        im.save(d / name.replace(".rgba", ".png"))

    mark, _, mw, mh = write_svgs(t, INK_DARK_BG, GREY_BAREMETAL, subtitle=False)
    full, _, fw, fh = write_svgs(t, INK_DARK_BG, GREY_BAREMETAL)
    (d / "nanochronometer_wordmark_baremetal.svg").write_text(mark)
    (d / "nanochronometer_logo_baremetal.svg").write_text(full)
    for h in [24, 32, 40]:
        rgba(mark, round(mw * h / mh), h, f"nanochronometer_wordmark_{h}.rgba")
    rgba(full, round(fw * 96 / fh), 96, "nanochronometer_logo_96.rgba")

    # The desktop GUI's header (dark theme): the wordmark, white lettering.
    png(mark, round(mw * 80 / mh), 80).save(ASSETS / "nanochronometer_wordmark_dark.png")

    # The Android app's header, and its launcher icons, straight into the
    # app's resources. 144 px tall, shown at 36 dp: sharp up to xxxhdpi.
    res = ROOT / "packaging" / "android" / "app" / "res"
    p = res / "drawable-nodpi"
    p.mkdir(parents=True, exist_ok=True)
    png(mark, round(mw * 144 / mh), 144).save(p / "nanochronometer_wordmark.png")
    for dpi, n in [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]:
        png(icon, n).save(res / f"mipmap-{dpi}" / "ic_launcher.png")

    print(f"logo {lw}x{lh}; icon 228x228; wrote {ASSETS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
