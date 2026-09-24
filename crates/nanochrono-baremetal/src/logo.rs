// SPDX-License-Identifier: Apache-2.0
//! The NanoChronometer logo, as pixels the kernel can blit.
//!
//! Decoding a PNG or rendering the SVG in a kernel would mean an inflate
//! implementation or a vector rasteriser — far more code, and more attack
//! surface, than the picture is worth. So `tools/gen-icons.py` rasterises the
//! logo at build time into raw RGBA (an 8-byte header, width and height as
//! little-endian `u32`, then straight, non-premultiplied pixels) and the
//! kernel embeds those bytes as they are. Drawing is a per-pixel blend over
//! what is already on screen.
//!
//! The variant is the bare-metal one: "Nano" green, "Chronometer" white, the
//! subtitle green, for the black interface. Nothing in it is grey.

use crate::draw;
use crate::framebuffer::{Colour, Framebuffer};

/// One embedded image.
pub struct Image {
    pub width: u32,
    pub height: u32,
    pixels: &'static [u8],
}

impl Image {
    /// Splits the header off. `const`, so a malformed asset fails the build
    /// rather than the boot.
    const fn parse(bytes: &'static [u8]) -> Image {
        assert!(bytes.len() >= 8, "logo asset has no header");
        let width = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let height = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert!(
            bytes.len() == 8 + (width as usize) * (height as usize) * 4,
            "logo asset size does not match its header"
        );
        let (_, pixels) = bytes.split_at(8);
        Image { width, height, pixels }
    }
}

macro_rules! asset {
    ($file:literal) => {
        Image::parse(include_bytes!(concat!("../../../assets/icons/baremetal/", $file)))
    };
}

/// The stopwatch and "NanoChronometer", no subtitle: for the header, where
/// the subtitle would be two pixels tall.
static WORDMARKS: [Image; 3] = [
    asset!("nanochronometer_wordmark_24.rgba"),
    asset!("nanochronometer_wordmark_32.rgba"),
    asset!("nanochronometer_wordmark_40.rgba"),
];

/// The whole logo, subtitle included: for the boot screen.
pub static LOGO: Image = asset!("nanochronometer_logo_96.rgba");

/// The tallest wordmark no taller than `max_height`, or the smallest one
/// when none fits.
pub fn wordmark(max_height: u32) -> &'static Image {
    WORDMARKS
        .iter()
        .rev()
        .find(|i| i.height <= max_height)
        .unwrap_or(&WORDMARKS[0])
}

/// Blends `image` onto the framebuffer with its top-left corner at `(x, y)`,
/// clipped to the screen. Does not present.
pub fn draw(fb: &Framebuffer, image: &Image, x: u32, y: u32) {
    let w = image.width.min(fb.width.saturating_sub(x));
    let h = image.height.min(fb.height.saturating_sub(y));
    for row in 0..h {
        for col in 0..w {
            let i = ((row * image.width + col) * 4) as usize;
            let px = &image.pixels[i..i + 4];
            let alpha = px[3];
            if alpha == 0 {
                continue;
            }
            let fg: Colour = (px[0] as u32) << 16 | (px[1] as u32) << 8 | px[2] as u32;
            let bg = fb.get(x + col, y + row);
            fb.set(x + col, y + row, draw::blend(bg, fg, alpha));
        }
    }
}
