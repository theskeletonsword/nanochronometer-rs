// SPDX-License-Identifier: Apache-2.0
//! The NanoChronometer logo, as pixels the kernel can blit.
//!
//! The picture is `assets/nanochronometer_logo_dark.png` itself — the logo
//! made for dark backgrounds. A PNG decoder in a kernel would be an inflate
//! implementation in ring 0, so `build.rs` decodes it on the host and scales
//! it to the heights drawn here, writing raw RGBA (an 8-byte header, width
//! and height as little-endian `u32`, then straight, non-premultiplied
//! pixels) that the kernel embeds as it is. Drawing is a per-pixel blend
//! over what is already on screen.

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
    pub const fn parse(bytes: &'static [u8]) -> Image {
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

    /// The straight RGBA pixel at `(x, y)`; transparent outside the image.
    pub fn rgba(&self, x: u32, y: u32) -> [u8; 4] {
        if x >= self.width || y >= self.height {
            return [0; 4];
        }
        let i = ((y * self.width + x) * 4) as usize;
        match self.pixels.get(i..i + 4) {
            Some(p) => [p[0], p[1], p[2], p[3]],
            None => [0; 4],
        }
    }
}

macro_rules! asset {
    ($h:literal) => {
        Image::parse(include_bytes!(concat!(env!("OUT_DIR"), "/logo_", $h, ".rgba")))
    };
}

/// The header sizes, smallest first (see `LOGO_HEIGHTS` in build.rs).
static HEADER: [Image; 4] = [asset!("28"), asset!("36"), asset!("44"), asset!("52")];

/// The boot screen's size.
pub static LOGO: Image = asset!("128");

/// The tallest header logo no taller than `max_height`, or the smallest one
/// when none fits.
pub fn for_height(max_height: u32) -> &'static Image {
    HEADER.iter().rev().find(|i| i.height <= max_height).unwrap_or(&HEADER[0])
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
