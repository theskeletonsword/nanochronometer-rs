// SPDX-License-Identifier: Apache-2.0
//! A linear framebuffer, and the back buffer that makes it drawable.
//!
//! The loader is asked for a graphics mode through the multiboot2 header and
//! reports what it produced in the boot information structure. Everything
//! here works from that: a base address, a pitch, a size and a pixel format.
//! There is no GPU driver and no acceleration — every pixel is a store.
//!
//! # Why there is a back buffer
//!
//! Firmware framebuffers are mapped **uncached**, and this kernel's page
//! tables set PCD on everything above the first gigabyte for exactly that
//! reason: MMIO that is cached is MMIO that does not work. The cost is that a
//! store to the framebuffer is an uncached transaction, on the order of a
//! hundred times slower than a store to RAM, and drawing a glyph means
//! *reading* every pixel it covers to blend against — which is slower still.
//!
//! A frame drawn straight onto the device therefore has two problems at once:
//! it is slow enough to see, and it is visible while it is being assembled,
//! so a redraw flickers. Both are the same fix. Everything is drawn into a
//! plain-RAM buffer where reads and writes are cached, and only the rectangle
//! that actually changed is copied out. A cursor move copies a hundred
//! pixels; a digit changing copies the digit.
//!
//! That is what makes an animated interface possible here at all. Without it
//! the frame rate is set by the width of the panel, and a full-screen redraw
//! on a 1080p display is tens of milliseconds of visible tearing.
//!
//! What this draws is the same *design* as the desktop GUI, not the same
//! code: `iced` renders through `wgpu` onto a surface `winit` gets from a
//! window server, none of which exists here.

use core::sync::atomic::{AtomicU32, Ordering};

/// Where the loader put the framebuffer, and how it is laid out.
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    base: *mut u8,
    /// The back buffer, or null when the mode is too large for it. Always
    /// `width` pixels per row, 32 bits per pixel, regardless of what the
    /// device wants — the conversion happens once, in [`Framebuffer::present`].
    shadow: *mut u32,
    pub width: u32,
    pub height: u32,
    /// Bytes per scanline on the *device*. Not always `width *
    /// bytes_per_pixel`: the loader may pad rows, and assuming it does not is
    /// how a display ends up sheared diagonally.
    pitch: u32,
    bytes_per_pixel: u32,
}

/// A colour, as the framebuffer wants it.
pub type Colour = u32;

/// How large a mode the back buffer covers.
///
/// 1920x1200 is the largest panel this is likely to meet on a laptop, and the
/// buffer costs four bytes a pixel of `.bss` — about nine megabytes, zeroed
/// once by the boot stub. A larger mode is not an error: the interface falls
/// back to drawing straight onto the device, which works and merely flickers.
const SHADOW_W: usize = 1920;
const SHADOW_H: usize = 1200;

/// The back buffer itself.
///
/// A static rather than an allocation because there is no allocator, and in
/// `.bss` rather than `.data` so the nine megabytes are zeroes in the ELF
/// rather than nine megabytes of file.
static mut SHADOW: [u32; SHADOW_W * SHADOW_H] = [0; SHADOW_W * SHADOW_H];

/// The rectangle drawn into since the last present.
///
/// Held as four scalars rather than a struct so each is one atomic: this is
/// updated on every fill and every glyph, and the whole point of the back
/// buffer is that those are cheap. Stored as an empty range — `x0 > x1` —
/// which is what `reset` restores.
static DIRTY_X0: AtomicU32 = AtomicU32::new(u32::MAX);
static DIRTY_Y0: AtomicU32 = AtomicU32::new(u32::MAX);
static DIRTY_X1: AtomicU32 = AtomicU32::new(0);
static DIRTY_Y1: AtomicU32 = AtomicU32::new(0);

/// Widens the damage rectangle to include `[x, x + w) x [y, y + h)`.
#[inline]
fn mark(x: u32, y: u32, w: u32, h: u32) {
    // Relaxed throughout: this kernel runs on one core with interrupts
    // masked, so there is no other writer to order against. The atomics exist
    // to hold the value in a static at all, not to synchronise.
    DIRTY_X0.fetch_min(x, Ordering::Relaxed);
    DIRTY_Y0.fetch_min(y, Ordering::Relaxed);
    DIRTY_X1.fetch_max(x.saturating_add(w), Ordering::Relaxed);
    DIRTY_Y1.fetch_max(y.saturating_add(h), Ordering::Relaxed);
}

impl Framebuffer {
    /// Wraps a framebuffer the loader described.
    ///
    /// # Safety
    /// `base` must be a linear framebuffer of at least `pitch * height`
    /// bytes, mapped and writable.
    pub const unsafe fn new(
        base: *mut u8,
        width: u32,
        height: u32,
        pitch: u32,
        bits_per_pixel: u8,
    ) -> Framebuffer {
        Framebuffer {
            base,
            shadow: core::ptr::null_mut(),
            width,
            height,
            pitch,
            bytes_per_pixel: (bits_per_pixel as u32).div_ceil(8),
        }
    }

    /// Attaches the back buffer, if this mode fits in it.
    ///
    /// Called once, before anything is drawn. Returns whether compositing is
    /// on, which the interface reports rather than hides: a mode with no back
    /// buffer redraws visibly, and that is worth being able to explain.
    ///
    /// # Safety
    /// Must be called at most once, and before any other reference to the
    /// back buffer exists. There is one caller, in `kmain`.
    pub unsafe fn attach_back_buffer(&mut self) -> bool {
        if self.width as usize > SHADOW_W || self.height as usize > SHADOW_H {
            return false;
        }
        // `addr_of_mut!` rather than `&mut SHADOW`: taking a reference to a
        // `static mut` is unsound the moment a second one exists, and this
        // pointer outlives the call. Only the address is wanted.
        self.shadow = core::ptr::addr_of_mut!(SHADOW).cast::<u32>();
        true
    }

    /// Whether drawing goes through the back buffer.
    pub fn composited(&self) -> bool {
        !self.shadow.is_null()
    }

    /// Whether this describes a usable surface.
    ///
    /// Also the only check between a loader's numbers and pixel writes that
    /// index memory by them, so the geometry has to be *consistent*, not just
    /// non-zero: a row must fit in its pitch (otherwise the last pixels of
    /// the last row land past the end of the framebuffer), and
    /// `pitch * height` must fit in 32 bits (every offset is computed as
    /// `y * pitch + x * bpp` in `u32`, and a wrapped product would point
    /// back into the middle of memory rather than off the end).
    pub fn is_usable(&self) -> bool {
        let row_bytes = self.width.checked_mul(self.bytes_per_pixel);
        let size = self.pitch.checked_mul(self.height);
        !self.base.is_null()
            && self.width > 0
            && self.height > 0
            && self.bytes_per_pixel >= 2
            && self.bytes_per_pixel <= 4
            && matches!(row_bytes, Some(row) if row <= self.pitch)
            && size.is_some()
    }

    /// Where the device surface starts.
    pub fn base_address(&self) -> *mut u8 {
        self.base
    }

    /// Bytes the device surface spans, `pitch * height`.
    pub fn size_bytes(&self) -> u64 {
        self.pitch as u64 * self.height as u64
    }

    /// Writes one pixel, ignoring anything outside the surface.
    #[inline]
    pub fn set(&self, x: u32, y: u32, colour: Colour) {
        if x >= self.width || y >= self.height {
            return;
        }
        if !self.shadow.is_null() {
            // SAFETY: the bounds check above keeps the index inside the back
            // buffer, whose rows are exactly `width` pixels.
            unsafe { self.shadow.add((y * self.width + x) as usize).write(colour) };
            mark(x, y, 1, 1);
            return;
        }
        // SAFETY: bounds-checked above; `new`'s caller guaranteed the surface.
        unsafe { self.store(x, y, colour) };
    }

    /// Reads one pixel back.
    ///
    /// Blending a glyph against what is under it needs this for every pixel
    /// of every glyph. Through the back buffer it is a cached load; without
    /// one it is an uncached read from device memory, which is why text is
    /// the slowest thing this draws on a machine with no back buffer.
    #[inline]
    pub fn get(&self, x: u32, y: u32) -> Colour {
        if x >= self.width || y >= self.height {
            return 0;
        }
        if !self.shadow.is_null() {
            // SAFETY: bounds-checked above.
            return unsafe { self.shadow.add((y * self.width + x) as usize).read() };
        }
        let offset = (y * self.pitch + x * self.bytes_per_pixel) as usize;
        // SAFETY: the bounds check keeps the offset inside the surface
        // `new`'s caller guaranteed.
        unsafe {
            match self.bytes_per_pixel {
                4 => core::ptr::read_volatile(self.base.add(offset).cast::<u32>()),
                3 => {
                    let p = self.base.add(offset);
                    core::ptr::read_volatile(p) as u32
                        | (core::ptr::read_volatile(p.add(1)) as u32) << 8
                        | (core::ptr::read_volatile(p.add(2)) as u32) << 16
                }
                _ => {
                    // 5:6:5 expanded back to 8:8:8. The low bits were lost
                    // when it was written, so this is not exact — on a 16-bit
                    // mode a restored pixel can differ by a shade.
                    let packed = core::ptr::read_volatile(self.base.add(offset).cast::<u16>());
                    let r = ((packed >> 11) & 0x1F) as u32;
                    let g = ((packed >> 5) & 0x3F) as u32;
                    let b = (packed & 0x1F) as u32;
                    (r << 19) | (g << 10) | (b << 3)
                }
            }
        }
    }

    /// Writes one pixel straight to the device, in its own format.
    ///
    /// # Safety
    /// `x` and `y` must be inside the surface.
    #[inline]
    unsafe fn store(&self, x: u32, y: u32, colour: Colour) {
        let offset = (y * self.pitch + x * self.bytes_per_pixel) as usize;
        // SAFETY: forwarded from this function's own contract; a framebuffer
        // write has no aliasing requirements beyond being in range.
        unsafe {
            match self.bytes_per_pixel {
                4 => core::ptr::write_volatile(self.base.add(offset).cast::<u32>(), colour),
                3 => {
                    let p = self.base.add(offset);
                    core::ptr::write_volatile(p, colour as u8);
                    core::ptr::write_volatile(p.add(1), (colour >> 8) as u8);
                    core::ptr::write_volatile(p.add(2), (colour >> 16) as u8);
                }
                _ => {
                    // 16-bit: 5:6:5, the only packed format worth supporting.
                    let r = (colour >> 19) & 0x1F;
                    let g = (colour >> 10) & 0x3F;
                    let b = (colour >> 3) & 0x1F;
                    let packed = ((r << 11) | (g << 5) | b) as u16;
                    core::ptr::write_volatile(self.base.add(offset).cast::<u16>(), packed);
                }
            }
        }
    }

    /// Fills a rectangle.
    pub fn fill(&self, x: u32, y: u32, w: u32, h: u32, colour: Colour) {
        if x >= self.width || y >= self.height || w == 0 || h == 0 {
            return;
        }
        let right = x.saturating_add(w).min(self.width);
        let bottom = y.saturating_add(h).min(self.height);

        if !self.shadow.is_null() {
            for row in y..bottom {
                // SAFETY: rows and columns were clipped to the surface, and
                // the back buffer's rows are exactly `width` pixels.
                unsafe {
                    let start = self.shadow.add((row * self.width + x) as usize);
                    for col in 0..(right - x) {
                        start.add(col as usize).write(colour);
                    }
                }
            }
            mark(x, y, right - x, bottom - y);
            return;
        }

        for row in y..bottom {
            for col in x..right {
                // SAFETY: both were clipped to the surface above.
                unsafe { self.store(col, row, colour) };
            }
        }
    }

    /// Fills the whole surface.
    pub fn clear(&self, colour: Colour) {
        self.fill(0, 0, self.width, self.height, colour);
    }

    /// Draws a one-pixel rectangle outline.
    pub fn outline(&self, x: u32, y: u32, w: u32, h: u32, colour: Colour) {
        if w == 0 || h == 0 {
            return;
        }
        self.fill(x, y, w, 1, colour);
        self.fill(x, y + h - 1, w, 1, colour);
        self.fill(x, y, 1, h, colour);
        self.fill(x + w - 1, y, 1, h, colour);
    }

    /// Copies one rectangle of the back buffer to the device.
    ///
    /// A no-op without a back buffer, where the pixels are already there.
    pub fn present(&self, x: u32, y: u32, w: u32, h: u32) {
        if self.shadow.is_null() || w == 0 || h == 0 || x >= self.width || y >= self.height {
            return;
        }
        let right = x.saturating_add(w).min(self.width);
        let bottom = y.saturating_add(h).min(self.height);

        for row in y..bottom {
            // SAFETY: clipped to the surface; the back buffer's rows are
            // `width` pixels and the device's are `pitch` bytes.
            unsafe {
                let src = self.shadow.add((row * self.width) as usize);
                let mut offset = (row * self.pitch + x * self.bytes_per_pixel) as usize;
                for col in x..right {
                    let colour = src.add(col as usize).read();
                    match self.bytes_per_pixel {
                        4 => core::ptr::write_volatile(self.base.add(offset).cast::<u32>(), colour),
                        3 => {
                            let p = self.base.add(offset);
                            core::ptr::write_volatile(p, colour as u8);
                            core::ptr::write_volatile(p.add(1), (colour >> 8) as u8);
                            core::ptr::write_volatile(p.add(2), (colour >> 16) as u8);
                        }
                        _ => {
                            let r = (colour >> 19) & 0x1F;
                            let g = (colour >> 10) & 0x3F;
                            let b = (colour >> 3) & 0x1F;
                            core::ptr::write_volatile(
                                self.base.add(offset).cast::<u16>(),
                                ((r << 11) | (g << 5) | b) as u16,
                            );
                        }
                    }
                    offset += self.bytes_per_pixel as usize;
                }
            }
        }
    }

    /// Copies everything drawn since the last call, and forgets it.
    ///
    /// The damage is one bounding box rather than a list of rectangles. That
    /// is the right trade here because the interface presents each widget
    /// group as it finishes it: a box around one readout is tight, while a
    /// box around a readout and a cursor in the far corner would be the whole
    /// screen. Callers that redraw scattered things call this between them.
    pub fn present_damage(&self) {
        let x0 = DIRTY_X0.swap(u32::MAX, Ordering::Relaxed);
        let y0 = DIRTY_Y0.swap(u32::MAX, Ordering::Relaxed);
        let x1 = DIRTY_X1.swap(0, Ordering::Relaxed);
        let y1 = DIRTY_Y1.swap(0, Ordering::Relaxed);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        self.present(x0, y0, x1 - x0, y1 - y0);
    }

    /// Discards the damage without presenting it.
    ///
    /// For the one case where a caller knows it is about to present a larger
    /// rectangle by hand.
    pub fn discard_damage(&self) {
        DIRTY_X0.store(u32::MAX, Ordering::Relaxed);
        DIRTY_Y0.store(u32::MAX, Ordering::Relaxed);
        DIRTY_X1.store(0, Ordering::Relaxed);
        DIRTY_Y1.store(0, Ordering::Relaxed);
    }
}

// SAFETY: a framebuffer is memory-mapped device storage, and the back buffer
// is a static this kernel owns. It runs on one core with interrupts masked, so
// there is no concurrent access to race with; the markers exist so a
// `Framebuffer` can live in a static.
unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}
