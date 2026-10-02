// SPDX-License-Identifier: Apache-2.0
//! Rectangles, and the pool window surfaces are cut from.
//!
//! There is no allocator, so the desktop's pixels come from one static pool,
//! carved into blocks as windows open and returned as they close: first fit
//! over a short sorted table of the blocks in use. It is an allocator for
//! pixel buffers only — a few dozen, each large — not a heap: nothing else
//! the kernel does allocates.

/// A rectangle on the screen or in a surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }

    pub fn right(&self) -> i32 {
        self.x + self.w
    }

    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }

    pub fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }

    pub fn contains(&self, x: i32, y: i32) -> bool {
        !self.is_empty() && x >= self.x && y >= self.y && x < self.right() && y < self.bottom()
    }

    pub fn intersect(&self, o: &Rect) -> Option<Rect> {
        let x = self.x.max(o.x);
        let y = self.y.max(o.y);
        let r = self.right().min(o.right());
        let b = self.bottom().min(o.bottom());
        (r > x && b > y).then_some(Rect::new(x, y, r - x, b - y))
    }

    pub fn union(&self, o: &Rect) -> Rect {
        if self.is_empty() {
            return *o;
        }
        if o.is_empty() {
            return *self;
        }
        let x = self.x.min(o.x);
        let y = self.y.min(o.y);
        Rect::new(x, y, self.right().max(o.right()) - x, self.bottom().max(o.bottom()) - y)
    }

    pub fn offset(&self, dx: i32, dy: i32) -> Rect {
        Rect::new(self.x + dx, self.y + dy, self.w, self.h)
    }

    pub fn inset(&self, d: i32) -> Rect {
        Rect::new(self.x + d, self.y + d, self.w - 2 * d, self.h - 2 * d)
    }

    /// Whether `o` lies wholly inside this one.
    pub fn covers(&self, o: &Rect) -> bool {
        o.x >= self.x && o.y >= self.y && o.right() <= self.right() && o.bottom() <= self.bottom()
    }
}

/// The pool, in pixels. x86_64 machines have memory to spare; elsewhere the
/// boards QEMU models have 256 MiB, and a smaller pool keeps the image there.
#[cfg(target_arch = "x86_64")]
pub const POOL_PIXELS: usize = 14 * 1024 * 1024;
#[cfg(not(target_arch = "x86_64"))]
pub const POOL_PIXELS: usize = 6 * 1024 * 1024;

static mut POOL: [u32; POOL_PIXELS] = [0; POOL_PIXELS];

/// A block of the pool: `len` pixels from `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    start: usize,
    len: usize,
}

impl Block {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn bytes(&self) -> usize {
        self.len * 4
    }

    /// The block's pixels.
    ///
    /// # Safety
    /// One mutable view per block at a time; the block must be live.
    pub unsafe fn pixels(&self) -> &'static mut [u32] {
        // SAFETY: blocks never overlap and lie inside the pool; the caller
        // keeps one view at a time.
        unsafe { core::slice::from_raw_parts_mut((core::ptr::addr_of_mut!(POOL) as *mut u32).add(self.start), self.len) }
    }
}

const MAX_BLOCKS: usize = 48;
static mut USED: [Option<Block>; MAX_BLOCKS] = [None; MAX_BLOCKS];

/// A block of at least `pixels`, or `None` when no gap is large enough.
pub fn alloc(pixels: usize) -> Option<Block> {
    if pixels == 0 || pixels > POOL_PIXELS {
        return None;
    }
    // SAFETY: one core; the table is only touched here and in `free`.
    let used = unsafe { &mut *core::ptr::addr_of_mut!(USED) };
    // Candidate starts: the pool's beginning and the end of every block.
    let mut best: Option<usize> = None;
    let fits = |start: usize, used: &[Option<Block>; MAX_BLOCKS]| {
        start + pixels <= POOL_PIXELS
            && used.iter().flatten().all(|b| start + pixels <= b.start || b.start + b.len <= start)
    };
    let mut candidates = [0usize; MAX_BLOCKS + 1];
    let mut n = 1;
    for b in used.iter().flatten() {
        candidates[n] = b.start + b.len;
        n += 1;
    }
    for &c in &candidates[..n] {
        if fits(c, used) && best.is_none_or(|b| c < b) {
            best = Some(c);
        }
    }
    let start = best?;
    let slot = used.iter_mut().find(|s| s.is_none())?;
    let block = Block { start, len: pixels };
    *slot = Some(block);
    Some(block)
}

/// Returns a block to the pool.
pub fn free(block: Block) {
    // SAFETY: as in `alloc`.
    let used = unsafe { &mut *core::ptr::addr_of_mut!(USED) };
    if let Some(slot) = used.iter_mut().find(|s| **s == Some(block)) {
        *slot = None;
    }
}

/// Pixels in use and the pool's size, for the task manager.
pub fn usage() -> (usize, usize) {
    // SAFETY: a read of the table on the one core.
    let used = unsafe { &*core::ptr::addr_of!(USED) };
    (used.iter().flatten().map(|b| b.len).sum(), POOL_PIXELS)
}

/// A drawable view of a block as a `w x h` surface.
///
/// # Safety
/// As [`Block::pixels`]; `w * h` must not exceed the block.
pub unsafe fn surface(block: &Block, w: u32, h: u32) -> crate::framebuffer::Framebuffer {
    debug_assert!((w * h) as usize <= block.len);
    // SAFETY: forwarded; the block holds at least `w * h` pixels.
    unsafe { crate::framebuffer::Framebuffer::surface(block.pixels().as_mut_ptr(), w, h) }
}
