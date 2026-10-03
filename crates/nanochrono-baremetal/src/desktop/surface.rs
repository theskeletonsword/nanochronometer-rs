// SPDX-License-Identifier: Apache-2.0
//! Rectangles, and the pool window surfaces are cut from.
//!
//! The desktop's pixels come from one static pool, carved into blocks as
//! windows open and returned as they close: first fit over a short table of
//! the blocks in use. It is an allocator for pixel buffers only — a few
//! dozen, each large — not a heap.
//!
//! The pool is sized for screens up to 1920×1200. A larger screen — a 4K
//! monitor wants two full-screen buffers of 8.3 million pixels each, the
//! wallpaper and the background — takes what the pool cannot hold from the
//! page allocator ([`crate::palloc`]), block by block, and gives it back
//! the same way.

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

/// A block of pixels: `len` from `start` in the pool, or — `paged` — `len`
/// at address `start`, from the page allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    start: usize,
    len: usize,
    paged: bool,
}

/// Pixels handed out from the page allocator and not yet given back.
static PAGED_PIXELS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
        if self.paged {
            // SAFETY: a run the page allocator handed this block alone,
            // identity-mapped and `len` pixels long.
            return unsafe { core::slice::from_raw_parts_mut(self.start as *mut u32, self.len) };
        }
        // SAFETY: blocks never overlap and lie inside the pool; the caller
        // keeps one view at a time.
        unsafe { core::slice::from_raw_parts_mut((core::ptr::addr_of_mut!(POOL) as *mut u32).add(self.start), self.len) }
    }
}

const MAX_BLOCKS: usize = 48;
static mut USED: [Option<Block>; MAX_BLOCKS] = [None; MAX_BLOCKS];

/// A block of at least `pixels`: from the pool, or when no gap there is
/// large enough, from the page allocator; `None` when neither has room.
pub fn alloc(pixels: usize) -> Option<Block> {
    if pixels == 0 {
        return None;
    }
    alloc_pooled(pixels).or_else(|| alloc_paged(pixels))
}

/// A block from the page allocator, zeroed as the pool's blocks start out.
fn alloc_paged(pixels: usize) -> Option<Block> {
    let bytes = pixels.checked_mul(4)?;
    let start = crate::palloc::alloc_zeroed(bytes, 4096)?;
    PAGED_PIXELS.fetch_add(pixels, core::sync::atomic::Ordering::Relaxed);
    Some(Block { start, len: pixels, paged: true })
}

/// A block of the static pool: first fit.
fn alloc_pooled(pixels: usize) -> Option<Block> {
    if pixels > POOL_PIXELS {
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
    let block = Block { start, len: pixels, paged: false };
    *slot = Some(block);
    Some(block)
}

/// Returns a block to the pool, or to the page allocator it came from.
pub fn free(block: Block) {
    if block.paged {
        if crate::palloc::free(block.start, block.len * 4) {
            PAGED_PIXELS.fetch_sub(block.len, core::sync::atomic::Ordering::Relaxed);
        }
        return;
    }
    // SAFETY: as in `alloc`.
    let used = unsafe { &mut *core::ptr::addr_of_mut!(USED) };
    if let Some(slot) = used.iter_mut().find(|s| **s == Some(block)) {
        *slot = None;
    }
}

/// Pixels in use and the pixels available, for the task manager: the pool,
/// plus what was taken from the page allocator (counted on both sides).
pub fn usage() -> (usize, usize) {
    // SAFETY: a read of the table on the one core.
    let used = unsafe { &*core::ptr::addr_of!(USED) };
    let paged = PAGED_PIXELS.load(core::sync::atomic::Ordering::Relaxed);
    (used.iter().flatten().map(|b| b.len).sum::<usize>() + paged, POOL_PIXELS + paged)
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
