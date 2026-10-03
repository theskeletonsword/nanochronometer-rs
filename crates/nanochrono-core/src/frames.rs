// SPDX-License-Identifier: Apache-2.0
//! Physical memory as ranges: what the firmware says is RAM, minus what is
//! already in use, handed out a page-aligned run at a time.
//!
//! The kernel had no allocator, by design, while everything it needed fit in
//! its own `.bss`. A screen does not: a 3840×2160 back buffer is 32 MiB, a
//! 5K one 56 MiB, and reserving the largest for every machine would cost
//! that much on all of them. Nor does a driver module, whose size the kernel
//! cannot know when it is built. So this is the smallest allocator that
//! serves both: a sorted table of free `[base, end)` ranges — FreeBSD's
//! `phys_avail[]` in spirit — with first-fit from the top, so low memory
//! stays free for whatever needs it later.
//!
//! `no_std`, allocation-free and pure: the kernel feeds it the loader's
//! memory map and its own reservations, and the host tests drive the same
//! code against a page-by-page model.
//!
//! The table is fixed (`N` ranges). An operation that would need a slot the
//! table lacks never hands out memory it should not: a reservation that
//! splits a range drops the smaller piece, a free that finds the table full
//! drops what was freed. Either way the memory is lost, never shared, and
//! [`Frames::dropped`] says how much.

/// The page size every range is aligned to.
pub const PAGE: u64 = 4096;

/// One free run, `[base, end)`, page-aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub base: u64,
    pub end: u64,
}

impl Range {
    pub const EMPTY: Range = Range { base: 0, end: 0 };

    pub const fn len(&self) -> u64 {
        self.end - self.base
    }

    pub const fn is_empty(&self) -> bool {
        self.end <= self.base
    }
}

/// `x` rounded down to a multiple of `align` (a power of two).
const fn align_down(x: u64, align: u64) -> u64 {
    x & !(align - 1)
}

/// `x` rounded up to a multiple of `align` (a power of two), or `None` past
/// the top of the address space.
const fn align_up(x: u64, align: u64) -> Option<u64> {
    match x.checked_add(align - 1) {
        Some(v) => Some(v & !(align - 1)),
        None => None,
    }
}

/// The free ranges, at most `N` of them, sorted and never touching (two
/// adjacent ranges are always merged into one).
#[derive(Debug, Clone)]
pub struct Frames<const N: usize> {
    ranges: [Range; N],
    len: usize,
    dropped: u64,
    /// Set by the first reservation, allocation or free: from then on RAM
    /// can no longer be added, since a range added over memory already
    /// taken would make it free a second time.
    closed: bool,
}

impl<const N: usize> Default for Frames<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Frames<N> {
    /// No memory at all.
    pub const fn new() -> Self {
        Frames { ranges: [Range::EMPTY; N], len: 0, dropped: 0, closed: false }
    }

    /// The free ranges, lowest first.
    pub fn ranges(&self) -> &[Range] {
        &self.ranges[..self.len]
    }

    /// Bytes free.
    pub fn free_bytes(&self) -> u64 {
        self.ranges().iter().map(Range::len).sum()
    }

    /// Bytes lost to a full table (see the module docs). Zero on any machine
    /// whose memory map fits.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Adds RAM the firmware reported, shrunk inward to whole pages; merged
    /// with any range it touches. Overlap with what is already free is
    /// tolerated (a map with duplicate entries), never double-counted.
    ///
    /// The whole map is added first: once anything has been reserved,
    /// allocated or freed, `add` refuses (`false`), because it cannot know
    /// what of the new range is already in use.
    pub fn add(&mut self, base: u64, len: u64) -> bool {
        if self.closed {
            return false;
        }
        let end = base.saturating_add(len);
        let Some(lo) = align_up(base, PAGE) else { return true };
        let hi = align_down(end, PAGE);
        if hi > lo {
            self.insert(lo, hi);
        }
        true
    }

    /// Takes `[base, base + len)` out of the free ranges — the kernel's
    /// image, a module, the loader's tables — widened outward to whole pages.
    /// Always succeeds (see the module docs).
    pub fn reserve(&mut self, base: u64, len: u64) {
        self.closed = true;
        if len == 0 {
            return;
        }
        let lo = align_down(base, PAGE);
        let hi = match align_up(base.saturating_add(len), PAGE) {
            Some(h) => h,
            None => !(PAGE - 1),
        };
        self.remove(lo, hi);
    }

    /// `len` bytes, rounded up to whole pages, aligned to `align` (a power
    /// of two, at least a page), lying entirely below `ceiling`: the highest
    /// such run, or `None`. The run is no longer free.
    pub fn alloc(&mut self, len: u64, align: u64, ceiling: u64) -> Option<u64> {
        self.closed = true;
        if len == 0 || !align.is_power_of_two() {
            return None;
        }
        let align = align.max(PAGE);
        let len = align_up(len, PAGE)?;
        let ceiling = align_down(ceiling, PAGE);
        for i in (0..self.len).rev() {
            let r = self.ranges[i];
            let top = r.end.min(ceiling);
            if top <= r.base || top - r.base < len {
                continue;
            }
            let start = align_down(top - len, align);
            if start >= r.base {
                self.remove(start, start + len);
                return Some(start);
            }
        }
        None
    }

    /// Gives back a run [`Frames::alloc`] returned (or any page-aligned run
    /// that is not free). Refused — `false`, nothing changes — when it is
    /// not page-aligned or overlaps memory that is already free: a double
    /// free, or a wrong length.
    pub fn free(&mut self, base: u64, len: u64) -> bool {
        self.closed = true;
        if !base.is_multiple_of(PAGE) || len == 0 {
            return false;
        }
        let Some(len) = align_up(len, PAGE) else { return false };
        let Some(end) = base.checked_add(len) else { return false };
        if self.ranges().iter().any(|r| r.base < end && base < r.end) {
            return false;
        }
        self.insert(base, end);
        true
    }

    /// Inserts `[base, end)` (page-aligned, disjoint from every free range or
    /// overlapping only as `add` tolerates), merging with neighbours.
    fn insert(&mut self, base: u64, end: u64) {
        if end <= base {
            return;
        }
        let (mut base, mut end) = (base, end);
        // Swallow every range that overlaps or touches [base, end).
        let mut i = 0;
        while i < self.len {
            let r = self.ranges[i];
            if r.end >= base && r.base <= end {
                base = base.min(r.base);
                end = end.max(r.end);
                self.delete(i);
            } else {
                i += 1;
            }
        }
        let at = self.ranges[..self.len].iter().position(|r| r.base > base).unwrap_or(self.len);
        if self.len == N {
            // Full: keep the larger of the new range and the smallest one
            // held, and count the other as lost.
            let (small, small_len) = self
                .ranges()
                .iter()
                .enumerate()
                .map(|(i, r)| (i, r.len()))
                .min_by_key(|&(_, l)| l)
                .unwrap_or((0, 0));
            if N == 0 || small_len >= end - base {
                self.dropped += end - base;
                return;
            }
            self.dropped += small_len;
            self.delete(small);
            let at = self.ranges[..self.len].iter().position(|r| r.base > base).unwrap_or(self.len);
            self.place(at, Range { base, end });
            return;
        }
        self.place(at, Range { base, end });
    }

    /// Removes `[lo, hi)` from every range it overlaps.
    fn remove(&mut self, lo: u64, hi: u64) {
        let mut i = 0;
        while i < self.len {
            let r = self.ranges[i];
            if r.end <= lo || r.base >= hi {
                i += 1;
                continue;
            }
            let left = Range { base: r.base, end: lo.max(r.base) };
            let right = Range { base: hi.min(r.end), end: r.end };
            match (left.is_empty(), right.is_empty()) {
                (true, true) => {
                    self.delete(i);
                    continue;
                }
                (false, true) => self.ranges[i] = left,
                (true, false) => self.ranges[i] = right,
                (false, false) => {
                    if self.len == N {
                        // No slot for the split: keep the larger half.
                        if left.len() >= right.len() {
                            self.ranges[i] = left;
                            self.dropped += right.len();
                        } else {
                            self.ranges[i] = right;
                            self.dropped += left.len();
                        }
                    } else {
                        self.ranges[i] = left;
                        self.place(i + 1, right);
                        i += 1;
                    }
                }
            }
            i += 1;
        }
    }

    fn delete(&mut self, i: usize) {
        self.ranges.copy_within(i + 1..self.len, i);
        self.len -= 1;
        self.ranges[self.len] = Range::EMPTY;
    }

    fn place(&mut self, at: usize, r: Range) {
        debug_assert!(self.len < N);
        self.ranges.copy_within(at..self.len, at + 1);
        self.ranges[at] = r;
        self.len += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans<const N: usize>(f: &Frames<N>) -> Vec<(u64, u64)> {
        f.ranges().iter().map(|r| (r.base, r.end)).collect()
    }

    #[test]
    fn ram_is_trimmed_inward_and_reservations_widen_outward() {
        let mut f = Frames::<8>::new();
        f.add(0x1234, 0x10000); // [0x1234, 0x11234) -> [0x2000, 0x11000)
        assert_eq!(spans(&f), [(0x2000, 0x11000)]);
        f.reserve(0x5800, 0x10); // the page around it
        assert_eq!(spans(&f), [(0x2000, 0x5000), (0x6000, 0x11000)]);
        f.reserve(0, 0x3000);
        assert_eq!(spans(&f), [(0x3000, 0x5000), (0x6000, 0x11000)]);
        f.reserve(0x10fff, 0x10); // straddles the top
        assert_eq!(spans(&f), [(0x3000, 0x5000), (0x6000, 0x10000)]);
        assert_eq!(f.free_bytes(), 0x2000 + 0xa000);
        // RAM after a reservation is refused: it may cover memory in use.
        assert!(!f.add(0x20000, 0x10000));
        assert_eq!(f.ranges().len(), 2);
        // Less than a page of RAM is no RAM.
        let mut g = Frames::<8>::new();
        assert!(g.add(0x20010, 0xff0));
        assert!(g.ranges().is_empty());
    }

    #[test]
    fn duplicate_and_touching_ram_merges() {
        let mut f = Frames::<8>::new();
        f.add(0x10000, 0x4000);
        f.add(0x14000, 0x4000);
        f.add(0x12000, 0x8000);
        assert_eq!(spans(&f), [(0x10000, 0x1a000)]);
    }

    #[test]
    fn alloc_takes_the_highest_aligned_run_below_the_ceiling() {
        let mut f = Frames::<8>::new();
        f.add(0x100000, 0x100000); // 1 MiB .. 2 MiB
        f.add(0x4000_0000, 0x100000); // above a 1 GiB ceiling
        let a = f.alloc(0x3000, PAGE, 0x4000_0000).unwrap();
        assert_eq!(a, 0x1fd000);
        let b = f.alloc(0x1000, 0x10000, 0x4000_0000).unwrap();
        assert_eq!(b, 0x1f0000);
        assert_eq!(b % 0x10000, 0);
        // Rounded to pages.
        let c = f.alloc(1, PAGE, 0x4000_0000).unwrap();
        assert_eq!(c, 0x1fc000);
        // The memory above the ceiling is never used.
        assert!(f.ranges().iter().any(|r| r.base == 0x4000_0000));
        assert_eq!(f.alloc(0x200000, PAGE, 0x4000_0000), None);
        // Bad requests.
        assert_eq!(f.alloc(0, PAGE, u64::MAX), None);
        assert_eq!(f.alloc(PAGE, 3 * PAGE, u64::MAX), None);
        assert_eq!(f.alloc(u64::MAX, PAGE, u64::MAX), None);
    }

    #[test]
    fn free_merges_and_refuses_what_is_already_free() {
        let mut f = Frames::<8>::new();
        f.add(0, 0x10000);
        let a = f.alloc(0x2000, PAGE, u64::MAX).unwrap();
        let b = f.alloc(0x2000, PAGE, u64::MAX).unwrap();
        assert_eq!(spans(&f), [(0, 0xc000)]);
        assert!(f.free(a, 0x2000));
        assert!(!f.free(a, 0x2000), "a double free is refused");
        assert!(!f.free(b + 1, 0x1000), "unaligned");
        assert!(!f.free(b, 0x3000), "overlaps the free run above it");
        assert!(f.free(b, 0x2000));
        assert_eq!(spans(&f), [(0, 0x10000)]);
    }

    #[test]
    fn a_full_table_loses_memory_and_never_shares_it() {
        let mut f = Frames::<2>::new();
        f.add(0, 0x10000);
        f.add(0x20000, 0x10000);
        // A third range when full: the smaller of it and the smallest held
        // is dropped.
        let mut g = f.clone();
        g.add(0x40000, 0x1000);
        assert_eq!(spans(&g), [(0, 0x10000), (0x20000, 0x30000)]);
        assert_eq!(g.dropped(), 0x1000);
        g.add(0x40000, 0x40000);
        assert_eq!(spans(&g), [(0x20000, 0x30000), (0x40000, 0x80000)]);
        assert_eq!(g.dropped(), 0x1000 + 0x10000);
        // A split needs a third slot: the smaller half is dropped.
        f.reserve(0x3000, 0x1000);
        assert_eq!(spans(&f), [(0x4000, 0x10000), (0x20000, 0x30000)]);
        assert_eq!(f.dropped(), 0x3000);
        // An allocation that splits a range, with no slot: the smaller half
        // (below it) is dropped.
        let a = f.alloc(0x2000, PAGE, 0x8000).unwrap();
        assert_eq!(a, 0x6000);
        assert_eq!(spans(&f), [(0x8000, 0x10000), (0x20000, 0x30000)]);
        assert_eq!(f.dropped(), 0x5000);
        // Freed beside a free run: merged, no slot needed.
        assert!(f.free(a, 0x2000));
        assert_eq!(spans(&f), [(0x6000, 0x10000), (0x20000, 0x30000)]);
        // Freed with the table full and no neighbour: the smaller is dropped.
        assert!(f.free(0x14000, 0x1000));
        assert_eq!(spans(&f), [(0x6000, 0x10000), (0x20000, 0x30000)]);
        assert_eq!(f.dropped(), 0x6000);
        // And a table of none holds nothing.
        let mut z = Frames::<0>::new();
        z.add(0, 0x10000);
        assert_eq!(z.free_bytes(), 0);
        assert_eq!(z.alloc(PAGE, PAGE, u64::MAX), None);
    }

    /// Random operations against a page-by-page model: a page is never both
    /// handed out and free; with a large table the free set is exactly the
    /// model's; with a small one it is a subset of it.
    #[test]
    fn matches_a_page_model() {
        const PAGES: usize = 512;
        fn run<const N: usize>(seed: u64, exact: bool) {
            #[derive(Clone, Copy, PartialEq, Debug)]
            enum P {
                Absent,
                Free,
                Reserved,
                Taken,
            }
            let mut x = seed;
            let mut next = move || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            let mut f = Frames::<N>::new();
            let mut model = vec![P::Absent; PAGES];
            let mut taken: Vec<(u64, u64)> = Vec::new();
            // The map first, as the kernel adds it.
            for _ in 0..(1 + next() % 12) {
                let base = next() % (PAGES as u64 * PAGE);
                let len = next() % (96 * PAGE);
                assert!(f.add(base, len));
                let lo = base.div_ceil(PAGE) as usize;
                let hi = (((base + len) / PAGE) as usize).min(PAGES);
                for p in model.iter_mut().take(hi).skip(lo) {
                    *p = P::Free;
                }
            }
            let mut closed = false;
            for _ in 0..400 {
                let op = next() % 5;
                // Every operation but `add` closes the table, once it runs.
                if op == 1 || op == 2 || op == 3 || (op == 4 && !taken.is_empty()) {
                    closed = true;
                }
                match op {
                    0 => assert_eq!(f.add(next() % (PAGES as u64 * PAGE), 0), !closed),
                    1 => {
                        let base = next() % (PAGES as u64 * PAGE);
                        let len = 1 + next() % (16 * PAGE);
                        f.reserve(base, len);
                        let lo = (base / PAGE) as usize;
                        let hi = ((base + len).div_ceil(PAGE) as usize).min(PAGES);
                        for p in model.iter_mut().take(hi).skip(lo) {
                            if *p == P::Free {
                                *p = P::Reserved;
                            }
                        }
                    }
                    2 | 3 => {
                        let len = (1 + next() % 8) * PAGE;
                        let align = PAGE << (next() % 3);
                        let ceiling = next() % (PAGES as u64 * PAGE + PAGE);
                        if let Some(a) = f.alloc(len, align, ceiling) {
                            assert_eq!(a % align, 0);
                            assert!(a + len <= ceiling);
                            let (lo, hi) = ((a / PAGE) as usize, ((a + len) / PAGE) as usize);
                            for (p, page) in model.iter_mut().enumerate().take(hi).skip(lo) {
                                assert_eq!(*page, P::Free, "page {p} handed out but not free");
                                *page = P::Taken;
                            }
                            taken.push((a, len));
                        }
                    }
                    _ => {
                        if !taken.is_empty() {
                            let (a, len) = taken.swap_remove((next() % taken.len() as u64) as usize);
                            assert!(f.free(a, len));
                            let (lo, hi) = ((a / PAGE) as usize, ((a + len) / PAGE) as usize);
                            for page in model.iter_mut().take(hi).skip(lo) {
                                *page = P::Free;
                            }
                        }
                    }
                }
                // The table's invariants.
                let r = f.ranges();
                for w in r.windows(2) {
                    assert!(w[0].end < w[1].base, "sorted, never touching: {r:?}");
                }
                for range in r {
                    assert!(range.base % PAGE == 0 && range.end % PAGE == 0 && range.base < range.end);
                }
                // Free per the table, page by page, against the model.
                let mut free = vec![false; PAGES];
                for range in r {
                    let (lo, hi) = ((range.base / PAGE) as usize, ((range.end / PAGE) as usize).min(PAGES));
                    for page in free.iter_mut().take(hi).skip(lo) {
                        *page = true;
                    }
                }
                for p in 0..PAGES {
                    if free[p] {
                        assert_eq!(model[p], P::Free, "page {p} free in the table, {:?} in the model", model[p]);
                    } else if exact {
                        assert_ne!(model[p], P::Free, "page {p} lost with room in the table");
                    }
                }
            }
        }
        for seed in 1..60u64 {
            run::<256>(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1, true);
            run::<3>(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1, false);
        }
    }
}
