// SPDX-License-Identifier: Apache-2.0
//! Building strings with no allocator.
//!
//! Every label the interface draws is composed from numbers that are only
//! known at run time, and `format!` needs a heap. What there is instead is a
//! fixed buffer with a length: enough to render a duration, a byte count or a
//! frequency, and nothing that can grow without bound.
//!
//! Writes past the end are dropped rather than panicking. A truncated label is
//! a cosmetic fault; a panic in a kernel with no operating system under it
//! stops the machine, and no readout is worth that.

/// A stack-allocated string of at most `N` bytes.
pub struct Text<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Text<N> {
        Text::new()
    }
}

impl<const N: usize> Text<N> {
    pub const fn new() -> Text<N> {
        Text {
            buf: [0; N],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// How many bytes have been written.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether another `bytes` would fit without being silently dropped.
    ///
    /// [`push`](Self::push) discards past the end rather than panicking,
    /// which is right for a kernel and wrong to rely on: a caller building a
    /// list wants to stop at a whole entry, not half of one.
    pub fn has_room_for(&self, bytes: usize) -> bool {
        self.len + bytes <= N
    }

    pub fn push(&mut self, byte: u8) -> &mut Self {
        if self.len < N {
            self.buf[self.len] = byte;
            self.len += 1;
        }
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        for byte in s.bytes() {
            self.push(byte);
        }
        self
    }

    /// Appends a decimal number.
    pub fn num(&mut self, value: u64) -> &mut Self {
        self.pad(value, 1)
    }

    /// Appends a decimal number, zero-padded to at least `width` digits.
    ///
    /// Built backwards into a scratch array and reversed, because division
    /// yields the least significant digit first. Twenty digits covers `u64`.
    pub fn pad(&mut self, mut value: u64, width: usize) -> &mut Self {
        let mut scratch = [0u8; 20];
        let mut digits = 0;
        loop {
            scratch[digits] = b'0' + (value % 10) as u8;
            value /= 10;
            digits += 1;
            if value == 0 || digits == scratch.len() {
                break;
            }
        }
        for _ in digits..width {
            self.push(b'0');
        }
        for i in (0..digits).rev() {
            self.push(scratch[i]);
        }
        self
    }

    /// Appends a number with `decimals` digits after a point, given a value
    /// already scaled by `10^decimals`.
    ///
    /// Fixed point rather than floating: the freestanding build has no `libm`,
    /// and a ratio worked out in integers cannot be a shade wrong in the last
    /// place the way a float formatted by hand can.
    pub fn fixed(&mut self, scaled: u64, decimals: usize) -> &mut Self {
        let divisor = 10u64.pow(decimals as u32);
        self.num(scaled / divisor);
        if decimals > 0 {
            self.push(b'.');
            self.pad(scaled % divisor, decimals);
        }
        self
    }

    pub fn as_str(&self) -> &str {
        // Mostly ASCII by construction; where a multi-byte character was cut
        // by the end of the buffer, the valid prefix is what is shown.
        match core::str::from_utf8(&self.buf[..self.len]) {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&self.buf[..e.valid_up_to()]).unwrap_or(""),
        }
    }

    /// Removes the last character, whole (a multi-byte one too).
    pub fn pop(&mut self) -> Option<char> {
        let c = self.as_str().chars().next_back()?;
        self.len -= c.len_utf8();
        Some(c)
    }

    /// Appends a character, whole or not at all.
    pub fn char(&mut self, c: char) -> &mut Self {
        let mut utf8 = [0u8; 4];
        let s = c.encode_utf8(&mut utf8);
        if self.has_room_for(s.len()) {
            self.str(s);
        }
        self
    }
}

impl<const N: usize> core::fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.str(s);
        Ok(())
    }
}

impl<const N: usize> Clone for Text<N> {
    fn clone(&self) -> Text<N> {
        Text { buf: self.buf, len: self.len }
    }
}

impl<const N: usize> Copy for Text<N> {}

impl<const N: usize> core::fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

/// A duration as `hh:mm:ss:mmm:uuu:sss`.
///
/// Colons all the way down, rather than a decimal point and nine run-together
/// digits. `00:00:00.000000000` makes the reader count places to find the
/// microseconds; `00:00:00:000:000:000` groups them the way the units already
/// group, and the milliseconds, microseconds and nanoseconds each get a field
/// of their own — which is the whole point of a chronometer that resolves
/// them.
pub fn duration(ns: u64, nanoseconds: bool) -> Text<24> {
    let mut out = Text::new();
    let seconds = ns / 1_000_000_000;
    let fraction = ns % 1_000_000_000;

    out.pad(seconds / 3600, 2)
        .push(b':')
        .pad(seconds / 60 % 60, 2)
        .push(b':')
        .pad(seconds % 60, 2)
        .push(b':')
        .pad(fraction / 1_000_000, 3);

    if nanoseconds {
        out.push(b':')
            .pad(fraction / 1_000 % 1_000, 3)
            .push(b':')
            .pad(fraction % 1_000, 3);
    }
    out
}

/// A byte count as a human-sized figure: `2.9 MB`, `31.7 GB`.
///
/// Powers of 1024 with the short unit names, which is what a person reading a
/// status bar expects to see and what every desktop shows them. The
/// alternative — `0.3 GB` for a kernel using three megabytes of a
/// thirty-two-gigabyte machine — is arithmetically fine and tells the reader
/// nothing, which is the failure this exists to avoid.
pub fn bytes(value: u64) -> Text<16> {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut out = Text::new();

    let mut unit = 0;
    let mut scaled = value;
    while scaled >= 1024 && unit + 1 < UNITS.len() {
        scaled /= 1024;
        unit += 1;
    }

    if unit == 0 {
        out.num(value).str(" B");
        return out;
    }

    // One decimal below a hundred, none above: `2.9 MB` is worth the digit and
    // `317.4 GB` is not. Recomputed from the original value rather than from
    // the truncated one, so the tenth is the real tenth.
    let divisor = 1024u64.pow(unit as u32);
    let tenths = value * 10 / divisor;
    if tenths < 1000 {
        out.fixed(tenths, 1);
    } else {
        out.num(tenths / 10);
    }
    out.push(b' ').str(UNITS[unit]);
    out
}

/// A frequency in hertz as `2.418 GHz`, or megahertz below a gigahertz.
pub fn frequency(hz: u64) -> Text<16> {
    let mut out = Text::new();
    if hz >= 1_000_000_000 {
        out.fixed(hz / 1_000_000, 3).str(" GHz");
    } else if hz >= 1_000_000 {
        out.fixed(hz / 1_000, 3).str(" MHz");
    } else {
        out.num(hz).str(" Hz");
    }
    out
}
