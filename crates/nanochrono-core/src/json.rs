// SPDX-License-Identifier: Apache-2.0
//! Strict JSON (RFC 8259), for the package manifest (`ncpkg.meta`) and the
//! package database (`/var/lib/ncpkg/db.json`).
//!
//! # Why another JSON reader
//!
//! The manifest arrives inside a package off a USB stick or a mirror:
//! untrusted input, read by a kernel that has no allocator. So the reader is
//! `no_std`, allocates nothing and keeps no token table: [`parse`] validates
//! the whole text once — grammar, UTF-8, nesting depth, string lengths,
//! escapes and surrogate pairs — and hands back a [`Value`], a span of the
//! text. Navigating ([`Value::get`], [`Value::members`],
//! [`Value::elements`]) re-scans the validated text rather than indexing a
//! tree, which costs a pass over an object per lookup and no memory at all.
//! Every read is a checked `get`, so even a span over text that never went
//! through [`parse`] cannot panic or read out of bounds: it just yields less.
//!
//! # Strict
//!
//! Exactly RFC 8259 and nothing more: no comments, no trailing commas, no
//! single quotes, no `NaN`, no byte-order mark, no unpaired surrogate escape.
//! Duplicate keys are a *schema* error, refused by the layers above (the
//! manifest's objects have fixed keys, checked with a bitmask; the
//! database's maps go through a `BTreeMap`) — never "last one wins", which
//! is how two parsers come to disagree about what a signed document says.
//!
//! # Writing
//!
//! With the `alloc` feature, [`Json`] is an owned value and [`Json::write`]
//! its writer: compact or indented, keys in insertion order or sorted. The
//! sorted compact form is canonical — the packer emits the signed part of a
//! manifest that way, so a package built twice from the same sources is the
//! same bytes.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Limits on a document. Every loop in the parser is bounded by the text's
/// length; these bound what the text may claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The whole text, in bytes.
    pub max_len: usize,
    /// Nesting of objects and arrays. At most 64.
    pub max_depth: usize,
    /// One string's raw length (between its quotes), in bytes.
    pub max_string: usize,
}

impl Limits {
    /// A package manifest: 2 MiB, signatures up to 96 KiB of base64 (an
    /// SLH-DSA-256f signature is 49 856 bytes, 66 476 characters).
    pub const MANIFEST: Limits = Limits { max_len: 2 << 20, max_depth: 16, max_string: 96 * 1024 };
    /// The package database: 64 MiB, ordinary strings.
    pub const DATABASE: Limits = Limits { max_len: 64 << 20, max_depth: 16, max_string: 4096 };
}

/// What went wrong, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// No value at all.
    Empty,
    TooLong,
    TooDeep,
    /// The text is not UTF-8.
    BadUtf8,
    /// A character that cannot appear here.
    Syntax,
    /// An unterminated string, or a raw control character in one.
    BadString,
    /// An unknown escape, bad `\u` digits or an unpaired surrogate.
    BadEscape,
    BadNumber,
    StringTooLong,
    /// Something after the top-level value.
    Trailing,
}

/// A parse error: its kind and the byte offset it was found at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub at: usize,
}

impl Error {
    const fn new(kind: ErrorKind, at: usize) -> Error {
        Error { kind, at }
    }

    pub const fn message(&self) -> &'static str {
        match self.kind {
            ErrorKind::Empty => "no JSON value",
            ErrorKind::TooLong => "document longer than allowed",
            ErrorKind::TooDeep => "objects and arrays nested too deep",
            ErrorKind::BadUtf8 => "not UTF-8",
            ErrorKind::Syntax => "unexpected character",
            ErrorKind::BadString => "unterminated string or control character in a string",
            ErrorKind::BadEscape => "bad escape sequence",
            ErrorKind::BadNumber => "malformed number",
            ErrorKind::StringTooLong => "string longer than allowed",
            ErrorKind::Trailing => "data after the JSON value",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.message(), self.at)
    }
}

/// Validates `text` against RFC 8259 and `limits`, and returns its
/// top-level value.
pub fn parse<'a>(text: &'a [u8], limits: &Limits) -> Result<Value<'a>, Error> {
    if text.len() > limits.max_len {
        return Err(Error::new(ErrorKind::TooLong, limits.max_len));
    }
    if let Err(e) = core::str::from_utf8(text) {
        return Err(Error::new(ErrorKind::BadUtf8, e.valid_up_to()));
    }
    let mut p = Parser { t: text, i: 0, max_string: limits.max_string };
    p.ws();
    let start = p.i;
    if start >= text.len() {
        return Err(Error::new(ErrorKind::Empty, start));
    }
    p.document(limits.max_depth.min(64))?;
    let end = p.i;
    p.ws();
    if p.i != text.len() {
        return Err(Error::new(ErrorKind::Trailing, p.i));
    }
    Ok(Value { t: text, s: start, e: end })
}

struct Parser<'a> {
    t: &'a [u8],
    i: usize,
    max_string: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// A value is next.
    Value,
    /// Just after `[`: a value or `]`.
    ArrayFirst,
    /// Just after `{`: a key or `}`.
    ObjectFirst,
    /// After a comma in an object: a key.
    Key,
    /// After a key: `:`.
    Colon,
    /// After a value inside a container: `,` or the closing bracket.
    Next,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.t.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.i += 1;
        }
    }

    /// One complete value, iteratively: the container stack is a bit per
    /// level (1 = object), so depth costs no recursion and no memory.
    fn document(&mut self, max_depth: usize) -> Result<(), Error> {
        let mut stack: u64 = 0;
        let mut depth = 0usize;
        let mut state = State::Value;
        loop {
            self.ws();
            let at = self.i;
            let Some(c) = self.peek() else {
                return Err(Error::new(ErrorKind::Syntax, at));
            };
            match state {
                State::Value | State::ArrayFirst => {
                    if state == State::ArrayFirst && c == b']' {
                        self.i += 1;
                        depth -= 1;
                        stack >>= 1;
                    } else {
                        match c {
                            b'{' | b'[' => {
                                if depth >= max_depth {
                                    return Err(Error::new(ErrorKind::TooDeep, at));
                                }
                                stack = (stack << 1) | u64::from(c == b'{');
                                depth += 1;
                                self.i += 1;
                                state = if c == b'{' { State::ObjectFirst } else { State::ArrayFirst };
                                continue;
                            }
                            b'"' => self.string()?,
                            b'-' | b'0'..=b'9' => self.number()?,
                            b't' => self.literal(b"true")?,
                            b'f' => self.literal(b"false")?,
                            b'n' => self.literal(b"null")?,
                            _ => return Err(Error::new(ErrorKind::Syntax, at)),
                        }
                    }
                }
                State::ObjectFirst | State::Key => {
                    if state == State::ObjectFirst && c == b'}' {
                        self.i += 1;
                        depth -= 1;
                        stack >>= 1;
                    } else if c == b'"' {
                        self.string()?;
                        state = State::Colon;
                        continue;
                    } else {
                        return Err(Error::new(ErrorKind::Syntax, at));
                    }
                }
                State::Colon => {
                    if c != b':' {
                        return Err(Error::new(ErrorKind::Syntax, at));
                    }
                    self.i += 1;
                    state = State::Value;
                    continue;
                }
                State::Next => {
                    let in_object = stack & 1 == 1;
                    match (c, in_object) {
                        (b',', true) => {
                            self.i += 1;
                            state = State::Key;
                            continue;
                        }
                        (b',', false) => {
                            self.i += 1;
                            state = State::Value;
                            continue;
                        }
                        (b'}', true) | (b']', false) => {
                            self.i += 1;
                            depth -= 1;
                            stack >>= 1;
                        }
                        _ => return Err(Error::new(ErrorKind::Syntax, at)),
                    }
                }
            }
            // A value (scalar or closed container) just ended.
            if depth == 0 {
                return Ok(());
            }
            state = State::Next;
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), Error> {
        let end = self.i + word.len();
        if self.t.get(self.i..end) != Some(word) {
            return Err(Error::new(ErrorKind::Syntax, self.i));
        }
        self.i = end;
        Ok(())
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while let Some(b'0'..=b'9') = self.peek() {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<(), Error> {
        let start = self.i;
        let bad = Error::new(ErrorKind::BadNumber, start);
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(bad),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(bad);
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.i += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(bad);
            }
        }
        // A number is a token, not a payload: 64 characters is far past any
        // value the schemas use.
        if self.i - start > 64 {
            return Err(bad);
        }
        Ok(())
    }

    fn hex4(&self, at: usize) -> Result<u32, Error> {
        let digits = self.t.get(at..at + 4).ok_or(Error::new(ErrorKind::BadEscape, at))?;
        let mut v = 0u32;
        for &d in digits {
            let n = match d {
                b'0'..=b'9' => d - b'0',
                b'a'..=b'f' => d - b'a' + 10,
                b'A'..=b'F' => d - b'A' + 10,
                _ => return Err(Error::new(ErrorKind::BadEscape, at)),
            };
            v = (v << 4) | u32::from(n);
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<(), Error> {
        let start = self.i;
        self.i += 1;
        loop {
            if self.i - start - 1 > self.max_string {
                return Err(Error::new(ErrorKind::StringTooLong, start));
            }
            let Some(c) = self.peek() else {
                return Err(Error::new(ErrorKind::BadString, start));
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(());
                }
                b'\\' => {
                    let at = self.i;
                    match self.t.get(at + 1) {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 2,
                        Some(b'u') => {
                            let cp = self.hex4(at + 2)?;
                            self.i += 6;
                            if (0xD800..0xDC00).contains(&cp) {
                                // A high surrogate must be followed at once
                                // by an escaped low one.
                                if self.t.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(Error::new(ErrorKind::BadEscape, at));
                                }
                                let lo = self.hex4(self.i + 2)?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(Error::new(ErrorKind::BadEscape, at));
                                }
                                self.i += 6;
                            } else if (0xDC00..0xE000).contains(&cp) {
                                return Err(Error::new(ErrorKind::BadEscape, at));
                            }
                        }
                        _ => return Err(Error::new(ErrorKind::BadEscape, at)),
                    }
                }
                0x00..=0x1F => return Err(Error::new(ErrorKind::BadString, self.i)),
                // UTF-8 was checked up front, and no byte of a multi-byte
                // sequence is a quote, a backslash or a control character.
                _ => self.i += 1,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/// What a value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Object,
    Array,
    String,
    Number,
    Bool,
    Null,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Object => "object",
            Kind::Array => "array",
            Kind::String => "string",
            Kind::Number => "number",
            Kind::Bool => "boolean",
            Kind::Null => "null",
        }
    }
}

/// A value inside a validated document: a span of its text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Value<'a> {
    t: &'a [u8],
    s: usize,
    e: usize,
}

impl core::fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Value({:?} @ {}..{})", self.kind(), self.s, self.e)
    }
}

/// The end of the string starting at `i` (one past its closing quote).
fn skip_string(t: &[u8], mut i: usize) -> usize {
    i += 1;
    while let Some(&c) = t.get(i) {
        match c {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    t.len()
}

/// The end of the value starting at `i`. Exact on validated text; on any
/// other text it stops somewhere at or before the end, never past it.
fn skip_value(t: &[u8], mut i: usize) -> usize {
    match t.get(i) {
        Some(b'"') => skip_string(t, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            while let Some(&c) = t.get(i) {
                match c {
                    b'"' => {
                        i = skip_string(t, i);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            t.len()
        }
        Some(_) => {
            while let Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' | b'a'..=b'z') = t.get(i) {
                i += 1;
            }
            i
        }
        None => t.len(),
    }
}

fn skip_ws(t: &[u8], mut i: usize) -> usize {
    while let Some(b' ' | b'\t' | b'\n' | b'\r') = t.get(i) {
        i += 1;
    }
    i
}

impl<'a> Value<'a> {
    pub fn kind(&self) -> Kind {
        match self.t.get(self.s) {
            Some(b'{') => Kind::Object,
            Some(b'[') => Kind::Array,
            Some(b'"') => Kind::String,
            Some(b't' | b'f') => Kind::Bool,
            Some(b'n') => Kind::Null,
            _ => Kind::Number,
        }
    }

    /// The value's exact bytes in the document.
    pub fn raw(&self) -> &'a [u8] {
        self.t.get(self.s..self.e).unwrap_or(&[])
    }

    /// Where the value sits in the document, as a byte range.
    pub fn span(&self) -> core::ops::Range<usize> {
        self.s..self.e
    }

    pub fn as_str(&self) -> Option<Str<'a>> {
        if self.kind() != Kind::String || self.e < self.s + 2 {
            return None;
        }
        Some(Str { raw: self.t.get(self.s + 1..self.e - 1)? })
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self.raw() {
            b"true" => Some(true),
            b"false" => Some(false),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        self.raw() == b"null"
    }

    /// A non-negative integer written without a fraction or an exponent.
    pub fn as_u64(&self) -> Option<u64> {
        let raw = self.raw();
        if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut v = 0u64;
        for &d in raw {
            v = v.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
        }
        Some(v)
    }

    /// An integer, possibly negative, without a fraction or an exponent.
    pub fn as_i64(&self) -> Option<i64> {
        let raw = self.raw();
        let (neg, digits) = match raw.split_first() {
            Some((b'-', rest)) => (true, rest),
            _ => (false, raw),
        };
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut v = 0i64;
        for &d in digits {
            let d = i64::from(d - b'0');
            v = v.checked_mul(10)?;
            v = if neg { v.checked_sub(d)? } else { v.checked_add(d)? };
        }
        Some(v)
    }

    /// An object's members in document order; empty for anything else.
    pub fn members(&self) -> Members<'a> {
        Members { t: self.t, i: self.s + 1, end: self.e, done: self.kind() != Kind::Object }
    }

    /// An array's elements in document order; empty for anything else.
    pub fn elements(&self) -> Elements<'a> {
        Elements { t: self.t, i: self.s + 1, end: self.e, done: self.kind() != Kind::Array }
    }

    /// The first member named `key` (the schemas refuse duplicates).
    pub fn get(&self, key: &str) -> Option<Value<'a>> {
        self.members().find(|(k, _)| k.eq_str(key)).map(|(_, v)| v)
    }

    /// Members of an object, or elements of an array; zero otherwise.
    pub fn len(&self) -> usize {
        match self.kind() {
            Kind::Object => self.members().count(),
            Kind::Array => self.elements().count(),
            _ => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The value as an owned [`Json`]; `None` if it holds a number that is
    /// not an `i64` (a fraction, an exponent, or out of range).
    #[cfg(feature = "alloc")]
    pub fn to_json(&self) -> Option<Json> {
        Some(match self.kind() {
            Kind::Null => Json::Null,
            Kind::Bool => Json::Bool(self.as_bool()?),
            Kind::Number => Json::Int(self.as_i64()?),
            Kind::String => Json::Str(self.as_str()?.to_string()),
            Kind::Array => Json::Arr(self.elements().map(|v| v.to_json()).collect::<Option<Vec<_>>>()?),
            Kind::Object => Json::Obj(
                self.members().map(|(k, v)| Some((k.to_string(), v.to_json()?))).collect::<Option<Vec<_>>>()?,
            ),
        })
    }
}

/// An object's members: `(key, value)` pairs.
#[derive(Debug, Clone)]
pub struct Members<'a> {
    t: &'a [u8],
    i: usize,
    end: usize,
    done: bool,
}

impl<'a> Iterator for Members<'a> {
    type Item = (Str<'a>, Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let t = self.t;
        let mut i = skip_ws(t, self.i);
        if t.get(i) == Some(&b',') {
            i = skip_ws(t, i + 1);
        }
        if t.get(i) != Some(&b'"') {
            self.done = true;
            return None;
        }
        let key_end = skip_string(t, i);
        let key = Str { raw: t.get(i + 1..key_end.saturating_sub(1).max(i + 1)).unwrap_or(&[]) };
        let colon = skip_ws(t, key_end);
        if t.get(colon) != Some(&b':') {
            self.done = true;
            return None;
        }
        let vs = skip_ws(t, colon + 1);
        let ve = skip_value(t, vs);
        if ve > self.end || ve <= vs {
            self.done = true;
            return None;
        }
        self.i = ve;
        Some((key, Value { t, s: vs, e: ve }))
    }
}

/// An array's elements.
#[derive(Debug, Clone)]
pub struct Elements<'a> {
    t: &'a [u8],
    i: usize,
    end: usize,
    done: bool,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let t = self.t;
        let mut i = skip_ws(t, self.i);
        if t.get(i) == Some(&b',') {
            i = skip_ws(t, i + 1);
        }
        match t.get(i) {
            None | Some(b']') => {
                self.done = true;
                return None;
            }
            _ => {}
        }
        let e = skip_value(t, i);
        if e > self.end || e <= i {
            self.done = true;
            return None;
        }
        self.i = e;
        Some(Value { t, s: i, e })
    }
}

/// A JSON string as it stands in the text, escapes not yet decoded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Str<'a> {
    raw: &'a [u8],
}

impl core::fmt::Debug for Str<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("\"")?;
        for c in self.chars() {
            write!(f, "{}", c.escape_debug())?;
        }
        f.write_str("\"")
    }
}

impl core::fmt::Display for Str<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(s) = self.as_plain() {
            // `pad`, so `{:<20}` lines a column up.
            return f.pad(s);
        }
        for c in self.chars() {
            core::fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

impl<'a> Str<'a> {
    /// The bytes between the quotes, escapes included.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// No escapes: the raw bytes are the string.
    pub fn is_plain(&self) -> bool {
        !self.raw.contains(&b'\\')
    }

    /// The string itself, when it holds no escapes.
    pub fn as_plain(&self) -> Option<&'a str> {
        if self.is_plain() {
            core::str::from_utf8(self.raw).ok()
        } else {
            None
        }
    }

    /// The decoded characters.
    pub fn chars(&self) -> Chars<'a> {
        Chars { inner: core::str::from_utf8(self.raw).unwrap_or("").chars() }
    }

    /// Whether the decoded string equals `s`.
    pub fn eq_str(&self, s: &str) -> bool {
        if self.is_plain() {
            self.raw == s.as_bytes()
        } else {
            self.chars().eq(s.chars())
        }
    }

    /// The decoded length in UTF-8 bytes.
    pub fn decoded_len(&self) -> usize {
        if self.is_plain() {
            self.raw.len()
        } else {
            self.chars().map(char::len_utf8).sum()
        }
    }

    /// The number of characters once decoded.
    pub fn char_count(&self) -> usize {
        self.chars().count()
    }

    /// Decodes into `buf`; `None` if it does not fit.
    pub fn decode_into<'b>(&self, buf: &'b mut [u8]) -> Option<&'b str> {
        let mut n = 0;
        for c in self.chars() {
            let len = c.len_utf8();
            let slot = buf.get_mut(n..n + len)?;
            c.encode_utf8(slot);
            n += len;
        }
        core::str::from_utf8(buf.get(..n)?).ok()
    }

    #[cfg(feature = "alloc")]
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        match self.as_plain() {
            Some(s) => String::from(s),
            None => self.chars().collect(),
        }
    }
}

/// The characters of a [`Str`], escapes decoded.
#[derive(Debug, Clone)]
pub struct Chars<'a> {
    inner: core::str::Chars<'a>,
}

impl Chars<'_> {
    fn hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 4) | self.inner.next()?.to_digit(16)?;
        }
        Some(v)
    }
}

impl Iterator for Chars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        let c = self.inner.next()?;
        if c != '\\' {
            return Some(c);
        }
        Some(match self.inner.next()? {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let hi = self.hex4().unwrap_or(0xFFFD);
                if (0xD800..0xDC00).contains(&hi) {
                    let mut rest = self.inner.clone();
                    let paired = rest.next() == Some('\\') && rest.next() == Some('u');
                    if paired {
                        self.inner = rest;
                        let lo = self.hex4().unwrap_or(0);
                        if (0xDC00..0xE000).contains(&lo) {
                            char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)).unwrap_or('\u{FFFD}')
                        } else {
                            '\u{FFFD}'
                        }
                    } else {
                        '\u{FFFD}'
                    }
                } else {
                    char::from_u32(hi).unwrap_or('\u{FFFD}')
                }
            }
            _ => '\u{FFFD}',
        })
    }
}

// ---------------------------------------------------------------------------
// Owned values and the writer
// ---------------------------------------------------------------------------

/// An owned JSON value, for building documents. Numbers are integers: no
/// schema here has a fraction, and integers print the same everywhere.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    /// Members in insertion order; [`Style::sort_keys`] sorts on output.
    Obj(Vec<(String, Json)>),
}

/// How [`Json::write`] lays a document out.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Members sorted by key (byte order) rather than in insertion order.
    pub sort_keys: bool,
    /// Two-space indentation and a newline after each member; compact
    /// otherwise.
    pub pretty: bool,
}

#[cfg(feature = "alloc")]
impl Style {
    /// Sorted and compact: one spelling per document.
    pub const CANONICAL: Style = Style { sort_keys: true, pretty: false };
    /// Insertion order, indented: for files people read.
    pub const PRETTY: Style = Style { sort_keys: false, pretty: true };
}

#[cfg(feature = "alloc")]
impl Json {
    /// An object from `(key, value)` pairs.
    pub fn obj<const N: usize>(members: [(&str, Json); N]) -> Json {
        Json::Obj(members.into_iter().map(|(k, v)| (String::from(k), v)).collect())
    }

    pub fn str(s: &str) -> Json {
        Json::Str(String::from(s))
    }

    /// An unsigned quantity (a size, a count): saturates at `i64::MAX`,
    /// which no size here comes near.
    pub fn uint(v: u64) -> Json {
        Json::Int(i64::try_from(v).unwrap_or(i64::MAX))
    }

    /// Appends `(key, value)` to an object; does nothing to anything else.
    pub fn push(&mut self, key: &str, value: Json) {
        if let Json::Obj(members) = self {
            members.push((String::from(key), value));
        }
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        match self {
            Json::Obj(members) => members.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The document as text in `style`.
    pub fn write(&self, style: Style) -> String {
        let mut out = String::new();
        self.write_into(&mut out, style, 0);
        if style.pretty {
            out.push('\n');
        }
        out
    }

    fn write_into(&self, out: &mut String, style: Style, indent: usize) {
        let newline = |out: &mut String, indent: usize| {
            if style.pretty {
                out.push('\n');
                for _ in 0..indent {
                    out.push_str("  ");
                }
            }
        };
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(v) => {
                use core::fmt::Write;
                let _ = write!(out, "{v}");
            }
            Json::Str(s) => write_string(out, s),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, indent + 1);
                    item.write_into(out, style, indent + 1);
                }
                if !items.is_empty() {
                    newline(out, indent);
                }
                out.push(']');
            }
            Json::Obj(members) => {
                let mut order: Vec<&(String, Json)> = members.iter().collect();
                if style.sort_keys {
                    order.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                }
                out.push('{');
                for (i, (k, v)) in order.iter().map(|m| (&m.0, &m.1)).enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, indent + 1);
                    write_string(out, k);
                    out.push(':');
                    if style.pretty {
                        out.push(' ');
                    }
                    v.write_into(out, style, indent + 1);
                }
                if !members.is_empty() {
                    newline(out, indent);
                }
                out.push('}');
            }
        }
    }
}

/// A string in JSON's spelling: quotes, backslashes and control characters
/// escaped, everything else as UTF-8.
#[cfg(feature = "alloc")]
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;
    use std::vec::Vec;

    const L: Limits = Limits { max_len: 1 << 16, max_depth: 8, max_string: 256 };

    fn ok(s: &str) -> Value<'_> {
        parse(s.as_bytes(), &L).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn err(s: &[u8]) -> ErrorKind {
        parse(s, &L).err().unwrap_or_else(|| panic!("{:?} parsed", std::string::String::from_utf8_lossy(s))).kind
    }

    #[test]
    fn accepts_rfc_8259() {
        for s in [
            "0", "-0", "1", "-12", "1.5", "1e9", "1E-2", "2.5e+3", "true", "false", "null", "\"\"", "\"a\\\"b\"",
            "\"\\u00e9\\ud83d\\ude00\"", "[]", "{}", "[1,[2,[3]]]", "{\"a\":{\"b\":[]}}", " \t\r\n{ \"k\" : [ 1 , 2 ] } \n",
            "\"\u{e9}\u{1F600}\"", "\"\\/\\b\\f\\n\\r\\t\"",
        ] {
            ok(s);
        }
    }

    #[test]
    fn refuses_everything_else() {
        let cases: &[(&[u8], ErrorKind)] = &[
            (b"", ErrorKind::Empty),
            (b"   ", ErrorKind::Empty),
            (b"01", ErrorKind::Trailing),
            (b"1.", ErrorKind::BadNumber),
            (b".5", ErrorKind::Syntax),
            (b"-", ErrorKind::BadNumber),
            (b"1e", ErrorKind::BadNumber),
            (b"+1", ErrorKind::Syntax),
            (b"NaN", ErrorKind::Syntax),
            (b"tru", ErrorKind::Syntax),
            (b"[1,]", ErrorKind::Syntax),
            (b"{\"a\":1,}", ErrorKind::Syntax),
            (b"{'a':1}", ErrorKind::Syntax),
            (b"{\"a\" 1}", ErrorKind::Syntax),
            (b"{1:1}", ErrorKind::Syntax),
            (b"[1 2]", ErrorKind::Syntax),
            (b"[", ErrorKind::Syntax),
            (b"]", ErrorKind::Syntax),
            (b"{\"a\":1}}", ErrorKind::Trailing),
            (b"{} {}", ErrorKind::Trailing),
            (b"\"abc", ErrorKind::BadString),
            (b"\"a\nb\"", ErrorKind::BadString),
            (b"\"\\x\"", ErrorKind::BadEscape),
            (b"\"\\u12\"", ErrorKind::BadEscape),
            (b"\"\\ud800\"", ErrorKind::BadEscape),
            (b"\"\\udc00\"", ErrorKind::BadEscape),
            (b"\"\\ud800\\u0041\"", ErrorKind::BadEscape),
            (b"\xef\xbb\xbf{}", ErrorKind::Syntax),
            (b"\"\xff\"", ErrorKind::BadUtf8),
            (b"// c\n{}", ErrorKind::Syntax),
            (b"[[[[[[[[[1]]]]]]]]]", ErrorKind::TooDeep),
        ];
        for (text, kind) in cases {
            assert_eq!(err(text), *kind, "{:?}", std::string::String::from_utf8_lossy(text));
        }
        let long = std::format!("\"{}\"", "x".repeat(257));
        assert_eq!(err(long.as_bytes()), ErrorKind::StringTooLong);
        let ok_len = std::format!("\"{}\"", "x".repeat(256));
        ok(&ok_len);
        let huge = std::vec![b' '; (1 << 16) + 1];
        assert_eq!(err(&huge), ErrorKind::TooLong);
    }

    #[test]
    fn navigates_without_a_tree() {
        let v = ok(r#"{"name":"Snake","n":42,"neg":-7,"ok":true,"none":null,"list":[1,"two",{"three":3}],"nested":{"a":{"b":"c"}}}"#);
        assert_eq!(v.kind(), Kind::Object);
        assert_eq!(v.len(), 7);
        assert!(v.get("name").unwrap().as_str().unwrap().eq_str("Snake"));
        assert_eq!(v.get("n").unwrap().as_u64(), Some(42));
        assert_eq!(v.get("neg").unwrap().as_u64(), None);
        assert_eq!(v.get("neg").unwrap().as_i64(), Some(-7));
        assert_eq!(v.get("ok").unwrap().as_bool(), Some(true));
        assert!(v.get("none").unwrap().is_null());
        assert!(v.get("missing").is_none());
        let list: Vec<Value<'_>> = v.get("list").unwrap().elements().collect();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].as_u64(), Some(1));
        assert_eq!(list[1].as_str().unwrap().as_plain(), Some("two"));
        assert_eq!(list[2].get("three").unwrap().as_u64(), Some(3));
        let c = v.get("nested").and_then(|n| n.get("a")).and_then(|a| a.get("b")).unwrap();
        assert_eq!(c.raw(), b"\"c\"");
        assert_eq!(ok("[]").elements().count(), 0);
        assert_eq!(ok("{}").members().count(), 0);
        assert_eq!(ok("5").members().count(), 0);
    }

    #[test]
    fn strings_decode_escapes_and_pairs() {
        let v = ok(r#""caf\u00e9 \"q\" \\ \ud83d\ude00 \n""#);
        let s = v.as_str().unwrap();
        assert!(!s.is_plain());
        assert_eq!(s.as_plain(), None);
        assert_eq!(s.to_string(), "caf\u{e9} \"q\" \\ \u{1F600} \n");
        assert!(s.eq_str("caf\u{e9} \"q\" \\ \u{1F600} \n"));
        assert_eq!(s.decoded_len(), "caf\u{e9} \"q\" \\ \u{1F600} \n".len());
        let mut buf = [0u8; 64];
        assert_eq!(s.decode_into(&mut buf), Some("caf\u{e9} \"q\" \\ \u{1F600} \n"));
        let mut small = [0u8; 4];
        assert_eq!(s.decode_into(&mut small), None);
        let key = ok(r#"{"k\u0065y":1}"#);
        assert_eq!(key.get("key").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn integers_are_checked() {
        assert_eq!(ok("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(ok("18446744073709551616").as_u64(), None);
        assert_eq!(ok("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(ok("9223372036854775808").as_i64(), None);
        assert_eq!(ok("1.0").as_u64(), None);
        assert_eq!(ok("1e3").as_i64(), None);
    }

    #[test]
    fn writer_round_trips_and_canonicalises() {
        let doc = Json::Obj(std::vec![
            ("z".to_string(), Json::Int(-3)),
            ("a".to_string(), Json::Arr(std::vec![Json::Bool(true), Json::Null, Json::str("x\"\\\n\u{1}\u{e9}")])),
            ("m".to_string(), Json::obj([("k", Json::Obj(Vec::new()))])),
        ]);
        let canonical = doc.write(Style::CANONICAL);
        assert_eq!(canonical, r#"{"a":[true,null,"x\"\\\n\u0001é"],"m":{"k":{}},"z":-3}"#);
        let pretty = doc.write(Style::PRETTY);
        for text in [&canonical, &pretty] {
            let back = parse(text.as_bytes(), &L).unwrap().to_json().unwrap();
            assert_eq!(back.write(Style::CANONICAL), canonical);
        }
        assert!(pretty.starts_with("{\n  \"z\": -3,"));
        assert!(pretty.ends_with("}\n"));
        assert_eq!(Json::Arr(Vec::new()).write(Style::PRETTY), "[]\n");
    }

    /// Mutated documents: parse never panics, and whatever it accepts can
    /// be walked completely and re-written to something that parses again.
    #[test]
    fn corrupted_documents_never_panic() {
        let base = br#"{"format":"ncpkg/2","signed":{"id":"org.example.app","files":[{"path":"a","size":1,"sha512":"00"}],"n":[1,-2,3.5e1,true,false,null,"\u00e9\ud83d\ude00"]},"signatures":[]}"#;
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let interesting = b"{}[]\":,\\-0123456789.eEtrufalsn \x00\xff\xc3";
        let mut accepted = 0;
        for _ in 0..40_000 {
            let mut b = base.to_vec();
            for _ in 0..(next() % 4 + 1) {
                let r = next();
                let at = (r >> 8) as usize % b.len().max(1);
                match r % 4 {
                    0 if !b.is_empty() => b[at] = interesting[(r >> 32) as usize % interesting.len()],
                    1 if !b.is_empty() => {
                        b.remove(at);
                    }
                    2 => b.insert(at.min(b.len()), interesting[(r >> 32) as usize % interesting.len()]),
                    _ => b.truncate(at),
                }
            }
            if let Ok(v) = parse(&b, &L) {
                accepted += 1;
                fn walk(v: Value<'_>, depth: usize) {
                    assert!(depth < 64);
                    let _ = (v.kind(), v.raw(), v.as_u64(), v.as_i64(), v.as_bool());
                    if let Some(s) = v.as_str() {
                        let _ = s.to_string();
                    }
                    for (k, m) in v.members() {
                        let _ = k.to_string();
                        walk(m, depth + 1);
                    }
                    for e in v.elements() {
                        walk(e, depth + 1);
                    }
                }
                walk(v, 0);
                if let Some(owned) = v.to_json() {
                    let text = owned.write(Style::CANONICAL);
                    parse(text.as_bytes(), &Limits { max_len: 1 << 20, ..L }).expect("rewritten document parses");
                }
            }
        }
        assert!(accepted > 0);
    }

    /// A span over text that never went through `parse` still cannot read
    /// out of bounds: navigation stops early instead.
    #[test]
    fn navigation_is_total_on_garbage() {
        let garbage: &[&[u8]] = &[b"{\"a\"", b"{\"a\":", b"{\"a\":[1,", b"[\"\\", b"{\"\\\"", b"[{]", b"{,,,}"];
        for g in garbage {
            let v = Value { t: g, s: 0, e: g.len() };
            for (k, m) in v.members() {
                let _ = (k.to_string(), m.raw(), m.len());
            }
            for e in v.elements() {
                let _ = (e.raw(), e.len());
            }
            let _ = v.get("a");
        }
    }
}
