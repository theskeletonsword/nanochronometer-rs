// SPDX-License-Identifier: Apache-2.0
//! Finding the pointer in a HID report descriptor.
//!
//! # Why this is needed at all
//!
//! A USB keyboard or mouse can be driven without ever reading its report
//! descriptor, because the HID specification defines a **boot protocol**: a
//! fixed eight-byte layout for keyboards and a fixed three-byte one for mice,
//! which firmware relies on and which the freestanding USB stack here uses.
//!
//! An I2C-HID device has no boot protocol. There is no BIOS on an I2C bus and
//! nothing ever needed one, so the specification never defined it. The only
//! way to know what a byte of a report means is to read the descriptor the
//! device hands you — which is the whole reason a touchpad needs more code
//! than a mouse.
//!
//! # What is looked for, and why that is enough
//!
//! Not gestures, and not multi-touch. A Windows Precision Touchpad declares
//! *two* interfaces in one descriptor: a digitizer collection reporting
//! absolute contacts, and an ordinary **mouse collection** reporting relative
//! X, Y and buttons. The device sends the mouse reports until the host
//! explicitly switches it into touchpad mode by writing an Input Mode feature
//! report — which is what a desktop operating system does, and what this
//! deliberately does not.
//!
//! So the search is for the input report carrying `GenericDesktop:X` and
//! `GenericDesktop:Y` as relative variables, together with whatever buttons
//! share it. That is a cursor, which is what the interface wants, and it
//! needs none of the report-descriptor machinery that multi-touch does.
//!
//! # Reference
//!
//! Item encoding from the USB-IF *Device Class Definition for Human Interface
//! Devices*, section 6.2.2. The approach — parse the descriptor into field
//! locations, then extract by bit offset — follows FreeBSD's `sys/dev/hid/hid.c`
//! and `hidmap.c`. No code was copied; this looks for one report where those
//! build a general mapping table.

/// Usage pages this needs to recognise.
mod page {
    pub const GENERIC_DESKTOP: u16 = 0x01;
    /// Keyboard and keypad. Its usages *are* the keycodes.
    pub const KEYBOARD: u16 = 0x07;
    pub const BUTTON: u16 = 0x09;
    pub const DIGITIZER: u16 = 0x0D;
}

/// The eight modifier usages, `LeftControl` through `RightGUI`.
const MODIFIER_FIRST: u32 = 0xE0;
const MODIFIER_LAST: u32 = 0xE7;

/// Usages within the generic desktop page.
mod usage {
    pub const POINTER: u32 = 0x0001;
    pub const MOUSE: u32 = 0x0002;
    pub const X: u32 = 0x0030;
    pub const Y: u32 = 0x0031;
    pub const WHEEL: u32 = 0x0038;
}

/// Where one value sits inside a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Field {
    /// Bits from the start of the report body — that is, *after* the report
    /// ID byte where there is one.
    pub bit_offset: usize,
    pub bit_size: usize,
    /// How many consecutive values of this size the field holds. One for X or
    /// Y; the button count for a button field.
    pub count: usize,
    /// Whether the value is two's complement. Taken from the logical minimum
    /// being negative, which is how the descriptor says so.
    pub signed: bool,
    /// Whether it reports a delta rather than a position.
    pub relative: bool,
}

impl Field {
    /// Reads this field's `index`th value out of a report body.
    ///
    /// `body` excludes the report ID. Returns zero for a field that runs past
    /// the end of the report, which is what a short report from a device that
    /// pads inconsistently looks like — and a zero delta is the harmless
    /// reading.
    pub fn value(&self, body: &[u8], index: usize) -> i32 {
        if index >= self.count || self.bit_size == 0 || self.bit_size > 32 {
            return 0;
        }
        // Checked: the offsets come from a descriptor the device wrote, and a
        // hostile one (BadUSB) can declare sizes whose products wrap.
        let Some(start) = index
            .checked_mul(self.bit_size)
            .and_then(|skip| self.bit_offset.checked_add(skip))
        else {
            return 0;
        };
        let mut raw = 0u32;
        for bit in 0..self.bit_size {
            let Some(at) = start.checked_add(bit) else {
                return 0;
            };
            let Some(byte) = body.get(at / 8) else {
                return 0;
            };
            if byte >> (at % 8) & 1 != 0 {
                raw |= 1 << bit;
            }
        }
        if self.signed && self.bit_size < 32 && raw >> (self.bit_size - 1) & 1 != 0 {
            // Sign-extend. Without this an eight-bit -1 reads as 255, and a
            // cursor moves only right and down — the classic symptom.
            (raw | (!0u32 << self.bit_size)) as i32
        } else {
            raw as i32
        }
    }

    /// Whether the `index`th bit of a bitmap field is set.
    pub fn bit(&self, body: &[u8], index: usize) -> bool {
        self.value(body, index) != 0
    }
}

/// The report that carries a cursor, and where its values are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerLayout {
    /// The report ID, or `None` for a descriptor that uses none. A device
    /// with several reports prefixes each with its ID; one with a single
    /// unnumbered report does not, and reading a byte that is not there
    /// shifts every field by eight bits.
    pub report_id: Option<u8>,
    /// Total size of the report body in bytes, ID excluded.
    pub body_bytes: usize,
    pub x: Field,
    pub y: Field,
    pub buttons: Option<Field>,
    pub wheel: Option<Field>,
}

impl PointerLayout {
    /// Decodes a report into a movement.
    ///
    /// `report` includes the report ID byte when the layout has one. Returns
    /// `None` for a report belonging to a different collection — a touchpad
    /// interleaves its digitizer reports with its mouse reports, and
    /// decoding one as the other produces a cursor that jumps.
    pub fn decode(&self, report: &[u8]) -> Option<Movement> {
        let body = match self.report_id {
            Some(id) => {
                if report.first().copied()? != id {
                    return None;
                }
                report.get(1..)?
            }
            None => report,
        };

        Some(Movement {
            dx: self.x.value(body, 0),
            dy: self.y.value(body, 0),
            wheel: self.wheel.map_or(0, |field| field.value(body, 0)),
            left: self.button(body, 0),
            right: self.button(body, 1),
            middle: self.button(body, 2),
        })
    }

    fn button(&self, body: &[u8], index: usize) -> bool {
        self.buttons
            .is_some_and(|field| index < field.count && field.bit(body, index))
    }
}

/// The report that carries keystrokes, and where they are.
///
/// A keyboard is laid out differently from a pointer, and the difference is
/// the point: a pointer's fields are *variable* — one value per control, at a
/// fixed place — while the keys themselves are an **array**, a list of the
/// usages currently held. Six slots of eight bits is the usual shape, and an
/// empty slot is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardLayout {
    pub report_id: Option<u8>,
    pub body_bytes: usize,
    /// The modifier bitmap: control, shift, alt and GUI, left and right.
    pub modifiers: Option<Field>,
    /// The held-key slots. Each value is a HID usage, not a scancode.
    pub keys: Field,
}

impl KeyboardLayout {
    /// Reads the held keys out of a report, in boot-protocol shape.
    ///
    /// The eight-byte layout a boot keyboard sends — modifiers, a reserved
    /// byte, then six usages — because that is what the rest of this kernel's
    /// keyboard handling already speaks, and converting here means one
    /// translation table instead of two.
    pub fn decode(&self, report: &[u8]) -> Option<[u8; 8]> {
        let body = match self.report_id {
            Some(id) => {
                if report.first().copied()? != id {
                    return None;
                }
                report.get(1..)?
            }
            None => report,
        };

        let mut out = [0u8; 8];
        if let Some(modifiers) = self.modifiers {
            let mut bits = 0u8;
            for index in 0..modifiers.count.min(8) {
                if modifiers.bit(body, index) {
                    bits |= 1 << index;
                }
            }
            out[0] = bits;
        }
        for slot in 0..self.keys.count.min(6) {
            let usage = self.keys.value(body, slot);
            out[2 + slot] = u8::try_from(usage).unwrap_or(0);
        }
        Some(out)
    }
}

/// One decoded pointer report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Movement {
    pub dx: i32,
    pub dy: i32,
    pub wheel: i32,
    pub left: bool,
    pub right: bool,
    pub middle: bool,
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// Global item state, which persists across main items until changed.
#[derive(Debug, Clone, Copy, Default)]
struct Globals {
    usage_page: u16,
    logical_minimum: i32,
    report_size: usize,
    report_count: usize,
    report_id: Option<u8>,
}

/// How many usages one main item may have queued.
///
/// A descriptor may list a usage per field; sixteen covers a mouse's X, Y,
/// wheel and buttons several times over. A longer list is truncated rather
/// than refused: the fields this looks for come first in every descriptor
/// that has them.
const MAX_USAGES: usize = 16;

/// Local item state, which is cleared after every main item.
#[derive(Debug, Clone, Copy)]
struct Locals {
    usages: [u32; MAX_USAGES],
    count: usize,
    minimum: Option<u32>,
    maximum: Option<u32>,
}

impl Default for Locals {
    fn default() -> Locals {
        Locals {
            usages: [0; MAX_USAGES],
            count: 0,
            minimum: None,
            maximum: None,
        }
    }
}

impl Locals {
    fn push(&mut self, usage: u32) {
        if self.count < MAX_USAGES {
            self.usages[self.count] = usage;
            self.count += 1;
        }
    }
}

/// What is known about one candidate report so far.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    report_id: Option<u8>,
    bits: usize,
    x: Option<Field>,
    y: Option<Field>,
    buttons: Option<Field>,
    wheel: Option<Field>,
    modifiers: Option<Field>,
    keys: Option<Field>,
    /// Whether the enclosing collection is a digitizer. A digitizer's X and Y
    /// are absolute contact coordinates on a surface with its own logical
    /// range, and treating them as a delta sends the cursor to the corner.
    digitizer: bool,
}

impl Candidate {
    fn new(report_id: Option<u8>) -> Candidate {
        Candidate {
            report_id,
            bits: 0,
            x: None,
            y: None,
            buttons: None,
            wheel: None,
            modifiers: None,
            keys: None,
            digitizer: false,
        }
    }

    fn complete(&self) -> bool {
        self.x.is_some() && self.y.is_some() && !self.digitizer
    }

    fn is_keyboard(&self) -> bool {
        self.keys.is_some()
    }
}

/// How many distinct report IDs a descriptor may define.
///
/// The touchpad this was written against uses six. Sixteen is past anything
/// seen in the wild, and a descriptor with more is parsed up to the limit
/// rather than refused — the mouse report is never the sixteenth.
const MAX_REPORTS: usize = 16;

/// Finds the input report carrying a relative pointer.
///
/// Returns `None` for a descriptor with no such report — a keyboard, or a
/// touchpad already switched into digitizer-only mode.
pub fn find_pointer(descriptor: &[u8]) -> Option<PointerLayout> {
    // The first complete candidate. Descriptors put the mouse collection
    // first, and a device that also declares a digitizer declares it after —
    // so first-wins picks the relative report without having to rank them.
    let found = parse(descriptor)?
        .into_iter()
        .flatten()
        .find(|candidate| candidate.complete())?;

    Some(PointerLayout {
        report_id: found.report_id,
        body_bytes: found.bits.div_ceil(8),
        x: found.x?,
        y: found.y?,
        buttons: found.buttons,
        wheel: found.wheel,
    })
}

/// Walks a report descriptor into one candidate per report ID.
///
/// Shared by both finders: a descriptor is parsed once and then asked what it
/// holds, which is what lets a device declaring both a mouse and a keyboard
/// be understood as both.
fn parse(descriptor: &[u8]) -> Option<[Option<Candidate>; MAX_REPORTS]> {
    let mut globals = Globals::default();
    let mut locals = Locals::default();

    let mut candidates: [Option<Candidate>; MAX_REPORTS] = [None; MAX_REPORTS];
    let mut used = 0usize;

    // Collection nesting, tracked only to know whether the current item is
    // inside a digitizer.
    let mut digitizer_depth = 0usize;
    let mut depth = 0usize;

    let mut at = 0usize;
    while at < descriptor.len() {
        let prefix = descriptor[at];
        at += 1;

        // A long item: one length byte, one tag byte, then the data. Nothing
        // defines one, but stepping over it correctly is what keeps the rest
        // of the descriptor readable.
        if prefix == 0xFE {
            let length = *descriptor.get(at)? as usize;
            at = at.checked_add(2)?.checked_add(length)?;
            continue;
        }

        let size = match prefix & 0x03 {
            3 => 4,
            other => other as usize,
        };
        let kind = (prefix >> 2) & 0x03;
        let tag = prefix >> 4;

        let data = descriptor.get(at..at + size)?;
        at += size;

        let unsigned = {
            let mut value = 0u32;
            for (i, &byte) in data.iter().enumerate() {
                value |= (byte as u32) << (8 * i);
            }
            value
        };
        // Signed reading, for logical minimum. The item's width is the sign
        // width: a one-byte 0x81 is -127, not 129.
        let signed = if size > 0 && size < 4 && unsigned >> (8 * size - 1) & 1 != 0 {
            (unsigned | (!0u32 << (8 * size))) as i32
        } else {
            unsigned as i32
        };

        match kind {
            // Main
            0 => match tag {
                // Input
                0x8 => {
                    let flags = unsigned;
                    // Bit 0 set means constant — padding, with no usage.
                    // Bit 1 set means variable rather than an array.
                    let constant = flags & 0x01 != 0;
                    let variable = flags & 0x02 != 0;
                    let relative = flags & 0x04 != 0;

                    let slot = slot_for(&mut candidates, &mut used, globals.report_id)?;
                    let candidate = candidates[slot].as_mut()?;
                    if digitizer_depth > 0 {
                        candidate.digitizer = true;
                    }

                    // Saturating: both factors are 32-bit values straight out
                    // of the descriptor. A device claiming 2^32 fields of
                    // 2^32 bits must not wrap the running offset back to a
                    // plausible one (or panic a build with overflow checks).
                    let field_bits = globals.report_size.saturating_mul(globals.report_count);
                    // Arrays are recorded too, not only variables: a
                    // keyboard's held keys *are* an array, and skipping
                    // non-variable items is why an earlier version could find
                    // a mouse and never a keyboard.
                    if !constant {
                        record(candidate, &globals, &locals, relative, variable);
                    }
                    candidate.bits = candidate.bits.saturating_add(field_bits);
                    locals = Locals::default();
                }
                // Output and Feature: they consume the local state but
                // contribute no input bits.
                0x9 | 0xB => {
                    locals = Locals::default();
                }
                // Collection
                0xA => {
                    // A digitizer collection is recognised by the usage page
                    // that opened it. Once inside one, every nested
                    // collection counts too: a `Finger` collection inside a
                    // `TouchPad` is still absolute coordinates.
                    if globals.usage_page == page::DIGITIZER || digitizer_depth > 0 {
                        digitizer_depth += 1;
                    }
                    depth += 1;
                    locals = Locals::default();
                }
                // End collection
                0xC => {
                    depth = depth.saturating_sub(1);
                    digitizer_depth = digitizer_depth.saturating_sub(1);
                    locals = Locals::default();
                }
                _ => {
                    locals = Locals::default();
                }
            },

            // Global
            1 => match tag {
                0x0 => globals.usage_page = unsigned as u16,
                0x1 => globals.logical_minimum = signed,
                0x7 => globals.report_size = unsigned as usize,
                0x8 => globals.report_id = Some(unsigned as u8),
                0x9 => globals.report_count = unsigned as usize,
                // Push and pop of the global state. Nothing in a pointer
                // descriptor needs them, and a descriptor that uses them
                // would be misread — so parsing stops rather than continuing
                // with state that is now wrong.
                0xA | 0xB => return None,
                _ => {}
            },

            // Local
            2 => match tag {
                0x0 => {
                    // A usage is either a bare id, or a page and id packed
                    // into four bytes.
                    let usage = if size == 4 {
                        globals.usage_page = (unsigned >> 16) as u16;
                        unsigned & 0xFFFF
                    } else {
                        unsigned
                    };
                    locals.push(usage);
                }
                0x1 => locals.minimum = Some(unsigned),
                0x2 => locals.maximum = Some(unsigned),
                _ => {}
            },

            _ => {}
        }
    }

    Some(candidates)
}

/// Finds the input report carrying keystrokes.
///
/// Returns `None` for a descriptor with no key array — a mouse, or a
/// touchpad, both of which declare a `Keyboard` page nowhere.
pub fn find_keyboard(descriptor: &[u8]) -> Option<KeyboardLayout> {
    let found = parse(descriptor)?
        .into_iter()
        .flatten()
        .find(|candidate| candidate.is_keyboard())?;

    Some(KeyboardLayout {
        report_id: found.report_id,
        body_bytes: found.bits.div_ceil(8),
        modifiers: found.modifiers,
        keys: found.keys?,
    })
}

/// Finds or creates the candidate for a report ID.
fn slot_for(
    candidates: &mut [Option<Candidate>; MAX_REPORTS],
    used: &mut usize,
    report_id: Option<u8>,
) -> Option<usize> {
    if let Some(index) = candidates
        .iter()
        .position(|slot| slot.is_some_and(|candidate| candidate.report_id == report_id))
    {
        return Some(index);
    }
    if *used == MAX_REPORTS {
        return None;
    }
    candidates[*used] = Some(Candidate::new(report_id));
    *used += 1;
    Some(*used - 1)
}

/// Assigns the usages queued for this main item to bit positions.
fn record(
    candidate: &mut Candidate,
    globals: &Globals,
    locals: &Locals,
    relative: bool,
    variable: bool,
) {
    let field = |index: usize| Field {
        bit_offset: candidate
            .bits
            .saturating_add(index.saturating_mul(globals.report_size)),
        bit_size: globals.report_size,
        count: 1,
        signed: globals.logical_minimum < 0,
        relative,
    };

    match globals.usage_page {
        page::KEYBOARD => {
            if variable {
                // The modifiers: eight one-bit flags, declared as the usage
                // range 0xE0..=0xE7.
                let is_modifier = matches!(
                    (locals.minimum, locals.maximum),
                    (Some(MODIFIER_FIRST), Some(MODIFIER_LAST))
                );
                if is_modifier && candidate.modifiers.is_none() {
                    candidate.modifiers = Some(Field {
                        bit_offset: candidate.bits,
                        bit_size: globals.report_size,
                        count: globals.report_count,
                        signed: false,
                        relative,
                    });
                }
            } else if candidate.keys.is_none() {
                // An array on the keyboard page: the held keys.
                candidate.keys = Some(Field {
                    bit_offset: candidate.bits,
                    bit_size: globals.report_size,
                    count: globals.report_count,
                    signed: false,
                    relative,
                });
            }
        }
        page::BUTTON if variable => {
            // Buttons come as a usage range rather than one usage each.
            let count = match (locals.minimum, locals.maximum) {
                // `high - low + 1` overflows for the range 0..=u32::MAX.
                (Some(low), Some(high)) if high >= low => ((high - low) as usize).saturating_add(1),
                _ => locals.count,
            };
            if count == 0 {
                return;
            }
            if candidate.buttons.is_none() {
                candidate.buttons = Some(Field {
                    bit_offset: candidate.bits,
                    bit_size: globals.report_size,
                    count: count.min(globals.report_count),
                    signed: false,
                    relative,
                });
            }
        }
        page::GENERIC_DESKTOP if variable => {
            for index in 0..locals.count {
                match locals.usages[index] {
                    usage::X if candidate.x.is_none() => candidate.x = Some(field(index)),
                    usage::Y if candidate.y.is_none() => candidate.y = Some(field(index)),
                    usage::WHEEL if candidate.wheel.is_none() => {
                        candidate.wheel = Some(field(index))
                    }
                    // `Pointer` and `Mouse` open collections rather than
                    // naming fields.
                    usage::POINTER | usage::MOUSE => {}
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report descriptor of a real Elan I2C-HID touchpad.
    ///
    /// See `tests/fixtures/README.md` for where it came from and why a
    /// synthetic one is not a substitute.
    const ELAN: &[u8] = include_bytes!("../tests/fixtures/elan-i2c-hid.rdesc");

    /// A textbook three-byte relative mouse, with no report ID.
    ///
    /// The simplest thing the parser has to handle, and the case where a
    /// missing report ID must *not* shift every field by a byte.
    #[rustfmt::skip]
    const PLAIN_MOUSE: &[u8] = &[
        0x05, 0x01,       // Usage Page (Generic Desktop)
        0x09, 0x02,       // Usage (Mouse)
        0xA1, 0x01,       // Collection (Application)
        0x09, 0x01,       //   Usage (Pointer)
        0xA1, 0x00,       //   Collection (Physical)
        0x05, 0x09,       //     Usage Page (Button)
        0x19, 0x01,       //     Usage Minimum (1)
        0x29, 0x03,       //     Usage Maximum (3)
        0x15, 0x00,       //     Logical Minimum (0)
        0x25, 0x01,       //     Logical Maximum (1)
        0x95, 0x03,       //     Report Count (3)
        0x75, 0x01,       //     Report Size (1)
        0x81, 0x02,       //     Input (Data, Variable, Absolute)
        0x95, 0x01,       //     Report Count (1)
        0x75, 0x05,       //     Report Size (5)
        0x81, 0x01,       //     Input (Constant)
        0x05, 0x01,       //     Usage Page (Generic Desktop)
        0x09, 0x30,       //     Usage (X)
        0x09, 0x31,       //     Usage (Y)
        0x15, 0x81,       //     Logical Minimum (-127)
        0x25, 0x7F,       //     Logical Maximum (127)
        0x75, 0x08,       //     Report Size (8)
        0x95, 0x02,       //     Report Count (2)
        0x81, 0x06,       //     Input (Data, Variable, Relative)
        0xC0,             //   End Collection
        0xC0,             // End Collection
    ];

    #[test]
    fn a_plain_mouse_is_laid_out_where_the_specification_says() {
        let layout = find_pointer(PLAIN_MOUSE).expect("a pointer");
        assert_eq!(layout.report_id, None);
        assert_eq!(layout.body_bytes, 3);

        let buttons = layout.buttons.expect("buttons");
        assert_eq!(buttons.bit_offset, 0);
        assert_eq!(buttons.count, 3);

        assert_eq!(layout.x.bit_offset, 8);
        assert_eq!(layout.x.bit_size, 8);
        assert!(layout.x.signed);
        assert!(layout.x.relative);
        assert_eq!(layout.y.bit_offset, 16);
    }

    #[test]
    fn a_plain_mouse_report_decodes() {
        let layout = find_pointer(PLAIN_MOUSE).expect("a pointer");
        // Left button held, four right, three up.
        let movement = layout.decode(&[0x01, 0x04, 0xFD]).expect("movement");
        assert_eq!(movement.dx, 4);
        assert_eq!(movement.dy, -3);
        assert!(movement.left);
        assert!(!movement.right);
    }

    #[test]
    fn negative_deltas_sign_extend() {
        let layout = find_pointer(PLAIN_MOUSE).expect("a pointer");
        // 0xFF is -1, not 255. Reading it unsigned is what makes a cursor
        // travel only right and down, which is the classic symptom of
        // getting this wrong.
        let movement = layout.decode(&[0x00, 0xFF, 0xFF]).expect("movement");
        assert_eq!((movement.dx, movement.dy), (-1, -1));
    }

    #[test]
    fn the_real_touchpad_descriptor_yields_its_mouse_report() {
        let layout = find_pointer(ELAN).expect("a pointer in the Elan descriptor");

        // Report 1 is the mouse collection. Report 84 is the Precision
        // Touchpad digitizer, which reports absolute contacts and would send
        // the cursor to a corner if it were picked instead.
        assert_eq!(layout.report_id, Some(1));

        assert_eq!(layout.x.bit_size, 8);
        assert!(layout.x.relative, "the mouse report is relative");
        assert!(layout.x.signed, "logical minimum is -127");
        assert_eq!(layout.y.bit_offset, layout.x.bit_offset + 8);

        let buttons = layout.buttons.expect("buttons");
        assert_eq!(buttons.bit_offset, 0);
        assert_eq!(buttons.count, 2, "the touchpad declares two buttons");

        // Two button bits, six of padding, then X and Y.
        assert_eq!(layout.x.bit_offset, 8);
    }

    #[test]
    fn the_real_touchpad_report_decodes() {
        let layout = find_pointer(ELAN).expect("a pointer");
        // Report ID 1, no buttons, +10 in X, -5 in Y, then the padding the
        // descriptor declares.
        let report = [1u8, 0x00, 10, 0xFB, 0, 0, 0, 0, 0];
        let movement = layout.decode(&report).expect("movement");
        assert_eq!(movement.dx, 10);
        assert_eq!(movement.dy, -5);
        assert!(!movement.left && !movement.right);

        let clicked = layout
            .decode(&[1u8, 0x01, 0, 0, 0, 0, 0, 0, 0])
            .expect("movement");
        assert!(clicked.left);
    }

    #[test]
    fn a_report_from_another_collection_is_refused() {
        let layout = find_pointer(ELAN).expect("a pointer");
        // Report 84 is the digitizer. Decoding it as a mouse would read
        // absolute contact coordinates as a delta and throw the cursor
        // across the screen, so it has to be rejected by its ID.
        assert!(layout.decode(&[84u8, 0x01, 0x02, 0x03, 0x04]).is_none());
    }

    /// The report descriptor of a real notebook keyboard.
    const ITE_KEYBOARD: &[u8] = include_bytes!("../tests/fixtures/ite-notebook-keyboard.rdesc");

    #[test]
    fn the_real_keyboard_descriptor_yields_its_key_report() {
        let layout = find_keyboard(ITE_KEYBOARD).expect("a keyboard in the ITE descriptor");

        // Report 1 is the keyboard collection. Three vendor collections come
        // before it in this descriptor, one declaring a 191-byte report — a
        // parser that stopped at the first collection would find none of it.
        assert_eq!(layout.report_id, Some(1));

        let modifiers = layout.modifiers.expect("the modifier bitmap");
        assert_eq!(modifiers.bit_offset, 0);
        assert_eq!(modifiers.bit_size, 1);
        assert_eq!(modifiers.count, 8);

        // Eight modifier bits, then a reserved byte, then the key slots.
        assert_eq!(layout.keys.bit_offset, 16);
        assert_eq!(layout.keys.bit_size, 8);
        assert!(layout.keys.count >= 6);
    }

    #[test]
    fn the_real_keyboard_report_decodes() {
        let layout = find_keyboard(ITE_KEYBOARD).expect("a keyboard");
        // Report 1, left shift held, `a` (usage 0x04) and `b` (0x05) down.
        let mut report = [0u8; 16];
        report[0] = 1;
        report[1] = 0x02;
        report[3] = 0x04;
        report[4] = 0x05;

        let boot = layout.decode(&report).expect("a boot-shaped report");
        assert_eq!(boot[0], 0x02, "modifiers");
        assert_eq!(boot[2], 0x04);
        assert_eq!(boot[3], 0x05);
        assert_eq!(boot[4], 0x00);
    }

    #[test]
    fn a_keyboard_is_not_mistaken_for_a_pointer_or_the_reverse() {
        // Each descriptor answers one question and refuses the other. A
        // touchpad that reported keystrokes, or a keyboard that moved the
        // cursor, would both be a field offset read off the wrong report.
        assert!(find_pointer(ITE_KEYBOARD).is_none());
        assert!(find_keyboard(ELAN).is_none());
        assert!(find_keyboard(PLAIN_MOUSE).is_none());
    }

    #[test]
    fn a_truncated_keyboard_descriptor_is_refused_rather_than_misread() {
        for cut in 0..ITE_KEYBOARD.len() {
            let _ = find_keyboard(&ITE_KEYBOARD[..cut]);
            let _ = find_pointer(&ITE_KEYBOARD[..cut]);
        }
    }

    #[test]
    fn a_keyboard_descriptor_has_no_pointer() {
        #[rustfmt::skip]
        let keyboard: &[u8] = &[
            0x05, 0x01,       // Usage Page (Generic Desktop)
            0x09, 0x06,       // Usage (Keyboard)
            0xA1, 0x01,       // Collection (Application)
            0x05, 0x07,       //   Usage Page (Keyboard)
            0x19, 0xE0,       //   Usage Minimum (224)
            0x29, 0xE7,       //   Usage Maximum (231)
            0x15, 0x00, 0x25, 0x01,
            0x75, 0x01, 0x95, 0x08,
            0x81, 0x02,       //   Input (Data, Variable)
            0xC0,             // End Collection
        ];
        assert!(find_pointer(keyboard).is_none());
    }

    #[test]
    fn a_truncated_descriptor_is_refused_rather_than_misread() {
        // Every prefix of a real descriptor must either parse or return
        // `None`, and never panic or read past the end. A descriptor is
        // whatever the device sent, and a device that sends a short one is
        // not a reason to fault.
        for cut in 0..ELAN.len() {
            let _ = find_pointer(&ELAN[..cut]);
        }
    }

    /// A BadUSB-style descriptor: every size at its 32-bit maximum, a button
    /// range spanning all of `u32`, repeated so the running offset would
    /// wrap. It must parse to *something* or nothing, never panic (the host
    /// test build has overflow checks on), and decoding any report against
    /// what it yields must stay in bounds.
    #[test]
    fn a_hostile_descriptor_cannot_overflow_the_parser() {
        #[rustfmt::skip]
        let hostile: &[u8] = &[
            0x05, 0x09,                         // Usage Page (Button)
            0x1B, 0x00, 0x00, 0x00, 0x00,       // Usage Minimum (0)
            0x2B, 0xFF, 0xFF, 0xFF, 0xFF,       // Usage Maximum (u32::MAX)
            0x77, 0xFF, 0xFF, 0xFF, 0xFF,       // Report Size (u32::MAX)
            0x97, 0xFF, 0xFF, 0xFF, 0xFF,       // Report Count (u32::MAX)
            0x81, 0x02,                         // Input (Data, Variable)
            0x05, 0x01,                         // Usage Page (Generic Desktop)
            0x09, 0x30, 0x09, 0x31,             // Usage (X), Usage (Y)
            0x81, 0x06,                         // Input (Data, Variable, Relative)
            0x81, 0x06,
            0x81, 0x06,
        ];
        let _ = find_keyboard(hostile);
        if let Some(layout) = find_pointer(hostile) {
            let _ = layout.decode(&[0xFF; 64]);
            let _ = layout.decode(&[]);
        }
        // And every prefix of it.
        for cut in 0..hostile.len() {
            let _ = find_pointer(&hostile[..cut]);
        }
    }

    #[test]
    fn a_field_whose_offset_wraps_reads_zero() {
        let field = Field {
            bit_offset: usize::MAX - 3,
            bit_size: 8,
            count: 4,
            signed: false,
            relative: true,
        };
        assert_eq!(field.value(&[0xFF; 8], 3), 0);
        assert_eq!(field.value(&[0xFF; 8], 0), 0);
    }

    #[test]
    fn a_field_reading_past_a_short_report_is_zero() {
        let layout = find_pointer(PLAIN_MOUSE).expect("a pointer");
        // A device that pads inconsistently sends fewer bytes than the
        // descriptor promised. Zero is the harmless reading: the cursor does
        // not move.
        let movement = layout.decode(&[0x00]).expect("movement");
        assert_eq!((movement.dx, movement.dy), (0, 0));
    }
}
