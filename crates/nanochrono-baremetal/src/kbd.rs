// SPDX-License-Identifier: Apache-2.0
//! Keyboard layouts: set 1 scancodes, as every input stack here delivers
//! them, to the characters and editing keys a terminal or a text field wants.
//!
//! The interface's own bindings work on scancodes and need none of this — a
//! stopwatch's Space is the same key on every keyboard. Typing is different:
//! the key that types `ñ` on a Spanish keyboard types `;` on an American one,
//! and `@` is Shift+2 on one and AltGr+2 on the other. So the shell and the
//! desktop's text fields go through a [`Keyboard`], which tracks the
//! modifiers (Shift, Ctrl, Alt, AltGr — told apart from Alt by the `0xE0`
//! prefix the input stacks keep in `Key::extended` — Caps Lock and Num Lock)
//! and the Spanish layout's dead keys (´ ` ^ ¨ followed by a vowel).
//!
//! Layouts: `us` (the default) and `es` (Spain, ISO). Chosen at boot with
//! `kbd=es` on the kernel command line, and at run time with `loadkeys`.

use crate::input::Key;

/// A keyboard layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Us,
    Es,
}

impl Layout {
    pub const ALL: [Layout; 2] = [Layout::Us, Layout::Es];

    pub fn from_name(name: &str) -> Option<Layout> {
        match name {
            "us" | "en" | "en-us" => Some(Layout::Us),
            "es" | "es-es" | "spanish" => Some(Layout::Es),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Layout::Us => "us",
            Layout::Es => "es",
        }
    }
}

static LAYOUT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The layout new keyboards start with: `kbd=` at boot, `loadkeys` after.
pub fn default_layout() -> Layout {
    match LAYOUT.load(core::sync::atomic::Ordering::Relaxed) {
        1 => Layout::Es,
        _ => Layout::Us,
    }
}

pub fn set_default_layout(layout: Layout) {
    LAYOUT.store(layout as u8, core::sync::atomic::Ordering::Relaxed);
}

/// What one key press means to a text consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInput {
    Char(char),
    /// Ctrl with a letter (`'a'..='z'`) or one of `[ \ ] ^ _`.
    Ctrl(char),
    Enter,
    Backspace,
    Delete,
    Tab,
    BackTab,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    /// F1..F12.
    Function(u8),
}

/// The modifier and lock state, and a pending dead key.
#[derive(Debug, Clone, Copy)]
pub struct Keyboard {
    pub layout: Layout,
    left_shift: bool,
    right_shift: bool,
    ctrl_left: bool,
    ctrl_right: bool,
    alt: bool,
    altgr: bool,
    gui: bool,
    caps: bool,
    num: bool,
    dead: Option<char>,
}

impl Keyboard {
    pub const fn new(layout: Layout) -> Keyboard {
        Keyboard {
            layout,
            left_shift: false,
            right_shift: false,
            ctrl_left: false,
            ctrl_right: false,
            alt: false,
            altgr: false,
            gui: false,
            caps: false,
            // On: a keypad types digits until Num Lock says otherwise, which
            // is what nearly every firmware leaves it at.
            num: true,
            dead: None,
        }
    }

    pub fn shift(&self) -> bool {
        self.left_shift || self.right_shift
    }

    pub fn ctrl(&self) -> bool {
        self.ctrl_left || self.ctrl_right
    }

    pub fn alt(&self) -> bool {
        self.alt
    }

    /// The Super/Windows key, held.
    pub fn gui(&self) -> bool {
        self.gui
    }

    /// Feeds one key event; returns what it typed, if anything. Releases,
    /// modifiers and lock keys type nothing.
    pub fn feed(&mut self, key: Key) -> Option<KeyInput> {
        let (code, ext, down) = (key.scancode, key.extended, key.pressed);
        match (code, ext) {
            (0x2A, false) => self.left_shift = down,
            (0x36, false) => self.right_shift = down,
            (0x1D, false) => self.ctrl_left = down,
            (0x1D, true) => self.ctrl_right = down,
            (0x38, false) => self.alt = down,
            // Right Alt: AltGr on a layout that has one, Alt on one that
            // does not.
            (0x38, true) => {
                if self.layout == Layout::Us {
                    self.alt = down
                } else {
                    self.altgr = down
                }
            }
            (0x5B, true) | (0x5C, true) => self.gui = down,
            _ => {}
        }
        if !down {
            return None;
        }
        match (code, ext) {
            (0x3A, false) => {
                self.caps = !self.caps;
                return None;
            }
            (0x45, false) => {
                self.num = !self.num;
                return None;
            }
            (0x2A | 0x36 | 0x1D | 0x38, _) | (0x5B | 0x5C, true) => return None,
            _ => {}
        }
        if let Some(named) = self.named(code, ext) {
            self.dead = None;
            return Some(named);
        }
        let ch = self.character(code, ext)?;
        if self.ctrl() && !self.altgr {
            let lower = ch.to_ascii_lowercase();
            if lower.is_ascii_lowercase() || matches!(lower, '[' | '\\' | ']' | '^' | '_' | ' ') {
                self.dead = None;
                return Some(KeyInput::Ctrl(lower));
            }
        }
        // Dead keys: the accent waits for the next character.
        if let Some(accent) = dead_key(self.layout, ch) {
            if let Some(pending) = self.dead.take() {
                // Twice in a row types the accent itself.
                return Some(KeyInput::Char(spacing_accent(pending)));
            }
            self.dead = Some(accent);
            return None;
        }
        if let Some(accent) = self.dead.take() {
            if ch == ' ' {
                return Some(KeyInput::Char(spacing_accent(accent)));
            }
            return Some(KeyInput::Char(compose(accent, ch).unwrap_or(ch)));
        }
        Some(KeyInput::Char(ch))
    }

    /// The editing and navigation keys, which mean the same on every layout.
    fn named(&self, code: u8, ext: bool) -> Option<KeyInput> {
        // The keypad's navigation half, when Num Lock is off.
        let nav = ext || !self.num;
        Some(match code {
            0x1C => KeyInput::Enter,
            0x0E => KeyInput::Backspace,
            0x0F if self.shift() => KeyInput::BackTab,
            0x0F => KeyInput::Tab,
            0x01 => KeyInput::Escape,
            0x48 if nav => KeyInput::Up,
            0x50 if nav => KeyInput::Down,
            0x4B if nav => KeyInput::Left,
            0x4D if nav => KeyInput::Right,
            0x47 if nav => KeyInput::Home,
            0x4F if nav => KeyInput::End,
            0x49 if nav => KeyInput::PageUp,
            0x51 if nav => KeyInput::PageDown,
            0x52 if nav => KeyInput::Insert,
            0x53 if nav => KeyInput::Delete,
            0x3B..=0x44 => KeyInput::Function(code - 0x3A),
            0x57 => KeyInput::Function(11),
            0x58 => KeyInput::Function(12),
            _ => return None,
        })
    }

    fn character(&self, code: u8, ext: bool) -> Option<char> {
        // The keypad with Num Lock on, the same on both layouts.
        if !ext {
            let keypad = match code {
                0x47 => Some('7'),
                0x48 => Some('8'),
                0x49 => Some('9'),
                0x4A => Some('-'),
                0x4B => Some('4'),
                0x4C => Some('5'),
                0x4D => Some('6'),
                0x4E => Some('+'),
                0x4F => Some('1'),
                0x50 => Some('2'),
                0x51 => Some('3'),
                0x52 => Some('0'),
                0x53 => Some(if self.layout == Layout::Es { ',' } else { '.' }),
                0x37 => Some('*'),
                _ => None,
            };
            if keypad.is_some() {
                return keypad;
            }
        } else if code == 0x35 {
            return Some('/');
        }
        if ext {
            return None;
        }
        if code == 0x39 {
            return Some(' ');
        }
        let row = match self.layout {
            Layout::Us => &US,
            Layout::Es => &ES,
        };
        let entry = row.iter().find(|e| e.0 == code)?;
        let letter = entry.1.is_ascii_alphabetic() || matches!(entry.1, 'ñ' | 'ç');
        // Caps Lock shifts letters only, and Shift undoes it.
        let shifted = if letter { self.shift() != self.caps } else { self.shift() };
        if self.altgr {
            return (entry.3 != '\0').then_some(entry.3);
        }
        Some(if shifted { entry.2 } else { entry.1 })
    }
}

/// `(scancode, plain, shifted, altgr)`; `'\0'` where a level types nothing.
#[rustfmt::skip]
static US: [(u8, char, char, char); 48] = [
    (0x29, '`', '~', '\0'),
    (0x02, '1', '!', '\0'), (0x03, '2', '@', '\0'), (0x04, '3', '#', '\0'), (0x05, '4', '$', '\0'),
    (0x06, '5', '%', '\0'), (0x07, '6', '^', '\0'), (0x08, '7', '&', '\0'), (0x09, '8', '*', '\0'),
    (0x0A, '9', '(', '\0'), (0x0B, '0', ')', '\0'), (0x0C, '-', '_', '\0'), (0x0D, '=', '+', '\0'),
    (0x10, 'q', 'Q', '\0'), (0x11, 'w', 'W', '\0'), (0x12, 'e', 'E', '\0'), (0x13, 'r', 'R', '\0'),
    (0x14, 't', 'T', '\0'), (0x15, 'y', 'Y', '\0'), (0x16, 'u', 'U', '\0'), (0x17, 'i', 'I', '\0'),
    (0x18, 'o', 'O', '\0'), (0x19, 'p', 'P', '\0'), (0x1A, '[', '{', '\0'), (0x1B, ']', '}', '\0'),
    (0x1E, 'a', 'A', '\0'), (0x1F, 's', 'S', '\0'), (0x20, 'd', 'D', '\0'), (0x21, 'f', 'F', '\0'),
    (0x22, 'g', 'G', '\0'), (0x23, 'h', 'H', '\0'), (0x24, 'j', 'J', '\0'), (0x25, 'k', 'K', '\0'),
    (0x26, 'l', 'L', '\0'), (0x27, ';', ':', '\0'), (0x28, '\'', '"', '\0'), (0x2B, '\\', '|', '\0'),
    (0x56, '\\', '|', '\0'),
    (0x2C, 'z', 'Z', '\0'), (0x2D, 'x', 'X', '\0'), (0x2E, 'c', 'C', '\0'), (0x2F, 'v', 'V', '\0'),
    (0x30, 'b', 'B', '\0'), (0x31, 'n', 'N', '\0'), (0x32, 'm', 'M', '\0'), (0x33, ',', '<', '\0'),
    (0x34, '.', '>', '\0'), (0x35, '/', '?', '\0'),
];

/// Spain, ISO. `´` and `¨` (0x28), `` ` `` and `^` (0x1A) are dead keys.
#[rustfmt::skip]
static ES: [(u8, char, char, char); 48] = [
    (0x29, 'º', 'ª', '\\'),
    (0x02, '1', '!', '|'), (0x03, '2', '"', '@'), (0x04, '3', '·', '#'), (0x05, '4', '$', '~'),
    (0x06, '5', '%', '€'), (0x07, '6', '&', '¬'), (0x08, '7', '/', '\0'), (0x09, '8', '(', '\0'),
    (0x0A, '9', ')', '\0'), (0x0B, '0', '=', '\0'), (0x0C, '\'', '?', '\0'), (0x0D, '¡', '¿', '\0'),
    (0x10, 'q', 'Q', '\0'), (0x11, 'w', 'W', '\0'), (0x12, 'e', 'E', '€'), (0x13, 'r', 'R', '\0'),
    (0x14, 't', 'T', '\0'), (0x15, 'y', 'Y', '\0'), (0x16, 'u', 'U', '\0'), (0x17, 'i', 'I', '\0'),
    (0x18, 'o', 'O', '\0'), (0x19, 'p', 'P', '\0'), (0x1A, '`', '^', '['), (0x1B, '+', '*', ']'),
    (0x1E, 'a', 'A', '\0'), (0x1F, 's', 'S', '\0'), (0x20, 'd', 'D', '\0'), (0x21, 'f', 'F', '\0'),
    (0x22, 'g', 'G', '\0'), (0x23, 'h', 'H', '\0'), (0x24, 'j', 'J', '\0'), (0x25, 'k', 'K', '\0'),
    (0x26, 'l', 'L', '\0'), (0x27, 'ñ', 'Ñ', '\0'), (0x28, '´', '¨', '{'), (0x2B, 'ç', 'Ç', '}'),
    (0x56, '<', '>', '\0'),
    (0x2C, 'z', 'Z', '\0'), (0x2D, 'x', 'X', '\0'), (0x2E, 'c', 'C', '\0'), (0x2F, 'v', 'V', '\0'),
    (0x30, 'b', 'B', '\0'), (0x31, 'n', 'N', '\0'), (0x32, 'm', 'M', '\0'), (0x33, ',', ';', '\0'),
    (0x34, '.', ':', '\0'), (0x35, '-', '_', '\0'),
];

/// Whether `ch`, as typed on `layout`, is a dead key, and which accent.
fn dead_key(layout: Layout, ch: char) -> Option<char> {
    match (layout, ch) {
        (Layout::Es, '´' | '`' | '^' | '¨') => Some(ch),
        _ => None,
    }
}

/// The accent on its own, for a dead key followed by Space (or itself).
fn spacing_accent(accent: char) -> char {
    accent
}

/// A dead key's accent on a base letter, where Latin-1 has the result.
fn compose(accent: char, base: char) -> Option<char> {
    const TABLE: &[(char, &str, &str)] = &[
        ('´', "aeiouyAEIOUY", "áéíóúýÁÉÍÓÚÝ"),
        ('`', "aeiouAEIOU", "àèìòùÀÈÌÒÙ"),
        ('^', "aeiouAEIOU", "âêîôûÂÊÎÔÛ"),
        ('¨', "aeiouyAEIOU", "äëïöüÿÄËÏÖÜ"),
    ];
    let (_, from, to) = TABLE.iter().find(|t| t.0 == accent)?;
    let i = from.chars().position(|c| c == base)?;
    to.chars().nth(i)
}
