// SPDX-License-Identifier: Apache-2.0
//! Input off x86: the serial console, spoken to the interface as a keyboard.
//!
//! ARM, POWER and RISC-V boards have no 8042, and the USB and I2C stacks in
//! this crate are x86's. What every one of them does have is the UART the
//! kernel already prints to, and a terminal on the other end sends keys. This
//! turns those bytes into the set 1 scancodes the interface binds, so every
//! shortcut — digits for the confirmation code included — works unchanged.
//!
//! Each byte becomes a press and a release. Arrow keys arrive as ANSI escape
//! sequences (`ESC [ A`); an `ESC` with nothing after it in the same poll is
//! the Escape key.

use crate::serial;

/// One pointer movement. There is no pointer on a serial line; the type is
/// kept so the interface compiles against one input API.
#[derive(Debug, Clone, Copy, Default)]
pub struct Motion {
    pub dx: i32,
    pub dy: i32,
    pub wheel: i32,
    pub left: bool,
    pub right: bool,
    pub middle: bool,
}

/// A key press or release, as a set 1 scancode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub scancode: u8,
    pub pressed: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Event {
    Key(Key),
    Motion(Motion),
}

pub struct Input {
    /// The release still owed for the last press.
    pending_release: Option<u8>,
    recent: [u8; 8],
    recent_len: usize,
}

/// Whether the console is Open Firmware's (a PowerPC Mac): its stdin is the
/// machine's own keyboard, not a serial line.
fn open_firmware() -> bool {
    #[cfg(target_arch = "powerpc")]
    {
        crate::arch::ppc::of::present()
    }
    #[cfg(not(target_arch = "powerpc"))]
    {
        false
    }
}

/// Set 1 make code for an ASCII byte, if it is one the interface binds.
fn scancode(byte: u8) -> Option<u8> {
    const LETTERS: [u8; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, // a-m
        0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, // n-z
    ];
    Some(match byte {
        b'a'..=b'z' => LETTERS[(byte - b'a') as usize],
        b'A'..=b'Z' => LETTERS[(byte - b'A') as usize],
        b'1'..=b'9' => byte - b'1' + 0x02,
        b'0' => 0x0B,
        b' ' => 0x39,
        b'\t' => 0x0F,
        b'\r' | b'\n' => 0x1C,
        0x08 | 0x7F => 0x0E,
        0x1B => 0x01,
        _ => return None,
    })
}

impl Input {
    /// # Safety
    /// None beyond the UART having been initialised; the signature matches
    /// the x86 one.
    pub unsafe fn init(_ticks_per_us: u64) -> Input {
        Input { pending_release: None, recent: [0; 8], recent_len: 0 }
    }

    pub fn has_keyboard(&self) -> bool {
        true
    }

    pub fn has_pointer(&self) -> bool {
        false
    }

    pub fn source(&self) -> &'static str {
        if open_firmware() { "open firmware" } else { "serial" }
    }

    /// What the keys arrive through, for the input panel.
    pub fn console_name(&self) -> &'static str {
        if open_firmware() { "open firmware console" } else { "serial console" }
    }

    pub fn trouble(&self) -> &'static str {
        if open_firmware() {
            "keys come from the Open Firmware console; there is no pointer"
        } else {
            "keys come from the serial console; there is no pointer"
        }
    }

    pub fn recent_bytes(&self) -> &[u8] {
        &self.recent[..self.recent_len]
    }

    pub fn scancode_set(&self) -> u8 {
        1
    }

    fn remember(&mut self, byte: u8) {
        if self.recent_len == self.recent.len() {
            self.recent.rotate_left(1);
            self.recent_len -= 1;
        }
        self.recent[self.recent_len] = byte;
        self.recent_len += 1;
    }

    /// The next key event, if a byte is waiting.
    ///
    /// # Safety
    /// Reads the UART.
    pub unsafe fn poll(&mut self) -> Option<Event> {
        if let Some(code) = self.pending_release.take() {
            return Some(Event::Key(Key { scancode: code, pressed: false }));
        }
        let byte = serial::read_byte()?;
        self.remember(byte);
        let code = if byte == 0x1B {
            // An arrow is ESC [ A..D, sent together; a lone ESC is Escape.
            match serial::read_byte() {
                Some(b'[') => match serial::read_byte() {
                    Some(b'A') => 0x48,
                    Some(b'B') => 0x50,
                    Some(b'C') => 0x4D,
                    Some(b'D') => 0x4B,
                    _ => return None,
                },
                Some(other) => {
                    // Escape followed by an ordinary key: deliver Escape now
                    // and let the next poll see nothing of `other`, which
                    // was a keypress in its own right but is rare enough
                    // here not to queue.
                    let _ = other;
                    0x01
                }
                None => 0x01,
            }
        } else {
            scancode(byte)?
        };
        self.pending_release = Some(code);
        Some(Event::Key(Key { scancode: code, pressed: true }))
    }
}
