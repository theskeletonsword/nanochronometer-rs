// SPDX-License-Identifier: Apache-2.0
//! The launch card: what the kernel found out about a plugin, shown before
//! the plugin gets the screen — and the card that says why one was refused
//! or stopped.
//!
//! * ✅ **Creator** — signed by the creator's key. Runs in the kernel, after
//!   two seconds or at Enter.
//! * 🌳 **Trusted root** — signed by a root this machine's owner trusts. Also
//!   runs in the kernel, the same way; the badge just says who vouched for it.
//! * **No badge** — unsigned, or signed by no trusted key. Belongs in ring 3
//!   (the next module); until that exists it runs contained, and only after
//!   five seconds in which Esc cancels it, with the reason on screen.
//!
//! The typefaces are ASCII, so the marks are drawn rather than typed.

use crate::draw::{self, Palette};
use crate::framebuffer::{Colour, Framebuffer};
use crate::input::{Event, Input};
use crate::ncplu::{Fault, LoadError, Loaded, Signature, Tier};
use crate::text::Text;
use crate::typeface::{BODY, HEADING, TITLE};

const SC_ESC: u8 = 0x01;
const SC_ENTER: u8 = 0x1C;

const CARD_W: u32 = 600;
const CARD_H: u32 = 300;
const ICON: u32 = 56;

/// What the user did at a card.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Go,
    Cancel,
    Timeout,
}

/// The card's rectangle, centred and clipped to the screen.
fn frame(fb: &Framebuffer) -> (u32, u32, u32, u32) {
    let w = CARD_W.min(fb.width.saturating_sub(16));
    let h = CARD_H.min(fb.height.saturating_sub(16));
    ((fb.width - w) / 2, (fb.height - h) / 2, w, h)
}

fn background(fb: &Framebuffer, p: &Palette) -> (u32, u32, u32, u32) {
    fb.clear(p.background);
    let (x, y, w, h) = frame(fb);
    draw::rounded(fb, x, y, w, h, 12, p.panel);
    draw::rounded_outline(fb, x, y, w, h, 12, p.divider);
    (x, y, w, h)
}

/// A filled disc.
fn disc(fb: &Framebuffer, cx: i32, cy: i32, r: i32, c: Colour) {
    for dy in -r..=r {
        let mut dx = 0;
        while (dx + 1) * (dx + 1) + dy * dy <= r * r {
            dx += 1;
        }
        if cy + dy >= 0 && cx - dx >= 0 {
            fb.fill((cx - dx) as u32, (cy + dy) as u32, (2 * dx + 1) as u32, 1, c);
        }
    }
}

/// A line `thick` pixels wide, stamped as squares along its length.
fn stroke(fb: &Framebuffer, (x0, y0): (i32, i32), (x1, y1): (i32, i32), thick: i32, c: Colour) {
    let steps = (x1 - x0).abs().max((y1 - y0).abs()).max(1);
    for i in 0..=steps {
        let x = x0 + (x1 - x0) * i / steps - thick / 2;
        let y = y0 + (y1 - y0) * i / steps - thick / 2;
        if x >= 0 && y >= 0 {
            fb.fill(x as u32, y as u32, thick as u32, thick as u32, c);
        }
    }
}

/// ✅ — a green rounded square with a white check.
fn mark_official(fb: &Framebuffer, x: u32, y: u32) {
    draw::rounded(fb, x, y, ICON, ICON, 10, 0x0022_AA44);
    let (x, y) = (x as i32, y as i32);
    stroke(fb, (x + 13, y + 29), (x + 24, y + 40), 7, 0x00FF_FFFF);
    stroke(fb, (x + 24, y + 40), (x + 44, y + 17), 7, 0x00FF_FFFF);
}

/// 🌳 — a trunk and a crown of three discs.
fn mark_community(fb: &Framebuffer, x: u32, y: u32) {
    let (x, y) = (x as i32, y as i32);
    fb.fill((x + 24) as u32, (y + 34) as u32, 9, 20, 0x0077_5533);
    disc(fb, x + 28, y + 20, 15, 0x0033_AA33);
    disc(fb, x + 16, y + 30, 11, 0x0033_AA33);
    disc(fb, x + 40, y + 30, 11, 0x0033_AA33);
    disc(fb, x + 26, y + 16, 7, 0x0055_CC44);
}

/// 🌳 in the accent colour: a trusted-root plugin still runs in the kernel,
/// so its tree is green like the creator check rather than the warning shade.
fn mark_tree(fb: &Framebuffer, x: u32, y: u32) {
    mark_community(fb, x, y);
}

/// ✖ — a red disc with a white cross.
fn mark_refused(fb: &Framebuffer, x: u32, y: u32) {
    let (x, y) = (x as i32, y as i32);
    disc(fb, x + 28, y + 28, 27, 0x00CC_3333);
    stroke(fb, (x + 17, y + 17), (x + 39, y + 39), 7, 0x00FF_FFFF);
    stroke(fb, (x + 39, y + 17), (x + 17, y + 39), 7, 0x00FF_FFFF);
}

/// Pushes `bytes` as lower-case hex.
fn hex<const N: usize>(t: &mut Text<N>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        t.push(DIGITS[(b >> 4) as usize]).push(DIGITS[(b & 15) as usize]);
    }
}

/// A root fingerprint the way `ncplu-sign` prints it: xxxx-xxxx-xxxx-xxxx.
pub fn fingerprint<const N: usize>(t: &mut Text<N>, fp: &[u8; 8]) {
    for (i, pair) in fp.chunks(2).enumerate() {
        if i > 0 {
            t.push(b'-');
        }
        hex(t, pair);
    }
}

/// Waits until `seconds` pass, Enter or Esc, redrawing the countdown line.
fn wait(fb: &Framebuffer, input: &mut Input, hz: u64, seconds: u64, footer: (u32, u32, u32)) -> Answer {
    let p = &Palette::APP;
    let (x, y, w) = footer;
    let start = crate::arch::counter_ordered();
    let mut shown = u64::MAX;
    loop {
        let elapsed = crate::arch::counter_ordered().wrapping_sub(start) / hz.max(1);
        if elapsed >= seconds {
            return Answer::Timeout;
        }
        let left = seconds - elapsed;
        if left != shown {
            shown = left;
            let mut t = Text::<80>::new();
            t.str("Enter: run now    Esc: cancel    runs in ").num(left).str(" s");
            fb.fill(x, y, w, BODY.line_height as u32 + 2, p.panel);
            draw::text(fb, &BODY, x, y, t.as_str(), p.muted);
            fb.present_damage();
        }
        // SAFETY: ring 0; the interface is not polling while a card is up.
        while let Some(event) = unsafe { input.poll() } {
            if let Event::Key(k) = event {
                crate::rng::stir(nanochrono_core::rng::EVENT_KEY, k.scancode as u64);
                if k.pressed && k.scancode == SC_ENTER {
                    return Answer::Go;
                }
                if k.pressed && k.scancode == SC_ESC {
                    return Answer::Cancel;
                }
            }
        }
        core::hint::spin_loop();
    }
}

/// Shows what the kernel knows about a plugin that loaded, and asks. Returns
/// whether to run it: Enter or the timeout run it, Esc cancels.
pub fn confirm(fb: &Framebuffer, input: &mut Input, name: &str, loaded: &Loaded, hz: u64) -> bool {
    let p = &Palette::APP;
    let (x, y, w, h) = background(fb, p);
    match loaded.tier {
        Tier::Creator => mark_official(fb, x + 28, y + 28),
        Tier::TreeRoot => mark_tree(fb, x + 28, y + 28),
        Tier::Community => mark_community(fb, x + 28, y + 28),
    }
    let tx = x + 28 + ICON + 20;
    draw::text(fb, &TITLE, tx, y + 26, name, p.title);
    let (label, colour) = match loaded.tier {
        Tier::Creator => ("Creator plugin — runs in the kernel", p.ok),
        Tier::TreeRoot => ("Trusted-root plugin — runs in the kernel", p.ok),
        Tier::Community => ("Community plugin — bound for ring 3", p.warn),
    };
    draw::text(fb, &HEADING, tx, y + 26 + TITLE.line_height as u32, label, colour);

    let mut line = y + 110;
    let step = BODY.line_height as u32 + 6;
    let mut t = Text::<96>::new();
    t.str("signature   ").str(loaded.signature.describe());
    draw::text(fb, &BODY, x + 28, line, t.as_str(), p.text);
    line += step;

    t.clear();
    t.str("SHA-512     ");
    hex(&mut t, &loaded.digest);
    t.str("...");
    draw::text(fb, &BODY, x + 28, line, t.as_str(), p.text);
    line += step;

    t.clear();
    let shown_root = match loaded.tier {
        Tier::Creator => Some(Tier::Creator),
        Tier::TreeRoot => Some(Tier::TreeRoot),
        Tier::Community => None,
    };
    match shown_root.and_then(crate::ncplu::root_fingerprint) {
        Some(fp) => {
            t.str("root key    ");
            fingerprint(&mut t, &fp);
        }
        None => {
            t.str("root key    ");
            match crate::ncplu::root_fingerprint(Tier::Creator) {
                Some(_) => t.str("does not match a trusted root"),
                None => t.str("none: this kernel trusts no signing key"),
            };
        }
    }
    draw::text(fb, &BODY, x + 28, line, t.as_str(), p.text);
    line += step;

    t.clear();
    t.str("size        ").num(loaded.file_size as u64).str(" bytes, arena ").num(loaded.arena_size as u64).str(" bytes");
    draw::text(fb, &BODY, x + 28, line, t.as_str(), p.text);
    line += step;

    t.clear();
    t.str("can use     ");
    crate::ncplu::write_caps(&mut t, loaded.capabilities);
    draw::text(fb, &BODY, x + 28, line, t.as_str(), p.text);
    line += step;

    if loaded.tier == Tier::Community {
        let why = match loaded.signature {
            Signature::Untrusted { .. } => "Signed by no key this kernel trusts.",
            Signature::NoRoot => "This kernel was built without a signing root.",
            _ => "Not signed.",
        };
        draw::text(fb, &BODY, x + 28, line + 4, why, p.warn);
        draw::text(
            fb,
            &BODY,
            x + 28,
            line + 4 + step,
            "No privileged services; it runs in ring 3, isolated. Esc cancels.",
            p.warn,
        );
    }
    fb.present(0, 0, fb.width, fb.height);
    fb.discard_damage();

    let footer = (x + 28, y + h - 36, w - 56);
    let seconds = if loaded.tier.runs_in_kernel() { 2 } else { 5 };
    wait(fb, input, hz, seconds, footer) != Answer::Cancel
}

/// Says why a plugin was refused, for three seconds or until a key.
pub fn refused(fb: &Framebuffer, input: &mut Input, name: &str, error: LoadError, hz: u64) {
    let p = &Palette::APP;
    let (x, y, w, h) = background(fb, p);
    mark_refused(fb, x + 28, y + 28);
    let tx = x + 28 + ICON + 20;
    draw::text(fb, &TITLE, tx, y + 26, name, p.title);
    draw::text(fb, &HEADING, tx, y + 26 + TITLE.line_height as u32, "Plugin refused", p.danger);
    draw::text(fb, &BODY, x + 28, y + 120, error.message(), p.text);
    let note = match error {
        LoadError::Format(_) => "It breaks the .ncplu format. Nothing from it was loaded.",
        LoadError::Corrupt => "Its digest does not match: damaged, or edited after packing.",
        LoadError::Privileged => "Privileged services need a creator or trusted-root signature.",
        LoadError::UnresolvedImport => "It needs a kernel symbol this kernel does not export.",
        LoadError::WrongArch => "Install the package for this machine's architecture.",
        LoadError::NotRunnable => "Drivers load at boot; libraries live in /usr/lib.",
        LoadError::BadPackage(_) => "It breaks the .ncplu package format. Nothing from it was loaded.",
    };
    draw::text(fb, &BODY, x + 28, y + 120 + BODY.line_height as u32 + 6, note, p.muted);
    fb.present(0, 0, fb.width, fb.height);
    fb.discard_damage();
    let _ = wait(fb, input, hz, 3, (x + 28, y + h - 36, w - 56));
}

/// Says a plugin was stopped by a fault the kernel contained.
pub fn stopped(fb: &Framebuffer, input: &mut Input, name: &str, fault: &Fault, hz: u64) {
    let mut t = Text::<96>::new();
    if fault.stack {
        t.str("It ran out of stack (guard page at 0x");
        hex(&mut t, &(fault.cr2 as u32).to_be_bytes());
        t.str(").");
    } else {
        t.str("A ").str(crate::ncplu::vector_name(fault.vector)).str(" in its code at 0x");
        hex(&mut t, &(fault.rip as u32).to_be_bytes());
        t.str(".");
    }
    stopped_because(fb, input, name, t.as_str(), hz);
}

/// The card for a plugin its own stack canary stopped: a buffer on its stack
/// overflowed into the canary, caught before the corrupted return address
/// was used.
pub fn smashed(fb: &Framebuffer, input: &mut Input, name: &str, hz: u64) {
    stopped_because(fb, input, name, "Stack smashing: a buffer overflowed into its stack canary.", hz);
}

/// A stopped plugin's card, with the reason on its first line.
fn stopped_because(fb: &Framebuffer, input: &mut Input, name: &str, why: &str, hz: u64) {
    let p = &Palette::APP;
    let (x, y, w, h) = background(fb, p);
    mark_refused(fb, x + 28, y + 28);
    let tx = x + 28 + ICON + 20;
    draw::text(fb, &TITLE, tx, y + 26, name, p.title);
    draw::text(fb, &HEADING, tx, y + 26 + TITLE.line_height as u32, "Plugin stopped", p.danger);
    draw::text(fb, &BODY, x + 28, y + 120, why, p.text);
    draw::text(
        fb,
        &BODY,
        x + 28,
        y + 120 + BODY.line_height as u32 + 6,
        "The kernel caught it and carried on.",
        p.muted,
    );
    fb.present(0, 0, fb.width, fb.height);
    fb.discard_damage();
    let _ = wait(fb, input, hz, 3, (x + 28, y + h - 36, w - 56));
}
