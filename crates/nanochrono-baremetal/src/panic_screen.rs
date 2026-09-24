// SPDX-License-Identifier: Apache-2.0
//! The screen a freestanding kernel shows when it cannot continue.
//!
//! Green rather than blue, and it stops rather than restarting. A kernel that
//! reboots on panic loses the one thing worth having — what went wrong — and
//! a machine that reboots into the same fault does it forever. This waits,
//! shows the reason, and lets the operator choose.
//!
//! There is no window manager and no mouse, so the two controls are drawn as
//! buttons and driven from the keyboard: `R` asks to restart, `S` to power
//! off, and either then shows a two-digit code that has to be typed back
//! ([`nanochrono_core::power_confirm`]). A firmware's legacy USB emulation
//! delivers a USB keyboard's keys through the 8042 this screen reads, so a
//! BadUSB reaches it too; what it cannot do is read the code. Both actions go
//! through [`crate::acpi`].

use crate::acpi;
use crate::arch::x86::inb;
use crate::draw::{self, Palette};
use crate::framebuffer::Framebuffer;
use crate::typeface::{BODY, TITLE};
use nanochrono_core::power_confirm::{Action, Confirm, Outcome};

/// The 8042 keyboard controller's data and status ports.
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

/// Set 1 scancodes for the keys this screen listens for.
const SCAN_R: u8 = 0x13;
const SCAN_S: u8 = 0x1F;

/// Draws the stop screen and waits for a choice. Never returns.
///
/// # Safety
/// Reads I/O ports and writes the framebuffer; requires ring 0.
pub unsafe fn show(fb: Option<&Framebuffer>, reason: &str) -> ! {
    // SAFETY: forwarded from this function's own contract.
    let power = unsafe { acpi::power_registers() };

    match fb.filter(|f| f.is_usable()) {
        // SAFETY: as above.
        Some(fb) => unsafe { graphical(fb, reason, power.as_ref()) },
        // No graphics mode. The serial port has already carried the reason,
        // so the only thing left is to offer the same choice over it.
        // SAFETY: as above.
        None => unsafe { serial_only(power.as_ref()) },
    }
}

/// # Safety
/// Requires ring 0.
unsafe fn graphical(fb: &Framebuffer, reason: &str, power: Option<&acpi::PowerRegisters>) -> ! {
    let p = Palette::STOP;
    fb.clear(p.background);

    let w = fb.width;

    // A header band, the way the desktop GUI carries its title bar.
    draw::gradient(fb, 0, 0, w, 76, p.header_from, p.header_to);
    fb.fill(0, 75, w, 1, p.divider);
    draw::text(fb, &TITLE, 28, 20, "Stopped", p.title);

    let mut y = 116;
    draw::text(fb, &BODY, 28, y, "The kernel cannot continue.", p.text);
    y += BODY.line_height as u32 + 10;
    draw::text(
        fb,
        &BODY,
        28,
        y,
        "It is waiting rather than restarting, so the reason below is not",
        p.muted,
    );
    y += BODY.line_height as u32;
    draw::text(fb, &BODY, 28, y, "lost to a reboot loop.", p.muted);

    y += 42;
    draw::text(fb, &BODY, 28, y, "REASON", p.accent);
    y += BODY.line_height as u32 + 8;
    // The reason can be long; wrap it rather than running off the edge.
    // Characters per line is estimated from the widest common glyph, since
    // the face is proportional and an exact fit would need measuring twice.
    let columns = ((w - 56) / BODY.width_of("m").max(1)) as usize;
    for chunk in draw::wrap(reason, columns.max(16)) {
        draw::text(fb, &BODY, 28, y, chunk, p.text);
        y += BODY.line_height as u32;
    }

    // The two controls, in the corner the desktop GUI puts its window buttons
    // — except these restart and power off, because on bare metal there is no
    // window to minimise and nothing to close to.
    let button_w = 240;
    let button_h = 56;
    let by = fb.height.saturating_sub(button_h + 40);
    let reboot_x = w.saturating_sub(button_w * 2 + 60);
    let off_x = w.saturating_sub(button_w + 30);

    draw::button(fb, reboot_x, by, button_w, button_h, "R    Restart", &p);
    draw::button(fb, off_x, by, button_w, button_h, "S    Shut down", &p);

    if power.is_none() {
        draw::text(
            fb,
            &BODY,
            28,
            by + 18,
            "no ACPI tables found; using fallbacks",
            p.muted,
        );
    }

    let prompt = Prompt { fb, p, x: 28, y: by.saturating_sub(BODY.line_height as u32 + 24) };
    // SAFETY: forwarded from this function's own contract.
    unsafe { wait_for_choice(power, Some(&prompt)) }
}

/// Where the code is shown on the graphical screen.
struct Prompt<'a> {
    fb: &'a Framebuffer,
    p: Palette,
    x: u32,
    y: u32,
}

impl Prompt<'_> {
    fn show(&self, line: &str) {
        let w = self.fb.width.saturating_sub(self.x * 2);
        self.fb.fill(self.x, self.y, w, BODY.line_height as u32, self.p.background);
        draw::text(self.fb, &BODY, self.x, self.y, line, self.p.text);
        self.fb.present(0, self.y, self.fb.width, BODY.line_height as u32);
    }
}

/// # Safety
/// Requires ring 0.
unsafe fn serial_only(power: Option<&acpi::PowerRegisters>) -> ! {
    crate::println!();
    crate::println!("=== STOPPED ===");
    crate::println!("No graphics mode; not restarting.");
    crate::println!("  R = restart      S = shut down   (then type the code shown)");
    // SAFETY: forwarded from this function's own contract.
    unsafe { wait_for_choice(power, None) }
}

/// Polls the keyboard until a restart or power-off is confirmed.
///
/// # Safety
/// Reads I/O ports; requires ring 0.
unsafe fn wait_for_choice(power: Option<&acpi::PowerRegisters>, prompt: Option<&Prompt>) -> ! {
    let mut confirm = Confirm::new();
    let clock = NsPerTick::detect();
    // Whether the prompt line shows something that has since gone stale (an
    // expired code, a lockout that ended).
    let mut shown = false;
    let say = |line: &str| {
        crate::println!("{}", line);
        if let Some(prompt) = prompt {
            prompt.show(line);
        }
    };
    loop {
        let now = clock.now_ns();
        if shown && !confirm.is_pending(now) && confirm.lockout_remaining_ns(now) == 0 {
            say("");
            shown = false;
        }
        // Status bit 0 is "output buffer full", meaning a byte is waiting.
        // SAFETY: reading the 8042 status port has no side effects.
        if unsafe { inb(PS2_STATUS) } & 1 == 0 {
            core::hint::spin_loop();
            continue;
        }
        // SAFETY: the status bit says a byte is there to read.
        let code = unsafe { inb(PS2_DATA) };
        // When a byte lands is the entropy; the byte itself is the attacker's.
        confirm.stir(crate::arch::counter_ordered());

        // Bit 7 marks a release, 0xE0/0xE1 a prefix; only presses count.
        if code & 0x80 != 0 {
            continue;
        }

        if confirm.is_pending(now) {
            let digit = match code {
                0x02..=0x0A => Some(code - 0x01),
                0x0B => Some(0),
                _ => None,
            };
            match digit.map(|d| confirm.digit(d, now)) {
                Some(Outcome::Confirmed(Action::Restart)) => {
                    crate::println!("restarting");
                    // SAFETY: forwarded from this function's own contract.
                    unsafe { acpi::reboot(power) }
                }
                Some(Outcome::Confirmed(Action::Shutdown)) => {
                    crate::println!("shutting down");
                    // SAFETY: as above.
                    unsafe { acpi::shutdown(power) };
                    // Every method failed. Saying so beats a machine that
                    // looks hung for no stated reason.
                    crate::println!("shutdown failed: no method this platform answers");
                    crate::arch::halt()
                }
                Some(Outcome::Pending) => {}
                Some(Outcome::Rejected) => {
                    let s = confirm.lockout_remaining_ns(now).div_ceil(1_000_000_000);
                    let mut line = crate::text::Text::<48>::new();
                    line.str("wrong code; R and S locked for ").num(s).str(" s");
                    say(line.as_str());
                }
                // Not a digit (Esc included): walk away without penalty.
                Some(Outcome::Idle) | None => {
                    confirm.cancel();
                    say("cancelled");
                }
            }
            continue;
        }

        let action = match code {
            SCAN_R => Action::Restart,
            SCAN_S => Action::Shutdown,
            _ => continue,
        };
        let mut line = crate::text::Text::<64>::new();
        match confirm.request(action, now, crate::arch::counter_ordered()) {
            Ok(digits) => {
                line.str("to ").str(action.verb()).str(", type ");
                for d in digits {
                    line.push(b'0' + d).str(" ");
                }
                line.str("(Esc cancels)");
            }
            Err(_) => {
                let s = confirm.lockout_remaining_ns(now).div_ceil(1_000_000_000);
                line.str("locked for ").num(s).str(" s after a wrong code");
            }
        }
        say(line.as_str());
        shown = true;
    }
}

/// Counter ticks to nanoseconds, without the calibration a panic may have
/// come before.
///
/// CPUID 0x16 states the base frequency on processors that have the leaf,
/// and the TSC runs at that rate. Where it reads zero — older parts, most
/// hypervisors — 3 GHz is assumed. The windows this times (a 10 s code, a
/// lockout from 5 s) then stretch or shrink by the error, a few times at
/// most; the lockout still doubles, which is what makes guessing blind take
/// hours.
struct NsPerTick {
    /// Ticks per microsecond.
    mhz: u64,
}

impl NsPerTick {
    fn detect() -> NsPerTick {
        let max_leaf = crate::arch::x86::cpuid(0, 0)[0];
        let base = if max_leaf >= 0x16 {
            (crate::arch::x86::cpuid(0x16, 0)[0] & 0xFFFF) as u64
        } else {
            0
        };
        NsPerTick { mhz: if base == 0 { 3000 } else { base } }
    }

    fn now_ns(&self) -> u64 {
        (crate::arch::counter_ordered() as u128 * 1000 / self.mhz as u128) as u64
    }
}
