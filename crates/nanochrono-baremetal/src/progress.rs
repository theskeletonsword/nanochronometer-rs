// SPDX-License-Identifier: Apache-2.0
//! The boot screen: where the kernel got to, drawn while it gets there.
//!
//! A machine with no serial port gives no other answer. Without this, a boot
//! that stops anywhere between the loader and the first drawn frame looks
//! identical from the outside: the loader's last message stays on screen and
//! nothing else happens, whether the kernel faulted in its first instruction
//! or hung in a driver five phases later.
//!
//! So each phase says what it is about to do before it starts. The caption
//! left on screen names the phase that did not finish, which turns "it hangs"
//! into a bug report with a location in it. The bar behind it says how far
//! along that was.
//!
//! # Why it looks like this
//!
//! Because the alternative was a row of coloured squares in a corner, and a
//! row of squares needs this file open beside it to mean anything. The
//! information is the same; a sentence and a bar are legible from across the
//! room and to somebody who has never seen the source.
//!
//! It is also the honest amount of ceremony. The phases are real work — a
//! `VMCALL` that can triple-fault a machine that does not implement it, MSR
//! writes, a walk of firmware tables that vary by vendor — and some of them
//! take long enough on real hardware to look like a hang. Naming them while
//! they run is the difference between a pause and a fault.
//!
//! # Composited displays
//!
//! Drawing here has to reach the screen *now*, not at the next frame. The
//! back buffer is attached before the first phase is reported, so every paint
//! below is followed by a present — without which the boot screen would be
//! written faithfully into memory that nothing ever scans out, which is
//! exactly what happened before this was noticed: the progress marks were
//! invisible on every machine whose mode fits the back buffer, which is to
//! say on every machine anyone would run this on.

use crate::draw::{self, Palette};
use crate::framebuffer::Framebuffer;
use crate::typeface::{BODY, TITLE};

/// What the kernel is about to do.
///
/// Ordered as they run. The discriminant is the position along the bar, so
/// adding a phase in the middle renumbers the ones after it — which is fine,
/// because the number is never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Long mode reached, framebuffer found. Anything earlier than this
    /// leaves nothing on screen at all.
    Entered,
    /// Reading CPUID and the feature registers.
    CpuFeatures,
    /// Programming and reading the performance counters. Writes MSRs, which
    /// is the phase most likely to fault on hardware an emulator does not
    /// model.
    Pmu,
    /// Timing the architectural counter.
    Counter,
    /// Enumerating PCI and any USB host controller.
    Pci,
    /// Detecting a hypervisor, which may issue a hypercall.
    Hypervisor,
    /// Reading the firmware's ACPI tables, which are whatever the firmware
    /// says they are.
    Acpi,
    /// Bringing up the input devices.
    Input,
    /// Drawing the interface.
    Interface,
}

/// How many there are, for the bar's arithmetic.
const PHASES: u32 = Phase::Interface as u32 + 1;

impl Phase {
    const fn index(self) -> u32 {
        self as u32
    }

    /// The short name, for the serial log.
    pub const fn name(self) -> &'static str {
        match self {
            Phase::Entered => "entered",
            Phase::CpuFeatures => "cpu features",
            Phase::Pmu => "pmu",
            Phase::Counter => "counter",
            Phase::Pci => "pci",
            Phase::Hypervisor => "hypervisor",
            Phase::Acpi => "acpi",
            Phase::Input => "input",
            Phase::Interface => "interface",
        }
    }

    /// The sentence shown while it runs.
    ///
    /// Written for somebody watching the machine boot, not for somebody
    /// reading the source: it says what is happening and, where it is not
    /// obvious, why it is worth waiting for.
    pub const fn caption(self) -> &'static str {
        match self {
            Phase::Entered => "Initialising",
            Phase::CpuFeatures => "Reading CPU features",
            Phase::Pmu => "Programming the performance counters",
            Phase::Counter => "Calibrating the counter",
            Phase::Pci => "Enumerating PCI and USB",
            // The one that has to say *why*. "Detecting VM" on its own reads
            // like something evading a sandbox, which is the opposite of what
            // this does: a guest's counter runs against a host's clock, and
            // the offset between them has to be measured or every reading is
            // wrong by it. The hypercall that measures it costs microseconds,
            // and a variable number of them, so it is asked once — here — and
            // never again. See `crate::hypervisor::hypercalls`.
            Phase::Hypervisor => {
                "Detecting virtualization to correct for its overhead (one hypercall, now)"
            }
            Phase::Acpi => "Reading the firmware's ACPI tables",
            Phase::Input => "Detecting keyboard and pointer",
            Phase::Interface => "Starting the interface",
        }
    }
}

/// The framebuffer to draw on, if there is one.
///
/// A `static mut` because the phases are reported from functions that take no
/// context and cannot be given one. Written once at boot on a single core
/// with interrupts masked, and read nowhere else.
static mut SURFACE: Option<Framebuffer> = None;

/// Whether the fixed part of the screen — the mark, the wordmark, the empty
/// bar — has been drawn yet.
///
/// It never changes after the first phase, so redrawing it every time would
/// be nine full-screen repaints of identical pixels. Only the bar's fill and
/// the caption are repainted, and only those regions are presented.
static mut DRESSED: bool = false;

/// Records the surface to draw the boot screen on.
pub fn attach(fb: Option<Framebuffer>) {
    // SAFETY: single core, interrupts masked, called once before any phase is
    // reported; nothing else reads or writes these.
    unsafe {
        SURFACE = fb;
        DRESSED = false;
    }
}

/// Geometry, derived from the mode rather than fixed.
///
/// A boot screen laid out for 1920x1200 and shown at 800x600 is a mark
/// hanging off the bottom edge, and the modes this runs at are whatever the
/// loader could get.
struct Layout {
    centre_x: u32,
    /// The logo: the whole one, or the header's wordmark on a screen too
    /// narrow for it.
    logo: &'static crate::logo::Image,
    logo_y: u32,
    bar_x: u32,
    bar_y: u32,
    bar_w: u32,
    bar_h: u32,
    caption_y: u32,
}

impl Layout {
    fn for_screen(fb: &Framebuffer) -> Layout {
        let centre_x = fb.width / 2;
        // Sitting slightly above centre, the way a boot screen does: the
        // caption below it then falls at the optical middle rather than the
        // arithmetic one.
        let block_y = fb.height * 2 / 5;

        let logo = if fb.width >= crate::logo::LOGO.width + 32 {
            &crate::logo::LOGO
        } else {
            crate::logo::wordmark(40)
        };
        let bar_w = (fb.width / 4).clamp(220, 460);
        let bar_h = 6;

        // Stacked downwards, each row starting where the last one ended.
        //
        // The `y` a text call takes is the **top of the line**, not the
        // baseline — `draw::text` adds the ascent itself. Reading it as a
        // baseline, which an earlier version of this did, puts every row one
        // ascent too high: the bar was drawn through the middle of the
        // wordmark and the caption was clipped to its top few rows.
        let title = TITLE.line_height as u32;
        let body = BODY.line_height as u32;
        let logo_y = block_y.saturating_sub(logo.height / 2);
        let bar_y = logo_y + logo.height + title;
        let caption_y = bar_y + bar_h + body;

        Layout {
            centre_x,
            logo,
            logo_y,
            bar_x: centre_x - bar_w / 2,
            bar_y,
            bar_w,
            bar_h,
            caption_y,
        }
    }
}

/// Draws the parts that never change, once.
fn dress(fb: &Framebuffer, p: &Palette, layout: &Layout) {
    fb.clear(p.background);

    // The logo, the same artwork the interface's header carries, so the boot
    // screen and the interface are recognisably one thing.
    crate::logo::draw(
        fb,
        layout.logo,
        layout.centre_x.saturating_sub(layout.logo.width / 2),
        layout.logo_y,
    );

    // The empty bar. Rounded to its own height, which is what makes it a pill
    // rather than a rectangle.
    draw::rounded(
        fb,
        layout.bar_x,
        layout.bar_y,
        layout.bar_w,
        layout.bar_h,
        layout.bar_h / 2,
        p.track,
    );

    fb.present(0, 0, fb.width, fb.height);
}

/// Repaints the bar's fill and the caption, and presents only those.
fn update(fb: &Framebuffer, p: &Palette, layout: &Layout, phase: Phase, done: bool) {
    // A phase that has started is counted as half complete, so the bar moves
    // when a phase begins as well as when it ends. A bar that only moves on
    // completion sits still through the phase most likely to hang, which is
    // the opposite of what it is for.
    let steps = PHASES * 2;
    let at = phase.index() * 2 + if done { 2 } else { 1 };
    let filled = (layout.bar_w as u64 * at.min(steps) as u64 / steps as u64) as u32;

    draw::rounded(
        fb,
        layout.bar_x,
        layout.bar_y,
        layout.bar_w,
        layout.bar_h,
        layout.bar_h / 2,
        p.track,
    );
    if filled >= layout.bar_h {
        draw::rounded(
            fb,
            layout.bar_x,
            layout.bar_y,
            filled,
            layout.bar_h,
            layout.bar_h / 2,
            p.accent,
        );
    }

    // The caption band is cleared before it is written: the sentences differ
    // in length, and a shorter one drawn over a longer one leaves the tail of
    // the last phase on screen.
    let band_y = layout.caption_y.saturating_sub(2);
    let band_h = (BODY.line_height as u32) + 4;
    fb.fill(0, band_y, fb.width, band_h, p.background);
    draw::text_centred(
        fb,
        &BODY,
        0,
        fb.width,
        layout.caption_y,
        phase.caption(),
        if done { p.muted } else { p.text },
    );

    fb.present(
        layout.bar_x,
        layout.bar_y,
        layout.bar_w,
        layout.bar_h.max(1),
    );
    fb.present(0, band_y, fb.width, band_h);
}

/// Paints the boot screen for `phase`.
fn show(phase: Phase, done: bool) {
    // SAFETY: written once by `attach` before this can be called; single core,
    // interrupts masked.
    let Some(fb) = (unsafe { SURFACE }) else {
        return;
    };
    if !fb.is_usable() {
        return;
    }
    let p = Palette::APP;
    let layout = Layout::for_screen(&fb);
    // A mode too small to hold the mark and the bar gets the caption alone
    // rather than a mark drawn off the edge.
    if fb.height < layout.caption_y + (BODY.line_height as u32) {
        return;
    }

    // SAFETY: as above.
    if !unsafe { DRESSED } {
        dress(&fb, &p, &layout);
        // SAFETY: as above.
        unsafe { DRESSED = true };
    }
    update(&fb, &p, &layout, phase, done);
}

/// Marks `phase` as started.
pub fn enter(phase: Phase) {
    show(phase, false);
}

/// Marks `phase` as finished.
pub fn leave(phase: Phase) {
    show(phase, true);
}

/// Runs `body`, marking the phase around it.
pub fn phase<T>(phase: Phase, body: impl FnOnce() -> T) -> T {
    enter(phase);
    let out = body();
    leave(phase);
    out
}
