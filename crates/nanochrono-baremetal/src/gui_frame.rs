// SPDX-License-Identifier: Apache-2.0
//! The interface, on a machine with no window system.
//!
//! # What this is, and what it is not
//!
//! The desktop build's GUI is `iced` drawing through `wgpu` onto a surface
//! `winit` obtained from a window server. None of that exists here: there is
//! no GPU driver, no compositor, no window and no event loop to hook into. So
//! this is **not the same code** as the Windows, Linux and macOS GUI, and no
//! amount of arrangement would make it so.
//!
//! What it is: the same *application*, drawn pixel by pixel. Same palette,
//! same header, the same three modes along the top — clock, stopwatch, timer
//! — the same chips selecting what the lower panel reports, the same large
//! readout down the middle and the same status bar underneath. The one
//! deliberate difference is the corner where a desktop window puts minimise
//! and close: there is no window to minimise and nothing to close to, so
//! those two become restart and shut down, through [`crate::acpi`].
//!
//! # Where the animation comes from, with no timer interrupt
//!
//! A moving interface needs to know how much time has passed, and the usual
//! way — programme a timer, take an interrupt on every tick — is the one
//! thing this project must not do: a handler running between two counter
//! reads becomes part of what the chronometer measures.
//!
//! It does not need one. The counter *is* the clock. [`crate::clock`]
//! calibrates it once at startup, the loop below reads it, and a frame is
//! drawn when enough nanoseconds have gone by. Everything that moves is a
//! [`Tween`] stepped once per frame. There is no scheduler, no interrupt and
//! no timer — the same instruction that measures an interval also paces the
//! animation, which means the interface cannot disagree with the measurement
//! it is displaying.
//!
//! Redraws go through the back buffer in [`crate::framebuffer`], and only the
//! rectangle that changed is copied to the screen. Without that, none of this
//! would be possible: an uncached full-screen redraw on a 1080p panel is tens
//! of milliseconds, and a "frame rate" measured in single digits is not an
//! animation.

use crate::acpi;
use crate::clock::Clock;
use crate::draw::{self, Palette, Tween};
#[cfg(x86_any)]
use crate::gpio::Mapping;
#[cfg(x86_any)]
use crate::i2c_hid::{Discovery, GateState};
use crate::framebuffer::{Colour, Framebuffer};
use crate::input::{Event, Input, Motion};
use nanochrono_core::power_confirm::{Action, Confirm, Outcome};
use nanochrono_core::crosscheck::{CrossCheck, Unwrap, Verdict};
use nanochrono_core::space_mode::SpaceMode;
use nanochrono_core::{Integrity, Protected};
use crate::multiboot::Memory;
use crate::pmu::{CorePmu, CounterRoute};
use crate::text::{self, Text};
use crate::typeface::{Face, BODY, HEADING, READOUT, READOUT_BIG};

// Set 1 scancodes for everything the interface binds.
const SCAN_1: u8 = 0x02;
const SCAN_2: u8 = 0x03;
const SCAN_3: u8 = 0x04;
const SCAN_4: u8 = 0x05;
const SCAN_B: u8 = 0x30;
const SCAN_C: u8 = 0x2E;
const SCAN_H: u8 = 0x23;
const SCAN_L: u8 = 0x26;
const SCAN_M: u8 = 0x32;
const SCAN_N: u8 = 0x31;
const SCAN_P: u8 = 0x19;
const SCAN_R: u8 = 0x13;
const SCAN_S: u8 = 0x1F;
const SCAN_U: u8 = 0x16;
const SCAN_Z: u8 = 0x2C;
const SCAN_T: u8 = 0x14;
const SCAN_G: u8 = 0x22;
const SCAN_V: u8 = 0x2F;
const SCAN_K: u8 = 0x25;
const SCAN_ESC: u8 = 0x01;
const SCAN_SPACE: u8 = 0x39;
const SCAN_TAB: u8 = 0x0F;
const SCAN_UP: u8 = 0x48;
const SCAN_DOWN: u8 = 0x50;

/// How long a frame is meant to take.
///
/// Sixty a second. Nothing enforces it — there is no vertical blank to wait
/// for and no compositor to hand a frame to — so this is a floor on how often
/// the loop redraws, not a ceiling on how fast it could.
const FRAME_NS: u64 = 1_000_000_000 / 60;

/// How many input events to take before drawing.
///
/// Bounded so a pointer being moved continuously cannot starve the draw: an
/// unbounded drain is how an interface stops repainting while the mouse is in
/// motion, which looks exactly like a hang.
const EVENTS_PER_FRAME: usize = 24;

/// The three things this application is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Clock,
    Stopwatch,
    Timer,
    /// The ISA kernels and RustCrypto, run on demand.
    Bench,
}

impl Tab {
    const ALL: [Tab; 4] = [Tab::Clock, Tab::Stopwatch, Tab::Timer, Tab::Bench];

    const fn name(self) -> &'static str {
        match self {
            Tab::Clock => "CLOCK",
            Tab::Stopwatch => "STOPWATCH",
            Tab::Timer => "TIMER",
            Tab::Bench => "BENCH",
        }
    }
}

/// What the lower panel reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    Cpu,
    Pmu,
    Counter,
    Memory,
    Usb,
    Hypervisor,
    /// The task manager: CPU active time, frequency, IPC, and where the
    /// loop's time went.
    Tasks,
    /// Settings: the counter source.
    Settings,
}

impl Panel {
    const ALL: [Panel; 8] = [
        Panel::Cpu,
        Panel::Pmu,
        Panel::Counter,
        Panel::Memory,
        Panel::Usb,
        Panel::Hypervisor,
        Panel::Tasks,
        Panel::Settings,
    ];

    const fn name(self) -> &'static str {
        match self {
            Panel::Cpu => "CPU",
            Panel::Pmu => "PMU",
            Panel::Counter => "COUNTER",
            Panel::Memory => "MEMORY",
            Panel::Usb => "USB",
            Panel::Hypervisor => "HYPERVISOR",
            Panel::Tasks => "TASKS",
            Panel::Settings => "SETTINGS",
        }
    }

    /// The label to use when the long one will not fit.
    const fn short(self) -> &'static str {
        match self {
            Panel::Counter => "CNT",
            Panel::Memory => "MEM",
            Panel::Hypervisor => "HYP",
            Panel::Tasks => "TASK",
            Panel::Settings => "SET",
            other => other.name(),
        }
    }
}

/// How much of a duration the readout shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precision {
    /// `hh:mm:ss:mmm` — a wall clock.
    Simple,
    /// `hh:mm:ss:mmm:uuu:sss` — what this instrument is for.
    Nano,
}

impl Precision {
    const fn nanoseconds(self) -> bool {
        matches!(self, Precision::Nano)
    }
}

/// Where everything sits, worked out once from the mode the loader gave us.
///
/// Computed rather than constant because the same layout has to hold at
/// 800x600, which is what a BIOS machine with no `gfxpayload` produces, and
/// at 1920x1200, which is what a laptop panel produces. Proportions rather
/// than pixel offsets, with floors so nothing collapses at the small end.
struct Layout {
    width: u32,
    header_h: u32,
    tabs_y: u32,
    tabs_h: u32,
    /// The readout's own box, which is narrower than the screen. Only this is
    /// cleared and copied out each frame: the readout is the one thing that
    /// changes sixty times a second, and on a 1920-wide panel the difference
    /// between copying the full width and copying the digits is most of the
    /// frame.
    readout_x: u32,
    readout_w: u32,
    readout_y: u32,
    readout_h: u32,
    cards_y: u32,
    cards_h: u32,
    /// How many cards fit, and how wide each is. Worked out here rather than
    /// at the draw because the card height depends on it: a narrow mode folds
    /// the machine summary into the session card, and that card then needs
    /// room for both.
    columns: u32,
    card_w: u32,
    hint_y: u32,
    status_y: u32,
    status_h: u32,
    margin: u32,
    /// Which readout face fits this width.
    readout: &'static Face,
}

/// Hex digits as strings, so a byte can be rendered without an allocator and
/// without a formatting machinery this has no other use for.
#[rustfmt::skip]
const HEX_DIGITS: [&str; 16] = [
    "0", "1", "2", "3", "4", "5", "6", "7",
    "8", "9", "A", "B", "C", "D", "E", "F",
];

/// The widest string the readout can ever hold, used to pick a face and to
/// reserve its box.
const READOUT_SAMPLE: &str = "00:00:00:000:000:000";

impl Layout {
    fn for_screen(fb: &Framebuffer) -> Layout {
        let width = fb.width;
        let height = fb.height;
        let margin = (width / 40).clamp(12, 32);

        let header_h = (height / 18).clamp(34, 64);
        let tabs_h = (height / 16).clamp(34, 56);
        let tabs_y = header_h;
        let content_y = tabs_y + tabs_h;

        let status_h = BODY.line_height as u32 * 2 + 22;
        let status_y = height.saturating_sub(status_h);
        let hint_h = BODY.line_height as u32 + 14;
        let hint_y = status_y.saturating_sub(hint_h);

        // The large face if its box fits with margins to spare, the smaller
        // one otherwise. A bitmap cannot be scaled, so this is a choice
        // between two baked sizes rather than a computed one.
        let readout = if READOUT_BIG.width_of(READOUT_SAMPLE) + margin * 4 <= width {
            &READOUT_BIG
        } else {
            &READOUT
        };
        // The face's line box, the caption under it, and the space between.
        // Sized here rather than at the draw, because a caption that does not
        // fit is not drawn at all — and a box measured without it is exactly
        // how the caption disappears on every mode.
        let readout_h = readout.line_height as u32 + BODY.line_height as u32 + 30;

        // The readout sits in the upper part of the content area and the
        // cards fill what is left. Where there is not enough room for both —
        // a short mode — the cards get whatever remains, down to nothing.
        // How many cards fit. Three at a width that still holds a label
        // beside its value, two when that would make them narrower, one on a
        // small mode. The threshold is measured from the widest ordinary pair
        // rather than picked, so it stays right if the typeface is
        // regenerated at another size.
        let total = width.saturating_sub(margin * 2);
        let narrowest = BODY.width_of("invariant TSC") + BODY.width_of("unavailable") + 70;
        let columns = match total / 3 {
            w if w >= narrowest => 3,
            _ if total / 2 >= narrowest => 2,
            _ => 1,
        };
        let card_w = (total - margin * (columns - 1)) / columns;

        // Two cards means the machine summary folds into the session card, so
        // that card has to hold both. Three means the session card holds at
        // most its own two lines and six laps.
        let card_rows = if columns < 3 { 15 } else { 9 };

        // The cards are sized by what they hold and anchored to the bottom,
        // and the readout is centred in what is left. Letting the cards
        // stretch to fill instead leaves most of a 1200-pixel panel as empty
        // card, which reads as a layout that ran out of things to say.
        let card_content =
            30 + HEADING.line_height as u32 + card_rows * (BODY.line_height as u32 + 7) + 18;
        let available = hint_y.saturating_sub(content_y);
        let readout_box = readout_h.min(available);
        let cards_h = card_content.min(available.saturating_sub(readout_box + margin + 8));
        let cards_y = hint_y.saturating_sub(cards_h + 8);
        let readout_y = content_y + (cards_y.saturating_sub(content_y + readout_box)) / 2;

        // Wide enough for the longest readout the face can produce.
        let readout_w = (readout.width_of(READOUT_SAMPLE) + margin * 2).min(width);
        let readout_x = (width - readout_w) / 2;

        Layout {
            width,
            header_h,
            tabs_y,
            tabs_h,
            readout_x,
            readout_w,
            readout_y,
            readout_h: readout_box,
            cards_y,
            cards_h,
            columns,
            card_w,
            hint_y,
            status_y,
            status_h,
            margin,
            readout,
        }
    }
}

/// A rectangle a click can be tested against.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Hitbox {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

impl Hitbox {
    fn contains(&self, x: i32, y: i32) -> bool {
        self.w > 0
            && x >= self.x as i32
            && y >= self.y as i32
            && x < (self.x + self.w) as i32
            && y < (self.y + self.h) as i32
    }
}

/// What the machine turned out to be. Measured once, at boot, with nothing
/// else running — which is the only condition under which these numbers mean
/// anything.
struct Machine {
    features: nanochrono_core::cpu::CpuFeatures,
    pmu: CorePmu,
    route: CounterRoute,
    cycles_per_op: Option<u64>,
    read_overhead: u64,
    worst_read: u64,
    hypervisor: crate::hypervisor::Report,
    memory: Memory,
    footprint: u64,
    acpi: Option<acpi::PowerRegisters>,
}

impl Machine {
    /// # Safety
    /// Programs the PMU and reads firmware tables; requires ring 0.
    unsafe fn probe() -> Machine {
        use crate::progress::{self, Phase};

        progress::enter(Phase::Acpi);
        // SAFETY: forwarded. Firmware tables are whatever the firmware says
        // they are, which is why every address out of them is checked before
        // it is followed.
        let acpi = unsafe { acpi::power_registers() };
        progress::leave(Phase::Acpi);

        let mut pmu = CorePmu::detect();
        let mut route = CounterRoute::None;
        let mut cycles_per_op = None;
        if pmu.leaf.is_available() {
            // SAFETY: forwarded from this function's own contract.
            route = unsafe { pmu.enable() };
            if route != CounterRoute::None {
                const ITERATIONS: u64 = 100_000;
                let mut acc = 0u64;
                // SAFETY: the PMU was just enabled on this core, at ring 0.
                let (out, cycles) = unsafe {
                    pmu.measure(|| {
                        for i in 0..ITERATIONS {
                            acc = acc.wrapping_add(i).rotate_left(3);
                        }
                        acc
                    })
                };
                core::hint::black_box(out);
                cycles_per_op = cycles.map(|c| c / ITERATIONS);
            }
        }

        const ROUNDS: u32 = 1024;
        let mut read_overhead = u64::MAX;
        let mut worst_read = 0;
        for _ in 0..ROUNDS {
            let a = crate::arch::counter_ordered();
            let b = crate::arch::counter_ordered();
            let d = b.wrapping_sub(a);
            read_overhead = read_overhead.min(d);
            worst_read = worst_read.max(d);
        }

        // SAFETY: forwarded from this function's own contract.
        let hypervisor = unsafe { crate::hypervisor::detect() };

        Machine {
            features: nanochrono_core::cpu::features(),
            pmu,
            route,
            cycles_per_op,
            read_overhead,
            worst_read,
            hypervisor,
            memory: Memory::default(),
            footprint: crate::multiboot::kernel_footprint(),
            acpi,
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A stopwatch, with the accumulator held redundantly.
///
/// [`Protected`](nanochrono_core::Protected) is not decoration here. This is a
/// machine with no operating system, no ECC scrubber and no memory manager:
/// a bit flipped by a cosmic ray in the accumulated total is a wrong
/// measurement that nothing else would ever notice. The value carries a
/// Hamming code and three replicas, so a single flip is corrected on read and
/// a double flip is reported rather than believed.
///
/// Every stored counter value is protected, not only the total: while a run
/// is in progress the total is usually zero and the reading is all
/// `started_at`, so a flip there is the one that matters. When each is
/// checked is [`SpaceMode`]'s decision, not this struct's.
struct Stopwatch {
    running: bool,
    /// Counter ticks banked from previous runs.
    accumulated: Protected,
    /// The counter when the current run started.
    started_at: Protected,
    laps: [Protected; Stopwatch::MAX_LAPS],
    lap_count: usize,
    /// The worst integrity verdict seen since the last reset.
    integrity: nanochrono_core::Integrity,
}

impl Stopwatch {
    const MAX_LAPS: usize = 6;

    fn new() -> Stopwatch {
        Stopwatch {
            running: false,
            accumulated: Protected::new(0),
            started_at: Protected::new(0),
            laps: [Protected::new(0); Stopwatch::MAX_LAPS],
            lap_count: 0,
            integrity: Integrity::Clean,
        }
    }

    /// Ticks elapsed. With `verify` the stored values are checked (and
    /// repaired) first; without it they are plain loads — see [`SpaceMode`].
    /// Returns the worst verdict of this read.
    fn ticks(&mut self, now: u64, verify: bool) -> (u64, Integrity) {
        let mut worst = Integrity::Clean;
        if verify {
            worst = self.accumulated.verify().max(self.started_at.verify());
            self.integrity = self.integrity.max(worst);
        }
        let banked = self.accumulated.get();
        let ticks = if self.running {
            banked + now.wrapping_sub(self.started_at.get())
        } else {
            banked
        };
        (ticks, worst)
    }

    /// Checks and repairs every stored value; the worst verdict.
    fn scrub(&mut self) -> Integrity {
        let mut worst = self.accumulated.verify().max(self.started_at.verify());
        for lap in &mut self.laps[..self.lap_count] {
            worst = worst.max(lap.verify());
        }
        self.integrity = self.integrity.max(worst);
        worst
    }

    /// Always verified: a pause writes the total back, and a flipped bit
    /// banked here would be re-encoded as good.
    fn toggle(&mut self, now: u64) -> Integrity {
        if self.running {
            let (banked, verdict) = self.ticks(now, true);
            self.accumulated.set(banked);
            self.running = false;
            verdict
        } else {
            self.started_at.set(now);
            self.running = true;
            Integrity::Clean
        }
    }

    fn reset(&mut self) {
        self.running = false;
        self.accumulated.set(0);
        self.started_at.set(0);
        self.lap_count = 0;
        self.laps = [Protected::new(0); Stopwatch::MAX_LAPS];
        self.integrity = Integrity::Clean;
    }

    /// Records a lap, dropping the oldest once the table is full. Verified,
    /// for the same reason as [`toggle`](Self::toggle).
    fn lap(&mut self, now: u64) -> Integrity {
        let (ticks, verdict) = self.ticks(now, true);
        if self.lap_count == Stopwatch::MAX_LAPS {
            self.laps.rotate_left(1);
            self.laps[Stopwatch::MAX_LAPS - 1].set(ticks);
        } else {
            self.laps[self.lap_count].set(ticks);
            self.lap_count += 1;
        }
        verdict
    }
}

/// A countdown.
struct Timer {
    running: bool,
    /// What it counts down from, in nanoseconds.
    target_ns: Protected,
    /// Counter ticks already spent.
    spent: Protected,
    started_at: Protected,
    /// Set when it reaches zero, cleared by a reset. What makes the readout
    /// go red and stay there rather than blinking past.
    expired: bool,
}

impl Timer {
    /// A minute, which is the length a timer with no keypad most often wants.
    const DEFAULT_NS: u64 = 60 * 1_000_000_000;
    /// How much a press of up or down moves the target.
    const STEP_NS: u64 = 10 * 1_000_000_000;

    fn new() -> Timer {
        Timer {
            running: false,
            target_ns: Protected::new(Timer::DEFAULT_NS),
            spent: Protected::new(0),
            started_at: Protected::new(0),
            expired: false,
        }
    }

    fn elapsed_ticks(&self, now: u64) -> u64 {
        if self.running {
            self.spent.get() + now.wrapping_sub(self.started_at.get())
        } else {
            self.spent.get()
        }
    }

    /// Checks and repairs every stored value; the worst verdict.
    fn scrub(&mut self) -> Integrity {
        self.target_ns
            .verify()
            .max(self.spent.verify())
            .max(self.started_at.verify())
    }

    /// Nanoseconds left, saturating at zero, and the verdict if `verify`.
    fn remaining_ns(&mut self, now: u64, clock: &Clock, verify: bool) -> (u64, Integrity) {
        let verdict = if verify { self.scrub() } else { Integrity::Clean };
        let spent = clock.calibration.ticks_to_ns(self.elapsed_ticks(now));
        let target = self.target_ns.get();
        if spent >= target {
            if self.running {
                // Stopped rather than left running past zero: the counter
                // would keep climbing and the display would be showing a
                // saturated number that is no longer measuring anything.
                // Verified first: this stores the total.
                let verdict = verdict.max(self.scrub());
                self.spent.set(self.elapsed_ticks(now));
                self.running = false;
                self.expired = true;
                return (0, verdict);
            }
            return (0, verdict);
        }
        (target - spent, verdict)
    }

    /// Verified, like the stopwatch's: a pause stores the total.
    fn toggle(&mut self, now: u64) -> Integrity {
        if self.expired {
            return Integrity::Clean;
        }
        if self.running {
            let verdict = self.scrub();
            self.spent.set(self.elapsed_ticks(now));
            self.running = false;
            verdict
        } else {
            self.started_at.set(now);
            self.running = true;
            Integrity::Clean
        }
    }

    fn reset(&mut self) {
        self.running = false;
        self.spent.set(0);
        self.expired = false;
    }

    fn adjust(&mut self, up: bool) {
        if self.running {
            return;
        }
        let target = self.target_ns.get();
        self.target_ns.set(if up {
            target.saturating_add(Timer::STEP_NS)
        } else {
            target.saturating_sub(Timer::STEP_NS).max(Timer::STEP_NS)
        });
        self.expired = false;
        self.spent.set(0);
    }
}

/// One control that can be clicked and can light up under the pointer.
#[derive(Clone, Copy, Default)]
struct Control {
    box_: Hitbox,
    /// How lit it is, 0 to 1000. A tween rather than a flag, which is the
    /// difference between a control that responds and one that switches.
    highlight: Tween,
}

impl Control {
    fn new() -> Control {
        Control {
            box_: Hitbox::default(),
            highlight: Tween::with_rate(0, 200),
        }
    }

    /// Aims the highlight at where it should be for this state, and steps it.
    fn step(&mut self, hovered: bool, selected: bool) -> bool {
        self.highlight.retarget(if selected {
            1000
        } else if hovered {
            420
        } else {
            0
        });
        self.highlight.step()
    }

    fn colour(&self, p: &Palette) -> Colour {
        let t = self.highlight.value().clamp(0, 1000) as u32;
        if t <= 420 {
            draw::mix_colour(p.panel, p.hover, t * 1000 / 420)
        } else {
            draw::mix_colour(p.hover, p.accent, (t - 420) * 1000 / 580)
        }
    }

    fn label_colour(&self, p: &Palette) -> Colour {
        let t = self.highlight.value().clamp(0, 1000) as u32;
        // The selected chip's background is the accent, so its label has to
        // go dark or it disappears into it.
        draw::mix_colour(p.text, p.background, t)
    }
}

/// Everything that changes.
struct Ui {
    tab: Tab,
    panel: Panel,
    precision: Precision,

    stopwatch: Stopwatch,
    timer: Timer,

    /// The tab controls, the panel chips, the precision toggle and the two
    /// title-bar buttons.
    tabs: [Control; 4],
    chips: [Control; 8],
    precision_chip: Control,
    restart: Control,
    shutdown: Control,

    /// Where the selected tab's underline is, sliding between tabs.
    underline_x: Tween,
    underline_w: Tween,

    /// The two status meters, easing towards their readings.
    memory_meter: Tween,
    load_meter: Tween,

    /// How faded in the readout and the cards are. Restarted on a tab or
    /// panel change, which is what makes a switch read as a transition rather
    /// than a repaint.
    readout_fade: Tween,
    cards_fade: Tween,

    /// What to say instead of the key legend, when a stack came up short.
    input_note: Option<&'static str>,

    /// Set when something changed a label in the tab row without moving any
    /// of its highlights. The row is only repainted when it moved, which is
    /// what keeps it off the frame budget — but the precision chip's *text*
    /// changes with no motion at all, so it needs a way to ask.
    chrome_dirty: bool,
    /// The same for the cards, whose contents change with the session state.
    /// Separate from the fade because starting a stopwatch should update the
    /// card, not replay the transition every time the space bar is pressed.
    cards_dirty: bool,

    cursor: Cursor,
    pointer_x: i32,
    pointer_y: i32,

    /// Counter ticks spent drawing in the current second, and the total the
    /// second covered, which together are the only honest "CPU" figure a
    /// kernel with no scheduler can report.
    busy_ticks: u64,
    window_ticks: u64,
    window_started: u64,
    load_permille: u32,

    /// What the readout showed last frame, so an unchanged one is not
    /// redrawn.
    last_readout: Text<24>,
    last_header_clock: Text<24>,
    last_load: Text<8>,

    /// The task manager's figures, refreshed once a second.
    stats: TaskStats,
    /// The outcome of the last re-probe request (HYPERVISOR panel).
    reprobe_status: Text<32>,

    /// The code a restart or power-off waits for. See
    /// [`nanochrono_core::power_confirm`]: one key must not be enough,
    /// because one key is what a BadUSB presses.
    power: Confirm,
    /// When stored state is checked for flipped bits. See
    /// [`nanochrono_core::space_mode`].
    space: SpaceMode,
    /// The counter against the PM timer and the RTC.
    checks: Option<ClockChecks>,
    /// Cycles and instructions over the stopwatch's runs.
    stopwatch_pmu: PmuTally,
    /// The benchmark tab's last results, and a run asked for.
    bench: crate::bench::Results,
    bench_requested: bool,
    bench_dirty: bool,
    /// What the key legend showed last, per [`hint_signature`], so it is
    /// repainted when the prompt or its countdown changes and not otherwise.
    hint_state: u64,
}

/// What the core did while the stopwatch ran: cycles and instructions from
/// the PMU, summed over every run between reset and now.
///
/// Read at start and stop, and folded once a frame while running — never
/// inside a measurement, only after the counter has been read. The frame
/// fold is what keeps a narrow counter honest: AArch64 counts instructions
/// in 32 bits, which wrap several times a second at full speed, and a delta
/// taken across more than one wrap is wrong. The counts are the whole
/// core's, the interface's own drawing included.
#[derive(Clone, Copy, Default)]
struct PmuTally {
    running: bool,
    last_cycles: Option<u64>,
    last_instructions: Option<u64>,
    cycles: u64,
    instructions: u64,
    cycles_width: u8,
    instructions_width: u8,
    /// Whether any reading ever arrived, for the card to say so.
    counted: bool,
}

/// `b - a` for a counter `width` bits wide, across at most one wrap.
fn counter_delta(a: u64, b: u64, width: u8) -> u64 {
    let d = b.wrapping_sub(a);
    if width == 0 || width >= 64 { d } else { d & ((1u64 << width) - 1) }
}

impl PmuTally {
    /// # Safety
    /// Ring 0 / EL1; the PMU was enabled by `CorePmu::enable`.
    unsafe fn read(pmu: &CorePmu) -> (Option<u64>, Option<u64>) {
        if pmu.route == CounterRoute::None {
            return (None, None);
        }
        // SAFETY: forwarded from this function's own contract.
        unsafe { (pmu.read_cycles().map(|r| r.value), pmu.read_instructions().map(|r| r.value)) }
    }

    /// # Safety
    /// As [`read`](Self::read).
    unsafe fn start(&mut self, pmu: &CorePmu) {
        // SAFETY: forwarded.
        let (c, i) = unsafe { Self::read(pmu) };
        self.last_cycles = c;
        self.last_instructions = i;
        self.cycles_width = match pmu.route {
            CounterRoute::General(_) => pmu.leaf.general_width,
            _ => pmu.leaf.fixed_width,
        };
        self.instructions_width =
            if cfg!(target_arch = "aarch64") { 32 } else { pmu.leaf.fixed_width };
        self.running = true;
    }

    /// Adds what was counted since the last read.
    ///
    /// # Safety
    /// As [`read`](Self::read).
    unsafe fn fold(&mut self, pmu: &CorePmu) {
        if !self.running {
            return;
        }
        // SAFETY: forwarded.
        let (c, i) = unsafe { Self::read(pmu) };
        if let (Some(a), Some(b)) = (self.last_cycles, c) {
            self.cycles += counter_delta(a, b, self.cycles_width);
            self.counted = true;
        }
        if let (Some(a), Some(b)) = (self.last_instructions, i) {
            self.instructions += counter_delta(a, b, self.instructions_width);
        }
        self.last_cycles = c;
        self.last_instructions = i;
    }

    /// # Safety
    /// As [`read`](Self::read).
    unsafe fn stop(&mut self, pmu: &CorePmu) {
        // SAFETY: forwarded.
        unsafe { self.fold(pmu) };
        self.running = false;
    }

    fn reset(&mut self) {
        *self = PmuTally::default();
    }
}

/// The counter checked against two clocks that do not share its failure
/// modes. See [`nanochrono_core::crosscheck`].
///
/// - The ACPI PM timer: its own counter at 3.579545 MHz. Read back to back
///   with the counter once a second, so a pairing is good to a microsecond
///   or two and a rate is judged within a minute.
/// - The RTC: its own 32.768 kHz crystal, the one clock here that shares no
///   oscillator with anything else. It only says when a second changes, so
///   its seconds register is polled — and only in a window around the
///   expected change, not all the time. Coarser, so it takes longer to judge
///   a rate; it catches steps from the first seconds.
struct ClockChecks {
    pm: Option<(CrossCheck, Unwrap, (u16, bool))>,
    rtc: CrossCheck,
    rtc_last: Option<u8>,
    rtc_edges: u64,
    /// When to start polling for the next RTC edge (ns since start).
    rtc_poll_from: u64,
}

/// How early before the expected RTC edge polling starts.
const RTC_WINDOW_NS: u64 = 50_000_000;
/// The pacing loop's longest idle slice: the RTC edge's timing uncertainty.
const RTC_POLL_NS: u64 = 2_000_000;

impl ClockChecks {
    fn new(hz: u64, acpi: Option<&acpi::PowerRegisters>) -> ClockChecks {
        ClockChecks {
            // The ACPI PM timer is an x86 fixture; elsewhere there is none.
            #[cfg(x86_any)]
            pm: acpi.and_then(|a| a.pm_timer).map(|timer| {
                (
                    CrossCheck::new(hz, acpi::PM_TIMER_HZ, 200, 2_000),
                    Unwrap::new(if timer.1 { 32 } else { 24 }),
                    timer,
                )
            }),
            #[cfg(not(x86_any))]
            pm: {
                let _ = (hz, acpi);
                None
            },
            rtc: CrossCheck::new(hz, 1, 500, RTC_POLL_NS),
            rtc_last: None,
            rtc_edges: 0,
            rtc_poll_from: 0,
        }
    }

    /// One PM-timer pairing. Once a second: the 24-bit timer wraps every
    /// 4.7 s, and nothing is gained by more.
    ///
    /// # Safety
    /// Port I/O; requires ring 0.
    unsafe fn sample_pm(&mut self) -> Option<Verdict> {
        let (check, unwrap, timer) = self.pm.as_mut()?;
        let before = crate::arch::counter_ordered();
        // SAFETY: forwarded from this function's own contract.
        #[cfg(x86_any)]
        let raw = unsafe { acpi::read_pm_timer(*timer) };
        #[cfg(not(x86_any))]
        let raw: u32 = {
            let _ = timer;
            0
        };
        let after = crate::arch::counter_ordered();
        let reference = unwrap.feed(raw as u64);
        Some(check.sample(before + after.wrapping_sub(before) / 2, reference))
    }

    /// Looks for an RTC edge, if one is due. Returns whether it sampled.
    ///
    /// # Safety
    /// Port I/O; requires ring 0.
    unsafe fn poll_rtc(&mut self, now_ns: u64) -> bool {
        if now_ns < self.rtc_poll_from {
            return false;
        }
        // SAFETY: forwarded from this function's own contract.
        let Some(second) = (unsafe { crate::clock::rtc_second_raw() }) else {
            return false;
        };
        let counter = crate::arch::counter_ordered();
        let changed = self.rtc_last.is_some_and(|last| last != second);
        self.rtc_last = Some(second);
        if !changed {
            return false;
        }
        self.rtc_edges += 1;
        self.rtc.sample(counter, self.rtc_edges);
        self.rtc_poll_from = now_ns + 1_000_000_000 - RTC_WINDOW_NS;
        true
    }
}

/// The instruction set this kernel was built for, with the name people
/// search for next to the formal one.
const ARCHITECTURE: &str = if cfg!(target_arch = "x86_64") {
    "x86_64 (x64)"
} else if cfg!(target_arch = "x86") {
    "i386 (x86, 32-bit)"
} else if cfg!(target_arch = "aarch64") {
    "aarch64 (arm64)"
} else if cfg!(target_arch = "arm") {
    "arm32 (armv7-a)"
} else if cfg!(all(target_arch = "powerpc64", target_endian = "little")) {
    "ppc64le (power, little-endian)"
} else if cfg!(target_arch = "powerpc64") {
    "ppc64 (power, big-endian)"
} else if cfg!(target_arch = "powerpc") {
    "ppc (32-bit)"
} else if cfg!(target_arch = "riscv64") {
    "riscv64 (rv64gc)"
} else if cfg!(target_arch = "riscv32") {
    "riscv32 (rv32imac)"
} else {
    "unknown"
};

/// How this architecture turns itself off, for the machine card.
const POWER_MECHANISM: &str = if cfg!(x86_any) {
    "acpi"
} else if cfg!(any(target_arch = "aarch64", target_arch = "arm")) {
    "psci"
} else if cfg!(any(target_arch = "riscv32", target_arch = "riscv64")) {
    "sbi srst"
} else {
    "opal"
};

/// What the TASKS panel shows: the last second, per [`crate::cpuload`].
#[derive(Default, Clone, Copy)]
struct TaskStats {
    load: crate::cpuload::Load,
    ticks: [u64; 5],
}

impl Ui {
    fn new() -> Ui {
        Ui {
            tab: Tab::Stopwatch,
            panel: Panel::Cpu,
            precision: Precision::Nano,
            stopwatch: Stopwatch::new(),
            timer: Timer::new(),
            tabs: [Control::new(); 4],
            chips: [Control::new(); 8],
            precision_chip: Control::new(),
            restart: Control::new(),
            shutdown: Control::new(),
            underline_x: Tween::with_rate(0, 180),
            underline_w: Tween::with_rate(0, 180),
            memory_meter: Tween::with_rate(0, 90),
            load_meter: Tween::with_rate(0, 90),
            readout_fade: Tween::with_rate(1000, 130),
            cards_fade: Tween::with_rate(1000, 110),
            input_note: None,
            chrome_dirty: false,
            cards_dirty: false,
            cursor: Cursor::new(),
            pointer_x: 0,
            pointer_y: 0,
            busy_ticks: 0,
            window_ticks: 0,
            window_started: 0,
            load_permille: 0,
            last_readout: Text::new(),
            last_header_clock: Text::new(),
            last_load: Text::new(),
            stats: TaskStats::default(),
            reprobe_status: Text::new(),
            power: Confirm::new(),
            space: SpaceMode::new(),
            checks: None,
            stopwatch_pmu: PmuTally::default(),
            bench: crate::bench::Results::new(),
            bench_requested: false,
            bench_dirty: true,
            hint_state: 0,
        }
    }

    /// Feeds a verified read's (or a scrub's) verdict to the space-mode
    /// policy, and repaints what reports it when the mode changes.
    fn note_integrity(&mut self, verdict: Integrity, now_ns: u64) {
        self.record_integrity(verdict, now_ns, false);
    }

    fn record_integrity(&mut self, verdict: Integrity, now_ns: u64, was_scrub: bool) {
        let before = (self.space.mode(), self.space.unrecoverable(), self.space.detections());
        self.space.record(verdict, now_ns, was_scrub);
        if before != (self.space.mode(), self.space.unrecoverable(), self.space.detections()) {
            self.cards_dirty = true;
        }
    }

    /// Restarts the readout's fade-in. Called when what it shows changes
    /// kind, not when its digits change.
    fn transition_readout(&mut self) {
        self.readout_fade = Tween::with_rate(0, 130);
        self.readout_fade.retarget(1000);
        self.last_readout.clear();
    }

    fn transition_cards(&mut self) {
        self.cards_fade = Tween::with_rate(0, 110);
        self.cards_fade.retarget(1000);
        self.cards_dirty = true;
    }

    /// Redraws the cards without replaying the fade.
    ///
    /// For a state change the cards report — starting the stopwatch,
    /// adjusting the timer — where the card is stale but nothing has
    /// *arrived*. A fade on every keypress reads as a stutter rather than as
    /// motion.
    fn refresh_cards(&mut self) {
        self.cards_dirty = true;
    }

    fn select_tab(&mut self, tab: Tab) {
        if self.tab == tab {
            return;
        }
        self.tab = tab;
        self.transition_readout();
        // The session card reports the selected mode, so it changes with the
        // tab. Without this the stopwatch's laps stay on screen under the
        // timer's readout, which is worse than a stale number: it is a
        // reading attached to the wrong instrument.
        self.transition_cards();
    }

    /// Switches between the full and the abbreviated readout.
    fn toggle_precision(&mut self) {
        self.precision = match self.precision {
            Precision::Nano => Precision::Simple,
            Precision::Simple => Precision::Nano,
        };
        self.chrome_dirty = true;
        self.transition_readout();
        // The header clock is drawn at the same precision, and it is only
        // repainted when its text changes — which it would not, for the
        // fraction of a second in which the seconds field has not ticked.
        self.last_header_clock.clear();
    }

    fn select_panel(&mut self, panel: Panel) {
        if self.panel == panel {
            return;
        }
        self.panel = panel;
        self.transition_cards();
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// Draws the interface and drives it. Never returns.
///
/// # Safety
/// Reads I/O ports, programs the PMU and writes the framebuffer; requires
/// ring 0.
pub unsafe fn run(fb: &Framebuffer, memory: Memory) -> ! {
    use crate::progress::{self, Phase};

    let p = Palette::APP;

    // SAFETY: forwarded from this function's own contract. Calibrating the
    // counter comes first: everything below is timed by it, including the
    // frame pacing of this loop.
    let clock = unsafe { Clock::start() };

    // SAFETY: as above.
    let mut machine = unsafe { Machine::probe() };
    machine.memory = memory;

    progress::enter(Phase::Interface);

    let layout = Layout::for_screen(fb);
    let mut ui = Ui::new();
    // Centred, the way a display server places a cursor. Set on the cursor as
    // well as on the pointer: they are separate because the cursor remembers
    // where it was last *drawn*, and leaving that at the origin is how a
    // cursor ends up invisible under the header.
    ui.pointer_x = fb.width as i32 / 2;
    ui.pointer_y = fb.height as i32 / 2;
    ui.cursor.move_to(ui.pointer_x, ui.pointer_y);
    ui.window_started = clock.elapsed_ticks();
    ui.checks = Some(ClockChecks::new(clock.calibration.hz, machine.acpi.as_ref()));

    // The first frame is a full repaint; everything after it is regional.
    fb.clear(p.background);
    header(fb, &p, &layout, &mut ui, &machine);
    tab_bar(fb, &p, &layout, &mut ui);
    hint_bar(fb, &p, &layout, &mut ui, clock.elapsed_ns());
    status_frame(fb, &p, &layout);

    // **Painted before the input stacks are brought up, not after.**
    //
    // Finding a keyboard, enumerating USB and reading a touchpad out of the
    // firmware's AML are all things that can take time or fail slowly on real
    // hardware — a controller that never leaves reset, a device that never
    // answers. Doing them first means a machine where one of them stalls
    // shows nothing at all, which is indistinguishable from a kernel that
    // never started. Now the interface is up first and says what it is doing.
    draw::text_centred(
        fb,
        &HEADING,
        layout.readout_x,
        layout.readout_w,
        layout.readout_y + layout.readout_h / 2,
        "detecting input devices",
        p.muted,
    );
    fb.present(0, 0, fb.width, fb.height);
    fb.discard_damage();

    // SAFETY: as above. A microsecond's worth of counter ticks, so the I2C
    // driver's timeouts are denominated in time rather than in loop
    // iterations — see `i2c`.
    let mut input = unsafe { Input::init(clock.calibration.hz / 1_000_000) };

    // If a stack came up short, open on the panel that says which. The
    // diagnosis was previously behind a keypress, which is no use at all on
    // the one machine that most needs it: the keyboard is what did not work.
    if !input.has_keyboard() || !input.has_pointer() {
        ui.panel = Panel::Usb;
        ui.input_note = Some(input.trouble());
        // The legend was drawn before the probe, when there was nothing yet
        // to say about it.
        hint_bar(fb, &p, &layout, &mut ui, clock.elapsed_ns());
        fb.present_damage();
    }

    // No `leave` for this phase: the interface being on screen *is* the
    // evidence it finished, and painting a marker over a finished frame
    // leaves a square on the header.

    ui.transition_readout();
    ui.transition_cards();

    // The task manager's data: activity counters (APERF/MPERF where the CPU
    // has them), the PMU the machine probe already enabled, and a real idle
    // wait between frames — see `cpuload`.
    // SAFETY: ring 0, once, on the only running core.
    unsafe { crate::cpuload::init() };
    let pmu_for_load = (machine.route != CounterRoute::None).then_some(&machine.pmu);
    // SAFETY: as above.
    let mut load_sample = unsafe { crate::cpuload::sample(pmu_for_load) };

    let mut next_frame = 0u64;

    loop {
        // --- input, bounded so a moving pointer cannot starve the draw
        crate::cpuload::switch_to(crate::cpuload::Task::Input);
        for _ in 0..EVENTS_PER_FRAME {
            // SAFETY: forwarded from this function's own contract.
            let Some(event) = (unsafe { input.poll() }) else {
                break;
            };
            // SAFETY: as above; the handler can power the machine off.
            unsafe { handle(event, &mut ui, fb, &p, &layout, &clock, &machine) };
        }

        // --- pacing
        let now_ns = clock.elapsed_ns();
        // The RTC edge search runs at the pacing loop's rate, not the frame
        // rate, so the edge is placed to within one idle slice.
        if let Some(checks) = ui.checks.as_mut() {
            // SAFETY: CPL 0.
            if unsafe { checks.poll_rtc(now_ns) } && ui.panel == Panel::Counter {
                ui.cards_dirty = true;
            }
        }
        if now_ns < next_frame {
            // A real wait (TPAUSE where the CPU has WAITPKG), in slices of at
            // most 2 ms so input is still polled promptly.
            let wait = (next_frame - now_ns).min(2_000_000);
            crate::cpuload::idle_until(
                crate::arch::counter_ordered().wrapping_add(clock.calibration.ns_to_ticks(wait)),
            );
            continue;
        }
        // Set from the current time rather than incremented, so a frame that
        // overran does not leave the loop trying to catch up with a burst of
        // frames it cannot draw either.
        next_frame = now_ns + FRAME_NS;

        // --- the space-mode scrub: once a second in Normal mode, never inside
        // a measurement (every counter read above has already happened).
        if ui.stopwatch_pmu.running {
            // SAFETY: ring 0; the PMU was enabled at probe.
            unsafe { ui.stopwatch_pmu.fold(&machine.pmu) };
        }
        if core::mem::take(&mut ui.bench_requested) {
            // Said before the few seconds of silence the run takes.
            let top = layout.tabs_y + layout.tabs_h + 8;
            fb.fill(0, top, layout.width, layout.cards_y.saturating_sub(top + 8), p.background);
            draw::text_centred(fb, &HEADING, layout.readout_x, layout.readout_w,
                (top + layout.cards_y) / 2, "running the benchmarks...", p.muted);
            fb.present_damage();
            // SAFETY: ring 0 / EL1 / supervisor, which the kernels and PMU need.
            unsafe { crate::bench::run_all(clock.calibration.hz, &machine.pmu, &mut ui.bench) };
            ui.bench_dirty = true;
            ui.refresh_cards();
        }
        if ui.space.scrub_due(now_ns) {
            let worst = ui.stopwatch.scrub().max(ui.timer.scrub());
            ui.record_integrity(worst, now_ns, true);
        }

        let frame_start = clock.elapsed_ticks();
        crate::cpuload::switch_to(crate::cpuload::Task::Render);

        // --- the frame
        if input.has_pointer() {
            ui.cursor.erase(fb);
            present(fb);
        }

        header_clock(fb, &p, &layout, &mut ui, &clock);
        present(fb);

        if tab_bar(fb, &p, &layout, &mut ui) {
            present(fb);
        }

        readout(fb, &p, &layout, &mut ui, &clock);
        present(fb);

        if core::mem::take(&mut ui.cards_dirty) | !ui.cards_fade.settled() {
            ui.cards_fade.step();
            cards(fb, &p, &layout, &mut ui, &machine, &clock, &input);
            present(fb);
        }

        status_bar(fb, &p, &layout, &mut ui, &machine, &clock, &input);
        present(fb);

        if hint_signature(&ui, clock.elapsed_ns()) != ui.hint_state {
            hint_bar(fb, &p, &layout, &mut ui, clock.elapsed_ns());
            present(fb);
        }

        if input.has_pointer() {
            ui.cursor.draw(fb, &p);
            present(fb);
        }

        // --- how much of the frame was spent drawing
        let spent = clock.elapsed_ticks().wrapping_sub(frame_start);
        ui.busy_ticks += spent;
        let elapsed = clock.elapsed_ticks().wrapping_sub(ui.window_started);
        crate::cpuload::switch_to(crate::cpuload::Task::Measure);
        if elapsed >= clock.calibration.hz {
            // SAFETY: as at `cpuload::init`.
            let sample = unsafe { crate::cpuload::sample(pmu_for_load) };
            ui.stats = TaskStats {
                load: crate::cpuload::between(&load_sample, &sample, clock.calibration.hz),
                ticks: crate::cpuload::take_task_ticks(),
            };
            load_sample = sample;
            if let Some(checks) = ui.checks.as_mut() {
                // SAFETY: CPL 0.
                unsafe { checks.sample_pm() };
            }
            // The re-probe countdown ticks once a second too, and so do the
            // clock cross-checks.
            if ui.panel == Panel::Tasks
                || ui.panel == Panel::Counter
                || (ui.panel == Panel::Hypervisor
                    && crate::hypervisor::reprobe_wait_s(clock.calibration.hz) > 0)
            {
                ui.cards_dirty = true;
            }
            ui.window_ticks = elapsed;
            ui.load_permille = (ui.busy_ticks * 1000 / elapsed.max(1)).min(1000) as u32;
            ui.busy_ticks = 0;
            ui.window_started = clock.elapsed_ticks();
        }
    }
}

/// Copies the damaged region out, charged to the "present" task.
fn present(fb: &Framebuffer) {
    crate::cpuload::switch_to(crate::cpuload::Task::Present);
    fb.present_damage();
    crate::cpuload::switch_to(crate::cpuload::Task::Render);
}

/// Acts on one input event.
///
/// # Safety
/// May restart or power off the machine through ACPI; requires ring 0.
unsafe fn handle(
    event: Event,
    ui: &mut Ui,
    fb: &Framebuffer,
    p: &Palette,
    layout: &Layout,
    clock: &Clock,
    machine: &Machine,
) {
    let now = clock.elapsed_ticks();

    // The input panel shows the raw bytes the 8042 delivered, so it has to be
    // repainted when another one arrives. This is the one place where a
    // keypress that binds to nothing still has to change the screen — on a
    // machine where keys appear to do nothing, seeing the byte is the answer.
    if matches!(event, Event::Key(_)) && ui.panel == Panel::Usb {
        ui.refresh_cards();
    }

    // Every event's arrival time goes into the confirmation's pool: the
    // nanosecond a human or a USB poll lands on is not something a script
    // typing blind can choose.
    ui.power.stir(crate::arch::counter_ordered() ^ hw_entropy());
    let now_ns = clock.elapsed_ns();

    // While a code is on screen every key belongs to it: digits answer, Esc
    // cancels, anything else cancels too — a script that fires its next
    // binding has not answered, and must not reach that binding either.
    if ui.power.is_pending(now_ns) {
        if let Event::Key(k) = event {
            if k.pressed {
                match digit_of(k.scancode) {
                    Some(d) => match ui.power.digit(d, now_ns) {
                        // SAFETY: forwarded from this function's own contract.
                        Outcome::Confirmed(action) => unsafe { carry_out(action, fb, p, layout, machine) },
                        Outcome::Pending | Outcome::Rejected | Outcome::Idle => {}
                    },
                    None => ui.power.cancel(),
                }
            }
            return;
        }
    }

    match event {
        Event::Key(k) if k.pressed => match k.scancode {
            SCAN_R => request_power(ui, Action::Restart, now_ns),
            SCAN_S => request_power(ui, Action::Shutdown, now_ns),
            SCAN_ESC => ui.power.cancel(),
            SCAN_1 | SCAN_C => ui.select_tab(Tab::Clock),
            SCAN_2 => ui.select_tab(Tab::Stopwatch),
            SCAN_3 => ui.select_tab(Tab::Timer),
            SCAN_4 => ui.select_tab(Tab::Bench),
            SCAN_SPACE | SCAN_P => {
                let verdict = match ui.tab {
                    Tab::Stopwatch => ui.stopwatch.toggle(now),
                    Tab::Timer => ui.timer.toggle(now),
                    Tab::Clock => Integrity::Clean,
                    Tab::Bench => {
                        ui.bench_requested = true;
                        Integrity::Clean
                    }
                };
                // SAFETY: ring 0; the PMU was enabled at probe.
                unsafe { sync_stopwatch_pmu(ui, machine) };
                ui.note_integrity(verdict, now_ns);
                ui.refresh_cards();
            }
            SCAN_L if ui.tab == Tab::Stopwatch => {
                let verdict = ui.stopwatch.lap(now);
                ui.note_integrity(verdict, now_ns);
                ui.transition_cards();
            }
            SCAN_Z => match ui.tab {
                Tab::Stopwatch => {
                    ui.stopwatch.reset();
                    ui.stopwatch_pmu.reset();
                    // The damaged state is gone; so is the reason to latch.
                    ui.space.clear_unrecoverable();
                    ui.transition_cards();
                }
                Tab::Timer => {
                    ui.timer.reset();
                    ui.refresh_cards();
                }
                Tab::Bench => {
                    ui.bench = crate::bench::Results::new();
                    ui.bench_dirty = true;
                    ui.refresh_cards();
                }
                Tab::Clock => {}
            },
            SCAN_UP if ui.tab == Tab::Timer => {
                ui.timer.adjust(true);
                ui.refresh_cards();
            }
            SCAN_DOWN if ui.tab == Tab::Timer => {
                ui.timer.adjust(false);
                ui.refresh_cards();
            }
            SCAN_N => ui.toggle_precision(),
            // The panel chips, by initial where each is unambiguous.
            SCAN_B => ui.select_panel(Panel::Pmu),
            SCAN_M => ui.select_panel(Panel::Memory),
            SCAN_U => ui.select_panel(Panel::Usb),
            SCAN_H => ui.select_panel(Panel::Hypervisor),
            SCAN_T => ui.select_panel(Panel::Tasks),
            SCAN_G => ui.select_panel(Panel::Settings),
            // Re-probe the hypervisor: the one way to repeat the boot-time
            // negotiation, behind the cooldown. See `crate::hypervisor`.
            SCAN_V => {
                ui.reprobe_status.clear();
                // SAFETY: forwarded from this function's own contract (ring 0).
                match unsafe { crate::hypervisor::reprobe(clock.calibration.hz) } {
                    Ok(_) => {
                        ui.reprobe_status.str("re-probed");
                    }
                    Err(left) => {
                        ui.reprobe_status.str("wait ").num(left as u64).str(" s (cooldown)");
                    }
                }
                ui.select_panel(Panel::Hypervisor);
                ui.refresh_cards();
            }
            SCAN_K if ui.panel == Panel::Settings => {
                crate::hypervisor::set_cooldown_enabled(!crate::hypervisor::cooldown_enabled());
                ui.refresh_cards();
            }
            SCAN_TAB => {
                let next = Panel::ALL
                    .iter()
                    .position(|&panel| panel == ui.panel)
                    .map_or(0, |i| (i + 1) % Panel::ALL.len());
                ui.select_panel(Panel::ALL[next]);
            }
            _ => {}
        },
        Event::Key(_) => {}
        Event::Motion(m) => {
            pointer(m, ui, fb, layout, clock, machine)
        }
    }
}

/// Moves the cursor and acts on a click. The power buttons only ask for a
/// code; nothing here restarts or powers off.
fn pointer(m: Motion, ui: &mut Ui, fb: &Framebuffer, layout: &Layout, clock: &Clock, machine: &Machine) {
    // Clamped rather than wrapped: a cursor that leaves one edge and appears
    // at the other is not a cursor.
    //
    // Saturating: the delta is whatever the device put in its report — a
    // 32-bit HID field from a hostile device can hold i32::MAX — and the
    // bounds are floored at zero so a zero-sized mode cannot hand `clamp`
    // an inverted range, which panics.
    let max_x = (fb.width as i32).saturating_sub(1).max(0);
    let max_y = (fb.height as i32).saturating_sub(1).max(0);
    ui.pointer_x = ui.pointer_x.saturating_add(m.dx).clamp(0, max_x);
    ui.pointer_y = ui.pointer_y.saturating_add(m.dy).clamp(0, max_y);
    ui.cursor.move_to(ui.pointer_x, ui.pointer_y);

    if !m.left {
        return;
    }
    let (x, y) = (ui.pointer_x, ui.pointer_y);

    // A click is as easy to inject as a key — a BadUSB can be a mouse and
    // the buttons sit at fixed places — so it asks for the code too.
    let now_ns = clock.elapsed_ns();
    if ui.restart.box_.contains(x, y) {
        request_power(ui, Action::Restart, now_ns);
        return;
    }
    if ui.shutdown.box_.contains(x, y) {
        request_power(ui, Action::Shutdown, now_ns);
        return;
    }
    // Clicking anywhere else walks away from a pending code.
    ui.power.cancel();
    for (i, tab) in Tab::ALL.iter().enumerate() {
        if ui.tabs[i].box_.contains(x, y) {
            ui.select_tab(*tab);
        }
    }
    for (i, panel) in Panel::ALL.iter().enumerate() {
        if ui.chips[i].box_.contains(x, y) {
            ui.select_panel(*panel);
        }
    }
    if ui.precision_chip.box_.contains(x, y) {
        ui.toggle_precision();
    }
    // Clicking the readout starts and stops it, the way a stopwatch face
    // does. The largest target on screen for the action it is most likely to
    // be asked for.
    let readout_box = Hitbox {
        x: layout.readout_x,
        y: layout.readout_y,
        w: layout.readout_w,
        h: layout.readout_h,
    };
    if readout_box.contains(x, y) {
        let now = clock.elapsed_ticks();
        let verdict = match ui.tab {
            Tab::Stopwatch => ui.stopwatch.toggle(now),
            Tab::Timer => ui.timer.toggle(now),
            Tab::Clock => Integrity::Clean,
            Tab::Bench => {
                ui.bench_requested = true;
                Integrity::Clean
            }
        };
        // SAFETY: ring 0; the PMU was enabled at probe.
        unsafe { sync_stopwatch_pmu(ui, machine) };
        ui.note_integrity(verdict, now_ns);
        ui.refresh_cards();
    }
}

/// What the key legend would show at `now_ns`, reduced to a number: equal
/// numbers draw the same pixels. Bit 63: a code is pending (with its action,
/// digits typed and seconds left); bit 62: locked out (with seconds left).
fn hint_signature(ui: &Ui, now_ns: u64) -> u64 {
    if let Some((action, _, typed)) = ui.power.shown(now_ns) {
        let left = ui.power.remaining_ns(now_ns).unwrap_or(0).div_ceil(1_000_000_000);
        return 1 << 63 | (action as u64) << 40 | (typed as u64) << 32 | left;
    }
    let locked = ui.power.lockout_remaining_ns(now_ns).div_ceil(1_000_000_000);
    if locked > 0 {
        return 1 << 62 | locked;
    }
    0
}

/// "agree +3 ppm", "DRIFT -812 ppm", "STEP +5000 us (2 steps)", "absent".
fn cross_label(check: Option<CrossCheck>) -> Text<40> {
    let mut out = Text::<40>::new();
    let Some(check) = check else {
        out.str("absent");
        return out;
    };
    let signed = |out: &mut Text<40>, v: i64| {
        out.str(if v < 0 { "-" } else { "+" }).num(v.unsigned_abs());
    };
    match check.verdict() {
        Verdict::Warming => {
            out.str("warming up");
        }
        Verdict::Agree { ppm } | Verdict::Drift { ppm } => {
            out.str(check.verdict().name()).str(" ");
            signed(&mut out, ppm);
            out.str(" ppm");
        }
        Verdict::Step { ns } => {
            out.str("STEP ");
            signed(&mut out, ns / 1000);
            out.str(" us");
        }
    }
    if check.steps() > 0 {
        out.str(" (").num(check.steps() as u64).str(" steps)");
    }
    out
}

/// The PMU's part of the stopwatch card: what the core did during the runs.
#[allow(clippy::too_many_arguments)]
fn pmu_rows(
    fb: &Framebuffer,
    p: &Palette,
    x: u32,
    w: u32,
    y: &mut u32,
    ui: &mut Ui,
    clock: &Clock,
    machine: &Machine,
) {
    let t = ui.stopwatch_pmu;
    if machine.route == CounterRoute::None {
        // Said plainly: no architected PMU (TCG), or a hypervisor that does
        // not pass one through (KVM with enable_pmu=N).
        *y = row(fb, p, x, w, *y, "pmu", "unavailable - time only");
        return;
    }
    if !t.counted {
        *y = row(fb, p, x, w, *y, "pmu", "counts cycles while running");
        return;
    }
    let mut cycles = Text::<24>::new();
    cycles.num(t.cycles);
    *y = row(fb, p, x, w, *y, "core cycles", cycles.as_str());
    if t.instructions > 0 {
        let mut instr = Text::<24>::new();
        instr.num(t.instructions);
        *y = row(fb, p, x, w, *y, "instructions", instr.as_str());
        let mut ipc = Text::<16>::new();
        ipc.fixed(t.instructions * 100 / t.cycles.max(1), 2);
        *y = row(fb, p, x, w, *y, "ipc", ipc.as_str());
    }
    // Cycles over the time the stopwatch shows: the clock the core actually
    // ran at during the runs, turbo and throttling included.
    let now = clock.elapsed_ticks();
    let (ticks, _) = ui.stopwatch.ticks(now, false);
    let ns = clock.calibration.ticks_to_ns(ticks);
    if ns > 0 {
        let mut ghz = Text::<16>::new();
        ghz.fixed((t.cycles as u128 * 1000 / ns as u128) as u64, 3).str(" GHz");
        *y = row(fb, p, x, w, *y, "effective clock", ghz.as_str());
    }
}

/// The benchmark results, in the space the readout uses, three groups side
/// by side. Redrawn only when they change.
fn bench_view(fb: &Framebuffer, p: &Palette, layout: &Layout, ui: &mut Ui) {
    if !ui.bench_dirty && ui.last_readout.as_str() == "bench" {
        return;
    }
    ui.bench_dirty = false;
    ui.last_readout.clear();
    ui.last_readout.str("bench");
    let top = layout.tabs_y + layout.tabs_h + 8;
    let bottom = layout.cards_y.saturating_sub(8);
    fb.fill(0, top, layout.width, bottom.saturating_sub(top), p.background);
    let line = BODY.line_height as u32 + 3;
    if ui.bench.len == 0 {
        draw::text_centred(
            fb,
            &HEADING,
            layout.readout_x,
            layout.readout_w,
            (top + bottom) / 2,
            "SPACE runs the benchmarks - ISA kernels, crypto raw speed, RustCrypto",
            p.muted,
        );
        return;
    }
    use crate::bench::Group;
    let groups = [(Group::Isa, "ISA KERNELS"), (Group::Instruction, "CRYPTO RAW SPEED"), (Group::Crypto, "RUSTCRYPTO (16 KiB)")];
    let col_w = (layout.width - 2 * layout.margin) / 3;
    for (c, (group, title)) in groups.iter().enumerate() {
        let x = layout.margin + c as u32 * col_w;
        let mut y = top;
        draw::text(fb, &BODY, x, y, title, p.accent);
        y += line + 2;
        for r in ui.bench.iter().filter(|r| r.group == *group) {
            if y + line > bottom {
                break;
            }
            draw::text(fb, &BODY, x, y, r.name, p.text);
            if !r.path.is_empty() {
                let nx = x + BODY.width_of(r.name) + BODY.width_of(" ");
                draw::text(fb, &BODY, nx, y, r.path, if r.path == "soft" { p.danger } else { p.accent });
            }
            // Values are held x1000; shown to one decimal (rates) and two
            // (cycles), so the thousandths are dropped before formatting.
            let mut v = Text::<48>::new();
            v.fixed(r.rate_milli / 100, 1).str(" ").str(group.unit());
            match (r.cycles_per_op_milli, *group) {
                (Some(c), _) => {
                    v.str("  ").fixed(c / 10, 2).str(" cyc");
                }
                // A crypto operation is one 16 KiB buffer: microseconds.
                (None, Group::Crypto) => {
                    v.str("  ").fixed(r.ns_per_op_milli / 100_000, 1).str(" us");
                }
                (None, _) => {
                    v.str("  ").fixed(r.ns_per_op_milli, 3).str(" ns");
                }
            }
            let vw = BODY.width_of(v.as_str());
            draw::text(fb, &BODY, (x + col_w).saturating_sub(vw + 16), y, v.as_str(), p.muted);
            y += line;
        }
    }
}

/// Whether the vector state the benchmarks use was switched on by the boot
/// stub: on x86 the CR4 bits and XCR0 components, read back, not assumed.
fn simd_state_rows(fb: &Framebuffer, p: &Palette, x: u32, w: u32, y: &mut u32) {
    #[cfg(x86_any)]
    {
        let cr4: usize;
        // SAFETY: reading CR4 at CPL 0 has no side effects.
        unsafe { core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
        let bit = |b: usize| if cr4 & (1 << b) != 0 { "on" } else { "off" };
        let mut t = Text::<48>::new();
        t.str("osfxsr ").str(bit(9)).str(" xmmexcpt ").str(bit(10)).str(" osxsave ").str(bit(18));
        *y = row(fb, p, x, w, *y, "cr4", t.as_str());
        if cr4 & (1 << 18) != 0 {
            // SAFETY: CR4.OSXSAVE is set, so XGETBV is legal.
            let xcr0 = unsafe { nanochrono_core::arch::x86::xgetbv0() };
            let comp = |b: u64| if xcr0 & (1 << b) != 0 { "on" } else { "off" };
            let mut t = Text::<48>::new();
            t.str("sse ").str(comp(1)).str(" avx ").str(comp(2)).str(" avx-512 ").str(if xcr0 & 0xE0 == 0xE0 { "on" } else { "off" });
            *y = row(fb, p, x, w, *y, "xcr0", t.as_str());
        }
    }
    #[cfg(not(x86_any))]
    {
        *y = row(fb, p, x, w, *y, "fp/simd", "enabled by the boot stub");
    }
}

/// Starts or stops the PMU tally to match the stopwatch, right after a toggle.
///
/// # Safety
/// Ring 0; the PMU was enabled at probe.
unsafe fn sync_stopwatch_pmu(ui: &mut Ui, machine: &Machine) {
    match (ui.stopwatch.running, ui.stopwatch_pmu.running) {
        // SAFETY: forwarded from this function's own contract.
        (true, false) => unsafe { ui.stopwatch_pmu.start(&machine.pmu) },
        // SAFETY: as above.
        (false, true) => unsafe { ui.stopwatch_pmu.stop(&machine.pmu) },
        _ => {}
    }
}

/// Shows a code for `action`, or leaves the lockout on the legend.
fn request_power(ui: &mut Ui, action: Action, now_ns: u64) {
    // Refused means locked out; the legend already counts that down.
    let _ = ui.power.request(action, now_ns, hw_entropy());
}

/// Does what a confirmed code asked for.
///
/// # Safety
/// Requires ring 0.
unsafe fn carry_out(action: Action, fb: &Framebuffer, p: &Palette, layout: &Layout, machine: &Machine) {
    match action {
        // SAFETY: forwarded from this function's own contract.
        Action::Restart => unsafe { acpi::reboot(machine.acpi.as_ref()) },
        // SAFETY: as above.
        Action::Shutdown => unsafe { power_off(fb, p, layout, machine.acpi.as_ref()) },
    }
}

/// The digit a set 1 scancode types on the top row, if it is one.
fn digit_of(scancode: u8) -> Option<u8> {
    match scancode {
        0x02..=0x0A => Some(scancode - 0x01),
        0x0B => Some(0),
        _ => None,
    }
}

/// Bits from every independent source this CPU has, folded together.
///
/// No single generator is trusted. RDRAND is a DRBG whose design cannot be
/// audited from here; RDSEED taps the noise source before that DRBG; the
/// counter's jitter across a short busy loop depends on the cache, the bus
/// and SMM, none of which the instruction set controls. The confirmation's
/// pool folds this through a non-linear mix, so a source that is broken — or
/// hostile, and trying to cancel the others — cannot undo them without
/// knowing the pool, which it never sees.
fn hw_entropy() -> u64 {
    // Off x86 there is no RDRAND/RDSEED to consult (ARMv8.5's RNDR is
    // optional and absent on the parts this runs on); the counter's jitter
    // is the source, alongside the event timings already stirred in.
    #[cfg(not(x86_any))]
    {
        counter_jitter()
    }
    #[cfg(x86_any)]
    hw_entropy_x86()
}

/// x86: jitter, RDRAND and RDSEED, folded.
#[cfg(x86_any)]
fn hw_entropy_x86() -> u64 {
    let leaf1 = crate::arch::x86::cpuid(1, 0);
    // Leaf 7 reads as zeros where it is not implemented.
    let leaf7 = crate::arch::x86::cpuid(7, 0);
    let mut acc = counter_jitter();
    if leaf1[2] & (1 << 30) != 0 {
        // SAFETY: CPUID said RDRAND exists.
        acc = acc.rotate_left(21) ^ unsafe { rdrand() };
    }
    if leaf7[1] & (1 << 18) != 0 {
        // SAFETY: CPUID said RDSEED exists.
        acc = acc.rotate_left(21) ^ unsafe { rdseed() };
    }
    acc
}

#[cfg(x86_any)]
/// RDRAND, or 0 if it reported failure (CF clear).
///
/// # Safety
/// The CPU must implement RDRAND.
unsafe fn rdrand() -> u64 {
    // One register's worth per read: 64 bits on x86_64, 32 on i386, where
    // two reads fill the word.
    let mut acc = 0u64;
    for _ in 0..(8 / core::mem::size_of::<usize>()) {
        let (value, ok): (usize, u8);
        // SAFETY: the caller checked CPUID; it only writes the named registers.
        unsafe {
            core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok,
                options(nomem, nostack));
        }
        if ok == 0 {
            return 0;
        }
        acc = acc.rotate_left(32) ^ value as u64;
    }
    acc
}

#[cfg(x86_any)]
/// RDSEED, or 0 if the noise source had nothing ready (CF clear).
///
/// # Safety
/// The CPU must implement RDSEED.
unsafe fn rdseed() -> u64 {
    // One register's worth per read: 64 bits on x86_64, 32 on i386, where
    // two reads fill the word.
    let mut acc = 0u64;
    for _ in 0..(8 / core::mem::size_of::<usize>()) {
        let (value, ok): (usize, u8);
        // SAFETY: the caller checked CPUID; it only writes the named registers.
        unsafe {
            core::arch::asm!("rdseed {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok,
                options(nomem, nostack));
        }
        if ok == 0 {
            return 0;
        }
        acc = acc.rotate_left(32) ^ value as u64;
    }
    acc
}

/// The low bits of how long each of a few tiny intervals took, packed.
/// Only called on an input event or a power request, never per frame.
fn counter_jitter() -> u64 {
    let mut acc = 0u64;
    let mut last = crate::arch::counter_ordered();
    for _ in 0..16 {
        for _ in 0..64 {
            core::hint::spin_loop();
        }
        let now = crate::arch::counter_ordered();
        acc = acc.rotate_left(4) ^ now.wrapping_sub(last);
        last = now;
    }
    acc ^ last
}

/// # Safety
/// Requires ring 0.
unsafe fn power_off(
    fb: &Framebuffer,
    p: &Palette,
    layout: &Layout,
    power: Option<&acpi::PowerRegisters>,
) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { acpi::shutdown(power) };
    // Every method returned, so none of them worked. Saying so beats a
    // machine that looks hung for no stated reason.
    let y = layout.hint_y;
    fb.fill(0, y, layout.width, BODY.line_height as u32 + 4, p.panel);
    draw::text(
        fb,
        &BODY,
        layout.margin,
        y,
        "shutdown: no method this platform answers",
        p.danger,
    );
    fb.present_damage();
}

// ---------------------------------------------------------------------------
// The header
// ---------------------------------------------------------------------------

/// Where the live clock sits in the header, so only that box is repainted.
fn header_clock_box(layout: &Layout) -> Hitbox {
    let mark = header_wordmark(layout);
    let mut x = layout.margin + mark.width.min(layout.width / 3) + 10;
    x += BODY.width_of(" v") + BODY.width_of(crate::VERSION) + 26;
    // Wide enough for the longest form this can draw, suffix included.
    // Reserving less leaves the tail of the previous string on screen when a
    // shorter one replaces it, because the repaint only covers the box.
    let w = BODY.width_of("00:00:00:000:000:000 RTC") + 12;
    Hitbox {
        x,
        y: layout.header_h.saturating_sub(BODY.line_height as u32) / 2,
        w: w.min(layout.width.saturating_sub(x)),
        h: BODY.line_height as u32,
    }
}

/// The wordmark size that fits the header with some air above and below.
fn header_wordmark(layout: &Layout) -> &'static crate::logo::Image {
    crate::logo::wordmark(layout.header_h.saturating_sub(16))
}

/// The title bar: identity on the left, restart and shut down on the right.
fn header(fb: &Framebuffer, p: &Palette, layout: &Layout, ui: &mut Ui, machine: &Machine) {
    let h = layout.header_h;
    // A gradient rather than a flat fill. It costs one extra loop and is most
    // of what separates a header from a coloured rectangle.
    draw::gradient(fb, 0, 0, layout.width, h, p.header_from, p.header_to);
    fb.fill(0, h - 1, layout.width, 1, p.divider);

    // The logo itself — stopwatch, green "Nano", white "Chronometer" —
    // rasterised at build time (see `logo`), vertically centred.
    let mark = header_wordmark(layout);
    crate::logo::draw(fb, mark, layout.margin, h.saturating_sub(mark.height) / 2);
    let x = layout.margin + mark.width + 10;

    let small_y = h.saturating_sub(BODY.line_height as u32) / 2;
    let mut version = Text::<16>::new();
    version.str("v").str(crate::VERSION);
    draw::text(fb, &BODY, x, small_y, version.as_str(), p.muted);

    // Everything to the right of the clock: what the counter and the SIMD
    // backend actually are. Laid out after the clock's reserved box so the
    // two cannot collide as the clock's width changes.
    let clock_box = header_clock_box(layout);
    let mut pen = clock_box.x + clock_box.w + 18;

    let simd = nanochrono_core::Backend::best().name();
    if pen + BODY.width_of(simd) < layout.width / 2 {
        draw::text(fb, &BODY, pen, small_y, simd, p.muted);
        pen += BODY.width_of(simd) + 14;
        draw::text(fb, &BODY, pen, small_y, "|", p.divider);
        pen += BODY.width_of("|") + 14;
    }
    let counter = if machine.features.invariant_counter {
        "INVARIANT"
    } else {
        "COUNTER"
    };
    if pen + BODY.width_of(counter) < layout.width / 2 {
        draw::text(fb, &BODY, pen, small_y, counter, p.accent);
    }

    // Where a desktop window puts minimise and close. Restart and shut down
    // instead: there is no window manager to minimise into and nothing to
    // close to.
    let bw = (h * 5 / 4).clamp(40, 64);
    let bh = (h * 3 / 5).clamp(26, 44);
    let by = (h - bh) / 2;
    let off_x = layout.width.saturating_sub(bw + layout.margin);
    let restart_x = off_x.saturating_sub(bw + 10);

    ui.restart.box_ = Hitbox {
        x: restart_x,
        y: by,
        w: bw,
        h: bh,
    };
    ui.shutdown.box_ = Hitbox {
        x: off_x,
        y: by,
        w: bw,
        h: bh,
    };
    header_buttons(fb, p, ui);
}

/// Repaints the two title-bar buttons at their current highlight.
fn header_buttons(fb: &Framebuffer, p: &Palette, ui: &Ui) {
    for (control, danger) in [(&ui.restart, false), (&ui.shutdown, true)] {
        let b = control.box_;
        if b.w == 0 {
            continue;
        }
        let lit = control.highlight.value().clamp(0, 1000) as u32;
        let base = draw::mix_colour(p.button, if danger { p.danger } else { p.accent }, lit / 3);
        draw::rounded(fb, b.x, b.y, b.w, b.h, 10, base);
        draw::rounded_outline(
            fb,
            b.x,
            b.y,
            b.w,
            b.h,
            10,
            if danger { p.danger } else { p.button_edge },
        );
        let ink = if danger { p.danger } else { p.title };
        if danger {
            glyph_power(fb, b.x + b.w / 2, b.y + b.h / 2, ink);
        } else {
            glyph_restart(fb, b.x + b.w / 2, b.y + b.h / 2, ink);
        }
    }
}

/// Repaints just the live clock in the header.
fn header_clock(fb: &Framebuffer, p: &Palette, layout: &Layout, ui: &mut Ui, clock: &Clock) {
    let mut label = Text::<24>::new();
    match clock.wall_ns() {
        Some(ns) => {
            label.str(text::duration(ns, ui.precision.nanoseconds()).as_str());
            // The RTC is read exactly as the firmware keeps it, and firmware
            // is configured either way. Marked rather than silently called
            // one or the other, which would be a guess presented as a fact.
            label.str(" RTC");
        }
        None => {
            label.str("no rtc");
        }
    }
    if label.as_str() == ui.last_header_clock.as_str() {
        return;
    }
    ui.last_header_clock.clear();
    ui.last_header_clock.str(label.as_str());

    let b = header_clock_box(layout);
    // The header is a gradient, so the box is repainted from the gradient
    // rather than from a flat colour — filling it with either end would leave
    // a visible rectangle.
    for col in 0..b.w {
        let t = ((b.x + col) * 255 / layout.width.max(1)) as u8;
        fb.fill(
            b.x + col,
            b.y,
            1,
            b.h,
            draw::blend(p.header_from, p.header_to, t),
        );
    }
    draw::text(fb, &BODY, b.x, b.y, label.as_str(), p.text);

    // The buttons share the repaint: their highlight is stepped here, and a
    // control that only lit up when something else happened to redraw would
    // respond a frame late.
    let hovered_restart = ui.restart.box_.contains(ui.pointer_x, ui.pointer_y);
    let hovered_off = ui.shutdown.box_.contains(ui.pointer_x, ui.pointer_y);
    let moved = ui.restart.step(hovered_restart, false) | ui.shutdown.step(hovered_off, false);
    if moved {
        header_buttons(fb, p, ui);
    }
}

// ---------------------------------------------------------------------------
// Tabs and chips
// ---------------------------------------------------------------------------

/// The row under the header: modes on the left, panel chips on the right.
///
/// Returns whether anything moved, so the caller only presents a row that
/// actually changed.
fn tab_bar(fb: &Framebuffer, p: &Palette, layout: &Layout, ui: &mut Ui) -> bool {
    let y = layout.tabs_y;
    let h = layout.tabs_h;
    let (px, py) = (ui.pointer_x, ui.pointer_y);

    // --- layout, which does not depend on state
    let pad = 20;
    let chip_h = (h * 3 / 5).clamp(22, 34);
    let chip_y = y + (h - chip_h) / 2;

    let mut x = layout.margin;
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let w = BODY.width_of(tab.name()) + pad * 2;
        ui.tabs[i].box_ = Hitbox { x, y, w, h };
        x += w;
    }

    // The chips are laid out from the right so the row stays anchored to the
    // edge, and any that will not fit are dropped rather than overlapping the
    // tabs. Short labels are tried before a chip is given up entirely.
    let mut right = layout.width.saturating_sub(layout.margin);
    let precision_label = match ui.precision {
        Precision::Nano => "NANO",
        Precision::Simple => "SIMPLE",
    };

    let mut boxes = [Hitbox::default(); Panel::ALL.len()];
    let mut short = false;
    for pass in 0..2 {
        short = pass == 1;
        let mut cursor = right;
        let mut fits = true;
        for (i, panel) in Panel::ALL.iter().enumerate().rev() {
            let label = if short { panel.short() } else { panel.name() };
            let w = BODY.width_of(label) + 22;
            if cursor.saturating_sub(w) <= x + 24 {
                fits = false;
                break;
            }
            cursor -= w + 8;
            boxes[i] = Hitbox {
                x: cursor,
                y: chip_y,
                w,
                h: chip_h,
            };
        }
        if fits {
            right = cursor;
            break;
        }
        boxes = [Hitbox::default(); Panel::ALL.len()];
    }
    for (i, b) in boxes.iter().enumerate() {
        ui.chips[i].box_ = *b;
    }

    let precision_w = BODY.width_of("SIMPLE") + 22;
    ui.precision_chip.box_ = if right.saturating_sub(precision_w + 12) > x + 24 {
        Hitbox {
            x: right - precision_w - 12,
            y: chip_y,
            w: precision_w,
            h: chip_h,
        }
    } else {
        Hitbox::default()
    };

    // --- state: step every highlight, and note whether any of them moved
    let mut moved = core::mem::take(&mut ui.chrome_dirty);
    for (i, tab) in Tab::ALL.iter().enumerate() {
        moved |= ui.tabs[i].step(ui.tabs[i].box_.contains(px, py), *tab == ui.tab);
    }
    for (i, panel) in Panel::ALL.iter().enumerate() {
        moved |= ui.chips[i].step(ui.chips[i].box_.contains(px, py), *panel == ui.panel);
    }
    moved |= ui
        .precision_chip
        .step(ui.precision_chip.box_.contains(px, py), false);

    // The underline chases the selected tab rather than jumping to it, which
    // is the single most recognisable piece of motion in a modern interface.
    let selected = ui.tabs[Tab::ALL.iter().position(|&t| t == ui.tab).unwrap_or(0)].box_;
    ui.underline_x.retarget(selected.x as i32);
    ui.underline_w.retarget(selected.w as i32);
    moved |= ui.underline_x.step() | ui.underline_w.step();

    if !moved {
        return false;
    }

    // --- draw
    fb.fill(0, y, layout.width, h, p.background);
    fb.fill(0, y + h - 1, layout.width, 1, p.divider);

    for (i, tab) in Tab::ALL.iter().enumerate() {
        let b = ui.tabs[i].box_;
        let lit = ui.tabs[i].highlight.value().clamp(0, 1000) as u32;
        // A tab is not a pill: it fills its cell and is marked by the
        // underline, which is what makes the sliding indicator legible.
        if lit > 0 {
            fb.fill(
                b.x,
                b.y,
                b.w,
                b.h - 1,
                draw::mix_colour(p.background, p.panel, lit),
            );
        }
        let ink = draw::mix_colour(p.muted, p.title, lit);
        draw::text_centred(
            fb,
            &BODY,
            b.x,
            b.w,
            b.y + (b.h - BODY.line_height as u32) / 2,
            tab.name(),
            ink,
        );
    }

    draw::underline(
        fb,
        ui.underline_x.value().max(0) as u32,
        y + h - 3,
        ui.underline_w.value().max(0) as u32,
        p.accent,
        p.glow,
    );

    for (i, panel) in Panel::ALL.iter().enumerate() {
        let b = ui.chips[i].box_;
        if b.w == 0 {
            continue;
        }
        let label = if short { panel.short() } else { panel.name() };
        draw::chip(
            fb,
            &BODY,
            b.x,
            b.y,
            b.w,
            b.h,
            label,
            ui.chips[i].colour(p),
            ui.chips[i].label_colour(p),
        );
    }

    let b = ui.precision_chip.box_;
    if b.w > 0 {
        draw::chip(
            fb,
            &BODY,
            b.x,
            b.y,
            b.w,
            b.h,
            precision_label,
            draw::mix_colour(p.panel, p.hover, 600),
            p.accent,
        );
    }
    true
}

// ---------------------------------------------------------------------------
// The readout
// ---------------------------------------------------------------------------

/// The large elapsed-time display, and the one line of context under it.
fn readout(fb: &Framebuffer, p: &Palette, layout: &Layout, ui: &mut Ui, clock: &Clock) {
    if ui.tab == Tab::Bench {
        bench_view(fb, p, layout, ui);
        return;
    }
    let now = clock.elapsed_ticks();
    let running;
    let value_ns = match ui.tab {
        Tab::Bench => return,
        Tab::Clock => {
            running = true;
            clock.wall_ns().unwrap_or_else(|| clock.elapsed_ns())
        }
        Tab::Stopwatch => {
            running = ui.stopwatch.running;
            let (ticks, verdict) = ui.stopwatch.ticks(now, ui.space.verify_reads());
            ui.note_integrity(verdict, clock.elapsed_ns());
            clock.calibration.ticks_to_ns(ticks)
        }
        Tab::Timer => {
            running = ui.timer.running;
            let (left, verdict) = ui.timer.remaining_ns(now, clock, ui.space.verify_reads());
            ui.note_integrity(verdict, clock.elapsed_ns());
            left
        }
    };

    let label = text::duration(value_ns, ui.precision.nanoseconds());
    let fading = ui.readout_fade.step();
    if !fading && label.as_str() == ui.last_readout.as_str() {
        return;
    }
    ui.last_readout.clear();
    ui.last_readout.str(label.as_str());

    let face = layout.readout;
    let text_w = face.width_of(label.as_str());
    let x = layout.readout_x + layout.readout_w.saturating_sub(text_w) / 2;
    let y = layout.readout_y + layout.readout_h.saturating_sub(face.line_height as u32) / 2;

    // The whole box is cleared rather than the text's own width: switching
    // precision or crossing from one to two hours changes the width, and a
    // clear that only covers the new string leaves the old one's tail behind.
    fb.fill(
        layout.readout_x,
        layout.readout_y,
        layout.readout_w,
        layout.readout_h,
        p.background,
    );

    let ink = if ui.tab == Tab::Timer && ui.timer.expired {
        p.danger
    } else if running {
        p.accent
    } else {
        // A stopped stopwatch is still a reading, so it stays legible — just
        // not lit.
        p.text
    };
    let halo = if running { p.glow } else { p.shadow };

    draw::text_glow(fb, face, x, y, label.as_str(), ink, halo, 2);

    // One line of context, so the number is not left to speak for itself.
    let mut note = Text::<64>::new();
    match ui.tab {
        Tab::Bench => {}
        Tab::Clock => {
            note.str("wall clock · rtc + counter · ")
                .str(clock.calibration.source.name());
        }
        Tab::Stopwatch => {
            note.str(if ui.stopwatch.running {
                "running · SPACE stops · L records a lap"
            } else if ui.stopwatch.accumulated.get() == 0 {
                "ready · SPACE starts"
            } else {
                "stopped · SPACE resumes · Z zeroes"
            });
        }
        Tab::Timer => {
            if ui.timer.expired {
                note.str("elapsed · Z resets");
            } else {
                note.str("counting down from ")
                    .str(text::duration(ui.timer.target_ns.get(), false).as_str())
                    .str(" · UP and DOWN adjust");
            }
        }
    }
    let note_y = y + face.line_height as u32 + 6;
    if note_y + BODY.line_height as u32 <= layout.readout_y + layout.readout_h {
        draw::text_centred(
            fb,
            &BODY,
            layout.readout_x,
            layout.readout_w,
            note_y,
            note.as_str(),
            p.muted,
        );
    }

    // The fade, applied over the finished box. A readout that appears rather
    // than blinks into place is most of what a tab switch reads as.
    let alpha = (ui.readout_fade.value().clamp(0, 1000) * 255 / 1000) as u8;
    draw::fade_region(
        fb,
        layout.readout_x,
        layout.readout_y,
        layout.readout_w,
        layout.readout_h,
        p.background,
        alpha,
    );
}

// ---------------------------------------------------------------------------
// The cards
// ---------------------------------------------------------------------------

/// Three cards: the selected panel, the current mode, and what this machine
/// is. Redrawn on a change rather than every frame — the numbers in them are
/// measurements taken once, and repainting a settled measurement sixty times
/// a second is work with no reader.
#[allow(clippy::too_many_arguments)]
fn cards(
    fb: &Framebuffer,
    p: &Palette,
    layout: &Layout,
    ui: &mut Ui,
    machine: &Machine,
    clock: &Clock,
    input: &Input,
) {
    if layout.cards_h < 80 {
        return;
    }
    // Both settled in `Layout`, because the card height depends on the column
    // count and the layout is what decides the height.
    let (columns, card_w) = (layout.columns, layout.card_w);

    fb.fill(
        0,
        layout.cards_y,
        layout.width,
        layout.cards_h,
        p.background,
    );

    for column in 0..columns {
        let x = layout.margin + column * (card_w + layout.margin);
        let mut y = card(
            fb,
            p,
            x,
            layout.cards_y,
            card_w,
            layout.cards_h,
            match column {
                0 => ui.panel.name(),
                1 if columns < 3 => "SESSION / MACHINE",
                1 => "SESSION",
                _ => "MACHINE",
            },
        );
        match column {
            0 => panel_rows(
                fb,
                p,
                x,
                card_w,
                &mut y,
                ui.panel,
                &ui.stats,
                ui.reprobe_status.as_str(),
                ui.checks.as_ref(),
                machine,
                clock,
                input,
            ),
            1 => {
                session_rows(fb, p, x, card_w, &mut y, ui, clock, machine);
                // On a mode too narrow for three cards the machine summary
                // moves in under the session rather than disappearing. There
                // is room: the cards are sized by the layout, not by their
                // contents, and none of them fills its height.
                if columns < 3 {
                    y += 6;
                    fb.fill(x + 20, y, card_w - 40, 1, p.divider);
                    y += 10;
                    machine_rows(fb, p, x, card_w, &mut y, machine, clock, fb.composited());
                }
            }
            _ => machine_rows(fb, p, x, card_w, &mut y, machine, clock, fb.composited()),
        }
    }

    let alpha = (ui.cards_fade.value().clamp(0, 1000) * 255 / 1000) as u8;
    draw::fade_region(
        fb,
        0,
        layout.cards_y,
        layout.width,
        layout.cards_h,
        p.background,
        alpha,
    );
}

#[allow(clippy::too_many_arguments)]
fn panel_rows(
    fb: &Framebuffer,
    p: &Palette,
    x: u32,
    w: u32,
    y: &mut u32,
    panel: Panel,
    stats: &TaskStats,
    status: &str,
    checks: Option<&ClockChecks>,
    machine: &Machine,
    clock: &Clock,
    input: &Input,
) {
    let f = &machine.features;
    match panel {
        Panel::Tasks => {
            let total: u64 = stats.ticks.iter().sum::<u64>().max(1);
            let permille = |t: u64| (t as u128 * 1000 / total as u128) as u64;
            let mut v = Text::<48>::new();
            let idle = permille(stats.ticks[crate::cpuload::Task::Idle as usize]);
            match stats.load.active_permille {
                Some(a) => {
                    v.fixed(a as u64, 1).str("% ").str(crate::cpuload::source().name());
                }
                None => {
                    v.fixed(1000 - idle.min(1000), 1).str("% (loop accounting)");
                }
            }
            *y = row(fb, p, x, w, *y, "CPU active", v.as_str());
            v.clear();
            match stats.load.frequency_khz {
                Some(k) => v.num(k / 1000).str(" MHz"),
                None => v.str("n/a"),
            };
            *y = row(fb, p, x, w, *y, "frequency", v.as_str());
            v.clear();
            match stats.load.ipc_x100 {
                Some(i) => v.fixed(i as u64, 2),
                None => v.str("n/a"),
            };
            *y = row(fb, p, x, w, *y, "IPC", v.as_str());
            *y = row(fb, p, x, w, *y, "idle wait", crate::cpuload::idle_method());
            for task in crate::cpuload::Task::ALL {
                let share = permille(stats.ticks[task as usize]);
                v.clear();
                v.fixed(share, 1).str("% ");
                for _ in 0..(share as usize * 12).div_ceil(1000).min(12) {
                    v.push(b'|');
                }
                *y = row(fb, p, x, w, *y, task.name(), v.as_str());
            }
        }
        Panel::Settings => {
            // x86 reads one counter, the TSC: there is no physical/virtual
            // pair to switch. The setting is shown, disabled, so it is clear
            // why — the AArch64 build has it, on its serial console.
            *y = row(fb, p, x, w, *y, "physical counter", "n/a: x86 has one TSC");
            *y = row(fb, p, x, w, *y, "counter in use", crate::arch::counter_source().name_here());
            *y = row(fb, p, x, w, *y, "on AArch64", "Settings > Enable Physical Counter");
            *y = row(fb, p, x, w, *y, "warning", "CNTPCT in VMs: trapped; nested: unstable");
            *y = row(fb, p, x, w, *y, "recommended", "real hardware, not VMs, for timing");
            let on = crate::hypervisor::cooldown_enabled();
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "[K] re-probe wait",
                if on { "ON: 10 s between re-probes" } else { "OFF: provider-ban risk is YOURS" },
            );
            *y = row(fb, p, x, w, *y, "why", "cloud hosts read repeated VM exits as abuse");
            if !on {
                *y = row(fb, p, x, w, *y, "warning", "throttling or a ban: user assumes it");
            }
        }
        Panel::Cpu => {
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "backend",
                nanochrono_core::Backend::best().name(),
            );
            *y = row(fb, p, x, w, *y, "AVX2", yes_no(f.avx2));
            *y = row(fb, p, x, w, *y, "AVX-512F", yes_no(f.avx512f));
            *y = row(fb, p, x, w, *y, "AES-NI", yes_no(f.aesni));
            *y = row(fb, p, x, w, *y, "SHA-NI", yes_no(f.shani));
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "invariant TSC",
                yes_no(f.invariant_counter),
            );
        }
        Panel::Pmu => {
            *y = row(fb, p, x, w, *y, "core type", machine.pmu.core_type.name());
            *y = value_row(fb, p, x, w, *y, "version", machine.pmu.leaf.version as u64);
            *y = value_row(
                fb,
                p,
                x,
                w,
                *y,
                "fixed counters",
                machine.pmu.leaf.fixed_counters as u64,
            );
            *y = value_row(
                fb,
                p,
                x,
                w,
                *y,
                "general counters",
                machine.pmu.leaf.general_counters as u64,
            );
            *y = row(fb, p, x, w, *y, "route", machine.route.name());
            match machine.cycles_per_op {
                Some(c) => *y = value_row(fb, p, x, w, *y, "cycles/op", c),
                None => *y = row(fb, p, x, w, *y, "cycles/op", "unavailable"),
            }
        }
        Panel::Counter => {
            *y = value_row(fb, p, x, w, *y, "read overhead", machine.read_overhead);
            *y = value_row(fb, p, x, w, *y, "worst read", machine.worst_read);
            *y = value_row(
                fb,
                p,
                x,
                w,
                *y,
                "jitter",
                machine.worst_read.saturating_sub(machine.read_overhead),
            );
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "frequency",
                text::frequency(clock.calibration.hz).as_str(),
            );
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "rate from",
                clock.calibration.source.name(),
            );
            if let Some(checks) = checks {
                let pm = checks.pm.as_ref().map(|(c, _, _)| *c);
                *y = row(fb, p, x, w, *y, "vs PM timer", cross_label(pm).as_str());
                *y = row(fb, p, x, w, *y, "vs RTC", cross_label(Some(checks.rtc)).as_str());
            }
        }
        Panel::Memory => {
            let total = machine.memory.total;
            // Bound before the call: the formatter returns an owned buffer,
            // and borrowing from it inside the argument list would drop it
            // before `row` reads it.
            let installed = text::bytes(total);
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "installed",
                if total > 0 {
                    installed.as_str()
                } else {
                    "unreported"
                },
            );
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "kernel image",
                text::bytes(machine.footprint).as_str(),
            );
            *y = value_row(
                fb,
                p,
                x,
                w,
                *y,
                "map entries",
                machine.memory.regions as u64,
            );
            *y = row(fb, p, x, w, *y, "allocator", "none");
            // Not a detail: with no allocator the image *is* the footprint,
            // which is why the figure below the meter can be exact.
            *y = row(fb, p, x, w, *y, "paging", "identity, 1 GiB pages");
        }
        #[cfg(x86_any)]
        Panel::Usb => {
            let found = input.found();
            // The touchpad first: on the machine this runs on it is the one
            // that was hardest to reach and the one most likely to be
            // missing, so it is the row worth reading first.
            match found.i2c {
                Some(pad) => {
                    let mut address = Text::<48>::new();
                    address.str("0x").pad(pad.slave_address as u64, 2);
                    address
                        .str(" on ")
                        .pad(pad.controller.1 as u64, 2)
                        .push(b'.')
                        .num(pad.controller.2 as u64);
                    // Where the address came from. On firmware whose `_CRS`
                    // is a method over vendor helpers, the declared address
                    // is a default for a different vendor's part, and the
                    // one that answered was found by scanning — which is
                    // worth saying rather than quietly presenting as fact.
                    address.str(match pad.discovery {
                        Discovery::Firmware => "",
                        Discovery::ProbedRegister => " (probed)",
                        Discovery::Scanned => " (found by scan)",
                    });
                    *y = row(fb, p, x, w, *y, "i2c-hid pad", address.as_str());

                    let mut ids = Text::<32>::new();
                    ids.str("0x").pad(pad.vendor as u64, 4);
                    ids.str(":0x").pad(pad.product as u64, 4);
                    *y = row(fb, p, x, w, *y, "  vendor:product", ids.as_str());

                    let mut detail = Text::<32>::new();
                    detail.str("report ");
                    match pad.report_id {
                        Some(id) => detail.num(id as u64),
                        None => detail.str("none"),
                    };
                    detail.str(" @ 0x").pad(pad.input_register as u64, 4);
                    *y = row(fb, p, x, w, *y, "  input", detail.as_str());

                    // The readiness gate. Worth a row of its own: it is the
                    // difference between the touchpad costing most of a
                    // frame's bus time and costing none of it, and while it
                    // is calibrating this is a live measurement.
                    let mut gate = Text::<48>::new();
                    match pad.gate {
                        GateState::Blind => {
                            gate.str("blind — every poll reads the bus");
                        }
                        GateState::Learning {
                            watching,
                            reports,
                            quiet,
                        } => {
                            gate.str("learning ")
                                .num(watching as u64)
                                .str(" pads (")
                                .num(reports as u64)
                                .push(b'/')
                                .num(quiet as u64)
                                .push(b')');
                        }
                        GateState::Gated { mapping, skipped } => {
                            gate.str(match mapping {
                                Mapping::Tabled(part) => part,
                                Mapping::Calibrated => "calibrated",
                            });
                            gate.str(", skipped ").num(skipped as u64);
                        }
                    }
                    *y = row(fb, p, x, w, *y, "  gpio gate", gate.as_str());
                }
                None => {
                    *y = row(
                        fb,
                        p,
                        x,
                        w,
                        *y,
                        "i2c-hid pad",
                        found.i2c_failure.map_or("not probed", |why| why.name()),
                    );
                }
            }
            *y = row(fb, p, x, w, *y, "ps/2 keyboard", yes_no(found.ps2_keyboard));
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "ps/2 pointer",
                found.ps2_pointer.map_or("none", |kind| kind.name()),
            );
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "xhci",
                if found.usb_controller {
                    "up"
                } else {
                    "not found"
                },
            );
            *y = row(fb, p, x, w, *y, "usb keyboard", yes_no(found.usb_keyboard));
            *y = row(fb, p, x, w, *y, "usb pointer", yes_no(found.usb_pointer));
            *y = row(fb, p, x, w, *y, "ehci / ohci", "seen, not driven");

            // The raw bytes, which is the row that actually settles an
            // argument about a keyboard that does nothing: none arriving and
            // the wrong ones arriving are different faults with the same
            // symptom.
            let mut raw = Text::<48>::new();
            if input.recent_bytes().is_empty() {
                raw.str("none yet - press a key");
            } else {
                for byte in input.recent_bytes() {
                    raw.str(HEX_DIGITS[(byte >> 4) as usize])
                        .str(HEX_DIGITS[(byte & 0x0F) as usize])
                        .push(b' ');
                }
            }
            *y = row(fb, p, x, w, *y, "8042 bytes", raw.as_str());

            let mut set = Text::<16>::new();
            set.str("set ").num(input.scancode_set() as u64);
            if input.scancode_set() == 2 {
                set.str(" (untranslated)");
            }
            *y = row(fb, p, x, w, *y, "  scancodes", set.as_str());
        }
        #[cfg(not(x86_any))]
        Panel::Usb => {
            // No USB or I2C stack off x86: keys come over the serial line.
            *y = row(fb, p, x, w, *y, "keyboard", input.console_name());
            *y = row(fb, p, x, w, *y, "pointer", "none");
            let mut bytes = Text::<32>::new();
            for &b in input.recent_bytes() {
                bytes.str(HEX_DIGITS[(b >> 4) as usize]).str(HEX_DIGITS[(b & 0x0F) as usize]).push(b' ');
            }
            *y = row(fb, p, x, w, *y, "last bytes", if bytes.as_str().is_empty() { "-" } else { bytes.as_str() });
        }
        Panel::Hypervisor => {
            let _ = machine;
            // The cached report: the boot negotiation or the last re-probe.
            // SAFETY: cached since boot; reading it issues nothing.
            let hv = unsafe { crate::hypervisor::detect() };
            let sig = hv.signature_str();
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "signature",
                if sig.is_empty() { "none" } else { sig },
            );
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "hypercall",
                yes_no(hv.hypercall_ok),
            );
            match hv.pairing {
                Some(pair) => {
                    *y = value_row(fb, p, x, w, *y, "host ns", pair.host_ns);
                    *y = row(fb, p, x, w, *y, "paired", "yes");
                }
                None => {
                    *y = row(fb, p, x, w, *y, "paired", "no");
                }
            }
            // Live, not the value taken at boot. A hypercall traps into the
            // host kernel and costs microseconds — and a variable number of
            // them, since what happens on the other side is another
            // scheduler. So the host clock is asked once, at boot, and the
            // stopwatch then reads the counter and nothing else. This row is
            // how that stays true: it should read the same number here and an hour
            // into a session, and if it ever climbs while the stopwatch runs,
            // a hypercall has got into the frame loop.
            let mut calls = Text::<32>::new();
            calls.num(crate::hypervisor::hypercalls() as u64);
            calls.str(if hv.probes > 1 { " (boot + re-probes)" } else { " (at boot only)" });
            *y = row(fb, p, x, w, *y, "hypercalls", calls.as_str());
            let wait = crate::hypervisor::reprobe_wait_s(clock.calibration.hz);
            let mut v = Text::<32>::new();
            if wait > 0 {
                v.str("wait ").num(wait as u64).str(" s");
            } else {
                v.str("ready");
            }
            if !crate::hypervisor::cooldown_enabled() {
                v.str(" (no cooldown!)");
            }
            *y = row(fb, p, x, w, *y, "[V] re-probe", v.as_str());
            let mut hal = Text::<32>::new();
            hal.str(hv.hypercall_insn.map_or("none", |i| i.name()));
            #[cfg(x86_any)]
            hal.str(" (").str(nanochrono_core::cpu::vendor().name()).str(")");
            *y = row(fb, p, x, w, *y, "hypercall HAL", hal.as_str());
            if !status.is_empty() {
                *y = row(fb, p, x, w, *y, "last request", status);
            }
        }
    }
}

fn session_rows(
    fb: &Framebuffer,
    p: &Palette,
    x: u32,
    w: u32,
    y: &mut u32,
    ui: &mut Ui,
    clock: &Clock,
    machine: &Machine,
) {
    match ui.tab {
        Tab::Bench => {
            let mut n = Text::<16>::new();
            n.num(ui.bench.len as u64);
            *y = row(fb, p, x, w, *y, "results", if ui.bench.len == 0 { "none - SPACE runs" } else { n.as_str() });
            *y = row(fb, p, x, w, *y, "passes", "3 per row, best kept");
            *y = row(fb, p, x, w, *y, "crypto", if cfg!(feature = "crypto") { "rustcrypto, 16 KiB" } else { "not in this build" });
            simd_state_rows(fb, p, x, w, y);
            let _ = (clock, machine);
        }
        Tab::Clock => {
            match clock.date {
                Some(d) => {
                    let mut date = Text::<16>::new();
                    date.pad(d.year as u64, 4)
                        .push(b'-')
                        .pad(d.month as u64, 2)
                        .push(b'-')
                        .pad(d.day as u64, 2);
                    *y = row(fb, p, x, w, *y, "date", date.as_str());
                    *y = row(fb, p, x, w, *y, "source", "cmos rtc");
                }
                None => {
                    *y = row(fb, p, x, w, *y, "date", "no rtc");
                    *y = row(fb, p, x, w, *y, "showing", "time since boot");
                }
            }
            *y = row(fb, p, x, w, *y, "sub-second from", "counter");
            *y = row(fb, p, x, w, *y, "resolution", "1 ns");
        }
        Tab::Stopwatch => {
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "state",
                if ui.stopwatch.running {
                    "running"
                } else {
                    "stopped"
                },
            );
            *y = row(fb, p, x, w, *y, "ecc", ui.stopwatch.integrity.name());
            let mut space = Text::<40>::new();
            space.str(ui.space.name());
            if ui.space.detections() > 0 {
                space.str(" (").num(ui.space.detections() as u64).str(" upsets)");
            }
            *y = row(fb, p, x, w, *y, "space mode", space.as_str());
            pmu_rows(fb, p, x, w, y, ui, clock, machine);
            if ui.stopwatch.lap_count == 0 {
                *y = row(fb, p, x, w, *y, "laps", "none — press L");
            }
            for (i, lap) in ui.stopwatch.laps[..ui.stopwatch.lap_count]
                .iter()
                .enumerate()
            {
                let ns = clock.calibration.ticks_to_ns(lap.get());
                let mut label = Text::<8>::new();
                label.str("lap ").num(i as u64 + 1);
                let value = text::duration(ns, false);
                *y = row(fb, p, x, w, *y, label.as_str(), value.as_str());
            }
        }
        Tab::Timer => {
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "set to",
                text::duration(ui.timer.target_ns.get(), false).as_str(),
            );
            *y = row(
                fb,
                p,
                x,
                w,
                *y,
                "state",
                if ui.timer.expired {
                    "elapsed"
                } else if ui.timer.running {
                    "running"
                } else {
                    "stopped"
                },
            );
            *y = row(fb, p, x, w, *y, "step", "10 s");
            *y = row(fb, p, x, w, *y, "alarm", "visual only (no sound device)");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn machine_rows(
    fb: &Framebuffer,
    p: &Palette,
    x: u32,
    w: u32,
    y: &mut u32,
    machine: &Machine,
    clock: &Clock,
    composited: bool,
) {
    *y = row(fb, p, x, w, *y, "operating system", "none");
    *y = row(fb, p, x, w, *y, "architecture", ARCHITECTURE);
    let irq = crate::irq_priority::state();
    let mut prio = Text::<48>::new();
    prio.str(irq.register).str(" = ").str(irq.outcome);
    *y = row(fb, p, x, w, *y, "irq priority", prio.as_str());
    // SAFETY: reads firmware memory only; the interface runs at ring 0.
    #[cfg(x86_any)]
    {
        let (source, xsdt) = unsafe { acpi::root_source() };
        *y = row(fb, p, x, w, *y, "acpi root", source.name());
        *y = row(
            fb,
            p,
            x,
            w,
            *y,
            "root table",
            if xsdt {
                "xsdt (64-bit)"
            } else {
                "rsdt (32-bit)"
            },
        );
    }
    #[cfg(not(x86_any))]
    {
        #[cfg(target_arch = "powerpc")]
        let firmware = if crate::arch::ppc::of::present() { "open firmware" } else { "devicetree" };
        #[cfg(not(target_arch = "powerpc"))]
        let firmware = "devicetree";
        *y = row(fb, p, x, w, *y, "firmware", firmware);
    }
    *y = row(
        fb,
        p,
        x,
        w,
        *y,
        "counter rate",
        text::frequency(clock.calibration.hz).as_str(),
    );
    *y = row(
        fb,
        p,
        x,
        w,
        *y,
        "power",
        match (machine.acpi.is_some(), POWER_MECHANISM) {
            (true, m) => m,
            (false, _) => "none reachable",
        },
    );
    *y = row(
        fb,
        p,
        x,
        w,
        *y,
        "compositing",
        if composited { "back buffer" } else { "direct" },
    );
    *y = row(fb, p, x, w, *y, "interrupts", "masked");
}

/// Draws a card and returns the y its rows start at.
fn card(fb: &Framebuffer, p: &Palette, x: u32, y: u32, w: u32, h: u32, title: &str) -> u32 {
    // A one-pixel offset fill under the card, which reads as a shadow at this
    // contrast and costs one more rectangle.
    draw::rounded(fb, x + 2, y + 3, w, h, 14, p.shadow);
    draw::rounded(fb, x, y, w, h, 14, p.panel);
    draw::rounded_outline(fb, x, y, w, h, 14, p.divider);

    draw::text(fb, &HEADING, x + 20, y + 14, title, p.accent);
    fb.fill(
        x + 20,
        y + 18 + HEADING.line_height as u32,
        w - 40,
        1,
        p.divider,
    );
    y + 28 + HEADING.line_height as u32
}

/// One label/value row, with the value right-aligned inside the card.
///
/// The value is what the row exists to show, so it keeps its place and the
/// label gives way. Truncation is by measured width, not character count:
/// the typeface is proportional, so counting characters is only ever
/// approximately right.
fn row(fb: &Framebuffer, p: &Palette, x: u32, w: u32, y: u32, label: &str, value: &str) -> u32 {
    let pad = 20;
    let right = x + w - pad;
    draw::text_right(fb, &BODY, right, y, value, p.text);

    let room = right.saturating_sub(BODY.width_of(value) + BODY.width_of("  ") + x + pad);
    draw::text(
        fb,
        &BODY,
        x + pad,
        y,
        truncate_to_width(label, room),
        p.muted,
    );

    y + BODY.line_height as u32 + 7
}

/// The same, for a number.
#[allow(clippy::too_many_arguments)]
fn value_row(
    fb: &Framebuffer,
    p: &Palette,
    x: u32,
    w: u32,
    y: u32,
    label: &str,
    value: u64,
) -> u32 {
    let mut text = Text::<24>::new();
    text.num(value);
    row(fb, p, x, w, y, label, text.as_str())
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

/// The longest prefix of `s` that fits in `width` pixels.
fn truncate_to_width(s: &str, width: u32) -> &str {
    if BODY.width_of(s) <= width {
        return s;
    }
    let mut used = 0;
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        let advance = BODY.glyph(b).advance as u32;
        if used + advance > width {
            break;
        }
        used += advance;
        end = i + 1;
    }
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// The bars along the bottom
// ---------------------------------------------------------------------------

/// The key legend — or, where there is no keyboard, what happened instead.
///
/// A legend of keyboard shortcuts is worse than useless on a machine whose
/// keyboard did not come up: it is the most prominent line on screen telling
/// the reader to press things that do nothing. When a stack came up short
/// this says so there instead.
fn hint_bar(fb: &Framebuffer, p: &Palette, layout: &Layout, ui: &mut Ui, now_ns: u64) {
    ui.hint_state = hint_signature(ui, now_ns);
    let y = layout.hint_y;
    let h = layout.status_y.saturating_sub(y);
    fb.fill(0, y, layout.width, h, p.background);

    let ty = y + h.saturating_sub(BODY.line_height as u32) / 2;

    // A pending code outranks everything else on the line, the input note
    // included: it is the one thing on screen that is waiting on the reader.
    if let Some((action, code, typed)) = ui.power.shown(now_ns) {
        let mut pen = layout.margin;
        let put = |text: &str, colour: Colour, pen: &mut u32| {
            draw::text(fb, &BODY, *pen, ty, text, colour);
            *pen += BODY.width_of(text);
        };
        let mut title = Text::<16>::new();
        for b in action.verb().bytes() {
            title.push(b.to_ascii_uppercase());
        }
        put(title.as_str(), p.danger, &mut pen);
        put("   type ", p.muted, &mut pen);
        for (i, d) in code.iter().enumerate() {
            let mut digit = Text::<4>::new();
            digit.push(b'0' + d).str(" ");
            put(digit.as_str(), if i < typed { p.muted } else { p.accent }, &mut pen);
        }
        put("to confirm   ", p.muted, &mut pen);
        put("[ESC]", p.accent, &mut pen);
        put(" cancel   ", p.muted, &mut pen);
        let left_s = ui.power.remaining_ns(now_ns).unwrap_or(0).div_ceil(1_000_000_000);
        let mut countdown = Text::<8>::new();
        countdown.num(left_s).str(" s");
        put(countdown.as_str(), p.muted, &mut pen);
        return;
    }

    if let Some(note) = ui.input_note {
        draw::text(fb, &BODY, layout.margin, ty, "INPUT", p.danger);
        draw::text(
            fb,
            &BODY,
            layout.margin + BODY.width_of("INPUT  "),
            ty,
            note,
            p.text,
        );
        return;
    }
    // Laid out one hint at a time and stopped when the row is full, rather
    // than as one string that would simply run off the edge on a narrow mode.
    let hints: [(&str, &str); 11] = [
        ("1-4", "Mode"),
        ("SPACE", "Start"),
        ("L", "Lap"),
        ("Z", "Zero"),
        ("N", "Precision"),
        ("TAB", "Panel"),
        ("T", "Tasks"),
        ("G", "Settings"),
        ("V", "Re-probe"),
        ("R", "Restart"),
        ("S", "Shut down"),
    ];
    // Locked out after a wrong code: the two power keys say so, and for how
    // long, in place of their usual labels.
    let locked_s = ui.power.lockout_remaining_ns(now_ns).div_ceil(1_000_000_000);
    let mut locked = Text::<24>::new();
    locked.str("locked ").num(locked_s).str(" s");

    let mut pen = layout.margin;
    for (key, action) in hints {
        let key = if locked_s > 0 && key == "R" { "R/S" } else { key };
        let action = if locked_s > 0 && key == "R/S" { locked.as_str() } else { action };
        if locked_s > 0 && key == "S" {
            continue;
        }
        let mut label = Text::<24>::new();
        label.str("[").str(key).str("] ").str(action);
        let w = BODY.width_of(label.as_str());
        if pen + w + layout.margin > layout.width {
            break;
        }
        // The bracketed key in the accent and the action muted, so the row
        // scans as keys rather than as a sentence.
        let mut bracket = Text::<12>::new();
        bracket.str("[").str(key).str("]");
        draw::text(fb, &BODY, pen, ty, bracket.as_str(), p.accent);
        draw::text(
            fb,
            &BODY,
            pen + BODY.width_of(bracket.as_str()) + BODY.width_of(" "),
            ty,
            action,
            p.muted,
        );
        pen += w + 22;
    }
}

/// The panel the status readings sit on, drawn once.
fn status_frame(fb: &Framebuffer, p: &Palette, layout: &Layout) {
    fb.fill(0, layout.status_y, layout.width, layout.status_h, p.panel);
    fb.fill(0, layout.status_y, layout.width, 1, p.divider);
}

/// The two rows of readings at the bottom.
///
/// Redrawn only when something in it moved. Most of what it shows was
/// measured once and does not change, and repainting a settled number sixty
/// times a second is the difference between a status bar and a busy loop.
fn status_bar(
    fb: &Framebuffer,
    p: &Palette,
    layout: &Layout,
    ui: &mut Ui,
    machine: &Machine,
    clock: &Clock,
    input: &Input,
) {
    // --- what the meters should read
    let used = machine.footprint;
    let total = machine.memory.total;
    let memory_permille = (used * 1000)
        .checked_div(total)
        .map_or(0, |permille| permille.min(1000) as u32);
    ui.memory_meter.retarget(memory_permille as i32);
    ui.load_meter.retarget(ui.load_permille as i32);
    let moving = ui.memory_meter.step() | ui.load_meter.step();

    // The load figure is recomputed once a second; without that, this row
    // would repaint every frame for a number that had not changed.
    let mut load = Text::<8>::new();
    load.num((ui.load_meter.value().max(0) as u32 / 10) as u64)
        .push(b'%');
    if !moving && load.as_str() == ui.last_load.as_str() {
        return;
    }
    ui.last_load.clear();
    ui.last_load.str(load.as_str());

    let row_h = BODY.line_height as u32;
    let y1 = layout.status_y + 7;
    let y2 = y1 + row_h + 6;
    fb.fill(
        0,
        layout.status_y + 1,
        layout.width,
        layout.status_h - 1,
        p.panel,
    );

    let meter_w = (layout.width / 8).clamp(70, 150);
    let meter_h = (row_h / 2).max(6);
    let meter_y = y1 + (row_h - meter_h) / 2;

    // --- row one: memory, load, counter rate
    let mut pen = layout.margin;
    draw::text(fb, &BODY, pen, y1, "MEM", p.muted);
    pen += BODY.width_of("MEM") + 10;
    draw::meter(
        fb,
        pen,
        meter_y,
        meter_w,
        meter_h,
        ui.memory_meter.value().max(0) as u32,
        p.track,
        p.accent,
    );
    pen += meter_w + 12;

    // `9.5 MB / 31.7 GB`, not `0.3 / 31.7 GB`. Each side is scaled to its own
    // magnitude, because a kernel using nine megabytes of a thirty-gigabyte
    // machine expressed in the machine's units is a number that rounds to
    // nothing and tells the reader nothing.
    let mut memory = Text::<32>::new();
    memory.str(text::bytes(used).as_str());
    memory.str(" / ");
    if total > 0 {
        memory.str(text::bytes(total).as_str());
    } else {
        memory.str("unreported");
    }
    draw::text(fb, &BODY, pen, y1, memory.as_str(), p.text);
    pen += BODY.width_of(memory.as_str()) + 28;

    if pen + meter_w + 90 < layout.width {
        draw::text(fb, &BODY, pen, y1, "CPU", p.muted);
        pen += BODY.width_of("CPU") + 10;
        let permille = ui.load_meter.value().max(0) as u32;
        draw::meter(
            fb,
            pen,
            meter_y,
            meter_w,
            meter_h,
            permille,
            p.track,
            if permille > 800 { p.warn } else { p.accent },
        );
        pen += meter_w + 12;
        draw::text(fb, &BODY, pen, y1, load.as_str(), p.text);
    }

    // Right of row one: the counter's rate and where the rate came from,
    // which is what every number above it is denominated in.
    let mut rate = Text::<32>::new();
    rate.str(text::frequency(clock.calibration.hz).as_str())
        .str("  ")
        .str(clock.calibration.source.name());
    draw::text_right(
        fb,
        &BODY,
        layout.width - layout.margin,
        y1,
        rate.as_str(),
        if clock.calibration.source.trustworthy() {
            p.accent
        } else {
            p.danger
        },
    );

    // --- row two: what the counter is and what read it
    let mut left = Text::<96>::new();
    left.str("route: ")
        .str(machine.route.name())
        .str("   overhead: ")
        .num(machine.read_overhead)
        .str("   jitter: ")
        .num(machine.worst_read.saturating_sub(machine.read_overhead))
        .str("   ecc: ")
        .str(ui.stopwatch.integrity.name())
        .str("   seu: ")
        .str(ui.space.name());
    draw::text(fb, &BODY, layout.margin, y2, left.as_str(), p.muted);

    let mut right = Text::<64>::new();
    right.str(input.source());
    let signature = machine.hypervisor.signature_str();
    if !signature.is_empty() {
        right.str("   ").str(signature);
    }
    let right_w = BODY.width_of(right.as_str());
    if layout.margin + BODY.width_of(left.as_str()) + right_w + 40 < layout.width {
        draw::text_right(
            fb,
            &BODY,
            layout.width - layout.margin,
            y2,
            right.as_str(),
            p.muted,
        );
    }
}

// ---------------------------------------------------------------------------
// The cursor
// ---------------------------------------------------------------------------

/// Cursor side, in pixels. Square and small: every move copies this many
/// pixels twice, and it is drawn from a polled loop.
const CURSOR: u32 = 12;

/// A software cursor: the framebuffer has no hardware overlay, so the pixels
/// under it are saved and restored as it moves.
///
/// With a back buffer this saves and restores *back buffer* pixels, which is
/// what keeps a cursor from becoming part of the background it is drawn over:
/// the buffer persists between frames, so a cursor drawn into it and not
/// erased would smear.
struct Cursor {
    x: i32,
    y: i32,
    /// Where it was when `under` was filled, which is not where it is now if
    /// it has been moved since.
    drawn_x: i32,
    drawn_y: i32,
    under: [Colour; (CURSOR * CURSOR) as usize],
    drawn: bool,
}

impl Cursor {
    fn new() -> Cursor {
        Cursor {
            x: 0,
            y: 0,
            drawn_x: 0,
            drawn_y: 0,
            under: [0; (CURSOR * CURSOR) as usize],
            drawn: false,
        }
    }

    fn move_to(&mut self, x: i32, y: i32) {
        self.x = x;
        self.y = y;
    }

    fn draw(&mut self, fb: &Framebuffer, p: &Palette) {
        self.drawn_x = self.x;
        self.drawn_y = self.y;
        for row in 0..CURSOR {
            for col in 0..CURSOR {
                // An arrow, which reads as a pointer where a square does not:
                // a triangle with a one-pixel dark edge so it stays visible
                // over the accent as well as over the background.
                if col > row || row >= CURSOR - col / 2 {
                    continue;
                }
                let x = self.drawn_x as u32 + col;
                let y = self.drawn_y as u32 + row;
                self.under[(row * CURSOR + col) as usize] = fb.get(x, y);
                let edge = col == 0 || col == row || row + 1 >= CURSOR - col / 2;
                fb.set(x, y, if edge { p.background } else { p.title });
            }
        }
        self.drawn = true;
    }

    fn erase(&mut self, fb: &Framebuffer) {
        if !self.drawn {
            return;
        }
        for row in 0..CURSOR {
            for col in 0..CURSOR {
                if col > row || row >= CURSOR - col / 2 {
                    continue;
                }
                fb.set(
                    self.drawn_x as u32 + col,
                    self.drawn_y as u32 + row,
                    self.under[(row * CURSOR + col) as usize],
                );
            }
        }
        self.drawn = false;
    }
}

// ---------------------------------------------------------------------------
// Glyphs drawn rather than decoded
// ---------------------------------------------------------------------------

/// A circular arrow: restart.
fn glyph_restart(fb: &Framebuffer, cx: u32, cy: u32, colour: Colour) {
    arc(fb, cx, cy, 9.0, 0.7, 5.4, 2, colour);
    // The head, at the open end.
    fb.fill(cx + 4, cy - 11, 8, 2, colour);
    fb.fill(cx + 10, cy - 11, 2, 8, colour);
}

/// A power symbol: a broken ring with a stem.
fn glyph_power(fb: &Framebuffer, cx: u32, cy: u32, colour: Colour) {
    arc(fb, cx, cy, 9.0, 5.5, 10.9, 2, colour);
    fb.fill(cx - 1, cy - 12, 2, 11, colour);
}

/// Plots an arc from `start` to `end` radians, `thickness` pixels wide.
///
/// Eight parameters, and every one is a distinct scalar the caller chooses.
/// Grouping them into a struct would move the same list one line up and add
/// a type to read through.
#[allow(clippy::too_many_arguments)]
fn arc(
    fb: &Framebuffer,
    cx: u32,
    cy: u32,
    r: f32,
    start: f32,
    end: f32,
    thickness: u32,
    c: Colour,
) {
    // Step chosen so consecutive samples land within a pixel of each other at
    // this radius; a coarser one draws a dotted line.
    let steps = ((end - start) * r * 2.0) as u32 + 1;
    for i in 0..=steps {
        let a = start + (end - start) * i as f32 / steps as f32;
        let (sin, cos) = sin_cos(a);
        let x = cx as i32 + (cos * r) as i32;
        let y = cy as i32 + (sin * r) as i32;
        if x < 0 || y < 0 {
            continue;
        }
        fb.fill(x as u32, y as u32, thickness, thickness, c);
    }
}

/// Sine and cosine by Taylor series.
///
/// `libm` is not linked and `core` has no floating-point maths. Four terms is
/// far more precision than a twenty-pixel circle can show.
fn sin_cos(a: f32) -> (f32, f32) {
    const TAU: f32 = 6.283_185_5;
    let mut x = a;
    while x > TAU / 2.0 {
        x -= TAU;
    }
    while x < -TAU / 2.0 {
        x += TAU;
    }
    let x2 = x * x;
    let sin = x * (1.0 - x2 / 6.0 * (1.0 - x2 / 20.0 * (1.0 - x2 / 42.0)));
    let cos = 1.0 - x2 / 2.0 * (1.0 - x2 / 12.0 * (1.0 - x2 / 30.0));
    (sin, cos)
}
