// SPDX-License-Identifier: Apache-2.0
//! The desktop's built-in apps, and the interface the window manager drives
//! them through.
//!
//! No trait objects and no allocation: an [`App`] is an enum over the apps'
//! states, and every call dispatches with a `match`. An app draws its client
//! area into the window's surface — a [`Framebuffer`] over the window's
//! block of the pool — and says what changed in a [`Response`]; the window
//! manager composes it onto the screen.

pub mod about;
pub mod files;
pub mod packages;
pub mod settings;
pub mod stopwatch;
pub mod tasks;
pub mod terminal;

use super::surface::Rect;
use crate::framebuffer::Framebuffer;
use crate::kbd::KeyInput;

/// Which app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stopwatch,
    Terminal,
    Tasks,
    Files,
    Settings,
    Packages,
    About,
}

impl Kind {
    /// Every built-in app, in the start menu's order.
    pub const ALL: [Kind; 7] = [
        Kind::Stopwatch,
        Kind::Terminal,
        Kind::Tasks,
        Kind::Files,
        Kind::Settings,
        Kind::Packages,
        Kind::About,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Kind::Stopwatch => "Stopwatch",
            Kind::Terminal => "Terminal",
            Kind::Tasks => "Task Manager",
            Kind::Files => "Files",
            Kind::Settings => "Settings",
            Kind::Packages => "Apps & Drivers",
            Kind::About => "About NanoChronometer",
        }
    }

    /// The short name, for `ps` and `top`.
    pub const fn process(self) -> &'static str {
        match self {
            Kind::Stopwatch => "stopwatch",
            Kind::Terminal => "terminal",
            Kind::Tasks => "taskmgr",
            Kind::Files => "files",
            Kind::Settings => "settings",
            Kind::Packages => "packages",
            Kind::About => "about",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Kind::Stopwatch => "nanochronometer",
            Kind::Terminal => "terminal",
            Kind::Tasks => "tasks",
            Kind::Files => "files",
            Kind::Settings => "settings",
            Kind::Packages => "apps",
            Kind::About => "about",
        }
    }

    /// Built in and never removable: the stopwatch, and what the system
    /// cannot be used without.
    pub const fn essential(self) -> bool {
        !matches!(self, Kind::About)
    }

    /// Pinned to the taskbar.
    pub const fn pinned(self) -> bool {
        matches!(self, Kind::Stopwatch | Kind::Terminal | Kind::Tasks | Kind::Files | Kind::Settings)
    }

    /// Only one window of it at a time.
    pub const fn single(self) -> bool {
        !matches!(self, Kind::Terminal)
    }

    /// The client area it opens with, given the screen's size.
    pub fn default_size(self, sw: i32, sh: i32) -> (i32, i32) {
        let (w, h) = match self {
            Kind::Stopwatch => (720, 520),
            Kind::Terminal => (820, 500),
            Kind::Tasks => (860, 580),
            Kind::Files => (820, 540),
            Kind::Settings => (860, 600),
            Kind::Packages => (760, 520),
            Kind::About => (560, 440),
        };
        (w.min(sw - 80), h.min(sh - 160))
    }
}

/// What the window manager hands an app with every call.
pub struct Ctx {
    pub now_ns: u64,
    pub focused: bool,
}

/// Input, in client coordinates for the pointer.
#[derive(Debug, Clone, Copy)]
pub enum Event {
    /// A key through the layout.
    Key(KeyInput),
    PointerMove { x: i32, y: i32 },
    PointerDown { x: i32, y: i32 },
    PointerUp { x: i32, y: i32 },
    Wheel { x: i32, y: i32, delta: i32 },
}

/// What an app asks for after a call.
#[derive(Debug, Clone, Copy, Default)]
pub struct Response {
    /// The state changed: the window manager calls `paint` and recomposes
    /// the whole client area.
    pub repaint: bool,
    /// The app drew this part of its surface itself.
    pub dirty: Option<Rect>,
    /// Close the window.
    pub close: bool,
    /// Open (or focus) another app.
    pub open: Option<Kind>,
    /// Switch the session to the CLI or the classic instrument.
    pub session: Option<crate::boot::Mode>,
    /// Use embedded wallpaper `n`.
    pub wallpaper: Option<usize>,
    /// Run the package at this VFS path (`Apps & Drivers`).
    pub run_package: Option<crate::text::Text<128>>,
    /// Ask for the power code (restart or shut down).
    pub power: Option<nanochrono_core::power_confirm::Action>,
}

impl Response {
    pub fn repaint() -> Response {
        Response { repaint: true, ..Response::default() }
    }

    pub fn dirty(r: Rect) -> Response {
        Response { dirty: Some(r), ..Response::default() }
    }

    pub fn merge(mut self, o: Response) -> Response {
        self.repaint |= o.repaint;
        self.dirty = match (self.dirty, o.dirty) {
            (Some(a), Some(b)) => Some(a.union(&b)),
            (a, b) => a.or(b),
        };
        self.close |= o.close;
        self.open = self.open.or(o.open);
        self.session = self.session.or(o.session);
        self.wallpaper = self.wallpaper.or(o.wallpaper);
        self.run_package = self.run_package.or(o.run_package);
        self.power = self.power.or(o.power);
        self
    }
}

/// A running app.
pub enum App {
    Stopwatch(stopwatch::Stopwatch),
    Terminal(terminal::TerminalApp),
    Tasks(tasks::Tasks),
    Files(files::Files),
    Settings(settings::Settings),
    Packages(packages::Packages),
    About(about::About),
}

impl App {
    /// Starts `kind` with a `w x h` client area; `None` when a resource it
    /// needs (a terminal slot) is exhausted.
    pub fn new(kind: Kind, w: i32, h: i32, ctx: &Ctx) -> Option<App> {
        Some(match kind {
            Kind::Stopwatch => App::Stopwatch(stopwatch::Stopwatch::new(ctx)),
            Kind::Terminal => App::Terminal(terminal::TerminalApp::new(w, h)?),
            Kind::Tasks => App::Tasks(tasks::Tasks::new(ctx)),
            Kind::Files => App::Files(files::Files::new()),
            Kind::Settings => App::Settings(settings::Settings::new()),
            Kind::Packages => App::Packages(packages::Packages::new()),
            Kind::About => App::About(about::About::new()),
        })
    }

    pub fn kind(&self) -> Kind {
        match self {
            App::Stopwatch(_) => Kind::Stopwatch,
            App::Terminal(_) => Kind::Terminal,
            App::Tasks(_) => Kind::Tasks,
            App::Files(_) => Kind::Files,
            App::Settings(_) => Kind::Settings,
            App::Packages(_) => Kind::Packages,
            App::About(_) => Kind::About,
        }
    }

    /// Draws the whole client area, `w x h`.
    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, ctx: &Ctx) {
        match self {
            App::Stopwatch(a) => a.paint(fb, w, h, ctx),
            App::Terminal(a) => a.paint(fb, w, h, ctx),
            App::Tasks(a) => a.paint(fb, w, h, ctx),
            App::Files(a) => a.paint(fb, w, h, ctx),
            App::Settings(a) => a.paint(fb, w, h, ctx),
            App::Packages(a) => a.paint(fb, w, h, ctx),
            App::About(a) => a.paint(fb, w, h, ctx),
        }
    }

    /// Once a frame: time passes.
    pub fn tick(&mut self, fb: &Framebuffer, w: i32, h: i32, ctx: &Ctx) -> Response {
        match self {
            App::Stopwatch(a) => a.tick(fb, w, h, ctx),
            App::Terminal(a) => a.tick(fb, w, h, ctx),
            App::Tasks(a) => a.tick(fb, w, h, ctx),
            _ => Response::default(),
        }
    }

    pub fn event(&mut self, ev: Event, fb: &Framebuffer, w: i32, h: i32, ctx: &Ctx) -> Response {
        match self {
            App::Stopwatch(a) => a.event(ev, fb, w, h, ctx),
            App::Terminal(a) => a.event(ev, fb, w, h, ctx),
            App::Tasks(a) => a.event(ev, ctx),
            App::Files(a) => a.event(ev, w, h, ctx),
            App::Settings(a) => a.event(ev, w, h, ctx),
            App::Packages(a) => a.event(ev, w, h, ctx),
            App::About(a) => a.event(ev, ctx),
        }
    }

    /// The client area changed size.
    pub fn resized(&mut self, w: i32, h: i32) {
        if let App::Terminal(a) = self {
            a.resized(w, h)
        }
    }

    /// The window is closing: give back what the app holds.
    pub fn closed(&mut self) {
        if let App::Terminal(a) = self {
            a.closed()
        }
    }

    /// The title bar's text.
    pub fn title(&self) -> crate::text::Text<64> {
        let mut t = crate::text::Text::new();
        match self {
            App::Terminal(a) => {
                t.str("Terminal — ").str(a.cwd());
            }
            other => {
                t.str(other.kind().title());
            }
        }
        t
    }
}

/// Shared: a clickable area an app remembers from its last paint.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hit {
    pub rect: Rect,
    pub id: u16,
}

/// Up to `N` hit areas, rebuilt at every paint.
pub struct Hits<const N: usize> {
    items: [Hit; N],
    n: usize,
}

impl<const N: usize> Hits<N> {
    pub const fn new() -> Self {
        Hits { items: [Hit { rect: Rect::new(0, 0, 0, 0), id: 0 }; N], n: 0 }
    }

    pub fn clear(&mut self) {
        self.n = 0;
    }

    pub fn add(&mut self, rect: Rect, id: u16) {
        if self.n < N {
            self.items[self.n] = Hit { rect, id };
            self.n += 1;
        }
    }

    pub fn at(&self, x: i32, y: i32) -> Option<u16> {
        self.items[..self.n].iter().rev().find(|h| h.rect.contains(x, y)).map(|h| h.id)
    }

    pub fn rect(&self, id: u16) -> Option<Rect> {
        self.items[..self.n].iter().find(|h| h.id == id).map(|h| h.rect)
    }
}
