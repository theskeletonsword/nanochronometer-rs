// SPDX-License-Identifier: Apache-2.0
//! The NanoChronometer GUI (`mode=gui`, the default session; `mode=desktop`
//! is its old name).
//!
//! What a desktop operating system's session looks like — a wallpaper,
//! icons, windows that move, a taskbar with a start menu and a clock — on a
//! kernel with no allocator, no interrupts and one core. In the layout of
//! Windows Server's Desktop Experience (a taskbar along the bottom, a start
//! button on its left, the tray and clock on its right), in a GNOME-like dark
//! theme ([`theme`]).
//!
//! # How a frame is made
//!
//! Layers, each a block of pixels from the static pool ([`surface`]):
//!
//! * the background — the wallpaper scaled to the screen with the desktop's
//!   icons baked in (a clean copy of the wallpaper is kept to re-bake them);
//! * one surface per window holding its whole frame: the title bar the
//!   window manager draws and the client area the app draws;
//! * the taskbar, the start menu, the power dialog;
//! * the cursor, drawn last, straight onto the screen.
//!
//! Nothing is redrawn that did not change. A change adds a rectangle to the
//! frame's damage; each damaged rectangle is composed from the layers
//! bottom to top into the back buffer and only that rectangle is copied to
//! the screen. A running stopwatch damages its readout, the taskbar clock its
//! own few hundred pixels — `hh:mm:ss:mmm:uuu:nnn`, every frame: this is a
//! NanoChronometer, not a phone's clock.
//!
//! # Time
//!
//! As in the classic interface: no timer interrupt. The calibrated counter
//! paces the loop at sixty frames a second and the time between frames is a
//! real idle wait (`cpuload`). Every app's calls are timed on the same
//! counter, which is what `top` and the Task Manager show per app.

pub mod apps;
pub mod surface;
pub mod theme;

use crate::cpuload::{self, Task};
use crate::framebuffer::{Colour, Framebuffer};
use crate::input::{Event as InputEvent, Input};
use crate::kbd::{KeyInput, Keyboard};
use crate::multiboot::Memory;
use crate::text::Text;
use apps::{App, Ctx, Event, Kind, Response};
use core::fmt::Write;
use surface::{Block, Rect};
use theme::{TASKBAR_H, TITLE_H};

const MAX_WINDOWS: usize = 12;
const FRAME_NS: u64 = 1_000_000_000 / 60;
const ICON_COLUMN: [Kind; 6] = [Kind::Stopwatch, Kind::Terminal, Kind::Tasks, Kind::Files, Kind::Settings, Kind::Packages];

/// One window.
struct Window {
    frame: Rect,
    restore: Rect,
    maximized: bool,
    minimized: bool,
    block: Block,
    app: App,
    /// Counter ticks spent in the app this second, and last second's share.
    ticks: u64,
    load_permille: u32,
    /// The title bar's buttons' hover state, for repainting it.
    hover_button: Option<u8>,
}

impl Window {
    fn client(&self) -> Rect {
        Rect::new(0, TITLE_H, self.frame.w, self.frame.h - TITLE_H)
    }

    /// The window's whole surface (frame and client).
    ///
    /// # Safety
    /// One view at a time; the block is the window's own.
    unsafe fn surface(&self) -> Framebuffer {
        // SAFETY: forwarded; the block holds `w * h` pixels.
        unsafe { surface::surface(&self.block, self.frame.w as u32, self.frame.h as u32) }
    }

    /// The client area's surface: the rows under the title bar, which are
    /// contiguous because the surface's stride is its width.
    ///
    /// # Safety
    /// As [`Window::surface`].
    unsafe fn client_surface(&self) -> Framebuffer {
        let w = self.frame.w as u32;
        let h = (self.frame.h - TITLE_H) as u32;
        // SAFETY: the block holds `frame.w * frame.h` pixels; the client is
        // its last `w * h`.
        unsafe { Framebuffer::surface(self.block.pixels().as_mut_ptr().add((TITLE_H as u32 * w) as usize), w, h) }
    }
}

/// What the Task Manager and `ps`/`top` read about one window.
#[derive(Debug, Clone, Copy)]
pub struct AppInfo {
    pub name: &'static str,
    pub icon: &'static str,
    pub load_permille: u32,
    pub memory_bytes: usize,
    pub essential: bool,
}

static mut INFOS: [Option<AppInfo>; MAX_WINDOWS] = [None; MAX_WINDOWS];
/// The windows: a static, not a field of the desktop — each holds its app's
/// state, a dozen kilobytes for some, and a dozen of them built on the stack
/// overflowed it. Uninitialised (so `.bss`, not 140 KiB of image: `None`
/// is not all zero bits) until the desktop writes every slot.
static mut WINDOWS: core::mem::MaybeUninit<[Option<Window>; MAX_WINDOWS]> = core::mem::MaybeUninit::uninit();

/// The window table, every slot `None`.
fn window_table() -> &'static mut [Option<Window>; MAX_WINDOWS] {
    // SAFETY: one desktop per session, the only user of the table; each slot
    // is written before the table is read as initialised.
    unsafe {
        let slots = &mut *(core::ptr::addr_of_mut!(WINDOWS) as *mut [core::mem::MaybeUninit<Option<Window>>; MAX_WINDOWS]);
        for slot in slots.iter_mut() {
            slot.write(None);
        }
        (*core::ptr::addr_of_mut!(WINDOWS)).assume_init_mut()
    }
}
static mut PHASES: [u64; 5] = [0; 5];
static mut CLOSE_REQUEST: Option<usize> = None;
static RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The windows open now, as the Task Manager lists them.
pub fn app_infos() -> impl Iterator<Item = AppInfo> {
    // SAFETY: written by the desktop's loop on the same core.
    let infos = unsafe { *core::ptr::addr_of!(INFOS) };
    infos.into_iter().flatten()
}

/// `(process name, state)` per window, for `ps`.
pub fn app_list() -> impl Iterator<Item = (&'static str, &'static str)> {
    app_infos().map(|i| (i.name, "running"))
}

/// `(process name, share of the last second)` per window, for `top`.
pub fn app_load() -> impl Iterator<Item = (&'static str, u32)> {
    app_infos().map(|i| (i.name, i.load_permille))
}

/// The loop's phases over the last second (render, present, input, measure,
/// idle), for the Task Manager.
pub fn phase_ticks() -> [u64; 5] {
    // SAFETY: as `app_infos`.
    unsafe { *core::ptr::addr_of!(PHASES) }
}

/// Asks the desktop to close the `index`-th window the Task Manager lists.
pub fn request_close(index: usize) {
    // SAFETY: one core; read and cleared by the loop.
    unsafe { *core::ptr::addr_of_mut!(CLOSE_REQUEST) = Some(index) };
}

/// The desktop's static pools, for the memory report.
pub fn pools() -> impl Iterator<Item = (&'static str, usize)> {
    [("desktop pool", surface::POOL_PIXELS * 4), ("terminal cells", apps::terminal::POOL_BYTES)].into_iter()
}

/// The parts of the screen the pointer can be over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Nothing,
    Start,
    TaskbarApp(usize),
    StartItem(usize),
    StartPower(u8),
    Icon(usize),
    Window(usize),
    TitleButton(usize, u8),
}

struct Drag {
    window: usize,
    dx: i32,
    dy: i32,
}

struct Desktop<'a> {
    fb: &'a Framebuffer,
    sw: i32,
    sh: i32,
    clean: Block,
    background: Block,
    taskbar_base: Block,
    taskbar: Block,
    menu: Option<Block>,
    menu_rect: Rect,
    windows: &'static mut [Option<Window>; MAX_WINDOWS],
    /// Window indices, bottom to top.
    z: [usize; MAX_WINDOWS],
    zn: usize,
    focus: Option<usize>,
    damage: [Rect; 32],
    nd: usize,
    cursor: (i32, i32),
    cursor_drawn: Rect,
    left: bool,
    drag: Option<Drag>,
    captured: Option<usize>,
    hover: Target,
    selected_icon: Option<usize>,
    last_icon_click: (Option<usize>, u64),
    last_title_click: (Option<usize>, u64),
    keyboard: Keyboard,
    super_down: bool,
    super_used: bool,
    power: nanochrono_core::power_confirm::Confirm,
    power_action: Option<nanochrono_core::power_confirm::Action>,
    clock_rect: Rect,
    now_ns: u64,
    taskbar_slots: [(Rect, Option<usize>, Kind); 16],
    taskbar_n: usize,
    load_text: Text<16>,
}

fn alloc_or_die(pixels: usize, what: &str) -> Block {
    match surface::alloc(pixels) {
        Some(b) => b,
        None => panic!("desktop: the pool has no room for the {what} ({pixels} pixels)"),
    }
}

impl<'a> Desktop<'a> {
    fn new(fb: &'a Framebuffer) -> Desktop<'a> {
        let (sw, sh) = (fb.width as i32, fb.height as i32);
        let screen = (sw * sh) as usize;
        let clean = alloc_or_die(screen, "wallpaper");
        let background = alloc_or_die(screen, "background");
        let taskbar_base = alloc_or_die((sw * TASKBAR_H) as usize, "taskbar");
        let taskbar = alloc_or_die((sw * TASKBAR_H) as usize, "taskbar");
        Desktop {
            fb,
            sw,
            sh,
            clean,
            background,
            taskbar_base,
            taskbar,
            menu: None,
            menu_rect: Rect::default(),
            windows: window_table(),
            z: [0; MAX_WINDOWS],
            zn: 0,
            focus: None,
            damage: [Rect::default(); 32],
            nd: 0,
            cursor: (sw / 2, sh / 2),
            cursor_drawn: Rect::default(),
            left: false,
            drag: None,
            captured: None,
            hover: Target::Nothing,
            selected_icon: None,
            last_icon_click: (None, 0),
            last_title_click: (None, 0),
            keyboard: Keyboard::new(crate::kbd::default_layout()),
            super_down: false,
            super_used: false,
            power: nanochrono_core::power_confirm::Confirm::new(),
            power_action: None,
            clock_rect: Rect::default(),
            now_ns: 0,
            taskbar_slots: [(Rect::default(), None, Kind::Stopwatch); 16],
            taskbar_n: 0,
            load_text: Text::new(),
        }
    }

    fn screen(&self) -> Rect {
        Rect::new(0, 0, self.sw, self.sh)
    }

    fn work_area(&self) -> Rect {
        Rect::new(0, 0, self.sw, self.sh - TASKBAR_H)
    }

    fn taskbar_rect(&self) -> Rect {
        Rect::new(0, self.sh - TASKBAR_H, self.sw, TASKBAR_H)
    }

    fn damage(&mut self, r: Rect) {
        let Some(r) = r.intersect(&self.screen()) else { return };
        for d in &mut self.damage[..self.nd] {
            if d.covers(&r) {
                return;
            }
        }
        if self.nd == self.damage.len() {
            let all = self.damage.iter().fold(r, |a, b| a.union(b));
            self.damage[0] = all;
            self.nd = 1;
            return;
        }
        self.damage[self.nd] = r;
        self.nd += 1;
    }

    fn damage_all(&mut self) {
        self.nd = 0;
        self.damage(self.screen());
    }

    // ------------------------------------------------------------------
    // The background: wallpaper and icons
    // ------------------------------------------------------------------

    fn set_wallpaper(&mut self, n: usize) {
        let wallpapers = crate::assets::WALLPAPERS;
        // SAFETY: the desktop's own blocks, one view at a time.
        let clean = unsafe { self.clean.pixels() };
        let ok = wallpapers
            .get(n)
            .or(wallpapers.first())
            .is_some_and(|w| crate::assets::render_cover(w, clean, self.sw as u32, self.sh as u32));
        if !ok {
            // No picture: the brand's dark gradient.
            for y in 0..self.sh {
                let c = crate::draw::mix_colour(0x0E1A14, 0x050607, (y as u32 * 1000) / self.sh as u32);
                clean[(y * self.sw) as usize..((y + 1) * self.sw) as usize].fill(c);
            }
        }
        self.bake_background();
        self.build_taskbar_base();
        self.paint_taskbar();
        self.damage_all();
    }

    fn icon_rect(&self, i: usize) -> Rect {
        let rows = ((self.sh - TASKBAR_H - 24) / 104).max(1) as usize;
        Rect::new(18 + (i / rows) as i32 * 104, 18 + (i % rows) as i32 * 104, 96, 96)
    }

    fn bake_background(&mut self) {
        // SAFETY: the desktop's own blocks.
        let (clean, bg) = unsafe { (self.clean.pixels(), self.background.pixels()) };
        bg.copy_from_slice(&clean[..bg.len()]);
        for i in 0..ICON_COLUMN.len() {
            self.bake_icon(i);
        }
    }

    fn bake_icon(&mut self, i: usize) {
        let r = self.icon_rect(i);
        // SAFETY: the desktop's own blocks.
        let (clean, bg) = unsafe { (self.clean.pixels(), self.background.pixels()) };
        for y in r.y..r.bottom().min(self.sh) {
            let row = (y * self.sw) as usize;
            let (a, b) = (row + r.x as usize, row + r.right().min(self.sw) as usize);
            bg[a..b].copy_from_slice(&clean[a..b]);
        }
        // SAFETY: as above.
        let fb = unsafe { surface::surface(&self.background, self.sw as u32, self.sh as u32) };
        let selected = self.selected_icon == Some(i);
        let hovered = self.hover == Target::Icon(i);
        if selected || hovered {
            // A translucent plate behind the icon.
            for y in r.y..r.bottom() {
                for x in r.x..r.right() {
                    let under = fb.get(x as u32, y as u32);
                    fb.set(x as u32, y as u32, crate::draw::blend(under, if selected { 0x2F6B3A } else { 0xFFFFFF }, if selected { 120 } else { 40 }));
                }
            }
        }
        let kind = ICON_COLUMN[i];
        theme::icon(&fb, kind.icon(), 48, r.x + 24, r.y + 10);
        let face = &crate::fonts::UI13;
        let label = kind.title();
        let label = if label.len() > 14 { label.split(' ').next().unwrap_or(label) } else { label };
        // A shadow under the label, so it reads on any wallpaper.
        face.draw_centred(&fb, r.x + 1, r.w as u32, r.y + 66, label, 0x000000);
        face.draw_centred(&fb, r.x, r.w as u32, r.y + 65, label, 0xFFFFFF);
        self.damage(r);
    }

    // ------------------------------------------------------------------
    // The taskbar
    // ------------------------------------------------------------------

    fn build_taskbar_base(&mut self) {
        // SAFETY: the desktop's own blocks.
        let (bg, base) = unsafe { (self.background.pixels(), self.taskbar_base.pixels()) };
        let y0 = self.sh - TASKBAR_H;
        for y in 0..TASKBAR_H {
            for x in 0..self.sw {
                let under = bg[((y0 + y) * self.sw + x) as usize];
                base[(y * self.sw + x) as usize] = crate::draw::blend(under, theme::TASKBAR, 225);
            }
        }
        for x in 0..self.sw {
            base[x as usize] = 0x2E333B;
        }
    }

    /// Redraws the whole taskbar layer: start, apps, tray, clock.
    fn paint_taskbar(&mut self) {
        // SAFETY: the desktop's own blocks.
        let (base, bar) = unsafe { (self.taskbar_base.pixels(), self.taskbar.pixels()) };
        bar.copy_from_slice(&base[..bar.len()]);
        // SAFETY: as above.
        let fb = unsafe { surface::surface(&self.taskbar, self.sw as u32, TASKBAR_H as u32) };
        let start = Rect::new(8, 6, 44, 40);
        if self.menu.is_some() || self.hover == Target::Start {
            theme::rounded(&fb, start, 8, if self.menu.is_some() { 0x2F6B3A } else { theme::HOVER });
        }
        theme::icon(&fb, "nanochronometer", 32, start.x + 6, start.y + 4);

        // Pinned apps, then running ones that are not pinned.
        self.taskbar_n = 0;
        let mut x = 64;
        let mut slots: [(Kind, Option<usize>); 16] = [(Kind::Stopwatch, None); 16];
        let mut n = 0;
        for kind in Kind::ALL {
            if kind.pinned() {
                slots[n] = (kind, self.window_of(kind));
                n += 1;
            }
        }
        for i in self.z[..self.zn].iter().copied() {
            if let Some(w) = &self.windows[i] {
                let kind = w.app.kind();
                if !kind.pinned() || (kind == Kind::Terminal && self.window_of(kind) != Some(i)) {
                    if n < slots.len() {
                        slots[n] = (kind, Some(i));
                        n += 1;
                    }
                }
            }
        }
        for (k, (kind, win)) in slots[..n].iter().enumerate() {
            let r = Rect::new(x, 6, 44, 40);
            let focused = win.is_some() && *win == self.focus;
            if self.hover == Target::TaskbarApp(k) {
                theme::rounded(&fb, r, 8, theme::HOVER);
            } else if focused {
                theme::rounded(&fb, r, 8, 0x262B33);
            }
            theme::icon(&fb, kind.icon(), 32, r.x + 6, r.y + 4);
            if win.is_some() {
                let bw = if focused { 16 } else { 6 };
                theme::rounded(&fb, Rect::new(r.x + (r.w - bw) / 2, r.bottom() - 3, bw, 3), 1, if focused { theme::ACCENT } else { theme::TEXT_DIM });
            }
            self.taskbar_slots[k] = (r.offset(0, self.sh - TASKBAR_H), *win, *kind);
            self.taskbar_n = k + 1;
            x += 48;
        }

        // The tray: keyboard layout and CPU, then the clock.
        let mono = &crate::fonts::TERM14;
        let clock_w = 20 * mono.cell_w as i32;
        self.clock_rect = Rect::new(self.sw - clock_w - 16, 6, clock_w, 40);
        let tray_x = self.clock_rect.x - 16;
        let kb = crate::kbd::default_layout().name();
        let mut layout = Text::<4>::new();
        for c in kb.chars() {
            layout.char(c.to_ascii_uppercase());
        }
        crate::fonts::UI15_SEMIBOLD.draw_right(&fb, tray_x, 16, layout.as_str(), theme::TEXT_DIM);
        let cpu_x = tray_x - 40 - 70;
        crate::fonts::UI13.draw(&fb, cpu_x, 9, "CPU", theme::TEXT_FAINT, u32::MAX);
        crate::fonts::UI13.draw(&fb, cpu_x, 26, self.load_text.as_str(), theme::TEXT, u32::MAX);
        self.paint_clock();
        self.damage(self.taskbar_rect());
    }

    fn window_of(&self, kind: Kind) -> Option<usize> {
        self.z[..self.zn].iter().rev().copied().find(|&i| self.windows[i].as_ref().is_some_and(|w| w.app.kind() == kind))
    }

    /// The clock alone: every frame.
    fn paint_clock(&mut self) {
        let r = self.clock_rect;
        // SAFETY: the desktop's own blocks.
        let (base, bar) = unsafe { (self.taskbar_base.pixels(), self.taskbar.pixels()) };
        for y in r.y..r.bottom() {
            let row = (y * self.sw) as usize;
            bar[row + r.x as usize..row + r.right() as usize].copy_from_slice(&base[row + r.x as usize..row + r.right() as usize]);
        }
        // SAFETY: as above.
        let fb = unsafe { surface::surface(&self.taskbar, self.sw as u32, TASKBAR_H as u32) };
        let mono = &crate::fonts::TERM14;
        let mut t = Text::<24>::new();
        let mut date = Text::<24>::new();
        match crate::system::get().and_then(|s| s.clock.wall_ns().map(|ns| (s, ns))) {
            Some((s, ns)) => {
                crate::shell::nanochrono::elapsed_nano(&mut t, ns);
                if let Some(d) = s.clock.date {
                    let _ = write!(date, "{:04}-{:02}-{:02}", d.year, d.month, d.day);
                }
            }
            None => {
                let up = crate::system::get().map_or(0, |s| s.uptime_ns());
                crate::shell::nanochrono::elapsed_nano(&mut t, up);
                date.str("uptime");
            }
        }
        for (i, c) in t.as_str().chars().enumerate() {
            if let Some(cov) = mono.glyph(c) {
                fb.draw_coverage((r.x + i as i32 * mono.cell_w as i32) as u32, (r.y + 2) as u32, mono.cell_w, mono.cell_h, cov, theme::TEXT, None);
            }
        }
        crate::fonts::UI13.draw_right(&fb, r.right(), r.y + 22, date.as_str(), theme::TEXT_FAINT);
        self.damage(r.offset(0, self.sh - TASKBAR_H));
    }

    // ------------------------------------------------------------------
    // The start menu
    // ------------------------------------------------------------------

    fn open_menu(&mut self) {
        let (w, h) = (500, 470);
        self.menu_rect = Rect::new(8, self.sh - TASKBAR_H - h - 8, w, h);
        if self.menu.is_none() {
            self.menu = surface::alloc((w * h) as usize);
        }
        self.paint_menu();
        self.paint_taskbar();
    }

    fn close_menu(&mut self) {
        if let Some(b) = self.menu.take() {
            surface::free(b);
            self.damage(self.menu_rect);
            self.paint_taskbar();
        }
    }

    fn menu_item_rect(&self, i: usize) -> Rect {
        let cols = 4;
        let (cw, ch) = (112, 96);
        Rect::new(18 + (i % cols) as i32 * cw, 70 + (i / cols) as i32 * ch, cw - 8, ch - 8)
    }

    fn menu_power_rect(&self, which: u8) -> Rect {
        let h = self.menu_rect.h;
        match which {
            0 => Rect::new(18, h - 52, 132, 38),
            1 => Rect::new(160, h - 52, 132, 38),
            2 => Rect::new(self.menu_rect.w - 196, h - 52, 86, 38),
            _ => Rect::new(self.menu_rect.w - 102, h - 52, 86, 38),
        }
    }

    fn paint_menu(&mut self) {
        let Some(block) = self.menu else { return };
        let (w, h) = (self.menu_rect.w, self.menu_rect.h);
        // SAFETY: the menu's own block.
        let fb = unsafe { surface::surface(&block, w as u32, h as u32) };
        // Corners keyed out, then the panel.
        fb.fill(0, 0, w as u32, h as u32, KEY);
        theme::rounded(&fb, Rect::new(0, 0, w, h), 14, theme::MENU);
        theme::rounded_outline(&fb, Rect::new(0, 0, w, h), 14, 0x30343C);
        crate::fonts::UI20_SEMIBOLD.draw(&fb, 22, 18, "NanoChronometer", theme::TEXT, u32::MAX);
        crate::fonts::UI13.draw_right(&fb, w - 22, 24, crate::system::MACHINE, theme::TEXT_FAINT);
        for (i, kind) in Kind::ALL.iter().enumerate() {
            let r = self.menu_item_rect(i);
            if self.hover == Target::StartItem(i) {
                theme::rounded(&fb, r, 10, theme::HOVER);
            }
            theme::icon(&fb, kind.icon(), 48, r.x + (r.w - 48) / 2, r.y + 8);
            let label = kind.title();
            let label = if label.len() > 14 { label.split(' ').next().unwrap_or(label) } else { label };
            crate::fonts::UI13.draw_centred(&fb, r.x, r.w as u32, r.y + 64, label, theme::TEXT);
        }
        theme::fill(&fb, Rect::new(16, h - 66, w - 32, 1), 0x2E333B);
        for (which, label, style) in [
            (0u8, "Switch to CLI", theme::Style::Normal),
            (1, "Classic", theme::Style::Normal),
            (2, "Restart", theme::Style::Normal),
            (3, "Shut down", theme::Style::Danger),
        ] {
            let r = self.menu_power_rect(which);
            theme::button(&fb, r, label, style, self.hover == Target::StartPower(which));
        }
        self.damage(self.menu_rect);
    }

    // ------------------------------------------------------------------
    // Windows
    // ------------------------------------------------------------------

    fn ctx(&self, now_ns: u64, focused: bool) -> Ctx {
        Ctx { now_ns, focused }
    }

    fn open(&mut self, kind: Kind, now_ns: u64) {
        if kind.single() {
            if let Some(i) = self.window_of(kind) {
                self.focus_window(i);
                return;
            }
        }
        let Some(slot) = self.windows.iter().position(|w| w.is_none()) else { return };
        let (cw, ch) = kind.default_size(self.sw, self.sh - TASKBAR_H);
        let (fw, fh) = (cw, ch + TITLE_H);
        // Cascaded from the centre, so new windows do not stack exactly.
        let n = self.zn as i32;
        let x = ((self.sw - fw) / 2 + n * 28 - 56).clamp(0, (self.sw - fw).max(0));
        let y = ((self.sh - TASKBAR_H - fh) / 2 + n * 24 - 48).clamp(0, (self.sh - TASKBAR_H - fh).max(0));
        let Some(block) = surface::alloc((fw * fh) as usize) else { return };
        let ctx = self.ctx(now_ns, true);
        let Some(app) = App::new(kind, cw, ch, &ctx) else {
            surface::free(block);
            return;
        };
        let frame = Rect::new(x, y, fw, fh);
        self.windows[slot] = Some(Window {
            frame,
            restore: frame,
            maximized: false,
            minimized: false,
            block,
            app,
            ticks: 0,
            load_permille: 0,
            hover_button: None,
        });
        self.z[self.zn] = slot;
        self.zn += 1;
        self.focus = Some(slot);
        self.repaint_window(slot, now_ns, true);
        self.publish();
        self.paint_taskbar();
    }

    fn close(&mut self, i: usize) {
        let Some(mut w) = self.windows[i].take() else { return };
        w.app.closed();
        surface::free(w.block);
        self.damage(w.frame.inset(-16));
        if let Some(p) = self.z[..self.zn].iter().position(|&j| j == i) {
            self.z.copy_within(p + 1..self.zn, p);
            self.zn -= 1;
        }
        if self.focus == Some(i) {
            self.focus = self.z[..self.zn].iter().rev().copied().find(|&j| self.windows[j].as_ref().is_some_and(|w| !w.minimized));
            if let Some(f) = self.focus {
                self.repaint_frame(f);
            }
        }
        if self.captured == Some(i) {
            self.captured = None;
        }
        self.drag = None;
        self.publish();
        self.paint_taskbar();
    }

    fn focus_window(&mut self, i: usize) {
        if let Some(w) = self.windows[i].as_mut() {
            if w.minimized {
                w.minimized = false;
            }
        }
        if let Some(p) = self.z[..self.zn].iter().position(|&j| j == i) {
            self.z.copy_within(p + 1..self.zn, p);
            self.z[self.zn - 1] = i;
        }
        let previous = self.focus.replace(i);
        if let Some(p) = previous {
            if p != i {
                self.repaint_frame(p);
            }
        }
        self.repaint_frame(i);
        if let Some(w) = &self.windows[i] {
            self.damage(w.frame.inset(-16));
        }
        self.paint_taskbar();
    }

    fn minimize(&mut self, i: usize) {
        if let Some(w) = self.windows[i].as_mut() {
            w.minimized = true;
            let r = w.frame.inset(-16);
            self.damage(r);
        }
        if self.focus == Some(i) {
            self.focus = self.z[..self.zn].iter().rev().copied().find(|&j| j != i && self.windows[j].as_ref().is_some_and(|w| !w.minimized));
        }
        self.paint_taskbar();
    }

    fn toggle_maximize(&mut self, i: usize, now_ns: u64) {
        let work = self.work_area();
        let Some(w) = self.windows[i].as_mut() else { return };
        let target = if w.maximized { w.restore } else { work };
        let Some(block) = surface::alloc((target.w * target.h) as usize) else { return };
        let old = w.frame;
        surface::free(w.block);
        w.block = block;
        if !w.maximized {
            w.restore = w.frame;
        }
        w.maximized = !w.maximized;
        w.frame = target;
        w.app.resized(target.w, target.h - TITLE_H);
        self.damage(old.inset(-16));
        self.repaint_window(i, now_ns, true);
    }

    /// The title bar: icon, title, the three buttons.
    fn repaint_frame(&mut self, i: usize) {
        let focused = self.focus == Some(i);
        let Some(w) = &self.windows[i] else { return };
        // SAFETY: the window's own block.
        let fb = unsafe { w.surface() };
        let (fw, fh) = (w.frame.w, w.frame.h);
        let bar = if focused { theme::TITLE_FOCUSED } else { theme::TITLE_UNFOCUSED };
        fb.fill(0, 0, fw as u32, TITLE_H as u32, bar);
        theme::icon(&fb, w.app.kind().icon(), 16, 14, (TITLE_H - 16) / 2);
        let title = w.app.title();
        crate::fonts::UI15_SEMIBOLD.draw(&fb, 40, (TITLE_H - 19) / 2, title.as_str(), if focused { theme::TEXT } else { theme::TEXT_DIM }, (fw - 170).max(0) as u32);
        for b in 0..3u8 {
            let r = title_button(fw, b);
            let hovered = w.hover_button == Some(b);
            if hovered {
                theme::rounded(&fb, r, r.w / 2, if b == 2 { theme::DANGER } else { theme::HOVER });
            } else {
                theme::rounded(&fb, r, r.w / 2, if focused { 0x3A3F48 } else { 0x2F333A });
            }
            let ink = if hovered && b == 2 { 0xFFFFFF } else { theme::TEXT };
            let (cx, cy) = (r.x + r.w / 2, r.y + r.h / 2);
            match b {
                0 => theme::fill(&fb, Rect::new(cx - 5, cy, 10, 2), ink),
                1 => {
                    let sq = Rect::new(cx - 5, cy - 5, 10, 10);
                    theme::fill(&fb, Rect::new(sq.x, sq.y, sq.w, 2), ink);
                    theme::fill(&fb, Rect::new(sq.x, sq.bottom() - 1, sq.w, 1), ink);
                    theme::fill(&fb, Rect::new(sq.x, sq.y, 1, sq.h), ink);
                    theme::fill(&fb, Rect::new(sq.right() - 1, sq.y, 1, sq.h), ink);
                }
                _ => {
                    for d in 0..9 {
                        theme::fill(&fb, Rect::new(cx - 4 + d, cy - 4 + d, 2, 1), ink);
                        theme::fill(&fb, Rect::new(cx + 4 - d, cy - 4 + d, 2, 1), ink);
                    }
                }
            }
        }
        // The frame's edge and its rounded corners, keyed out so whatever is
        // under the window shows through them.
        let edge = if focused { theme::BORDER_FOCUSED } else { theme::BORDER };
        theme::fill(&fb, Rect::new(0, TITLE_H - 1, fw, 1), 0x1A1C20);
        theme::fill(&fb, Rect::new(0, 0, fw, 1), edge);
        theme::fill(&fb, Rect::new(0, fh - 1, fw, 1), edge);
        theme::fill(&fb, Rect::new(0, 0, 1, fh), edge);
        theme::fill(&fb, Rect::new(fw - 1, 0, 1, fh), edge);
        key_corners(&fb, fw, fh, if w.maximized { 0 } else { theme::RADIUS }, edge);
        let frame = w.frame;
        self.damage(Rect::new(frame.x, frame.y, frame.w, TITLE_H));
    }

    /// The app's whole client area, then the frame over its edges.
    fn repaint_window(&mut self, i: usize, now_ns: u64, frame_too: bool) {
        let focused = self.focus == Some(i);
        let ctx = self.ctx(now_ns, focused);
        let Some(w) = self.windows[i].as_mut() else { return };
        let t0 = crate::arch::counter_ordered();
        // SAFETY: the window's own block.
        let client = unsafe { w.client_surface() };
        let c = w.client();
        w.app.paint(&client, c.w, c.h, &ctx);
        w.ticks += crate::arch::counter_ordered().wrapping_sub(t0);
        let r = w.frame;
        if frame_too {
            self.repaint_frame(i);
        } else {
            // The app painted over the frame's bottom and side edges.
            self.repaint_frame(i);
        }
        self.damage(r.inset(-16));
    }

    fn apply(&mut self, i: usize, resp: Response, now_ns: u64) -> Option<SessionRequest> {
        if resp.close {
            self.close(i);
            return None;
        }
        if resp.repaint {
            self.repaint_window(i, now_ns, false);
        } else if let Some(d) = resp.dirty {
            if let Some(w) = &self.windows[i] {
                let r = d.offset(w.frame.x, w.frame.y + TITLE_H);
                if let Some(r) = r.intersect(&w.frame) {
                    self.damage(r);
                }
            }
        }
        if let Some(kind) = resp.open {
            self.open(kind, now_ns);
        }
        if let Some(n) = resp.wallpaper {
            self.set_wallpaper(n);
        }
        if let Some(action) = resp.power {
            self.ask_power(action, now_ns);
        }
        if let Some(mode) = resp.session {
            return Some(SessionRequest::Mode(mode));
        }
        if let Some(path) = resp.run_package {
            return Some(SessionRequest::Run(path));
        }
        None
    }

    // ------------------------------------------------------------------
    // Power
    // ------------------------------------------------------------------

    fn power_rect(&self) -> Rect {
        let (w, h) = (440, 200);
        Rect::new((self.sw - w) / 2, (self.sh - h) / 2, w, h)
    }

    fn ask_power(&mut self, action: nanochrono_core::power_confirm::Action, now_ns: u64) {
        let mut seed = [0u8; 8];
        let _ = crate::rng::fill(&mut seed, nanochrono_core::rng::Mode::Fast);
        if self.power.request(action, now_ns, u64::from_le_bytes(seed) ^ crate::arch::counter_ordered()).is_ok() {
            self.power_action = Some(action);
            self.close_menu();
            self.damage(self.power_rect().inset(-20));
        }
    }

    fn draw_power(&self, clip: Rect) {
        let Some(action) = self.power_action else { return };
        let r = self.power_rect();
        if r.inset(-20).intersect(&clip).is_none() {
            return;
        }
        // Drawn straight onto the back buffer, after the layers: small and
        // short-lived, no layer of its own.
        theme::shadow(self.fb, r, clip, 14);
        theme::rounded(self.fb, r, 14, theme::MENU);
        theme::rounded_outline(self.fb, r, 14, 0x30343C);
        let face = &crate::fonts::UI20_SEMIBOLD;
        let mut title = Text::<32>::new();
        let _ = write!(title, "{}?", if action == nanochrono_core::power_confirm::Action::Restart { "Restart" } else { "Shut down" });
        face.draw(self.fb, r.x + 24, r.y + 22, title.as_str(), theme::TEXT, u32::MAX);
        crate::fonts::UI13.draw(self.fb, r.x + 24, r.y + 58, "Type the code to confirm. Anything else cancels.", theme::TEXT_DIM, (r.w - 48) as u32);
        if let Some((_, code, typed)) = self.power.shown(self.now_ns) {
            let mut x = r.x + 24;
            for (k, d) in code.iter().enumerate() {
                let cell = Rect::new(x, r.y + 92, 52, 64);
                theme::rounded(self.fb, cell, 10, if k < typed { 0x2F6B3A } else { theme::CARD });
                let mut s = Text::<2>::new();
                let _ = write!(s, "{d}");
                crate::fonts::UI28_LIGHT.draw_centred(self.fb, cell.x, cell.w as u32, cell.y + 14, s.as_str(), theme::TEXT);
                x += 64;
            }
        }
    }

    // ------------------------------------------------------------------
    // Composition
    // ------------------------------------------------------------------

    fn compose(&mut self) {
        let n = self.nd;
        let rects = self.damage;
        self.nd = 0;
        // The cursor goes first: wherever it was is repainted from the
        // layers, then it is drawn where it is.
        let cursor = cursor_rect(self.cursor);
        let mut all = Rect::default();
        for r in &rects[..n] {
            self.compose_rect(*r);
            all = all.union(r);
        }
        let cursor_damaged = rects[..n].iter().any(|r| r.intersect(&cursor).is_some()) || self.cursor_drawn != cursor;
        if cursor_damaged {
            if self.cursor_drawn != cursor && !self.cursor_drawn.is_empty() {
                let old = self.cursor_drawn;
                self.compose_rect(old);
                self.fb.present(old.x.max(0) as u32, old.y.max(0) as u32, old.w as u32, old.h as u32);
            }
            draw_cursor(self.fb, self.cursor);
            self.cursor_drawn = cursor;
        }
        for r in &rects[..n] {
            self.fb.present(r.x as u32, r.y as u32, r.w as u32, r.h as u32);
        }
        if cursor_damaged {
            self.fb.present(cursor.x.max(0) as u32, cursor.y.max(0) as u32, cursor.w as u32, cursor.h as u32);
        }
        self.fb.discard_damage();
        let _ = all;
    }

    fn compose_rect(&mut self, clip: Rect) {
        let Some(clip) = clip.intersect(&self.screen()) else { return };
        // 1. The background.
        // SAFETY: the desktop's own block, read only here.
        let bg = unsafe { self.background.pixels() };
        let start = (clip.y * self.sw + clip.x) as usize;
        self.fb.blit(clip.x, clip.y, clip.w as u32, clip.h as u32, &bg[start..], self.sw as usize);
        // 2. Windows, bottom to top.
        for k in 0..self.zn {
            let i = self.z[k];
            let Some(w) = &self.windows[i] else { continue };
            if w.minimized {
                continue;
            }
            if !w.maximized && w.frame.inset(-14).intersect(&clip).is_some() {
                theme::shadow(self.fb, w.frame, clip, if self.focus == Some(i) { 14 } else { 8 });
            }
            let Some(part) = w.frame.intersect(&clip) else { continue };
            // SAFETY: the window's own block, read only here.
            let px = unsafe { w.block.pixels() };
            blit_keyed(self.fb, px, w.frame, part);
        }
        // 3. The taskbar.
        let tb = self.taskbar_rect();
        if let Some(part) = tb.intersect(&clip) {
            // SAFETY: the desktop's own block.
            let px = unsafe { self.taskbar.pixels() };
            let from = ((part.y - tb.y) * self.sw + part.x) as usize;
            self.fb.blit(part.x, part.y, part.w as u32, part.h as u32, &px[from..], self.sw as usize);
        }
        // 4. The start menu.
        if let Some(block) = self.menu {
            if let Some(part) = self.menu_rect.intersect(&clip) {
                theme::shadow(self.fb, self.menu_rect, clip, 10);
                // SAFETY: the menu's own block.
                let px = unsafe { block.pixels() };
                blit_keyed(self.fb, px, self.menu_rect, part);
            } else if self.menu_rect.inset(-10).intersect(&clip).is_some() {
                theme::shadow(self.fb, self.menu_rect, clip, 10);
            }
        }
        // 5. The power dialog.
        self.draw_power(clip);
    }

    // ------------------------------------------------------------------
    // Input
    // ------------------------------------------------------------------

    fn target_at(&self, x: i32, y: i32) -> Target {
        if self.menu.is_some() && self.menu_rect.contains(x, y) {
            let (lx, ly) = (x - self.menu_rect.x, y - self.menu_rect.y);
            for i in 0..Kind::ALL.len() {
                if self.menu_item_rect(i).contains(lx, ly) {
                    return Target::StartItem(i);
                }
            }
            for b in 0..4u8 {
                if self.menu_power_rect(b).contains(lx, ly) {
                    return Target::StartPower(b);
                }
            }
            return Target::Nothing;
        }
        if self.taskbar_rect().contains(x, y) {
            if Rect::new(8, self.sh - TASKBAR_H + 6, 44, 40).contains(x, y) {
                return Target::Start;
            }
            for k in 0..self.taskbar_n {
                if self.taskbar_slots[k].0.contains(x, y) {
                    return Target::TaskbarApp(k);
                }
            }
            return Target::Nothing;
        }
        for k in (0..self.zn).rev() {
            let i = self.z[k];
            let Some(w) = &self.windows[i] else { continue };
            if w.minimized || !w.frame.contains(x, y) {
                continue;
            }
            let (lx, ly) = (x - w.frame.x, y - w.frame.y);
            if ly < TITLE_H {
                for b in 0..3u8 {
                    if title_button(w.frame.w, b).contains(lx, ly) {
                        return Target::TitleButton(i, b);
                    }
                }
            }
            return Target::Window(i);
        }
        for i in 0..ICON_COLUMN.len() {
            if self.icon_rect(i).contains(x, y) {
                return Target::Icon(i);
            }
        }
        Target::Nothing
    }

    fn set_hover(&mut self, target: Target) {
        if target == self.hover {
            return;
        }
        let old = self.hover;
        self.hover = target;
        for t in [old, target] {
            match t {
                Target::Start | Target::TaskbarApp(_) => self.paint_taskbar(),
                Target::StartItem(_) | Target::StartPower(_) => self.paint_menu(),
                Target::Icon(i) => self.bake_icon(i),
                Target::TitleButton(i, _) => {
                    if let Some(w) = self.windows[i].as_mut() {
                        w.hover_button = if let Target::TitleButton(j, b) = target { (j == i).then_some(b) } else { None };
                    }
                    self.repaint_frame(i);
                }
                _ => {}
            }
        }
    }

    fn pointer(&mut self, dx: i32, dy: i32, left: bool, wheel: i32, now_ns: u64) -> Option<SessionRequest> {
        let (ox, oy) = self.cursor;
        self.cursor = ((ox + dx).clamp(0, self.sw - 1), (oy + dy).clamp(0, self.sh - 1));
        let (x, y) = self.cursor;
        let pressed = left && !self.left;
        let released = !left && self.left;
        self.left = left;

        if let Some(drag) = &self.drag {
            let i = drag.window;
            let (ddx, ddy) = (drag.dx, drag.dy);
            if released {
                self.drag = None;
            } else if (dx, dy) != (0, 0) {
                let work = self.work_area();
                if let Some(w) = self.windows[i].as_mut() {
                    let old = w.frame;
                    w.frame.x = (x - ddx).clamp(-w.frame.w + 80, work.right() - 80);
                    w.frame.y = (y - ddy).clamp(0, work.bottom() - TITLE_H);
                    let new = w.frame;
                    self.damage(old.inset(-16));
                    self.damage(new.inset(-16));
                }
            }
            return None;
        }

        // A drag that started in a window's client area goes on to it.
        if let Some(i) = self.captured {
            if let Some(w) = &self.windows[i] {
                let (lx, ly) = (x - w.frame.x, y - w.frame.y - TITLE_H);
                let ev = if released { Event::PointerUp { x: lx, y: ly } } else { Event::PointerMove { x: lx, y: ly } };
                if released {
                    self.captured = None;
                }
                return self.app_event(i, ev, now_ns);
            }
            self.captured = None;
        }

        let target = self.target_at(x, y);
        self.set_hover(target);
        if wheel != 0 {
            if let Target::Window(i) = target {
                if let Some(w) = &self.windows[i] {
                    let (lx, ly) = (x - w.frame.x, y - w.frame.y - TITLE_H);
                    return self.app_event(i, Event::Wheel { x: lx, y: ly, delta: wheel }, now_ns);
                }
            }
        }
        if !pressed {
            if let Target::Window(i) = target {
                if let Some(w) = &self.windows[i] {
                    let (lx, ly) = (x - w.frame.x, y - w.frame.y - TITLE_H);
                    if ly >= 0 && (dx, dy) != (0, 0) {
                        return self.app_event(i, Event::PointerMove { x: lx, y: ly }, now_ns);
                    }
                }
            }
            return None;
        }

        // A press.
        if self.power_action.is_some() {
            self.cancel_power();
            return None;
        }
        match target {
            Target::Start => {
                if self.menu.is_some() {
                    self.close_menu();
                } else {
                    self.open_menu();
                }
            }
            Target::StartItem(i) => {
                self.close_menu();
                self.open(Kind::ALL[i], now_ns);
            }
            Target::StartPower(b) => {
                self.close_menu();
                match b {
                    0 => return Some(SessionRequest::Mode(crate::boot::Mode::Cli)),
                    1 => return Some(SessionRequest::Mode(crate::boot::Mode::Classic)),
                    2 => self.ask_power(nanochrono_core::power_confirm::Action::Restart, now_ns),
                    _ => self.ask_power(nanochrono_core::power_confirm::Action::Shutdown, now_ns),
                }
            }
            Target::TaskbarApp(k) => {
                self.close_menu();
                let (_, win, kind) = self.taskbar_slots[k];
                match win {
                    Some(i) if self.focus == Some(i) && !self.windows[i].as_ref().is_some_and(|w| w.minimized) => self.minimize(i),
                    Some(i) => self.focus_window(i),
                    None => self.open(kind, now_ns),
                }
            }
            Target::TitleButton(i, b) => {
                self.close_menu();
                match b {
                    0 => self.minimize(i),
                    1 => self.toggle_maximize(i, now_ns),
                    _ => self.close(i),
                }
            }
            Target::Window(i) => {
                self.close_menu();
                if self.focus != Some(i) || self.z[self.zn - 1] != i {
                    self.focus_window(i);
                }
                let Some(w) = &self.windows[i] else { return None };
                let (lx, ly) = (x - w.frame.x, y - w.frame.y);
                let maximized = w.maximized;
                if ly < TITLE_H {
                    let double = self.last_title_click.0 == Some(i) && now_ns.wrapping_sub(self.last_title_click.1) < 450_000_000;
                    self.last_title_click = (Some(i), now_ns);
                    if double {
                        self.toggle_maximize(i, now_ns);
                    } else if !maximized {
                        self.drag = Some(Drag { window: i, dx: lx, dy: ly });
                    }
                    return None;
                }
                self.captured = Some(i);
                return self.app_event(i, Event::PointerDown { x: lx, y: ly - TITLE_H }, now_ns);
            }
            Target::Icon(i) => {
                self.close_menu();
                let double = self.last_icon_click.0 == Some(i) && now_ns.wrapping_sub(self.last_icon_click.1) < 450_000_000;
                self.last_icon_click = (Some(i), now_ns);
                let previous = self.selected_icon.replace(i);
                if let Some(p) = previous {
                    self.bake_icon(p);
                }
                self.bake_icon(i);
                if double {
                    self.open(ICON_COLUMN[i], now_ns);
                }
            }
            Target::Nothing => {
                self.close_menu();
                if let Some(p) = self.selected_icon.take() {
                    self.bake_icon(p);
                }
            }
        }
        None
    }

    fn cancel_power(&mut self) {
        self.power.cancel();
        self.power_action = None;
        self.damage(self.power_rect().inset(-20));
    }

    fn key(&mut self, key: crate::input::Key, now_ns: u64) -> Option<SessionRequest> {
        // The Super key alone opens the start menu, as on every desktop.
        if key.extended && matches!(key.scancode, 0x5B | 0x5C) {
            if key.pressed {
                self.super_down = true;
                self.super_used = false;
            } else if self.super_down {
                self.super_down = false;
                if !self.super_used {
                    if self.menu.is_some() {
                        self.close_menu();
                    } else {
                        self.open_menu();
                    }
                }
            }
        } else if key.pressed && self.super_down {
            self.super_used = true;
        }
        let input = self.keyboard.feed(key)?;

        if let Some(action) = self.power_action {
            match input {
                KeyInput::Char(c) if c.is_ascii_digit() => match self.power.digit(c as u8 - b'0', now_ns) {
                    nanochrono_core::power_confirm::Outcome::Confirmed(_) => {
                        let acpi = crate::system::get().and_then(|s| s.acpi.as_ref());
                        // SAFETY: kernel privilege; the user typed the code.
                        unsafe {
                            match action {
                                nanochrono_core::power_confirm::Action::Restart => crate::acpi::reboot(acpi),
                                nanochrono_core::power_confirm::Action::Shutdown => crate::acpi::shutdown(acpi),
                            }
                        }
                        self.cancel_power();
                    }
                    nanochrono_core::power_confirm::Outcome::Pending => self.damage(self.power_rect()),
                    _ => self.cancel_power(),
                },
                _ => self.cancel_power(),
            }
            return None;
        }

        let alt = self.keyboard.alt();
        match input {
            KeyInput::Tab if alt => {
                // Alt+Tab: the window under the top one comes up.
                if self.zn >= 2 {
                    let next = self.z[self.zn - 2];
                    self.focus_window(next);
                }
                return None;
            }
            KeyInput::Function(4) if alt => {
                if let Some(f) = self.focus {
                    self.close(f);
                }
                return None;
            }
            KeyInput::Ctrl('t') if alt => {
                self.open(Kind::Terminal, now_ns);
                return None;
            }
            KeyInput::Escape if self.menu.is_some() => {
                self.close_menu();
                return None;
            }
            _ => {}
        }
        if self.menu.is_some() {
            return None;
        }
        let i = self.focus?;
        self.app_event(i, Event::Key(input), now_ns)
    }

    fn app_event(&mut self, i: usize, ev: Event, now_ns: u64) -> Option<SessionRequest> {
        let focused = self.focus == Some(i);
        let ctx = self.ctx(now_ns, focused);
        let w = self.windows[i].as_mut()?;
        let t0 = crate::arch::counter_ordered();
        // SAFETY: the window's own block.
        let client = unsafe { w.client_surface() };
        let c = w.client();
        let resp = w.app.event(ev, &client, c.w, c.h, &ctx);
        w.ticks += crate::arch::counter_ordered().wrapping_sub(t0);
        self.apply(i, resp, now_ns)
    }

    fn tick_apps(&mut self, now_ns: u64) -> Option<SessionRequest> {
        for k in 0..self.zn {
            let i = self.z[k];
            let focused = self.focus == Some(i);
            let ctx = self.ctx(now_ns, focused);
            let Some(w) = self.windows[i].as_mut() else { continue };
            if w.minimized && !matches!(w.app.kind(), Kind::Terminal) {
                continue;
            }
            let t0 = crate::arch::counter_ordered();
            // SAFETY: the window's own block.
            let client = unsafe { w.client_surface() };
            let c = w.client();
            let resp = w.app.tick(&client, c.w, c.h, &ctx);
            w.ticks += crate::arch::counter_ordered().wrapping_sub(t0);
            if let Some(req) = self.apply(i, resp, now_ns) {
                return Some(req);
            }
        }
        None
    }

    /// Last second's figures, for `top`, `ps` and the Task Manager.
    fn account(&mut self, hz: u64) {
        for w in self.windows.iter_mut().flatten() {
            w.load_permille = ((w.ticks as u128 * 1000) / hz.max(1) as u128).min(1000) as u32;
            w.ticks = 0;
        }
        // SAFETY: one core.
        unsafe { *core::ptr::addr_of_mut!(PHASES) = cpuload::take_task_ticks() };
        self.publish();
    }

    fn publish(&mut self) {
        let mut infos: [Option<AppInfo>; MAX_WINDOWS] = [None; MAX_WINDOWS];
        for (slot, w) in infos.iter_mut().zip(self.windows.iter()) {
            if let Some(w) = w {
                let kind = w.app.kind();
                *slot = Some(AppInfo {
                    name: kind.process(),
                    icon: kind.icon(),
                    load_permille: w.load_permille,
                    memory_bytes: w.block.bytes(),
                    essential: kind.essential(),
                });
            }
        }
        // SAFETY: one core.
        unsafe { *core::ptr::addr_of_mut!(INFOS) = infos };
    }

    /// The Task Manager's End task: the `index`-th window as `app_infos`
    /// lists them (slot order).
    fn close_listed(&mut self, index: usize) {
        if let Some(i) = self.windows.iter().enumerate().filter(|(_, w)| w.is_some()).map(|(i, _)| i).nth(index) {
            self.close(i);
        }
    }
}

/// What the loop has to leave the desktop for.
enum SessionRequest {
    Mode(crate::boot::Mode),
    Run(Text<128>),
}

/// A pixel value no colour uses: the top byte set. Window and menu surfaces
/// put it where their rounded corners leave the frame, and the compositor
/// skips it.
const KEY: Colour = 0xFF00_0000;

/// Keys out the four corners of a `w x h` frame outside a radius-`r` arc,
/// and draws the arc's edge in `edge`.
fn key_corners(fb: &Framebuffer, w: i32, h: i32, r: i32, edge: Colour) {
    if r <= 0 {
        return;
    }
    for dy in 0..r {
        for dx in 0..r {
            let (ex, ey) = (r - dx, r - dy);
            let d2 = ex * ex + ey * ey;
            let inside = d2 <= (r - 1) * (r - 1);
            let on_edge = d2 <= r * r && !inside;
            for (x, y) in [(dx, dy), (w - 1 - dx, dy), (dx, h - 1 - dy), (w - 1 - dx, h - 1 - dy)] {
                if on_edge {
                    fb.set(x as u32, y as u32, edge);
                } else if !inside {
                    fb.set(x as u32, y as u32, KEY);
                }
            }
        }
    }
}

/// Copies `part` (screen coordinates, inside `frame`) of a layer whose
/// pixels cover `frame`, skipping keyed pixels. Rows with no corner in them
/// go across whole.
fn blit_keyed(fb: &Framebuffer, px: &[u32], frame: Rect, part: Rect) {
    let corner = theme::RADIUS.max(14);
    for y in part.y..part.bottom() {
        let ly = y - frame.y;
        let from = (ly * frame.w + (part.x - frame.x)) as usize;
        let Some(row) = px.get(from..from + part.w as usize) else { return };
        if ly >= corner && ly < frame.h - corner {
            fb.blit(part.x, y, part.w as u32, 1, row, part.w as usize);
            continue;
        }
        for (k, &p) in row.iter().enumerate() {
            if p & KEY != KEY {
                fb.set((part.x + k as i32) as u32, y as u32, p);
            }
        }
    }
}

/// The window's three title-bar buttons: minimize, maximize, close.
fn title_button(fw: i32, b: u8) -> Rect {
    let size = 26;
    Rect::new(fw - 12 - (3 - b as i32) * (size + 8) + 8, (TITLE_H - size) / 2, size, size)
}

fn cursor_rect(pos: (i32, i32)) -> Rect {
    Rect::new(pos.0 - 1, pos.1 - 1, 15, 22)
}

/// An arrow cursor: white with a dark outline, drawn straight onto the
/// back buffer.
fn draw_cursor(fb: &Framebuffer, (x, y): (i32, i32)) {
    const SHAPE: [&str; 19] = [
        "X",
        "XX",
        "X.X",
        "X..X",
        "X...X",
        "X....X",
        "X.....X",
        "X......X",
        "X.......X",
        "X........X",
        "X.........X",
        "X......XXXXX",
        "X...X..X",
        "X..XX..X",
        "X.X  X..X",
        "XX   X..X",
        "X     X..X",
        "      X..X",
        "       XX",
    ];
    for (dy, row) in SHAPE.iter().enumerate() {
        for (dx, c) in row.bytes().enumerate() {
            let colour = match c {
                b'X' => 0x101214,
                b'.' => 0xFFFFFF,
                _ => continue,
            };
            let (px, py) = (x + dx as i32, y + dy as i32);
            if px >= 0 && py >= 0 {
                fb.set(px as u32, py as u32, colour);
            }
        }
    }
}

/// Runs the desktop for the rest of the session.
///
/// # Safety
/// Kernel privilege; `fb` is the screen, with its back buffer attached.
pub unsafe fn run(fb: &Framebuffer, memory: Memory) -> ! {
    // SAFETY: forwarded. The system and the file tree may already be up (a
    // switch from the CLI); both calls are idempotent.
    let system = match crate::system::get() {
        Some(s) => s,
        None => unsafe { crate::system::init(memory) },
    };
    // SAFETY: once per session; idempotent.
    unsafe { crate::vfs::init() };
    // SAFETY: as above.
    unsafe { cpuload::init() };
    crate::config::from_command_line();
    RUNNING.store(true, core::sync::atomic::Ordering::Relaxed);

    // SAFETY: kernel privilege; a microsecond of counter ticks for the I2C
    // driver's timeouts.
    let mut input = unsafe { Input::init(system.hz() / 1_000_000) };

    let mut desktop = Desktop::new(fb);
    desktop.set_wallpaper(crate::config::wallpaper());
    desktop.compose();

    let hz = system.hz();
    let mut next_frame = 0u64;
    let mut second = system.uptime_ns();
    loop {
        cpuload::switch_to(Task::Input);
        let now_ns = system.uptime_ns();
        desktop.now_ns = now_ns;
        let mut request = None;
        for _ in 0..32 {
            // SAFETY: kernel privilege.
            let Some(event) = (unsafe { input.poll() }) else { break };
            cpuload::switch_to(Task::Measure);
            request = match event {
                InputEvent::Key(k) => {
                    crate::rng::stir(nanochrono_core::rng::EVENT_KEY, k.scancode as u64 | (k.pressed as u64) << 8);
                    desktop.key(k, now_ns)
                }
                InputEvent::Motion(m) => {
                    crate::rng::stir(nanochrono_core::rng::EVENT_POINTER, (m.dx as u32 as u64) | (m.dy as u32 as u64) << 32);
                    desktop.pointer(m.dx, m.dy, m.left, m.wheel, now_ns)
                }
            };
            cpuload::switch_to(Task::Input);
            if request.is_some() {
                break;
            }
        }
        // SAFETY: one core.
        if let Some(i) = unsafe { (*core::ptr::addr_of_mut!(CLOSE_REQUEST)).take() } {
            desktop.close_listed(i);
        }

        if request.is_none() {
            if now_ns < next_frame {
                let wait = (next_frame - now_ns).min(2_000_000);
                cpuload::idle_until(crate::arch::counter_ordered().wrapping_add(system.clock.calibration.ns_to_ticks(wait)));
                continue;
            }
            next_frame = now_ns + FRAME_NS;
            cpuload::switch_to(Task::Measure);
            request = desktop.tick_apps(now_ns);
            if desktop.power_action.is_some() && !desktop.power.is_pending(now_ns) {
                desktop.cancel_power();
            }
            cpuload::switch_to(Task::Render);
            desktop.paint_clock();
            if now_ns.wrapping_sub(second) >= 1_000_000_000 {
                second = now_ns;
                desktop.account(hz);
                let busy = phase_ticks();
                let total: u64 = busy.iter().sum::<u64>().max(1);
                let idle = busy[Task::Idle as usize];
                let permille = ((total - idle.min(total)) * 1000 / total) as u32;
                desktop.load_text.clear();
                let _ = write!(desktop.load_text, "{}.{}%", permille / 10, permille % 10);
                desktop.paint_taskbar();
            }
            cpuload::switch_to(Task::Present);
            desktop.compose();
        }

        match request {
            None => {}
            Some(SessionRequest::Mode(mode)) => {
                RUNNING.store(false, core::sync::atomic::Ordering::Relaxed);
                crate::boot::set_mode(mode);
                match mode {
                    // SAFETY: kernel privilege; the desktop gives the screen
                    // up for good.
                    crate::boot::Mode::Cli => unsafe { crate::cli::run(Some(fb), memory) },
                    crate::boot::Mode::Classic => unsafe { crate::gui::run(fb, memory) },
                    crate::boot::Mode::Gui => {}
                }
            }
            Some(SessionRequest::Run(path)) => {
                run_package(&mut desktop, &mut input, path.as_str(), hz);
            }
        }
    }
}

/// Runs a package full screen through the plugin loader, then gives the
/// screen back to the desktop.
fn run_package(desktop: &mut Desktop<'_>, input: &mut Input, path: &str, hz: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let Some(crate::vfs::Node { content: crate::vfs::Content::Bytes(bytes), .. }) = crate::vfs::lookup(path) else {
            return;
        };
        let name = path.rsplit('/').next().unwrap_or(path);
        if let Some(system) = crate::system::get() {
            // SAFETY: kernel privilege; the screen and the input stay valid
            // for the call, and nothing else draws meanwhile.
            unsafe { crate::ncplu::run(name, bytes, desktop.fb, input, &system.pmu, hz) };
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (input, path, hz);
    desktop.cursor_drawn = Rect::default();
    desktop.damage_all();
}
