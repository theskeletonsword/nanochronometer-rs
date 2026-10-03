// SPDX-License-Identifier: Apache-2.0
//! Terminal: the shell the CLI runs, in a window.
//!
//! The same [`Shell`] and the same commands as `mode=cli` — `top`, the
//! stopwatch, `nanochrono` — on a [`Term`] drawn into the window's surface.
//! A graphical terminal, so colour is on (`color off` turns it off); the CLI
//! itself stays plain text. A running `top` is a job the frame ticks, so the
//! desktop keeps drawing while it runs.

use super::{Ctx, Event, Response};
use crate::desktop::surface::Rect;
use crate::framebuffer::Framebuffer;
use crate::kbd::KeyInput;
use crate::shell::{Request, Shell};
use crate::term::{Cell, Term, Theme};

/// How many terminal windows can be open at once, and how many cells each
/// may have: 160 x 60 covers a window maximized on a 1920 x 1200 panel at
/// the small face's 8 x 18 cells... nearly; a larger one is clipped.
const SLOTS: usize = 4;
const SLOT_COLS: usize = 200;
const SLOT_ROWS: usize = 64;
const SLOT_CELLS: usize = SLOT_COLS * SLOT_ROWS;

static mut CELLS: [[Cell; SLOT_CELLS]; SLOTS] = [[Cell::BLANK; SLOT_CELLS]; SLOTS];
/// The slots' shells: written when a slot is taken, never read before
/// (`TAKEN` says which are live). Uninitialised, so `.bss`.
static mut SHELLS: [core::mem::MaybeUninit<Shell>; SLOTS] = [const { core::mem::MaybeUninit::uninit() }; SLOTS];
static mut TAKEN: [bool; SLOTS] = [false; SLOTS];

/// The bytes the terminal pool takes, for the memory report.
pub const POOL_BYTES: usize = core::mem::size_of::<[[Cell; SLOT_CELLS]; SLOTS]>();

const MARGIN: i32 = 6;

pub struct TerminalApp {
    slot: usize,
    term: Term,
    started: bool,
}

fn face() -> &'static crate::fonts::MonoFace {
    &crate::fonts::TERM14
}

impl TerminalApp {
    pub fn new(w: i32, h: i32) -> Option<TerminalApp> {
        // SAFETY: one core; a slot is handed out once until `closed`.
        let taken = unsafe { &mut *core::ptr::addr_of_mut!(TAKEN) };
        let slot = taken.iter().position(|t| !*t)?;
        taken[slot] = true;
        // SAFETY: the slot was free, so nothing else references its cells.
        let all: &'static mut [[Cell; SLOT_CELLS]; SLOTS] = unsafe { &mut *core::ptr::addr_of_mut!(CELLS) };
        let cells: &'static mut [Cell] = &mut all[slot][..];
        let (cols, rows) = Self::grid(w, h);
        let term = Term::new(cells, cols, rows);
        // SAFETY: as above, for the slot's shell; written before any read.
        unsafe { (*core::ptr::addr_of_mut!(SHELLS))[slot].write(Shell::new(false, true)) };
        Some(TerminalApp { slot, term, started: false })
    }

    fn grid(w: i32, h: i32) -> (usize, usize) {
        let f = face();
        let cols = ((w - 2 * MARGIN).max(f.cell_w as i32) / f.cell_w as i32) as usize;
        let rows = ((h - 2 * MARGIN).max(f.cell_h as i32) / f.cell_h as i32) as usize;
        (cols.min(SLOT_COLS), rows.min(SLOT_ROWS))
    }

    fn shell(&mut self) -> &mut Shell {
        // SAFETY: the slot is this app's while it is open, and was written
        // when it was taken.
        unsafe { (*core::ptr::addr_of_mut!(SHELLS))[self.slot].assume_init_mut() }
    }

    pub fn cwd(&self) -> &str {
        // SAFETY: as `shell`, read only.
        unsafe { (*core::ptr::addr_of!(SHELLS))[self.slot].assume_init_ref().cwd.as_str() }
    }

    pub fn resized(&mut self, w: i32, h: i32) {
        let (cols, rows) = Self::grid(w, h);
        self.term.resize(cols, rows);
    }

    pub fn closed(&mut self) {
        // SAFETY: one core; the slot goes back to the pool (a shell holds no
        // resources, so nothing needs dropping).
        unsafe { (*core::ptr::addr_of_mut!(TAKEN))[self.slot] = false };
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, ctx: &Ctx) {
        let theme = Theme::DARK;
        fb.fill(0, 0, w as u32, h as u32, theme.background);
        if !self.started {
            self.started = true;
            let term = &mut self.term as *mut Term;
            // SAFETY: `term` is this app's own, disjoint from the shell slot.
            self.shell().start(unsafe { &mut *term });
        }
        self.term.invalidate();
        self.term.render(fb, MARGIN as u32, MARGIN as u32, face(), &theme, ctx.focused);
    }

    pub fn tick(&mut self, fb: &Framebuffer, _w: i32, _h: i32, ctx: &Ctx) -> Response {
        let term = &mut self.term as *mut Term;
        // SAFETY: as in `paint`.
        self.shell().tick(unsafe { &mut *term }, ctx.now_ns);
        let mut response = self.requests();
        // Whatever the shell or a job wrote shows now.
        let theme = Theme::DARK;
        self.term.render(fb, MARGIN as u32, MARGIN as u32, face(), &theme, ctx.focused);
        let f = face();
        response = response.merge(Response::dirty(Rect::new(
            0,
            0,
            self.term.cols as i32 * f.cell_w as i32 + 2 * MARGIN,
            self.term.rows as i32 * f.cell_h as i32 + 2 * MARGIN,
        )));
        response
    }

    fn requests(&mut self) -> Response {
        let request = core::mem::replace(&mut self.shell().request, Request::None);
        match request {
            Request::None | Request::Gui => Response::default(),
            Request::Close => Response { close: true, ..Response::default() },
            Request::Classic => Response { session: Some(crate::boot::Mode::Classic), ..Response::default() },
        }
    }

    pub fn event(&mut self, ev: Event, fb: &Framebuffer, w: i32, h: i32, ctx: &Ctx) -> Response {
        let _ = (fb, w, h);
        if let Event::Key(k) = ev {
            let term = &mut self.term as *mut Term;
            // SAFETY: as in `paint`.
            self.shell().input(k, unsafe { &mut *term }, ctx.now_ns);
            if matches!(k, KeyInput::Ctrl('d')) && self.shell().job_is_idle_and_line_empty() {
                return Response { close: true, ..Response::default() };
            }
        }
        Response::default()
    }
}
