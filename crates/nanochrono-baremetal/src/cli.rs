// SPDX-License-Identifier: Apache-2.0
//! The NanoChronometer CLI (`mode=cli`): a full-screen text terminal and a
//! Unix-like shell, the hosted CLI's `nanochrono` among its commands.
//!
//! Pure text, the way a server console is: the terminal is drawn on the
//! framebuffer in "NC Terminal" (`crate::fonts`), and every byte of it also
//! goes to the serial line, so the same session runs from a serial terminal —
//! which is all there is on a machine without a framebuffer. Keys come from
//! the keyboard (PS/2, USB, I2C) through the layout `kbd=` chose, and from
//! the serial line as bytes.
//!
//! Everything the kernel prints while the CLI runs — a driver's message, the
//! self-test — lands in the terminal too (the console sink), and `dmesg`
//! shows what was printed before it started.

use crate::cpuload::{self, Task};
use crate::framebuffer::Framebuffer;
use crate::multiboot::Memory;
use crate::shell::{Request, Shell};
use crate::term::{Cell, Term, Theme, MAX_COLS, MAX_ROWS};

/// The full-screen terminal's cells.
static mut CELLS: [Cell; MAX_COLS * MAX_ROWS] = [Cell::BLANK; MAX_COLS * MAX_ROWS];
/// Their size, for the memory report.
pub const CELLS_BYTES: usize = core::mem::size_of::<Cell>() * MAX_COLS * MAX_ROWS;

static mut TERM: Option<Term> = None;
static ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Where kernel messages go while the CLI runs: its terminal.
fn cli_sink(s: &str) {
    // SAFETY: the CLI owns the terminal for the rest of the run; one core,
    // and the sink never re-enters.
    if let Some(term) = unsafe { (*core::ptr::addr_of_mut!(TERM)).as_mut() } {
        for c in s.chars() {
            if c == '\n' {
                term.feed('\r');
            }
            term.feed(c);
        }
    }
}

/// Puts the console sink back after a command captured it: the CLI's
/// terminal while the CLI runs, nothing otherwise.
pub fn restore_sink() {
    if ACTIVE.load(core::sync::atomic::Ordering::Relaxed) {
        crate::serial::set_console_sink(Some(cli_sink));
    } else {
        crate::serial::set_console_sink(None);
    }
}

const FRAME_NS: u64 = 1_000_000_000 / 60;

/// Runs the CLI for the rest of the session.
///
/// # Safety
/// Kernel privilege, once per session, after the boot-time setup; `fb`, when
/// given, is the screen the loader described, with its back buffer attached.
pub unsafe fn run(fb: Option<&Framebuffer>, memory: Memory) -> ! {
    // SAFETY: forwarded.
    let system = unsafe { crate::system::init(memory) };
    // SAFETY: once, after the modules are recorded.
    unsafe { crate::vfs::init() };
    // SAFETY: as above.
    unsafe { cpuload::init() };

    let theme = Theme::MONO;
    let face = match fb {
        Some(fb) => crate::fonts::face_for(fb.width, fb.height, 120, 36),
        None => &crate::fonts::TERM14,
    };
    let (cols, rows, x0, y0) = match fb {
        Some(fb) => {
            let cols = ((fb.width - 8) / face.cell_w) as usize;
            let rows = ((fb.height - 8) / face.cell_h) as usize;
            let x0 = (fb.width - cols as u32 * face.cell_w) / 2;
            let y0 = (fb.height - rows as u32 * face.cell_h) / 2;
            (cols.min(MAX_COLS), rows.min(MAX_ROWS), x0, y0)
        }
        None => (80, 25, 0, 0),
    };
    // SAFETY: once; nothing else references the cells.
    let cells: &'static mut [Cell] = unsafe { &mut *core::ptr::addr_of_mut!(CELLS) };
    // SAFETY: once, before the sink can run.
    unsafe { *core::ptr::addr_of_mut!(TERM) = Some(Term::new(cells, cols, rows)) };
    // SAFETY: as above; from here the CLI owns it.
    let term = unsafe { (*core::ptr::addr_of_mut!(TERM)).as_mut().expect("just set") };
    if let Some(fb) = fb {
        fb.clear(theme.background);
        fb.present(0, 0, fb.width, fb.height);
        fb.discard_damage();
    }

    // The keyboard: PS/2, USB and I2C on x86. Elsewhere the console is the
    // serial line, read below as bytes.
    #[cfg(x86_any)]
    // SAFETY: kernel privilege; a microsecond of counter ticks for the I2C
    // driver's timeouts.
    let mut input = unsafe { crate::input::Input::init(system.hz() / 1_000_000) };

    ACTIVE.store(true, core::sync::atomic::Ordering::Relaxed);
    restore_sink();
    // Plain text for good: `color on` is refused here (`Shell::cli`).
    let mut shell = Shell::cli();
    shell.start(term);

    let mut next_frame = 0u64;
    loop {
        cpuload::switch_to(Task::Input);
        let now_ns = system.uptime_ns();
        #[cfg(x86_any)]
        for _ in 0..32 {
            // SAFETY: kernel privilege.
            match unsafe { input.poll() } {
                Some(crate::input::Event::Key(k)) => {
                    crate::rng::stir(nanochrono_core::rng::EVENT_KEY, k.scancode as u64 | (k.pressed as u64) << 8);
                    cpuload::switch_to(Task::Measure);
                    shell.key(k, term, now_ns);
                    cpuload::switch_to(Task::Input);
                }
                Some(_) => {}
                None => break,
            }
        }
        for _ in 0..256 {
            let Some(byte) = crate::serial::read_byte() else { break };
            crate::rng::stir(nanochrono_core::rng::EVENT_KEY, byte as u64 | 0x8000);
            cpuload::switch_to(Task::Measure);
            shell.serial_byte(byte, term, now_ns);
            cpuload::switch_to(Task::Input);
        }

        cpuload::switch_to(Task::Measure);
        shell.tick(term, now_ns);
        match shell.request {
            Request::None | Request::Close => shell.request = Request::None,
            Request::Gui => {
                ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                restore_sink();
                crate::boot::set_mode(crate::boot::Mode::Gui);
                if let Some(fb) = fb {
                    // SAFETY: kernel privilege; the CLI gives the screen up
                    // for good.
                    unsafe { crate::desktop::run(fb, memory) }
                }
                shell.request = Request::None;
            }
            Request::Classic => {
                ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                restore_sink();
                crate::boot::set_mode(crate::boot::Mode::Classic);
                if let Some(fb) = fb {
                    // SAFETY: as above.
                    unsafe { crate::gui::run(fb, memory) }
                }
                shell.request = Request::None;
            }
        }

        if now_ns < next_frame {
            let wait = (next_frame - now_ns).min(2_000_000);
            cpuload::idle_until(crate::arch::counter_ordered().wrapping_add(system.clock.calibration.ns_to_ticks(wait)));
            continue;
        }
        next_frame = now_ns + FRAME_NS;
        if let Some(fb) = fb {
            cpuload::switch_to(Task::Render);
            term.render(fb, x0, y0, face, &theme, true);
            cpuload::switch_to(Task::Present);
            fb.present_damage();
        }
    }
}
