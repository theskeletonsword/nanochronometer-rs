// SPDX-License-Identifier: Apache-2.0
//! Snake, as a NanoChronometer app: `SNAKE.NCAPP`, and `SNAKE.NCPKG` — the
//! same app as a package (its manifest is `ncpkg.toml` beside this crate).
//!
//! An original — not a port of anyone's Snake — so it is Apache-2.0 like the
//! rest of the tree. It exists to prove the app pipeline end to end: it is
//! loaded from a filesystem (or out of its package), its sections relocated,
//! a kernel data symbol imported, and it draws and reads the keyboard through
//! the [`NcApi`] table the kernel hands it. GPL programs (DOOM, a GPL
//! decoder) ride the same path but are never built into this repository.

#![no_std]

use core::panic::PanicInfo;

// ===========================================================================
// The plugin ABI — kept in step with crates/nanochrono-baremetal/src/ncplu.rs
// ===========================================================================

#[repr(C)]
pub struct NcApi {
    abi_version: u32,
    screen_w: u32,
    screen_h: u32,
    _reserved: u32,
    ticks_per_sec: u64,
    fill_rect: extern "C" fn(x: i32, y: i32, w: i32, h: i32, rgb: u32),
    clear: extern "C" fn(rgb: u32),
    present: extern "C" fn(),
    poll_event: extern "C" fn() -> u32,
    ticks: extern "C" fn() -> u64,
    log: extern "C" fn(msg: *const u8, len: usize),
    // NC_TIMER / NC_PMU (module 3), appended to match the kernel's table.
    timer_now: extern "C" fn() -> u64,
    timer_now_end: extern "C" fn() -> u64,
    timer_hz: extern "C" fn() -> u64,
    timer_source: extern "C" fn() -> u32,
    timer_ticks_to_ns: extern "C" fn(ticks: u64) -> u64,
    pmu_caps: extern "C" fn() -> u32,
    pmu_open: extern "C" fn(event: u32) -> i32,
    pmu_read: extern "C" fn(handle: i32) -> u64,
    pmu_close: extern "C" fn(handle: i32),
    // NC_RNG, the kernel's entropy pool.
    rng_fill: extern "C" fn(buf: *mut u8, len: usize, flags: u32) -> i64,
    rng_status: extern "C" fn(out: *mut u8) -> i32,
    rng_stir: extern "C" fn(tag: u64, value: u64),
}

/// `NC_RNG_FAST`: the pool's output stage, not a fresh seed per block.
const NC_RNG_FAST: u32 = 0;
/// First event tag a plugin may use with `rng_stir`.
const NC_RNG_EVENT_USER: u64 = 0x100;

// A kernel data symbol, imported by name. Reading it is what makes the
// loader exercise its IMPORT64 relocation path; the value is folded into
// the food generator's seed so the read cannot be optimised away.
extern "C" {
    static nc_abi_version: u32;
}

// Set-1 scancodes for the keys Snake reads.
const SC_ESC: u8 = 0x01;
const SC_W: u8 = 0x11;
const SC_A: u8 = 0x1E;
const SC_S: u8 = 0x1F;
const SC_D: u8 = 0x20;
const SC_UP: u8 = 0x48;
const SC_LEFT: u8 = 0x4B;
const SC_RIGHT: u8 = 0x4D;
const SC_DOWN: u8 = 0x50;

// Colours (0xRRGGBB), in the green-on-black spirit of the interface.
const BG: u32 = 0x00_0A_0A;
const GRID: u32 = 0x0A_1A_0A;
const SNAKE: u32 = 0x33_FF_66;
const HEAD: u32 = 0x9B_FF_C0;
const FOOD: u32 = 0xFF_50_50;
const OVER: u32 = 0x40_10_10;

const CELL: i32 = 24;
const MAX_CELLS: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    x: i16,
    y: i16,
}

struct Game {
    cols: i16,
    rows: i16,
    body: [Cell; MAX_CELLS],
    head: usize,
    len: usize,
    dir: (i16, i16),
    food: Cell,
    rng: u64,
    dead: bool,
}

impl Game {
    fn rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn cell(&self, i: usize) -> Cell {
        self.body[(self.head + MAX_CELLS - i) % MAX_CELLS]
    }

    fn occupies(&self, c: Cell) -> bool {
        (0..self.len).any(|i| self.cell(i) == c)
    }

    fn place_food(&mut self) {
        // A bounded number of tries; on a nearly full board the first free
        // scan wins, but Snake never gets that far here.
        for _ in 0..256 {
            let c = Cell {
                x: (self.rand() % self.cols as u64) as i16,
                y: (self.rand() % self.rows as u64) as i16,
            };
            if !self.occupies(c) {
                self.food = c;
                return;
            }
        }
    }

    fn turn(&mut self, dir: (i16, i16)) {
        // No reversing straight back onto the neck.
        if self.len > 1 && dir == (-self.dir.0, -self.dir.1) {
            return;
        }
        self.dir = dir;
    }

    /// One step of the snake. Called through [`STEP_TABLE`] so the loader's
    /// `RELATIVE` relocation of a function pointer in static data is
    /// exercised and, if it were wrong, the game would jump to a bad address
    /// on the first tick.
    fn advance(&mut self) {
        if self.dead {
            return;
        }
        let h = self.cell(0);
        let next = Cell {
            x: h.x + self.dir.0,
            y: h.y + self.dir.1,
        };
        if next.x < 0
            || next.y < 0
            || next.x >= self.cols
            || next.y >= self.rows
            || self.occupies(next)
        {
            self.dead = true;
            return;
        }
        self.head = (self.head + 1) % MAX_CELLS;
        self.body[self.head] = next;
        if next == self.food {
            self.len = (self.len + 1).min(MAX_CELLS - 1);
            self.place_food();
        }
    }
}

type StepFn = fn(&mut Game);
/// A function pointer in static data: a `RELATIVE` relocation for the loader.
static STEP_TABLE: [StepFn; 1] = [Game::advance];

fn draw(api: &NcApi, g: &Game, ox: i32, oy: i32) {
    (api.clear)(if g.dead { OVER } else { BG });
    // A faint grid, so the board reads as a board.
    for i in 0..=g.cols as i32 {
        (api.fill_rect)(ox + i * CELL, oy, 1, g.rows as i32 * CELL, GRID);
    }
    for j in 0..=g.rows as i32 {
        (api.fill_rect)(ox, oy + j * CELL, g.cols as i32 * CELL, 1, GRID);
    }
    let cellf = |c: Cell, col: u32| {
        (api.fill_rect)(
            ox + c.x as i32 * CELL + 1,
            oy + c.y as i32 * CELL + 1,
            CELL - 2,
            CELL - 2,
            col,
        );
    };
    cellf(g.food, FOOD);
    for i in 0..g.len {
        cellf(g.cell(i), if i == 0 { HEAD } else { SNAKE });
    }
    (api.present)();
}

/// The entry point the kernel calls. Runs its own loop until the player
/// presses Esc, then returns control (and the screen) to the interface.
///
/// # Safety
/// `api` must point at a valid [`NcApi`] for the call's duration; the kernel
/// guarantees that.
#[no_mangle]
pub unsafe extern "C" fn ncplu_main(api: *const NcApi) -> i32 {
    let api = &*api;
    let msg = b"snake: starting\n";
    (api.log)(msg.as_ptr(), msg.len());

    let cols = ((api.screen_w as i32 / CELL) - 2).clamp(8, 60) as i16;
    let rows = ((api.screen_h as i32 / CELL) - 2).clamp(8, 40) as i16;
    let ox = (api.screen_w as i32 - cols as i32 * CELL) / 2;
    let oy = (api.screen_h as i32 - rows as i32 * CELL) / 2;

    // The food generator's seed comes from NC_RNG. Only if the pool refuses
    // (out of service) does the counter stand in: food placement is a game,
    // not a key, so a weak seed is a poorer game rather than a hole.
    let mut bytes = [0u8; 8];
    let got = (api.rng_fill)(bytes.as_mut_ptr(), bytes.len(), NC_RNG_FAST);
    let seed = if got == bytes.len() as i64 {
        let msg = b"snake: seeded from NC_RNG\n";
        (api.log)(msg.as_ptr(), msg.len());
        u64::from_le_bytes(bytes)
    } else {
        let msg = b"snake: NC_RNG refused, seeding from the counter\n";
        (api.log)(msg.as_ptr(), msg.len());
        (api.ticks)() ^ 0x9E37_79B9_7F4A_7C15
    } ^ ((nc_abi_version as u64) << 32);
    let mut g = Game {
        cols,
        rows,
        body: [Cell { x: 0, y: 0 }; MAX_CELLS],
        head: 0,
        len: 3,
        dir: (1, 0),
        food: Cell { x: 0, y: 0 },
        rng: seed | 1,
        dead: false,
    };
    let start = Cell {
        x: cols / 2,
        y: rows / 2,
    };
    for i in 0..3 {
        g.body[(MAX_CELLS - i) % MAX_CELLS] = Cell {
            x: start.x - i as i16,
            y: start.y,
        };
    }
    g.head = 0;
    // Lay the three-cell tail out behind the head at indices 0,-1,-2.
    g.body[0] = start;
    g.body[MAX_CELLS - 1] = Cell { x: start.x - 1, y: start.y };
    g.body[MAX_CELLS - 2] = Cell { x: start.x - 2, y: start.y };
    g.place_food();

    let step_ns: u64 = 110_000_000;
    let per_ns = api.ticks_per_sec as u128;
    let step_ticks = (step_ns as u128 * per_ns / 1_000_000_000) as u64;
    let mut next_step = (api.ticks)().wrapping_add(step_ticks);

    // NC_TIMER + NC_PMU: time the first frame without hand-written asm. The
    // barriers and the ISA split are the kernel's job; the plugin just calls.
    let t0 = (api.timer_now)();
    let c0 = {
        let h = (api.pmu_open)(0 /* NC_PMU_CYCLES */);
        if h >= 0 { (api.pmu_read)(h) } else { 0 }
    };
    draw(api, &g, ox, oy);
    let t1 = (api.timer_now_end)();
    let c1 = {
        let h = (api.pmu_open)(0);
        if h >= 0 { (api.pmu_read)(h) } else { 0 }
    };
    let mut line = [0u8; 96];
    let n = fmt_frame(&mut line, (api.timer_ticks_to_ns)(t1.wrapping_sub(t0)), c1.wrapping_sub(c0));
    (api.log)(line.as_ptr(), n);

    loop {
        // Drain input.
        loop {
            let ev = (api.poll_event)();
            if ev == 0 {
                break;
            }
            // Each key's arrival, under the plugin's own tag, into NC_RNG.
            (api.rng_stir)(NC_RNG_EVENT_USER, ev as u64);
            let pressed = ev & 0x100 != 0;
            let scancode = (ev & 0xFF) as u8;
            if !pressed {
                continue;
            }
            match scancode {
                SC_ESC => {
                    let bye = b"snake: quit\n";
                    (api.log)(bye.as_ptr(), bye.len());
                    return 0;
                }
                SC_UP | SC_W => g.turn((0, -1)),
                SC_DOWN | SC_S => g.turn((0, 1)),
                SC_LEFT | SC_A => g.turn((-1, 0)),
                SC_RIGHT | SC_D => g.turn((1, 0)),
                _ => {}
            }
        }

        let now = (api.ticks)();
        if now.wrapping_sub(next_step) as i64 >= 0 {
            next_step = now.wrapping_add(step_ticks);
            STEP_TABLE[0](&mut g);
            draw(api, &g, ox, oy);
        }
        core::hint::spin_loop();
    }
}

/// Formats "snake: first frame N ns, M cycles\n" without core::fmt, which a
/// no_std plugin would rather not pull in.
fn put(out: &mut [u8], n: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        if *n < out.len() {
            out[*n] = b;
            *n += 1;
        }
    }
}

fn put_num(out: &mut [u8], n: &mut usize, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    put(out, n, &buf[i..]);
}

fn fmt_frame(out: &mut [u8], ns: u64, cycles: u64) -> usize {
    let mut n = 0;
    put(out, &mut n, b"snake: first frame ");
    put_num(out, &mut n, ns);
    put(out, &mut n, b" ns, ");
    put_num(out, &mut n, cycles);
    put(out, &mut n, b" cycles\n");
    n
}

/// No unwinder on bare metal; a panic in a plugin stops the plugin.
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
