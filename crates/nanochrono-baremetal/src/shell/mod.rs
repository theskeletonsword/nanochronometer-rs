// SPDX-License-Identifier: Apache-2.0
//! The shell: a Unix-like command line on a [`Term`].
//!
//! One shell serves both places a terminal appears — the full-screen CLI
//! (`mode=cli`, `crate::cli`) and the desktop's terminal windows — so it owns
//! no screen and no keyboard: its owner feeds it keys (or bytes from a serial
//! line) and calls [`Shell::tick`] every frame, and it writes to the terminal
//! it is handed. Long-running commands — `top`, the stopwatch, a live clock —
//! are *jobs* the tick drives, not loops that hold the machine, so a desktop
//! keeps drawing its other windows while one runs.
//!
//! The line editor: left/right, Home/End (Ctrl-A, Ctrl-E), Backspace and
//! Delete, Ctrl-U and Ctrl-W, history on Up/Down, Tab completing a command
//! name or a path, Ctrl-L clearing the screen, Ctrl-C abandoning the line or
//! stopping the job. A line wider than the terminal scrolls sideways.
//!
//! The commands are in [`builtins`]; `nanochrono`, the hosted CLI's command
//! set, is in [`nanochrono`]; `top` in [`top`]; `ncpkg`, the package
//! manager's read-only half, in [`ncpkg`].

pub mod builtins;
pub mod nanochrono;
pub mod ncpkg;
pub mod top;

use crate::kbd::{KeyInput, Keyboard};
use crate::term::Term;
use crate::text::Text;
use core::fmt::Write;

/// Where a shell's output goes: its terminal, and in the CLI also the UART,
/// so the same session works from a serial terminal.
pub struct Out<'a> {
    pub term: &'a mut Term,
    pub mirror: bool,
    /// Colour and text attributes allowed through. Off — the CLI's default —
    /// every SGR sequence (`ESC [ ... m`) is dropped on the way out: a pure
    /// text console, not a GUI dressed as one.
    pub color: bool,
}

impl<'a> Out<'a> {
    pub fn new(term: &'a mut Term, mirror: bool, color: bool) -> Out<'a> {
        Out { term, mirror, color }
    }
}

/// `s` without its SGR sequences, into `buf` (a chunk at a time).
fn strip_sgr<'b>(s: &str, buf: &'b mut crate::text::Text<512>) -> &'b str {
    buf.clear();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            // Look ahead to the final byte: drop the sequence only if it is
            // SGR; cursor movement and erasing stay.
            let mut seq = crate::text::Text::<32>::new();
            seq.char(c);
            let mut final_byte = None;
            for d in chars.by_ref() {
                seq.char(d);
                if d.is_ascii_alphabetic() || d == '@' || d == '~' {
                    final_byte = Some(d);
                    break;
                }
            }
            if final_byte != Some('m') {
                buf.str(seq.as_str());
            }
            continue;
        }
        buf.char(c);
    }
    buf.as_str()
}

impl Write for Out<'_> {
    /// Like a tty with ONLCR: a `\n` goes out as `\r\n`, so text written
    /// with bare newlines — a file, a log — lines up on the left margin.
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let mut plain = crate::text::Text::<512>::new();
        let s = if self.color || !s.contains('\x1b') {
            s
        } else if s.len() <= 400 {
            strip_sgr(s, &mut plain)
        } else {
            // Long text with escapes: chunk it on line boundaries.
            for line in s.split_inclusive('\n') {
                self.write_str(line)?;
            }
            return Ok(());
        };
        for (i, part) in s.split('\n').enumerate() {
            if i > 0 {
                let _ = self.term.write_str("\r\n");
                if self.mirror {
                    crate::serial::console_write("\r\n");
                }
            }
            if !part.is_empty() {
                let _ = self.term.write_str(part);
                if self.mirror {
                    // The serial writer adds the carriage return itself.
                    crate::serial::console_write(part);
                }
            }
        }
        Ok(())
    }
}

/// What a command asks of the shell's owner, beyond output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    None,
    /// Switch the session to the NanoChronometer GUI.
    Gui,
    /// Switch the session to the classic instrument.
    Classic,
    /// Close the terminal (a desktop window); ignored full screen.
    Close,
}

/// A command that runs over many frames.
pub enum Job {
    None,
    Top(top::Top),
    Stopwatch(nanochrono::LiveStopwatch),
    Clock(nanochrono::LiveClock),
    /// `sleep`: done at this instant (ns since boot).
    Sleep(u64),
    /// `reboot`/`poweroff` waiting for the code shown.
    Power(nanochrono_core::power_confirm::Action),
}

const HISTORY: usize = 32;
const LINE: usize = 512;

/// A shell's whole state.
pub struct Shell {
    line: Text<LINE>,
    /// The cursor's position in the line, in characters.
    cursor: usize,
    history: [Text<LINE>; HISTORY],
    history_len: usize,
    /// While browsing history: how far back.
    browse: Option<usize>,
    /// The line being typed before browsing started.
    stash: Text<LINE>,
    pub cwd: Text<128>,
    pub job: Job,
    pub keyboard: Keyboard,
    pub request: Request,
    /// The power-off/restart confirmation the classic interface also uses:
    /// one key is not enough, because one key is what a BadUSB types.
    pub power: nanochrono_core::power_confirm::Confirm,
    /// Escape-sequence state for bytes from a serial line.
    vt: [u8; 4],
    vt_len: usize,
    /// A UTF-8 character arriving byte by byte on a serial line.
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    pub mirror: bool,
    /// Colours in the output (see [`Out::color`]).
    pub color: bool,
    /// The CLI session's shell: plain text for good, `color on` refused.
    /// Colours belong to the GUI's Terminal.
    pub plain_only: bool,
    /// The last command's exit status, for `$?` and the prompt.
    pub status: i32,
}

impl Shell {
    pub fn new(mirror: bool, color: bool) -> Shell {
        let mut cwd = Text::new();
        cwd.str("/");
        Shell {
            line: Text::new(),
            cursor: 0,
            history: [Text::new(); HISTORY],
            history_len: 0,
            browse: None,
            stash: Text::new(),
            cwd,
            job: Job::None,
            keyboard: Keyboard::new(crate::kbd::default_layout()),
            request: Request::None,
            power: nanochrono_core::power_confirm::Confirm::new(),
            vt: [0; 4],
            vt_len: 0,
            utf8: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            mirror,
            color,
            plain_only: false,
            status: 0,
        }
    }

    /// The CLI session's shell: mirrored to the serial line, and plain text
    /// whatever is asked — no colour, no coloured prompt.
    pub fn cli() -> Shell {
        Shell { plain_only: true, ..Shell::new(true, false) }
    }

    fn out<'a>(&self, term: &'a mut Term) -> Out<'a> {
        Out::new(term, self.mirror, self.color)
    }

    /// Whether nothing is running and nothing is typed: Ctrl-D then closes
    /// a terminal window, as it ends a shell.
    pub fn job_is_idle_and_line_empty(&self) -> bool {
        matches!(self.job, Job::None) && self.line.is_empty()
    }

    /// Greets and shows the first prompt.
    pub fn start(&mut self, term: &mut Term) {
        let mut out = self.out(term);
        let _ = write!(out, "\x1b[1;32mNanoChronometer {}\x1b[0m ", crate::VERSION);
        let _ = writeln!(out, "\x1b[2m({}, freestanding — no operating system underneath)\x1b[0m", crate::system::MACHINE);
        if let Some(motd) = crate::vfs::lookup("/etc/motd") {
            crate::vfs::read(&motd, &mut out);
        }
        self.prompt(term);
    }

    fn prompt_text(&self) -> Text<160> {
        let mut p = Text::new();
        let ok = if self.status == 0 { "32" } else { "31" };
        let _ = write!(p, "\x1b[1;{ok}mroot@nanochronometer\x1b[0m:\x1b[1;34m{}\x1b[0m# ", self.cwd.as_str());
        p
    }

    /// The prompt's width in columns: its text without the escapes.
    fn prompt_width(&self) -> usize {
        let p = self.prompt_text();
        let mut width = 0;
        let mut in_escape = false;
        for c in p.as_str().chars() {
            match (in_escape, c) {
                (false, '\x1b') => in_escape = true,
                (true, c) if c.is_ascii_alphabetic() => in_escape = false,
                (true, _) => {}
                (false, _) => width += 1,
            }
        }
        width
    }

    /// Draws the prompt and the line on the current row, scrolled so the
    /// cursor shows, and puts the terminal's cursor where the line's is.
    fn redraw(&self, term: &mut Term) {
        let cols = term.cols;
        let prompt_w = self.prompt_width();
        let avail = cols.saturating_sub(prompt_w + 1).max(8);
        let chars = self.line.as_str().chars().count();
        let first = if self.cursor >= avail { self.cursor + 1 - avail } else { 0 };
        let p = self.prompt_text();
        let mut out = self.out(term);
        let _ = out.write_str("\r");
        let _ = out.write_str(p.as_str());
        for c in self.line.as_str().chars().skip(first).take(avail) {
            let _ = out.write_char(c);
        }
        let _ = out.write_str("\x1b[K");
        let col = prompt_w + (self.cursor - first) + 1;
        let _ = write!(out, "\x1b[{col}G");
        let _ = chars;
    }

    fn prompt(&mut self, term: &mut Term) {
        self.line.clear();
        self.cursor = 0;
        self.browse = None;
        self.redraw(term);
    }

    /// A key from a keyboard, through the layout.
    pub fn key(&mut self, key: crate::input::Key, term: &mut Term, now_ns: u64) {
        if let Some(input) = self.keyboard.feed(key) {
            self.input(input, term, now_ns);
        }
    }

    /// A byte from a serial line: printable UTF-8 goes in as characters,
    /// control bytes and `ESC [ A`-style sequences as editing keys.
    pub fn serial_byte(&mut self, byte: u8, term: &mut Term, now_ns: u64) {
        if self.vt_len > 0 || byte == 0x1B {
            if self.vt_len < self.vt.len() {
                self.vt[self.vt_len] = byte;
                self.vt_len += 1;
            }
            let seq = &self.vt[..self.vt_len];
            let done = match seq {
                [0x1B] => return,
                [0x1B, b'['] | [0x1B, b'O'] | [0x1B, b'[', b'0'..=b'9'] => return,
                [0x1B, b'[' | b'O', b'A'] => Some(KeyInput::Up),
                [0x1B, b'[' | b'O', b'B'] => Some(KeyInput::Down),
                [0x1B, b'[' | b'O', b'C'] => Some(KeyInput::Right),
                [0x1B, b'[' | b'O', b'D'] => Some(KeyInput::Left),
                [0x1B, b'[' | b'O', b'H'] => Some(KeyInput::Home),
                [0x1B, b'[' | b'O', b'F'] => Some(KeyInput::End),
                [0x1B, b'[', b'3', b'~'] => Some(KeyInput::Delete),
                [0x1B, b'[', b'1' | b'7', b'~'] => Some(KeyInput::Home),
                [0x1B, b'[', b'4' | b'8', b'~'] => Some(KeyInput::End),
                [0x1B, b'[', b'5', b'~'] => Some(KeyInput::PageUp),
                [0x1B, b'[', b'6', b'~'] => Some(KeyInput::PageDown),
                [0x1B, x] if *x != b'[' && *x != b'O' => Some(KeyInput::Escape),
                _ if self.vt_len == self.vt.len() => None,
                _ => return,
            };
            self.vt_len = 0;
            if let Some(k) = done {
                self.input(k, term, now_ns);
            }
            return;
        }
        let input = match byte {
            b'\r' | b'\n' => KeyInput::Enter,
            0x7F | 0x08 => KeyInput::Backspace,
            b'\t' => KeyInput::Tab,
            0x01..=0x1A => KeyInput::Ctrl((b'a' + byte - 1) as char),
            0x20..=0x7E => KeyInput::Char(byte as char),
            _ => {
                // The start or middle of a UTF-8 character: assembled in the
                // line as it is typed (only whole characters are accepted).
                return self.utf8_byte(byte, term, now_ns);
            }
        };
        self.input(input, term, now_ns);
    }

    /// A byte of a multi-byte UTF-8 character from a serial line: the
    /// character goes in once it is whole (a stray continuation byte, or a
    /// sequence broken off, is dropped).
    fn utf8_byte(&mut self, byte: u8, term: &mut Term, now_ns: u64) {
        if byte & 0xC0 != 0x80 {
            self.utf8_need = match byte {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => 0,
            };
            self.utf8[0] = byte;
            self.utf8_len = if self.utf8_need > 0 { 1 } else { 0 };
            return;
        }
        if self.utf8_len == 0 || self.utf8_len >= self.utf8_need {
            return;
        }
        self.utf8[self.utf8_len] = byte;
        self.utf8_len += 1;
        if self.utf8_len == self.utf8_need {
            let whole = core::str::from_utf8(&self.utf8[..self.utf8_need]).ok().and_then(|s| s.chars().next());
            self.utf8_len = 0;
            if let Some(c) = whole {
                self.input(KeyInput::Char(c), term, now_ns);
            }
        }
    }

    /// One editing key or character.
    pub fn input(&mut self, input: KeyInput, term: &mut Term, now_ns: u64) {
        // A running job takes the keys first.
        if !matches!(self.job, Job::None) {
            self.job_key(input, term, now_ns);
            return;
        }
        match input {
            KeyInput::Char(c) => {
                if self.line.has_room_for(c.len_utf8()) {
                    self.insert(c);
                }
            }
            KeyInput::Enter => {
                let line = self.line;
                let mut out = self.out(term);
                let _ = out.write_str("\r\n");
                self.remember(line.as_str());
                self.run_line(line.as_str(), term, now_ns);
                if matches!(self.job, Job::None) {
                    self.prompt(term);
                }
                return;
            }
            KeyInput::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.remove_at(self.cursor);
                }
            }
            KeyInput::Delete | KeyInput::Ctrl('d') => {
                if self.cursor < self.chars() {
                    self.remove_at(self.cursor);
                }
            }
            KeyInput::Left | KeyInput::Ctrl('b') => self.cursor = self.cursor.saturating_sub(1),
            KeyInput::Right | KeyInput::Ctrl('f') => self.cursor = (self.cursor + 1).min(self.chars()),
            KeyInput::Home | KeyInput::Ctrl('a') => self.cursor = 0,
            KeyInput::End | KeyInput::Ctrl('e') => self.cursor = self.chars(),
            KeyInput::Ctrl('u') => {
                while self.cursor > 0 {
                    self.cursor -= 1;
                    self.remove_at(self.cursor);
                }
            }
            KeyInput::Ctrl('k') => {
                while self.cursor < self.chars() {
                    self.remove_at(self.cursor);
                }
            }
            KeyInput::Ctrl('w') => {
                while self.cursor > 0 && self.char_at(self.cursor - 1) == Some(' ') {
                    self.cursor -= 1;
                    self.remove_at(self.cursor);
                }
                while self.cursor > 0 && self.char_at(self.cursor - 1) != Some(' ') {
                    self.cursor -= 1;
                    self.remove_at(self.cursor);
                }
            }
            KeyInput::Ctrl('c') => {
                let mut out = self.out(term);
                let _ = out.write_str("^C\r\n");
                self.status = 130;
                self.prompt(term);
                return;
            }
            KeyInput::Ctrl('l') => {
                term.clear();
                if self.mirror {
                    crate::serial::console_write("\x1b[H\x1b[2J");
                }
            }
            KeyInput::Up | KeyInput::Ctrl('p') => self.history_step(true),
            KeyInput::Down | KeyInput::Ctrl('n') => self.history_step(false),
            KeyInput::Tab => self.complete(term),
            _ => {}
        }
        self.redraw(term);
    }

    fn chars(&self) -> usize {
        self.line.as_str().chars().count()
    }

    fn char_at(&self, i: usize) -> Option<char> {
        self.line.as_str().chars().nth(i)
    }

    fn insert(&mut self, c: char) {
        let mut next = Text::<LINE>::new();
        for (i, ch) in self.line.as_str().chars().enumerate() {
            if i == self.cursor {
                next.char(c);
            }
            next.char(ch);
        }
        if self.cursor >= self.chars() {
            next.char(c);
        }
        self.line = next;
        self.cursor += 1;
    }

    fn remove_at(&mut self, at: usize) {
        let mut next = Text::<LINE>::new();
        for (i, ch) in self.line.as_str().chars().enumerate() {
            if i != at {
                next.char(ch);
            }
        }
        self.line = next;
    }

    fn remember(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        if self.history_len > 0 && self.history[(self.history_len - 1) % HISTORY].as_str() == line {
            return;
        }
        let slot = &mut self.history[self.history_len % HISTORY];
        slot.clear();
        slot.str(line);
        self.history_len += 1;
    }

    fn history_step(&mut self, back: bool) {
        let available = self.history_len.min(HISTORY);
        if available == 0 {
            return;
        }
        let next = match (self.browse, back) {
            (None, true) => {
                self.stash = self.line;
                Some(1)
            }
            (None, false) => None,
            (Some(n), true) => Some((n + 1).min(available)),
            (Some(1), false) => None,
            (Some(n), false) => Some(n - 1),
        };
        self.browse = next;
        self.line = match next {
            Some(n) => self.history[(self.history_len - n) % HISTORY],
            None => self.stash,
        };
        self.cursor = self.chars();
    }

    /// Tab: the first word completes against the commands, the others
    /// against the file tree. One match completes; several are listed.
    fn complete(&mut self, term: &mut Term) {
        let line = self.line;
        let s = line.as_str();
        let upto: Text<LINE> = {
            let mut t = Text::new();
            for c in s.chars().take(self.cursor) {
                t.char(c);
            }
            t
        };
        let word_start = upto.as_str().rfind(' ').map_or(0, |i| i + 1);
        let word = &upto.as_str()[word_start..];
        let first_word = !upto.as_str()[..word_start].contains(|c: char| !c.is_whitespace());
        let mut matches: [Text<128>; 32] = [Text::new(); 32];
        let mut n = 0;
        let mut push = |cand: &str| {
            if n < matches.len() {
                matches[n].clear();
                matches[n].str(cand);
                n += 1;
            }
        };
        if first_word {
            for name in builtins::names() {
                if name.starts_with(word) {
                    push(name);
                }
            }
        } else {
            // Paths: the directory part as typed, then the entries in it.
            let (dir_typed, stem) = match word.rfind('/') {
                Some(i) => (&word[..=i], &word[i + 1..]),
                None => ("", word),
            };
            let dir = crate::vfs::resolve(self.cwd.as_str(), if dir_typed.is_empty() { "." } else { dir_typed });
            crate::vfs::list(dir.as_str(), |name, node| {
                if name.starts_with(stem) {
                    let mut cand = Text::<128>::new();
                    cand.str(dir_typed).str(name);
                    if node.is_dir() {
                        cand.str("/");
                    }
                    push(cand.as_str());
                }
            });
        }
        if n == 0 {
            return;
        }
        // The longest common prefix of the candidates.
        let mut common = matches[0];
        for m in &matches[1..n] {
            let len = common
                .as_str()
                .char_indices()
                .zip(m.as_str().chars())
                .take_while(|((_, a), b)| a == b)
                .last()
                .map_or(0, |((i, a), _)| i + a.len_utf8());
            let mut t = Text::<128>::new();
            t.str(&common.as_str()[..len]);
            common = t;
        }
        let addition = &common.as_str()[word.len().min(common.len())..];
        for c in addition.chars() {
            self.insert(c);
        }
        if n == 1 && !common.as_str().ends_with('/') {
            self.insert(' ');
        } else if n > 1 && addition.is_empty() {
            let mut out = self.out(term);
            let _ = out.write_str("\r\n");
            for m in &matches[..n] {
                let _ = write!(out, "{}  ", m.as_str());
            }
            let _ = out.write_str("\r\n");
        }
    }

    /// Runs one command line: `a; b` runs both, `a && b` the second only if
    /// the first succeeded.
    pub fn run_line(&mut self, line: &str, term: &mut Term, now_ns: u64) {
        let mut rest = line;
        loop {
            let (cmd, next, only_if_ok) = match (rest.find("&&"), rest.find(';')) {
                (Some(a), Some(b)) if a < b => (&rest[..a], Some(&rest[a + 2..]), true),
                (Some(a), None) => (&rest[..a], Some(&rest[a + 2..]), true),
                (_, Some(b)) => (&rest[..b], Some(&rest[b + 1..]), false),
                (None, None) => (rest, None, false),
            };
            self.run_command(cmd.trim(), term, now_ns);
            if !matches!(self.job, Job::None) || self.request != Request::None {
                return;
            }
            match next {
                Some(n) if !only_if_ok || self.status == 0 => rest = n,
                _ => return,
            }
        }
    }

    fn run_command(&mut self, line: &str, term: &mut Term, now_ns: u64) {
        if line.is_empty() {
            return;
        }
        let mut argv: [&str; 32] = [""; 32];
        let mut argc = 0;
        let mut scratch = Text::<LINE>::new();
        // Quotes group words; the unquoted text is copied into `scratch` so
        // each argument is a slice of it.
        let mut spans: [(usize, usize); 32] = [(0, 0); 32];
        let mut in_quote: Option<char> = None;
        let mut start: Option<usize> = None;
        for c in line.chars() {
            match (in_quote, c) {
                (None, '"' | '\'') => {
                    in_quote = Some(c);
                    start.get_or_insert(scratch.len());
                }
                (Some(q), c) if c == q => in_quote = None,
                (None, c) if c.is_whitespace() => {
                    if let Some(s) = start.take() {
                        if argc < spans.len() {
                            spans[argc] = (s, scratch.len());
                            argc += 1;
                        }
                    }
                }
                (_, c) => {
                    start.get_or_insert(scratch.len());
                    scratch.char(c);
                }
            }
        }
        if let Some(s) = start {
            if argc < spans.len() {
                spans[argc] = (s, scratch.len());
                argc += 1;
            }
        }
        for i in 0..argc {
            argv[i] = &scratch.as_str()[spans[i].0..spans[i].1];
        }
        let argv = &argv[..argc];
        if argv.is_empty() {
            return;
        }
        self.status = builtins::dispatch(self, argv, term, now_ns);
    }

    /// Advances a running job; called every frame.
    pub fn tick(&mut self, term: &mut Term, now_ns: u64) {
        let (mirror, color) = (self.mirror, self.color);
        let done = match &mut self.job {
            Job::None => return,
            Job::Top(top) => {
                let mut out = Out::new(term, mirror, color);
                !top.tick(&mut out, now_ns)
            }
            Job::Stopwatch(sw) => {
                let mut out = Out::new(term, mirror, color);
                !sw.tick(&mut out, now_ns)
            }
            Job::Clock(c) => {
                let mut out = Out::new(term, mirror, color);
                !c.tick(&mut out, now_ns)
            }
            Job::Sleep(until) => now_ns >= *until,
            Job::Power(_) => {
                let expired = !self.power.is_pending(now_ns);
                if expired {
                    let mut out = Out::new(term, mirror, color);
                    let _ = out.write_str("\r\nno code entered; cancelled\r\n");
                    self.status = 1;
                }
                expired
            }
        };
        if done {
            self.job = Job::None;
            self.prompt(term);
        }
    }

    fn job_key(&mut self, input: KeyInput, term: &mut Term, now_ns: u64) {
        let (mirror, color) = (self.mirror, self.color);
        let stop = match (&mut self.job, input) {
            (_, KeyInput::Ctrl('c')) => {
                let mut out = Out::new(&mut *term, mirror, color);
                let _ = out.write_str("^C\r\n");
                self.status = 130;
                self.power.cancel();
                true
            }
            (Job::Top(top), k) => {
                let mut out = Out::new(&mut *term, mirror, color);
                top.key(k, &mut out)
            }
            (Job::Stopwatch(sw), k) => {
                let mut out = Out::new(&mut *term, mirror, color);
                sw.key(k, &mut out, now_ns)
            }
            (Job::Clock(_), KeyInput::Char('q') | KeyInput::Escape) => true,
            (Job::Power(action), KeyInput::Char(c)) if c.is_ascii_digit() => {
                let action = *action;
                let mut out = Out::new(&mut *term, mirror, color);
                let _ = write!(out, "{c}");
                match self.power.digit(c as u8 - b'0', now_ns) {
                    nanochrono_core::power_confirm::Outcome::Confirmed(_) => {
                        let _ = out.write_str("\r\n");
                        builtins::carry_out(action, &mut out);
                        true
                    }
                    nanochrono_core::power_confirm::Outcome::Pending => false,
                    _ => {
                        let _ = out.write_str("\r\nwrong code; cancelled\r\n");
                        self.status = 1;
                        true
                    }
                }
            }
            (Job::Power(_), _) => {
                self.power.cancel();
                let mut out = Out::new(&mut *term, mirror, color);
                let _ = out.write_str("\r\ncancelled\r\n");
                self.status = 1;
                true
            }
            _ => false,
        };
        if stop {
            self.job = Job::None;
            self.prompt(term);
        }
    }
}
