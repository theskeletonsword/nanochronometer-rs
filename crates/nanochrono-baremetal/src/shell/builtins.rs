// SPDX-License-Identifier: Apache-2.0
//! The shell's commands.
//!
//! Unix names where Unix has one (`ls`, `cat`, `uname`, `free`, `top`,
//! `dmesg`, `lspci`...), NanoChronometer's own for the rest, and
//! `nanochrono` — the hosted CLI's command set — in its own module. Every
//! command returns an exit status, 0 for success, as a Unix one would.

use super::{Job, Out, Request, Shell};
use crate::term::Term;
use crate::text::Text;
use core::fmt::Write;

type Run = fn(&mut Shell, &mut Out<'_>, &[&str], u64) -> i32;

struct Command {
    name: &'static str,
    usage: &'static str,
    summary: &'static str,
    run: Run,
}

/// Kept in step with `nanochrono_core::ncpkg::RESERVED_COMMANDS`: a `cli`
/// package may not install a command under one of these names.
static COMMANDS: &[Command] = &[
    Command { name: "help", usage: "help [command]", summary: "list the commands, or explain one", run: help },
    Command { name: "nanochrono", usage: "nanochrono <command> [options]", summary: "the hosted CLI's commands (nanochrono --help)", run: super::nanochrono::run },
    Command { name: "stopwatch", usage: "stopwatch", summary: "the nanosecond stopwatch (space: lap, s: stop/start, q: quit)", run: stopwatch },
    Command { name: "top", usage: "top", summary: "what the machine is doing, live (q to quit)", run: top },
    Command { name: "ps", usage: "ps", summary: "the kernel's tasks and the time each took", run: ps },
    Command { name: "free", usage: "free [-h]", summary: "memory: installed, the kernel image and its pools", run: free },
    Command { name: "uptime", usage: "uptime", summary: "time since the session started", run: uptime },
    Command { name: "date", usage: "date", summary: "the real-time clock, to the nanosecond", run: date },
    Command { name: "uname", usage: "uname [-a|-s|-n|-r|-m]", summary: "the system's name and version", run: uname },
    Command { name: "hostname", usage: "hostname", summary: "the machine's name", run: hostname },
    Command { name: "whoami", usage: "whoami", summary: "the current user", run: whoami },
    Command { name: "echo", usage: "echo [-n] [text...]", summary: "print its arguments", run: echo },
    Command { name: "clear", usage: "clear", summary: "clear the screen", run: clear },
    Command { name: "ls", usage: "ls [-l] [path]", summary: "list a directory", run: ls },
    Command { name: "cd", usage: "cd [path]", summary: "change the current directory", run: cd },
    Command { name: "pwd", usage: "pwd", summary: "print the current directory", run: pwd },
    Command { name: "cat", usage: "cat <file>...", summary: "print files", run: cat },
    Command { name: "hexdump", usage: "hexdump [-n bytes] <file>", summary: "a file's bytes in hex", run: hexdump },
    Command { name: "dmesg", usage: "dmesg", summary: "the kernel log since boot", run: dmesg },
    Command { name: "lscpu", usage: "lscpu", summary: "the processor (same as cat /proc/cpuinfo)", run: lscpu },
    Command { name: "cpuctl", usage: "cpuctl", summary: "the control-register dispatcher's decisions", run: cpuctl },
    Command { name: "lspci", usage: "lspci", summary: "the PCI devices", run: lspci },
    Command { name: "hypervisor", usage: "hypervisor [--reprobe]", summary: "the hypervisor this runs under, if any", run: hypervisor },
    Command { name: "selftest", usage: "selftest", summary: "run the boot self-test again", run: selftest },
    Command { name: "bench", usage: "bench [isa|crypto|raw] [row]", summary: "the benchmarks (no row: list them)", run: bench },
    Command { name: "loadkeys", usage: "loadkeys <us|es>", summary: "the keyboard layout", run: loadkeys },
    Command { name: "color", usage: "color [on|off]", summary: "colours in the output (off: plain text, the default)", run: color },
    Command { name: "apps", usage: "apps", summary: "packages (.ncpkg), apps, libraries, plugins and drivers on this system", run: apps },
    Command { name: "ncpkg", usage: "ncpkg <info|verify|list|files|install|remove> ...", summary: "the package manager (read-only until NCFS is mounted)", run: super::ncpkg::run },
    Command { name: "sudo", usage: "sudo <command> [args]", summary: "run a command as the administrator (this session already is)", run: sudo },
    Command { name: "history", usage: "history", summary: "the commands typed so far", run: history },
    Command { name: "sleep", usage: "sleep <seconds>", summary: "wait", run: sleep },
    Command { name: "desktop", usage: "desktop", summary: "switch to the Desktop Experience", run: desktop },
    Command { name: "classic", usage: "classic", summary: "switch to the classic instrument", run: classic },
    Command { name: "reboot", usage: "reboot", summary: "restart the machine (asks for a code)", run: reboot },
    Command { name: "poweroff", usage: "poweroff", summary: "power the machine off (asks for a code)", run: poweroff },
    Command { name: "true", usage: "true", summary: "succeed", run: |_, _, _, _| 0 },
    Command { name: "false", usage: "false", summary: "fail", run: |_, _, _, _| 1 },
    Command { name: "exit", usage: "exit", summary: "close this terminal (in a desktop window)", run: exit },
];

/// Every command's name, for completion.
pub fn names() -> impl Iterator<Item = &'static str> {
    COMMANDS.iter().map(|c| c.name).chain(["shutdown", "cpuinfo", "halt"])
}

/// Runs `argv` and returns its exit status.
pub fn dispatch(shell: &mut Shell, argv: &[&str], term: &mut Term, now_ns: u64) -> i32 {
    let name = match argv[0] {
        "shutdown" | "halt" => "poweroff",
        "cpuinfo" => "lscpu",
        other => other,
    };
    let mut out = Out::new(term, shell.mirror, shell.color);
    match COMMANDS.iter().find(|c| c.name == name) {
        Some(c) => {
            // What the kernel prints while the command runs (the self-test,
            // a driver) goes to this terminal too.
            let _capture = capture(out.term, shell.mirror);
            (c.run)(shell, &mut out, argv, now_ns)
        }
        None => {
            let _ = writeln!(out, "{}: command not found (try `help`)\r", argv[0]);
            127
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel messages into the terminal of the command that caused them
// ---------------------------------------------------------------------------

static mut CAPTURE: Option<(*mut Term, bool)> = None;

struct Capture;

impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: one core; set by `capture` for the duration of a command.
        unsafe { *core::ptr::addr_of_mut!(CAPTURE) = None };
        crate::cli::restore_sink();
    }
}

fn sink(s: &str) {
    // SAFETY: the pointer is the terminal of the command running now, which
    // outlives the command; one core, and the sink never re-enters.
    if let Some((term, _)) = unsafe { *core::ptr::addr_of!(CAPTURE) } {
        let term = unsafe { &mut *term };
        for c in s.chars() {
            if c == '\n' {
                term.feed('\r');
            }
            term.feed(c);
        }
    }
}

fn capture(term: &mut Term, mirror: bool) -> Capture {
    // SAFETY: as `sink`.
    unsafe { *core::ptr::addr_of_mut!(CAPTURE) = Some((term as *mut Term, mirror)) };
    crate::serial::set_console_sink(Some(sink));
    Capture
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

fn help(_: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    if let Some(name) = argv.get(1) {
        return match COMMANDS.iter().find(|c| c.name == *name) {
            Some(c) => {
                let _ = writeln!(out, "usage: {}\r\n  {}\r", c.usage, c.summary);
                0
            }
            None => {
                let _ = writeln!(out, "help: no command `{name}`\r");
                1
            }
        };
    }
    let _ = writeln!(out, "\x1b[1mNanoChronometer shell\x1b[0m — commands:\r");
    for c in COMMANDS {
        let _ = writeln!(out, "  \x1b[32m{:<11}\x1b[0m {}\r", c.name, c.summary);
    }
    let _ = writeln!(out, "Lines: `a; b` runs both, `a && b` runs b if a succeeded. Tab completes.\r");
    0
}

fn stopwatch(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], now_ns: u64) -> i32 {
    super::nanochrono::start_stopwatch(shell, out, now_ns)
}

fn top(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], now_ns: u64) -> i32 {
    match super::top::Top::start(out, now_ns) {
        Some(t) => {
            shell.job = Job::Top(t);
            0
        }
        None => {
            let _ = writeln!(out, "top: the machine has not been probed yet\r");
            1
        }
    }
}

fn ps(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = writeln!(out, "  PID TASK         STATE   WHAT\r");
    let _ = writeln!(out, "    1 kernel       running the one loop: no scheduler, no preemption\r");
    let mut i = 2;
    for task in crate::cpuload::Task::ALL {
        let what = match task {
            crate::cpuload::Task::Render => "drawing into the back buffer",
            crate::cpuload::Task::Present => "copying to the framebuffer",
            crate::cpuload::Task::Input => "polling keyboard, pointer, USB, UART",
            crate::cpuload::Task::Measure => "counters, PMU, probes, commands",
            crate::cpuload::Task::Idle => "waiting for the next frame",
        };
        let _ = writeln!(out, "  {i:>3} {:<12} phase   {what}\r", task.name());
        i += 1;
    }
    for (name, state) in crate::desktop::app_list() {
        let _ = writeln!(out, "  {i:>3} {:<12} {state:<7} desktop app\r", name);
        i += 1;
    }
    0
}

fn free(_: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let human = argv.contains(&"-h");
    let mut text = Text::<1024>::new();
    crate::system::meminfo(&mut text, crate::system::get());
    let _ = human;
    for line in text.as_str().lines() {
        let _ = writeln!(out, "{line}\r");
    }
    0
}

fn uptime(_: &mut Shell, out: &mut Out<'_>, _: &[&str], now_ns: u64) -> i32 {
    let s = now_ns / 1_000_000_000;
    let _ = writeln!(
        out,
        "up {}:{:02}:{:02}.{:09}, 1 core in use, load: one loop\r",
        s / 3600,
        s / 60 % 60,
        s % 60,
        now_ns % 1_000_000_000
    );
    0
}

fn date(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let Some(system) = crate::system::get() else { return 1 };
    match (system.clock.date, system.clock.wall_ns()) {
        (Some(d), Some(ns)) => {
            let _ = writeln!(
                out,
                "{:04}-{:02}-{:02} {} (RTC + counter)\r",
                d.year,
                d.month,
                d.day,
                crate::text::duration(ns, true).as_str()
            );
            0
        }
        _ => {
            let _ = writeln!(out, "date: no real-time clock this kernel can read on this machine\r");
            1
        }
    }
}

fn uname(_: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let all = argv.contains(&"-a");
    let pick = |flag: &str| all || argv.contains(&flag);
    let mut parts: [&str; 5] = [""; 5];
    let mut n = 0;
    if argv.len() == 1 || pick("-s") {
        parts[n] = "NanoChronometer";
        n += 1;
    }
    if pick("-n") {
        parts[n] = "nanochronometer";
        n += 1;
    }
    if pick("-r") {
        parts[n] = crate::VERSION;
        n += 1;
    }
    if pick("-m") {
        parts[n] = crate::system::MACHINE;
        n += 1;
    }
    if all {
        parts[n] = "freestanding";
        n += 1;
    }
    for (i, p) in parts[..n].iter().enumerate() {
        let _ = write!(out, "{}{}", if i > 0 { " " } else { "" }, p);
    }
    let _ = writeln!(out, "\r");
    0
}

fn hostname(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = writeln!(out, "nanochronometer\r");
    0
}

fn whoami(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = writeln!(out, "root\r");
    0
}

fn echo(_: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let (newline, words) = match argv.get(1) {
        Some(&"-n") => (false, &argv[2..]),
        _ => (true, &argv[1..]),
    };
    for (i, w) in words.iter().enumerate() {
        let _ = write!(out, "{}{}", if i > 0 { " " } else { "" }, w);
    }
    if newline {
        let _ = out.write_str("\r\n");
    }
    0
}

fn clear(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = out.write_str("\x1b[H\x1b[2J");
    0
}

fn ls(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let long = argv.iter().any(|a| *a == "-l" || *a == "-la" || *a == "-al");
    let target = argv[1..].iter().find(|a| !a.starts_with('-')).copied().unwrap_or(".");
    let path = crate::vfs::resolve(shell.cwd.as_str(), target);
    let Some(node) = crate::vfs::lookup(path.as_str()) else {
        let _ = writeln!(out, "ls: {target}: no such file or directory\r");
        return 1;
    };
    if !node.is_dir() {
        let _ = writeln!(out, "{}\r", path.as_str());
        return 0;
    }
    let mut count = 0;
    crate::vfs::list(path.as_str(), |name, node| {
        count += 1;
        let colour = if node.is_dir() {
            "1;34"
        } else if [".ncpkg", ".ncapp", ".ncdyn", ".ncplu", ".ncar", ".ncdri"].iter().any(|ext| ends_with_ignore_case(name, ext)) {
            "1;32"
        } else {
            "0"
        };
        if long {
            let kind = if node.is_dir() { 'd' } else { '-' };
            match node.size() {
                Some(size) => {
                    let _ = writeln!(out, "{kind}r--r--r-- root {size:>10} \x1b[{colour}m{name}\x1b[0m\r");
                }
                None => {
                    let _ = writeln!(out, "{kind}r--r--r-- root {:>10} \x1b[{colour}m{name}\x1b[0m\r", "-");
                }
            }
        } else {
            let _ = write!(out, "\x1b[{colour}m{name}\x1b[0m  ");
        }
    });
    if !long && count > 0 {
        let _ = out.write_str("\r\n");
    }
    0
}

fn ends_with_ignore_case(name: &str, suffix: &str) -> bool {
    let (n, s) = (name.as_bytes(), suffix.as_bytes());
    n.len() >= s.len() && n[n.len() - s.len()..].eq_ignore_ascii_case(s)
}

fn cd(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let target = argv.get(1).copied().unwrap_or("/");
    let path = crate::vfs::resolve(shell.cwd.as_str(), target);
    match crate::vfs::lookup(path.as_str()) {
        Some(n) if n.is_dir() => {
            shell.cwd = path;
            0
        }
        Some(_) => {
            let _ = writeln!(out, "cd: {target}: not a directory\r");
            1
        }
        None => {
            let _ = writeln!(out, "cd: {target}: no such file or directory\r");
            1
        }
    }
}

fn pwd(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = writeln!(out, "{}\r", shell.cwd.as_str());
    0
}

/// Text written to a terminal: a lone `\n` becomes `\r\n`.
struct Lines<'a, 'b>(&'a mut Out<'b>);

impl Write for Lines<'_, '_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for (i, part) in s.split('\n').enumerate() {
            if i > 0 {
                self.0.write_str("\r\n")?;
            }
            self.0.write_str(part)?;
        }
        Ok(())
    }
}

fn cat(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    if argv.len() < 2 {
        let _ = writeln!(out, "usage: cat <file>...\r");
        return 2;
    }
    let mut status = 0;
    for arg in &argv[1..] {
        let path = crate::vfs::resolve(shell.cwd.as_str(), arg);
        match crate::vfs::lookup(path.as_str()) {
            Some(n) if n.is_dir() => {
                let _ = writeln!(out, "cat: {arg}: is a directory\r");
                status = 1;
            }
            Some(n) => crate::vfs::read(&n, &mut Lines(out)),
            None => {
                let _ = writeln!(out, "cat: {arg}: no such file or directory\r");
                status = 1;
            }
        }
    }
    status
}

fn hexdump(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let mut limit = 256usize;
    let mut file = None;
    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "-n" {
            limit = argv.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(limit);
            i += 2;
            continue;
        }
        file = Some(argv[i]);
        i += 1;
    }
    let Some(arg) = file else {
        let _ = writeln!(out, "usage: hexdump [-n bytes] <file>\r");
        return 2;
    };
    let path = crate::vfs::resolve(shell.cwd.as_str(), arg);
    let Some(crate::vfs::Node { content: crate::vfs::Content::Bytes(bytes), .. }) = crate::vfs::lookup(path.as_str()) else {
        let _ = writeln!(out, "hexdump: {arg}: not a regular file\r");
        return 1;
    };
    for (row, chunk) in bytes[..bytes.len().min(limit)].chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", row * 16);
        for (j, b) in chunk.iter().enumerate() {
            let _ = write!(out, "{b:02x}{}", if j == 7 { "  " } else { " " });
        }
        for _ in chunk.len()..16 {
            let _ = out.write_str("   ");
        }
        let _ = out.write_str(" |");
        for &b in chunk {
            let _ = out.write_char(if (0x20..0x7F).contains(&b) { b as char } else { '.' });
        }
        let _ = out.write_str("|\r\n");
    }
    0
}

fn dmesg(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let (a, b) = crate::serial::klog::contents();
    crate::vfs::write_bytes(&mut Lines(out), a);
    crate::vfs::write_bytes(&mut Lines(out), b);
    0
}

fn lscpu(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    crate::system::proc_file(crate::vfs::Proc::Cpuinfo, &mut Lines(out));
    0
}

fn cpuctl(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    crate::system::proc_file(crate::vfs::Proc::Cpuctl, &mut Lines(out));
    0
}

fn lspci(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    #[cfg(x86_any)]
    {
        let mut n = 0;
        // SAFETY: configuration-space reads at CPL 0 (the shell runs in the
        // kernel); `scan` bounds the walk.
        unsafe {
            crate::pci::scan(|d| {
                let _ = writeln!(
                    out,
                    "{:02x}:{:02x}.{} {:<28} [{:04x}:{:04x}] class {:02x}{:02x}{:02x}\r",
                    d.bus,
                    d.slot,
                    d.function,
                    pci_class_name(d.class, d.subclass),
                    d.vendor,
                    d.device,
                    d.class,
                    d.subclass,
                    d.prog_if
                );
                n += 1;
                true
            })
        };
        if n == 0 {
            let _ = writeln!(out, "no PCI devices answered\r");
        }
        0
    }
    #[cfg(not(x86_any))]
    {
        let _ = writeln!(out, "lspci: this kernel reaches PCI through x86 I/O ports only\r");
        1
    }
}

#[cfg(x86_any)]
fn pci_class_name(class: u8, sub: u8) -> &'static str {
    match (class, sub) {
        (0x01, 0x01) => "IDE controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, 0x08) => "NVMe controller",
        (0x01, _) => "storage controller",
        (0x02, 0x00) => "Ethernet controller",
        (0x02, 0x80) => "network controller",
        (0x02, _) => "network controller",
        (0x03, 0x00) => "VGA-compatible display",
        (0x03, _) => "display controller",
        (0x04, 0x03) => "audio device (HD Audio)",
        (0x04, _) => "multimedia controller",
        (0x05, _) => "memory controller",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI-to-PCI bridge",
        (0x06, _) => "bridge",
        (0x07, 0x80) => "communication controller",
        (0x07, _) => "serial controller",
        (0x08, _) => "system peripheral",
        (0x0C, 0x03) => "USB controller",
        (0x0C, 0x05) => "SMBus controller",
        (0x0C, _) => "serial bus controller",
        (0x0D, _) => "wireless controller",
        (0x10, _) => "encryption controller",
        (0x11, _) => "signal processing controller",
        (0x12, _) => "processing accelerator",
        _ => "device",
    }
}

fn hypervisor(_: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    let Some(system) = crate::system::get() else { return 1 };
    if argv.contains(&"--reprobe") {
        // SAFETY: kernel privilege; the shell runs in the kernel.
        match unsafe { crate::hypervisor::reprobe(system.hz()) } {
            Ok(_) => {
                let _ = writeln!(out, "re-probed\r");
            }
            Err(left) => {
                let _ = writeln!(out, "refused: {left} s of cooldown left\r");
                return 1;
            }
        }
    }
    // SAFETY: cached since boot; this does not probe.
    let hv = unsafe { crate::hypervisor::detect() };
    let _ = writeln!(out, "virtualized    : {}\r", if hv.is_virtualized() { "yes" } else { "no" });
    let sig = hv.signature_str();
    let _ = writeln!(out, "signature      : {}\r", if sig.is_empty() { "none" } else { sig });
    let _ = writeln!(out, "hypercall      : {}\r", if hv.hypercall_ok { "answered" } else { "none" });
    let _ = writeln!(out, "probes run     : {}\r", hv.probes);
    0
}

fn selftest(_: &mut Shell, _: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    // SAFETY: kernel privilege. Its output is printed, and printing reaches
    // this terminal through the capture `dispatch` set up.
    unsafe { crate::selftest::run() };
    0
}

fn bench(_: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    use crate::bench::Mode;
    let Some(system) = crate::system::get() else { return 1 };
    let mode = match argv.get(1).copied() {
        Some("isa") | None => Mode::Isa,
        Some("crypto") => Mode::Crypto,
        Some("raw") => Mode::CryptoRaw,
        Some(other) => {
            let _ = writeln!(out, "bench: unknown mode `{other}` (isa, crypto, raw)\r");
            return 2;
        }
    };
    let items = mode.items();
    let Some(row) = argv.get(2) else {
        let _ = writeln!(out, "{} — rows (bench {} <row|all>):\r", mode.label(), argv.get(1).copied().unwrap_or("isa"));
        for (i, item) in items.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {i:>2}  {:<28} {}\r",
                item.name().as_str(),
                if item.is_available() { "available" } else { "not available" }
            );
        }
        return 0;
    };
    let mut ran = 0;
    for (i, item) in items.iter().enumerate() {
        let wanted = *row == "all" || row.parse::<usize>().ok() == Some(i) || item.name().as_str() == *row;
        if !wanted || !item.is_available() {
            continue;
        }
        // SAFETY: kernel privilege, which the kernels and the PMU need.
        let report = unsafe { crate::bench::run_one(*item, system.hz(), &system.pmu) };
        for line in report.log.as_str().lines() {
            let _ = writeln!(out, "{line}\r");
        }
        ran += 1;
    }
    if ran == 0 {
        let _ = writeln!(out, "bench: no available row matches `{row}`\r");
        return 1;
    }
    0
}

fn loadkeys(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    match argv.get(1).and_then(|n| crate::kbd::Layout::from_name(n)) {
        Some(layout) => {
            shell.keyboard.layout = layout;
            crate::kbd::set_default_layout(layout);
            let _ = writeln!(out, "keyboard layout: {}\r", layout.name());
            0
        }
        None => {
            let _ = writeln!(out, "usage: loadkeys <us|es> (now: {})\r", shell.keyboard.layout.name());
            2
        }
    }
}

fn apps(_: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let mut n = 0;
    for (suffix, what) in [
        (".ncpkg", "package"),
        (".ncapp", "app"),
        (".ncdyn", "library"),
        (".ncplu", "plugin"),
        (".ncdri", "driver"),
    ] {
        crate::vfs::find_suffix(suffix, |node| {
            let _ = writeln!(out, "  {what:<8} {:<48} {:>9} bytes\r", node.path.as_str(), node.size().unwrap_or(0));
            n += 1;
        });
    }
    if n == 0 {
        let _ = writeln!(out, "no packages, apps or drivers on this system (GRUB `module2`, or the initrd)\r");
    } else {
        let _ = writeln!(out, "`ncpkg info <file.ncpkg>` reads a package; `ncpkg list`, what is installed\r");
    }
    0
}

fn sudo(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], now_ns: u64) -> i32 {
    if argv.len() < 2 {
        let _ = writeln!(out, "usage: sudo <command> [args]\r");
        return 2;
    }
    // One user so far, the administrator (users, hashed passwords and the
    // installer's wizard are the next step): run the command as it stands.
    dispatch(shell, &argv[1..], out.term, now_ns)
}

fn color(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], _: u64) -> i32 {
    match argv.get(1).copied() {
        Some("on") => shell.color = true,
        Some("off") => shell.color = false,
        None => {}
        Some(_) => {
            let _ = writeln!(out, "usage: color [on|off]\r");
            return 2;
        }
    }
    let _ = writeln!(out, "color: {}\r", if shell.color { "on" } else { "off" });
    0
}

fn history(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let n = shell.history_len.min(super::HISTORY);
    for i in 0..n {
        let index = shell.history_len - n + i;
        let _ = writeln!(out, "  {:>4}  {}\r", index + 1, shell.history[index % super::HISTORY].as_str());
    }
    0
}

fn sleep(shell: &mut Shell, out: &mut Out<'_>, argv: &[&str], now_ns: u64) -> i32 {
    let Some(secs) = argv.get(1).and_then(|s| parse_seconds(s)) else {
        let _ = writeln!(out, "usage: sleep <seconds>\r");
        return 2;
    };
    shell.job = Job::Sleep(now_ns.saturating_add(secs));
    0
}

/// `1`, `0.25`, `1.5` seconds as nanoseconds.
fn parse_seconds(s: &str) -> Option<u64> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let mut ns = whole.checked_mul(1_000_000_000)?;
    let mut scale = 100_000_000;
    for c in frac.chars().take(9) {
        ns += c.to_digit(10)? as u64 * scale;
        scale /= 10;
    }
    Some(ns)
}

fn desktop(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = writeln!(out, "starting the Desktop Experience...\r");
    shell.request = Request::Desktop;
    0
}

fn classic(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    let _ = writeln!(out, "starting the classic instrument...\r");
    shell.request = Request::Classic;
    0
}

fn exit(shell: &mut Shell, _: &mut Out<'_>, _: &[&str], _: u64) -> i32 {
    shell.request = Request::Close;
    0
}

fn reboot(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], now_ns: u64) -> i32 {
    request_power(shell, out, nanochrono_core::power_confirm::Action::Restart, now_ns)
}

fn poweroff(shell: &mut Shell, out: &mut Out<'_>, _: &[&str], now_ns: u64) -> i32 {
    request_power(shell, out, nanochrono_core::power_confirm::Action::Shutdown, now_ns)
}

/// Shows a code and waits for it: the same rule the classic interface's
/// power buttons follow — a BadUSB can type `reboot`, it cannot read the
/// screen.
fn request_power(shell: &mut Shell, out: &mut Out<'_>, action: nanochrono_core::power_confirm::Action, now_ns: u64) -> i32 {
    let mut entropy = [0u8; 8];
    let _ = crate::rng::fill(&mut entropy, nanochrono_core::rng::Mode::Fast);
    match shell.power.request(action, now_ns, u64::from_le_bytes(entropy) ^ crate::arch::counter_ordered()) {
        Ok(code) => {
            let _ = write!(out, "to {}, type the code ", action.verb());
            for d in code {
                let _ = write!(out, "\x1b[1;33m{d}\x1b[0m");
            }
            let _ = write!(out, " within 10 s (anything else cancels): ");
            shell.job = Job::Power(action);
            0
        }
        Err(nanochrono_core::power_confirm::Refused::LockedOut { remaining_ns }) => {
            let _ = writeln!(out, "locked out for {} s after wrong codes\r", remaining_ns.div_ceil(1_000_000_000));
            1
        }
    }
}

/// Does what a confirmed code asked for.
pub fn carry_out(action: nanochrono_core::power_confirm::Action, out: &mut Out<'_>) {
    let acpi = crate::system::get().and_then(|s| s.acpi.as_ref());
    match action {
        nanochrono_core::power_confirm::Action::Restart => {
            let _ = writeln!(out, "restarting\r");
            // SAFETY: kernel privilege; the user confirmed.
            unsafe { crate::acpi::reboot(acpi) }
        }
        nanochrono_core::power_confirm::Action::Shutdown => {
            let _ = writeln!(out, "powering off\r");
            // SAFETY: as above.
            unsafe { crate::acpi::shutdown(acpi) };
            let _ = writeln!(out, "poweroff: no method this platform answers\r");
        }
    }
}
