// SPDX-License-Identifier: Apache-2.0
//! `nccall`'s dispatcher: what a call means, the same on every ISA.
//!
//! The kernel's trap entries (per ISA, beside its vectors) save the caller's
//! registers into a frame; its glue reads the number and six arguments out
//! of that frame through [`hal`]'s map for the ISA and hands them here as a
//! [`Call`]. [`dispatch`] answers it for a [`Caller`] — who is calling, what
//! it owns and was granted, and how its console and NC_RNG are reached — and
//! the [`Reply`] goes back through the same map: two results and the error
//! flag, or the caller is ended.
//!
//! `no_std` and pure: everything the kernel does on a caller's behalf goes
//! through the [`Caller`] it passes, so the rules are tested on the host with
//! the code the freestanding kernel runs (`nanochrono-baremetal/src/nccall`).

pub mod hal;

use crate::ncplu::{CAP_INPUT, CAP_LOG, CAP_PMU, CAP_RNG, CAP_SCREEN, CAP_TIMER};
use crate::rng::Mode;
use nanochrono_sys::nr::{self, nc, posix};
use nanochrono_sys::Errno;

/// The most `getrandom` fills in one call (NC_RNG's own limit).
pub const MAX_RANDOM: usize = 1 << 20;

/// One call, as the glue read it from the trap.
#[derive(Debug, Clone, Copy)]
pub struct Call {
    /// The number register, whole: a value past 32 bits ends the caller.
    pub nr: usize,
    /// The six argument words.
    pub args: [usize; 6],
    /// Where the trap instruction is: what a pin is checked against.
    pub site: usize,
    /// The caller's stack pointer at the trap.
    pub sp: usize,
}

/// A rule of the boundary a caller broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Violation {
    /// The stack pointer was outside the caller's stack: a stack pivot.
    StackPointer = 1,
    /// A NanoChronometer-service call from outside the kernel's stubs.
    UnpinnedSite = 2,
    /// A return address the exit path cannot take (x86-64's `SYSRET`).
    ReturnAddress = 3,
}

impl Violation {
    pub const fn describe(self) -> &'static str {
        match self {
            Violation::StackPointer => "nccall with the stack pointer outside its stack (a stack pivot)",
            Violation::UnpinnedSite => "a NanoChronometer-service nccall from outside the kernel's stubs",
            Violation::ReturnAddress => "a nccall whose return address SYSRET cannot take",
        }
    }
}

/// Why a caller is ended rather than answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// `exit`, with this status.
    Exit(u64),
    /// Its stack canary changed (`nc::STACK_CHK_FAIL`).
    StackSmashed,
    /// A NanoChronometer service it was not granted the capability for.
    Denied(u32),
    /// It broke a rule of the boundary.
    Violation(Violation),
    /// A number no class knows, or a class-0 service there is none of.
    Unknown(usize),
}

/// What goes back through the glue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The two result words; the error flag clear.
    Ok(usize, usize),
    /// The errno in the first result word; the error flag set.
    Err(Errno),
    /// The caller does not get an answer: it is ended.
    End(Ending),
}

/// Who is calling, and what the kernel may do on its behalf.
pub trait Caller {
    /// The capability groups granted (`CAP_*` bits).
    fn caps(&self) -> u32;
    /// Whether `[ptr, ptr + len)` is the caller's own memory: the only
    /// memory the kernel reads or writes for it.
    fn owns(&self, ptr: usize, len: usize) -> bool;
    /// The caller's stack, `[base, base + len]`. A call made with the stack
    /// pointer elsewhere is a stack pivot, and ends the caller (OpenBSD's
    /// rule). `None`: not checked.
    fn stack(&self) -> Option<(usize, usize)> {
        None
    }
    /// Whether a class-0 call from `site` comes from code the kernel vouches
    /// for (its stubs; later, the pins the loader registers).
    fn pinned(&self, _site: usize) -> bool {
        true
    }
    /// A class-0 service: the screen, input, the timer, the PMU, NC_RNG, the
    /// log — what depends on the caller's environment. `None`: there is no
    /// such service for it, and it is ended.
    fn service(&mut self, nr: u32, args: &[usize; 6]) -> Option<usize>;
    /// Monotonic time in nanoseconds, for `clock_gettime`.
    fn now_ns(&self) -> Option<u64> {
        None
    }
    /// `len` bytes of fresh, zeroed, read-write memory of the caller's.
    fn map_anon(&mut self, _len: usize) -> Result<usize, Errno> {
        Err(Errno::ENOMEM)
    }
    /// Gives a range from [`Caller::map_anon`] back.
    fn unmap(&mut self, _addr: usize, _len: usize) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    /// `write(1|2, …)`: the bytes to the console — the UART, or what stands
    /// in for it — and nowhere else. Default: there is no console.
    fn console(&mut self, _bytes: &[u8]) -> Result<(), Errno> {
        Err(Errno::EIO)
    }
    /// `getrandom`: `out` filled from NC_RNG in `mode`; the bytes written, or
    /// `None` when it cannot be done now. Default: there is no generator.
    fn random(&mut self, _out: &mut [u8], _mode: Mode) -> Option<usize> {
        None
    }
    /// Told why it is ended, before the glue unwinds it.
    fn ended(&mut self, _why: Ending) {}
}

/// The capability a class-0 call needs, or 0 for one always allowed.
pub fn capability(nr: u32) -> u32 {
    match nr {
        nc::FILL_RECT | nc::CLEAR | nc::PRESENT => CAP_SCREEN,
        nc::POLL_EVENT => CAP_INPUT,
        nc::LOG => CAP_LOG,
        nc::TICKS | nc::TIMER_NOW | nc::TIMER_NOW_END | nc::TIMER_HZ | nc::TIMER_SOURCE | nc::TIMER_TICKS_TO_NS => {
            CAP_TIMER
        }
        nc::PMU_CAPS | nc::PMU_OPEN | nc::PMU_READ | nc::PMU_CLOSE => CAP_PMU,
        nc::RNG_FILL | nc::RNG_STATUS | nc::RNG_STIR | nc::RNG_SELFTEST => CAP_RNG,
        _ => 0,
    }
}

/// Answers one call for `caller`. Every ISA's glue ends here.
pub fn dispatch(call: &Call, caller: &mut dyn Caller) -> Reply {
    let reply = route(call, caller);
    if let Reply::End(why) = reply {
        caller.ended(why);
    }
    reply
}

fn route(call: &Call, caller: &mut dyn Caller) -> Reply {
    // OpenBSD's rule: a system call is made on the program's own stack, or
    // the program is not what it was.
    if let Some((base, len)) = caller.stack() {
        if !(base..=base.saturating_add(len)).contains(&call.sp) {
            return Reply::End(Ending::Violation(Violation::StackPointer));
        }
    }
    if call.nr > u32::MAX as usize {
        return Reply::End(Ending::Unknown(call.nr));
    }
    let n = call.nr as u32;
    match nr::class(n) {
        nr::CLASS_NC => service(n, call, caller),
        // exit's status is an int: sign-extended, as the C caller meant it.
        nr::CLASS_POSIX if n == posix::EXIT => Reply::End(Ending::Exit(call.args[0] as i32 as i64 as u64)),
        nr::CLASS_POSIX => match posix_call(n, &call.args, caller) {
            Ok((value, value2)) => Reply::Ok(value, value2),
            Err(e) => Reply::Err(e),
        },
        nr::CLASS_DIAG if n == nr::diag::ECHO => {
            let (value, value2) = nr::diag::echo(call.args);
            Reply::Ok(value, value2)
        }
        nr::CLASS_DIAG => Reply::Err(Errno::ENOSYS),
        _ => Reply::End(Ending::Unknown(call.nr)),
    }
}

/// A class-0 call: one `NcApi` service. An unknown number ends the caller
/// (the default FreeBSD gives `SIGSYS`); so does a service it was not
/// granted, and so does a call from a site the kernel does not vouch for.
fn service(n: u32, call: &Call, caller: &mut dyn Caller) -> Reply {
    if !caller.pinned(call.site) {
        return Reply::End(Ending::Violation(Violation::UnpinnedSite));
    }
    // Its canary changed: the caller's stack is corrupt, so it is ended here,
    // before its return address is ever used. Always allowed.
    if n == nc::STACK_CHK_FAIL {
        return Reply::End(Ending::StackSmashed);
    }
    // The capability wall: a caller reaching past what it declared is
    // misbehaving, and cannot talk its way around this.
    let cap = capability(n);
    if cap != 0 && caller.caps() & cap != cap {
        return Reply::End(Ending::Denied(n));
    }
    if n == nc::EXIT {
        return Reply::End(Ending::Exit(call.args[0] as u64));
    }
    match caller.service(n, &call.args) {
        Some(value) => Reply::Ok(value, 0),
        None => Reply::End(Ending::Unknown(call.nr)),
    }
}

/// A class-1 call other than `exit`. What exists is served; the rest is
/// `ENOSYS`, so a library can probe. A call outside the capability groups the
/// caller declared is refused with `ENOTCAPABLE` — Capsicum's answer, where a
/// class-0 service ends the caller instead.
fn posix_call(n: u32, a: &[usize; 6], caller: &mut dyn Caller) -> Result<(usize, usize), Errno> {
    let need = |cap: u32| if caller.caps() & cap == cap { Ok(()) } else { Err(Errno::ENOTCAPABLE) };
    match n {
        // The caller is the only process there is.
        posix::GETPID => Ok((1, 0)),
        posix::WRITE => {
            let (fd, buf, len) = (a[0] as i32, a[1], a[2]);
            if fd != 1 && fd != 2 {
                return Err(Errno::EBADF);
            }
            need(CAP_LOG)?;
            if len == 0 {
                return Ok((0, 0));
            }
            // A short write is a write: at most 4 KiB per call, as the
            // console takes them.
            let len = len.min(4096);
            if !caller.owns(buf, len) {
                return Err(Errno::EFAULT);
            }
            // SAFETY: the range is the caller's own memory (checked above).
            let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
            caller.console(bytes)?;
            Ok((len, 0))
        }
        posix::MMAP => {
            use nr::{map, prot};
            let (len, prot_bits, flags, fd, pgoff) = (a[1], a[2] as u32, a[3] as u32, a[4] as i32, a[5]);
            if len == 0 || flags & map::FIXED != 0 {
                return Err(Errno::EINVAL);
            }
            if flags & map::ANON == 0 || fd != -1 || pgoff != 0 {
                // No file can be mapped: there is no file descriptor table yet.
                return Err(Errno::ENOTSUP);
            }
            if flags & (map::SHARED | map::PRIVATE) == 0 {
                return Err(Errno::EINVAL);
            }
            if prot_bits & prot::EXEC != 0 {
                // W^X for everything a caller maps.
                return Err(Errno::EACCES);
            }
            if prot_bits & !(prot::READ | prot::WRITE) != 0 {
                return Err(Errno::EINVAL);
            }
            caller.map_anon(len).map(|p| (p, 0))
        }
        posix::MUNMAP => caller.unmap(a[0], a[1]).map(|()| (0, 0)),
        posix::CLOCK_GETTIME => {
            need(CAP_TIMER)?;
            let (clock, out) = (a[0] as u32, a[1]);
            if clock != nr::clock::MONOTONIC && clock != nr::clock::UPTIME {
                // No wall clock until the RTC is read: CLOCK_REALTIME is not
                // one this kernel has.
                return Err(Errno::EINVAL);
            }
            if !caller.owns(out, core::mem::size_of::<nr::Timespec>()) {
                return Err(Errno::EFAULT);
            }
            let ns = caller.now_ns().ok_or(Errno::ENOSYS)?;
            let ts = nr::Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
            // SAFETY: the caller's own memory, sized for one Timespec.
            unsafe { core::ptr::write_unaligned(out as *mut nr::Timespec, ts) };
            Ok((0, 0))
        }
        posix::GETRANDOM => {
            need(CAP_RNG)?;
            let (buf, len, flags) = (a[0], a[1], a[2] as u32);
            if flags & !(nr::grnd::NONBLOCK | nr::grnd::RANDOM | nr::grnd::INSECURE) != 0 {
                return Err(Errno::EINVAL);
            }
            let len = len.min(MAX_RANDOM);
            if len == 0 {
                return Ok((0, 0));
            }
            if !caller.owns(buf, len) {
                return Err(Errno::EFAULT);
            }
            // SAFETY: the caller's own memory (checked above).
            let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
            // GRND_RANDOM asks for NC_RNG's TRUE mode, a fresh seed per block.
            let mode = Mode::from_flags((flags & nr::grnd::RANDOM != 0) as u32);
            match caller.random(out, mode) {
                Some(n) => Ok((n, 0)),
                None if flags & nr::grnd::NONBLOCK != 0 => Err(Errno::EAGAIN),
                None => Err(Errno::EIO),
            }
        }
        _ => Err(Errno::ENOSYS),
    }
}

// ---------------------------------------------------------------------------
// The caller every trap is answered for
// ---------------------------------------------------------------------------

/// The caller [`serve`] installed; null when nobody is being served.
static mut CURRENT: Option<*mut (dyn Caller + 'static)> = None;

/// Runs `f` with `caller` as the one every `nccall` trap is answered for —
/// a ring-3 run, a self-test — and puts the previous one back after.
pub fn serve<'a, R>(caller: &'a mut (dyn Caller + 'a), f: impl FnOnce() -> R) -> R {
    let pointer: *mut (dyn Caller + 'a) = caller;
    // SAFETY: only the lifetime changes. The pointer lives in CURRENT while
    // `caller` is borrowed here and is taken out again below, before this
    // function returns; one core, interrupts masked, so nothing else reads
    // CURRENT meanwhile.
    let previous = unsafe {
        let erased = core::mem::transmute::<*mut (dyn Caller + 'a), *mut (dyn Caller + 'static)>(pointer);
        core::ptr::replace(&raw mut CURRENT, Some(erased))
    };
    let result = f();
    // SAFETY: as above.
    unsafe { CURRENT = previous };
    result
}

/// Whether `[ptr, ptr + len)` is the served caller's own memory; false
/// with nobody served.
pub fn current_owns(ptr: usize, len: usize) -> bool {
    // SAFETY: as `dispatch_current`.
    match unsafe { CURRENT } {
        // SAFETY: valid for as long as it is installed (see `serve`).
        Some(caller) => unsafe { (*caller).owns(ptr, len) },
        None => false,
    }
}

/// Answers `call` for the caller being served. With none — a stray trap from
/// the kernel itself — the answer is `ENOSYS` and nobody is ended.
pub fn dispatch_current(call: &Call) -> Reply {
    // SAFETY: set and cleared only by `serve`, around the borrow it erases.
    match unsafe { CURRENT } {
        // SAFETY: valid for as long as it is installed (see `serve`).
        Some(caller) => dispatch(call, unsafe { &mut *caller }),
        None => Reply::Err(Errno::ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller with a 64-byte buffer of its own and every capability.
    struct Probe {
        buf: [u8; 64],
        ended: Option<Ending>,
        printed: usize,
    }

    impl Caller for Probe {
        fn caps(&self) -> u32 {
            u32::MAX
        }
        fn owns(&self, ptr: usize, len: usize) -> bool {
            let base = self.buf.as_ptr() as usize;
            ptr >= base && ptr.saturating_add(len) <= base + self.buf.len()
        }
        fn stack(&self) -> Option<(usize, usize)> {
            Some((0x1000, 0x1000))
        }
        fn service(&mut self, n: u32, _: &[usize; 6]) -> Option<usize> {
            (n == nc::TIMER_HZ).then_some(1_000_000_000)
        }
        fn now_ns(&self) -> Option<u64> {
            Some(5_000_000_123)
        }
        fn console(&mut self, bytes: &[u8]) -> Result<(), Errno> {
            self.printed += bytes.len();
            Ok(())
        }
        fn random(&mut self, out: &mut [u8], _: Mode) -> Option<usize> {
            out.fill(0xA5);
            Some(out.len())
        }
        fn ended(&mut self, why: Ending) {
            self.ended = Some(why);
        }
    }

    fn probe() -> Probe {
        Probe { buf: [0; 64], ended: None, printed: 0 }
    }

    fn call(nr: u32, args: [usize; 6]) -> Call {
        Call { nr: nr as usize, args, site: 0, sp: 0x1800 }
    }

    #[test]
    fn echo_returns_what_every_register_carried() {
        let mut p = probe();
        let a = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert_eq!(dispatch(&call(nr::diag::ECHO, a), &mut p), Reply::Ok(0x60B, 0x66));
    }

    #[test]
    fn posix_answers_and_errors() {
        let mut p = probe();
        assert_eq!(dispatch(&call(posix::GETPID, [0; 6]), &mut p), Reply::Ok(1, 0));
        assert_eq!(dispatch(&call(posix::freebsd(999), [0; 6]), &mut p), Reply::Err(Errno::ENOSYS));
        assert_eq!(dispatch(&call(posix::WRITE, [7, 0, 1, 0, 0, 0]), &mut p), Reply::Err(Errno::EBADF));
        // A pointer that is not the caller's.
        assert_eq!(dispatch(&call(posix::WRITE, [1, 16, 8, 0, 0, 0]), &mut p), Reply::Err(Errno::EFAULT));
        let ts = p.buf.as_mut_ptr() as usize;
        let r = dispatch(&call(posix::CLOCK_GETTIME, [nr::clock::MONOTONIC as usize, ts, 0, 0, 0, 0]), &mut p);
        assert_eq!(r, Reply::Ok(0, 0));
        assert_eq!(&p.buf[..8], &5i64.to_ne_bytes());
        assert_eq!(&p.buf[8..16], &123i64.to_ne_bytes());
        // mmap's rules come before the caller's pool (which this one has not).
        let anon = (nr::map::ANON | nr::map::PRIVATE) as usize;
        let rw = (nr::prot::READ | nr::prot::WRITE) as usize;
        let exec = nr::prot::EXEC as usize;
        assert_eq!(dispatch(&call(posix::MMAP, [0, 4096, exec, anon, usize::MAX, 0]), &mut p), Reply::Err(Errno::EACCES));
        assert_eq!(dispatch(&call(posix::MMAP, [0, 4096, rw, anon, 3, 0]), &mut p), Reply::Err(Errno::ENOTSUP));
        assert_eq!(dispatch(&call(posix::MMAP, [0, 4096, rw, anon, usize::MAX, 0]), &mut p), Reply::Err(Errno::ENOMEM));
    }

    #[test]
    fn write_and_getrandom_go_through_the_caller() {
        let mut p = probe();
        let buf = p.buf.as_mut_ptr() as usize;
        assert_eq!(dispatch(&call(posix::WRITE, [1, buf, 10, 0, 0, 0]), &mut p), Reply::Ok(10, 0));
        assert_eq!(p.printed, 10);
        assert_eq!(dispatch(&call(posix::WRITE, [2, buf, 0, 0, 0, 0]), &mut p), Reply::Ok(0, 0));
        assert_eq!(dispatch(&call(posix::GETRANDOM, [buf, 16, 0, 0, 0, 0]), &mut p), Reply::Ok(16, 0));
        assert_eq!(&p.buf[..16], &[0xA5; 16]);
        assert_eq!(dispatch(&call(posix::GETRANDOM, [buf, 16, 0x80, 0, 0, 0]), &mut p), Reply::Err(Errno::EINVAL));
        // A caller with neither: EIO, or EAGAIN when it asked not to block.
        struct Mute(u8);
        impl Caller for Mute {
            fn caps(&self) -> u32 {
                u32::MAX
            }
            fn owns(&self, _: usize, _: usize) -> bool {
                true
            }
            fn service(&mut self, _: u32, _: &[usize; 6]) -> Option<usize> {
                None
            }
        }
        let mut m = Mute(0);
        let at = &mut m.0 as *mut u8 as usize;
        assert_eq!(dispatch(&call(posix::WRITE, [1, at, 1, 0, 0, 0]), &mut m), Reply::Err(Errno::EIO));
        assert_eq!(dispatch(&call(posix::GETRANDOM, [at, 1, 0, 0, 0, 0]), &mut m), Reply::Err(Errno::EIO));
        let nonblock = nr::grnd::NONBLOCK as usize;
        assert_eq!(dispatch(&call(posix::GETRANDOM, [at, 1, nonblock, 0, 0, 0]), &mut m), Reply::Err(Errno::EAGAIN));
    }

    #[test]
    fn the_caller_is_ended_for_what_ends_it() {
        let mut p = probe();
        assert_eq!(dispatch(&call(posix::EXIT, [3, 0, 0, 0, 0, 0]), &mut p), Reply::End(Ending::Exit(3)));
        assert_eq!(p.ended, Some(Ending::Exit(3)));
        // exit's status is an int: -1 comes back sign-extended.
        let r = dispatch(&call(posix::EXIT, [u32::MAX as usize, 0, 0, 0, 0, 0]), &mut p);
        assert_eq!(r, Reply::End(Ending::Exit(u64::MAX)));
        assert_eq!(dispatch(&call(nc::STACK_CHK_FAIL, [0; 6]), &mut p), Reply::End(Ending::StackSmashed));
        assert_eq!(dispatch(&call(nc::TIMER_HZ, [0; 6]), &mut p), Reply::Ok(1_000_000_000, 0));
        assert_eq!(dispatch(&call(nc::RNG_SELFTEST, [0; 6]), &mut p), Reply::End(Ending::Unknown(nc::RNG_SELFTEST as usize)));
        assert_eq!(dispatch(&call(nr::make(9, 0), [0; 6]), &mut p), Reply::End(Ending::Unknown(nr::make(9, 0) as usize)));
        // A stack pivot ends the caller whatever it asked.
        let mut pivot = call(posix::GETPID, [0; 6]);
        pivot.sp = 0x9000;
        assert_eq!(dispatch(&pivot, &mut p), Reply::End(Ending::Violation(Violation::StackPointer)));
    }

    #[test]
    fn capabilities_are_checked_per_class() {
        struct Bare;
        impl Caller for Bare {
            fn caps(&self) -> u32 {
                0
            }
            fn owns(&self, _: usize, _: usize) -> bool {
                true
            }
            fn service(&mut self, _: u32, _: &[usize; 6]) -> Option<usize> {
                Some(0)
            }
        }
        // A class-0 service without its capability ends the caller...
        assert_eq!(dispatch(&call(nc::TIMER_HZ, [0; 6]), &mut Bare), Reply::End(Ending::Denied(nc::TIMER_HZ)));
        // ... a class-1 call says ENOTCAPABLE.
        assert_eq!(dispatch(&call(posix::WRITE, [1, 0x100, 1, 0, 0, 0]), &mut Bare), Reply::Err(Errno::ENOTCAPABLE));
        // Class 2 needs nothing.
        assert_eq!(dispatch(&call(nr::diag::ECHO, [1, 0, 0, 0, 0, 0]), &mut Bare), Reply::Ok(1, 0));
    }

    #[test]
    fn nobody_served_means_enosys() {
        assert_eq!(dispatch_current(&call(posix::GETPID, [0; 6])), Reply::Err(Errno::ENOSYS));
        let mut p = probe();
        assert_eq!(serve(&mut p, || dispatch_current(&call(posix::GETPID, [0; 6]))), Reply::Ok(1, 0));
        assert_eq!(dispatch_current(&call(posix::GETPID, [0; 6])), Reply::Err(Errno::ENOSYS));
    }
}
