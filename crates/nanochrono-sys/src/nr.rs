// SPDX-License-Identifier: Apache-2.0
//! Call numbers: what the number register holds when `nccall` traps.
//!
//! A number is 32 bits: a **class** in bits 31..16 and an index in bits
//! 15..0. Two classes exist.
//!
//! * [`nc`] (class 0) — NanoChronometer's own services: the screen, input,
//!   the instrument's timer and PMU, NC_RNG. These are the calls behind the
//!   `NcApi` table a plugin is handed; their numbers are the ones the
//!   kernel's ring-3 stubs have always loaded, unchanged. An unknown class-0
//!   number ends the caller — the default FreeBSD gives `SIGSYS`.
//! * [`posix`] (class 1) — the POSIX/BSD surface, **indexed by FreeBSD's
//!   `sys/kern/syscalls.master`**: `write` is FreeBSD's 4, `mmap` its 477.
//!   A C library adapted from FreeBSD's finds every call at the number it
//!   was generated for, plus the class bit. A class-1 number the kernel does
//!   not serve fails with `ENOSYS` instead of ending the caller, so a library
//!   can probe and fall back.
//!
//! # Arguments
//!
//! At most [`MAX_ARGS`] (six) machine words, on every architecture. A 64-bit
//! value on a 32-bit target takes two consecutive words, low word first, no
//! padding — except the `mmap` offset, which is passed in 4 KiB units so the
//! call still fits in six words there. Results come back the same way: one
//! word, or two (`ret0` low, `ret1` high) for a 64-bit result on a 32-bit
//! target.

/// Bit position of the class in a call number.
pub const CLASS_SHIFT: u32 = 16;
/// Mask of the index within a class.
pub const INDEX_MASK: u32 = 0xFFFF;
/// NanoChronometer services.
pub const CLASS_NC: u32 = 0;
/// POSIX/BSD calls, indexed by FreeBSD's `syscalls.master`.
pub const CLASS_POSIX: u32 = 1;

/// The most argument words any call takes, on every architecture.
pub const MAX_ARGS: usize = 6;

/// The class of a call number.
pub const fn class(nr: u32) -> u32 {
    nr >> CLASS_SHIFT
}

/// The index of a call number within its class.
pub const fn index(nr: u32) -> u32 {
    nr & INDEX_MASK
}

/// Builds a number from a class and an index.
pub const fn make(class: u32, index: u32) -> u32 {
    (class << CLASS_SHIFT) | (index & INDEX_MASK)
}

/// NanoChronometer services (class 0). Each is one entry of the plugin's
/// `NcApi` table; the kernel builds a stub per entry that loads this number.
pub mod nc {
    /// Ends the caller; argument 1 is its exit status.
    pub const EXIT: u32 = 0;
    pub const FILL_RECT: u32 = 1;
    pub const CLEAR: u32 = 2;
    pub const PRESENT: u32 = 3;
    pub const POLL_EVENT: u32 = 4;
    pub const TICKS: u32 = 5;
    pub const LOG: u32 = 6;
    pub const TIMER_NOW: u32 = 7;
    pub const TIMER_NOW_END: u32 = 8;
    pub const TIMER_HZ: u32 = 9;
    pub const TIMER_SOURCE: u32 = 10;
    pub const TIMER_TICKS_TO_NS: u32 = 11;
    pub const PMU_CAPS: u32 = 12;
    pub const PMU_OPEN: u32 = 13;
    pub const PMU_READ: u32 = 14;
    pub const PMU_CLOSE: u32 = 15;
    pub const RNG_FILL: u32 = 16;
    pub const RNG_STATUS: u32 = 17;
    pub const RNG_STIR: u32 = 18;
    pub const RNG_SELFTEST: u32 = 19;
    /// The caller's stack canary changed (`__stack_chk_fail`): end it.
    pub const STACK_CHK_FAIL: u32 = 20;
    /// Reserved: create a process from an image, NetBSD `posix_spawn(2)`
    /// semantics (one call, no `fork`). Fails with `ENOSYS` until processes
    /// exist; the number is fixed now so binaries built today keep it.
    pub const SPAWN: u32 = 32;
    /// The highest class-0 number assigned.
    pub const LAST: u32 = SPAWN;
}

// Every class-0 number fits below the class bits.
const _: () = assert!(nc::LAST < 1 << CLASS_SHIFT);

/// POSIX/BSD calls (class 1), at FreeBSD's index plus the class bit.
pub mod posix {
    use super::{make, CLASS_POSIX};

    /// FreeBSD `syscalls.master` index → class-1 number.
    pub const fn freebsd(index: u32) -> u32 {
        make(CLASS_POSIX, index)
    }

    /// `void exit(int status)` — FreeBSD 1.
    pub const EXIT: u32 = freebsd(1);
    /// `ssize_t read(int fd, void *buf, size_t nbyte)` — FreeBSD 3.
    pub const READ: u32 = freebsd(3);
    /// `ssize_t write(int fd, const void *buf, size_t nbyte)` — FreeBSD 4.
    pub const WRITE: u32 = freebsd(4);
    /// `int open(const char *path, int flags, mode_t mode)` — FreeBSD 5.
    pub const OPEN: u32 = freebsd(5);
    /// `int close(int fd)` — FreeBSD 6.
    pub const CLOSE: u32 = freebsd(6);
    /// `pid_t getpid(void)` — FreeBSD 20.
    pub const GETPID: u32 = freebsd(20);
    /// `int munmap(void *addr, size_t len)` — FreeBSD 73.
    pub const MUNMAP: u32 = freebsd(73);
    /// `int mprotect(void *addr, size_t len, int prot)` — FreeBSD 74.
    pub const MPROTECT: u32 = freebsd(74);
    /// `int socket(int domain, int type, int protocol)` — FreeBSD 97.
    pub const SOCKET: u32 = freebsd(97);
    /// `int clock_gettime(clockid_t clock_id, struct timespec *tp)` — FreeBSD 232.
    pub const CLOCK_GETTIME: u32 = freebsd(232);
    /// `int nanosleep(const struct timespec *rqtp, struct timespec *rmtp)` — FreeBSD 240.
    pub const NANOSLEEP: u32 = freebsd(240);
    /// `void *mmap(void *addr, size_t len, int prot, int flags, int fd,
    /// off_t pos)` — FreeBSD 477, with `pos` in 4 KiB units (see the module
    /// documentation).
    pub const MMAP: u32 = freebsd(477);
    /// `ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)` — FreeBSD 563.
    pub const GETRANDOM: u32 = freebsd(563);
}

/// One known call: its number, its name, how many argument words it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    pub nr: u32,
    pub name: &'static str,
    pub args: u8,
}

/// Every number this crate names, for tooling and the kernel's report.
pub const CALLS: &[Call] = &[
    Call { nr: nc::EXIT, name: "nc_exit", args: 1 },
    Call { nr: nc::FILL_RECT, name: "nc_fill_rect", args: 5 },
    Call { nr: nc::CLEAR, name: "nc_clear", args: 1 },
    Call { nr: nc::PRESENT, name: "nc_present", args: 0 },
    Call { nr: nc::POLL_EVENT, name: "nc_poll_event", args: 0 },
    Call { nr: nc::TICKS, name: "nc_ticks", args: 0 },
    Call { nr: nc::LOG, name: "nc_log", args: 2 },
    Call { nr: nc::TIMER_NOW, name: "nc_timer_now", args: 0 },
    Call { nr: nc::TIMER_NOW_END, name: "nc_timer_now_end", args: 0 },
    Call { nr: nc::TIMER_HZ, name: "nc_timer_hz", args: 0 },
    Call { nr: nc::TIMER_SOURCE, name: "nc_timer_source", args: 0 },
    Call { nr: nc::TIMER_TICKS_TO_NS, name: "nc_timer_ticks_to_ns", args: 1 },
    Call { nr: nc::PMU_CAPS, name: "nc_pmu_caps", args: 0 },
    Call { nr: nc::PMU_OPEN, name: "nc_pmu_open", args: 1 },
    Call { nr: nc::PMU_READ, name: "nc_pmu_read", args: 1 },
    Call { nr: nc::PMU_CLOSE, name: "nc_pmu_close", args: 1 },
    Call { nr: nc::RNG_FILL, name: "nc_rng_fill", args: 3 },
    Call { nr: nc::RNG_STATUS, name: "nc_rng_status", args: 1 },
    Call { nr: nc::RNG_STIR, name: "nc_rng_stir", args: 2 },
    Call { nr: nc::RNG_SELFTEST, name: "nc_rng_selftest", args: 0 },
    Call { nr: nc::STACK_CHK_FAIL, name: "nc_stack_chk_fail", args: 0 },
    Call { nr: nc::SPAWN, name: "nc_spawn", args: 4 },
    Call { nr: posix::EXIT, name: "exit", args: 1 },
    Call { nr: posix::READ, name: "read", args: 3 },
    Call { nr: posix::WRITE, name: "write", args: 3 },
    Call { nr: posix::OPEN, name: "open", args: 3 },
    Call { nr: posix::CLOSE, name: "close", args: 1 },
    Call { nr: posix::GETPID, name: "getpid", args: 0 },
    Call { nr: posix::MUNMAP, name: "munmap", args: 2 },
    Call { nr: posix::MPROTECT, name: "mprotect", args: 3 },
    Call { nr: posix::SOCKET, name: "socket", args: 3 },
    Call { nr: posix::CLOCK_GETTIME, name: "clock_gettime", args: 2 },
    Call { nr: posix::NANOSLEEP, name: "nanosleep", args: 2 },
    Call { nr: posix::MMAP, name: "mmap", args: 6 },
    Call { nr: posix::GETRANDOM, name: "getrandom", args: 3 },
];

/// The entry for `nr`, if this crate names it.
pub fn lookup(nr: u32) -> Option<&'static Call> {
    CALLS.iter().find(|c| c.nr == nr)
}

// ---------------------------------------------------------------------------
// Constants the POSIX-class calls take, FreeBSD's values.
// ---------------------------------------------------------------------------

/// `mmap`/`mprotect` protection bits (FreeBSD `sys/sys/mman.h`).
pub mod prot {
    pub const NONE: u32 = 0x00;
    pub const READ: u32 = 0x01;
    pub const WRITE: u32 = 0x02;
    pub const EXEC: u32 = 0x04;
}

/// `mmap` flags (FreeBSD `sys/sys/mman.h`).
pub mod map {
    pub const SHARED: u32 = 0x0001;
    pub const PRIVATE: u32 = 0x0002;
    pub const FIXED: u32 = 0x0010;
    pub const STACK: u32 = 0x0400;
    pub const ANON: u32 = 0x1000;
    pub const GUARD: u32 = 0x2000;
    pub const EXCL: u32 = 0x4000;
    /// The unit of `mmap`'s offset argument in a `nccall`, whatever the page
    /// size: the offset is passed as `pos / OFFSET_UNIT`.
    pub const OFFSET_UNIT: u64 = 4096;
}

/// `clock_gettime` clocks (FreeBSD `sys/sys/_clock_id.h`).
pub mod clock {
    pub const REALTIME: u32 = 0;
    pub const MONOTONIC: u32 = 4;
    pub const UPTIME: u32 = 5;
}

/// `getrandom` flags (FreeBSD `sys/sys/random.h`).
pub mod grnd {
    pub const NONBLOCK: u32 = 0x1;
    pub const RANDOM: u32 = 0x2;
    pub const INSECURE: u32 = 0x4;
}

/// The `struct timespec` a `clock_gettime` fills: 64-bit seconds and
/// nanoseconds on every architecture, so no target has a year-2038 limit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_split_and_join() {
        assert_eq!(class(posix::WRITE), CLASS_POSIX);
        assert_eq!(index(posix::WRITE), 4);
        assert_eq!(class(nc::RNG_FILL), CLASS_NC);
        assert_eq!(make(CLASS_POSIX, 477), posix::MMAP);
    }

    #[test]
    fn numbers_are_unique_and_args_bounded() {
        for (i, a) in CALLS.iter().enumerate() {
            assert!(a.args as usize <= MAX_ARGS, "{} takes too many words", a.name);
            for b in &CALLS[i + 1..] {
                assert_ne!(a.nr, b.nr, "{} and {} share a number", a.name, b.name);
                assert_ne!(a.name, b.name);
            }
        }
    }

    #[test]
    fn freebsd_indices_match_syscalls_master() {
        // The FreeBSD numbers, spelled out once more: a typo in `posix`
        // would otherwise silently route a call to another one.
        let expected = [
            (posix::EXIT, 1),
            (posix::READ, 3),
            (posix::WRITE, 4),
            (posix::OPEN, 5),
            (posix::CLOSE, 6),
            (posix::GETPID, 20),
            (posix::MUNMAP, 73),
            (posix::MPROTECT, 74),
            (posix::SOCKET, 97),
            (posix::CLOCK_GETTIME, 232),
            (posix::NANOSLEEP, 240),
            (posix::MMAP, 477),
            (posix::GETRANDOM, 563),
        ];
        for (nr, freebsd) in expected {
            assert_eq!(class(nr), CLASS_POSIX);
            assert_eq!(index(nr), freebsd);
        }
    }

    #[test]
    fn nc_class_keeps_the_plugin_api_numbers() {
        // The kernel's stubs and every existing plugin's NcApi depend on
        // these; they never move.
        assert_eq!(nc::EXIT, 0);
        assert_eq!(nc::LOG, 6);
        assert_eq!(nc::RNG_SELFTEST, 19);
        assert_eq!(nc::STACK_CHK_FAIL, 20);
    }

    #[test]
    fn timespec_is_two_words_of_64_bits() {
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
    }
}
