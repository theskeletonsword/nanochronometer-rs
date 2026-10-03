// SPDX-License-Identifier: Apache-2.0
//! Standard output and error as [`core::fmt::Write`], and the `print!` family
//! over them: formatting with no allocator, straight into `write(2)`.

use core::fmt;

use crate::posix::{self, Fd};

/// A file descriptor that formatted text is written to.
#[derive(Clone, Copy, Debug)]
pub struct FdWriter(pub Fd);

/// Standard output.
pub const STDOUT: FdWriter = FdWriter(posix::STDOUT);
/// Standard error.
pub const STDERR: FdWriter = FdWriter(posix::STDERR);

impl fmt::Write for FdWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        posix::write_all(self.0, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Writes formatted text to `fd`; the error, if any, is dropped as `print!`
/// drops it.
#[doc(hidden)]
pub fn _print(fd: Fd, args: fmt::Arguments<'_>) {
    let _ = fmt::Write::write_fmt(&mut FdWriter(fd), args);
}

/// `print!` to standard output.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::io::_print($crate::posix::STDOUT, format_args!($($arg)*)) };
}

/// `println!` to standard output.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        $crate::io::_print($crate::posix::STDOUT, format_args!($($arg)*));
        $crate::print!("\n");
    }};
}

/// `eprintln!` to standard error.
#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        $crate::io::_print($crate::posix::STDERR, format_args!($($arg)*));
        $crate::io::_print($crate::posix::STDERR, format_args!("\n"));
    }};
}
