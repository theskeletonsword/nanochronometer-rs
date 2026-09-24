// SPDX-License-Identifier: Apache-2.0
//! Output with no operating system to print through.
//!
//! There is no `write(2)`, no stdout and no console driver. What there is, on
//! both architectures, is a UART at a known address that needs no
//! initialisation beyond a handful of register writes — so that is where the
//! results go. Under QEMU it lands on the host's terminal with `-serial
//! stdio`, which is what makes this kernel testable at all.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

/// Whether output is still being attempted.
///
/// Starts true and is only cleared by evidence: a probe that says there is no
/// UART is a *hint*, and a hint that turns out to be wrong would silence the
/// log on a machine that has a perfectly good port. What actually clears this
/// is the transmitter timing out — which cannot be wrong, because it means
/// the byte was not sent.
///
/// The point of clearing it at all is cost. Each timeout is bounded, but
/// paying one per character on a machine with no serial port turns a page of
/// output into a visible stall.
static LIVE: AtomicBool = AtomicBool::new(true);

/// A UART, wherever this architecture keeps one.
pub struct Serial;

impl Serial {
    /// Prepares the port for output.
    ///
    /// # Safety
    /// Touches device registers, so it requires ring 0 / EL1 and assumes
    /// nothing else is driving the same UART.
    pub unsafe fn init() {
        #[cfg(x86_any)]
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            x86_uart::init()
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            pl011::init()
        }
        #[cfg(any(target_arch = "powerpc", target_arch = "riscv32", target_arch = "riscv64"))]
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            ns16550::init()
        }
        LIVE.store(true, Ordering::Relaxed);
    }

    /// Whether output is still going anywhere.
    ///
    /// Worth surfacing: on a machine with no serial port the log goes
    /// nowhere, and that is not the same as a kernel that produced none.
    pub fn is_live() -> bool {
        LIVE.load(Ordering::Relaxed)
    }

    // powernv writes whole strings through OPAL instead; see `write_str`.
    #[cfg(not(target_arch = "powerpc64"))]
    fn put(byte: u8) {
        // The VGA text console, when there is no framebuffer to draw on. It
        // is not an alternative to the serial port but a parallel one: a
        // machine with neither has nowhere to report a failure, and that is
        // the case where a fault looks like a boot that never happened.
        #[cfg(x86_any)]
        crate::vga::put(byte);

        if !LIVE.load(Ordering::Relaxed) {
            return;
        }
        #[cfg(x86_any)]
        let sent = x86_uart::put(byte);
        #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
        let sent = pl011::put(byte);
        #[cfg(any(target_arch = "powerpc", target_arch = "riscv32", target_arch = "riscv64"))]
        let sent = ns16550::put(byte);

        if !sent {
            // The transmitter never reported ready. There is no port, or
            // nothing is draining it; either way further attempts would only
            // pay the timeout again.
            LIVE.store(false, Ordering::Relaxed);
        }
    }
}

impl fmt::Write for Serial {
    /// OPAL takes a buffer per call, and every call is a round trip through
    /// firmware (two endianness switches on `ppc64le`), so lines go over
    /// whole rather than a byte at a time.
    #[cfg(target_arch = "powerpc64")]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if !LIVE.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut sent = true;
        for (i, line) in s.split('\n').enumerate() {
            if i > 0 {
                sent &= opal_console::write(b"\r\n");
            }
            if !line.is_empty() {
                sent &= opal_console::write(line.as_bytes());
            }
        }
        if !sent {
            LIVE.store(false, Ordering::Relaxed);
        }
        Ok(())
    }

    #[cfg(not(target_arch = "powerpc64"))]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            // A bare newline leaves the cursor in column zero on a real
            // terminal, so the carriage return is added here rather than in
            // every caller's format string.
            if byte == b'\n' {
                Serial::put(b'\r');
            }
            Serial::put(byte);
        }
        Ok(())
    }
}

/// One byte from the console, if one is waiting. Never blocks.
///
/// The input half of whichever console [`Serial::init`] set up: COM1 on x86,
/// the PL011 on AArch64, OPAL on OpenPOWER, the 16550 (or firmware — the SBI
/// on RISC-V, Open Firmware on a G3/G4) elsewhere. The interactive console
/// polls it between refreshes.
pub fn read_byte() -> Option<u8> {
    #[cfg(x86_any)]
    {
        x86_uart::get()
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        pl011::get()
    }
    #[cfg(target_arch = "powerpc64")]
    {
        opal_console::read()
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "riscv32", target_arch = "riscv64"))]
    {
        ns16550::get()
    }
}

/// Writes a line to the serial port.
///
/// A macro rather than a function because the freestanding build has no
/// allocator: `format_args!` renders straight into the UART without ever
/// building a string.
#[macro_export]
macro_rules! println {
    () => { $crate::serial::_print(format_args!("\n")) };
    ($($arg:tt)*) => {{
        $crate::serial::_print(format_args!($($arg)*));
        $crate::serial::_print(format_args!("\n"));
    }};
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    use fmt::Write as _;
    // The error can only come from the formatter, and there is nothing to
    // report it to.
    let _ = Serial.write_fmt(args);
}

#[cfg(x86_any)]
mod x86_uart {
    //! The 16550 UART at COM1.

    use crate::arch::x86::{inb, outb};

    /// The address every PC has had at this port since 1981.
    const COM1: u16 = 0x3F8;

    /// # Safety
    /// Writes device registers; requires CPL 0.
    pub(super) unsafe fn init() {
        // SAFETY: caller guarantees CPL 0. This is the documented 16550
        // initialisation order; writing it out of order leaves the divisor
        // latch open and the port silent.
        unsafe {
            outb(COM1 + 1, 0x00); // no interrupts: there is no handler
            outb(COM1 + 3, 0x80); // DLAB on, so the next two writes set speed
            outb(COM1, 0x01); // divisor 1 => 115200 baud
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03); // DLAB off, 8 bits, no parity, 1 stop bit
            outb(COM1 + 2, 0xC7); // enable and clear the FIFOs
            outb(COM1 + 4, 0x0B); // RTS/DSR set
        }
    }

    /// How long to wait for the transmitter, in spin iterations.
    ///
    /// Bounded, and that bound is not a nicety. A laptop has no UART at
    /// `0x3F8`: reading an unassigned port gives `0xFF` on most chipsets,
    /// where bit 5 happens to be set and the write is harmlessly discarded —
    /// but some return `0x00`, and an unbounded wait for a bit that will
    /// never set hangs the machine on the *first* character printed, before
    /// anything else has run.
    ///
    /// That is indistinguishable from a kernel that never started, which is
    /// exactly what it looks like from the outside.
    const TX_SPIN_LIMIT: u32 = 100_000;

    /// Sends one byte. `false` if the transmitter never became ready.
    /// A received byte, if the line status register says one is waiting.
    pub(super) fn get() -> Option<u8> {
        // SAFETY: COM1's LSR and RBR; reading RBR consumes the byte.
        unsafe { (inb(COM1 + 5) & 0x01 != 0).then(|| inb(COM1)) }
    }

    pub(super) fn put(byte: u8) -> bool {
        // Bit 5 of the line status register is "transmit holding register
        // empty". Writing before it is set drops the byte.
        for _ in 0..TX_SPIN_LIMIT {
            // SAFETY: reading the line status register has no side effects,
            // and the freestanding build is always at CPL 0.
            if unsafe { inb(COM1 + 5) } & 0x20 != 0 {
                // SAFETY: as above; the port is initialised by `init`.
                unsafe { outb(COM1, byte) };
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
mod pl011 {
    //! The PL011 UART, at the address QEMU's `virt` machine maps it to.

    /// `virt` places UART0 here. A different board places it elsewhere; there
    /// is no way to discover it without parsing the device tree, which is
    /// more machinery than a self-test needs.
    const UART0: usize = 0x0900_0000;
    const UARTDR: usize = UART0;
    const UARTFR: usize = UART0 + 0x18;

    /// # Safety
    /// Writes device registers; requires EL1 and a `virt`-compatible map.
    pub(super) unsafe fn init() {
        // QEMU's PL011 is usable from reset, so there is nothing to program.
        // A real board would need the baud divisors and line control set
        // here.
    }

    /// Bounded for the same reason the x86 side is: a board that maps
    /// nothing at this address leaves TXFF set forever, and waiting on it
    /// hangs the kernel on its first character.
    const TX_SPIN_LIMIT: u32 = 100_000;

    /// Sends one byte. `false` if the FIFO never drained.
    /// A received byte, unless the receive FIFO is empty (UARTFR.RXFE,
    /// bit 4).
    pub(super) fn get() -> Option<u8> {
        // SAFETY: the PL011's flag and data registers; reading DR pops the
        // FIFO.
        unsafe {
            if core::ptr::read_volatile(UARTFR as *const u32) & (1 << 4) != 0 {
                return None;
            }
            Some(core::ptr::read_volatile(UARTDR as *const u32) as u8)
        }
    }

    pub(super) fn put(byte: u8) -> bool {
        // UARTFR bit 5 is TXFF, "transmit FIFO full".
        for _ in 0..TX_SPIN_LIMIT {
            // SAFETY: the flag register is a device MMIO read with no side
            // effects, at an address fixed by the machine model.
            if unsafe { core::ptr::read_volatile(UARTFR as *const u32) } & (1 << 5) == 0 {
                // SAFETY: the data register accepts a byte and is mapped by
                // the machine model.
                unsafe { core::ptr::write_volatile(UARTDR as *mut u32, byte as u32) };
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

/// The console on OpenPOWER: OPAL's, which drives whatever UART the platform
/// has (on `powernv` one behind the LPC bus, whose address differs per chip —
/// the reason to go through firmware at all).
#[cfg(target_arch = "powerpc64")]
mod opal_console {
    use crate::arch::ppc;

    /// Bounded retries while OPAL reports its buffer full, so a console that
    /// never drains costs a bounded delay rather than a hang.
    const BUSY_LIMIT: u32 = 10_000;

    /// One byte from OPAL's console, if one is waiting.
    pub(super) fn read() -> Option<u8> {
        if !ppc::opal_present() {
            return None;
        }
        let mut byte = [0u8; 1];
        let mut len: u64 = 1u64.to_be();
        // SAFETY: as for `write`; OPAL writes at most `len` bytes and the
        // count back through the pointer, big-endian.
        let rc = unsafe {
            ppc::opal_call(
                ppc::OPAL_CONSOLE_READ,
                0,
                &mut len as *mut u64 as u64,
                byte.as_mut_ptr() as u64,
            )
        };
        (rc == ppc::OPAL_SUCCESS && u64::from_be(len) == 1).then_some(byte[0])
    }

    pub(super) fn write(mut bytes: &[u8]) -> bool {
        if !ppc::opal_present() {
            return false;
        }
        let mut busy = 0;
        while !bytes.is_empty() {
            // OPAL reads and writes the length through a pointer, as a
            // big-endian doubleword, whatever the kernel's byte order.
            let mut len: u64 = (bytes.len() as u64).to_be();
            // SAFETY: `opal_present` says the entry point was handed over;
            // both pointers are real addresses (translation is off) of live
            // memory, and OPAL writes only `len`.
            let rc = unsafe {
                ppc::opal_call(
                    ppc::OPAL_CONSOLE_WRITE,
                    0,
                    &mut len as *mut u64 as u64,
                    bytes.as_ptr() as u64,
                )
            };
            let written = (u64::from_be(len) as usize).min(bytes.len());
            match rc {
                ppc::OPAL_SUCCESS if written > 0 => {
                    bytes = &bytes[written..];
                    busy = 0;
                }
                ppc::OPAL_SUCCESS | ppc::OPAL_BUSY | ppc::OPAL_BUSY_EVENT => {
                    busy += 1;
                    if busy > BUSY_LIMIT {
                        return false;
                    }
                    // Let OPAL's pollers drain the buffer.
                    // SAFETY: as above; a null event pointer is permitted.
                    unsafe { ppc::opal_call(ppc::OPAL_POLL_EVENTS, 0, 0, 0) };
                }
                _ => return false,
            }
        }
        true
    }
}

/// A memory-mapped 16550 — the e500's DUART inside CCSR, or the `ns16550a`
/// a RISC-V board's device tree names.
///
/// Its address comes from the device tree (and on e500 is mapped by `kmain`)
/// before [`set_uart_base`] is called. With no base set, output goes to the
/// SBI console on RISC-V — every board has one — and is dropped elsewhere
/// rather than written to address zero.
#[cfg(any(target_arch = "powerpc", target_arch = "riscv32", target_arch = "riscv64"))]
mod ns16550 {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static BASE: AtomicUsize = AtomicUsize::new(0);

    const THR: usize = 0;
    const LSR: usize = 5;
    const LSR_THRE: u8 = 0x20;

    pub(super) fn set_base(virt: usize) {
        BASE.store(virt, Ordering::Relaxed);
    }

    /// Leaves the line settings alone: firmware or the emulator configured
    /// the baud rate for the board's clock, which this kernel does not know.
    pub(super) unsafe fn init() {}

    const TX_SPIN_LIMIT: u32 = 100_000;

    pub(super) fn put(byte: u8) -> bool {
        let base = BASE.load(Ordering::Relaxed);
        if base == 0 {
            #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
            return sbi_put(byte);
            // On a classic PowerPC booted by Open Firmware the console is
            // firmware's stdout.
            #[cfg(target_arch = "powerpc")]
            return !crate::arch::ppc::of::present() || crate::arch::ppc::of::write(&[byte]);
            #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "powerpc")))]
            return true;
        }
        for _ in 0..TX_SPIN_LIMIT {
            // SAFETY: `base` is the UART the device tree named (on e500 the
            // cache-inhibited, guarded mapping `kmain` created); these are its
            // byte registers.
            if unsafe { core::ptr::read_volatile((base + LSR) as *const u8) } & LSR_THRE != 0 {
                // SAFETY: as above.
                unsafe { core::ptr::write_volatile((base + THR) as *mut u8, byte) };
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    const RBR: usize = 0;
    const LSR_DR: u8 = 0x01;

    /// A received byte: from the UART when there is one (LSR.DR), else from
    /// firmware — the SBI on RISC-V, Open Firmware's stdin on a G3/G4.
    pub(super) fn get() -> Option<u8> {
        let base = BASE.load(Ordering::Relaxed);
        if base != 0 {
            // SAFETY: the UART the device tree named; RBR read pops a byte.
            unsafe {
                if core::ptr::read_volatile((base + LSR) as *const u8) & LSR_DR == 0 {
                    return None;
                }
                return Some(core::ptr::read_volatile((base + RBR) as *const u8));
            }
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        {
            sbi_get()
        }
        #[cfg(target_arch = "powerpc")]
        {
            crate::arch::ppc::of::read_byte()
        }
    }

    /// The SBI console's input: DBCN read (v2.0), else the legacy getchar.
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn sbi_get() -> Option<u8> {
        use crate::arch::riscv::{sbi, sbi_call, sbi_has};
        let mut byte = [0u8; 1];
        // SAFETY: satp is Bare, so the buffer address is physical.
        unsafe {
            if sbi_has(sbi::EXT_DBCN) {
                let (error, count) = sbi_call(sbi::EXT_DBCN, sbi::DBCN_READ, 1, byte.as_mut_ptr() as usize, 0);
                return (error == 0 && count == 1).then_some(byte[0]);
            }
            let (value, _) = sbi_call(sbi::EXT_LEGACY_GETCHAR, 0, 0, 0, 0);
            (value >= 0).then_some(value as u8)
        }
    }

    /// The SBI console: the Debug Console extension where the SBI has it
    /// (v2.0), the legacy putchar otherwise. A trap into firmware per call,
    /// so it is the fallback, not the default.
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn sbi_put(byte: u8) -> bool {
        use crate::arch::riscv::{sbi, sbi_call, sbi_has};
        use core::sync::atomic::AtomicU8;
        // 0 = not asked yet, 1 = DBCN, 2 = legacy.
        static MODE: AtomicU8 = AtomicU8::new(0);
        let mut mode = MODE.load(Ordering::Relaxed);
        if mode == 0 {
            mode = if sbi_has(sbi::EXT_DBCN) { 1 } else { 2 };
            MODE.store(mode, Ordering::Relaxed);
        }
        let buf = [byte];
        // SAFETY: S-mode with `satp` Bare, so the buffer's address is its
        // physical address, which is what DBCN takes.
        let (error, _) = unsafe {
            if mode == 1 {
                sbi_call(sbi::EXT_DBCN, sbi::DBCN_WRITE, 1, buf.as_ptr() as usize, 0)
            } else {
                sbi_call(sbi::EXT_LEGACY_PUTCHAR, 0, byte as usize, 0, 0)
            }
        };
        error == 0
    }
}

/// Where the 16550 is, once `kmain` has found (and on e500 mapped) it.
#[cfg(any(target_arch = "powerpc", target_arch = "riscv32", target_arch = "riscv64"))]
pub fn set_uart_base(virt: usize) {
    ns16550::set_base(virt);
}
