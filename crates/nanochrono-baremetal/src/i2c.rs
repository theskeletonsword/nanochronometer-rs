// SPDX-License-Identifier: Apache-2.0
//! The Synopsys DesignWare I2C master, as Intel ships it in the LPSS block.
//!
//! # What this is for
//!
//! One device: the touchpad. A notebook's built-in pointer is usually an
//! I2C-HID device hanging off one of the chipset's I2C controllers, and
//! neither PCI enumeration nor the USB stack can see it. The controller
//! itself *is* a PCI device — `8086:7a7d` on the machine this was written
//! against — but what is behind it is not enumerable at all: an I2C bus has
//! no discovery, so the only way to find the touchpad is to read the address
//! out of the firmware's ACPI tables and then talk to it.
//!
//! # No interrupts, which changes the shape of the driver
//!
//! Every other driver for this part is interrupt-driven: arm the FIFO
//! thresholds, take an interrupt when the transmit FIFO drains or the receive
//! FIFO fills, and run a state machine. This kernel has no IDT, so the whole
//! transfer is one polled loop that pushes commands while the transmit FIFO
//! has room and drains bytes while the receive FIFO has any.
//!
//! Interleaving those two is not an optimisation. The receive FIFO is
//! sixteen entries; a report descriptor is several hundred bytes, and a loop
//! that queued every read command before draining anything would overflow it
//! and lose the middle of the descriptor.
//!
//! # Reference
//!
//! Register layout, bit names and the reset sequence follow FreeBSD's
//! `sys/dev/ichiic/ig4_reg.h` and `ig4_iic.c`, which is the same hardware.
//! The constants below keep that file's names so the two can be read side by
//! side. No code was copied: that driver is interrupt-driven, has a bus
//! layer under it and handles four generations of the part.

use crate::pci::Device;

// --- DesignWare core registers ---------------------------------------------

const REG_CTL: usize = 0x0000;
const REG_TAR_ADD: usize = 0x0004;
const REG_DATA_CMD: usize = 0x0010;
const REG_SS_SCL_HCNT: usize = 0x0014;
const REG_SS_SCL_LCNT: usize = 0x0018;
const REG_FS_SCL_HCNT: usize = 0x001C;
const REG_FS_SCL_LCNT: usize = 0x0020;
const REG_INTR_MASK: usize = 0x0030;
const REG_RAW_INTR_STAT: usize = 0x0034;
const REG_RX_TL: usize = 0x0038;
const REG_TX_TL: usize = 0x003C;
const REG_CLR_INTR: usize = 0x0040;
const REG_CLR_TX_ABORT: usize = 0x0054;
const REG_I2C_EN: usize = 0x006C;
const REG_I2C_STA: usize = 0x0070;
const REG_TXFLR: usize = 0x0074;
const REG_RXFLR: usize = 0x0078;
const REG_SDA_HOLD: usize = 0x007C;
const REG_TX_ABRT_SOURCE: usize = 0x0080;
const REG_ENABLE_STATUS: usize = 0x009C;
/// Fixed signature, `0x44570140`, readable only once the core is out of
/// reset. Polling it is how this waits exactly as long as necessary rather
/// than for a guessed interval.
const REG_COMP_TYPE: usize = 0x00FC;

// --- LPSS wrapper registers, which sit above the core ----------------------

/// Reset control for the Skylake-and-later LPSS wrapper.
const REG_RESETS: usize = 0x0204;
const RESETS_ASSERT: u32 = 0x0000;
const RESETS_DEASSERT: u32 = 0x0003;
/// Power/idle handshake. A controller the firmware left idle answers reads
/// with zeroes until this is cleared.
const REG_DEVIDLE_CTRL: usize = 0x024C;
const DEVIDLE: u32 = 0x0004;
const RESTORE_REQUIRED: u32 = 0x0008;

const COMP_TYPE_SIGNATURE: u32 = 0x4457_0140;

// --- Control bits ----------------------------------------------------------

const CTL_MASTER: u32 = 0x0001;
const CTL_SPEED_STD: u32 = 0x0002;
const CTL_SPEED_FAST: u32 = 0x0004;
const CTL_SPEED_MASK: u32 = 0x0006;
const CTL_RESTARTEN: u32 = 0x0020;
const CTL_SLAVE_DISABLE: u32 = 0x0040;

const DATA_RESTART: u32 = 0x0400;
const DATA_STOP: u32 = 0x0200;
const DATA_COMMAND_RD: u32 = 0x0100;

const INTR_TX_ABRT: u32 = 0x0040;

const I2C_ENABLE: u32 = 0x0001;

const STATUS_RX_NOTEMPTY: u32 = 0x0008;
const STATUS_TX_EMPTY: u32 = 0x0004;
const STATUS_TX_NOTFULL: u32 = 0x0002;
const STATUS_ACTIVITY: u32 = 0x0020;

/// The transmit FIFO's depth on this part. Read back rather than assumed
/// where the register cooperates; this is the floor every generation has.
const FIFO_DEPTH: u32 = 16;

/// How long to wait on a register bit, in microseconds.
///
/// **Real time, not spin iterations.** An iteration count is not a timeout:
/// an MMIO read on this part costs somewhere between a hundred nanoseconds
/// and a microsecond depending on the link, so a two-million-iteration
/// "bound" is somewhere between 0.2 and 2 seconds — and there are several of
/// them in one transfer. That is invisible under an emulator, where the reads
/// are function calls, and on real hardware it is an interface that stops
/// responding.
///
/// Five milliseconds is far longer than any single FIFO wait at 400 kHz,
/// where a byte takes 22.5 microseconds.
const WAIT_US: u64 = 5_000;

/// The same, for bring-up: a controller leaving reset is allowed longer than
/// a byte is, and it happens once.
const RESET_US: u64 = 50_000;

/// The bus clock this drives the device at.
///
/// Fast mode. Every I2C-HID touchpad declares 400 kHz in its `_CRS`, and the
/// speed the descriptor asks for is used when it is one of the two the part
/// implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Standard,
    Fast,
}

impl Speed {
    /// Picks the mode for the rate a `_CRS` asked for.
    pub fn for_hz(hz: u32) -> Speed {
        if hz > 100_000 {
            Speed::Fast
        } else {
            Speed::Standard
        }
    }

    const fn control_bits(self) -> u32 {
        match self {
            Speed::Standard => CTL_SPEED_STD,
            Speed::Fast => CTL_SPEED_FAST,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Speed::Standard => "100 kHz",
            Speed::Fast => "400 kHz",
        }
    }
}

/// Clock counts, in units of the controller's input clock.
#[derive(Debug, Clone, Copy)]
struct Timing {
    high: u32,
    low: u32,
    sda_hold: u32,
}

/// The controller's input clock, in megahertz.
///
/// 133 MHz on every LPSS generation from Apollo Lake onward, which is
/// everything this is likely to meet. Where firmware has already programmed
/// the count registers those are preferred — see [`I2cMaster::timing`] — so
/// this is the fallback, not the first answer.
const INPUT_CLOCK_MHZ: u32 = 133;

/// Bus timing from the I2C specification, in nanoseconds.
const STD_HIGH_NS: u32 = 4000;
const STD_LOW_NS: u32 = 4700;
const FAST_HIGH_NS: u32 = 600;
const FAST_LOW_NS: u32 = 1300;
/// Worst-case fall time, used when the platform states none.
const FALL_NS: u32 = 300;
/// Data hold time. The LPSS value for this generation.
const SDA_HOLD_NS: u32 = 42;

/// Computes counts the way the DesignWare databook does.
fn computed_timing(speed: Speed) -> Timing {
    let (high, low) = match speed {
        Speed::Standard => (STD_HIGH_NS, STD_LOW_NS),
        Speed::Fast => (FAST_HIGH_NS, FAST_LOW_NS),
    };
    Timing {
        // The `- 3` and `- 1` are the core's own pipeline delays, which the
        // databook specifies and which are not derivable from the bus timing.
        high: (INPUT_CLOCK_MHZ * (high + FALL_NS) + 500) / 1000 - 3,
        low: (INPUT_CLOCK_MHZ * (low + FALL_NS) + 500) / 1000 - 1,
        sda_hold: (INPUT_CLOCK_MHZ * SDA_HOLD_NS + 500) / 1000,
    }
}

/// A brought-up I2C master.
/// A deadline in counter ticks.
///
/// The counter is the only clock this kernel has, and it is the same one the
/// chronometer reads — so a timeout here is denominated in the same units as
/// everything else the machine reports.
#[derive(Debug, Clone, Copy)]
struct Deadline {
    end: u64,
}

impl Deadline {
    fn in_us(ticks_per_us: u64, microseconds: u64) -> Deadline {
        Deadline {
            end: crate::arch::counter_ordered().wrapping_add(ticks_per_us.max(1) * microseconds),
        }
    }

    /// Whether there is still time. Compares by wrapped difference so a
    /// counter that rolls over does not make every deadline expire at once.
    fn live(&self) -> bool {
        (self.end.wrapping_sub(crate::arch::counter_ordered()) as i64) > 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct I2cMaster {
    base: usize,
    speed: Speed,
    /// Counter ticks in a microsecond, so waits are bounded in time rather
    /// than in loop iterations.
    ticks_per_us: u64,
    /// The address the controller is currently pointed at, so a run of
    /// transfers to one device does not disable and re-enable the core
    /// between each. Changing it requires the controller to be disabled.
    target: u16,
}

impl I2cMaster {
    /// Brings up the controller behind `device`.
    ///
    /// # Safety
    /// Touches MMIO and PCI configuration space; requires ring 0 and an
    /// identity map covering the BAR. The BAR on this part is 64-bit and
    /// routinely above four gigabytes, which is why the map has to be as
    /// large as it is.
    pub unsafe fn new(device: &Device, speed: Speed, ticks_per_us: u64) -> Option<I2cMaster> {
        let base = device.bar0_addr()?;
        // Memory decoding only: this driver moves bytes through the FIFOs by
        // programmed I/O, so the controller never needs to master the bus.
        // SAFETY: forwarded from this function's own contract.
        unsafe { device.enable_mmio() };

        let mut master = I2cMaster {
            base,
            speed,
            ticks_per_us: ticks_per_us.max(1),
            target: u16::MAX,
        };

        // SAFETY: as above.
        unsafe {
            // What firmware programmed, before anything resets it away.
            let firmware = master.firmware_timing(speed);
            master.wake()?;
            master.reset()?;
            master.configure(firmware)?;
        }
        Some(master)
    }

    /// Reads back the counts firmware left, if they look like counts.
    ///
    /// Preferred over the computed values: the BIOS was written for this
    /// board and knows its trace lengths and pull-ups, where the computation
    /// assumes the specification's worst-case fall time. A count of zero or
    /// one is not a timing, it is a register that was never programmed.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn firmware_timing(&self, speed: Speed) -> Timing {
        let (high_reg, low_reg) = match speed {
            Speed::Standard => (REG_SS_SCL_HCNT, REG_SS_SCL_LCNT),
            Speed::Fast => (REG_FS_SCL_HCNT, REG_FS_SCL_LCNT),
        };
        // SAFETY: forwarded from this function's own contract.
        let (high, low, hold) = unsafe {
            (
                self.read(high_reg),
                self.read(low_reg),
                self.read(REG_SDA_HOLD),
            )
        };
        // The databook's minimum is 6; anything below that would be a bus
        // running far faster than the device agreed to.
        if high >= 6 && low >= 8 && high < 0xFFFF && low < 0xFFFF {
            Timing {
                high,
                low,
                sda_hold: hold,
            }
        } else {
            computed_timing(speed)
        }
    }

    /// Lifts the LPSS idle/power handshake.
    ///
    /// A controller firmware left idle answers every register read with zero,
    /// which looks exactly like a controller that is not there.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn wake(&self) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let state = self.read(REG_DEVIDLE_CTRL);
            if state & RESTORE_REQUIRED != 0 || state & DEVIDLE != 0 {
                self.write(REG_DEVIDLE_CTRL, DEVIDLE | RESTORE_REQUIRED);
                self.write(REG_DEVIDLE_CTRL, 0);
                self.pause(100);
            }
        }
        Some(())
    }

    /// Waits `microseconds`, by the counter.
    fn pause(&self, microseconds: u64) {
        let deadline = Deadline::in_us(self.ticks_per_us, microseconds);
        while deadline.live() {
            core::hint::spin_loop();
        }
    }

    /// Resets the core and waits for it to come back.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn reset(&self) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.write(REG_RESETS, RESETS_ASSERT);
            self.write(REG_RESETS, RESETS_DEASSERT);

            // The core's registers read back as zero until it leaves reset.
            // Polling its fixed signature means proceeding exactly when it is
            // ready rather than after a guessed delay.
            let deadline = Deadline::in_us(self.ticks_per_us, RESET_US);
            while deadline.live() {
                if self.read(REG_COMP_TYPE) == COMP_TYPE_SIGNATURE {
                    return Some(());
                }
                core::hint::spin_loop();
            }
        }
        None
    }

    /// Programs the clock counts and the control register.
    ///
    /// # Safety
    /// MMIO; requires ring 0 and the controller disabled.
    unsafe fn configure(&mut self, timing: Timing) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.disable()?;

            // Interrupts off: there is no handler, and one that fired would
            // be a triple fault.
            self.write(REG_INTR_MASK, 0);
            let _ = self.read(REG_CLR_INTR);

            match self.speed {
                Speed::Standard => {
                    self.write(REG_SS_SCL_HCNT, timing.high);
                    self.write(REG_SS_SCL_LCNT, timing.low);
                }
                Speed::Fast => {
                    self.write(REG_FS_SCL_HCNT, timing.high);
                    self.write(REG_FS_SCL_LCNT, timing.low);
                }
            }
            if timing.sda_hold != 0 {
                self.write(REG_SDA_HOLD, timing.sda_hold);
            }

            // Thresholds at zero: every byte is polled for, so there is
            // nothing to be woken at.
            self.write(REG_RX_TL, 0);
            self.write(REG_TX_TL, 0);

            self.write(
                REG_CTL,
                CTL_MASTER
                    | CTL_SLAVE_DISABLE
                    // Restart is what makes a write-then-read one
                    // transaction rather than two. Without it the address
                    // pointer written in the first half is not guaranteed to
                    // survive to the second.
                    | CTL_RESTARTEN
                    | (self.speed.control_bits() & CTL_SPEED_MASK),
            );
        }
        self.target = u16::MAX;
        Some(())
    }

    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn disable(&self) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.write(REG_I2C_EN, 0);
            let deadline = Deadline::in_us(self.ticks_per_us, WAIT_US);
            while deadline.live() {
                if self.read(REG_ENABLE_STATUS) & I2C_ENABLE == 0 {
                    return Some(());
                }
                core::hint::spin_loop();
            }
        }
        None
    }

    /// Points the controller at a slave, disabling it if that has to change.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn aim(&mut self, address: u16) -> Option<()> {
        if self.target == address {
            return Some(());
        }
        // SAFETY: forwarded from this function's own contract. The target
        // address register may only be written with the controller disabled.
        unsafe {
            self.disable()?;
            self.write(REG_TAR_ADD, (address & 0x03FF) as u32);
            self.write(REG_I2C_EN, I2C_ENABLE);
        }
        self.target = address;
        Some(())
    }

    /// Writes `out`, then reads `into`, as one transaction with a restart.
    ///
    /// Either side may be empty: a plain write passes an empty `into`, and a
    /// plain read an empty `out`. The combined form is what every I2C-HID
    /// exchange is — write the register address, restart, read the contents —
    /// and splitting it into two transactions would let another master
    /// interleave, which on a bus with a touchpad and nothing else is
    /// theoretical but free to avoid.
    ///
    /// # Safety
    /// Drives MMIO; requires ring 0.
    pub unsafe fn write_read(&mut self, address: u16, out: &[u8], into: &mut [u8]) -> bool {
        if out.is_empty() && into.is_empty() {
            return true;
        }
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            if self.aim(address).is_none() {
                return false;
            }
            // A previous transfer's abort holds the transmit FIFO in reset
            // until it is read out.
            let _ = self.read(REG_CLR_TX_ABORT);

            // --- the write half
            for (index, &byte) in out.iter().enumerate() {
                let last = index + 1 == out.len();
                // A stop only if nothing is read afterwards; otherwise the
                // restart in the read half carries the transaction on.
                let command = byte as u32
                    | if last && into.is_empty() {
                        DATA_STOP
                    } else {
                        0
                    };
                if !self.push(command) {
                    return false;
                }
            }

            // --- the read half, interleaved
            //
            // One command is written per byte wanted, and the receive FIFO is
            // drained as it fills. Queuing every command first would overflow
            // sixteen entries on any read longer than that — which a report
            // descriptor always is.
            let wanted = into.len();
            let mut queued = 0usize;
            let mut taken = 0usize;
            while taken < wanted {
                while queued < wanted {
                    let outstanding = queued - taken;
                    // Never let more be in flight than the receive FIFO can
                    // hold, or the overflow is silent and the descriptor
                    // comes back with a hole in it.
                    if outstanding as u32 >= FIFO_DEPTH {
                        break;
                    }
                    if self.read(REG_I2C_STA) & STATUS_TX_NOTFULL == 0 {
                        break;
                    }
                    let mut command = DATA_COMMAND_RD;
                    if queued == 0 && !out.is_empty() {
                        command |= DATA_RESTART;
                    }
                    if queued + 1 == wanted {
                        command |= DATA_STOP;
                    }
                    self.write(REG_DATA_CMD, command);
                    queued += 1;
                }

                if self.aborted() {
                    return false;
                }

                let mut progressed = false;
                while taken < queued && self.read(REG_I2C_STA) & STATUS_RX_NOTEMPTY != 0 {
                    into[taken] = (self.read(REG_DATA_CMD) & 0xFF) as u8;
                    taken += 1;
                    progressed = true;
                }
                if progressed {
                    continue;
                }

                // Nothing moved this pass. Wait, bounded, for either.
                if !self.settle() {
                    return false;
                }
            }

            // A write with no read still has to be seen out, or the caller
            // takes the absence of an abort as success before the bus has
            // even carried the bytes.
            if into.is_empty() && !self.drain() {
                return false;
            }
            !self.aborted()
        }
    }

    /// Pushes one byte into the transmit FIFO, waiting for room.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn push(&self, command: u32) -> bool {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let deadline = Deadline::in_us(self.ticks_per_us, WAIT_US);
            while deadline.live() {
                if self.aborted() {
                    return false;
                }
                if self.read(REG_I2C_STA) & STATUS_TX_NOTFULL != 0 {
                    self.write(REG_DATA_CMD, command);
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }

    /// Waits for the transmit FIFO to empty and the bus to go idle.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn drain(&self) -> bool {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let deadline = Deadline::in_us(self.ticks_per_us, WAIT_US);
            while deadline.live() {
                if self.aborted() {
                    return false;
                }
                let status = self.read(REG_I2C_STA);
                if status & STATUS_TX_EMPTY != 0 && status & STATUS_ACTIVITY == 0 {
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }

    /// A bounded pause while a transfer is in flight.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn settle(&self) -> bool {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let deadline = Deadline::in_us(self.ticks_per_us, WAIT_US);
            while deadline.live() {
                if self.aborted() {
                    return false;
                }
                let status = self.read(REG_I2C_STA);
                if status & STATUS_RX_NOTEMPTY != 0 || status & STATUS_TX_NOTFULL != 0 {
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }

    /// Whether the controller gave up on the transfer.
    ///
    /// An abort is how a device that is not there answers: the address goes
    /// out, nothing acknowledges it, and the controller sets this and flushes
    /// the transmit FIFO. Treating it as anything other than failure is how a
    /// driver reports a device it never reached.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn aborted(&self) -> bool {
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.read(REG_RAW_INTR_STAT) & INTR_TX_ABRT != 0 }
    }

    /// Why the last transfer was abandoned, for reporting.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    pub unsafe fn abort_source(&self) -> u32 {
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.read(REG_TX_ABRT_SOURCE) }
    }

    /// How many bytes are waiting in each FIFO, for reporting.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    pub unsafe fn fifo_levels(&self) -> (u32, u32) {
        // SAFETY: forwarded from this function's own contract.
        unsafe { (self.read(REG_TXFLR), self.read(REG_RXFLR)) }
    }

    /// # Safety
    /// `offset` must be inside the controller's register window.
    unsafe fn read(&self, offset: usize) -> u32 {
        // SAFETY: forwarded from this function's own contract; the BAR was
        // checked non-zero and the identity map covers it.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// # Safety
    /// `offset` must be inside the controller's register window.
    unsafe fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
}
