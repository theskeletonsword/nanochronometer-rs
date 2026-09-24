//! The Intel GPIO controller, read as a readiness signal rather than driven
//! as an interrupt source.
//!
//! # Why a GPIO driver is here at all
//!
//! An I2C-HID device has no way to say "I have data" over I2C. I2C has no
//! interrupt line and no way for a slave to start a transfer, so the
//! specification gives the device a *separate* wire — a GPIO pin — which it
//! pulls to announce that a report is waiting. `_CRS` declares which pin, in
//! a `GpioInt` descriptor next to the `I2cSerialBus` one.
//!
//! Every other kernel wires that pin to an interrupt controller and sleeps
//! until it fires. This one has no interrupt controller and no scheduler, on
//! purpose: the whole measurement story depends on nothing preempting the
//! counter read. So the pin is *polled* instead — read as a level, once per
//! frame, and the far more expensive I2C transaction is only started when it
//! says there is something to fetch.
//!
//! That inverts the usual cost. Blind polling of an I2C-HID touchpad means a
//! ~30-byte transfer at 400 kHz every time, whether or not the finger moved:
//! roughly 700 µs of bus time per poll, most of it spent learning that
//! nothing happened. Reading one 32-bit MMIO register instead costs a few
//! hundred nanoseconds, and answers the same question. At 250 Hz that is the
//! difference between a fifth of the frame budget and none of it.
//!
//! # What was taken, and what is new
//!
//! The register layout — `PADBAR` at 0x00C, sixteen bytes per pad,
//! `PADCFG0`'s mode and direction bits — and the pin-to-pad arithmetic are
//! FreeBSD's `sys/dev/gpio/intel/`, which is BSD-2-Clause and may be
//! reproduced; see `NOTICE`. Its Alder Lake and Tiger Lake H pad-group tables
//! are ported here too, and the Alder Lake one is what makes this work on the
//! machine it was developed against.
//!
//! What is not from either kernel is [`Calibration`]. FreeBSD and Linux both
//! resolve an ACPI pin number through a per-SoC table of pad groups,
//! hand-written and hand-maintained; on a part nobody has added yet, both
//! simply fail. That is the right trade for a general-purpose kernel and the
//! wrong *only* answer for a diagnostic that has to run on machines it has
//! never seen. So there is a second route that needs no table: sample every
//! plausible pad before each poll, label the sample with what the poll then
//! found, and keep the pad whose level always agrees with the outcome. It
//! costs nothing extra — the polls were happening anyway — and it measures
//! the line's polarity rather than believing what `_CRS` claims about it.
//!
//! # What this deliberately does not do
//!
//! It never *writes* a pad. Reconfiguring a pin the firmware set up is how a
//! kernel turns a working touchpad into a dead one, and there is nothing to
//! gain: the firmware has already put the line in the state the device needs.
//! Every register access here is a read.

use nanochrono_core::aml::{MemoryRegion, Namespace, Path};

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

/// Offset, within a community's window, of the pointer to its pad registers.
///
/// The pads do not start at a fixed place: the community header grew across
/// generations, so the hardware states where they begin instead. Reading this
/// is what makes the rest of the driver independent of that.
const PADBAR: usize = 0x00C;

/// Bytes per pad. Four 32-bit registers, of which only the first is read here.
const PAD_STRIDE: usize = 16;

/// `PADCFG0` bit 1: the level currently on the pin.
///
/// This is the whole reason the driver exists — the one bit that says whether
/// the device is asserting its interrupt line.
const PADCFG0_RXSTATE: u32 = 1 << 1;

/// `PADCFG0` bit 8: transmit disabled. Set on an input.
const PADCFG0_TXDIS: u32 = 1 << 8;

/// `PADCFG0` bit 9: receive disabled. Clear on an input.
const PADCFG0_RXDIS: u32 = 1 << 9;

/// `PADCFG0` bits 12:10: the pad mode. Zero is GPIO; anything else is a
/// native function — a UART, a PCIe clock request — and not ours to read.
const PADCFG0_PMODE: u32 = 0x7 << 10;

/// A pad whose window reads as all-ones is not there. Firmware leaves
/// unimplemented pads decoding to this, and a community window is often
/// larger than the pads it actually holds.
const PAD_ABSENT: u32 = u32::MAX;

/// Communities a controller may declare. Alder Lake uses four, Tiger Lake H
/// five; eight leaves room without making the structure large.
const MAX_COMMUNITIES: usize = 8;

/// Pads considered during a table-free calibration.
///
/// A whole controller has three hundred or so. Only the ones that already
/// look like a host-owned GPIO input are worth watching, and on a laptop
/// there are a couple of dozen of those.
const MAX_CANDIDATES: usize = 32;

// ---------------------------------------------------------------------------
// The pad-group tables, ported from FreeBSD
// ---------------------------------------------------------------------------

/// Where a run of pads sits in both numbering schemes at once.
///
/// A controller has two: pads are numbered linearly across the whole part,
/// while ACPI numbers them in groups on a 32-pin stride, so a group with
/// twenty-six pads is followed by six numbers that address nothing. Every
/// pin-to-pad conversion is a walk from one scheme to the other.
#[derive(Clone, Copy)]
struct PadGroup {
    /// Index of this group's first pad in the controller-wide linear order.
    first_pad: u16,
    /// How many pads the group has.
    pads: u16,
    /// The ACPI pin number of this group's first pad, or [`NOMAP`] when the
    /// group is not reachable from ACPI at all.
    gpio_base: i32,
}

/// A group ACPI cannot address. Present in the tables because it still
/// occupies linear pad indices, which the arithmetic has to step over.
const NOMAP: i32 = -1;

/// One community: the groups inside it, in the order its pads are laid out.
#[derive(Clone, Copy)]
struct CommunityLayout {
    groups: &'static [PadGroup],
}

/// A part this driver has an exact map for, keyed by the ACPI identifiers its
/// GPIO controller declares.
struct Platform {
    hids: &'static [&'static str],
    communities: &'static [CommunityLayout],
    name: &'static str,
}

/// Alder Lake N, and the Raptor Lake parts that share its pad map.
///
/// `INTC1085` is the identifier on the machine this was written against.
const ADL_COM0: &[PadGroup] = &[
    PadGroup { first_pad: 0, pads: 26, gpio_base: 0 },
    PadGroup { first_pad: 26, pads: 16, gpio_base: 32 },
    PadGroup { first_pad: 42, pads: 25, gpio_base: 64 },
];
const ADL_COM1: &[PadGroup] = &[
    PadGroup { first_pad: 67, pads: 8, gpio_base: 96 },
    PadGroup { first_pad: 75, pads: 20, gpio_base: 128 },
    PadGroup { first_pad: 95, pads: 24, gpio_base: 160 },
    PadGroup { first_pad: 119, pads: 21, gpio_base: 192 },
    PadGroup { first_pad: 140, pads: 29, gpio_base: 224 },
];
const ADL_COM4: &[PadGroup] = &[
    PadGroup { first_pad: 169, pads: 24, gpio_base: 256 },
    PadGroup { first_pad: 193, pads: 25, gpio_base: 288 },
    PadGroup { first_pad: 218, pads: 6, gpio_base: NOMAP },
    PadGroup { first_pad: 224, pads: 25, gpio_base: 320 },
];
const ADL_COM5: &[PadGroup] = &[PadGroup { first_pad: 249, pads: 8, gpio_base: 352 }];

/// Tiger Lake H.
const TGLH_COM0: &[PadGroup] = &[
    PadGroup { first_pad: 0, pads: 25, gpio_base: 0 },
    PadGroup { first_pad: 25, pads: 20, gpio_base: 32 },
    PadGroup { first_pad: 45, pads: 26, gpio_base: 64 },
    PadGroup { first_pad: 71, pads: 8, gpio_base: 96 },
];
const TGLH_COM1: &[PadGroup] = &[
    PadGroup { first_pad: 79, pads: 26, gpio_base: 128 },
    PadGroup { first_pad: 105, pads: 24, gpio_base: 160 },
    PadGroup { first_pad: 129, pads: 8, gpio_base: 192 },
    PadGroup { first_pad: 137, pads: 17, gpio_base: 224 },
    PadGroup { first_pad: 154, pads: 27, gpio_base: 256 },
];
const TGLH_COM3: &[PadGroup] = &[
    PadGroup { first_pad: 181, pads: 13, gpio_base: 288 },
    PadGroup { first_pad: 194, pads: 24, gpio_base: 320 },
];
const TGLH_COM4: &[PadGroup] = &[
    PadGroup { first_pad: 218, pads: 24, gpio_base: 352 },
    PadGroup { first_pad: 242, pads: 10, gpio_base: 384 },
    PadGroup { first_pad: 252, pads: 15, gpio_base: 416 },
];
const TGLH_COM5: &[PadGroup] = &[
    PadGroup { first_pad: 267, pads: 15, gpio_base: 448 },
    PadGroup { first_pad: 282, pads: 9, gpio_base: NOMAP },
];

/// The parts with an exact map, tried in order.
const PLATFORMS: &[Platform] = &[
    Platform {
        hids: &["INTC1056", "INTC1057", "INTC1085"],
        communities: &[
            CommunityLayout { groups: ADL_COM0 },
            CommunityLayout { groups: ADL_COM1 },
            CommunityLayout { groups: ADL_COM4 },
            CommunityLayout { groups: ADL_COM5 },
        ],
        name: "alder lake",
    },
    Platform {
        hids: &["INT34C6"],
        communities: &[
            CommunityLayout { groups: TGLH_COM0 },
            CommunityLayout { groups: TGLH_COM1 },
            CommunityLayout { groups: TGLH_COM3 },
            CommunityLayout { groups: TGLH_COM4 },
            CommunityLayout { groups: TGLH_COM5 },
        ],
        name: "tiger lake h",
    },
];

// ---------------------------------------------------------------------------
// The controller
// ---------------------------------------------------------------------------

/// One community's window, as found.
#[derive(Clone, Copy)]
struct Community {
    base: usize,
    /// Offset of the first pad register, read from `PADBAR`.
    pads_at: usize,
    /// How many pads fit in the window. An upper bound, not a count: the
    /// window is usually rounded up past the last real pad.
    capacity: u32,
}

/// A resolved pad: which community, and where in it.
///
/// Packed into one word rather than kept as two fields, because a
/// calibration holds an array of these and the array is the bulk of it. The
/// community index goes in the top four bits — [`MAX_COMMUNITIES`] is eight,
/// so four is generous — and the byte offset in the rest, which leaves room
/// for a 256 MiB window against real ones of a few kilobytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pad(u32);

/// Bits of a [`Pad`] given to the offset.
const PAD_OFFSET_BITS: u32 = 28;

impl Pad {
    fn new(community: usize, offset: usize) -> Option<Pad> {
        if community >= MAX_COMMUNITIES || offset >= 1 << PAD_OFFSET_BITS {
            return None;
        }
        Some(Pad(((community as u32) << PAD_OFFSET_BITS) | offset as u32))
    }

    fn community(self) -> usize {
        (self.0 >> PAD_OFFSET_BITS) as usize
    }

    fn offset(self) -> usize {
        (self.0 & ((1 << PAD_OFFSET_BITS) - 1)) as usize
    }
}

/// How a pad was arrived at. Reported, because it is the difference between
/// "this is definitely the right pin" and "this is the pin that moved".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mapping {
    /// Converted through a pad-group table for a recognised part.
    Tabled(&'static str),
    /// Found by watching which pad responded to the device being reset.
    Calibrated,
}

/// An Intel GPIO controller, opened read-only.
pub struct Controller {
    communities: [Community; MAX_COMMUNITIES],
    count: usize,
    platform: Option<&'static Platform>,
}

impl Controller {
    /// Opens the controller a `GpioInt` descriptor named.
    ///
    /// `hid` is the controller's own `_HID`, used only to select a pad-group
    /// table; a controller with no table still opens, and its pads can still
    /// be calibrated for.
    ///
    /// Returns `None` when the namespace has no such device, when it declares
    /// no memory windows, or when none of them respond — all of which mean
    /// the same thing to a caller: fall back to polling the bus blind.
    ///
    /// # Safety
    ///
    /// The windows come from firmware's `_CRS` and are mapped by identity, so
    /// this must run with paging set up the way the rest of the kernel
    /// expects. Nothing here writes.
    pub unsafe fn open(namespace: &Namespace, controller: &Path, hid: Option<&str>) -> Option<Self> {
        let mut regions = [MemoryRegion { base: 0, length: 0, writable: false }; MAX_COMMUNITIES];
        let found = namespace.gpio_communities(controller, &mut regions);
        if found == 0 {
            return None;
        }

        let mut communities = [Community { base: 0, pads_at: 0, capacity: 0 }; MAX_COMMUNITIES];
        let mut count = 0usize;
        for region in regions.iter().take(found) {
            // Above what a pointer reaches (i386): not a window this can read.
            let Ok(base) = usize::try_from(region.base) else {
                continue;
            };
            // `PADBAR` is the first thing read, and it doubles as a presence
            // check: a window that is not decoded reads back all-ones, and a
            // pad pointer past the end of the window is nonsense either way.
            let padbar = unsafe { read32(base + PADBAR) } as usize;
            if padbar == 0 || padbar >= region.length as usize {
                continue;
            }
            communities[count] = Community {
                base,
                pads_at: padbar,
                capacity: ((region.length as usize - padbar) / PAD_STRIDE) as u32,
            };
            count += 1;
        }
        if count == 0 {
            return None;
        }

        let platform = hid.and_then(|hid| {
            PLATFORMS
                .iter()
                .find(|platform| platform.hids.iter().any(|known| known.eq_ignore_ascii_case(hid)))
        });

        Some(Controller { communities, count, platform })
    }

    /// The part this was recognised as, if any.
    pub fn platform(&self) -> Option<&'static str> {
        self.platform.map(|platform| platform.name)
    }

    /// How many communities responded.
    pub fn communities(&self) -> usize {
        self.count
    }

    /// Converts an ACPI pin number to a pad, through the pad-group table.
    ///
    /// This is FreeBSD's `intelgpio_gpio_to_pad`, in Rust: walk the groups
    /// until one contains the pin, convert to the controller-wide linear pad
    /// index, then subtract the community's own first pad to get a local one.
    ///
    /// Returns `None` when there is no table for this part, when the pin
    /// belongs to no group, or when the table and the firmware's windows
    /// disagree about how many pads a community has — the last of which means
    /// the table is wrong for this variant and should not be trusted.
    pub fn resolve(&self, pin: u16) -> Option<Pad> {
        let platform = self.platform?;
        let pin = pin as i32;

        for (index, layout) in platform.communities.iter().enumerate() {
            let community = self.communities.get(index).filter(|_| index < self.count)?;
            let first_pad = layout.groups.first()?.first_pad;

            for group in layout.groups {
                if group.gpio_base == NOMAP {
                    continue;
                }
                if pin < group.gpio_base || pin >= group.gpio_base + group.pads as i32 {
                    continue;
                }
                let within = (pin - group.gpio_base) as u16;
                let local = (group.first_pad + within).checked_sub(first_pad)?;
                if local as u32 >= community.capacity {
                    return None;
                }
                return Pad::new(index, community.pads_at + local as usize * PAD_STRIDE);
            }
        }
        None
    }

    /// Reads a pad's `PADCFG0`.
    fn config(&self, pad: Pad) -> u32 {
        let community = &self.communities[pad.community()];
        unsafe { read32(community.base + pad.offset()) }
    }

    /// Whether the pin is currently being driven.
    ///
    /// The sense is deliberately not interpreted here. An interrupt line is
    /// usually active-low, so "asserted" is normally a *zero* in this bit —
    /// but `_CRS` states the polarity and the caller has it, so this reports
    /// the level and lets the caller apply the meaning.
    pub fn level(&self, pad: Pad) -> bool {
        self.config(pad) & PADCFG0_RXSTATE != 0
    }

    /// Whether a pad looks like a host-owned GPIO input.
    ///
    /// Three things have to hold at once: the pad is in GPIO mode rather than
    /// serving a native function, its receiver is on, and its transmitter is
    /// off. That is what firmware leaves behind when it hands a device's
    /// interrupt line to the OS, and it rules out the great majority of pads
    /// on any real part.
    fn is_input(&self, pad: Pad) -> bool {
        let config = self.config(pad);
        config != PAD_ABSENT
            && config & PADCFG0_PMODE == 0
            && config & PADCFG0_RXDIS == 0
            && config & PADCFG0_TXDIS != 0
    }

    /// Confirms that a resolved pad really is an input.
    ///
    /// A pad-group table can be right about the arithmetic and still wrong
    /// about the part — vendors ship variants — so the answer is checked
    /// against the hardware before it is used. A pin ACPI declared as an
    /// interrupt source that does not read back as an input means the table
    /// does not apply here.
    pub fn verify(&self, pad: Pad) -> bool {
        self.is_input(pad)
    }
}

// ---------------------------------------------------------------------------
// Calibration by correlation
// ---------------------------------------------------------------------------

/// Learns which pad is a device's interrupt line by watching it work.
///
/// This is the part neither FreeBSD nor Linux has. Both convert an ACPI pin
/// number through a per-SoC table of pad groups, written by hand for each
/// part; on a part nobody has added, both give up. A table is the right
/// answer for a general-purpose kernel, and [`Controller::resolve`] ports
/// FreeBSD's. It is the wrong *only* answer for a diagnostic that has to run
/// on machines it has never seen.
///
/// So there is a second route, which needs no table and no knowledge of the
/// part at all. The insight is that the driver already knows, after the fact,
/// what the pin was doing: a poll that returns a report proves the line was
/// asserted a moment earlier, and a poll that comes back empty proves it was
/// not. Sampling every candidate pad *before* each poll and then labelling
/// that sample with the poll's outcome turns the question into a correlation:
/// the interrupt line is the pad that is one value whenever a report follows
/// and the other value whenever none does.
///
/// One pad satisfies that. Pads that never move are eliminated by the first
/// disagreement; pads that move for their own reasons — a lid switch, a
/// power rail — are eliminated as soon as they move at the wrong time. The
/// answer is accepted only when exactly one candidate survives, so a tie
/// leaves the driver polling blind rather than gated on the wrong wire.
pub struct Calibration {
    pads: [Pad; MAX_CANDIDATES],
    /// Per candidate: whether it has been seen high, and low, in each class.
    /// Four bits, one per (class, level) pair — enough to detect any
    /// disagreement without counting.
    seen: [u8; MAX_CANDIDATES],
    count: usize,
    /// Samples taken with a report following, and without.
    reports: u32,
    quiet: u32,
}

/// Seen high while a report was waiting.
const SEEN_BUSY_HIGH: u8 = 1 << 0;
/// Seen low while a report was waiting.
const SEEN_BUSY_LOW: u8 = 1 << 1;
/// Seen high while nothing was waiting.
const SEEN_IDLE_HIGH: u8 = 1 << 2;
/// Seen low while nothing was waiting.
const SEEN_IDLE_LOW: u8 = 1 << 3;

/// Samples of each class required before an answer is offered.
///
/// Two of each is enough to eliminate a pad that is simply stuck, but not
/// enough to survive a coincidence; four is cheap — the samples are taken
/// during polls that were happening anyway — and makes an accidental match
/// need four correlated coin flips.
const NEEDED: u32 = 4;

impl Controller {
    /// Collects the pads worth watching: every host-owned GPIO input.
    ///
    /// On a laptop this is a couple of dozen out of three hundred. The bound
    /// is [`MAX_CANDIDATES`]; overflowing it is not an error, the extras are
    /// simply not watched.
    pub fn begin_calibration(&self) -> Calibration {
        let mut calibration = Calibration {
            pads: [Pad(0); MAX_CANDIDATES],
            seen: [0; MAX_CANDIDATES],
            count: 0,
            reports: 0,
            quiet: 0,
        };

        for index in 0..self.count {
            let community = &self.communities[index];
            for local in 0..community.capacity {
                if calibration.count == MAX_CANDIDATES {
                    return calibration;
                }
                let Some(pad) = Pad::new(index, community.pads_at + local as usize * PAD_STRIDE)
                else {
                    continue;
                };
                if self.is_input(pad) {
                    calibration.pads[calibration.count] = pad;
                    calibration.count += 1;
                }
            }
        }
        calibration
    }
}

/// One set of pad levels, taken before a poll and labelled after it.
///
/// Separate from the [`Calibration`] because of the ordering it enforces: the
/// levels have to be read *before* the I2C transfer, since reading the input
/// register is what makes the device drop its line, and the outcome is only
/// known afterwards. Handing back a value that must be given a verdict makes
/// that order hard to get wrong.
pub struct Sample {
    levels: u32,
    count: usize,
}

impl Calibration {
    /// How many pads are being watched.
    pub fn watching(&self) -> usize {
        self.count
    }

    /// How many labelled samples have been taken, of each class.
    pub fn progress(&self) -> (u32, u32) {
        (self.reports, self.quiet)
    }

    /// Reads every candidate's level. Call immediately before a poll.
    pub fn sample(&self, controller: &Controller) -> Sample {
        let mut levels = 0u32;
        for (index, pad) in self.pads.iter().take(self.count).enumerate() {
            if controller.level(*pad) {
                levels |= 1 << index;
            }
        }
        Sample { levels, count: self.count }
    }

    /// Files a sample under what the poll that followed it found.
    ///
    /// `had_report` is the whole label: true if the device produced a report,
    /// false if it answered with a zero length.
    pub fn observe(&mut self, sample: Sample, had_report: bool) {
        if sample.count != self.count {
            return;
        }
        if had_report {
            self.reports = self.reports.saturating_add(1);
        } else {
            self.quiet = self.quiet.saturating_add(1);
        }
        for index in 0..self.count {
            let high = sample.levels & (1 << index) != 0;
            self.seen[index] |= match (had_report, high) {
                (true, true) => SEEN_BUSY_HIGH,
                (true, false) => SEEN_BUSY_LOW,
                (false, true) => SEEN_IDLE_HIGH,
                (false, false) => SEEN_IDLE_LOW,
            };
        }
    }

    /// The pad that correlates, once there is enough evidence for one.
    ///
    /// Returns the pad and the level that means "a report is waiting", so the
    /// caller does not have to know the line's polarity — it was measured
    /// rather than assumed, which is better than reading it out of `_CRS`,
    /// because firmware has been known to describe it wrongly.
    ///
    /// `None` until [`NEEDED`] samples of each class have been seen, and
    /// `None` for good if more than one pad survives.
    pub fn settled(&self) -> Option<(Pad, bool)> {
        if self.reports < NEEDED || self.quiet < NEEDED {
            return None;
        }
        let mut answer = None;
        for index in 0..self.count {
            // A survivor took one value under every report and the other
            // under every quiet poll: exactly one of the two busy bits set,
            // exactly one of the two idle bits, and the two disagreeing.
            let asserted_high = self.seen[index] == (SEEN_BUSY_HIGH | SEEN_IDLE_LOW);
            let asserted_low = self.seen[index] == (SEEN_BUSY_LOW | SEEN_IDLE_HIGH);
            if !asserted_high && !asserted_low {
                continue;
            }
            if answer.is_some() {
                return None;
            }
            answer = Some((self.pads[index], asserted_high));
        }
        answer
    }
}

/// Reads a 32-bit register.
///
/// # Safety
///
/// `address` must be inside a window firmware declared, mapped and readable.
unsafe fn read32(address: usize) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}
