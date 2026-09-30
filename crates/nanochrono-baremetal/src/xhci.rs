// SPDX-License-Identifier: Apache-2.0
//! An xHCI host controller, far enough to read a keyboard.
//!
//! # Scope
//!
//! This brings up the controller, enumerates one device on one port, and
//! polls its interrupt endpoint for HID boot-protocol reports. It is not a
//! USB stack: there is no hub support, no bulk or isochronous transfer, no
//! mass storage, and no more than one device at a time. Those are absent
//! because a keyboard needs none of them, not because they are almost here.
//!
//! Register offsets and the initialisation order follow FreeBSD's
//! `sys/dev/usb/controller/xhcireg.h` and `xhci.c`, so the two can be read
//! side by side. No code was copied; this is a much smaller driver with no
//! interrupts, no scheduling and no dynamic allocation.
//!
//! # No allocator
//!
//! Every structure the controller reads lives in a `static` with the
//! alignment the specification demands. The identity map makes a virtual
//! address its physical one, which is what lets a static be handed to
//! hardware at all — and is why this cannot be lifted into a kernel with real
//! paging without a translation step.
//!
//! # Polled, not interrupt-driven
//!
//! There is no IDT and no interrupt controller, so the event ring is polled.
//! For a keyboard on an otherwise idle machine that is not a compromise: the
//! poll costs one memory read, and an interrupt would have to be delivered,
//! dispatched, and returned from before the same byte was available.

use crate::pci::Device;

// --- capability registers, from xhcireg.h ---------------------------------

const XHCI_CAPLENGTH: usize = 0x00;
const XHCI_HCSPARAMS1: usize = 0x04;
/// Holds the scratchpad buffer count, split across two fields.
const XHCI_HCSPARAMS2: usize = 0x08;
const XHCI_HCCPARAMS1: usize = 0x10;
const XHCI_DBOFF: usize = 0x14;
const XHCI_RTSOFF: usize = 0x18;

// --- operational registers, relative to CAPLENGTH -------------------------

const XHCI_USBCMD: usize = 0x00;
const XHCI_USBSTS: usize = 0x04;
const XHCI_PAGESIZE: usize = 0x08;

// --- Extended capabilities, at `HCCPARAMS1 >> 16` dwords from the base ----

/// Capability ID 1: USB Legacy Support. Where the firmware says it owns the
/// controller.
const XECP_ID_LEGACY: u32 = 1;
/// Byte offsets of the two semaphores inside that capability: the firmware's
/// at 2, the operating system's at 3. Byte-wide rather than bits 16 and 24 of
/// the dword — the same storage either way, and one byte written is one byte
/// written, which is what the handshake wants.
const XECP_BIOS_SEM: usize = 0x02;
const XECP_OS_SEM: usize = 0x03;

/// How many scratchpad pages this will provide.
///
/// The field can express up to 1023, which would be four megabytes of `.bss`
/// for a controller that will never ask for it; FreeBSD caps at 256 for the
/// same reason. Sixty-four is past what any part asks for in practice and
/// costs a quarter of a megabyte.
const MAX_SCRATCHPAD: usize = 64;

/// The page size the specification fixes for scratchpad buffers.
///
/// The `PAGESIZE` register reports what the controller wants as a bitmap; the
/// only value any implementation reports is 4 KiB, and providing a larger
/// buffer than asked for is harmless where providing a smaller one is not.
const SCRATCHPAD_PAGE: usize = 4096;

/// How many times to ask the firmware to let go, at ten milliseconds each.
///
/// FreeBSD waits five seconds, which is the right call for a general-purpose
/// kernel. Half a second is the right call here: this runs before the
/// interface can be used, a firmware that has not released the controller in
/// that time is not about to, and the fallback — no USB input — is survivable
/// where a machine that appears to hang is not.
const HANDOFF_POLLS: u32 = 50;
const XHCI_CRCR: usize = 0x18;
const XHCI_DCBAAP: usize = 0x30;
const XHCI_CONFIG: usize = 0x38;
/// Port registers start here, 0x10 bytes each.
const XHCI_PORTSC: usize = 0x400;

const XHCI_CMD_RS: u32 = 1 << 0;
const XHCI_CMD_HCRST: u32 = 1 << 1;
const XHCI_STS_HCH: u32 = 1 << 0;
const XHCI_STS_CNR: u32 = 1 << 11;

/// `PORTSC`: current connect status, port enabled, port reset, port power.
const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_PED: u32 = 1 << 1;
const PORTSC_PR: u32 = 1 << 4;
const PORTSC_PP: u32 = 1 << 9;
/// Change bits, which are write-1-to-clear. Writing `PORTSC` without masking
/// these clears whichever happen to be set, which is how a port reset ends up
/// being acknowledged before it happened.
const PORTSC_CHANGE_MASK: u32 = (1 << 17) | (1 << 18) | (1 << 20) | (1 << 21) | (1 << 22);
/// Bits that must be preserved on any read-modify-write.
const PORTSC_RW_MASK: u32 = !(PORTSC_CHANGE_MASK | PORTSC_PED);

// --- TRB types ------------------------------------------------------------

const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_TRANSFER_EVENT: u32 = 32;
const TRB_COMMAND_COMPLETION: u32 = 33;

/// TRB cycle bit, which is how the controller knows which entries are new.
const TRB_CYCLE: u32 = 1 << 0;
/// Toggle-cycle, set on the link TRB that wraps a ring.
const TRB_TOGGLE: u32 = 1 << 1;
/// Interrupt on completion.
const TRB_IOC: u32 = 1 << 5;

/// Completion code 1 is success; everything else is a failure worth naming.
const CC_SUCCESS: u32 = 1;
/// Completion code 13: the device sent less than the endpoint's maximum. For
/// a HID device that is not an error but the normal case — a mouse's report
/// is shorter than the packet size its descriptor advertises.
const CC_SHORT_PACKET: u32 = 13;

/// Ring capacity. Small: this driver issues a handful of commands at boot and
/// one transfer at a time afterwards.
const RING_LEN: usize = 16;

/// One Transfer Request Block. Sixteen bytes, four little-endian dwords.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct Trb {
    parameter: u64,
    status: u32,
    control: u32,
}

/// A ring of TRBs with a link back to the start.
#[repr(C, align(64))]
struct Ring {
    trbs: [Trb; RING_LEN],
}

impl Ring {
    const fn new() -> Ring {
        Ring {
            trbs: [Trb {
                parameter: 0,
                status: 0,
                control: 0,
            }; RING_LEN],
        }
    }
}

/// How many devices this driver keeps addressed at the same time.
///
/// Two, because a notebook needs two: the keyboard and the pointer are
/// separate USB devices even when they share a chassis, and a driver that
/// addresses one of them can drive a cursor or accept a keystroke but not
/// both. Enumerating only the *first* connected port is worse still — on a
/// real machine that port is usually the webcam or the Bluetooth radio, and
/// the result is a stack that comes up cleanly and delivers no input at all.
pub const MAX_DEVICES: usize = 3;

// The structures the controller reads by physical address. Statics because
// there is no allocator, and the identity map makes their addresses usable
// as-is.
//
// The command and event rings are shared — there is one controller — but a
// transfer ring, a device context and a report buffer belong to a device, so
// there is one of each per device.
/// The device context base address array.
///
/// One entry per slot the controller may hand out, **plus entry zero**, which
/// is not a slot at all: it holds the scratchpad pointer. Sizing this to the
/// slot count alone is an index past the end the first time the controller
/// hands out the last slot.
#[repr(C, align(64))]
struct Dcbaa([u64; MAX_SLOTS + 1]);

/// How many device slots this driver asks the controller for.
///
/// Three devices are ever addressed (keyboard, pointer, and a mass-
/// storage stick for the crash dump), so the number is small — but the
/// controller assigns slot numbers itself and only promises them to be within
/// what `CONFIG` asked for, so the array has to cover all of them.
const MAX_SLOTS: usize = 8;

static mut DCBAA: Dcbaa = Dcbaa([0; MAX_SLOTS + 1]);

/// The array of scratchpad buffer addresses, which `DCBAA[0]` points at.
#[repr(C, align(64))]
struct ScratchpadArray([u64; MAX_SCRATCHPAD]);

static mut SCRATCHPAD_ARRAY: ScratchpadArray = ScratchpadArray([0; MAX_SCRATCHPAD]);

/// The buffers themselves. **The controller writes these**, and it is the
/// only user: they are private working storage it needs to exist, not
/// something this driver reads.
#[repr(C, align(4096))]
struct ScratchpadPages([[u8; SCRATCHPAD_PAGE]; MAX_SCRATCHPAD]);

static mut SCRATCHPAD_PAGES: ScratchpadPages =
    ScratchpadPages([[0; SCRATCHPAD_PAGE]; MAX_SCRATCHPAD]);
static mut COMMAND_RING: Ring = Ring::new();
static mut EVENT_RING: Ring = Ring::new();
static mut TRANSFER_RINGS: [Ring; MAX_DEVICES] = [Ring::new(), Ring::new(), Ring::new()];

/// Event Ring Segment Table: one entry, pointing at the event ring.
#[repr(C, align(64))]
struct Erst {
    base: u64,
    size: u32,
    reserved: u32,
}

static mut ERST: Erst = Erst {
    base: 0,
    size: 0,
    reserved: 0,
};

/// Input and device contexts. 2048 bytes covers the 64-byte context size the
/// specification allows for, which `HCCPARAMS1.CSZ` selects.
#[repr(C, align(64))]
struct Context([u8; 2048]);

/// The input context is one context *longer* than a device context: the
/// input control context, the slot context and all 31 endpoint contexts —
/// 33 × 64 = 2112 bytes at the 64-byte context size. A 2048-byte input
/// context puts endpoint 15 IN one past its end.
#[repr(C, align(64))]
struct InputContext([u8; INPUT_CONTEXT_BYTES]);
const INPUT_CONTEXT_BYTES: usize = 33 * 64;

/// The input context is shared: it is written only while a device is being
/// enumerated, and enumeration is serial. The device contexts are not — the
/// controller keeps writing them for as long as the device is addressed.
static mut INPUT_CONTEXT: InputContext = InputContext([0; INPUT_CONTEXT_BYTES]);
static mut DEVICE_CONTEXTS: [Context; MAX_DEVICES] =
    [Context([0; 2048]), Context([0; 2048]), Context([0; 2048])];

/// Where descriptors and reports are read into.
#[repr(C, align(64))]
struct Buffer([u8; 256]);

static mut BUFFERS: [Buffer; MAX_DEVICES] = [Buffer([0; 256]), Buffer([0; 256]), Buffer([0; 256])];

/// The address of one device's transfer ring.
fn transfer_ring_address(index: usize) -> u64 {
    (&raw const TRANSFER_RINGS) as u64 + (index * core::mem::size_of::<Ring>()) as u64
}

/// The address of one device's context.
fn context_address(index: usize) -> u64 {
    (&raw const DEVICE_CONTEXTS) as u64 + (index * core::mem::size_of::<Context>()) as u64
}

/// A pointer to one TRB of a ring at `base`.
///
/// A raw pointer rather than `&mut RING.trbs[i]`: a reference into a
/// `static mut` is unsound the moment a second one exists, and the controller
/// is reading these entries concurrently by definition.
///
/// # Safety
/// `base` must be a `Ring` and `index` below [`RING_LEN`].
unsafe fn trb_at(base: u64, index: usize) -> *mut Trb {
    // SAFETY: forwarded from this function's own contract.
    unsafe { (base as *mut Trb).add(index) }
}

/// The address of one device's report buffer.
fn buffer_address(index: usize) -> u64 {
    // `addr_of` on the element rather than a reference to the array: a shared
    // reference to a `static mut` is unsound the moment anything else touches
    // it, and only the address is wanted.
    (&raw const BUFFERS) as u64 + (index * core::mem::size_of::<Buffer>()) as u64
}

/// Copies the first `N` bytes out of one device's buffer.
///
/// An owned array rather than a borrow, for the reason above. Copying
/// sidesteps both lints: a hundred bytes at boot costs nothing, and nothing
/// aliases.
///
/// # Safety
/// The controller must not be writing the buffer concurrently, which holds
/// because a report is only read after its transfer event has been consumed.
/// `index` must be below [`MAX_DEVICES`], and `N` at most 256.
unsafe fn buffer_copy<const N: usize>(index: usize) -> [u8; N] {
    let mut out = [0u8; N];
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::ptr::copy_nonoverlapping(buffer_address(index) as *const u8, out.as_mut_ptr(), N);
    }
    out
}

/// One addressed device: its slot, its endpoint, and the state of its ring.
#[derive(Debug, Clone, Copy)]
struct DeviceSlot {
    /// The slot the controller gave it. Zero means the entry is unused.
    slot: u8,
    /// Its interrupt IN endpoint, once configured.
    endpoint: u8,
    cycle: u32,
    index: usize,
    /// An interrupt-IN transfer is queued and has not completed.
    queued: bool,
    /// A completed transfer's report is sitting in the buffer, unread.
    ready: bool,
}

impl DeviceSlot {
    const fn new() -> DeviceSlot {
        DeviceSlot {
            slot: 0,
            endpoint: 0,
            // A ring starts with its producer cycle set, which is what marks
            // the first entry written as belonging to this pass.
            cycle: 1,
            index: 0,
            queued: false,
            ready: false,
        }
    }
}

/// What a controller wants, without bringing it up.
///
/// Reported by the self-test because both answers are invisible under an
/// emulator: QEMU asks for no scratchpad pages and implements no legacy
/// support capability, so a driver missing either works there and fails on a
/// laptop. Seeing the real numbers is what turns that from a guess into a
/// fact.
///
/// # Safety
/// Reads MMIO; requires ring 0 and an identity map covering the BAR.
pub unsafe fn survey(device: &Device) -> (usize, bool) {
    let Some(base) = device.bar0_addr() else {
        return (0, false);
    };
    // SAFETY: forwarded from this function's own contract.
    let bar_len = unsafe { device.bar0_size() } as usize;
    if base == 0 || bar_len < MIN_BAR {
        return (0, false);
    }
    // SAFETY: forwarded from this function's own contract.
    let (hcs2, hcc1) = unsafe {
        (
            read32(base + XHCI_HCSPARAMS2),
            read32(base + XHCI_HCCPARAMS1),
        )
    };
    let scratchpad = (((hcs2 >> 16) & 0x3E0) | ((hcs2 >> 27) & 0x1F)) as usize;

    let mut offset = ((hcc1 >> 16) & 0xFFFF) as usize * 4;
    let mut firmware_owned = false;
    for _ in 0..64 {
        if offset == 0 || !xecp_in_bar(offset, bar_len) {
            break;
        }
        // SAFETY: as above.
        let header = unsafe { read32(base + offset) };
        if header == 0 || header == u32::MAX {
            break;
        }
        if header & 0xFF == XECP_ID_LEGACY {
            // SAFETY: as above.
            firmware_owned = unsafe { read8(base + offset + XECP_BIOS_SEM) } != 0;
            break;
        }
        let next = ((header >> 8) & 0xFF) as usize * 4;
        if next == 0 {
            break;
        }
        offset += next;
    }
    (scratchpad, firmware_owned)
}

/// The smallest BAR an xHCI can have: the capability, operational and
/// runtime blocks plus one port. Real controllers decode 64 KiB.
const MIN_BAR: usize = 0x1000;

/// Whether an extended capability at `offset` (header and the legacy
/// semaphores, 8 bytes) lies inside the BAR.
fn xecp_in_bar(offset: usize, bar_len: usize) -> bool {
    offset.checked_add(8).is_some_and(|end| end <= bar_len)
}

/// Whether the register blocks the capability registers place all lie
/// inside a BAR of `bar_len` bytes: the operational block and its port
/// array, a doorbell for every slot the controller could number (256), and
/// the runtime block through interrupter 0.
fn layout_fits(bar_len: usize, caplength: usize, dboff: usize, rtsoff: usize, max_ports: u8) -> bool {
    let operational_end = caplength + XHCI_PORTSC + max_ports as usize * 0x10;
    let doorbell_end = dboff.checked_add(256 * 4);
    let runtime_end = rtsoff.checked_add(0x20 + 0x20);
    caplength >= 0x20
        && operational_end <= bar_len
        && doorbell_end.is_some_and(|end| dboff >= caplength && end <= bar_len)
        && runtime_end.is_some_and(|end| rtsoff >= caplength && end <= bar_len)
}

/// A brought-up controller and the devices addressed on it.
pub struct Xhci {
    /// The BAR, kept because every other offset is derived from it and a
    /// second controller would need it to be re-read.
    #[allow(dead_code)]
    base: usize,
    operational: usize,
    doorbell: usize,
    runtime: usize,
    /// How many bytes the BAR decodes; every offset the controller supplies
    /// is checked against it.
    bar_len: usize,
    /// 64-byte contexts rather than 32, from `HCCPARAMS1.CSZ`. Getting this
    /// wrong puts every field at half its correct offset.
    context_size: usize,
    max_ports: u8,
    /// Cycle state of each shared ring, which flips every time one wraps.
    command_cycle: u32,
    event_cycle: u32,
    command_index: usize,
    event_index: usize,
    devices: [DeviceSlot; MAX_DEVICES],
    /// How many entries of `devices` are in use.
    device_count: usize,
    /// Scratchpad pages the controller asked for.
    scratchpad: usize,
    /// The mass-storage device, once one has been enumerated for the crash
    /// dump. `None` on a machine with no USB stick plugged in.
    msc: Option<MscSlot>,
}

impl Xhci {
    /// Brings up the controller on `device`.
    ///
    /// # Safety
    /// Touches MMIO and hands physical addresses to hardware; requires ring 0
    /// and an identity map covering both the BAR and these statics.
    pub unsafe fn new(device: &Device) -> Option<Xhci> {
        if device.bar0 == 0 {
            return None;
        }
        // Sized before decoding is turned on: the handshake switches it off
        // and restores whatever was there.
        // SAFETY: forwarded from this function's own contract.
        let bar_len = unsafe { device.bar0_size() } as usize;
        if bar_len < MIN_BAR {
            return None;
        }
        // SAFETY: forwarded from this function's own contract.
        unsafe { device.enable() };

        let base = device.bar0_addr()?;
        // SAFETY: the BAR is inside the identity map, checked by the caller.
        let (caplength, hcs1, hcc1, dboff, rtsoff) = unsafe {
            (
                read8(base + XHCI_CAPLENGTH) as usize,
                read32(base + XHCI_HCSPARAMS1),
                read32(base + XHCI_HCCPARAMS1),
                read32(base + XHCI_DBOFF) as usize & !0x3,
                read32(base + XHCI_RTSOFF) as usize & !0x1F,
            )
        };
        // Every register block below is placed by the controller's own
        // words. A controller that places one outside its BAR is not driven:
        // following it would read — and write — another device's registers.
        if !layout_fits(bar_len, caplength, dboff, rtsoff, (hcs1 >> 24) as u8) {
            return None;
        }

        let mut xhci = Xhci {
            base,
            operational: base + caplength,
            doorbell: base + dboff,
            runtime: base + rtsoff,
            // HCCPARAMS1 bit 2 is CSZ: contexts are 64 bytes rather than 32.
            context_size: if hcc1 & (1 << 2) != 0 { 64 } else { 32 },
            max_ports: (hcs1 >> 24) as u8,
            command_cycle: 1,
            event_cycle: 1,
            command_index: 0,
            event_index: 0,
            devices: [DeviceSlot::new(); MAX_DEVICES],
            device_count: 0,
            scratchpad: 0,
            msc: None,
            bar_len,
        };

        // **Before the reset, not after.** Until the handshake below the
        // firmware owns this controller, and resetting it out from under an
        // SMI handler that is still driving it is how a working machine
        // starts behaving strangely.
        // SAFETY: as above.
        unsafe { xhci.take_from_firmware(hcc1) };

        // SAFETY: as above.
        unsafe { xhci.reset()? };
        // SAFETY: as above.
        unsafe { xhci.configure_scratchpad() };
        // SAFETY: as above.
        unsafe { xhci.configure_rings(hcs1) };
        // SAFETY: as above.
        unsafe { xhci.run() };
        Some(xhci)
    }

    pub fn max_ports(&self) -> u8 {
        self.max_ports
    }

    /// Takes ownership of the controller from the firmware.
    ///
    /// **This does not exist under an emulator, and it is required on real
    /// hardware.** A PC's firmware drives the xHCI itself so a USB keyboard
    /// works in the boot menu, and it keeps driving it from System Management
    /// Mode after handing control to the loader. The xHCI specification
    /// defines a handshake for taking it away: the OS sets its ownership bit
    /// and waits for the firmware to drop its own.
    ///
    /// Skipping it means resetting a controller an SMI handler is still
    /// using. QEMU implements no legacy support capability at all, so the
    /// omission is invisible there and only shows up on a laptop.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn take_from_firmware(&self, hcc1: u32) {
        // The capability list starts at `HCCPARAMS1[31:16]`, counted in
        // dwords from the register base.
        let mut offset = ((hcc1 >> 16) & 0xFFFF) as usize * 4;

        // Bounded: the list is a linked chain out of hardware, and a
        // controller with a corrupt or circular one must not be followed
        // forever.
        for _ in 0..64 {
            if offset == 0 || !xecp_in_bar(offset, self.bar_len) {
                return;
            }
            // SAFETY: forwarded from this function's own contract; the
            // capability window is inside the BAR.
            let header = unsafe { read32(self.base + offset) };
            if header == 0 || header == u32::MAX {
                return;
            }

            if header & 0xFF == XECP_ID_LEGACY {
                // SAFETY: as above.
                unsafe {
                    // Nothing to take if the firmware is not holding it.
                    if read8(self.base + offset + XECP_BIOS_SEM) == 0 {
                        return;
                    }
                    // Claim it, then wait for the firmware to let go.
                    write8(self.base + offset + XECP_OS_SEM, 1);
                    for _ in 0..HANDOFF_POLLS {
                        if read8(self.base + offset + XECP_BIOS_SEM) == 0 {
                            return;
                        }
                        delay(10_000);
                    }
                }
                // It never let go. Proceeding anyway is what FreeBSD does,
                // and it is the better of two bad options: a controller the
                // firmware will not release is one this cannot use, and
                // giving up here means no USB input at all rather than the
                // chance of some.
                return;
            }

            let next = ((header >> 8) & 0xFF) as usize * 4;
            offset += next;
        }
    }

    /// Gives the controller the scratchpad pages it asked for.
    ///
    /// **Also invisible under an emulator.** A controller may require private
    /// working memory, and says how much in `HCSPARAMS2`; the addresses go in
    /// an array whose own address goes in `DCBAA[0]`. QEMU asks for none, so a
    /// driver that never implements this works there and fails on the Intel
    /// part in a laptop, which does ask.
    ///
    /// # Safety
    /// Writes memory the controller will write to; requires ring 0.
    unsafe fn configure_scratchpad(&mut self) {
        // SAFETY: forwarded from this function's own contract.
        let hcs2 = unsafe { read32(self.base + XHCI_HCSPARAMS2) };
        // The count is split across two fields: the high five bits at 25:21
        // and the low five at 31:27. Reading either half alone gives a
        // plausible wrong number, which is worse than none. The expression is
        // FreeBSD's `XHCI_HCS2_SPB_MAX`: shifting the high half down by
        // sixteen and masking 0x3E0 lands it at bits 9:5 in one step.
        let wanted = (((hcs2 >> 16) & 0x3E0) | ((hcs2 >> 27) & 0x1F)) as usize;
        self.scratchpad = wanted.min(MAX_SCRATCHPAD);
        if self.scratchpad == 0 {
            return;
        }

        // SAFETY: as above. The statics are this driver's alone, and the
        // controller is halted until `run`.
        unsafe {
            let pages = (&raw const SCRATCHPAD_PAGES) as u64;
            let array = (&raw mut SCRATCHPAD_ARRAY).cast::<u64>();
            for index in 0..self.scratchpad {
                array
                    .add(index)
                    .write(pages + (index * SCRATCHPAD_PAGE) as u64);
            }
            // Slot zero of the device context array is the scratchpad
            // pointer, not a device.
            DCBAA.0[0] = (&raw const SCRATCHPAD_ARRAY) as u64;
        }
    }

    /// How many scratchpad pages the controller asked for, for reporting.
    pub fn scratchpad_pages(&self) -> usize {
        self.scratchpad
    }

    /// Halts the controller and resets it.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn reset(&mut self) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            // Stop it before resetting: resetting a running controller leaves
            // it in a state the specification does not define.
            let cmd = read32(self.operational + XHCI_USBCMD);
            write32(self.operational + XHCI_USBCMD, cmd & !XHCI_CMD_RS);
            if !wait_for(|| read32(self.operational + XHCI_USBSTS) & XHCI_STS_HCH != 0) {
                return None;
            }

            write32(self.operational + XHCI_USBCMD, XHCI_CMD_HCRST);
            // HCRST clears when the reset is done, and CNR clears when the
            // controller will accept writes. Both must be waited for; writing
            // between them is silently dropped.
            if !wait_for(|| read32(self.operational + XHCI_USBCMD) & XHCI_CMD_HCRST == 0) {
                return None;
            }
            if !wait_for(|| read32(self.operational + XHCI_USBSTS) & XHCI_STS_CNR == 0) {
                return None;
            }
        }
        Some(())
    }

    /// Points the controller at the rings and contexts.
    ///
    /// # Safety
    /// MMIO and physical addresses; requires ring 0 and an identity map.
    unsafe fn configure_rings(&mut self, hcs1: u32) {
        let max_slots = (hcs1 & 0xFF).min(MAX_SLOTS as u32);

        // SAFETY: forwarded from this function's own contract.
        unsafe {
            // How many slots will be used. Without this the controller
            // refuses every Enable Slot.
            write32(self.operational + XHCI_CONFIG, max_slots);

            // The device context base address array. Entry zero already
            // holds the scratchpad pointer, set before this ran.
            let dcbaa = &raw const DCBAA as u64;
            write64(self.operational + XHCI_DCBAAP, dcbaa);

            // The command ring, with the cycle bit as its initial state.
            let cmd_ring = &raw const COMMAND_RING as u64;
            write64(self.operational + XHCI_CRCR, cmd_ring | 1);

            // The event ring: a one-entry segment table pointing at it.
            ERST.base = &raw const EVENT_RING as u64;
            ERST.size = RING_LEN as u32;

            // Interrupter 0's registers start at runtime + 0x20.
            let interrupter = self.runtime + 0x20;
            write32(interrupter + 0x08, 1); // ERSTSZ: one segment
            write64(interrupter + 0x18, ERST.base); // ERDP
            write64(interrupter + 0x10, &raw const ERST as u64); // ERSTBA
        }
    }

    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn run(&mut self) {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let cmd = read32(self.operational + XHCI_USBCMD);
            write32(self.operational + XHCI_USBCMD, cmd | XHCI_CMD_RS);
            wait_for(|| read32(self.operational + XHCI_USBSTS) & XHCI_STS_HCH == 0);
        }
    }

    /// Reads a port's status register.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    pub unsafe fn port_status(&self, port: u8) -> u32 {
        // SAFETY: forwarded; ports are numbered from one.
        unsafe { read32(self.operational + XHCI_PORTSC + (port as usize - 1) * 0x10) }
    }

    /// Every port with something plugged into it.
    ///
    /// All of them, not the first. On a laptop the root ports carry a webcam,
    /// a Bluetooth radio, a fingerprint reader and a card reader alongside
    /// anything a person plugged in, and which one answers first is a
    /// property of the board rather than of what the user wants to type on.
    /// Stopping at the first is how a stack that works in a virtual machine —
    /// where port 1 is the emulated keyboard — finds nothing usable on real
    /// hardware.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    pub unsafe fn connected_ports(&self) -> impl Iterator<Item = u8> + '_ {
        // SAFETY: forwarded from this function's own contract.
        (1..=self.max_ports)
            .filter(move |&port| unsafe { self.port_status(port) } & PORTSC_CCS != 0)
    }

    /// Resets a port and waits for it to enable.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    pub unsafe fn reset_port(&self, port: u8) -> bool {
        let offset = self.operational + XHCI_PORTSC + (port as usize - 1) * 0x10;
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let status = read32(offset);
            // Power first: a port that is not powered never connects, and
            // firmware does not always leave it on.
            if status & PORTSC_PP == 0 {
                write32(offset, (status & PORTSC_RW_MASK) | PORTSC_PP);
                delay(100_000);
            }

            let status = read32(offset);
            write32(offset, (status & PORTSC_RW_MASK) | PORTSC_PR);
            // The reset is done when PR clears; the port is usable when PED
            // sets. USB 3 ports enable themselves, USB 2 ports need the
            // reset — waiting for both covers each.
            if !wait_for(|| read32(offset) & PORTSC_PR == 0) {
                return false;
            }
            delay(20_000);
            read32(offset) & PORTSC_PED != 0
        }
    }
}

// --- MMIO -----------------------------------------------------------------

/// # Safety
/// `address` must be mapped device memory.
unsafe fn write8(address: usize, value: u8) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::write_volatile(address as *mut u8, value) }
}

/// # Safety
/// `address` must be mapped device memory.
unsafe fn read8(address: usize) -> u8 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::read_volatile(address as *const u8) }
}

/// # Safety
/// `address` must be mapped device memory.
unsafe fn read32(address: usize) -> u32 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// # Safety
/// `address` must be mapped device memory.
unsafe fn write32(address: usize, value: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

/// Writes a 64-bit register as two 32-bit halves.
///
/// The specification permits a controller to implement only 32-bit access,
/// and the low half must land first: writing the high half first can latch a
/// pointer made of the new high and the old low.
///
/// # Safety
/// `address` must be mapped device memory.
unsafe fn write64(address: usize, value: u64) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        write32(address, value as u32);
        write32(address + 4, (value >> 32) as u32);
    }
}

/// Spins until `check` passes, or gives up.
///
/// A bounded spin because there is no timer. The bound is generous: a
/// controller reset is specified to complete within milliseconds, and a
/// driver that hangs forever on absent hardware is worse than one that
/// reports failure.
fn wait_for(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..10_000_000u32 {
        if check() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// A crude busy-wait, in spin iterations rather than time.
///
/// Used where the specification requires a settling delay and there is no
/// clock to measure one with. Over-waiting costs boot time and nothing else.
fn delay(iterations: u32) {
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

// --- rings ----------------------------------------------------------------

impl Xhci {
    /// Rings a doorbell, which is how the controller is told a ring changed.
    ///
    /// Doorbell 0 is the command ring; doorbell N is slot N, with the target
    /// naming the endpoint.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn ring_doorbell(&self, slot: u8, target: u32) {
        // SAFETY: forwarded from this function's own contract.
        unsafe { write32(self.doorbell + slot as usize * 4, target) };
    }

    /// Places a TRB on the command ring and waits for its completion event.
    ///
    /// Returns the completion code and the event's parameter, which for
    /// Enable Slot carries the slot number.
    ///
    /// # Safety
    /// Writes memory the controller reads and rings a doorbell; requires
    /// ring 0 and an identity map.
    unsafe fn command(&mut self, parameter: u64, status: u32, control: u32) -> Option<Event> {
        // The last entry is reserved for the link TRB that wraps the ring.
        if self.command_index >= RING_LEN - 1 {
            // SAFETY: forwarded from this function's own contract.
            unsafe { self.wrap_command_ring() };
        }

        // SAFETY: single core, interrupts masked; the controller reads this
        // only after the doorbell below.
        unsafe {
            let trb = &mut COMMAND_RING.trbs[self.command_index];
            trb.parameter = parameter;
            trb.status = status;
            // The cycle bit is written last: it is what makes the entry
            // visible to the controller, so the rest must already be there.
            trb.control = control | self.command_cycle;
        }
        self.command_index += 1;

        // SAFETY: as above. Doorbell 0, target 0 is the command ring.
        unsafe { self.ring_doorbell(0, 0) };
        // SAFETY: as above.
        unsafe { self.wait_command_event() }
    }

    /// The completion event for the command just issued.
    ///
    /// Returned whole rather than as a code, because Enable Slot answers in
    /// the event's slot field and nowhere else.
    ///
    /// # Safety
    /// As [`next_event`](Self::next_event).
    unsafe fn wait_command_event(&mut self) -> Option<Event> {
        for _ in 0..10_000_000u32 {
            // SAFETY: forwarded from this function's own contract.
            match unsafe { self.next_event() } {
                Some(event) if event.kind == TRB_COMMAND_COMPLETION => return Some(event),
                Some(_) => {}
                None => core::hint::spin_loop(),
            }
        }
        None
    }

    /// Writes the link TRB and starts the ring over.
    ///
    /// # Safety
    /// Writes memory the controller reads; requires ring 0.
    unsafe fn wrap_command_ring(&mut self) {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let base = &raw const COMMAND_RING as u64;
            let trb = &mut COMMAND_RING.trbs[RING_LEN - 1];
            trb.parameter = base;
            trb.status = 0;
            // Toggle Cycle tells the controller the cycle bit flips here,
            // which is what lets a ring be reused rather than exhausted.
            trb.control = (TRB_LINK << 10) | TRB_TOGGLE | self.command_cycle;
        }
        self.command_index = 0;
        self.command_cycle ^= 1;
    }

    /// Takes the next event off the ring, or `None` if there is none *now*.
    ///
    /// Non-blocking, and that is the important part. The interface polls
    /// input from its draw loop, and a keyboard with no key pressed simply
    /// does not complete its transfer — so a blocking read costs the full
    /// timeout on every frame in which nothing was typed, which is every
    /// frame. This returns immediately and the caller comes back next frame.
    ///
    /// # Safety
    /// Reads memory the controller writes and updates the dequeue pointer;
    /// requires ring 0.
    unsafe fn next_event(&mut self) -> Option<Event> {
        // SAFETY: forwarded from this function's own contract.
        let trb = unsafe { EVENT_RING.trbs[self.event_index] };

        // An entry belongs to this pass only if its cycle bit matches;
        // otherwise it is left over from the previous one.
        if trb.control & TRB_CYCLE != self.event_cycle {
            return None;
        }

        let event = Event {
            kind: (trb.control >> 10) & 0x3F,
            completion: (trb.status >> 24) & 0xFF,
            parameter: trb.parameter,
            slot: (trb.control >> 24) as u8,
        };
        // When a transfer completes — a key report, a mouse report, a block
        // read from a USB stick — depends on the device and the bus, not on
        // anything this code controls. Into NC_RNG, uncredited.
        crate::rng::stir(
            nanochrono_core::rng::EVENT_USB,
            trb.parameter ^ (trb.status as u64) << 32 ^ trb.control as u64,
        );

        self.event_index += 1;
        if self.event_index >= RING_LEN {
            self.event_index = 0;
            self.event_cycle ^= 1;
        }

        // The controller must be told how far the ring was consumed, or it
        // stops posting once it believes the ring is full.
        // SAFETY: as above.
        unsafe {
            let erdp = &raw const EVENT_RING as u64 + (self.event_index * 16) as u64;
            // Bit 3 is the Event Handler Busy flag, write-1-to-clear.
            write64(self.runtime + 0x20 + 0x18, erdp | (1 << 3));
        }
        Some(event)
    }

    /// Waits for the next event of `kind`, discarding others.
    ///
    /// Only used during bring-up and enumeration, where blocking is correct:
    /// nothing else can proceed until the command completes, and a bounded
    /// wait is what keeps a controller that never answers from hanging the
    /// boot.
    ///
    /// # Safety
    /// As [`next_event`](Self::next_event).
    unsafe fn wait_event(&mut self, kind: u32) -> Option<(u32, u64)> {
        for _ in 0..10_000_000u32 {
            // SAFETY: forwarded from this function's own contract.
            match unsafe { self.next_event() } {
                Some(event) if event.kind == kind => {
                    return Some((event.completion, event.parameter))
                }
                // Some other event — a port status change, most likely.
                // Consumed and skipped rather than treated as the answer.
                Some(_) => {}
                None => core::hint::spin_loop(),
            }
        }
        None
    }
}

/// One entry taken off the event ring.
#[derive(Debug, Clone, Copy)]
struct Event {
    kind: u32,
    completion: u32,
    parameter: u64,
    /// Which device the event is about. This is what makes two devices on one
    /// controller possible: their transfers complete into the same ring, and
    /// the slot is the only thing that says whose a completion is.
    slot: u8,
}

// --- enumeration ----------------------------------------------------------

/// A USB setup packet.
#[derive(Clone, Copy)]
struct Setup {
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
}

impl Setup {
    fn as_u64(self) -> u64 {
        (self.request_type as u64)
            | ((self.request as u64) << 8)
            | ((self.value as u64) << 16)
            | ((self.index as u64) << 32)
            | ((self.length as u64) << 48)
    }
}

/// `GET_DESCRIPTOR`, device-to-host, standard, to the device.
const REQ_GET_DESCRIPTOR: u8 = 6;
/// How many bytes of the configuration descriptor are asked for: the whole
/// per-device buffer.
const CONFIG_READ: usize = 256;
const REQ_SET_CONFIGURATION: u8 = 9;
/// HID class request: select the boot protocol.
const REQ_SET_PROTOCOL: u8 = 0x0B;
const DESC_DEVICE: u16 = 0x0100;
const DESC_CONFIGURATION: u16 = 0x0200;

/// What a HID device turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidKind {
    /// Boot protocol keyboard: eight-byte reports.
    Keyboard,
    /// Boot protocol mouse or touchpad: three or more bytes.
    Pointer,
    /// A HID device this driver does not read.
    Other,
}

impl HidKind {
    pub const fn name(self) -> &'static str {
        match self {
            HidKind::Keyboard => "keyboard",
            HidKind::Pointer => "pointer",
            HidKind::Other => "hid (unread)",
        }
    }
}

/// An enumerated device.
#[derive(Debug, Clone, Copy)]
pub struct HidDevice {
    pub kind: HidKind,
    pub vendor: u16,
    pub product: u16,
    /// Report size the interrupt endpoint delivers.
    pub report_len: u16,
}

/// Which kinds of device the caller still needs; anything else found on a
/// port has its slot disabled again rather than taking one of the few device
/// indices.
#[derive(Debug, Clone, Copy)]
pub struct Want {
    pub keyboard: bool,
    pub pointer: bool,
    pub storage: bool,
}

/// What [`Xhci::enumerate_port`] found on a port.
#[derive(Debug, Clone, Copy)]
pub enum PortDevice {
    /// A boot-protocol keyboard or pointer, configured and ready to poll,
    /// with the index every later call about it takes.
    Hid(usize, HidDevice),
    /// A Bulk-Only mass-storage stick, configured and ready for block
    /// transfers — the crash dump's USB target.
    Storage,
    /// Anything else: a webcam, a radio, a fingerprint reader, a HID device
    /// this driver does not read. Its slot has been disabled again.
    Other,
}

impl Xhci {
    /// Enumerates the device on `port` **once**, and configures it as what
    /// its interface descriptor says it is.
    ///
    /// One pass per port, dispatching on the class, rather than one pass for
    /// HID and another for storage. Addressing a device takes a slot, and a
    /// controller refuses to address a port that another slot already holds
    /// — the second pass of the old two-pass scan got a TRB Error from
    /// Address Device for exactly that reason. Every device this driver does
    /// not keep has its slot disabled again, so the webcam, radio and
    /// fingerprint reader on a notebook's root ports do not use up the slots
    /// before a stick is reached.
    ///
    /// `want` says which kinds are still needed. A second keyboard, or a
    /// stick when one is already held, is handled like any unwanted device:
    /// its slot is disabled, so it cannot take the index the next wanted
    /// device needs.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0 and an identity map.
    pub unsafe fn enumerate_port(&mut self, port: u8, want: Want) -> Option<PortDevice> {
        let index = self.device_count;
        if index >= MAX_DEVICES {
            return None;
        }
        // SAFETY: forwarded from this function's own contract.
        let event = unsafe { self.command(0, 0, TRB_ENABLE_SLOT << 10) }?;
        if event.completion != CC_SUCCESS || event.slot == 0 {
            return None;
        }
        // The slot number is in the top byte of the completion event's
        // control field, and nowhere else.
        let slot = event.slot;
        self.devices[index] = DeviceSlot::new();
        self.devices[index].slot = slot;

        // SAFETY: as above.
        let found = unsafe { self.identify(port, index, want) };
        if !matches!(found, Some(PortDevice::Hid(..)) | Some(PortDevice::Storage)) {
            // Not kept, or failed part-way: hand the slot back so the port
            // can be addressed again and the slot reused.
            // SAFETY: as above.
            unsafe { self.disable_slot(slot) };
        }
        found
    }

    /// Addresses the device, reads its descriptors and configures it by
    /// class. The caller disables the slot unless this keeps the device.
    ///
    /// # Safety
    /// As [`enumerate_port`](Self::enumerate_port).
    unsafe fn identify(&mut self, port: u8, index: usize, want: Want) -> Option<PortDevice> {
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.address_device(port, index)? };

        // The device descriptor names the vendor and product, and its
        // `bMaxPacketSize0` is what EP0 must actually be configured with —
        // the addressing above used a guess from the port speed.
        // SAFETY: as above.
        unsafe {
            self.control_in(
                index,
                Setup {
                    request_type: 0x80,
                    request: REQ_GET_DESCRIPTOR,
                    value: DESC_DEVICE,
                    index: 0,
                    length: 18,
                },
                18,
            )?
        };
        // SAFETY: the transfer completed, so the buffer holds the descriptor.
        let descriptor: [u8; 18] = unsafe { buffer_copy(index) };
        let vendor = u16::from_le_bytes([descriptor[8], descriptor[9]]);
        let product = u16::from_le_bytes([descriptor[10], descriptor[11]]);

        // The configuration descriptor carries the interface and endpoint
        // descriptors after it, which is where the class and the endpoints
        // are named. The whole buffer is asked for: a device answers with its
        // real `wTotalLength` as a short packet, and a composite device's
        // interfaces do not all fit in 64 bytes.
        // SAFETY: as above.
        unsafe {
            self.control_in(
                index,
                Setup {
                    request_type: 0x80,
                    request: REQ_GET_DESCRIPTOR,
                    value: DESC_CONFIGURATION,
                    index: 0,
                    length: CONFIG_READ as u16,
                },
                CONFIG_READ as u16,
            )?
        };
        // SAFETY: the transfer completed.
        let configuration: [u8; CONFIG_READ] = unsafe { buffer_copy(index) };

        if let Some(parsed) = parse_configuration(&configuration) {
            // A HID device this driver does not read, or one of a kind
            // already held, is not worth a slot.
            let wanted = match parsed.kind {
                HidKind::Keyboard => want.keyboard,
                HidKind::Pointer => want.pointer,
                HidKind::Other => false,
            };
            if !wanted {
                return Some(PortDevice::Other);
            }
            // SAFETY: as above.
            unsafe { self.configure_hid(index, &parsed)? };
            self.device_count = index + 1;
            return Some(PortDevice::Hid(
                index,
                HidDevice {
                    kind: parsed.kind,
                    vendor,
                    product,
                    report_len: parsed.max_packet,
                },
            ));
        }

        if want.storage && self.msc.is_none() {
            if let Some(parsed) = parse_mass_storage(&configuration) {
                // SAFETY: as above.
                unsafe { self.configure_storage(index, &parsed)? };
                self.device_count = index + 1;
                return Some(PortDevice::Storage);
            }
        }
        Some(PortDevice::Other)
    }

    /// Selects the configuration and the boot protocol, and adds the
    /// interrupt endpoint.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn configure_hid(&mut self, index: usize, parsed: &Parsed) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.control_out(
                index,
                Setup {
                    request_type: 0x00,
                    request: REQ_SET_CONFIGURATION,
                    value: parsed.configuration as u16,
                    index: 0,
                    length: 0,
                },
            )?
        };

        // Boot protocol: a fixed report layout, so no report-descriptor
        // parser is needed. That parser is most of a HID stack, and a
        // keyboard that reports in boot protocol needs none of it.
        // SAFETY: as above.
        unsafe {
            self.control_out(
                index,
                Setup {
                    request_type: 0x21,
                    request: REQ_SET_PROTOCOL,
                    value: 0,
                    index: parsed.interface as u16,
                    length: 0,
                },
            )
        };

        self.devices[index].endpoint = parsed.endpoint;
        // SAFETY: as above.
        unsafe { self.configure_endpoint(index, parsed.endpoint, parsed.max_packet) }
    }

    /// Hands a slot back to the controller: Disable Slot, and the DCBAA entry
    /// cleared so a stale context is never followed.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn disable_slot(&mut self, slot: u8) {
        if slot == 0 || slot as usize > MAX_SLOTS {
            return;
        }
        let control = (TRB_DISABLE_SLOT << 10) | ((slot as u32) << 24);
        // SAFETY: forwarded from this function's own contract. The result is
        // not needed: a slot that fails to disable only costs one of eight.
        let _ = unsafe { self.command(0, 0, control) };
        // SAFETY: single core; the controller no longer owns the slot.
        unsafe { (*core::ptr::addr_of_mut!(DCBAA)).0[slot as usize] = 0 };
    }

    /// Builds the input context and issues Address Device.
    ///
    /// # Safety
    /// Writes memory the controller reads; requires ring 0.
    unsafe fn address_device(&mut self, port: u8, index: usize) -> Option<()> {
        let cs = self.context_size;
        let slot = self.devices[index].slot;
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let input = &raw mut INPUT_CONTEXT as *mut u8;
            core::ptr::write_bytes(input, 0, INPUT_CONTEXT_BYTES);

            // Input Control Context: add the slot and EP0.
            write_ctx(input, 1, 0b11); // add flags: A0 | A1

            // Slot context follows the control context.
            let slot_ctx = input.add(cs);
            // Speed in bits 23:20, one context entry in bits 31:27.
            let speed = (self.port_speed(port) as u32) << 20;
            write_ctx(slot_ctx, 0, speed | (1 << 27));
            // Root hub port number in bits 23:16.
            write_ctx(slot_ctx, 1, (port as u32) << 16);

            // EP0 context follows the slot context.
            let ep0 = input.add(cs * 2);
            // Type 4 is Control, in bits 5:3; max packet size in bits 31:16;
            // CErr 3 in bits 2:1, which is what the specification requires
            // for a control endpoint.
            let max_packet = self.default_max_packet(port) as u32;
            write_ctx(ep0, 1, (4 << 3) | (3 << 1) | (max_packet << 16));
            // Transfer ring dequeue pointer, with the dequeue cycle state.
            write_ctx64(ep0, 2, transfer_ring_address(index) | 1);
            // Average TRB length, which the controller uses for bandwidth.
            write_ctx(ep0, 4, 8);

            // The device context this slot will be given. One per device: the
            // controller keeps writing it for as long as the device is
            // addressed, so two devices sharing one would each be overwriting
            // the other's state.
            let device = context_address(index);
            core::ptr::write_bytes(device as *mut u8, 0, 2048);
            // The slot number comes from the controller. Bounds-checked
            // rather than trusted: an index past the array is a panic in a
            // kernel with nowhere to report one.
            // Slot 0 is not a slot: DCBAA[0] is the scratchpad array pointer.
            if slot == 0 || slot as usize > MAX_SLOTS {
                return None;
            }
            DCBAA.0[slot as usize] = device;

            let control = (TRB_ADDRESS_DEVICE << 10) | ((slot as u32) << 24);
            let event = self.command(&raw const INPUT_CONTEXT as u64, 0, control)?;
            (event.completion == CC_SUCCESS).then_some(())
        }
    }

    /// Adds the HID interrupt endpoint to the device.
    ///
    /// # Safety
    /// Writes memory the controller reads; requires ring 0.
    unsafe fn configure_endpoint(
        &mut self,
        device: usize,
        address: u8,
        max_packet: u16,
    ) -> Option<()> {
        // Endpoint context index: 2 * number, plus one for an IN endpoint.
        //
        // `address` is the device's own bEndpointAddress, so it is checked:
        // number 0 is the control endpoint (context 1), which this would
        // silently reprogram as an interrupt endpoint.
        let number = (address & 0x0F) as usize;
        if number == 0 {
            return None;
        }
        let index = number * 2 + 1;
        let cs = self.context_size;
        let slot = self.devices[device].slot;

        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let input = &raw mut INPUT_CONTEXT as *mut u8;
            core::ptr::write_bytes(input, 0, INPUT_CONTEXT_BYTES);
            // Add the slot and this endpoint.
            write_ctx(input, 1, 1 | (1 << index));

            let slot_ctx = input.add(cs);
            // Context entries must now reach this endpoint.
            write_ctx(slot_ctx, 0, (index as u32) << 27);

            let ep = input.add(cs * (index + 1));
            // Type 7 is Interrupt IN, in bits 5:3.
            write_ctx(ep, 1, (7 << 3) | (3 << 1) | ((max_packet as u32) << 16));
            write_ctx64(ep, 2, transfer_ring_address(device) | 1);
            write_ctx(ep, 4, max_packet as u32);
            // Interval: 8 is a millisecond at high speed. Slower than a
            // device may support and far faster than a person types.
            write_ctx(ep, 0, 8 << 16);

            let control = (TRB_CONFIGURE_ENDPOINT << 10) | ((slot as u32) << 24);
            let event = self.command(&raw const INPUT_CONTEXT as u64, 0, control)?;
            (event.completion == CC_SUCCESS).then_some(())
        }
    }

    /// A control transfer that reads `length` bytes into the shared buffer.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn control_in(&mut self, index: usize, setup: Setup, length: u16) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            core::ptr::write_bytes(buffer_address(index) as *mut u8, 0, 256);

            // Setup stage. TRT 3 is an IN data stage.
            self.transfer(
                index,
                setup.as_u64(),
                8,
                (TRB_SETUP << 10) | (3 << 16) | (1 << 6),
            );
            // Data stage, direction IN.
            self.transfer(
                index,
                buffer_address(index),
                length as u32,
                (TRB_DATA << 10) | (1 << 16),
            );
            // Status stage, direction OUT, with an interrupt so there is
            // something to wait for.
            self.transfer(index, 0, 0, (TRB_STATUS << 10) | TRB_IOC);

            self.ring_doorbell(self.devices[index].slot, 1);
            let (code, _) = self.wait_event(TRB_TRANSFER_EVENT)?;
            (code == CC_SUCCESS).then_some(())
        }
    }

    /// A control transfer with no data stage.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn control_out(&mut self, index: usize, setup: Setup) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.transfer(index, setup.as_u64(), 8, (TRB_SETUP << 10) | (1 << 6));
            self.transfer(index, 0, 0, (TRB_STATUS << 10) | TRB_IOC | (1 << 16));
            self.ring_doorbell(self.devices[index].slot, 1);
            let (code, _) = self.wait_event(TRB_TRANSFER_EVENT)?;
            (code == CC_SUCCESS).then_some(())
        }
    }

    /// Places one TRB on the transfer ring.
    ///
    /// # Safety
    /// Writes memory the controller reads; requires ring 0.
    unsafe fn transfer(&mut self, device: usize, parameter: u64, status: u32, control: u32) {
        let base = transfer_ring_address(device);
        if self.devices[device].index >= RING_LEN - 1 {
            // SAFETY: forwarded from this function's own contract; `device`
            // is below `MAX_DEVICES` and the ring is `RING_LEN` entries.
            unsafe {
                let trb = trb_at(base, RING_LEN - 1);
                (*trb).parameter = base;
                (*trb).status = 0;
                (*trb).control = (TRB_LINK << 10) | TRB_TOGGLE | self.devices[device].cycle;
            }
            self.devices[device].index = 0;
            self.devices[device].cycle ^= 1;
        }
        // SAFETY: as above.
        unsafe {
            let trb = trb_at(base, self.devices[device].index);
            (*trb).parameter = parameter;
            (*trb).status = status;
            // The cycle bit is written last: it is what makes the entry
            // visible to the controller, so the rest must already be there.
            (*trb).control = control | self.devices[device].cycle;
        }
        self.devices[device].index += 1;
    }

    /// Takes a report from `device` if one has arrived, and keeps a read
    /// queued.
    ///
    /// **Never blocks.** A keyboard with no key held does not complete its
    /// interrupt transfer at all — that is what an interrupt endpoint is —
    /// so waiting for one costs the full timeout on every frame in which
    /// nothing was typed, which is nearly all of them. The earlier version of
    /// this function did exactly that, and the result was an interface that
    /// looked frozen and answered a keypress seconds later, if at all.
    ///
    /// Instead the transfer is queued once and left outstanding; each call
    /// drains whatever the controller has posted, hands back a report if one
    /// is now complete, and re-arms.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    pub unsafe fn poll_report(&mut self, device: usize, out: &mut [u8]) -> Option<usize> {
        if device >= self.device_count {
            return None;
        }
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.drain_events() };

        if !self.devices[device].ready {
            // SAFETY: as above.
            unsafe { self.arm(device, out.len()) };
            return None;
        }
        self.devices[device].ready = false;

        // SAFETY: the transfer event for this device has been consumed, so
        // the controller is no longer writing its buffer.
        let report: [u8; 64] = unsafe { buffer_copy(device) };
        let len = out.len().min(64);
        out[..len].copy_from_slice(&report[..len]);

        // Re-arm immediately, so the next report is already in flight.
        // SAFETY: as above.
        unsafe { self.arm(device, out.len()) };
        Some(len)
    }

    /// Queues an interrupt-IN transfer for `device`, if one is not already
    /// outstanding.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn arm(&mut self, device: usize, len: usize) {
        if self.devices[device].queued {
            return;
        }
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.transfer(
                device,
                buffer_address(device),
                len.min(64) as u32,
                (TRB_NORMAL << 10) | TRB_IOC,
            );
            // Doorbell target for endpoint N IN is 2N + 1.
            let target = ((self.devices[device].endpoint & 0x0F) as u32) * 2 + 1;
            self.ring_doorbell(self.devices[device].slot, target);
        }
        self.devices[device].queued = true;
    }

    /// Consumes every event the controller has posted, routing transfer
    /// completions to the device they belong to.
    ///
    /// # Safety
    /// Reads the event ring; requires ring 0.
    unsafe fn drain_events(&mut self) {
        // Bounded by the ring: there cannot be more outstanding events than
        // entries, and an unbounded loop here would be a second way to hang.
        for _ in 0..RING_LEN {
            // SAFETY: forwarded from this function's own contract.
            let Some(event) = (unsafe { self.next_event() }) else {
                return;
            };
            if event.kind != TRB_TRANSFER_EVENT {
                continue;
            }
            let Some(device) = self.device_of_slot(event.slot) else {
                continue;
            };
            // The transfer is no longer outstanding whatever happened to it.
            // A stall or a babble leaves `ready` clear, so the next call
            // re-arms rather than handing back a buffer nothing wrote.
            self.devices[device].queued = false;
            // Short packets are how a device with a report smaller than the
            // endpoint's maximum answers, which is routine for a mouse.
            if event.completion == CC_SUCCESS || event.completion == CC_SHORT_PACKET {
                self.devices[device].ready = true;
            }
        }
    }

    /// Which device an event's slot number refers to.
    fn device_of_slot(&self, slot: u8) -> Option<usize> {
        (0..self.device_count).find(|&i| self.devices[i].slot == slot)
    }

    /// The port's link speed, from `PORTSC` bits 13:10.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn port_speed(&self, port: u8) -> u8 {
        // SAFETY: forwarded from this function's own contract.
        ((unsafe { self.port_status(port) } >> 10) & 0xF) as u8
    }

    /// EP0's max packet size before the device descriptor has been read.
    ///
    /// The specification fixes this per speed, which is what makes the first
    /// control transfer possible at all — the value that would tell you is
    /// inside the descriptor that transfer fetches.
    ///
    /// # Safety
    /// MMIO; requires ring 0.
    unsafe fn default_max_packet(&self, port: u8) -> u16 {
        // SAFETY: forwarded from this function's own contract.
        match unsafe { self.port_speed(port) } {
            1 => 8,   // full speed: 8, then re-read from the descriptor
            2 => 8,   // low speed
            3 => 64,  // high speed
            _ => 512, // super speed and above
        }
    }
}

/// Writes a dword of a context structure.
///
/// # Safety
/// `base` must point at a context with at least `index + 1` dwords.
unsafe fn write_ctx(base: *mut u8, index: usize, value: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::write_volatile(base.add(index * 4).cast::<u32>(), value) }
}

/// # Safety
/// `base` must point at a context with at least `index + 2` dwords.
unsafe fn write_ctx64(base: *mut u8, index: usize, value: u64) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        write_ctx(base, index, value as u32);
        write_ctx(base, index + 1, (value >> 32) as u32);
    }
}

/// What the configuration descriptor said.
struct Parsed {
    configuration: u8,
    interface: u8,
    endpoint: u8,
    max_packet: u16,
    kind: HidKind,
}

/// Walks a configuration descriptor for the HID interface and its interrupt
/// endpoint.
///
/// Descriptors are a byte stream of `[length, type, ...]` records, so this
/// steps by the length field rather than assuming an order — a device is free
/// to put its endpoint descriptors anywhere after the interface they belong
/// to, and several do.
fn parse_configuration(buf: &[u8]) -> Option<Parsed> {
    if buf.len() < 9 || buf[1] != 2 {
        return None;
    }
    let configuration = buf[5];
    let mut kind = None;
    let mut interface = 0u8;
    let mut offset = 0usize;

    while offset + 2 <= buf.len() {
        let length = buf[offset] as usize;
        let descriptor_type = buf[offset + 1];
        if length < 2 || offset + length > buf.len() {
            break;
        }

        match descriptor_type {
            // Interface: class 3 is HID, and the boot protocol subclass is 1
            // with protocol 1 for a keyboard and 2 for a pointer.
            4 if length >= 9 => {
                if buf[offset + 5] == 3 {
                    interface = buf[offset + 2];
                    kind = Some(match buf[offset + 7] {
                        1 => HidKind::Keyboard,
                        2 => HidKind::Pointer,
                        _ => HidKind::Other,
                    });
                } else {
                    kind = None;
                }
            }
            // Endpoint: attribute bits 1:0 == 3 is interrupt, and the top bit
            // of the address is the direction.
            5 if length >= 7 && kind.is_some() => {
                let address = buf[offset + 2];
                let attributes = buf[offset + 3];
                if attributes & 0x03 == 0x03 && address & 0x80 != 0 {
                    return Some(Parsed {
                        configuration,
                        interface,
                        endpoint: address,
                        max_packet: u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]) & 0x7FF,
                        kind: kind?,
                    });
                }
            }
            _ => {}
        }
        offset += length;
    }
    None
}

// --- mass storage (Bulk-Only Transport + SCSI) ----------------------------
//
// Enough of a USB mass-storage driver to write a crash dump to a stick, and
// no more: one LUN, one block at a time, no stall recovery beyond giving up.
// The reference is the USB Mass Storage Bulk-Only Transport specification;
// the CBW/CSW signatures, flags and sizes were cross-checked against
// FreeBSD's `sys/dev/usb/storage/umass.c` (see NOTICE). Like umass without a
// quirk entry, a CSW with any other signature is a failure.

/// Mass-storage class, SCSI transparent command set, Bulk-Only Transport.
const MSC_CLASS: u8 = 0x08;
const MSC_SUBCLASS_SCSI: u8 = 0x06;
const MSC_PROTOCOL_BOT: u8 = 0x50;

/// Endpoint transfer type 2 in the `bmAttributes` low bits is bulk.
const EP_ATTR_BULK: u8 = 0x02;

/// `dCBWSignature` "USBC" and `dCSWSignature" "USBS", little-endian.
const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;

/// SCSI opcodes.
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;

/// The largest block this driver handles. 4096 covers 4K-native sticks;
/// 512 is what almost all of them report.
const MAX_BLOCK: usize = 4096;

/// Dedicated bulk transfer rings for the one mass-storage device. Separate
/// from the HID transfer rings, and separate from each other: the two bulk
/// endpoints keep independent dequeue pointers, so they cannot share a ring.
static mut MSC_OUT_RING: Ring = Ring::new();
static mut MSC_IN_RING: Ring = Ring::new();

/// The data buffer the controller reads and writes for a block transfer.
#[repr(C, align(4096))]
struct MscData([u8; MAX_BLOCK]);
static mut MSC_DATA: MscData = MscData([0; MAX_BLOCK]);

/// The 31-byte command wrapper and 13-byte status wrapper, each in a cache
/// line of its own so a controller that writes the CSW cannot touch the CBW.
#[repr(C, align(64))]
struct MscFrame([u8; 64]);
static mut MSC_CBW: MscFrame = MscFrame([0; 64]);
static mut MSC_CSW: MscFrame = MscFrame([0; 64]);

/// The producer state of one bulk ring: which entry is next, and the cycle
/// bit that marks it as this pass's.
#[derive(Clone, Copy)]
struct RingCursor {
    index: usize,
    cycle: u32,
}

impl RingCursor {
    const fn new() -> RingCursor {
        RingCursor { index: 0, cycle: 1 }
    }
}

/// An addressed mass-storage device: its slot, its two bulk endpoints and
/// their rings, and the geometry SCSI reported.
#[derive(Clone, Copy)]
struct MscSlot {
    slot: u8,
    /// `bEndpointAddress` of each bulk endpoint — the IN one has bit 7 set.
    in_ep: u8,
    out_ep: u8,
    in_cursor: RingCursor,
    out_cursor: RingCursor,
    block_size: u32,
    block_count: u64,
    /// The `dCBWTag`, incremented per command so a CSW can be matched to it.
    tag: u32,
}

/// The address of a bulk ring.
fn msc_ring_address(in_dir: bool) -> u64 {
    if in_dir {
        &raw const MSC_IN_RING as u64
    } else {
        &raw const MSC_OUT_RING as u64
    }
}

impl Xhci {
    /// Whether a mass-storage device was enumerated.
    pub fn has_storage(&self) -> bool {
        self.msc.is_some()
    }

    /// The block size the stick reported, or zero if there is none.
    pub fn block_size(&self) -> u32 {
        self.msc.map_or(0, |m| m.block_size)
    }

    /// The number of addressable blocks, or zero.
    pub fn block_count(&self) -> u64 {
        self.msc.map_or(0, |m| m.block_count)
    }

    /// Configures an addressed mass-storage device for block transfers:
    /// selects its configuration, adds both bulk endpoints, and brings the
    /// SCSI unit up. Records the stick in `self.msc` on success.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0 and an identity map.
    unsafe fn configure_storage(&mut self, index: usize, parsed: &MassStorage) -> Option<()> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            self.control_out(
                index,
                Setup {
                    request_type: 0x00,
                    request: REQ_SET_CONFIGURATION,
                    value: parsed.configuration as u16,
                    index: 0,
                    length: 0,
                },
            )?;
            self.configure_bulk(index, parsed)?;
        }

        let mut msc = MscSlot {
            slot: self.devices[index].slot,
            in_ep: parsed.in_ep,
            out_ep: parsed.out_ep,
            in_cursor: RingCursor::new(),
            out_cursor: RingCursor::new(),
            block_size: 512,
            block_count: 0,
            tag: 0,
        };

        // Wake the device and read its geometry before it is trusted with a
        // write. A stick answers `TEST UNIT READY` with a check condition
        // until its medium is ready, which is why this is a loop.
        // SAFETY: as above.
        unsafe {
            let mut inquiry = [0u8; 6];
            inquiry[0] = SCSI_INQUIRY;
            inquiry[4] = 36;
            self.bot(&mut msc, &inquiry, true, 36)?;

            let ready = (0..16).any(|_| {
                let cdb = [SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0];
                let ok = self.bot(&mut msc, &cdb, false, 0).is_some();
                if !ok {
                    delay(200_000);
                }
                ok
            });
            if !ready {
                return None;
            }

            let cdb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            self.bot(&mut msc, &cdb, true, 8)?;
            let cap: [u8; 8] = msc_data_copy();
            let last_lba = u32::from_be_bytes([cap[0], cap[1], cap[2], cap[3]]);
            let block_size = u32::from_be_bytes([cap[4], cap[5], cap[6], cap[7]]);
            if block_size == 0 || block_size as usize > MAX_BLOCK {
                return None;
            }
            msc.block_size = block_size;
            msc.block_count = last_lba as u64 + 1;
        }

        self.msc = Some(msc);
        Some(())
    }

    /// Adds both bulk endpoints to the device, each on its own ring.
    ///
    /// # Safety
    /// Writes memory the controller reads; requires ring 0.
    unsafe fn configure_bulk(&mut self, device: usize, parsed: &MassStorage) -> Option<()> {
        let out_dci = (parsed.out_ep & 0x0F) as usize * 2;
        let in_dci = (parsed.in_ep & 0x0F) as usize * 2 + 1;
        if out_dci < 2 || in_dci < 2 || out_dci >= 32 || in_dci >= 32 {
            return None;
        }
        let cs = self.context_size;
        let slot = self.devices[device].slot;
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let input = &raw mut INPUT_CONTEXT as *mut u8;
            core::ptr::write_bytes(input, 0, INPUT_CONTEXT_BYTES);
            // Add the slot and both endpoints.
            write_ctx(input, 1, 1 | (1 << out_dci) | (1 << in_dci));

            let slot_ctx = input.add(cs);
            write_ctx(slot_ctx, 0, (out_dci.max(in_dci) as u32) << 27);

            // Bulk OUT is endpoint type 2, Bulk IN type 6.
            let ep_out = input.add(cs * (out_dci + 1));
            write_ctx(ep_out, 1, (2 << 3) | (3 << 1) | ((parsed.out_mps as u32) << 16));
            write_ctx64(ep_out, 2, msc_ring_address(false) | 1);
            write_ctx(ep_out, 4, parsed.out_mps as u32);

            let ep_in = input.add(cs * (in_dci + 1));
            write_ctx(ep_in, 1, (6 << 3) | (3 << 1) | ((parsed.in_mps as u32) << 16));
            write_ctx64(ep_in, 2, msc_ring_address(true) | 1);
            write_ctx(ep_in, 4, parsed.in_mps as u32);

            let control = (TRB_CONFIGURE_ENDPOINT << 10) | ((slot as u32) << 24);
            let event = self.command(&raw const INPUT_CONTEXT as u64, 0, control)?;
            (event.completion == CC_SUCCESS).then_some(())
        }
    }

    /// Reads one block into `out`.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    pub unsafe fn read_block(&mut self, lba: u32, out: &mut [u8]) -> Option<()> {
        let mut msc = self.msc?;
        let bs = msc.block_size;
        let cdb = read_write_cdb(SCSI_READ_10, lba);
        // SAFETY: forwarded from this function's own contract.
        let ok = unsafe { self.bot(&mut msc, &cdb, true, bs) };
        self.msc = Some(msc);
        ok?;
        let n = out.len().min(bs as usize);
        // SAFETY: the transfer completed, so the controller is done writing.
        out[..n].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&raw const MSC_DATA as *const u8, n)
        });
        Some(())
    }

    /// Writes one block from `data`, zero-padded to the block size.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    pub unsafe fn write_block(&mut self, lba: u32, data: &[u8]) -> Option<()> {
        let mut msc = self.msc?;
        let bs = msc.block_size as usize;
        let n = data.len().min(bs);
        // SAFETY: MSC_DATA is `MAX_BLOCK` and `bs <= MAX_BLOCK`.
        unsafe {
            let buf = &raw mut MSC_DATA as *mut u8;
            core::ptr::write_bytes(buf, 0, bs);
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf, n);
        }
        let cdb = read_write_cdb(SCSI_WRITE_10, lba);
        // SAFETY: forwarded from this function's own contract.
        let ok = unsafe { self.bot(&mut msc, &cdb, false, bs as u32) };
        self.msc = Some(msc);
        ok
    }

    /// One Bulk-Only transaction: command wrapper out, an optional data
    /// stage, status wrapper in. `true` when the device reports success.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn bot(
        &mut self,
        msc: &mut MscSlot,
        cdb: &[u8],
        data_in: bool,
        data_len: u32,
    ) -> Option<()> {
        msc.tag = msc.tag.wrapping_add(1);
        // SAFETY: MSC_CBW is 64 bytes; a CBW is 31.
        unsafe {
            let cbw = &raw mut MSC_CBW as *mut u8;
            core::ptr::write_bytes(cbw, 0, 64);
            write_le32(cbw, 0, CBW_SIGNATURE);
            write_le32(cbw, 4, msc.tag);
            write_le32(cbw, 8, data_len);
            *cbw.add(12) = if data_in { 0x80 } else { 0x00 }; // bmCBWFlags
            *cbw.add(13) = 0; // LUN 0
            *cbw.add(14) = cdb.len() as u8;
            core::ptr::copy_nonoverlapping(cdb.as_ptr(), cbw.add(15), cdb.len().min(16));
        }

        // Command out.
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.bulk(msc, false, &raw const MSC_CBW as u64, 31)? };
        // Data stage, if any.
        if data_len > 0 {
            // SAFETY: as above.
            unsafe { self.bulk(msc, data_in, &raw const MSC_DATA as u64, data_len)? };
        }
        // Status in.
        // SAFETY: as above.
        unsafe { self.bulk(msc, true, &raw const MSC_CSW as u64, 13)? };

        // SAFETY: the status transfer completed, so the CSW is in memory.
        unsafe {
            let csw = &raw const MSC_CSW as *const u8;
            let signature = read_le32(csw, 0);
            let tag = read_le32(csw, 4);
            let status = *csw.add(12);
            (signature == CSW_SIGNATURE && tag == msc.tag && status == 0).then_some(())
        }
    }

    /// One bulk transfer on the IN or OUT ring, waited to completion.
    ///
    /// Blocking, which is correct here: this runs at boot and in the panic
    /// handler, and in both nothing else can proceed until the block is
    /// moved. A stall or other non-success completion gives up rather than
    /// trying to recover, because the caller's fallback — the next storage
    /// tier, or the serial dump — is better than a driver that loops on a
    /// wedged endpoint.
    ///
    /// # Safety
    /// Drives the controller; requires ring 0.
    unsafe fn bulk(&mut self, msc: &mut MscSlot, in_dir: bool, buffer: u64, len: u32) -> Option<()> {
        let base = msc_ring_address(in_dir);
        let cursor = if in_dir {
            &mut msc.in_cursor
        } else {
            &mut msc.out_cursor
        };
        // SAFETY: `base` is one of the two bulk rings, each `RING_LEN` long.
        unsafe { bulk_enqueue(cursor, base, buffer, len, (TRB_NORMAL << 10) | TRB_IOC) };

        // Doorbell target: OUT endpoint N is DCI 2N, IN endpoint N is 2N + 1.
        let ep = if in_dir { msc.in_ep } else { msc.out_ep };
        let dci = ((ep & 0x0F) as u32) * 2 + if in_dir { 1 } else { 0 };
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.ring_doorbell(msc.slot, dci) };
        // SAFETY: as above.
        let (code, _) = unsafe { self.wait_event(TRB_TRANSFER_EVENT)? };
        (code == CC_SUCCESS || code == CC_SHORT_PACKET).then_some(())
    }
}

/// Places one TRB on a bulk ring, wrapping with a link TRB at the end.
///
/// # Safety
/// `base` must be a `Ring` and `cursor` its matching state.
unsafe fn bulk_enqueue(cursor: &mut RingCursor, base: u64, parameter: u64, status: u32, control: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        if cursor.index >= RING_LEN - 1 {
            let trb = trb_at(base, RING_LEN - 1);
            (*trb).parameter = base;
            (*trb).status = 0;
            (*trb).control = (TRB_LINK << 10) | TRB_TOGGLE | cursor.cycle;
            cursor.index = 0;
            cursor.cycle ^= 1;
        }
        let trb = trb_at(base, cursor.index);
        (*trb).parameter = parameter;
        (*trb).status = status;
        // The cycle bit last, as everywhere: it hands the entry to hardware.
        (*trb).control = control | cursor.cycle;
    }
    cursor.index += 1;
}

/// Copies the first `N` bytes out of the shared block buffer.
///
/// # Safety
/// The controller must not be writing it, which holds after a completed
/// transfer. `N` at most [`MAX_BLOCK`].
unsafe fn msc_data_copy<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::ptr::copy_nonoverlapping(&raw const MSC_DATA as *const u8, out.as_mut_ptr(), N);
    }
    out
}

/// A READ(10) or WRITE(10) command block for one block at `lba`.
fn read_write_cdb(opcode: u8, lba: u32) -> [u8; 10] {
    let l = lba.to_be_bytes();
    // bytes 2..6 LBA, byte 7..9 transfer length = 1 block.
    [opcode, 0, l[0], l[1], l[2], l[3], 0, 0, 1, 0]
}

/// Writes a little-endian u32 into a byte buffer.
///
/// # Safety
/// `base` must point at `offset + 4` writable bytes.
unsafe fn write_le32(base: *mut u8, offset: usize, value: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), base.add(offset), 4) }
}

/// Reads a little-endian u32 from a byte buffer.
///
/// # Safety
/// `base` must point at `offset + 4` readable bytes.
unsafe fn read_le32(base: *const u8, offset: usize) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: forwarded from this function's own contract.
    unsafe { core::ptr::copy_nonoverlapping(base.add(offset), b.as_mut_ptr(), 4) };
    u32::from_le_bytes(b)
}

/// The bulk endpoints of a mass-storage interface.
struct MassStorage {
    configuration: u8,
    in_ep: u8,
    out_ep: u8,
    in_mps: u16,
    out_mps: u16,
}

/// Walks a configuration descriptor for a Bulk-Only mass-storage interface
/// and its two bulk endpoints.
///
/// Like [`parse_configuration`], it steps by the length byte rather than
/// assuming an order. The endpoints are only accepted while the walk is
/// inside a mass-storage interface, so a composite device's other interfaces
/// cannot contribute one.
fn parse_mass_storage(buf: &[u8]) -> Option<MassStorage> {
    if buf.len() < 9 || buf[1] != 2 {
        return None;
    }
    let configuration = buf[5];
    let mut in_ep = None;
    let mut out_ep = None;
    let mut in_mps = 0u16;
    let mut out_mps = 0u16;
    let mut in_msc = false;
    let mut offset = 0usize;

    while offset + 2 <= buf.len() {
        let length = buf[offset] as usize;
        let descriptor_type = buf[offset + 1];
        if length < 2 || offset + length > buf.len() {
            break;
        }
        match descriptor_type {
            // Interface: is it the BOT/SCSI mass-storage one?
            4 if length >= 9 => {
                in_msc = buf[offset + 5] == MSC_CLASS
                    && buf[offset + 6] == MSC_SUBCLASS_SCSI
                    && buf[offset + 7] == MSC_PROTOCOL_BOT;
            }
            // Endpoint: bulk, inside that interface. Direction from bit 7.
            5 if length >= 7 && in_msc => {
                let address = buf[offset + 2];
                let attributes = buf[offset + 3];
                let mps = u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]) & 0x7FF;
                if attributes & 0x03 == EP_ATTR_BULK {
                    if address & 0x80 != 0 {
                        in_ep = Some(address);
                        in_mps = mps;
                    } else {
                        out_ep = Some(address);
                        out_mps = mps;
                    }
                }
            }
            _ => {}
        }
        offset += length;
    }

    Some(MassStorage {
        configuration,
        in_ep: in_ep?,
        out_ep: out_ep?,
        in_mps: in_mps.max(1),
        out_mps: out_mps.max(1),
    })
}

const _: usize = XHCI_PAGESIZE;
