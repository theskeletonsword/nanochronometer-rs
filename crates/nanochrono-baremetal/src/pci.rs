// SPDX-License-Identifier: Apache-2.0
//! Finding devices, through PCI configuration space.
//!
//! The first step of any USB stack: the host controller is a PCI device, and
//! nothing can be done with it until its base address is known.
//!
//! Access is through the legacy `0xCF8`/`0xCFC` port pair rather than memory
//! mapped configuration. MMCONFIG needs the base address out of the ACPI MCFG
//! table and covers buses this kernel will never enumerate; the port pair
//! needs nothing, reaches the first 256 buses, and is what every controller
//! worth finding lives on.

/// Address port. A write here selects the register the data port reads.
const CONFIG_ADDRESS: u16 = 0x0CF8;
/// Data port.
const CONFIG_DATA: u16 = 0x0CFC;

/// PCI class 0x0C, subclass 0x03: a USB host controller.
const CLASS_SERIAL_BUS: u8 = 0x0C;
const SUBCLASS_USB: u8 = 0x03;
/// PCI class 0x03: a display controller.
const CLASS_DISPLAY: u8 = 0x03;

/// Which host controller interface a device implements, from the prog-if
/// byte. The three generations, and they are not interchangeable: each has
/// its own register layout and its own transfer model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbKind {
    /// USB 1.1, Intel's interface. Prog-if `0x00`.
    Uhci,
    /// USB 1.1, the open interface. Prog-if `0x10`.
    Ohci,
    /// USB 2.0. Prog-if `0x20`.
    Ehci,
    /// USB 3.0 and later. Prog-if `0x30`.
    Xhci,
}

impl UsbKind {
    fn from_prog_if(prog_if: u8) -> Option<UsbKind> {
        match prog_if {
            0x00 => Some(UsbKind::Uhci),
            0x10 => Some(UsbKind::Ohci),
            0x20 => Some(UsbKind::Ehci),
            0x30 => Some(UsbKind::Xhci),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            UsbKind::Uhci => "UHCI (USB 1.1)",
            UsbKind::Ohci => "OHCI (USB 1.1)",
            UsbKind::Ehci => "EHCI (USB 2.0)",
            UsbKind::Xhci => "xHCI (USB 3.0+)",
        }
    }
}

/// One device on the bus.
#[derive(Debug, Clone, Copy)]
pub struct Device {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    /// Header type, with the multifunction bit masked off. Type 1 is a
    /// bridge, which is what makes the walk below possible.
    pub header_type: u8,
    /// BAR0, with its flag bits cleared. Zero if it is an I/O BAR or unset.
    pub bar0: u64,
}

impl Device {
    /// The USB interface this device implements, if it is a host controller.
    pub fn usb_kind(&self) -> Option<UsbKind> {
        if self.class != CLASS_SERIAL_BUS || self.subclass != SUBCLASS_USB {
            return None;
        }
        UsbKind::from_prog_if(self.prog_if)
    }

    /// Turns on memory decoding and bus mastering.
    ///
    /// Firmware usually leaves both set, but "usually" is not a guarantee:
    /// without memory decoding the BAR reads as zeros, and without bus
    /// mastering the controller cannot reach the rings in memory. Neither
    /// failure reports itself.
    ///
    /// # Safety
    /// Writes PCI configuration space; requires ring 0.
    pub unsafe fn enable(&self) {
        // Command register at offset 4: bit 1 memory space, bit 2 bus master.
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let command = read32(self.bus, self.slot, self.function, 0x04);
            write32(
                self.bus,
                self.slot,
                self.function,
                0x04,
                command | (1 << 1) | (1 << 2),
            );
        }
    }

    /// BAR0 as an address this kernel can use: `None` when unset, or when
    /// it lies above what a pointer here reaches (a 64-bit BAR above 4 GiB on
    /// i386) — cast blindly, it would name some other device's registers.
    pub fn bar0_addr(&self) -> Option<usize> {
        usize::try_from(self.bar0).ok().filter(|&a| a != 0)
    }

    /// Turns on memory decoding only, for a device driven by programmed I/O
    /// that never needs to reach memory itself.
    ///
    /// Bus mastering is what lets a device write RAM on its own. Without an
    /// IOMMU nothing limits *where*, so it is granted only to a device that
    /// has rings or buffers in memory — see [`restrict_bus_masters`].
    ///
    /// # Safety
    /// Writes PCI configuration space; requires ring 0.
    pub unsafe fn enable_mmio(&self) {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            let command = read32(self.bus, self.slot, self.function, 0x04);
            write32(self.bus, self.slot, self.function, 0x04, command | (1 << 1));
        }
    }

    /// Whether this device must keep bus mastering for the machine to work
    /// while this kernel runs: a bridge (its bit gates DMA from everything
    /// behind it, including the controllers this does use), a display
    /// controller (scan-out can read system memory), or a USB host
    /// controller (the firmware's legacy emulation may be driving one to
    /// deliver the keyboard, and the xHCI is this kernel's own).
    pub fn needs_bus_master(&self) -> bool {
        self.header_type == HEADER_TYPE_BRIDGE
            || self.class == CLASS_DISPLAY
            || self.usb_kind().is_some()
    }

    /// How many bytes BAR0 decodes; 0 for an I/O or unimplemented BAR.
    ///
    /// Every offset a driver reads out of a device's own registers — a
    /// capability chain, a doorbell offset — is the device's word, and a
    /// defective or hostile device (anything on Thunderbolt is a PCIe device)
    /// can point it past its BAR into another device's registers. The BAR's
    /// size is the one bound that does not come from those registers: the
    /// standard sizing handshake, with decoding off so the probe value is
    /// never live as an address.
    ///
    /// Only for the device about to be driven — never in a bus sweep, where
    /// switching decode off under a GPU would blank the framebuffer.
    ///
    /// # Safety
    /// Writes PCI configuration space; requires ring 0 and nothing else using
    /// the device while it runs.
    pub unsafe fn bar0_size(&self) -> u64 {
        let (b, s, f) = (self.bus, self.slot, self.function);
        // SAFETY: forwarded from this function's own contract. Every register
        // written is restored before returning.
        unsafe {
            let lo = read32(b, s, f, 0x10);
            if lo & 1 != 0 {
                return 0;
            }
            let wide = (lo >> 1) & 0x3 == 0x2;
            let command = read32(b, s, f, 0x04);
            write32(b, s, f, 0x04, command & !0b11);

            write32(b, s, f, 0x10, u32::MAX);
            let lo_mask = read32(b, s, f, 0x10) & 0xFFFF_FFF0;
            write32(b, s, f, 0x10, lo);
            let hi_mask = if wide {
                let hi = read32(b, s, f, 0x14);
                write32(b, s, f, 0x14, u32::MAX);
                let mask = read32(b, s, f, 0x14);
                write32(b, s, f, 0x14, hi);
                mask
            } else {
                u32::MAX
            };
            write32(b, s, f, 0x04, command);

            let mask = (hi_mask as u64) << 32 | lo_mask as u64;
            if lo_mask == 0 {
                return 0;
            }
            (!mask).wrapping_add(1)
        }
    }
}

/// What [`restrict_bus_masters`] did, for the self-test to report.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaLockdown {
    /// Devices whose bus mastering was switched off.
    pub revoked: u16,
    /// Devices that keep it (see [`Device::needs_bus_master`]).
    pub kept: u16,
}

/// Switches bus mastering off on every device that does not need it.
///
/// Without an IOMMU programmed, a device with bus mastering can write any
/// physical address — this kernel's code, the stopwatch's state. Firmware
/// commonly leaves the bit set on whatever it touched during boot: the NVMe
/// it loaded from, the network card it could PXE-boot from, a Thunderbolt
/// controller whose downstream port anything can be plugged into. This kernel
/// drives none of those, so none of them keeps the ability.
///
/// This narrows the attack surface; it does not close it. A kept device
/// (see [`Device::needs_bus_master`]) can still reach all of memory, and a
/// device behind a kept bridge that turns its own bit back on is not stopped
/// by anything here. Only an IOMMU does that.
///
/// # Safety
/// Writes PCI configuration space; requires ring 0, before any device this
/// kernel drives is brought up.
pub unsafe fn restrict_bus_masters() -> DmaLockdown {
    let mut report = DmaLockdown::default();
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        scan(|dev| {
            let command = read32(dev.bus, dev.slot, dev.function, 0x04);
            if command & (1 << 2) != 0 {
                if dev.needs_bus_master() {
                    report.kept = report.kept.saturating_add(1);
                } else {
                    write32(dev.bus, dev.slot, dev.function, 0x04, command & !(1 << 2));
                    report.revoked = report.revoked.saturating_add(1);
                }
            }
            true
        });
    }
    LOCKDOWN_REVOKED.store(report.revoked, core::sync::atomic::Ordering::Relaxed);
    LOCKDOWN_KEPT.store(report.kept, core::sync::atomic::Ordering::Relaxed);
    report
}

static LOCKDOWN_REVOKED: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
static LOCKDOWN_KEPT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

/// What the boot-time [`restrict_bus_masters`] did.
pub fn dma_lockdown() -> DmaLockdown {
    DmaLockdown {
        revoked: LOCKDOWN_REVOKED.load(core::sync::atomic::Ordering::Relaxed),
        kept: LOCKDOWN_KEPT.load(core::sync::atomic::Ordering::Relaxed),
    }
}

/// Header type 1: a PCI-to-PCI bridge, which declares the bus behind it.
const HEADER_TYPE_BRIDGE: u8 = 1;

/// Walks the bus, calling `found` for each device until it returns `false`.
///
/// Follows bridges rather than sweeping all 256 bus numbers. The sweep is
/// simpler and it is what this did first, but it is wrong in two ways that
/// only show on real hardware:
///
/// * It touches configuration space for 255 buses that do not exist. Firmware
///   is entitled to leave those decoded by nothing, and a chipset is entitled
///   to be unhappy about it.
/// * It costs 8192 slot probes — around 33 ms of port I/O on a real machine,
///   every time, whether the device is on bus 0 or nowhere.
///
/// A bridge walk visits only the buses something declares. On a laptop that
/// is typically three or four, not 256.
///
/// `found` returns whether to keep going, so a caller looking for one device
/// stops at it instead of enumerating the rest of the machine.
///
/// # Safety
/// Reads PCI configuration space; requires ring 0.
pub unsafe fn scan(mut found: impl FnMut(Device) -> bool) {
    // Which buses have been walked. A malformed bridge can name a bus that
    // leads back to itself, and without this that is an infinite descent.
    let mut visited = [0u32; 8];
    // SAFETY: forwarded from this function's own contract.
    unsafe { scan_bus(0, &mut found, &mut visited) };
}

/// # Safety
/// Reads PCI configuration space; requires ring 0.
unsafe fn scan_bus(
    bus: u8,
    found: &mut impl FnMut(Device) -> bool,
    visited: &mut [u32; 8],
) -> bool {
    let word = (bus / 32) as usize;
    let bit = 1u32 << (bus % 32);
    if visited[word] & bit != 0 {
        return true;
    }
    visited[word] |= bit;

    for slot in 0..32u8 {
        // Function 0 must exist for any device to be present, and its header
        // type says whether to look at the other seven.
        // SAFETY: forwarded from this function's own contract.
        let id = unsafe { read32(bus, slot, 0, 0x00) };
        if id == 0xFFFF_FFFF {
            continue;
        }
        // SAFETY: as above.
        let header = unsafe { read32(bus, slot, 0, 0x0C) };
        let multifunction = (header >> 16) & 0x80 != 0;
        let functions = if multifunction { 8 } else { 1 };

        for function in 0..functions {
            // SAFETY: as above.
            let Some(dev) = (unsafe { probe(bus, slot, function as u8) }) else {
                continue;
            };
            if !found(dev) {
                return false;
            }

            // A bridge names the bus on its far side at offset 0x19; descend
            // into it rather than guessing that it exists.
            if dev.header_type == HEADER_TYPE_BRIDGE {
                // SAFETY: as above.
                let secondary = (unsafe { read32(bus, slot, function as u8, 0x18) } >> 8) as u8;
                if secondary != 0 && secondary != bus {
                    // SAFETY: as above.
                    if !unsafe { scan_bus(secondary, found, visited) } {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Finds the first device `wanted` accepts, and stops there.
///
/// # Safety
/// Reads PCI configuration space; requires ring 0.
pub unsafe fn find(mut wanted: impl FnMut(&Device) -> bool) -> Option<Device> {
    let mut hit = None;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        scan(|dev| {
            if wanted(&dev) {
                hit = Some(dev);
                return false;
            }
            true
        })
    };
    hit
}

/// # Safety
/// Reads PCI configuration space; requires ring 0.
unsafe fn probe(bus: u8, slot: u8, function: u8) -> Option<Device> {
    // SAFETY: forwarded from this function's own contract.
    let id = unsafe { read32(bus, slot, function, 0x00) };
    if id == 0xFFFF_FFFF {
        return None;
    }
    // SAFETY: as above.
    let classes = unsafe { read32(bus, slot, function, 0x08) };
    // SAFETY: as above.
    let header_type = ((unsafe { read32(bus, slot, function, 0x0C) } >> 16) & 0x7F) as u8;
    // SAFETY: as above.
    let bar_lo = unsafe { read32(bus, slot, function, 0x10) };

    // Bit 0 clear means a memory BAR. Bits 2:1 == 0b10 means 64-bit, in which
    // case the next BAR holds the upper half — reading only the low one gives
    // an address that is right on most machines and catastrophically wrong on
    // the ones that map above 4 GiB.
    let bar0 = if bar_lo & 1 == 0 {
        let base = (bar_lo & 0xFFFF_FFF0) as u64;
        if (bar_lo >> 1) & 0x3 == 0x2 {
            // SAFETY: as above.
            let bar_hi = unsafe { read32(bus, slot, function, 0x14) } as u64;
            base | (bar_hi << 32)
        } else {
            base
        }
    } else {
        0
    };

    Some(Device {
        bus,
        slot,
        function,
        vendor: (id & 0xFFFF) as u16,
        device: (id >> 16) as u16,
        class: (classes >> 24) as u8,
        subclass: (classes >> 16) as u8,
        prog_if: (classes >> 8) as u8,
        header_type,
        bar0,
    })
}

/// Selects a configuration register, then reads it.
///
/// # Safety
/// Requires ring 0.
unsafe fn read32(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        select(bus, slot, function, offset);
        in32(CONFIG_DATA)
    }
}

/// # Safety
/// Requires ring 0.
unsafe fn write32(bus: u8, slot: u8, function: u8, offset: u8, value: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        select(bus, slot, function, offset);
        out32(CONFIG_DATA, value);
    }
}

/// # Safety
/// Requires ring 0.
unsafe fn select(bus: u8, slot: u8, function: u8, offset: u8) {
    // Bit 31 enables the mechanism; the register offset is dword-aligned, so
    // its low two bits are always zero.
    let address = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((slot as u32 & 0x1F) << 11)
        | ((function as u32 & 0x7) << 8)
        | (offset as u32 & 0xFC);
    // SAFETY: forwarded from this function's own contract.
    unsafe { out32(CONFIG_ADDRESS, address) };
}

/// # Safety
/// Requires ring 0.
unsafe fn in32(port: u16) -> u32 {
    let value: u32;
    // SAFETY: forwarded; reading a configuration port has no side effects
    // beyond the register the address port already selected.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") value,
                         options(nomem, nostack, preserves_flags));
    }
    value
}

/// # Safety
/// Requires ring 0.
unsafe fn out32(port: u16, value: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value,
                         options(nomem, nostack, preserves_flags));
    }
}
