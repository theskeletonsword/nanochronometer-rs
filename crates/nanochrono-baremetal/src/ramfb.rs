// SPDX-License-Identifier: Apache-2.0
//! A screen for the `virt` machines: QEMU's `ramfb`, set up through fw_cfg.
//!
//! On x86 the loader hands over a framebuffer. On ARM and RISC-V `virt`
//! nothing does — there is no VGA and the firmware draws nothing — but QEMU's
//! `-device ramfb` scans out a buffer the *guest* places in its own RAM, once
//! told where through the fw_cfg file `etc/ramfb`. fw_cfg itself is a small
//! MMIO device whose address the devicetree gives (`qemu,fw-cfg-mmio`).
//!
//! Real hardware describes its framebuffer in the devicetree instead
//! (`simple-framebuffer`, set up by U-Boot or the Raspberry Pi firmware),
//! which [`simple_framebuffer`] reads. Both end in the same [`Framebuffer`].
//!
//! fw_cfg is big-endian throughout: the selector, the DMA descriptor, and
//! the ramfb configuration all say so, whatever the CPU is.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use crate::fdt::Fdt;
use crate::framebuffer::Framebuffer;

/// `FW_CFG_FILE_DIR`: the directory of named files.
const FILE_DIR: u16 = 0x19;
/// DMA control bits.
const DMA_ERROR: u32 = 0x01;
const DMA_SELECT: u32 = 0x08;
const DMA_WRITE: u32 = 0x10;
/// DRM `XR24`: 32-bit xRGB, little-endian — the layout the rest of the
/// drawing code already writes.
const FOURCC_XRGB8888: u32 = u32::from_le_bytes(*b"XR24");

/// The mode set. 1280x800 fits the back buffer and every QEMU display.
pub const WIDTH: u32 = 1280;
pub const HEIGHT: u32 = 800;

/// The scanout buffer. In `.bss`, page-aligned; QEMU reads it straight out
/// of guest RAM.
#[repr(C, align(4096))]
struct Scanout([u32; (WIDTH * HEIGHT) as usize]);
static mut SCANOUT: Scanout = Scanout([0; (WIDTH * HEIGHT) as usize]);

/// The fw_cfg DMA descriptor. Big-endian fields; aligned as the spec asks.
#[repr(C, align(16))]
struct DmaAccess {
    control: u32,
    length: u32,
    address: u64,
}

/// The ramfb configuration record: 28 bytes, packed, big-endian.
#[repr(C, packed)]
struct RamfbConfig {
    address: u64,
    fourcc: u32,
    flags: u32,
    width: u32,
    height: u32,
    stride: u32,
}

struct FwCfg {
    base: usize,
}

impl FwCfg {
    /// # Safety
    /// `base` is the fw_cfg MMIO window, mapped as device memory.
    unsafe fn select(&self, key: u16) {
        // SAFETY: the selector register, 16 bits, big-endian, at +8.
        unsafe { write_volatile((self.base + 8) as *mut u16, key.to_be()) };
    }

    /// # Safety
    /// As [`select`](Self::select); a file must be selected.
    unsafe fn read(&self, out: &mut [u8]) {
        for b in out.iter_mut() {
            // SAFETY: the data register at +0; byte reads stream the file.
            *b = unsafe { read_volatile(self.base as *const u8) };
        }
    }

    /// The selector of the file `name` in the fw_cfg directory.
    ///
    /// # Safety
    /// As [`select`](Self::select).
    unsafe fn find(&self, name: &[u8]) -> Option<u16> {
        // SAFETY: forwarded.
        unsafe { self.select(FILE_DIR) };
        let mut count = [0u8; 4];
        // SAFETY: forwarded.
        unsafe { self.read(&mut count) };
        // Bounded: the directory is QEMU's, but a count is still a number
        // this loop would otherwise follow wherever it pointed.
        let count = u32::from_be_bytes(count).min(1024);
        for _ in 0..count {
            let mut entry = [0u8; 64];
            // SAFETY: forwarded.
            unsafe { self.read(&mut entry) };
            let select = u16::from_be_bytes([entry[4], entry[5]]);
            let file = &entry[8..];
            let len = file.iter().position(|&c| c == 0).unwrap_or(file.len());
            if &file[..len] == name {
                return Some(select);
            }
        }
        None
    }

    /// Writes `data` to the file `key` by DMA and waits for it.
    ///
    /// # Safety
    /// As [`select`](Self::select); `data` lives until this returns.
    unsafe fn dma_write(&self, key: u16, data: *const u8, len: u32) -> bool {
        let mut access = DmaAccess {
            control: (((key as u32) << 16) | DMA_SELECT | DMA_WRITE).to_be(),
            length: len.to_be(),
            address: (data as u64).to_be(),
        };
        let addr = addr_of_mut!(access) as u64;
        // The descriptor and the data it points at are ordinary stores, and
        // a volatile MMIO write does not order ordinary stores: without a
        // fence the compiler (or the CPU) may still be filling them in when
        // the device, told to go, reads them. That is not hypothetical — it
        // is how this failed on RISC-V while working on ARM.
        fence(Ordering::SeqCst);
        // SAFETY: the DMA address register at +16, big-endian: high word
        // first, and the write of the low word starts the transfer.
        unsafe {
            write_volatile((self.base + 16) as *mut u32, ((addr >> 32) as u32).to_be());
            write_volatile((self.base + 20) as *mut u32, (addr as u32).to_be());
        }
        // The device clears `control` when done, or sets the error bit.
        for _ in 0..10_000_000u32 {
            // SAFETY: `access` is live; QEMU writes it back.
            let control = u32::from_be(unsafe { read_volatile(addr_of_mut!(access.control)) });
            if control & !DMA_ERROR == 0 {
                fence(Ordering::SeqCst);
                if control & DMA_ERROR != 0 {
                    crate::println!("ramfb: fw_cfg DMA error (control {control:#x}, descriptor at {addr:#x})");
                }
                return control & DMA_ERROR == 0;
            }
            core::hint::spin_loop();
        }
        // SAFETY: as above.
        let control = u32::from_be(unsafe { read_volatile(addr_of_mut!(access.control)) });
        crate::println!("ramfb: fw_cfg DMA never finished (control {control:#x}, descriptor at {addr:#x})");
        false
    }
}

/// Sets up `ramfb` if QEMU has one and returns its framebuffer.
///
/// # Safety
/// Called once, with the MMIO window of fw_cfg mapped as device memory and
/// RAM identity-mapped.
pub unsafe fn ramfb(tree: &Fdt<'_>) -> Option<Framebuffer> {
    let Some(base) = tree.find_compatible_reg(b"qemu,fw-cfg-mmio") else {
        crate::println!("ramfb: no fw_cfg in the devicetree");
        return None;
    };
    let fw = FwCfg { base: base as usize };
    // SAFETY: forwarded from this function's own contract.
    let Some(key) = (unsafe { fw.find(b"etc/ramfb") }) else {
        crate::println!("ramfb: fw_cfg at {base:#x} has no etc/ramfb (no -device ramfb?)");
        return None;
    };
    let pixels = addr_of_mut!(SCANOUT) as *mut u8;
    let config = RamfbConfig {
        address: (pixels as u64).to_be(),
        fourcc: FOURCC_XRGB8888.to_be(),
        flags: 0,
        width: WIDTH.to_be(),
        height: HEIGHT.to_be(),
        stride: (WIDTH * 4).to_be(),
    };
    // SAFETY: as above; `config` outlives the synchronous transfer.
    let ok = unsafe {
        fw.dma_write(key, (&config as *const RamfbConfig).cast(), core::mem::size_of::<RamfbConfig>() as u32)
    };
    if !ok {
        crate::println!("ramfb: the fw_cfg DMA write was refused");
    }
    // SAFETY: the scanout buffer is ours, `WIDTH * HEIGHT` pixels, mapped.
    ok.then(|| unsafe { Framebuffer::new(pixels, WIDTH, HEIGHT, WIDTH * 4, 32) })
}

/// The devicetree's `simple-framebuffer`, if firmware left one: its
/// address, and the mode from `width`, `height`, `stride` and a 32-bit
/// `format`.
///
/// # Safety
/// The framebuffer the tree names must be mapped and writable.
pub unsafe fn simple_framebuffer(tree: &Fdt<'_>) -> Option<Framebuffer> {
    let base = tree.find_compatible_reg(b"simple-framebuffer")?;
    let width = tree.compatible_u32(b"simple-framebuffer", b"width")?;
    let height = tree.compatible_u32(b"simple-framebuffer", b"height")?;
    let stride = tree.compatible_u32(b"simple-framebuffer", b"stride")?;
    let format = tree.compatible_str(b"simple-framebuffer", b"format")?;
    // Only the 32-bit layouts the drawing code writes directly.
    if format != b"a8r8g8b8" && format != b"x8r8g8b8" {
        return None;
    }
    if width == 0 || height == 0 || stride < width * 4 {
        return None;
    }
    // SAFETY: forwarded from this function's own contract.
    Some(unsafe { Framebuffer::new(base as *mut u8, width, height, stride, 32) })
}
