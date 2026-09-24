// SPDX-License-Identifier: Apache-2.0
//! NanoChronometer with no operating system underneath.
//!
//! A freestanding build for `x86_64-unknown-none`, `aarch64-unknown-none`,
//! `riscv64gc-unknown-none-elf`, `riscv32imac-unknown-none-elf` and the
//! PowerPC `powerpc{,64,64le}-nanochrono-none` specs:
//! no syscalls, no allocator, no runtime. It exists because the measurement
//! floor a hosted process can reach is set by the kernel underneath it —
//! scheduling, interrupts, the syscall boundary itself — and the only way to
//! see past that floor is to remove the kernel.
//!
//! # What changes without an OS
//!
//! | | Hosted | Here |
//! |---|---|---|
//! | Counter | `RDTSC` / `CNTVCT_EL0` | the same instructions |
//! | PMU | `perf_event_open`, thread-profiling API | `RDPMC` / `PMCCNTR_EL0`, programmed directly |
//! | Calibration | against the monotonic clock | against the PMU's reference counter |
//! | Output | `write(2)` | a UART |
//!
//! The counter layer is *literally the same code*: this crate depends on
//! `nanochrono-core` with `default-features = false`, which keeps `arch`,
//! `backend`, `cpu`, `simd` and `redundancy` and drops everything that needs
//! a kernel. A freestanding kernel therefore executes the same instruction
//! sequences as a hosted process rather than a reimplementation that has
//! drifted.
//!
//! # Why RDPMC is right here and wrong there
//!
//! Every other target in this project refuses to touch `RDPMC` or
//! `PMCCNTR_EL0`, because a raw counter read cannot see the kernel's
//! multiplexing, does not survive a context switch, and on a hybrid CPU
//! silently reads whichever PMU it landed on. None of those hazards exist
//! without a kernel: nothing multiplexes the counters, nothing deschedules
//! this code, and it never migrates because there is no scheduler. So the
//! instruction that is a trap in a hosted build is the only correct option
//! here.
//!
//! The hybrid hazard does survive, in a different form — see [`pmu`].

// Unconditionally `no_std`: there is no operating system to provide the
// library, and pulling it in even for a test build would let a dependency on
// it reach the kernel unnoticed. The logic that needs testing lives in
// `nanochrono_core::pmu_leaf`, which is `no_std` too but is part of a crate
// that has a hosted test build.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
/// x86 and AArch64: ACPI on one, PSCI on the other. PowerPC boards describe
/// themselves with a device tree ([`fdt`]) and power off through firmware.
pub mod acpi;
pub mod arch;
/// x86 only: the PIT and the CMOS real-time clock are PC firmware. An AArch64
/// board has `CNTFRQ_EL0`, which needs no calibration at all.
pub mod clock;
/// The benchmark tab: ISA kernels and RustCrypto, timed on the counter.
pub mod bench;
/// CPU load, effective frequency and the loop's own time accounting: the
/// data behind the task-manager view.
pub mod cpuload;
/// The interactive serial console: menu, task manager, settings.
pub mod console;
pub mod draw;
/// The device-tree reader. Used by the PowerPC boot path; architecture
/// neutral.
pub mod fdt;
pub mod font;
pub mod framebuffer;
/// The logo, rasterised at build time and embedded as raw RGBA.
pub mod logo;
/// The interrupt-controller priority floor (CR8 on x86_64, its equivalents
/// elsewhere), set at boot. Enables no interrupt.
pub mod irq_priority;
/// A screen off x86: QEMU's ramfb, or the devicetree's simple-framebuffer.
#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64", target_arch = "riscv32"))]
pub mod ramfb;
/// Detection and host-time negotiation. Both architectures, because at ring 0
/// the hypercall is available on both — unlike the hosted build, where it is
/// not available at all.
pub mod hypervisor;
pub mod typeface;

/// The interface. The x86 and AArch64 sides are separate modules — different
/// firmware hands the screen and console over in different ways — and `gui`
/// re-exports whichever one compiles for the machine at hand.
/// The interface, one implementation for every architecture; what differs
/// (input, power, the clocks it checks against) is chosen inside it.
mod gui_frame;
pub mod gui;
/// x86 only: the controller is an Intel LPSS device on the PCI bus.
#[cfg(x86_any)]
pub mod i2c;
/// x86 only: an Intel GPIO controller, found through the DSDT. Read to know
/// when an I2C-HID device has a report waiting, instead of asking the bus.
#[cfg(x86_any)]
pub mod gpio;
/// x86 only: it needs the DSDT, PCI and the I2C controller.
#[cfg(x86_any)]
pub mod i2c_hid;
/// x86 only: the 8042 controller and the multiboot framebuffer are PC
/// firmware. An AArch64 board reports its console over the serial port.
#[cfg(x86_any)]
pub mod input;
/// Off x86 the keyboard is the serial console; see `input_serial.rs`.
#[cfg(not(x86_any))]
#[path = "input_serial.rs"]
pub mod input;
pub mod multiboot;
pub mod panic;
/// x86 only: the 8042 controller and the multiboot framebuffer are PC
/// firmware. An AArch64 board reports its console over the serial port.
#[cfg(x86_any)]
pub mod panic_screen;
/// x86 only: PCI configuration space is reached through I/O ports.
#[cfg(x86_any)]
pub mod pci;
pub mod pmu;
/// x86 only: it needs the multiboot framebuffer.
#[cfg(x86_any)]
pub mod progress;
/// Off x86 there is no boot-progress marker to paint (it draws before the
/// interface on the multiboot framebuffer); the same calls are no-ops.
#[cfg(not(x86_any))]
pub mod progress {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Phase { Entered, CpuFeatures, Pmu, Counter, Pci, Hypervisor, Acpi, Input, Interface }
    pub fn attach(_fb: Option<crate::framebuffer::Framebuffer>) {}
    pub fn enter(_phase: Phase) {}
    pub fn leave(_phase: Phase) {}
    pub fn phase<T>(_phase: Phase, body: impl FnOnce() -> T) -> T { body() }
}
pub mod selftest;
pub mod serial;
pub mod text;
/// x86 only: the text buffer is PC firmware.
#[cfg(x86_any)]
pub mod vga;
/// x86 only for now: the controller is found through PCI.
#[cfg(x86_any)]
pub mod xhci;

pub use nanochrono_core::{arch as core_arch, cpu, Backend, Integrity, Protected, SimdFamily};

/// Crate version, from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
