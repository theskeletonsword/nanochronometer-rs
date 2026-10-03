// SPDX-License-Identifier: Apache-2.0
//! The machine as the shell and the desktop see it: the calibrated clock,
//! the PMU, the hypervisor report, the memory the loader described and the
//! power registers — probed once, when a session starts, and shared.
//!
//! The classic interface (`gui_frame`) keeps its own copy of the same probes;
//! the CLI and the desktop start from this one.

use crate::clock::Clock;
use crate::multiboot::Memory;
use crate::pmu::{CorePmu, CounterRoute};
use crate::vfs::Proc;
use core::fmt::Write;

/// What a session knows about the machine.
pub struct System {
    pub clock: Clock,
    pub pmu: CorePmu,
    pub route: CounterRoute,
    pub hypervisor: crate::hypervisor::Report,
    pub memory: Memory,
    pub acpi: Option<crate::acpi::PowerRegisters>,
}

static mut SYSTEM: Option<System> = None;

/// Probes the machine, once.
///
/// # Safety
/// Kernel privilege (the PMU, the PIT, firmware tables); once, at the start
/// of a session, on one core.
pub unsafe fn init(memory: Memory) -> &'static System {
    // SAFETY: forwarded from this function's own contract.
    let clock = unsafe { Clock::start() };
    let mut pmu = CorePmu::detect();
    let route = if pmu.is_available() {
        // SAFETY: as above.
        unsafe { pmu.enable() }
    } else {
        CounterRoute::None
    };
    // SAFETY: as above.
    let hypervisor = unsafe { crate::hypervisor::detect() };
    // SAFETY: as above.
    let acpi = unsafe { crate::acpi::power_registers() };
    // SAFETY: once, before anything reads it.
    unsafe {
        *core::ptr::addr_of_mut!(SYSTEM) = Some(System { clock, pmu, route, hypervisor, memory, acpi });
    }
    let system = get().expect("just set");
    crate::rng::attach_pmu(&system.pmu);
    system
}

/// The machine, once [`init`] has run.
pub fn get() -> Option<&'static System> {
    // SAFETY: written once by `init`, read-only after.
    unsafe { (*core::ptr::addr_of!(SYSTEM)).as_ref() }
}

impl System {
    pub fn hz(&self) -> u64 {
        self.clock.calibration.hz
    }

    /// Nanoseconds since the session's clock started.
    pub fn uptime_ns(&self) -> u64 {
        self.clock.elapsed_ns()
    }

    /// The PMU, where there is one to read.
    pub fn pmu_for_load(&self) -> Option<&CorePmu> {
        (self.route != CounterRoute::None).then_some(&self.pmu)
    }
}

/// The instruction set, as `uname -m` names it.
pub const MACHINE: &str = if cfg!(target_arch = "x86_64") {
    "x86_64"
} else if cfg!(target_arch = "x86") {
    "i686"
} else if cfg!(target_arch = "aarch64") {
    "aarch64"
} else if cfg!(target_arch = "arm") {
    "armv7l"
} else if cfg!(all(target_arch = "powerpc64", target_endian = "little")) {
    "ppc64le"
} else if cfg!(target_arch = "powerpc64") {
    "ppc64"
} else if cfg!(target_arch = "powerpc") {
    "ppc"
} else if cfg!(target_arch = "riscv64") {
    "riscv64"
} else if cfg!(target_arch = "riscv32") {
    "riscv32"
} else {
    "unknown"
};

/// Writes one of `/proc`'s files.
pub fn proc_file(p: Proc, out: &mut dyn Write) {
    let system = get();
    match p {
        Proc::Version => {
            let _ = writeln!(out, "NanoChronometer {} ({}) freestanding, no operating system", crate::VERSION, MACHINE);
        }
        Proc::Cmdline => {
            let _ = writeln!(out, "{}", crate::boot::command_line());
        }
        Proc::Initramdisk => crate::initramdisk::report(out),
        Proc::Uptime => {
            let ns = system.map_or(0, |s| s.uptime_ns());
            let _ = writeln!(out, "{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000);
        }
        Proc::Meminfo => meminfo(out, system),
        Proc::Cpuinfo => cpuinfo(out, system),
        Proc::Cpuctl => match crate::cpu_control::report() {
            Some(r) => {
                let _ = writeln!(out, "{}: {:#x} -> {:#x}", r.register, r.before, r.after);
                if let Some((name, before, after)) = r.extra {
                    let _ = writeln!(out, "{name}: {before:#x} -> {after:#x}");
                }
                for d in r.decisions() {
                    if d.bit == 0xFF {
                        let _ = writeln!(out, "{:<10} {:<12} {:<3} {}", d.register, d.name, if d.on { "on" } else { "off" }, d.reason);
                    } else {
                        let mut place = crate::text::Text::<16>::new();
                        let _ = write!(place, "{}.{}", d.register, d.bit);
                        let _ = writeln!(out, "{:<10} {:<12} {:<3} {}", place.as_str(), d.name, if d.on { "on" } else { "off" }, d.reason);
                    }
                }
            }
            None => {
                let _ = writeln!(out, "not configured yet");
            }
        },
        Proc::Modules => {
            for m in crate::boot::modules() {
                let _ = writeln!(out, "{:#010x}-{:#010x} {:>9} {}", m.start, m.end, m.end - m.start, m.name);
            }
        }
        Proc::Kmsg => {
            let (a, b) = crate::serial::klog::contents();
            crate::vfs::write_bytes(out, a);
            crate::vfs::write_bytes(out, b);
        }
    }
}

/// Where the kernel's memory goes: the image's sections, and in it the big
/// static pools, against what the loader said the machine has.
pub fn meminfo(out: &mut dyn Write, system: Option<&System>) {
    let total = system.map_or(0, |s| s.memory.total);
    let image = crate::multiboot::kernel_footprint();
    let kib = |b: u64| b / 1024;
    let pages = crate::palloc::stats();
    if total > 0 {
        let _ = writeln!(out, "MemTotal:      {:>10} kB", kib(total));
        let _ = writeln!(out, "MemFree:       {:>10} kB", kib(total.saturating_sub(image).saturating_sub(pages.in_use)));
    } else {
        let _ = writeln!(out, "MemTotal:      {:>10}    (the loader did not say)", "?");
    }
    let _ = writeln!(out, "KernelImage:   {:>10} kB   text, data and every static pool", kib(image));
    for (name, bytes) in crate::memstat::pools() {
        let _ = writeln!(out, "  {:<12}{:>10} kB", name, kib(bytes));
    }
    if crate::palloc::ready() {
        let _ = writeln!(out, "Pages:         {:>10} kB   handed out by the page allocator", kib(pages.in_use));
        let back = crate::framebuffer::dynamic_back_buffer_bytes() as u64;
        if back > 0 {
            let _ = writeln!(out, "  {:<12}{:>10} kB", "back buffer", kib(back));
        }
        let _ = writeln!(
            out,
            "PagesFree:     {:>10} kB   below {} MiB, in {} runs",
            kib(pages.free),
            crate::palloc::CEILING >> 20,
            pages.runs
        );
    } else {
        let _ = writeln!(out, "Pages:         {:>10} kB   (no page allocator: the loader gave no memory map)", 0);
    }
    let _ = writeln!(out, "Heap:          {:>10} kB   (none: pages only, no general allocator)", 0);
}

fn cpuinfo(out: &mut dyn Write, system: Option<&System>) {
    let f = nanochrono_core::cpu::features();
    let _ = writeln!(out, "architecture   : {}", MACHINE);
    #[cfg(x86_any)]
    {
        let _ = writeln!(out, "vendor         : {}", nanochrono_core::cpu::vendor().name());
        let mut brand = [0u8; 48];
        for (i, leaf) in [0x8000_0002u32, 0x8000_0003, 0x8000_0004].iter().enumerate() {
            let r = nanochrono_core::arch::x86::cpuid(*leaf, 0);
            for (j, word) in r.iter().enumerate() {
                brand[i * 16 + j * 4..i * 16 + j * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        let end = brand.iter().position(|&b| b == 0).unwrap_or(48);
        let _ = writeln!(out, "model name     : {}", core::str::from_utf8(&brand[..end]).unwrap_or("?").trim());
    }
    if let Some(s) = system {
        let _ = writeln!(out, "counter        : {} Hz ({})", s.hz(), s.clock.calibration.source.name());
        let _ = writeln!(out, "pmu            : {}", s.route.name());
        let _ = writeln!(out, "hypervisor     : {}", if s.hypervisor.is_virtualized() { s.hypervisor.signature_str() } else { "none" });
    }
    let _ = write!(out, "flags          :");
    let flags: &[(&str, bool)] = &[
        ("sse2", f.sse2),
        ("avx", f.avx),
        ("avx2", f.avx2),
        ("avx512f", f.avx512f),
        ("aes", f.aesni),
        ("sha", f.shani),
        ("neon", f.neon),
        ("sve", f.sve),
        ("sve2", f.sve2),
        ("sme", f.sme),
        ("rvv", f.rvv),
        ("altivec", f.altivec),
        ("invariant_counter", f.invariant_counter),
    ];
    for (name, on) in flags {
        if *on {
            let _ = write!(out, " {name}");
        }
    }
    let _ = writeln!(out);
}
