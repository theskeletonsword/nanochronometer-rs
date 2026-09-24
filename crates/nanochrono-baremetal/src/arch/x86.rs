// SPDX-License-Identifier: Apache-2.0
//! Privileged x86-64 instructions, and the one unprivileged instruction Rust
//! has no intrinsic for.
//!
//! `core::arch::x86_64` provides `_rdtsc` and `__rdtscp`, but **not**
//! `_rdpmc`: stdarch lists it in `missing_x86_common.txt`, so it is a known
//! gap rather than a different name. `RDMSR`, `WRMSR` and port I/O have no
//! intrinsics either, being privileged. All of it is `core::arch::asm!`.

pub use nanochrono_core::arch::x86::cpuid;

/// `RDPMC` — reads performance counter `index`.
///
/// The counter number goes in `ECX`; bit 30 selects a fixed-function counter.
/// The result arrives as `EDX:EAX`, sign-extended above the counter's real
/// width, so the caller must mask it — see `pmu::CorePmu::read`.
///
/// # Safety
/// Faults with `#GP` at CPL > 0 unless `CR4.PCE` is set, and with `#GP` at any
/// privilege level if `index` names a counter the CPU does not implement. The
/// caller must be at CPL 0, or have enabled user access, and must have checked
/// the index against `CPUID.0AH`.
#[inline]
pub unsafe fn rdpmc(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: the caller guarantees the privilege level and a valid index.
    // RDPMC reads a counter and writes only EDX:EAX.
    unsafe {
        core::arch::asm!(
            "rdpmc",
            in("ecx") index,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | low as u64
}

/// `RDMSR` — reads model-specific register `msr`.
///
/// # Safety
/// Privileged: `#GP` at CPL > 0. Also `#GP` if the MSR is not implemented,
/// which is not detectable in advance for most of them — the caller must know
/// the MSR exists on this part.
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: the caller guarantees CPL 0 and that the MSR exists.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | low as u64
}

/// `WRMSR` — writes model-specific register `msr`.
///
/// # Safety
/// Privileged, and far more dangerous than the read: many MSRs change how the
/// processor executes, and a reserved-bit write raises `#GP`. The caller must
/// be at CPL 0 and must know the MSR's layout on this part.
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: the caller guarantees CPL 0 and a valid value for this MSR.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// `OUT` — writes a byte to an I/O port.
///
/// # Safety
/// Privileged, and the effect depends entirely on what is wired to the port.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller guarantees CPL 0 and that the port is safe to write.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value,
                         options(nomem, nostack, preserves_flags));
    }
}

/// `IN` — reads a byte from an I/O port.
///
/// # Safety
/// Privileged. Reading some ports has side effects on the device behind them.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees CPL 0 and that the read is harmless.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value,
                         options(nomem, nostack, preserves_flags));
    }
    value
}

#[cfg(target_arch = "x86_64")]
/// Names of the architectural exception vectors, for the report.
const EXCEPTION_NAMES: [&str; 32] = [
    "#DE divide error",
    "#DB debug",
    "NMI",
    "#BP breakpoint",
    "#OF overflow",
    "#BR bound range",
    "#UD invalid opcode",
    "#NM device not available",
    "#DF double fault",
    "coprocessor segment overrun",
    "#TS invalid TSS",
    "#NP segment not present",
    "#SS stack fault",
    "#GP general protection",
    "#PF page fault",
    "reserved",
    "#MF x87 floating point",
    "#AC alignment check",
    "#MC machine check",
    "#XM SIMD floating point",
    "#VE virtualization",
    "#CP control protection",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "#HV hypervisor injection",
    "#VC VMM communication",
    "#SX security",
    "reserved",
];

#[cfg(target_arch = "x86_64")]
/// Set on entry to the handler, so a fault *inside* the report — a bad
/// framebuffer, a UART that is not there — halts instead of recursing.
static IN_EXCEPTION: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
/// Entered from the IDT stubs in `boot32.S` with a pointer to
/// `[vector, error, RIP, CS, RFLAGS, RSP, SS]`. Reports and never returns.
///
/// Goes through `panic!` so the report reaches the framebuffer's panic screen
/// as well as the UART: on a laptop with no serial port the screen is the
/// only place a fault can be seen.
#[no_mangle]
extern "C" fn nanochrono_x86_exception(frame: *const u64) -> ! {
    if IN_EXCEPTION.swap(true, core::sync::atomic::Ordering::Relaxed) {
        crate::arch::halt();
    }
    // SAFETY: the stub passes the seven quadwords it and the CPU just pushed.
    let f = unsafe { core::slice::from_raw_parts(frame, 7) };
    let vector = f[0] as usize;
    let cr2: u64;
    // SAFETY: reading CR2 at CPL 0 has no side effects.
    unsafe {
        core::arch::asm!("mov {v}, cr2", v = out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    extern "C" {
        static nc_stack_guard: u8;
    }
    let guard = &raw const nc_stack_guard as u64;
    if vector == 14 && (guard..guard + 4096).contains(&cr2) {
        panic!(
            "kernel stack overflow: write to the guard page at {:#x} from rip={:#x}",
            cr2, f[2]
        );
    }
    panic!(
        "CPU exception {} ({}) error={:#x} rip={:#x} rsp={:#x} rflags={:#x} cr2={:#x}",
        vector,
        EXCEPTION_NAMES.get(vector).copied().unwrap_or("?"),
        f[1],
        f[2],
        f[5],
        f[4],
        cr2
    );
}
