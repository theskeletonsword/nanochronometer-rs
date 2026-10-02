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

/// `CR4`.
#[cfg(target_arch = "x86_64")]
pub fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: reading CR4 at CPL 0 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// `CR4`.
#[cfg(target_arch = "x86")]
pub fn read_cr4() -> u64 {
    let v: u32;
    // SAFETY: reading CR4 at CPL 0 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v as u64
}

/// Writes `CR4`.
///
/// # Safety
/// CPL 0, and `value` must be legal for this part — a bit for a feature it
/// lacks is `#GP` (see `nanochrono_core::cpu_control`, which decides them).
pub unsafe fn write_cr4(value: u64) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags));
        #[cfg(target_arch = "x86")]
        core::arch::asm!("mov cr4, {}", in(reg) value as u32, options(nostack, preserves_flags));
    }
}

/// Invalidates every TLB entry, global ones included.
///
/// A `CR3` reload leaves global entries cached, and with `CR4.PGE` set the
/// boot map's first gigabyte is global (boot32.S), so code that edits those
/// entries — the plugin guard pages, ring 3's user pages — flushes here:
/// toggling `CR4.PGE` invalidates everything, for every PCID too (SDM Vol. 3A
/// 4.10.4.1). Without PGE a `CR3` reload is the same thing.
///
/// # Safety
/// CPL 0, paging on.
#[cfg(target_arch = "x86_64")]
pub unsafe fn flush_tlb_all() {
    const PGE: u64 = 1 << 7;
    let cr4 = read_cr4();
    // SAFETY: CPL 0 (this function's contract); PGE is only toggled when it
    // is already set, so the part supports it.
    unsafe {
        if cr4 & PGE != 0 {
            write_cr4(cr4 & !PGE);
            write_cr4(cr4);
        } else {
            core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack, preserves_flags));
        }
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

/// A short, bus-speed delay: a write to the POST diagnostic port `0x80`.
///
/// Nothing decodes the port on a modern board, but the write still crosses
/// the LPC/eSPI bus and takes about a microsecond whatever the CPU's clock —
/// which is what a legacy device such as the 8042 needs between a command
/// and the next status read. A spin loop's length depends on the CPU and is
/// shorter on exactly the fast machines where the gap matters.
///
/// # Safety
/// Privileged. Harmless on every PC: the port is the POST code latch.
#[inline]
pub unsafe fn io_wait() {
    // SAFETY: the caller guarantees CPL 0; port 0x80 has no side effects
    // beyond a POST display some boards have.
    unsafe { outb(0x80, 0) };
}

#[cfg(x86_any)]
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
/// First stage of every CPU exception, before the crash path. A fault that
/// belongs to the running plugin — in its own code, or on its stack's guard
/// pages — is contained: the plugin runtime rewrites `frame` to resume on the
/// kernel's stack, and this returns 1 so the stub pops it and `iretq`s. Any
/// other fault returns 0 and goes on to [`nanochrono_x86_exception`]: a fault
/// in kernel code is never hidden.
#[no_mangle]
extern "C" fn nanochrono_x86_trap(frame: *mut crate::crashdump::TrapFrame) -> u64 {
    // CR2 first, before anything else can fault and replace it.
    let cr2: u64;
    // SAFETY: reading CR2 at CPL 0 has no side effects.
    unsafe {
        core::arch::asm!("mov {v}, cr2", v = out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: the stub passes the frame it and the CPU just pushed, and only
    // this function touches it until the stub resumes from it.
    let f = unsafe { &mut *frame };
    crate::ncplu::contain_fault(f, cr2) as u64
}

#[cfg(x86_any)]
/// Set on entry to the handler, so a fault *inside* the report — a bad
/// framebuffer, a UART that is not there — halts instead of recursing.
static IN_EXCEPTION: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(x86_any)]
/// The floating-point state at the fault — MXCSR and the x87 status word,
/// which say what an `#XM` or `#MF` was — read before anything can change
/// it, and then a clean state for the report's own code: every exception
/// masked and nothing pending. The faulting MXCSR still has its exception
/// unmasked, and an x87 one stays pending until cleared, so the first float
/// operation of the report would fault again — inside the report, which
/// ends in the nested-fault halt instead of the stop screen. (CR0.TS, for an
/// `#NM`, is cleared by the stubs, before any Rust.)
fn take_fp_state() -> (u32, u16) {
    let mut mxcsr: u32 = 0;
    let mut fsw: u16 = 0;
    let clean: u32 = 0x1F80;
    // SAFETY: SSE and x87 are enabled at boot (boot32.S / boot_i386.S) and
    // CR0.TS is clear; the stores go to the locals, the loads come from one.
    unsafe {
        core::arch::asm!(
            "stmxcsr [{m}]",
            "fnstsw [{s}]",
            "fninit",
            "ldmxcsr [{c}]",
            m = in(reg) &mut mxcsr,
            s = in(reg) &mut fsw,
            c = in(reg) &clean,
            options(nostack),
        );
    }
    (mxcsr, fsw)
}

#[cfg(x86_any)]
/// What the report adds for a floating-point fault: the x87 status word for
/// `#MF`, MXCSR for `#XM` — their flags say which exception it was.
struct FpDetail {
    vector: usize,
    mxcsr: u32,
    fsw: u16,
}

#[cfg(x86_any)]
impl core::fmt::Display for FpDetail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.vector {
            16 => write!(f, " fsw={:#06x}", self.fsw),
            19 => write!(f, " mxcsr={:#06x}", self.mxcsr),
            _ => Ok(()),
        }
    }
}

#[cfg(target_arch = "x86_64")]
/// Entered from the IDT stubs in `boot32.S` with a pointer to the saved
/// general registers and the CPU's frame — see `crashdump::TrapFrame`.
/// Records the state for the crash dump, then reports and never returns.
///
/// Goes through `panic!` so the report reaches the framebuffer's panic screen
/// as well as the UART: on a laptop with no serial port the screen is the
/// only place a fault can be seen.
#[no_mangle]
extern "C" fn nanochrono_x86_exception(frame: *const crate::crashdump::TrapFrame) -> ! {
    // SAFETY: the stub passes the frame it and the CPU just pushed.
    let f = unsafe { &*frame };
    // CR2 first: a later page fault, even a nested one, would replace it.
    let cr2: u64;
    // SAFETY: reading CR2 at CPL 0 has no side effects.
    unsafe {
        core::arch::asm!("mov {v}, cr2", v = out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    let (mxcsr, fsw) = take_fp_state();
    if IN_EXCEPTION.swap(true, core::sync::atomic::Ordering::Relaxed) {
        // A fault inside the report. Said with nothing but port writes —
        // `core::fmt`, the framebuffer and the dump writer are all suspects
        // now — and then stopped, rather than recursing into a third fault.
        crate::serial::write_uart_only(b"\r\nnested exception: vector ");
        crate::crashdump::raw_hex(f.vector);
        crate::serial::write_uart_only(b" rip ");
        crate::crashdump::raw_hex(f.rip);
        crate::serial::write_uart_only(b" cr2 ");
        crate::crashdump::raw_hex(cr2);
        crate::serial::write_uart_only(b"\r\nhalted\r\n");
        crate::arch::halt();
    }
    // SAFETY: once, here, before the panic that writes the dump.
    unsafe { crate::crashdump::record_exception(f, cr2) };

    let vector = f.vector as usize;
    extern "C" {
        static nc_stack_guard: u8;
    }
    let guard = &raw const nc_stack_guard as u64;
    if vector == 14 && (guard..guard + 4096).contains(&cr2) {
        panic!(
            "kernel stack overflow: write to the guard page at {:#x} from rip={:#x}",
            cr2, f.rip
        );
    }
    panic!(
        "CPU exception {} ({}) error={:#x} rip={:#x} rsp={:#x} rflags={:#x} cr2={:#x}{}",
        vector,
        EXCEPTION_NAMES.get(vector).copied().unwrap_or("?"),
        f.error,
        f.rip,
        f.rsp,
        f.rflags,
        cr2,
        FpDetail { vector, mxcsr, fsw }
    );
}

#[cfg(target_arch = "x86")]
/// What the i386 exception stubs in `boot_i386.S` leave on the stack: the
/// general registers as `pusha` stores them — its ESP slot rewritten to the
/// ESP at the fault — then the vector and error code, then the frame the CPU
/// pushed (no SS:ESP: nothing runs outside ring 0). The double-fault task
/// builds the same frame from the state the task switch saved.
#[repr(C)]
pub struct TrapFrame32 {
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub vector: u32,
    pub error: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
}

#[cfg(target_arch = "x86")]
/// Entered from the i386 IDT — the stubs in `boot_i386.S`, or its
/// double-fault task — with the frame above. Reports and never returns:
/// through `panic!`, to the UART and the stop screen, as on x86_64 (which
/// adds the crash dump).
#[no_mangle]
extern "C" fn nanochrono_i386_exception(frame: *const TrapFrame32) -> ! {
    // SAFETY: the stub passes the frame it built.
    let f = unsafe { &*frame };
    // CR2: the linear address a page fault was about (stale for any other
    // vector, and reported for all of them, as x86_64 does).
    let cr2: u32;
    // SAFETY: reading CR2 at CPL 0 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags)) };
    let (mxcsr, fsw) = take_fp_state();
    if IN_EXCEPTION.swap(true, core::sync::atomic::Ordering::Relaxed) {
        // A fault inside the report: port writes only, then stop.
        crate::serial::write_uart_only(b"\r\nnested exception: vector ");
        crate::crashdump::raw_hex(f.vector as u64);
        crate::serial::write_uart_only(b" eip ");
        crate::crashdump::raw_hex(f.eip as u64);
        crate::serial::write_uart_only(b"\r\nhalted\r\n");
        crate::arch::halt();
    }
    let vector = f.vector as usize;
    panic!(
        "CPU exception {} ({}) error={:#x} eip={:#x} esp={:#x} eflags={:#x} cr2={:#x} \
         eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x} ebp={:#x}{}",
        vector,
        EXCEPTION_NAMES.get(vector).copied().unwrap_or("?"),
        f.error,
        f.eip,
        f.esp,
        f.eflags,
        cr2,
        f.eax,
        f.ebx,
        f.ecx,
        f.edx,
        f.esi,
        f.edi,
        f.ebp,
        FpDetail { vector, mxcsr, fsw }
    );
}
