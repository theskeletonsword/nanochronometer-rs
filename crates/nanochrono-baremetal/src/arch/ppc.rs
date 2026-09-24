// SPDX-License-Identifier: Apache-2.0
//! PowerPC: entry, firmware calls and the privileged registers.
//!
//! Two machines, one per word size, both the plainest a freestanding kernel
//! can target:
//!
//! * **64-bit (`ppc64`, `ppc64le`) — OpenPOWER `powernv`.** Bare metal in
//!   hypervisor state, booted by skiboot, which hands over a device tree in
//!   r3 and its own entry point (OPAL) in r8/r9. The console is OPAL's; the
//!   UART behind it sits on an LPC bus whose address changes per chip.
//! * **32-bit (`ppc`) — Freescale/NXP e500 (QEMU `ppce500`, `-cpu e500mc`).**
//!   Book E, booted the ePAPR way: device tree in r3, a TLB1 entry already
//!   mapping RAM, and a 16550 UART inside the CCSR block, which this kernel
//!   maps itself.
//!
//! # Entry state and what the stub fixes
//!
//! | | powernv | e500 |
//! |---|---|---|
//! | Endianness | big, always — skiboot is BE | big |
//! | MMU | off (real mode) | on, one TLB1 entry over RAM |
//! | Stack | skiboot's | QEMU's r1 = 16 MiB − 8 |
//! | FP / VMX / VSX | off (`MSR[FP,VEC,VSX]` = 0) | FP off |
//!
//! Every Rust function may touch the FPRs — and on the POWER8 target the
//! vector registers, which LLVM uses for `memcpy` — so `MSR[FP]` (and
//! `MSR[VEC]`, `MSR[VSX]` on 64-bit) are set before the first call. A
//! floating-point or vector instruction with its MSR bit clear is not slow,
//! it is a "facility unavailable" interrupt.
//!
//! # Little-endian on firmware that is not
//!
//! skiboot enters every kernel big-endian. A `ppc64le` image therefore opens
//! with a sequence that reads as one thing to a big-endian core and another
//! to a little-endian one: `tdi 0,0,0x48` assembled little-endian is the
//! bytes `48 00 00 08`, which a big-endian core decodes as `b .+8`. The
//! big-endian path lands on eight instructions stored as literal big-endian
//! bytes — set `MSR[LE]`, `rfid` to the next instruction — and the
//! little-endian path steps over them. Every OPAL call makes the same trip
//! in reverse and back, because OPAL is big-endian too.
//!
//! # Stack and ABI
//!
//! `r1` is 16-byte aligned with a zero back chain in the first frame, which
//! is what both ABIs require at a call: ELFv2's minimum frame is 32 bytes,
//! the 32-bit SysV one 16. `r2` is the TOC pointer on 64-bit (ELFv2 static
//! code still addresses its globals through it), set from `.TOC.` before
//! anything else. The red zone ELFv2 allows below `r1` is disabled in the
//! target spec, as on the other architectures.

use core::arch::asm;

/// `MSR[FP]`.
pub const MSR_FP: u64 = 0x2000;
/// `MSR[VEC]` (64-bit Book3S).
pub const MSR_VEC: u64 = 0x0200_0000;
/// `MSR[VSX]` (64-bit Book3S).
pub const MSR_VSX: u64 = 0x0080_0000;
/// `MSR[HV]` (64-bit Book3S): hypervisor state.
pub const MSR_HV: u64 = 1 << 60;

/// The Machine State Register.
#[inline]
pub fn msr() -> u64 {
    let v: usize;
    // SAFETY: `mfmsr` is legal in supervisor state, which is the only state
    // this kernel runs in, and has no side effects.
    unsafe { asm!("mfmsr {v}", v = out(reg) v, options(nomem, nostack, preserves_flags)) };
    v as u64
}

/// The Processor Version Register.
#[inline]
pub fn pvr() -> u32 {
    let v: usize;
    // SAFETY: as above.
    unsafe { asm!("mfpvr {v}", v = out(reg) v, options(nomem, nostack, preserves_flags)) };
    v as u32
}

/// A name for the core, from the PVR's version half.
pub fn core_name(pvr: u32) -> &'static str {
    match pvr >> 16 {
        0x004B => "POWER8E",
        0x004C => "POWER8NVL",
        0x004D => "POWER8",
        0x004E => "POWER9",
        0x0080 => "POWER10",
        0x0082 => "POWER11",
        0x003F => "POWER7",
        0x004A => "POWER7+",
        0x0039 | 0x003C | 0x0044 | 0x0045 => "PowerPC 970",
        0x8020 => "e500v1",
        0x8021 => "e500v2",
        0x8023 => "e500mc",
        0x8024 => "e5500",
        0x8040 => "e6500",
        0x000C | 0x800C | 0x8000..=0x8004 => "PowerPC 74xx (G4)",
        0x0008 => "PowerPC 750 (G3)",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// 64-bit: powernv entry and OPAL
// ---------------------------------------------------------------------------

/// A big-endian → little-endian switch that resumes at the instruction after
/// it, as literal big-endian bytes (so the same bytes are emitted whichever
/// endianness the assembler targets):
///
/// ```text
/// mfmsr  r11
/// ori    r11, r11, 1        ; MSR[LE]
/// bcl    20, 31, .+4        ; LR = address of the next instruction
/// mflr   r12
/// addi   r12, r12, 20       ; -> the first instruction after rfid
/// mtsrr0 r12
/// mtsrr1 r11
/// rfid
/// ```
///
/// Encodings produced by the LLVM assembler for `powerpc64`. Clobbers r11,
/// r12, LR, SRR0 and SRR1 — nothing an entry point or a call return needs.
#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
macro_rules! be_to_le_switch {
    () => {
        "
    .byte 0x7d, 0x60, 0x00, 0xa6
    .byte 0x61, 0x6b, 0x00, 0x01
    .byte 0x42, 0x9f, 0x00, 0x05
    .byte 0x7d, 0x88, 0x02, 0xa6
    .byte 0x39, 0x8c, 0x00, 0x14
    .byte 0x7d, 0x9a, 0x03, 0xa6
    .byte 0x7d, 0x7b, 0x03, 0xa6
    .byte 0x4c, 0x00, 0x00, 0x24
"
    };
}

#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
core::arch::global_asm!(
    "
.section .text.boot, \"ax\"
.global _start
_start:
    // Big-endian core: `b .+8`, into the switch. Little-endian: a trap that
    // never fires (TO = 0), then over the switch.
    tdi 0, 0, 0x48
    b 1f
",
    be_to_le_switch!(),
    "
1:
    b nc_ppc64_common_entry
"
);

#[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
core::arch::global_asm!(
    "
.section .text.boot, \"ax\"
.global _start
_start:
    b nc_ppc64_common_entry
"
);

#[cfg(target_arch = "powerpc64")]
core::arch::global_asm!(
    "
.section .text.boot, \"ax\"
nc_ppc64_common_entry:
    // skiboot: r3 = device tree, r8 = OPAL base, r9 = OPAL entry. Kept in
    // non-volatile registers across the setup below.
    mr 29, 3
    mr 30, 8
    mr 31, 9

    // The TOC pointer, PC-relative so it is right wherever this runs.
    bcl 20, 31, 0f
0:  mflr 12
    addis 2, 12, (.TOC. - 0b)@ha
    addi 2, 2, (.TOC. - 0b)@l

    // Zero .bss (8-byte stores; the linker script aligns both bounds).
    addis 4, 2, __bss_start@toc@ha
    addi 4, 4, __bss_start@toc@l
    addis 5, 2, __bss_end@toc@ha
    addi 5, 5, __bss_end@toc@l
    li 0, 0
2:  cmpld 4, 5
    bge 3f
    std 0, 0(4)
    addi 4, 4, 8
    b 2b

3:  // Our stack, 16-byte aligned, with one 32-byte ELFv2 frame whose back
    // chain is zero so a stack walk terminates.
    addis 1, 2, nc_stack_top@toc@ha
    addi 1, 1, nc_stack_top@toc@l
    stdu 0, -32(1)

    // FP, VMX and VSX on, before any Rust — see the module documentation.
    mfmsr 11
    ori 11, 11, 0x2000
    oris 11, 11, 0x0280
    mtmsrd 11
    isync

    // A defined FPSCR (all exceptions disabled, round to nearest) and VSCR
    // (Java mode, no saturation) rather than whatever firmware left.
    std 0, 24(1)
    lfd 0, 24(1)
    mtfsf 255, 0
    vxor 0, 0, 0
    mtvscr 0

    addis 4, 2, nc_opal_base@toc@ha
    std 30, nc_opal_base@toc@l(4)
    addis 4, 2, nc_opal_entry@toc@ha
    std 31, nc_opal_entry@toc@l(4)

    mr 3, 29
    mr 4, 30
    mr 5, 31
    bl kmain
    nop
4:  b 4b

.section .bss.nc_stack, \"aw\", @nobits
.balign 16
nc_stack_bottom:
    .skip 65536
nc_stack_top:

.section .data.nc_opal, \"aw\"
.balign 8
.global nc_opal_base
nc_opal_base:
    .quad 0
.global nc_opal_entry
nc_opal_entry:
    .quad 0
"
);

// Calls OPAL: r0 = token, r3.. = arguments, in big-endian real mode with
// r2 = OPAL's base. OPAL preserves r1 and the non-volatile registers but
// not r2, so the TOC is saved in the ELFv2 TOC slot and restored.
#[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
core::arch::global_asm!(
    "
.section .text.nc_opal_call, \"ax\"
.global nc_opal_call
nc_opal_call:
    mflr 0
    std 0, 16(1)
    std 2, 24(1)
    stdu 1, -64(1)
    addis 11, 2, nc_opal_entry@toc@ha
    ld 11, nc_opal_entry@toc@l(11)
    addis 12, 2, nc_opal_base@toc@ha
    ld 12, nc_opal_base@toc@l(12)
    mtctr 11
    mr 0, 3
    mr 3, 4
    mr 4, 5
    mr 5, 6
    mr 2, 12
    bctrl
    addi 1, 1, 64
    ld 2, 24(1)
    ld 0, 16(1)
    mtlr 0
    blr
"
);

// The little-endian call: `rfid` into OPAL with `MSR[LE]` clear and LR
// pointing at a big-endian switch back, which `rfid`s to the instruction
// after itself with `MSR[LE]` set again.
#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
core::arch::global_asm!(
    "
.section .text.nc_opal_call, \"ax\"
.global nc_opal_call
nc_opal_call:
    mflr 0
    std 0, 16(1)
    std 2, 24(1)
    stdu 1, -64(1)
    addis 11, 2, nc_opal_entry@toc@ha
    ld 11, nc_opal_entry@toc@l(11)
    addis 12, 2, nc_opal_base@toc@ha
    ld 12, nc_opal_base@toc@l(12)
    mr 0, 3
    mr 3, 4
    mr 4, 5
    mr 5, 6
    mtsrr0 11
    mfmsr 11
    rldicr 11, 11, 0, 62
    mtsrr1 11
    mr 2, 12
    bcl 20, 31, 1f
1:  mflr 12
    addi 12, 12, (2f - 1b)
    mtlr 12
    rfid
2:
",
    be_to_le_switch!(),
    "
    addi 1, 1, 64
    ld 2, 24(1)
    ld 0, 16(1)
    mtlr 0
    blr
"
);

#[cfg(target_arch = "powerpc64")]
extern "C" {
    fn nc_opal_call(token: u64, a0: u64, a1: u64, a2: u64) -> i64;
}

/// OPAL token: write to a console.
#[cfg(target_arch = "powerpc64")]
pub const OPAL_CONSOLE_WRITE: u64 = 1;
/// OPAL token: read from a console.
#[cfg(target_arch = "powerpc64")]
pub const OPAL_CONSOLE_READ: u64 = 2;
/// OPAL token: power the machine off.
#[cfg(target_arch = "powerpc64")]
pub const OPAL_CEC_POWER_DOWN: u64 = 5;
/// OPAL token: run OPAL's pollers (which flush the console).
#[cfg(target_arch = "powerpc64")]
pub const OPAL_POLL_EVENTS: u64 = 10;
/// OPAL return codes.
#[cfg(target_arch = "powerpc64")]
pub const OPAL_SUCCESS: i64 = 0;
#[cfg(target_arch = "powerpc64")]
pub const OPAL_BUSY: i64 = -2;
#[cfg(target_arch = "powerpc64")]
pub const OPAL_BUSY_EVENT: i64 = -12;

/// Issues an OPAL call.
///
/// # Safety
/// Only after `kmain` was entered by the boot stub (which recorded OPAL's
/// base and entry), in hypervisor real mode, with the arguments the call
/// defines. Pointer arguments are real addresses, which here are the same
/// as virtual ones because translation is off.
#[cfg(target_arch = "powerpc64")]
pub unsafe fn opal_call(token: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    // SAFETY: forwarded from this function's contract.
    unsafe { nc_opal_call(token, a0, a1, a2) }
}

/// Whether OPAL's entry point was handed over, i.e. whether calls can work.
#[cfg(target_arch = "powerpc64")]
pub fn opal_present() -> bool {
    extern "C" {
        static nc_opal_entry: u64;
    }
    // SAFETY: written once by the entry stub before any Rust ran.
    unsafe { core::ptr::read_volatile(&raw const nc_opal_entry) != 0 }
}

// ---------------------------------------------------------------------------
// 32-bit: e500 entry, TLB and exception vectors
// ---------------------------------------------------------------------------

#[cfg(target_arch = "powerpc")]
core::arch::global_asm!(
    "
.section .text.boot, \"ax\"
.global _start
_start:
    // Two boot protocols reach this entry point:
    //  * ePAPR (e500, `ppce500`): r3 = device tree, r6 = 0x45504150 (ASCII EPAP).
    //  * IEEE 1275 Open Firmware (G3/G4 Macs, Pegasos): r5 = the client
    //    interface entry, and no tree in r3.
    // r31 = tree (or 0), r30 = OF entry (or 0), r29 = 1 on ePAPR.
    lis 0, 0x4550
    ori 0, 0, 0x4150
    li 29, 0
    li 30, 0
    li 31, 0
    cmpw 6, 0
    bne 5f
    li 29, 1
    mr 31, 3
    b 6f
5:  mr 30, 5
6:

    // Zero .bss (4-byte stores; the linker script aligns both bounds).
    lis 4, __bss_start@ha
    addi 4, 4, __bss_start@l
    lis 5, __bss_end@ha
    addi 5, 5, __bss_end@l
    li 0, 0
1:  cmplw 4, 5
    bge 2f
    stw 0, 0(4)
    addi 4, 4, 4
    b 1b

2:  // Our stack, 16-byte aligned, one 16-byte SysV frame with a zero back
    // chain.
    lis 1, nc_stack_top@ha
    addi 1, 1, nc_stack_top@l
    stwu 0, -16(1)

    // MSR[FP] on before any Rust. Book E keeps the classic FPU's bit.
    mfmsr 3
    ori 3, 3, 0x2000
    mtmsr 3
    isync

    // A defined FPSCR.
    stw 0, 8(1)
    stw 0, 12(1)
    lfd 0, 8(1)
    mtfsf 255, 0

    // Book E exception vectors — e500 only. The IVPR/IVOR SPRs do not exist
    // on a classic core (G3/G4), whose vectors sit at fixed low addresses
    // that Open Firmware owns while its client interface is in use.
    cmpwi 29, 0
    beq 7f

    // Exception vectors before anything can fault: IVPR holds the upper
    // half of the table's address, IVORn the offset of each handler.
    lis 3, nc_ivor_table@h
    mtspr 63, 3
    li 3, nc_ivor_0 - nc_ivor_table
    mtspr 400, 3
    li 3, nc_ivor_1 - nc_ivor_table
    mtspr 401, 3
    li 3, nc_ivor_2 - nc_ivor_table
    mtspr 402, 3
    li 3, nc_ivor_3 - nc_ivor_table
    mtspr 403, 3
    li 3, nc_ivor_4 - nc_ivor_table
    mtspr 404, 3
    li 3, nc_ivor_5 - nc_ivor_table
    mtspr 405, 3
    li 3, nc_ivor_6 - nc_ivor_table
    mtspr 406, 3
    li 3, nc_ivor_7 - nc_ivor_table
    mtspr 407, 3
    li 3, nc_ivor_8 - nc_ivor_table
    mtspr 408, 3
    li 3, nc_ivor_9 - nc_ivor_table
    mtspr 409, 3
    li 3, nc_ivor_10 - nc_ivor_table
    mtspr 410, 3
    li 3, nc_ivor_11 - nc_ivor_table
    mtspr 411, 3
    li 3, nc_ivor_12 - nc_ivor_table
    mtspr 412, 3
    li 3, nc_ivor_13 - nc_ivor_table
    mtspr 413, 3
    li 3, nc_ivor_14 - nc_ivor_table
    mtspr 414, 3
    li 3, nc_ivor_15 - nc_ivor_table
    mtspr 415, 3
    isync

7:  mr 3, 31
    mr 4, 30
    bl kmain
3:  b 3b

// The table: IVPR supplies bits 0:47 of each handler's address, so it sits
// on a 64 KiB boundary, and each IVOR offset is 16-byte aligned. Every
// handler saves r3 in SPRG0, loads its vector number and joins the common
// path; all of them are fatal.
.section .text.nc_ivors, \"ax\"
.balign 65536
nc_ivor_table:
.irp v, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    .balign 16
nc_ivor_\\v:
    mtspr 272, 3
    li 3, \\v
    b nc_ppc32_fatal
.endr

nc_ppc32_fatal:
    // A private stack: the fault may have been a stack overflow.
    lis 1, nc_exc_stack_top@ha
    addi 1, 1, nc_exc_stack_top@l
    li 0, 0
    stwu 0, -16(1)
    // Interrupt entry clears MSR[FP]; the reporter formats numbers.
    mfmsr 4
    ori 4, 4, 0x2000
    mtmsr 4
    isync
    bl nanochrono_ppc_exception
4:  b 4b

.section .bss.nc_stack, \"aw\", @nobits
.balign 16
nc_stack_bottom:
    .skip 65536
nc_stack_top:
.balign 16
nc_exc_stack_bottom:
    .skip 16384
nc_exc_stack_top:
"
);

/// Reports a fatal Book E interrupt and stops. Entered from the vectors on
/// a private stack with r3 = the IVOR number.
#[cfg(target_arch = "powerpc")]
#[no_mangle]
extern "C" fn nanochrono_ppc_exception(vector: u32) -> ! {
    const NAMES: [&str; 16] = [
        "critical input",
        "machine check",
        "data storage",
        "instruction storage",
        "external input",
        "alignment",
        "program",
        "floating-point unavailable",
        "system call",
        "auxiliary processor unavailable",
        "decrementer",
        "fixed-interval timer",
        "watchdog timer",
        "data TLB error",
        "instruction TLB error",
        "debug",
    ];
    let (srr0, srr1, esr, dear): (usize, usize, usize, usize);
    // SAFETY: supervisor state; reading these SPRs has no side effects. The
    // save/restore pair depends on the interrupt class: critical (0, 15)
    // uses CSRR0/1, machine check MCSRR0/1, the rest SRR0/1.
    unsafe {
        match vector {
            0 | 15 => asm!("mfspr {a}, 58", "mfspr {b}, 59", a = out(reg) srr0, b = out(reg) srr1,
                           options(nomem, nostack, preserves_flags)),
            1 => asm!("mfspr {a}, 570", "mfspr {b}, 571", a = out(reg) srr0, b = out(reg) srr1,
                      options(nomem, nostack, preserves_flags)),
            _ => asm!("mfspr {a}, 26", "mfspr {b}, 27", a = out(reg) srr0, b = out(reg) srr1,
                      options(nomem, nostack, preserves_flags)),
        }
        asm!("mfspr {a}, 62", "mfspr {b}, 61", a = out(reg) esr, b = out(reg) dear,
             options(nomem, nostack, preserves_flags));
    }
    crate::println!();
    crate::println!(
        "exception: IVOR{} {}",
        vector,
        NAMES.get(vector as usize).copied().unwrap_or("?")
    );
    crate::println!("  pc={srr0:#x} msr={srr1:#x} esr={esr:#x} dear={dear:#x}");
    crate::println!("stopped; not restarting");
    crate::arch::halt()
}

/// The Open Firmware client interface (IEEE 1275, PowerPC binding), for the
/// classic 32-bit machines that boot through it: G3/G4 Macs, Pegasos.
///
/// A call passes one array of 32-bit cells — service name, argument count,
/// result count, arguments, then room for results — in r3 to the entry point
/// firmware handed over in r5, as an ordinary function call. Everything is
/// big-endian and 32-bit, which this build already is.
#[cfg(target_arch = "powerpc")]
pub mod of {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static ENTRY: AtomicUsize = AtomicUsize::new(0);
    static STDOUT: AtomicUsize = AtomicUsize::new(0);
    static STDIN: AtomicUsize = AtomicUsize::new(0);

    /// Records the client interface entry the boot stub received.
    pub fn set_entry(entry: usize) {
        ENTRY.store(entry, Ordering::Relaxed);
    }

    /// Whether this boot came through Open Firmware.
    pub fn present() -> bool {
        ENTRY.load(Ordering::Relaxed) != 0
    }

    /// One client-interface call. `service` must be NUL-terminated.
    /// Returns `None` if there is no interface or the call itself failed.
    pub fn call<const R: usize>(service: &[u8], args: &[u32]) -> Option<[u32; R]> {
        let entry = ENTRY.load(Ordering::Relaxed);
        if entry == 0 || args.len() + R > 12 || service.last() != Some(&0) {
            return None;
        }
        let mut cells = [0u32; 15];
        cells[0] = service.as_ptr() as u32;
        cells[1] = args.len() as u32;
        cells[2] = R as u32;
        cells[3..3 + args.len()].copy_from_slice(args);
        // SAFETY: `entry` is the client interface firmware passed in r5; the
        // binding defines it as a function taking the cell array in r3 and
        // returning 0 or -1 in r3, preserving the ABI's non-volatiles.
        let status = unsafe {
            let f: extern "C" fn(*mut u32) -> i32 = core::mem::transmute(entry);
            f(cells.as_mut_ptr())
        };
        if status != 0 {
            return None;
        }
        let mut out = [0u32; R];
        out.copy_from_slice(&cells[3 + args.len()..3 + args.len() + R]);
        Some(out)
    }

    /// `finddevice`: a phandle for `path` (NUL-terminated), if it exists.
    pub fn finddevice(path: &[u8]) -> Option<u32> {
        let [ph] = call::<1>(b"finddevice\0", &[path.as_ptr() as u32])?;
        (ph != 0 && ph != u32::MAX).then_some(ph)
    }

    /// `getprop`: the first four bytes of `name` (NUL-terminated) on `node`.
    pub fn getprop_u32(node: u32, name: &[u8]) -> Option<u32> {
        let mut buf = [0u8; 4];
        let [len] = call::<1>(
            b"getprop\0",
            &[node, name.as_ptr() as u32, buf.as_mut_ptr() as u32, 4],
        )?;
        (len == 4).then(|| u32::from_be_bytes(buf))
    }

    /// `child`: the first child of `node`.
    pub fn child(node: u32) -> Option<u32> {
        let [ph] = call::<1>(b"child\0", &[node])?;
        (ph != 0 && ph != u32::MAX).then_some(ph)
    }

    /// Looks up `/chosen`'s `stdout` instance once, for [`write`].
    pub fn open_console() -> bool {
        let Some(chosen) = finddevice(b"/chosen\0") else {
            return false;
        };
        if let Some(ihandle) = getprop_u32(chosen, b"stdin\0").filter(|&h| h != 0) {
            STDIN.store(ihandle as usize, Ordering::Relaxed);
        }
        match getprop_u32(chosen, b"stdout\0") {
            Some(ihandle) if ihandle != 0 => {
                STDOUT.store(ihandle as usize, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }

    /// One byte from firmware's stdin, if one is waiting. The binding's
    /// `read` does not block: it returns 0 (or -2, "no data yet").
    pub fn read_byte() -> Option<u8> {
        let ihandle = STDIN.load(Ordering::Relaxed) as u32;
        if ihandle == 0 {
            return None;
        }
        let mut byte = [0u8; 1];
        let [actual] = call::<1>(b"read\0", &[ihandle, byte.as_mut_ptr() as u32, 1])?;
        (actual == 1).then_some(byte[0])
    }

    /// Writes to firmware's stdout. Returns whether it was accepted.
    pub fn write(bytes: &[u8]) -> bool {
        let ihandle = STDOUT.load(Ordering::Relaxed) as u32;
        if ihandle == 0 {
            return false;
        }
        call::<1>(b"write\0", &[ihandle, bytes.as_ptr() as u32, bytes.len() as u32]).is_some()
    }

    /// `timebase-frequency` of the first CPU under `/cpus`.
    pub fn timebase_frequency() -> Option<u32> {
        let cpus = finddevice(b"/cpus\0")?;
        let cpu = child(cpus)?;
        getprop_u32(cpu, b"timebase-frequency\0").or_else(|| getprop_u32(cpus, b"timebase-frequency\0"))
    }
}

/// Turns on `MSR[VEC]` on a classic core with AltiVec (G4, 970 in 32-bit
/// mode). The boot stub cannot know from the target alone, and a vector
/// instruction with the bit clear is a "vector unavailable" interrupt.
///
/// # Safety
/// Supervisor state, on a core whose PVR says it has AltiVec. On e500 the
/// same bit is SPE-available and is not touched.
#[cfg(target_arch = "powerpc")]
pub unsafe fn enable_altivec() {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!(
            "mfmsr {t}",
            "oris {t}, {t}, 0x0200",
            "mtmsr {t}",
            "isync",
            t = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Maps `size` bytes of physical address space (a power of four from 4 KiB
/// to 256 MiB — the sizes e500 TLB1 entries share with MMU v2) at `virt`,
/// cache-inhibited and guarded, supervisor read/write, in TLB1 slot `slot`.
///
/// For device windows such as CCSR, which sits above 4 GiB on the parts that
/// have 36-bit physical addressing (QEMU's `ppce500` puts it at
/// `0xF_E000_0000`) — hence MAS7 for the upper physical bits.
///
/// # Safety
/// Supervisor state on an e500-family core. `slot` must not be the entry
/// the running code is mapped by (the loader's is slot 0), and `virt` must
/// not overlap any live mapping.
#[cfg(target_arch = "powerpc")]
pub unsafe fn e500_map_device(slot: u32, virt: u32, phys: u64, size: u32) -> bool {
    if !size.is_power_of_two() || size < 4096 || (virt as u64 | phys) & (size as u64 - 1) != 0 {
        return false;
    }
    // MAS1.TSIZE is log2(size in KiB), at bits 7..11.
    let tsize = size.trailing_zeros() - 10;
    if tsize % 2 != 0 || tsize > 18 {
        return false;
    }
    let mas0: u32 = 0x1000_0000 | ((slot & 0x3F) << 16); // TLBSEL = 1, ESEL
    let mas1: u32 = 0x8000_0000 | 0x4000_0000 | (tsize << 7); // V, IPROT, TS 0, TID 0
    let mas2: u32 = virt | 0x08 | 0x02; // EPN, I (inhibited), G (guarded)
    let mas3: u32 = (phys as u32 & 0xFFFF_F000) | 0x04 | 0x01; // RPN, SW, SR
    let mas7: u32 = (phys >> 32) as u32;
    // SAFETY: forwarded from this function's contract. `tlbwe` writes the
    // entry the MAS registers describe; `isync` makes it visible to the
    // accesses that follow.
    unsafe {
        asm!(
            "mtspr 624, {m0}",
            "mtspr 625, {m1}",
            "mtspr 626, {m2}",
            "mtspr 627, {m3}",
            "mtspr 944, {m7}",
            "isync",
            "tlbwe",
            "isync",
            m0 = in(reg) mas0,
            m1 = in(reg) mas1,
            m2 = in(reg) mas2,
            m3 = in(reg) mas3,
            m7 = in(reg) mas7,
            options(nostack, preserves_flags),
        );
    }
    true
}
