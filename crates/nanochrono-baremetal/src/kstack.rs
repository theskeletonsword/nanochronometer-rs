// SPDX-License-Identifier: Apache-2.0
//! Which stack every x86-64 kernel entry runs on — the hardware half of the
//! guarantee that ring-3 code keeps its red zone (docs/NCCALL.md §3).
//!
//! # The rule
//!
//! A ring-3 program may keep 128 bytes of live data below its stack pointer
//! (the System V red zone). The kernel must therefore never push onto a
//! ring-3 stack, and on x86-64 there are three ways it could:
//!
//! * **An exception or interrupt from ring 3** through a gate with IST 0:
//!   the processor loads `TSS.RSP0` before it pushes, so this one is safe by
//!   construction — `RSP0` is the kernel stack ring-3 traps run on.
//! * **`SYSCALL`**, which does not switch stacks at all: `ring3.rs`'s entry
//!   moves to a kernel stack in its first two instructions, before any push.
//! * **An event in the window between them**: an NMI or a machine check can
//!   arrive on the first instruction of the `SYSCALL` entry, at ring 0 but
//!   with RSP still the user's — and so can a `#DB` that `MOV SS`/`POP SS`
//!   deferred past the `SYSCALL` (CVE-2018-8897). Through an IST-0 gate the
//!   processor, seeing no privilege change, would push onto the user's stack.
//!   So those three vectors get stacks of their own (IST), which the
//!   processor switches to unconditionally.
//!
//! The double fault has one too, as on every BSD: it is what a kernel stack
//! overflow becomes, and it needs a stack that did not overflow. The page
//! fault keeps the one it had (IST2): every ring-0 `#PF` here is fatal and
//! reported, and a fault on a stack guard is taken with RSP inside the
//! guard. That is the one place this differs from FreeBSD, OpenBSD and
//! NetBSD, which deliver `#PF` on the current stack because they recover
//! kernel page faults (`copyin`); when this kernel does, `#PF` moves off the
//! IST and a guard hit is reported from the `#DF` with CR2 instead.
//!
//! Every other vector stays on IST 0: from ring 3 that is RSP0, from ring 0
//! the current stack, which is safe because kernel code is built without a
//! red zone (`-C no-redzone=yes`, `disable-redzone` in the target spec).
//!
//! # References
//!
//! The IST assignment follows the one FreeBSD makes in
//! `sys/amd64/amd64/machdep.c` (`hammer_time`, `amd64_bsp_ist_init`: #DF
//! IST1, NMI IST2, #MC IST3, #DB IST4), OpenBSD in `sys/arch/amd64/amd64/
//! machdep.c` and NetBSD in `sys/arch/amd64/amd64/machdep.c`; consulted, not
//! reproduced (see NOTICE). `#BP` and `#OF` gates take DPL 3 as in all three,
//! so `int3` and `into` from ring 3 arrive as themselves rather than as #GP.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// One vector with a stack of its own.
#[derive(Debug, Clone, Copy)]
pub struct IstSlot {
    pub vector: u8,
    /// TSS IST index, 1..=7.
    pub ist: u8,
    pub name: &'static str,
    pub why: &'static str,
}

/// The plan. Every vector not listed is delivered with IST 0.
pub const PLAN: [IstSlot; 5] = [
    IstSlot { vector: 8, ist: 1, name: "#DF", why: "a kernel stack overflow becomes #DF" },
    IstSlot { vector: 14, ist: 2, name: "#PF", why: "a guard-page fault is taken with RSP in the guard" },
    IstSlot { vector: 2, ist: 3, name: "NMI", why: "may land between SYSCALL and its stack switch" },
    IstSlot { vector: 18, ist: 4, name: "#MC", why: "may land between SYSCALL and its stack switch" },
    IstSlot { vector: 1, ist: 5, name: "#DB", why: "MOV SS can defer it onto the SYSCALL entry" },
];

/// Vectors whose gate ring 3 may raise directly (`int3`, `into`).
pub const USER_GATES: [u8; 2] = [3, 4];

/// Bytes in each stack this module owns (IST3-5). IST1 and IST2 are
/// boot32.S's, 32 KiB each, set up before any Rust runs.
const IST_STACK: usize = 16 * 1024;

#[repr(C, align(16))]
struct Stack([u8; IST_STACK]);

static mut NMI_STACK: Stack = Stack([0; IST_STACK]);
static mut MC_STACK: Stack = Stack([0; IST_STACK]);
static mut DB_STACK: Stack = Stack([0; IST_STACK]);

/// `[bottom, top)` of the three stacks installed here, for the crash dump's
/// question "which stack was this on".
pub fn own_stacks() -> [(u64, u64); 3] {
    let span = |p: *const Stack| (p as u64, p as u64 + IST_STACK as u64);
    [span(&raw const NMI_STACK), span(&raw const MC_STACK), span(&raw const DB_STACK)]
}

extern "C" {
    static nc_ist1_bottom: u8;
    static nc_ist1_top: u8;
    static nc_ist2_bottom: u8;
    static nc_ist2_top: u8;
    static nc_ring3_kstack_bottom: u8;
    static nc_ring3_kstack_top: u8;
}

/// `[bottom, top)` of the stack IST index `ist` (1..=5) should point into.
fn region(ist: u8) -> (u64, u64) {
    match ist {
        1 => (&raw const nc_ist1_bottom as u64, &raw const nc_ist1_top as u64),
        2 => (&raw const nc_ist2_bottom as u64, &raw const nc_ist2_top as u64),
        3 => own_stacks()[0],
        4 => own_stacks()[1],
        5 => own_stacks()[2],
        _ => (0, 0),
    }
}

/// The ring-3 kernel stack, `TSS.RSP0`'s region.
fn rsp0_region() -> (u64, u64) {
    (&raw const nc_ring3_kstack_bottom as u64, &raw const nc_ring3_kstack_top as u64)
}

// ---------------------------------------------------------------------------
// Finding the live tables
// ---------------------------------------------------------------------------

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

fn sidt() -> (u64, u16) {
    let mut p = DescriptorTablePointer { limit: 0, base: 0 };
    // SAFETY: SIDT stores ten bytes into `p` and has no other effect.
    unsafe { core::arch::asm!("sidt [{}]", in(reg) &mut p, options(nostack, preserves_flags)) };
    (p.base, p.limit)
}

fn sgdt() -> (u64, u16) {
    let mut p = DescriptorTablePointer { limit: 0, base: 0 };
    // SAFETY: SGDT stores ten bytes into `p` and has no other effect.
    unsafe { core::arch::asm!("sgdt [{}]", in(reg) &mut p, options(nostack, preserves_flags)) };
    (p.base, p.limit)
}

fn str_selector() -> u16 {
    let sel: u16;
    // SAFETY: STR reads the task register's selector.
    unsafe { core::arch::asm!("str {0:x}", out(reg) sel, options(nomem, nostack, preserves_flags)) };
    sel
}

/// The 64-bit TSS the task register names, assembled from its 16-byte GDT
/// descriptor.
fn tss_base() -> Option<u64> {
    let (gdt, limit) = sgdt();
    let sel = (str_selector() & !7) as u64;
    if sel == 0 || sel + 15 > limit as u64 {
        return None;
    }
    // SAFETY: the descriptor lies within the live GDT (checked above).
    let (lo, hi) = unsafe { (core::ptr::read_unaligned((gdt + sel) as *const u64), core::ptr::read_unaligned((gdt + sel + 8) as *const u64)) };
    let base = ((lo >> 16) & 0xFF_FFFF) | (((lo >> 56) & 0xFF) << 24) | ((hi & 0xFFFF_FFFF) << 32);
    Some(base)
}

/// Offsets in the 64-bit TSS (SDM Vol. 3A, Figure 8-11).
const TSS_RSP0: u64 = 4;
const TSS_IST1: u64 = 36;

fn tss_read(tss: u64, offset: u64) -> u64 {
    // SAFETY: a field of the live TSS; the TSS is 8-byte fields at 4-byte
    // offsets, hence unaligned.
    unsafe { core::ptr::read_unaligned((tss + offset) as *const u64) }
}

/// One 16-byte IDT gate's fields.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    pub present: bool,
    pub dpl: u8,
    pub ist: u8,
    pub kind: u8,
    pub handler: u64,
}

fn gate(idt: u64, vector: u8) -> Gate {
    // SAFETY: callers pass a vector within the IDT's limit.
    let (lo, hi) = unsafe { (core::ptr::read((idt + vector as u64 * 16) as *const u64), core::ptr::read((idt + vector as u64 * 16 + 8) as *const u64)) };
    Gate {
        present: lo & (1 << 47) != 0,
        dpl: ((lo >> 45) & 3) as u8,
        ist: ((lo >> 32) & 7) as u8,
        kind: ((lo >> 40) & 0xF) as u8,
        handler: (lo & 0xFFFF) | ((lo >> 32) & 0xFFFF_0000) | ((hi & 0xFFFF_FFFF) << 32),
    }
}

// ---------------------------------------------------------------------------
// Installing the plan
// ---------------------------------------------------------------------------

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Points TSS.IST3-5 at this module's stacks, and every exception gate at the
/// stack [`PLAN`] gives it (IST 0 for the rest); opens `#BP`/`#OF` to ring 3.
/// boot32.S's early tables (IST1 for #DF, NMI and #MC; IST2 for #PF) catch
/// anything before this runs.
///
/// # Safety
/// CPL 0, once, early in `kmain`, with interrupts masked (they always are).
pub unsafe fn install() -> Result<(), &'static str> {
    if INSTALLED.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    let tss = tss_base().ok_or("no 64-bit TSS in the task register")?;
    let (idt, limit) = sidt();
    let vectors = (limit as u64 + 1) / 16;
    if vectors < 32 {
        return Err("IDT shorter than the 32 exception vectors");
    }
    for slot in PLAN {
        let (_, top) = region(slot.ist);
        if slot.ist >= 3 {
            // SAFETY: an IST field of the live TSS; the processor reads it
            // only when delivering through a gate that names it, and none
            // does yet.
            unsafe { core::ptr::write_unaligned((tss + TSS_IST1 + 8 * (slot.ist as u64 - 1)) as *mut u64, top & !15) };
        }
    }
    for vector in 0..32u8 {
        let ist = PLAN.iter().find(|s| s.vector == vector).map_or(0, |s| s.ist);
        let dpl = if USER_GATES.contains(&vector) { 3 } else { 0 };
        let entry = (idt + vector as u64 * 16) as *mut u64;
        // SAFETY: a gate within the live IDT. Only the IST field (bits 32-34)
        // and the DPL (bits 45-46) change; the handler, selector, type and
        // present bit stay. A single aligned 64-bit store, so the processor
        // never sees a half-written gate.
        unsafe {
            let lo = core::ptr::read(entry);
            let lo = (lo & !(7u64 << 32) & !(3u64 << 45)) | ((ist as u64) << 32) | ((dpl as u64) << 45);
            core::ptr::write_volatile(entry, lo);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Checking the plan against the hardware's view
// ---------------------------------------------------------------------------

/// What [`verify`] found.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    pub rsp0: u64,
    pub ist: [u64; 7],
    pub on_rsp0_or_current: u32,
}

/// Reads the live IDT and TSS back and checks them against [`PLAN`]: each
/// listed vector on its IST, every other one on IST 0; each IST pointer
/// inside its own stack, 16-byte aligned, none shared, none in RSP0's;
/// RSP0 the ring-3 kernel stack's top; DPL 3 on `#BP`/`#OF` only.
pub fn verify() -> Result<Report, &'static str> {
    let tss = tss_base().ok_or("no 64-bit TSS in the task register")?;
    let (idt, limit) = sidt();
    if (limit as u64 + 1) / 16 < 32 {
        return Err("IDT shorter than the 32 exception vectors");
    }
    let rsp0 = tss_read(tss, TSS_RSP0);
    let (r0lo, r0hi) = rsp0_region();
    if rsp0 != r0hi || rsp0 & 15 != 0 {
        return Err("TSS.RSP0 is not the top of the ring-3 kernel stack");
    }
    let mut ist = [0u64; 7];
    for (i, v) in ist.iter_mut().enumerate() {
        *v = tss_read(tss, TSS_IST1 + 8 * i as u64);
    }
    for slot in PLAN {
        let p = ist[slot.ist as usize - 1];
        let (lo, hi) = region(slot.ist);
        if p & 15 != 0 || !(lo < p && p <= hi) {
            return Err("an IST pointer is outside its stack or misaligned");
        }
        // Stacks are [bottom, top): adjacent is fine (boot32.S lays IST2 and
        // RSP0's stack end to end), sharing a byte is not.
        if lo < r0hi && r0lo < hi {
            return Err("an IST stack overlaps RSP0's");
        }
        for other in PLAN {
            let (olo, ohi) = region(other.ist);
            if other.ist != slot.ist && olo < hi && lo < ohi {
                return Err("two IST slots share a stack");
            }
        }
    }
    let mut on_rsp0_or_current = 0;
    for vector in 0..32u8 {
        let g = gate(idt, vector);
        if !g.present || g.kind != 0xE {
            return Err("an exception gate is not a present interrupt gate");
        }
        let want = PLAN.iter().find(|s| s.vector == vector).map_or(0, |s| s.ist);
        if g.ist != want {
            return Err("an exception gate names the wrong IST");
        }
        if want == 0 {
            on_rsp0_or_current += 1;
        }
        let want_dpl = if USER_GATES.contains(&vector) { 3 } else { 0 };
        if g.dpl != want_dpl {
            return Err("an exception gate has the wrong DPL");
        }
    }
    Ok(Report { rsp0, ist, on_rsp0_or_current })
}

// ---------------------------------------------------------------------------
// The breakpoint the red-zone selftest takes on purpose
// ---------------------------------------------------------------------------

/// Set by the selftest: the next `#BP` returns to the instruction after the
/// `int3` instead of ending a plugin or the kernel.
static RESUME_BREAKPOINT: AtomicBool = AtomicBool::new(false);
/// How many breakpoints were resumed that way.
static BREAKPOINTS_RESUMED: AtomicU32 = AtomicU32::new(0);

/// Arms one resumable breakpoint.
pub fn arm_breakpoint_resume() {
    RESUME_BREAKPOINT.store(true, Ordering::Relaxed);
}

/// How many armed breakpoints were taken and resumed.
pub fn breakpoints_resumed() -> u32 {
    BREAKPOINTS_RESUMED.load(Ordering::Relaxed)
}

/// Called first from the trap path: whether this exception is the armed
/// breakpoint, to be resumed. `#BP` is a trap, so the saved RIP already
/// points past the `int3`.
pub fn take_breakpoint(vector: u64) -> bool {
    if vector == 3 && RESUME_BREAKPOINT.swap(false, Ordering::Relaxed) {
        BREAKPOINTS_RESUMED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}
