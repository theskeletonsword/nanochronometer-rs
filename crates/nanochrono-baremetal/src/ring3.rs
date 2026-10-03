// SPDX-License-Identifier: Apache-2.0
//! Ring 3 for community plugins: the hardware privilege separation an
//! unsigned plugin runs behind.
//!
//! A creator (✅) or trusted-root (🌳) plugin runs in the kernel, called
//! directly. A community plugin has no such vouching, so it runs at **ring 3**
//! (CPL 3): it cannot execute privileged instructions, and the pages it can
//! touch are only its own — its loaded image and a user stack, mapped with the
//! page tables' user bit. Kernel memory has that bit clear at the leaf, so a
//! ring-3 read or write into it faults; the fault is delivered to the kernel,
//! which ends the plugin.
//!
//! The plugin reaches kernel services the only way ring 3 can: a `syscall`
//! (`nccall`, docs/NCCALL.md) that traps into the kernel. The same `NcApi`
//! table a kernel-tier plugin is handed is built here in user memory too, its
//! function pointers aimed at tiny stubs — also in user memory — that each
//! issue one `nccall`. So one plugin binary runs at either privilege
//! unchanged; only who it was signed by decides which. A plugin may also make
//! POSIX-class calls itself (`nanochrono-sys`, `sdk/include/nccall.h`):
//! `write`, `mmap`/`munmap`, `getrandom`, `clock_gettime`, `getpid`, `exit`.
//!
//! # The pieces
//!
//! * [`init`] arms `SYSCALL`/`SYSRET` (EFER.SCE, STAR, LSTAR, SFMASK). The
//!   GDT (boot32.S) already carries the ring-3 code and data segments and a
//!   TSS whose RSP0 is a kernel stack for ring-3 traps; `kstack` gives NMI,
//!   `#MC` and `#DB` stacks of their own.
//! * [`prepare`]/[`run`] set and clear the user bit on a plugin's arena, its
//!   shared page, its user stack and its heap — 2 MiB pages of their own, so
//!   no kernel byte ever shares a user-accessible page. The shared page, which
//!   holds the stubs, is read-only to ring 3 while it runs.
//! * `nc_ring3_enter` drops to ring 3 with an `iretq`; `nc_ring3_syscall` is
//!   the `nccall` trap; both leave through `nc_ring3_return`, whether the
//!   plugin exits cleanly, makes an unknown call, or faults ([`contain`]).
//!
//! # What the `nccall` path guarantees
//!
//! * **No write below the plugin's stack pointer.** `SYSCALL` leaves RSP the
//!   user's; the entry's first two instructions save it and load the
//!   syscall stack, before any push. The plugin's red zone survives every
//!   call (and every exception, which arrives on RSP0 or an IST stack) —
//!   [`prove_red_zone`] checks it at boot.
//! * **Nothing of the kernel's comes back.** Every general register the
//!   kernel may have used is zeroed on the way out but the two results, and
//!   the whole vector and x87 state is reset to its initial configuration by
//!   one `XRSTOR` (`FXRSTOR` without XSAVE) before the plugin's own MXCSR and
//!   x87 control word return. A `nccall` clobbers what a C call clobbers, so
//!   nothing a correct caller relies on is lost — and NC_RNG's state never
//!   lingers in a register a plugin can read.
//! * **Flags the plugin set do not reach the kernel.** SFMASK clears IF, DF,
//!   TF, AC and NT on entry: AC would switch SMAP off for the kernel's whole
//!   service, NT would make its next `iretq` fault.
//! * **Calls come from where they should.** A NanoChronometer-service call
//!   (class 0) must come from a stub the kernel wrote into the shared page,
//!   which the plugin cannot write: OpenBSD's `pinsyscalls(2)` model. Every
//!   call must arrive with the stack pointer inside the plugin's stack, as
//!   OpenBSD checks at each system call: a stack pivot ends the plugin.
//! * **Errors are BSD's.** A POSIX-class call that fails sets `RFLAGS.CF`
//!   and returns an errno (`nanochrono_sys::Errno`, FreeBSD's values); one
//!   that succeeds clears it.
//!
//! Every pointer a `nccall` carries is checked to lie in the plugin's own
//! user memory before the kernel follows it.
//!
//! # References
//!
//! The entry and exit follow FreeBSD's `fast_syscall` in
//! `sys/amd64/amd64/exception.S` (BSD-3-Clause): the user RSP parked while
//! the kernel stack is loaded, a frame of the argument registers built on
//! it, caller-saved registers zeroed before `sysretq`. The call-site and
//! stack-pointer checks follow OpenBSD's `pin_check` and `uvm_map_inentry`
//! in `sys/sys/syscall_mi.h` (BSD-3-Clause). See NOTICE.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use nanochrono_sys::nr;
use nanochrono_sys::Errno;

use crate::crashdump::TrapFrame;

// Segment selectors from the GDT in boot32.S. User selectors carry RPL 3.
const USER_CS: u64 = 0x28 | 3;
const USER_SS: u64 = 0x20 | 3;
const KERNEL_CS: u64 = 0x08;
const KERNEL_SS: u64 = 0x10;

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;

/// RFLAGS bits.
const RFLAGS_CF: u64 = 1 << 0;
const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_DF: u64 = 1 << 10;
const RFLAGS_NT: u64 = 1 << 14;
const RFLAGS_AC: u64 = 1 << 18;

/// What SFMASK clears on every `SYSCALL`.
pub const SFMASK: u64 = RFLAGS_IF | RFLAGS_DF | RFLAGS_TF | RFLAGS_AC | RFLAGS_NT;

/// `nccall` numbers of the NanoChronometer services, the plugin's view of the
/// kernel: `nanochrono_sys::nr::nc`, the one table the stubs, the C SDK and
/// this dispatcher share. Each maps to one `NcApi` entry.
pub mod sys {
    pub use nanochrono_sys::nr::nc::*;
}

// ---------------------------------------------------------------------------
// MSR setup
// ---------------------------------------------------------------------------

/// # Safety
/// Ring 0.
unsafe fn wrmsr(msr: u32, value: u64) {
    let (lo, hi) = (value as u32, (value >> 32) as u32);
    // SAFETY: the caller guarantees ring 0 and a writable MSR.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nostack, preserves_flags));
    }
}

/// # Safety
/// Ring 0.
unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller guarantees ring 0.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

static INITIALISED: AtomicUsize = AtomicUsize::new(0);

/// Arms `SYSCALL`/`SYSRET`, records the syscall stack top, and prepares the
/// clean floating-point image every return to ring 3 loads, once.
///
/// # Safety
/// Ring 0.
pub unsafe fn init() {
    if INITIALISED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    let top = core::ptr::addr_of!(SYSSTACK) as usize + core::mem::size_of::<SysStack>();
    // SAFETY: single core, before the first ring-3 run; the asm reads it after.
    unsafe { *core::ptr::addr_of_mut!(NC_R3_SYSSTACK_TOP) = top as u64 };

    // The image XRSTOR (or FXRSTOR) resets the vector and x87 state from:
    // the x87 control word and MXCSR at their initial values (every exception
    // masked, round to nearest), every tag empty, every register zero, and an
    // XSAVE header whose XSTATE_BV is zero — "every component in its initial
    // configuration", which XRSTOR applies without reading the components'
    // own areas.
    // SAFETY: single core, before the first ring-3 run.
    unsafe {
        let img = &mut (*core::ptr::addr_of_mut!(NC_R3_CLEAN_FPU)).0;
        img.fill(0);
        img[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        img[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        // XSAVE only where boot32.S turned it on (CR4.OSXSAVE); FXSAVE always.
        const CR4_OSXSAVE: u64 = 1 << 18;
        *core::ptr::addr_of_mut!(NC_R3_XSAVE_MODE) = (crate::arch::x86::read_cr4() & CR4_OSXSAVE != 0) as u32;
    }
    // SAFETY: ring 0.
    unsafe {
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | 1); // EFER.SCE
        wrmsr(MSR_STAR, (0x18u64 << 48) | (0x08u64 << 32));
        wrmsr(MSR_LSTAR, nc_ring3_syscall as *const () as usize as u64);
        wrmsr(MSR_SFMASK, SFMASK);
    }
}

/// The SFMASK value the processor holds, for the selftest.
///
/// # Safety
/// Ring 0, after [`init`].
pub unsafe fn sfmask() -> u64 {
    // SAFETY: forwarded.
    unsafe { rdmsr(MSR_SFMASK) }
}

// ---------------------------------------------------------------------------
// User mapping: the user bit on a plugin's own 2 MiB pages
// ---------------------------------------------------------------------------

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_HUGE: u64 = 1 << 7;
const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;

/// Sets or clears the user bit on the 2 MiB page containing `addr`, and on the
/// PML4 and PDPT entries above it; sets the page's write bit to `writable`.
/// A user access needs the user bit at every level, so opening the two top
/// levels lets ring 3 reach a user leaf while kernel leaves (user bit clear)
/// stay unreachable. The first gigabyte is 2 MiB pages and each plugin region
/// is a 2 MiB-aligned page of its own, so nothing splits.
///
/// # Safety
/// Ring 0; identity-mapped page tables; `addr` in the first gigabyte.
unsafe fn set_user_2m(addr: usize, user: bool, writable: bool) -> bool {
    let cr3: u64;
    // SAFETY: reading CR3 at ring 0 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    // SAFETY: each table is reached through a present entry of the live,
    // identity-mapped map; indices are masked to 0..512.
    unsafe {
        let e4 = ((cr3 & PTE_ADDR) as *mut u64).add((addr >> 39) & 511);
        if *e4 & PTE_PRESENT == 0 {
            return false;
        }
        set_bit(e4, PTE_USER, user);
        let e3 = ((*e4 & PTE_ADDR) as *mut u64).add((addr >> 30) & 511);
        if *e3 & PTE_PRESENT == 0 || *e3 & PTE_HUGE != 0 {
            return false;
        }
        set_bit(e3, PTE_USER, user);
        let e2 = ((*e3 & PTE_ADDR) as *mut u64).add((addr >> 21) & 511);
        if *e2 & PTE_PRESENT == 0 || *e2 & PTE_HUGE == 0 {
            return false;
        }
        set_bit(e2, PTE_USER, user);
        set_bit(e2, PTE_WRITABLE, writable);
        flush_tlb();
    }
    true
}

/// # Safety
/// `entry` points at a live page-table entry.
unsafe fn set_bit(entry: *mut u64, bit: u64, on: bool) {
    // SAFETY: forwarded.
    unsafe {
        if on {
            *entry |= bit;
        } else {
            *entry &= !bit;
        }
    }
}

/// # Safety
/// Ring 0.
unsafe fn flush_tlb() {
    // SAFETY: ring 0. The user bit changes on pages the boot map marks
    // global, which a CR3 reload alone would leave cached.
    unsafe { crate::arch::x86::flush_tlb_all() };
}

/// Grants (or, with `user = false`, revokes) ring-3 access to every 2 MiB page
/// overlapping `[base, base + len)`, writable or not. Revoking always leaves
/// the page writable again, as the kernel had it.
///
/// # Safety
/// Ring 0; `base` in the first gigabyte.
unsafe fn map_range(base: usize, len: usize, user: bool, writable: bool) -> bool {
    let mut a = base & !0x1F_FFFF;
    let end = base + len;
    let mut ok = true;
    while a < end {
        // SAFETY: forwarded.
        ok &= unsafe { set_user_2m(a, user, writable || !user) };
        a += 0x20_0000;
    }
    ok
}

// ---------------------------------------------------------------------------
// The user stack, the shared page (NcApi + syscall stubs) and the heap, 2 MiB
// each
// ---------------------------------------------------------------------------

#[repr(C, align(0x200000))]
struct Page2M {
    bytes: [u8; 0x200000],
}
/// The ring-3 plugin's stack. Its own 2 MiB page; an overflow runs off the
/// bottom into a kernel PDE and faults, ending the plugin.
static mut USER_STACK: Page2M = Page2M { bytes: [0; 0x200000] };
/// User-readable/executable page holding the `NcApi` the plugin is handed, the
/// syscall stubs its function pointers reach, and copies of any data symbols
/// it imports. Read-only to ring 3 while the plugin runs, so the only
/// `syscall` instructions in it are the kernel's.
static mut USER_SHARED: Page2M = Page2M { bytes: [0; 0x200000] };
/// The pool the POSIX-class `mmap` hands out, 4 KiB at a time.
static mut USER_HEAP: Page2M = Page2M { bytes: [0; 0x200000] };

fn user_stack() -> (usize, usize) {
    (core::ptr::addr_of!(USER_STACK) as usize, 0x200000)
}
fn user_shared() -> (usize, usize) {
    (core::ptr::addr_of!(USER_SHARED) as usize, 0x200000)
}
fn user_heap() -> (usize, usize) {
    (core::ptr::addr_of!(USER_HEAP) as usize, 0x200000)
}

// ---------------------------------------------------------------------------
// Assembly: enter, syscall, return
// ---------------------------------------------------------------------------

static mut NC_R3_KERNEL_RSP: u64 = 0;
static mut NC_R3_USER_RSP: u64 = 0;
static mut NC_R3_SYSSTACK_TOP: u64 = 0;
/// The kernel's MXCSR and x87 control word, saved by `nc_ring3_enter`, and
/// the plugin's, saved across each syscall. `ldmxcsr` and `fldcw` are not
/// privileged: a plugin can unmask a floating-point exception or change the
/// rounding, and kernel code running with its settings — the syscall
/// dispatch, or everything after the run — would take #XM or #MF on an
/// ordinary division by zero. So the kernel's go back in on every entry to
/// it, and the plugin's on every return to ring 3.
static mut NC_R3_KERNEL_MXCSR: u32 = 0;
static mut NC_R3_KERNEL_FCW: u16 = 0;
static mut NC_R3_USER_MXCSR: u32 = 0;
static mut NC_R3_USER_FCW: u16 = 0;
static NC_R3_RESULT: AtomicU64 = AtomicU64::new(0);
/// Set when the run must end (EXIT, an unknown call, or a fault) rather than
/// return to ring 3.
static NC_R3_UNWIND: AtomicU64 = AtomicU64::new(0);
/// 1 when the clean image is restored with XRSTOR, 0 with FXRSTOR.
static mut NC_R3_XSAVE_MODE: u32 = 0;

/// The initial vector and x87 state (see [`init`]): a 512-byte legacy region
/// and the 64-byte XSAVE header, 64-byte aligned as XRSTOR requires.
#[repr(C, align(64))]
struct CleanFpu([u8; 1024]);
static mut NC_R3_CLEAN_FPU: CleanFpu = CleanFpu([0; 1024]);

core::arch::global_asm!(
    // Resets every vector and x87 register the kernel may have touched to the
    // initial state. Keeps RAX and RDX (the results, on the way out of a
    // nccall) and every other general register.
    ".global nc_ring3_clean_fpu",
    "nc_ring3_clean_fpu:",
    "push rax",
    "push rdx",
    "cmp dword ptr [rip + {xmode}], 0",
    "je 2f",
    "mov eax, -1",
    "mov edx, -1",
    "xrstor64 [rip + {clean}]",
    "jmp 3f",
    "2:",
    "fxrstor64 [rip + {clean}]",
    "3:",
    "pop rdx",
    "pop rax",
    "ret",

    ".global nc_ring3_enter",
    "nc_ring3_enter:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "stmxcsr [rip + {kmxcsr}]",
    "fnstcw [rip + {kfcw}]",
    "mov [rip + {krsp}], rsp",
    "push {user_ss}",
    "push rsi",                // user stack pointer (return address already on it)
    "push 2",                  // RFLAGS: reserved bit 1; IF clear
    "push {user_cs}",
    "push rdi",                // entry
    "mov rdi, rdx",            // the plugin's argument: the user NcApi pointer
    "call nc_ring3_clean_fpu", // no kernel vector or x87 state crosses
    "mov eax, {user_ss}",      // stale ring-0 data selectors must not linger
    "mov ds, ax",
    "mov es, ax",
    // Nor any kernel value in a general register: RDI is the argument, the
    // rest start at zero.
    "xor eax, eax",
    "xor ebx, ebx",
    "xor ecx, ecx",
    "xor edx, edx",
    "xor esi, esi",
    "xor ebp, ebp",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "iretq",

    ".global nc_ring3_return",
    "nc_ring3_return:",
    "mov rsp, [rip + {krsp}]",
    // Whatever the plugin left in the x87 unit — values on its stack, an
    // unmasked exception pending — goes, and the kernel's settings return.
    "fninit",
    "ldmxcsr [rip + {kmxcsr}]",
    "fldcw [rip + {kfcw}]",
    "mov rax, [rip + {result}]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    krsp = sym NC_R3_KERNEL_RSP,
    kmxcsr = sym NC_R3_KERNEL_MXCSR,
    kfcw = sym NC_R3_KERNEL_FCW,
    result = sym NC_R3_RESULT,
    xmode = sym NC_R3_XSAVE_MODE,
    clean = sym NC_R3_CLEAN_FPU,
    user_ss = const USER_SS,
    user_cs = const USER_CS,
);

core::arch::global_asm!(
    // SYSCALL: RCX = the user RIP after the instruction, R11 = the user
    // RFLAGS, RSP = the user's, untouched. Nothing is pushed until RSP is the
    // kernel's: the plugin's red zone below its RSP is never written.
    ".global nc_ring3_syscall",
    "nc_ring3_syscall:",
    "mov [rip + {ursp}], rsp",
    "mov rsp, [rip + {systop}]",
    // The SyscallFrame, built downward: rsp, rip, rflags, the six argument
    // registers in reverse, the number. 80 bytes, so the call below finds
    // the stack 16-byte aligned as the psABI requires.
    "push qword ptr [rip + {ursp}]",
    "push rcx",
    "push r11",
    "push r9",
    "push r8",
    "push r10",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rax",
    "stmxcsr [rip + {umxcsr}]", // the plugin's float settings out, the kernel's in
    "fnstcw [rip + {ufcw}]",
    "ldmxcsr [rip + {kmxcsr}]",
    "fldcw [rip + {kfcw}]",
    "mov rdi, rsp",
    "call {dispatch}",         // RAX:RDX = the results; frame.rflags has CF
    "mov rcx, [rip + {unwind}]",
    "test rcx, rcx",
    "jnz 2f",
    "call nc_ring3_clean_fpu",
    "ldmxcsr [rip + {umxcsr}]",
    "fldcw [rip + {ufcw}]",
    // RAX and RDX are the results; RCX and R11 are SYSRET's; the
    // callee-saved registers were preserved by the dispatcher. The rest of
    // the caller-saved set held kernel values: zeroed.
    "xor esi, esi",
    "xor edi, edi",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "mov r11, [rsp + 56]",
    "mov rcx, [rsp + 64]",
    "mov rsp, [rsp + 72]",
    "sysretq",
    "2:",
    "mov [rip + {result}], rax",
    "jmp nc_ring3_return",
    ursp = sym NC_R3_USER_RSP,
    systop = sym NC_R3_SYSSTACK_TOP,
    kmxcsr = sym NC_R3_KERNEL_MXCSR,
    kfcw = sym NC_R3_KERNEL_FCW,
    umxcsr = sym NC_R3_USER_MXCSR,
    ufcw = sym NC_R3_USER_FCW,
    dispatch = sym dispatch,
    unwind = sym NC_R3_UNWIND,
    result = sym NC_R3_RESULT,
);

extern "C" {
    fn nc_ring3_enter(entry_rip: usize, user_stack: usize, api: usize) -> i64;
    fn nc_ring3_syscall();
    fn nc_ring3_return();
}

#[repr(C, align(16))]
struct SysStack {
    bytes: [u8; 32768],
}
static mut SYSSTACK: SysStack = SysStack { bytes: [0; 32768] };

/// What `nc_ring3_syscall` builds on the syscall stack and hands
/// [`dispatch`]: the number, the six argument registers, and what `SYSRET`
/// will return to. Field order is the push order, reversed.
#[repr(C)]
pub struct SyscallFrame {
    pub nr: u64,
    /// RDI, RSI, RDX, R10, R8, R9.
    pub args: [u64; 6],
    /// The plugin's RFLAGS (R11); the dispatcher sets or clears CF in it.
    pub rflags: u64,
    /// The instruction after the `syscall` (RCX).
    pub rip: u64,
    /// The plugin's RSP.
    pub rsp: u64,
}

/// RAX and RDX on the way back: a 16-byte INTEGER-class struct, returned in
/// exactly those two registers by the System V convention.
#[repr(C)]
pub struct SyscallRet {
    pub rax: u64,
    pub rdx: u64,
}

const _: () = assert!(core::mem::size_of::<SyscallFrame>() == 80);

// ---------------------------------------------------------------------------
// The dispatcher and pointer checks
// ---------------------------------------------------------------------------

static R3_ARENA_BASE: AtomicUsize = AtomicUsize::new(0);
static R3_ARENA_LEN: AtomicUsize = AtomicUsize::new(0);

/// Whether a ring-3 plugin is running.
pub fn active() -> bool {
    R3_ARENA_LEN.load(Ordering::Relaxed) != 0
}

/// Whether `[ptr, ptr + len)` is in the running ring-3 plugin's own memory:
/// its arena, its user stack or its heap. Not the shared page: nothing the
/// kernel is asked to read or write lives among the stubs.
pub fn user_owns(ptr: usize, len: usize) -> bool {
    let alen = R3_ARENA_LEN.load(Ordering::Relaxed);
    if alen == 0 {
        return false;
    }
    let Some(end) = ptr.checked_add(len) else { return false };
    let abase = R3_ARENA_BASE.load(Ordering::Relaxed);
    let in_region = |b: usize, l: usize| b <= ptr && end <= b + l;
    let (sbase, slen) = user_stack();
    let (hbase, hlen) = user_heap();
    in_region(abase, alen) || in_region(sbase, slen) || in_region(hbase, hlen)
}

/// The capability a class-0 `nccall` needs, or 0 for one always allowed.
fn cap_of(num: u32) -> u32 {
    use crate::ncplu::{CAP_INPUT, CAP_LOG, CAP_PMU, CAP_RNG, CAP_SCREEN, CAP_TIMER};
    match num {
        sys::FILL_RECT | sys::CLEAR | sys::PRESENT => CAP_SCREEN,
        sys::POLL_EVENT => CAP_INPUT,
        sys::LOG => CAP_LOG,
        sys::TICKS
        | sys::TIMER_NOW
        | sys::TIMER_NOW_END
        | sys::TIMER_HZ
        | sys::TIMER_SOURCE
        | sys::TIMER_TICKS_TO_NS => CAP_TIMER,
        sys::PMU_CAPS | sys::PMU_OPEN | sys::PMU_READ | sys::PMU_CLOSE => CAP_PMU,
        sys::RNG_FILL | sys::RNG_STATUS | sys::RNG_STIR | sys::RNG_SELFTEST => CAP_RNG,
        _ => 0,
    }
}

/// The `nccall` a plugin was killed for making without the capability, if any
/// (the number plus one; 0 means none).
static R3_DENIED_CALL: AtomicU64 = AtomicU64::new(0);

/// Set when a ring-3 plugin's stack canary changed (`sys::STACK_CHK_FAIL`).
static R3_STACK_SMASHED: AtomicBool = AtomicBool::new(false);

/// Why the kernel ended a plugin at its `nccall` boundary, if it did:
/// [`Violation`] as a byte, 0 for none.
static R3_VIOLATION: AtomicU8 = AtomicU8::new(0);

/// A rule of the `nccall` boundary a plugin broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Violation {
    /// The stack pointer was outside the plugin's stack: a stack pivot.
    StackPointer = 1,
    /// A NanoChronometer-service call from outside the kernel's stubs.
    UnpinnedSite = 2,
    /// A return address `SYSRET` could not take (non-canonical, or in the
    /// kernel's half).
    ReturnAddress = 3,
}

impl Violation {
    pub const fn describe(self) -> &'static str {
        match self {
            Violation::StackPointer => "nccall with the stack pointer outside its stack (a stack pivot)",
            Violation::UnpinnedSite => "a NanoChronometer-service nccall from outside the kernel's stubs",
            Violation::ReturnAddress => "a nccall whose return address SYSRET cannot take",
        }
    }
}

/// Whether the last ring-3 run was stopped by its stack canary.
pub fn stack_smashed() -> bool {
    R3_STACK_SMASHED.load(Ordering::Relaxed)
}

/// The service a ring-3 plugin was stopped for calling without the capability.
pub fn denied_call() -> Option<u64> {
    let v = R3_DENIED_CALL.load(Ordering::Relaxed);
    (v != 0).then(|| v - 1)
}

/// The boundary rule the last ring-3 run was stopped for breaking, if any.
pub fn violation() -> Option<Violation> {
    match R3_VIOLATION.load(Ordering::Relaxed) {
        1 => Some(Violation::StackPointer),
        2 => Some(Violation::UnpinnedSite),
        3 => Some(Violation::ReturnAddress),
        _ => None,
    }
}

/// How many `nccall`s the current or last run made.
static R3_CALLS: AtomicU64 = AtomicU64::new(0);

/// Ends the run with `code` as its result.
fn unwind(code: u64) -> SyscallRet {
    NC_R3_UNWIND.store(1, Ordering::Relaxed);
    SyscallRet { rax: code, rdx: 0 }
}

/// Ends the run for breaking `v`.
fn violate(v: Violation) -> SyscallRet {
    R3_VIOLATION.store(v as u8, Ordering::Relaxed);
    unwind(u64::MAX)
}

/// The first address `SYSRET` cannot return to: the top of the lower
/// canonical half. A `SYSRET` to a non-canonical RCX faults *in ring 0* with
/// the user's RSP on some processors (CVE-2012-0217), which is why FreeBSD
/// takes the `iretq` path instead; here no such address can be reached — the
/// plugin's pages are all in the first gigabyte — and the check is the
/// belt to that brace.
const USER_LIMIT: u64 = 0x0000_8000_0000_0000;

extern "C" fn dispatch(frame: &mut SyscallFrame) -> SyscallRet {
    R3_CALLS.fetch_add(1, Ordering::Relaxed);
    if frame.rip >= USER_LIMIT {
        return violate(Violation::ReturnAddress);
    }
    // OpenBSD's rule: a system call is made on the program's own stack, or
    // the program is not what it was.
    let (sbase, slen) = user_stack();
    if !(sbase as u64..=(sbase + slen) as u64).contains(&frame.rsp) {
        return violate(Violation::StackPointer);
    }
    let nr = frame.nr as u32;
    if frame.nr > u32::MAX as u64 {
        return unwind(u64::MAX);
    }
    match nr::class(nr) {
        nr::CLASS_NC => {
            // The plugin cannot write the shared page while it runs, so a
            // `syscall` there is one the kernel wrote.
            let site = frame.rip.wrapping_sub(2) as usize;
            let (hbase, hlen) = user_shared();
            if !(hbase..hbase + hlen).contains(&site) {
                return violate(Violation::UnpinnedSite);
            }
            let value = nc_service(nr, &frame.args);
            frame.rflags &= !RFLAGS_CF;
            SyscallRet { rax: value, rdx: 0 }
        }
        nr::CLASS_POSIX => match posix(nr, &frame.args) {
            Ok((rax, rdx)) => {
                frame.rflags &= !RFLAGS_CF;
                SyscallRet { rax, rdx }
            }
            Err(e) => {
                frame.rflags |= RFLAGS_CF;
                SyscallRet { rax: e.get() as u64, rdx: 0 }
            }
        },
        _ => unwind(u64::MAX),
    }
}

/// A class-0 call: one `NcApi` service. Unknown numbers end the plugin (the
/// default FreeBSD gives `SIGSYS`); so does a service it did not declare.
fn nc_service(num: u32, a: &[u64; 6]) -> u64 {
    use crate::ncplu;
    // Its canary changed: the plugin's stack is corrupt, so it is ended here,
    // before its return address is ever used. No capability: always allowed.
    if num == sys::STACK_CHK_FAIL {
        R3_STACK_SMASHED.store(true, Ordering::Relaxed);
        return unwind(u64::MAX).rax;
    }
    // A call to a service the plugin did not declare ends it: an unsigned
    // plugin reaching past what it asked for is misbehaving, and this is the
    // capability wall the plugin cannot talk its way around.
    let cap = cap_of(num);
    if cap != 0 && !ncplu::cap_granted(cap) {
        R3_DENIED_CALL.store(num as u64 + 1, Ordering::Relaxed);
        return unwind(u64::MAX).rax;
    }
    let [a1, a2, a3, a4, a5, _] = *a;
    match num {
        sys::EXIT => unwind(a1).rax,
        sys::FILL_RECT => {
            ncplu::nc_fill_rect(a1 as i32, a2 as i32, a3 as i32, a4 as i32, a5 as u32);
            0
        }
        sys::CLEAR => {
            ncplu::nc_clear(a1 as u32);
            0
        }
        sys::PRESENT => {
            ncplu::nc_present();
            0
        }
        sys::POLL_EVENT => ncplu::nc_poll_event() as u64,
        sys::TICKS => ncplu::nc_ticks(),
        sys::LOG => {
            if user_owns(a1 as usize, a2 as usize) {
                ncplu::nc_log(a1 as *const u8, a2 as usize);
            }
            0
        }
        sys::TIMER_NOW => ncplu::nc_timer_now(),
        sys::TIMER_NOW_END => ncplu::nc_timer_now_end(),
        sys::TIMER_HZ => ncplu::nc_timer_hz(),
        sys::TIMER_SOURCE => ncplu::nc_timer_source() as u64,
        sys::TIMER_TICKS_TO_NS => ncplu::nc_timer_ticks_to_ns(a1),
        sys::PMU_CAPS => ncplu::nc_pmu_caps() as u64,
        sys::PMU_OPEN => ncplu::nc_pmu_open(a1 as u32) as u32 as u64,
        sys::PMU_READ => ncplu::nc_pmu_read(a1 as i32),
        sys::PMU_CLOSE => {
            ncplu::nc_pmu_close(a1 as i32);
            0
        }
        // nc_rng_fill / nc_rng_status check their own pointers (caller_owns →
        // plugin_owns → user_owns) and refuse one that is not the plugin's.
        sys::RNG_FILL => crate::rng::nc_rng_fill(a1 as *mut u8, a2 as usize, a3 as u32) as u64,
        sys::RNG_STATUS => crate::rng::nc_rng_status(a1 as *mut _) as u32 as u64,
        sys::RNG_STIR => {
            crate::rng::nc_rng_stir(a1, a2);
            0
        }
        sys::RNG_SELFTEST => crate::rng::nc_rng_selftest() as u32 as u64,
        _ => unwind(u64::MAX).rax,
    }
}

/// A class-1 call. What exists is served; the rest is `ENOSYS`, so a library
/// can probe. A call outside the capability groups the plugin declared is
/// refused with `ENOTCAPABLE` — Capsicum's answer, where a class-0 service
/// ends the plugin instead.
fn posix(num: u32, a: &[u64; 6]) -> Result<(u64, u64), Errno> {
    use crate::ncplu::{self, CAP_LOG, CAP_RNG, CAP_TIMER};
    use nr::posix;
    let need = |cap: u32| if ncplu::cap_granted(cap) { Ok(()) } else { Err(Errno::ENOTCAPABLE) };
    match num {
        posix::EXIT => Ok((unwind(a[0] as i32 as i64 as u64).rax, 0)),
        // The plugin is the only process there is.
        posix::GETPID => Ok((1, 0)),
        posix::WRITE => {
            let (fd, buf, len) = (a[0] as i32, a[1] as usize, a[2] as usize);
            if fd != 1 && fd != 2 {
                return Err(Errno::EBADF);
            }
            need(CAP_LOG)?;
            if len == 0 {
                return Ok((0, 0));
            }
            // A short write is a write: at most 4 KiB per call, as the
            // console takes them.
            let len = len.min(4096);
            if !user_owns(buf, len) {
                return Err(Errno::EFAULT);
            }
            // SAFETY: the range is the plugin's own memory (checked above).
            let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
            crate::serial::write_uart_only(bytes);
            Ok((len as u64, 0))
        }
        posix::MMAP => heap_mmap(a).map(|p| (p as u64, 0)),
        posix::MUNMAP => heap_munmap(a[0] as usize, a[1] as usize).map(|()| (0, 0)),
        posix::CLOCK_GETTIME => {
            need(CAP_TIMER)?;
            let (clock, out) = (a[0] as u32, a[1] as usize);
            if clock != nr::clock::MONOTONIC && clock != nr::clock::UPTIME {
                // No wall clock until the RTC is read: CLOCK_REALTIME is not
                // one this kernel has.
                return Err(Errno::EINVAL);
            }
            if !user_owns(out, core::mem::size_of::<nr::Timespec>()) {
                return Err(Errno::EFAULT);
            }
            let ns = ncplu::nc_timer_ticks_to_ns(ncplu::nc_timer_now());
            let ts = nr::Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
            // SAFETY: the plugin's own memory, sized for one Timespec.
            unsafe { core::ptr::write_unaligned(out as *mut nr::Timespec, ts) };
            Ok((0, 0))
        }
        posix::GETRANDOM => {
            need(CAP_RNG)?;
            let (buf, len, flags) = (a[0] as usize, a[1] as usize, a[2] as u32);
            if flags & !(nr::grnd::NONBLOCK | nr::grnd::RANDOM | nr::grnd::INSECURE) != 0 {
                return Err(Errno::EINVAL);
            }
            let len = len.min(crate::rng::NC_RNG_MAX_FILL);
            if len == 0 {
                return Ok((0, 0));
            }
            if !user_owns(buf, len) {
                return Err(Errno::EFAULT);
            }
            // GRND_RANDOM asks for NC_RNG's TRUE mode, a fresh seed per block.
            let mode = (flags & nr::grnd::RANDOM != 0) as u32;
            let n = crate::rng::nc_rng_fill(buf as *mut u8, len, mode);
            if n < 0 {
                return Err(if flags & nr::grnd::NONBLOCK != 0 { Errno::EAGAIN } else { Errno::EIO });
            }
            Ok((n as u64, 0))
        }
        _ => Err(Errno::ENOSYS),
    }
}

// ---------------------------------------------------------------------------
// The heap: anonymous mappings from one 2 MiB pool, 4 KiB at a time
// ---------------------------------------------------------------------------

const HEAP_PAGE: usize = 4096;
const HEAP_PAGES: usize = 0x200000 / HEAP_PAGE;
/// One bit per page of the pool, set when it is handed out.
static HEAP_MAP: [AtomicU64; HEAP_PAGES / 64] = [const { AtomicU64::new(0) }; HEAP_PAGES / 64];

fn heap_bit(page: usize) -> bool {
    HEAP_MAP[page / 64].load(Ordering::Relaxed) & (1 << (page % 64)) != 0
}

fn heap_set(page: usize, on: bool) {
    if on {
        HEAP_MAP[page / 64].fetch_or(1 << (page % 64), Ordering::Relaxed);
    } else {
        HEAP_MAP[page / 64].fetch_and(!(1 << (page % 64)), Ordering::Relaxed);
    }
}

/// `mmap(addr, len, prot, flags, fd, pgoff)`: anonymous, private, readable
/// and writable memory, zeroed. Everything else is refused with the errno
/// FreeBSD gives it. The pages stay mapped user in 2 MiB granularity until
/// the run ends; `munmap` returns them to the pool, it does not unmap them.
fn heap_mmap(a: &[u64; 6]) -> Result<usize, Errno> {
    use nr::{map, prot};
    let (len, prot_bits, flags, fd, pgoff) = (a[1] as usize, a[2] as u32, a[3] as u32, a[4] as i32, a[5]);
    if len == 0 || flags & map::FIXED != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & map::ANON == 0 || fd != -1 || pgoff != 0 {
        // No file can be mapped: there is no file descriptor table yet.
        return Err(Errno::ENOTSUP);
    }
    if flags & (map::SHARED | map::PRIVATE) == 0 {
        return Err(Errno::EINVAL);
    }
    if prot_bits & prot::EXEC != 0 {
        // The pool is data: W^X for everything a plugin maps.
        return Err(Errno::EACCES);
    }
    if prot_bits & !(prot::READ | prot::WRITE) != 0 {
        return Err(Errno::EINVAL);
    }
    let pages = len.div_ceil(HEAP_PAGE);
    if pages > HEAP_PAGES {
        return Err(Errno::ENOMEM);
    }
    let mut run = 0;
    for page in 0..HEAP_PAGES {
        run = if heap_bit(page) { 0 } else { run + 1 };
        if run == pages {
            let first = page + 1 - pages;
            for p in first..=page {
                heap_set(p, true);
            }
            let (hbase, _) = user_heap();
            let addr = hbase + first * HEAP_PAGE;
            // SAFETY: these pages are the pool's, just taken off its map;
            // the kernel may write them (ring 0, writable leaf).
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, pages * HEAP_PAGE) };
            return Ok(addr);
        }
    }
    Err(Errno::ENOMEM)
}

/// `munmap(addr, len)`: gives the pages back. A range outside the pool is
/// `EINVAL`; a page in it that was not mapped is no error (POSIX).
fn heap_munmap(addr: usize, len: usize) -> Result<(), Errno> {
    let (hbase, hlen) = user_heap();
    if addr % HEAP_PAGE != 0 || len == 0 {
        return Err(Errno::EINVAL);
    }
    let end = addr.checked_add(len).ok_or(Errno::EINVAL)?;
    if addr < hbase || end > hbase + hlen {
        return Err(Errno::EINVAL);
    }
    let first = (addr - hbase) / HEAP_PAGE;
    let last = (end - hbase).div_ceil(HEAP_PAGE);
    for p in first..last {
        heap_set(p, false);
    }
    Ok(())
}

fn heap_reset() {
    for w in &HEAP_MAP {
        w.store(0, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// The user-space NcApi bridge: stubs that turn each NcApi call into an nccall
// ---------------------------------------------------------------------------

/// One syscall stub, written into the user shared page:
///   `mov r10, rcx` (System V's 4th arg → syscall's r10)
///   `mov eax, num`
///   `syscall`
///   `ret`
fn write_stub(buf: &mut [u8], num: u32) -> usize {
    let bytes = [
        0x49, 0x89, 0xCA, // mov r10, rcx
        0xB8, num as u8, (num >> 8) as u8, (num >> 16) as u8, (num >> 24) as u8, // mov eax, num
        0x0F, 0x05, // syscall
        0xC3, // ret
    ];
    buf[..bytes.len()].copy_from_slice(&bytes);
    bytes.len()
}

/// Builds the `NcApi` and its stubs in the user shared page, and returns the
/// user address of the `NcApi`. Also lays out what a plugin may import, for
/// the loader to relocate against (see [`user_symbol`]): `nc_abi_version`,
/// this run's stack canary `__stack_chk_guard`, and a `__stack_chk_fail` stub.
///
/// # Safety
/// Ring 0; `USER_SHARED` is mapped and not in use.
unsafe fn build_user_api(screen_w: u32, screen_h: u32, ticks_per_sec: u64) -> (usize, usize) {
    use crate::ncplu::NcApi;
    let (base, _) = user_shared();
    // SAFETY: single core; USER_SHARED is this page and nothing else uses it.
    let page = unsafe { &mut (*core::ptr::addr_of_mut!(USER_SHARED)).bytes };
    page.fill(0);

    // Layout: [NcApi][nc_abi_version u32 | pad][__stack_chk_guard u64]
    // [__stack_chk_fail stub][NcApi stubs...]. The NcApi comes first so its
    // address is `base`; the rest is 16-byte spaced, at the fixed offsets from
    // `abi_user` that `user_symbol` resolves.
    let api_len = core::mem::size_of::<NcApi>();
    let abi_off = (api_len + 15) & !15;
    page[abi_off..abi_off + 4].copy_from_slice(&crate::ncplu::ABI_VERSION.to_le_bytes());
    page[abi_off + GUARD_OFF..abi_off + GUARD_OFF + 8]
        .copy_from_slice(&crate::ncplu::stack_guard().to_le_bytes());
    write_stub(&mut page[abi_off + CHK_FAIL_OFF..], sys::STACK_CHK_FAIL);
    let abi_user = base + abi_off;

    let mut off = abi_off + CHK_FAIL_OFF + 16;
    let mut stub_addr = [0usize; 19];
    for (i, s) in stub_addr.iter_mut().enumerate() {
        *s = base + off;
        // num i+1: sys::EXIT (0) has no stub (the plugin never calls exit; the
        // kernel ends it). Stubs are for FILL_RECT (1) .. RNG_SELFTEST (19).
        off += (write_stub(&mut page[off..], (i + 1) as u32) + 15) & !15;
    }

    // The NcApi, with its function pointers aimed at the stubs. Written field
    // by field into the page at its start.
    let api = NcApi {
        abi_version: crate::ncplu::ABI_VERSION,
        screen_w,
        screen_h,
        _reserved: 0,
        ticks_per_sec,
        // SAFETY: transmuting a code address in the user page to the fn-pointer
        // type the field holds; the stub has the matching C ABI.
        fill_rect: unsafe { core::mem::transmute::<usize, _>(stub_addr[0]) },
        clear: unsafe { core::mem::transmute::<usize, _>(stub_addr[1]) },
        present: unsafe { core::mem::transmute::<usize, _>(stub_addr[2]) },
        poll_event: unsafe { core::mem::transmute::<usize, _>(stub_addr[3]) },
        ticks: unsafe { core::mem::transmute::<usize, _>(stub_addr[4]) },
        log: unsafe { core::mem::transmute::<usize, _>(stub_addr[5]) },
        timer_now: unsafe { core::mem::transmute::<usize, _>(stub_addr[6]) },
        timer_now_end: unsafe { core::mem::transmute::<usize, _>(stub_addr[7]) },
        timer_hz: unsafe { core::mem::transmute::<usize, _>(stub_addr[8]) },
        timer_source: unsafe { core::mem::transmute::<usize, _>(stub_addr[9]) },
        timer_ticks_to_ns: unsafe { core::mem::transmute::<usize, _>(stub_addr[10]) },
        pmu_caps: unsafe { core::mem::transmute::<usize, _>(stub_addr[11]) },
        pmu_open: unsafe { core::mem::transmute::<usize, _>(stub_addr[12]) },
        pmu_read: unsafe { core::mem::transmute::<usize, _>(stub_addr[13]) },
        pmu_close: unsafe { core::mem::transmute::<usize, _>(stub_addr[14]) },
        rng_fill: unsafe { core::mem::transmute::<usize, _>(stub_addr[15]) },
        rng_status: unsafe { core::mem::transmute::<usize, _>(stub_addr[16]) },
        rng_stir: unsafe { core::mem::transmute::<usize, _>(stub_addr[17]) },
    };
    // SAFETY: `base` is 2 MiB-aligned, so it satisfies NcApi's alignment; the
    // page has room for the struct at its start.
    unsafe { core::ptr::write(base as *mut NcApi, api) };
    let _ = stub_addr[18]; // rng_selftest stub exists for nc_resolve_symbol users
    (base, abi_user)
}

/// Where `__stack_chk_guard` and the `__stack_chk_fail` stub sit, from
/// `nc_abi_version` in the user page.
const GUARD_OFF: usize = 8;
const CHK_FAIL_OFF: usize = 16;

/// The address a ring-3 plugin's import resolves to: a user-readable copy or a
/// user stub in the shared page, never the kernel's own symbol (which ring 3
/// cannot reach). `nc_abi_version`, the run's stack canary, and the canary's
/// failure handler, which traps in with `nccall`; any other import is refused
/// — kernel functions are reached through the `NcApi`.
pub fn user_symbol(name: &[u8], abi_user: usize) -> Option<usize> {
    match name {
        b"nc_abi_version" => Some(abi_user),
        b"__stack_chk_guard" => Some(abi_user + GUARD_OFF),
        b"__stack_chk_fail" => Some(abi_user + CHK_FAIL_OFF),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// A fault that ended a ring-3 plugin.
#[derive(Debug, Clone, Copy)]
pub struct R3Fault {
    pub vector: u64,
    pub rip: u64,
    pub cr2: u64,
}

static mut R3_FAULT: Option<R3Fault> = None;

/// Called from the trap path: if a ring-3 plugin is running and the fault came
/// from ring 3 (any fault: a ring-3 plugin cannot harm the kernel), record it
/// and steer the trap's `iretq` to [`nc_ring3_return`] on the kernel stack, so
/// the plugin is abandoned and the machine carries on. Returns whether it took
/// the fault.
pub fn contain(frame: &mut TrapFrame, cr2: u64) -> bool {
    if !active() || frame.cs & 3 != 3 {
        return false;
    }
    // SAFETY: single core; the plugin is not running while its fault is handled.
    unsafe {
        *core::ptr::addr_of_mut!(R3_FAULT) = Some(R3Fault { vector: frame.vector, rip: frame.rip, cr2 });
    }
    NC_R3_RESULT.store((-(0x100 + frame.vector as i64)) as u64, Ordering::Relaxed);
    NC_R3_UNWIND.store(1, Ordering::Relaxed);
    // Resume the kernel at nc_ring3_return, at ring 0, on the saved kernel
    // stack. In long mode iretq always pops RSP and SS, so setting them here
    // is what returns control to the kernel rather than back to ring 3.
    frame.rip = nc_ring3_return as *const () as usize as u64;
    // SAFETY: written by nc_ring3_enter before the plugin ran.
    frame.rsp = unsafe { *core::ptr::addr_of!(NC_R3_KERNEL_RSP) };
    frame.cs = KERNEL_CS;
    frame.ss = KERNEL_SS;
    frame.rflags = 2;
    true
}

// ---------------------------------------------------------------------------
// Running a plugin
// ---------------------------------------------------------------------------

/// How a ring-3 run ended.
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    /// The plugin returned (its `ncplu_main` value), or made an unknown call.
    Exited(i32),
    /// A fault ended it; the kernel contained it.
    Faulted(R3Fault),
}

/// The user address of the `NcApi` a ring-3 plugin is handed, and the address
/// its `nc_abi_version` import resolves to. Set by [`prepare`] before the
/// loader relocates the plugin.
pub struct Prepared {
    pub api_user: usize,
    pub abi_user: usize,
}

/// Maps the plugin's arena, its stack and its heap into user space, writable,
/// and builds the user `NcApi` in the shared page. Called before the loader
/// applies relocations, so a data import can resolve to the user copy.
///
/// # Safety
/// Ring 0; `arena_base` is the 2 MiB-aligned plugin arena.
pub unsafe fn prepare(
    arena_base: usize,
    arena_len: usize,
    screen_w: u32,
    screen_h: u32,
    ticks_per_sec: u64,
) -> Prepared {
    R3_ARENA_BASE.store(arena_base, Ordering::Relaxed);
    R3_ARENA_LEN.store(arena_len, Ordering::Relaxed);
    heap_reset();
    let (sbase, slen) = user_stack();
    let (hbase, hlen) = user_heap();
    // SAFETY: ring 0; all regions are 2 MiB-aligned statics in the first
    // gigabyte.
    unsafe {
        map_range(arena_base, arena_len, true, true);
        map_range(sbase, slen, true, true);
        map_range(hbase, hlen, true, true);
        let (api_user, abi_user) = build_user_api(screen_w, screen_h, ticks_per_sec);
        Prepared { api_user, abi_user }
    }
}

/// Enters the prepared plugin at ring 3 at `entry` (an address in the arena)
/// and runs it until it exits or faults. Unmaps the user pages afterwards.
///
/// # Safety
/// Ring 0; [`prepare`] ran, the arena holds the relocated plugin, and
/// `PLUGIN_CTX` (in `ncplu`) is set for the services.
pub unsafe fn run(entry: usize, api_user: usize) -> Outcome {
    // SAFETY: single core; reset the run's flags.
    unsafe { *core::ptr::addr_of_mut!(R3_FAULT) = None };
    NC_R3_UNWIND.store(0, Ordering::Relaxed);
    NC_R3_RESULT.store(0, Ordering::Relaxed);
    R3_DENIED_CALL.store(0, Ordering::Relaxed);
    R3_STACK_SMASHED.store(false, Ordering::Relaxed);
    R3_VIOLATION.store(0, Ordering::Relaxed);
    R3_CALLS.store(0, Ordering::Relaxed);

    // The plugin runs `ncplu_main(api) -> i32`. It is entered by iretq (not a
    // call), so a return address is placed on the user stack by hand: an exit
    // shim that turns the returned value into `nccall(EXIT, value)`. A plugin
    // that instead calls exit itself never reaches it. rsp points at that
    // return address, exactly as it would just after a `call`.
    // SAFETY: ring 0; USER_SHARED is mapped.
    let exit_shim = unsafe { build_exit_shim() };
    let (sbase, slen) = user_stack();
    let stack_top = (sbase + slen) & !15;
    let rsp = stack_top - 8;
    // SAFETY: the user stack is mapped and ring 0 may write it; `rsp` is inside.
    unsafe { core::ptr::write(rsp as *mut u64, exit_shim as u64) };

    // The shared page holds everything the kernel wrote for this run: from
    // here on ring 3 may read and execute it, never write it.
    let (hbase, hlen) = user_shared();
    // SAFETY: ring 0; the shared page is a 2 MiB-aligned static.
    unsafe { map_range(hbase, hlen, true, false) };

    // SAFETY: entry, stack and api are all user-mapped; nc_ring3_enter drops to
    // ring 3 and returns via nc_ring3_return when the plugin exits or faults.
    let code = unsafe { nc_ring3_enter(entry, rsp, api_user) } as i32;

    // SAFETY: single core.
    let fault = unsafe { *core::ptr::addr_of!(R3_FAULT) };
    let abase = R3_ARENA_BASE.load(Ordering::Relaxed);
    let alen = R3_ARENA_LEN.load(Ordering::Relaxed);
    R3_ARENA_LEN.store(0, Ordering::Relaxed);
    let (pbase, plen) = user_heap();
    // SAFETY: ring 0; revoke user access to every region before returning, so
    // between plugins these pages are kernel-only (and kernel-writable) again.
    unsafe {
        map_range(sbase, slen, false, true);
        map_range(hbase, hlen, false, true);
        map_range(pbase, plen, false, true);
        map_range(abase, alen.max(0x200000), false, true);
    }
    heap_reset();
    match fault {
        Some(f) => Outcome::Faulted(f),
        None => Outcome::Exited(code),
    }
}

/// How many `nccall`s the last run made.
pub fn calls() -> u64 {
    R3_CALLS.load(Ordering::Relaxed)
}

/// Writes the exit shim near the end of the shared page — `mov edi, eax; xor
/// eax, eax; syscall` (`nccall(EXIT, return_value)`) — and returns its user
/// address. A plugin's `ncplu_main` returns into it, so a clean return ends
/// the run through the same path an explicit exit takes.
///
/// # Safety
/// Ring 0; `USER_SHARED` is mapped.
unsafe fn build_exit_shim() -> usize {
    let (base, len) = user_shared();
    let off = len - 64;
    // SAFETY: single core; USER_SHARED is this page.
    let page = unsafe { &mut (*core::ptr::addr_of_mut!(USER_SHARED)).bytes };
    let b = [
        0x89, 0xC7, // mov edi, eax   (return value -> exit code, arg 1)
        0x31, 0xC0, // xor eax, eax   (nccall number 0 = EXIT)
        0x0F, 0x05, // syscall
    ];
    page[off..off + b.len()].copy_from_slice(&b);
    base + off
}

// ---------------------------------------------------------------------------
// The red-zone proof
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    // nc_redzone_probe(make_call): fills the 128 bytes below RSP — the red
    // zone — with a pattern, makes a nccall there if `make_call` is nonzero,
    // takes a breakpoint, and returns 0 if the pattern survived, 1 if
    // anything wrote over it. Position independent, so it runs where it is
    // linked (ring 0) or from a copy in the shared page (ring 3).
    ".global nc_redzone_probe, nc_redzone_probe_end",
    "nc_redzone_probe:",
    "movabs rax, 0x21454E4F5A444552", // "REDZONE!"
    "lea rcx, [rsp - 128]",
    "xor edx, edx",
    "2:",
    "mov [rcx + rdx * 8], rax",
    "inc edx",
    "cmp edx, 16",
    "jb 2b",
    "test rdi, rdi",
    "jz 3f",
    "mov eax, {nr_timer_hz}",
    "syscall",
    "3:",
    "int3",
    "movabs rax, 0x21454E4F5A444552",
    "lea rcx, [rsp - 128]",
    "xor edx, edx",
    "4:",
    "cmp [rcx + rdx * 8], rax",
    "jne 5f",
    "inc edx",
    "cmp edx, 16",
    "jb 4b",
    "xor eax, eax",
    "ret",
    "5:",
    "mov eax, 1",
    "ret",
    "nc_redzone_probe_end:",
    nr_timer_hz = const sys::TIMER_HZ,
);

extern "C" {
    fn nc_redzone_probe(make_call: u64) -> u64;
    static nc_redzone_probe_end: u8;
}

/// What [`prove_red_zone`] observed.
#[derive(Debug, Clone, Copy)]
pub struct RedZoneProof {
    /// The ring-3 run: the probe's pattern below RSP survived a nccall and
    /// a breakpoint.
    pub ring3_intact: bool,
    /// The ring-3 run ended normally (not by a fault or a boundary rule).
    pub ring3_clean_exit: bool,
    /// The nccalls the ring-3 run made (the probe's, and its exit).
    pub ring3_calls: u64,
    /// The control: the same probe at ring 0, where the breakpoint's frame
    /// is pushed onto the stack the probe is using, found its pattern
    /// overwritten — the hazard is real and the probe can see it.
    pub ring0_corrupted: bool,
    /// Breakpoints taken and resumed (two: one per run).
    pub breakpoints: u32,
}

/// Runs the red-zone probe at ring 3 — where an exception arrives on RSP0
/// and a nccall switches stacks before its first push — and at ring 0 as the
/// control, where the breakpoint's frame lands on the probe's own stack.
///
/// # Safety
/// Ring 0, no plugin running, interrupts masked.
pub unsafe fn prove_red_zone() -> RedZoneProof {
    // SAFETY: ring 0.
    unsafe { init() };
    let before = crate::kstack::breakpoints_resumed();
    let caps = crate::ncplu::granted_caps();
    crate::ncplu::set_granted_caps(crate::ncplu::CAP_TIMER);

    let (hbase, hlen) = user_shared();
    // SAFETY: ring 0; the probe runs from the shared page itself (its
    // "arena"), so nothing else is mapped user.
    let prepared = unsafe { prepare(hbase, hlen, 0, 0, 1) };
    const PROBE_OFF: usize = 0x1000;
    let start = nc_redzone_probe as *const () as usize;
    // The end label follows the probe's code in the same section.
    let end = &raw const nc_redzone_probe_end as usize;
    // SAFETY: ring 0; the shared page is still kernel-writable (run() makes
    // it read-only to ring 3); the probe's code is `end - start` bytes, far
    // below the page's size, and lands clear of the NcApi and the stubs.
    unsafe {
        let page = &mut (*core::ptr::addr_of_mut!(USER_SHARED)).bytes;
        let code = core::slice::from_raw_parts(start as *const u8, end - start);
        page[PROBE_OFF..PROBE_OFF + code.len()].copy_from_slice(code);
    }
    crate::kstack::arm_breakpoint_resume();
    // SAFETY: prepared above; the entry is the probe's copy, user-mapped.
    let outcome = unsafe { run(hbase + PROBE_OFF, prepared.api_user) };
    let ring3_calls = calls();
    let (ring3_intact, ring3_clean_exit) = match outcome {
        Outcome::Exited(code) => (code == 0, violation().is_none()),
        Outcome::Faulted(_) => (false, false),
    };

    crate::kstack::arm_breakpoint_resume();
    // SAFETY: the probe at ring 0, no nccall (make_call = 0): it fills the
    // 128 bytes below its stack pointer, which are unused stack, and takes a
    // breakpoint the trap path resumes.
    let ring0 = unsafe { nc_redzone_probe(0) };

    crate::ncplu::set_granted_caps(caps);
    RedZoneProof {
        ring3_intact,
        ring3_clean_exit,
        ring3_calls,
        ring0_corrupted: ring0 != 0,
        breakpoints: crate::kstack::breakpoints_resumed() - before,
    }
}
