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
//! (`nccall`) that traps into the kernel. The same `NcApi` table a kernel-tier
//! plugin is handed is built here in user memory too, its function pointers
//! aimed at tiny stubs — also in user memory — that each issue one `nccall`.
//! So one plugin binary runs at either privilege unchanged; only who it was
//! signed by decides which.
//!
//! # The pieces
//!
//! * [`init`] arms `SYSCALL`/`SYSRET` (EFER.SCE, STAR, LSTAR, SFMASK). The
//!   GDT (boot32.S) already carries the ring-3 code and data segments and a
//!   TSS whose RSP0 is a kernel stack for ring-3 traps.
//! * [`map_user`]/[`unmap_user`] set and clear the user bit on a plugin's
//!   arena, its shared page and its user stack — 2 MiB pages of their own, so
//!   no kernel byte ever shares a user-accessible page.
//! * `nc_ring3_enter` drops to ring 3 with an `iretq`; `nc_ring3_syscall` is
//!   the `nccall` trap; both leave through `nc_ring3_return`, whether the
//!   plugin exits cleanly, makes an unknown call, or faults ([`contain`]).
//!
//! Every pointer a `nccall` carries is checked to lie in the plugin's own
//! user memory before the kernel follows it.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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

/// `nccall` numbers: the plugin's view of the kernel services. Each maps to
/// one `NcApi` entry; [`dispatch`] turns it back into the kernel call.
pub mod sys {
    pub const EXIT: u64 = 0;
    pub const FILL_RECT: u64 = 1;
    pub const CLEAR: u64 = 2;
    pub const PRESENT: u64 = 3;
    pub const POLL_EVENT: u64 = 4;
    pub const TICKS: u64 = 5;
    pub const LOG: u64 = 6;
    pub const TIMER_NOW: u64 = 7;
    pub const TIMER_NOW_END: u64 = 8;
    pub const TIMER_HZ: u64 = 9;
    pub const TIMER_SOURCE: u64 = 10;
    pub const TIMER_TICKS_TO_NS: u64 = 11;
    pub const PMU_CAPS: u64 = 12;
    pub const PMU_OPEN: u64 = 13;
    pub const PMU_READ: u64 = 14;
    pub const PMU_CLOSE: u64 = 15;
    pub const RNG_FILL: u64 = 16;
    pub const RNG_STATUS: u64 = 17;
    pub const RNG_STIR: u64 = 18;
    pub const RNG_SELFTEST: u64 = 19;
    /// The plugin's stack canary changed (`__stack_chk_fail`): end it.
    pub const STACK_CHK_FAIL: u64 = 20;
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

/// Arms `SYSCALL`/`SYSRET` and records the syscall stack top, once.
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
    // SAFETY: ring 0.
    unsafe {
        wrmsr(MSR_EFER, rdmsr(MSR_EFER) | 1); // EFER.SCE
        wrmsr(MSR_STAR, (0x18u64 << 48) | (0x08u64 << 32));
        wrmsr(MSR_LSTAR, nc_ring3_syscall as *const () as usize as u64);
        wrmsr(MSR_SFMASK, (1 << 9) | (1 << 10) | (1 << 8)); // clear IF, DF, TF
    }
}

// ---------------------------------------------------------------------------
// User mapping: the user bit on a plugin's own 2 MiB pages
// ---------------------------------------------------------------------------

const PTE_PRESENT: u64 = 1 << 0;
const PTE_USER: u64 = 1 << 2;
const PTE_HUGE: u64 = 1 << 7;
const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;

/// Sets or clears the user bit on the 2 MiB page containing `addr`, and on the
/// PML4 and PDPT entries above it. A user access needs the user bit at every
/// level, so opening the two top levels lets ring 3 reach a user leaf while
/// kernel leaves (user bit clear) stay unreachable. The first gigabyte is 2
/// MiB pages and each plugin region is a 2 MiB-aligned page of its own, so
/// nothing splits.
///
/// # Safety
/// Ring 0; identity-mapped page tables; `addr` in the first gigabyte.
unsafe fn set_user_2m(addr: usize, user: bool) -> bool {
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
    // SAFETY: reloading CR3 is valid at ring 0 and flushes the TLB.
    unsafe {
        core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack, preserves_flags));
    }
}

/// Grants (or, with `user = false`, revokes) ring-3 access to every 2 MiB page
/// overlapping `[base, base + len)`.
///
/// # Safety
/// Ring 0; `base` in the first gigabyte.
unsafe fn map_range(base: usize, len: usize, user: bool) -> bool {
    let mut a = base & !0x1F_FFFF;
    let end = base + len;
    let mut ok = true;
    while a < end {
        // SAFETY: forwarded.
        ok &= unsafe { set_user_2m(a, user) };
        a += 0x20_0000;
    }
    ok
}

// ---------------------------------------------------------------------------
// The user stack and the shared page (NcApi + syscall stubs), 2 MiB each
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
/// it imports.
static mut USER_SHARED: Page2M = Page2M { bytes: [0; 0x200000] };

fn user_stack() -> (usize, usize) {
    (core::ptr::addr_of!(USER_STACK) as usize, 0x200000)
}
fn user_shared() -> (usize, usize) {
    (core::ptr::addr_of!(USER_SHARED) as usize, 0x200000)
}

// ---------------------------------------------------------------------------
// Assembly: enter, syscall, return
// ---------------------------------------------------------------------------

static mut NC_R3_KERNEL_RSP: u64 = 0;
static mut NC_R3_USER_RSP: u64 = 0;
static mut NC_R3_SYSSTACK_TOP: u64 = 0;
static NC_R3_RESULT: AtomicU64 = AtomicU64::new(0);
/// Set when the run must end (EXIT, an unknown call, or a fault) rather than
/// return to ring 3.
static NC_R3_UNWIND: AtomicU64 = AtomicU64::new(0);

core::arch::global_asm!(
    ".global nc_ring3_enter",
    "nc_ring3_enter:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rip + {krsp}], rsp",
    "push {user_ss}",
    "push rsi",                // user stack pointer (return address already on it)
    "push 2",                  // RFLAGS: reserved bit 1; IF clear
    "push {user_cs}",
    "push rdi",                // entry
    "mov rdi, rdx",            // the plugin's argument: the user NcApi pointer
    "mov eax, {user_ss}",      // stale ring-0 data selectors must not linger
    "mov ds, ax",
    "mov es, ax",
    "iretq",

    ".global nc_ring3_return",
    "nc_ring3_return:",
    "mov rsp, [rip + {krsp}]",
    "mov rax, [rip + {result}]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    krsp = sym NC_R3_KERNEL_RSP,
    result = sym NC_R3_RESULT,
    user_ss = const USER_SS,
    user_cs = const USER_CS,
);

core::arch::global_asm!(
    ".global nc_ring3_syscall",
    "nc_ring3_syscall:",
    "mov [rip + {ursp}], rsp",
    "mov rsp, [rip + {systop}]",
    "push rcx",                // user RIP  (SYSRET needs it)
    "push r11",                // user RFLAGS
    "mov r9, r8",              // shuffle to System V: dispatch(num,a1,a2,a3,a4,a5)
    "mov r8, r10",
    "mov rcx, rdx",
    "mov rdx, rsi",
    "mov rsi, rdi",
    "mov rdi, rax",
    "call {dispatch}",
    "mov rcx, [rip + {unwind}]",
    "test rcx, rcx",
    "jnz 2f",
    "pop r11",
    "pop rcx",
    "mov rsp, [rip + {ursp}]",
    "sysretq",
    "2:",
    "mov [rip + {result}], rax",
    "jmp nc_ring3_return",
    ursp = sym NC_R3_USER_RSP,
    systop = sym NC_R3_SYSSTACK_TOP,
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

// ---------------------------------------------------------------------------
// The dispatcher and pointer checks
// ---------------------------------------------------------------------------

static R3_ARENA_BASE: AtomicUsize = AtomicUsize::new(0);
static R3_ARENA_LEN: AtomicUsize = AtomicUsize::new(0);

/// Whether a ring-3 plugin is running.
pub fn active() -> bool {
    R3_ARENA_LEN.load(Ordering::Relaxed) != 0
}

/// Whether `[ptr, ptr + len)` is in the running ring-3 plugin's user memory:
/// its arena, its user stack or its shared page.
pub fn user_owns(ptr: usize, len: usize) -> bool {
    let alen = R3_ARENA_LEN.load(Ordering::Relaxed);
    if alen == 0 {
        return false;
    }
    let Some(end) = ptr.checked_add(len) else { return false };
    let abase = R3_ARENA_BASE.load(Ordering::Relaxed);
    let in_region = |b: usize, l: usize| b <= ptr && end <= b + l;
    let (sbase, slen) = user_stack();
    let (hbase, hlen) = user_shared();
    in_region(abase, alen) || in_region(sbase, slen) || in_region(hbase, hlen)
}

/// The capability a `nccall` needs, or 0 for one always allowed (EXIT).
fn cap_of(num: u64) -> u32 {
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

/// Whether the last ring-3 run was stopped by its stack canary.
pub fn stack_smashed() -> bool {
    R3_STACK_SMASHED.load(Ordering::Relaxed)
}

/// The service a ring-3 plugin was stopped for calling without the capability.
pub fn denied_call() -> Option<u64> {
    let v = R3_DENIED_CALL.load(Ordering::Relaxed);
    (v != 0).then(|| v - 1)
}

extern "C" fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    use crate::ncplu;
    // A call to a service the plugin did not declare ends it: an unsigned
    // plugin reaching past what it asked for is misbehaving, and this is the
    // capability wall the plugin cannot talk its way around.
    // Its canary changed: the plugin's stack is corrupt, so it is ended here,
    // before its return address is ever used. No capability: always allowed.
    if num == sys::STACK_CHK_FAIL {
        R3_STACK_SMASHED.store(true, Ordering::Relaxed);
        NC_R3_UNWIND.store(1, Ordering::Relaxed);
        return u64::MAX;
    }
    let cap = cap_of(num);
    if cap != 0 && !ncplu::cap_granted(cap) {
        R3_DENIED_CALL.store(num + 1, Ordering::Relaxed);
        NC_R3_UNWIND.store(1, Ordering::Relaxed);
        return u64::MAX;
    }
    match num {
        sys::EXIT => {
            NC_R3_UNWIND.store(1, Ordering::Relaxed);
            a1
        }
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
        _ => {
            NC_R3_UNWIND.store(1, Ordering::Relaxed);
            u64::MAX
        }
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
    write_stub(&mut page[abi_off + CHK_FAIL_OFF..], sys::STACK_CHK_FAIL as u32);
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
/// from ring 3 (any fault — a ring-3 plugin cannot harm the kernel), record it
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

/// Maps the plugin's arena and the shared/stack pages into user space and
/// builds the user `NcApi`. Called before the loader applies relocations, so a
/// data import can resolve to the user copy.
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
    let (sbase, slen) = user_stack();
    let (hbase, hlen) = user_shared();
    // SAFETY: ring 0; all three regions are 2 MiB-aligned statics in the first
    // gigabyte.
    unsafe {
        map_range(arena_base, arena_len, true);
        map_range(sbase, slen, true);
        map_range(hbase, hlen, true);
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

    // SAFETY: entry, stack and api are all user-mapped; nc_ring3_enter drops to
    // ring 3 and returns via nc_ring3_return when the plugin exits or faults.
    let code = unsafe { nc_ring3_enter(entry, rsp, api_user) } as i32;

    // SAFETY: single core.
    let fault = unsafe { *core::ptr::addr_of!(R3_FAULT) };
    let abase = R3_ARENA_BASE.load(Ordering::Relaxed);
    R3_ARENA_LEN.store(0, Ordering::Relaxed);
    let (hbase, hlen) = user_shared();
    // SAFETY: ring 0; revoke user access to every region before returning, so
    // between plugins these pages are kernel-only again.
    unsafe {
        map_range(sbase, slen, false);
        map_range(hbase, hlen, false);
        map_range(abase, 0x200000, false);
    }
    match fault {
        Some(f) => Outcome::Faulted(f),
        None => Outcome::Exited(code),
    }
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
