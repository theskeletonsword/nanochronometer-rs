// SPDX-License-Identifier: Apache-2.0
//! The per-ISA half of `nccall`: where each architecture's trap leaves the
//! number, the six arguments and the way back, and where the two results and
//! the error flag go — the registers of `nanochrono_sys::abi`, as slots of
//! the frame each entry saves.
//!
//! | ISA | Trap | Entry | Proven at boot through |
//! |---|---|---|---|
//! | x86-64 | `syscall` | `ring3.rs` | the trap, from ring 3 (the red-zone probe); the glue, with a frame |
//! | i386 | `int $0x80` | `boot/boot_i386.S` | the trap, from ring 0 |
//! | AArch64 | `svc #0` | `arch/arm.rs` | the trap, from EL1 (or EL2) |
//! | ARM32 | `svc #0` | `arch/arm32.rs` | the trap, from SVC mode |
//! | PowerPC (e500) | `sc` | `arch/ppc.rs`, IVOR8 | the trap, from supervisor state |
//! | PowerPC (Open Firmware), PPC64 | `sc` | — (firmware owns the vectors) | the glue, with a frame |
//! | RISC-V | `ecall` | `arch/riscv.rs` | the trap, from U-mode (S-mode's goes to the SBI) |
//!
//! The maps themselves are `nanochrono_core::nccall::hal`'s, checked there
//! against `nanochrono_sys::abi` by host tests; each glue here reads and
//! writes its frame through its map, so the convention is written down once.

pub use nanochrono_core::nccall::hal::{answer, read, Flag, Map, Slot, AARCH64, ARM32, I386, POWERPC, RISCV, X86_64};

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
use super::Ending;
#[cfg(any(target_arch = "x86", target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc", target_arch = "powerpc64"))]
use super::Reply;
use nanochrono_sys::Errno;

/// What a caller that cannot be ended — the kernel itself, trapping from
/// ring 0 — is told instead: `ENOSYS`, the error flag set.
#[cfg(any(target_arch = "x86", target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc", target_arch = "powerpc64"))]
fn unendable(map: &Map, regs: &mut [usize], status: &mut usize) {
    let _ = answer(map, Reply::Err(Errno::ENOSYS), regs, status);
}

// ---------------------------------------------------------------------------
// The glue, one per ISA: called from its entry with the frame it saved
// ---------------------------------------------------------------------------

/// The frame `nc_sync_el*` (arch/arm.rs) saves for an `svc`: x0..x30, ELR,
/// SPSR, one word of padding; 128 bytes below the interrupted stack pointer
/// are skipped first (NCCALL.md §2.3).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct Frame {
    pub x: [usize; 31],
    pub elr: usize,
    pub spsr: usize,
    _pad: usize,
}

#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<Frame>() == 272);

#[cfg(target_arch = "aarch64")]
#[no_mangle]
extern "C" fn nanochrono_nccall_aarch64(f: &mut Frame) {
    let sp = f as *mut Frame as usize + 272 + 128;
    let call = read(&AARCH64, &f.x, f.elr.wrapping_sub(4), sp);
    if answer(&AARCH64, super::dispatch_current(&call), &mut f.x, &mut f.spsr).is_some() {
        unendable(&AARCH64, &mut f.x, &mut f.spsr);
    }
}

/// The frame `nc_arm32_svc` (arch/arm32.rs) pushes: r0..r12, the return
/// address, the SPSR and a pad word.
#[cfg(target_arch = "arm")]
#[repr(C)]
pub struct Frame {
    pub r: [usize; 13],
    pub lr: usize,
    pub spsr: usize,
    _pad: usize,
}

#[cfg(target_arch = "arm")]
const _: () = assert!(core::mem::size_of::<Frame>() == 64);

#[cfg(target_arch = "arm")]
#[no_mangle]
extern "C" fn nanochrono_nccall_arm(f: &mut Frame) {
    // The `svc` is 2 bytes before the return address in Thumb state.
    let site = f.lr.wrapping_sub(if f.spsr & (1 << 5) != 0 { 2 } else { 4 });
    let sp = f as *mut Frame as usize + 64;
    let call = read(&ARM32, &f.r, site, sp);
    if answer(&ARM32, super::dispatch_current(&call), &mut f.r, &mut f.spsr).is_some() {
        unendable(&ARM32, &mut f.r, &mut f.spsr);
    }
}

/// The frame the PowerPC `sc` entry saves: r0..r31 (r1's slot the caller's
/// stack pointer), then LR, CR, CTR, XER, SRR0, SRR1.
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
#[repr(C)]
pub struct Frame {
    pub r: [usize; 32],
    pub lr: usize,
    pub cr: usize,
    pub ctr: usize,
    pub xer: usize,
    pub srr0: usize,
    pub srr1: usize,
}

#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
#[no_mangle]
extern "C" fn nanochrono_nccall_ppc(f: &mut Frame) {
    let call = read(&POWERPC, &f.r, f.srr0.wrapping_sub(4), f.r[1]);
    if answer(&POWERPC, super::dispatch_current(&call), &mut f.r, &mut f.cr).is_some() {
        unendable(&POWERPC, &mut f.r, &mut f.cr);
    }
}

/// The frame the RISC-V trap entry saves for an `ecall` from U-mode:
/// x0..x31 (x0's slot unused, x2 the caller's stack pointer) and `sepc`.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[repr(C)]
pub struct Frame {
    pub x: [usize; 32],
    pub sepc: usize,
}

/// The status a U-mode run ended with (`nc_rv_user_run`).
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
static RV_END: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Returns 0 to resume the caller past its `ecall`, 1 to end its run.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[no_mangle]
extern "C" fn nanochrono_nccall_riscv(f: &mut Frame) -> usize {
    let call = read(&RISCV, &f.x, f.sepc, f.x[2]);
    let mut unused = 0;
    match answer(&RISCV, super::dispatch_current(&call), &mut f.x, &mut unused) {
        None => {
            f.sepc += 4;
            0
        }
        Some(why) => {
            let status = match why {
                Ending::Exit(status) => status as usize,
                _ => usize::MAX,
            };
            RV_END.store(status, core::sync::atomic::Ordering::Relaxed);
            1
        }
    }
}

/// What `nc_i386_int80` (boot/boot_i386.S) leaves: `pusha`'s eight words,
/// then what the CPU pushed — EIP, CS, EFLAGS, and from ring 3 ESP and SS.
#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct Frame {
    pub regs: [usize; 8],
    pub eip: usize,
    pub cs: usize,
    pub eflags: usize,
    pub user_esp: usize,
    pub user_ss: usize,
}

#[cfg(target_arch = "x86")]
#[no_mangle]
extern "C" fn nanochrono_nccall_i386(f: &mut Frame) {
    // From ring 3 the CPU pushed the caller's ESP; from ring 0 it pushed
    // nothing, and the caller's stack starts right after EFLAGS.
    let from_user = f.cs & 3 == 3;
    let sp = if from_user { f.user_esp } else { &f.user_esp as *const usize as usize };
    let mut call = read(&I386, &f.regs, f.eip.wrapping_sub(2), sp);
    let mut readable = true;
    if from_user {
        readable = super::current_owns(sp.wrapping_add(4), 24);
    }
    if readable {
        for (i, slot) in I386.args.iter().enumerate() {
            if let Slot::Stack(off) = *slot {
                // SAFETY: from ring 0 the kernel's own stack, from ring 3 a
                // range the caller owns (checked above).
                call.args[i] = unsafe { core::ptr::read_unaligned((sp + off) as *const usize) };
            }
        }
    }
    let reply = if readable { super::dispatch_current(&call) } else { Reply::Err(Errno::EFAULT) };
    if answer(&I386, reply, &mut f.regs, &mut f.eflags).is_some() {
        unendable(&I386, &mut f.regs, &mut f.eflags);
    }
}

// ---------------------------------------------------------------------------
// The boot-time proof
// ---------------------------------------------------------------------------

/// Whether this ISA's trap entry is installed: set by the code that installs
/// the vectors (on PowerPC, only an e500 has them; Open Firmware owns a
/// classic core's).
static TRAP_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Called once the entry is in place.
pub fn set_trap_ready() {
    TRAP_READY.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// What the self-test found.
#[derive(Debug, Clone, Copy, Default)]
pub struct Proof {
    /// Through what: the trap instruction from where, or the glue alone.
    pub path: &'static str,
    /// echo's six arguments and two results.
    pub echo: bool,
    /// getpid answered 1.
    pub getpid: bool,
    /// An unserved POSIX call came back ENOSYS with the error flag set.
    pub enosys: bool,
    /// write(1, …) printed its line and returned its length.
    pub write: bool,
    /// A class-0 service (the timer's rate) answered, error flag clear.
    pub timer: bool,
    /// What it answered: the counter's declared rate, 0 when none is.
    pub timer_hz: usize,
    /// Calls made.
    pub calls: u32,
}

impl Proof {
    pub fn ok(&self) -> bool {
        self.echo && self.getpid && self.enosys && self.write && self.timer
    }
}

/// The self-test's caller: every capability, one message it owns, the
/// counter's frequency as its timer.
struct Boot {
    hz: usize,
}

const MESSAGE: &[u8] = b"  nccall         : write(1) through the HAL\n";
const ECHO_ARGS: [usize; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

impl super::Caller for Boot {
    fn caps(&self) -> u32 {
        u32::MAX
    }
    fn console(&mut self, bytes: &[u8]) -> Result<(), Errno> {
        super::console(bytes);
        Ok(())
    }
    fn owns(&self, ptr: usize, len: usize) -> bool {
        let base = MESSAGE.as_ptr() as usize;
        ptr >= base && ptr.saturating_add(len) <= base + MESSAGE.len()
    }
    fn service(&mut self, nr: u32, _: &[usize; 6]) -> Option<usize> {
        (nr == nanochrono_sys::nr::nc::TIMER_HZ).then_some(self.hz)
    }
}

/// One result as the caller sees it: value, value2, error flag.
type Seen = (usize, usize, bool);

/// The five calls in order: echo, getpid, an unserved POSIX call, write(1)
/// and the timer's rate.
fn calls() -> [(u32, [usize; 6]); 5] {
    use nanochrono_sys::nr::{diag, nc, posix};
    [
        (diag::ECHO, ECHO_ARGS),
        (posix::GETPID, [0; 6]),
        (posix::freebsd(999), [0; 6]),
        (posix::WRITE, [1, MESSAGE.as_ptr() as usize, MESSAGE.len(), 0, 0, 0]),
        (nc::TIMER_HZ, [0; 6]),
    ]
}

/// What the five answers prove.
fn judge(hz: u64, path: &'static str, seen: [Seen; 5], made: u32) -> Proof {
    let (expect, expect2) = nanochrono_sys::nr::diag::echo(ECHO_ARGS);
    Proof {
        path,
        echo: seen[0] == (expect, expect2, false),
        getpid: seen[1] == (1, 0, false),
        enosys: seen[2].2 && seen[2].0 == Errno::ENOSYS.get() as usize,
        write: seen[3] == (MESSAGE.len(), 0, false),
        timer: !seen[4].2 && seen[4].0 == hz as usize,
        timer_hz: seen[4].0,
        calls: made,
    }
}

/// The five calls, made by `make` — through the trap, or the glue.
#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
fn prove(hz: u64, path: &'static str, make: impl Fn(u32, [usize; 6]) -> Seen) -> Proof {
    let mut boot = Boot { hz: hz as usize };
    super::serve(&mut boot, || judge(hz, path, calls().map(|(nr, a)| make(nr, a)), 5))
}

/// Through this ISA's real trap instruction, made with `nanochrono_sys` —
/// the same code a program's `nccall!` compiles to.
#[cfg(any(target_arch = "x86", target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc"))]
fn trap(nr: u32, a: [usize; 6]) -> Seen {
    // SAFETY: the self-test's own calls; echo, getpid and the unserved one
    // touch no memory, write reads MESSAGE (which the Boot caller owns).
    let r = unsafe { nanochrono_sys::raw::dynamic(nr, a) };
    (r.value, r.value2, r.failed)
}

/// Through the glue alone: the frame the entry would have saved, built here.
#[cfg(any(target_arch = "x86_64", target_arch = "powerpc", target_arch = "powerpc64"))]
fn glue(nr: u32, a: [usize; 6]) -> Seen {
    #[cfg(target_arch = "x86_64")]
    {
        crate::ring3::glue_once(nr, a)
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        let mut f = Frame { r: [0; 32], lr: 0, cr: 0, ctr: 0, xer: 0, srr0: 0x1004, srr1: 0 };
        f.r[POWERPC.number] = nr as usize;
        for (slot, v) in POWERPC.args.iter().zip(a) {
            if let Slot::Reg(i) = *slot {
                f.r[i] = v;
            }
        }
        nanochrono_nccall_ppc(&mut f);
        (f.r[POWERPC.ret[0]], f.r[POWERPC.ret[1]], f.cr & 0x1000_0000 != 0)
    }
}

/// The boot-time proof on this ISA. `hz` is the counter's frequency.
pub fn selftest(hz: u64) -> Proof {
    let ready = TRAP_READY.load(core::sync::atomic::Ordering::Relaxed);
    #[cfg(target_arch = "x86_64")]
    {
        let _ = ready;
        prove(hz, "the SYSCALL glue, with a frame (the trap itself: the red-zone probe, from ring 3)", glue)
    }
    #[cfg(target_arch = "x86")]
    {
        let _ = ready;
        prove(hz, "int $0x80, from ring 0", trap)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = ready;
        prove(hz, "svc #0, from the kernel's exception level", trap)
    }
    #[cfg(target_arch = "arm")]
    {
        let _ = ready;
        prove(hz, "svc #0, from SVC mode", trap)
    }
    #[cfg(target_arch = "powerpc")]
    {
        if ready {
            prove(hz, "sc, from supervisor state (e500 IVOR8)", trap)
        } else {
            prove(hz, "the sc glue, with a frame (Open Firmware owns the vectors)", glue)
        }
    }
    #[cfg(target_arch = "powerpc64")]
    {
        let _ = ready;
        prove(hz, "the sc glue, with a frame (skiboot's vectors until PPC64 has its own)", glue)
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        let _ = ready;
        riscv_selftest(hz)
    }
}

// ---------------------------------------------------------------------------
// RISC-V: a short U-mode run, since an S-mode `ecall` goes to the SBI
// ---------------------------------------------------------------------------

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
extern "C" {
    /// Enters `entry(arg)` in U-mode on `stack_top` and returns when it ends
    /// (an `exit` nccall, or any trap from U-mode): `crate::arch::riscv`.
    fn nc_rv_user_run(entry: usize, stack_top: usize, arg: usize) -> usize;
}

/// The U-mode run's results, where its code writes them (satp Bare: U-mode
/// reaches this memory as S-mode does).
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[repr(C)]
struct RvResults {
    seen: [Seen; 5],
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[repr(C, align(16))]
struct RvStack([u8; 8192]);

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
static mut RV_STACK: RvStack = RvStack([0; 8192]);

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
static mut RV_RESULTS: RvResults = RvResults { seen: [(0, 0, false); 5] };

/// Runs in U-mode: the five calls through `ecall`, then `exit(0)`.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
extern "C" fn rv_user_probe(results: *mut RvResults) -> ! {
    use nanochrono_sys::nr::posix;
    let seen = calls().map(|(nr, a)| {
        // SAFETY: as `trap`: nothing but MESSAGE is read.
        let r = unsafe { nanochrono_sys::raw::dynamic(nr, a) };
        (r.value, r.value2, r.failed)
    });
    // SAFETY: the launcher handed over this static and does not touch it
    // until the run has ended.
    unsafe { (*results).seen = seen };
    // SAFETY: exit takes no memory.
    let _ = unsafe { nanochrono_sys::raw::dynamic(posix::EXIT, [0; 6]) };
    // exit does not come back; if it did, the next trap ends the run.
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
fn riscv_selftest(hz: u64) -> Proof {
    let mut boot = Boot { hz: hz as usize };
    RV_END.store(usize::MAX - 1, core::sync::atomic::Ordering::Relaxed);
    let trapped = super::serve(&mut boot, || {
        // SAFETY: the stack and the results are statics only this run uses;
        // the entry point is a function that never returns but by `exit`.
        unsafe {
            let stack_top = (&raw mut RV_STACK) as usize + core::mem::size_of::<RvStack>();
            nc_rv_user_run(rv_user_probe as *const () as usize, stack_top, (&raw mut RV_RESULTS) as usize)
        }
    });
    let ended = RV_END.load(core::sync::atomic::Ordering::Relaxed);
    if trapped != 0 || ended != 0 {
        // A trap other than ecall from U-mode (PMP refusing it, say): no
        // proof, and nothing broken — the run was stepped out of.
        return Proof { path: "ecall from U-mode: the run did not complete (U-mode not usable here)", ..Proof::default() };
    }
    // SAFETY: the run has ended; nothing else writes the results.
    let seen = unsafe { (*(&raw const RV_RESULTS)).seen };
    // The five, and the exit that ended the run.
    judge(hz, "ecall, from U-mode", seen, 6)
}
