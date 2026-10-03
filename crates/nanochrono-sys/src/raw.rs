// SPDX-License-Identifier: Apache-2.0
//! The `nccall` instruction, one inline-assembly block per architecture
//! family, and the [`nccall!`](crate::nccall) macro over them.
//!
//! # What every block promises the compiler
//!
//! A `nccall` is a C function call as far as the caller's registers go: it
//! may change every register the psABI calls caller-saved — the scratch
//! integer registers, every vector register, the flags — and preserves the
//! callee-saved ones and the stack pointer. `clobber_abi("C")` says exactly
//! that. It is also what lets the kernel *zero* those registers on the way
//! back, so that nothing it computed reaches ring 3 except the results.
//!
//! Every block but i386's (which pushes its arguments) says `nostack`: the
//! trapping instruction does not touch the stack, and the kernel's entry
//! path never writes below a ring-3 stack pointer (docs/NCCALL.md §3). That
//! option is the contract in the compiler's own terms — without it LLVM must
//! assume the block may push, and turns the red zone off in every function
//! that makes a call; with it, a leaf function keeps data in its red zone
//! across a `nccall`, which `NCSYS-DEMO.NCAPP` checks at ring 3.
//!
//! # Pins
//!
//! Each call site whose number is a constant also emits an 8-byte record in
//! the `nccall_pins` section: the site's address as a 32-bit offset from the
//! record, and the number. That is OpenBSD's `PINSYSCALL` (`lib/libc/arch/
//! DEFS.h`, ISC), from which `pinsyscalls(2)` tells its kernel exactly which
//! instruction may make which call; a site whose number is only known at run
//! time records [`NR_ANY`]. The section is allocated and retained (`"aR"`)
//! so `--gc-sections` keeps it, and holds PC-relative offsets only, so it
//! needs no dynamic relocation. The kernel's use of it is described in
//! `docs/NCCALL.md` §7.

use crate::Errno;

/// The number a pin records for a site that can make any call.
pub const NR_ANY: u32 = u32::MAX;

/// What one `nccall` returned: the two result registers and the error flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ret {
    /// The first result register: the value, or the errno when `failed`.
    pub value: usize,
    /// The second result register: the high word of a 64-bit result on a
    /// 32-bit target, or a second value.
    pub value2: usize,
    /// Whether the architecture's error flag came back raised.
    pub failed: bool,
}

impl Ret {
    /// The value, or the error.
    #[inline]
    pub fn result(self) -> Result<usize, Errno> {
        if self.failed {
            Err(Errno(self.value as u32))
        } else {
            Ok(self.value)
        }
    }

    /// The two result words as one 64-bit value, low word in `value`: how a
    /// 32-bit target returns a 64-bit result. On a 64-bit target `value` is
    /// already the whole of it.
    #[inline]
    pub fn result64(self) -> Result<u64, Errno> {
        if self.failed {
            return Err(Errno(self.value as u32));
        }
        if usize::BITS == 64 {
            Ok(self.value as u64)
        } else {
            Ok(self.value as u64 | ((self.value2 as u64) << 32))
        }
    }
}

/// Pads up to six arguments out to the six slots every block loads. Unused
/// slots are zero, so a call never passes the kernel a stale register.
#[inline(always)]
pub const fn args<const N: usize>(a: [usize; N]) -> [usize; 6] {
    assert!(N <= 6, "nccall takes at most six argument words");
    let mut out = [0usize; 6];
    let mut i = 0;
    while i < N {
        out[i] = a[i];
        i += 1;
    }
    out
}

/// The `nccall_pins` record, appended to each block's template: where the
/// `2:` label is, and the number the site makes.
macro_rules! pin {
    () => {
        concat!(
            "\n.pushsection nccall_pins,\"aR\",%progbits\n",
            ".balign 4\n",
            ".long 2b - .\n",
            ".long {nr}\n",
            ".popsection\n"
        )
    };
}

/// One call whose number is a compile-time constant: the site is pinned.
///
/// # Safety
/// The call is whatever `NR` names; the caller passes arguments that call
/// accepts. A call can end the program, or hand the kernel pointers it will
/// write through — the kernel checks them against the caller's own memory,
/// but cannot know which of the caller's buffers it meant.
#[inline(always)]
pub unsafe fn pinned<const NR: u32>(a: [usize; 6]) -> Ret {
    // SAFETY: forwarded.
    unsafe { imp::call::<NR>(NR, a) }
}

/// One call whose number is only known at run time. Its pin records
/// [`NR_ANY`], which a strict kernel policy refuses; prefer [`nccall!`]
/// with a constant.
///
/// # Safety
/// As [`pinned`].
#[inline(always)]
pub unsafe fn dynamic(nr: u32, a: [usize; 6]) -> Ret {
    // SAFETY: forwarded.
    unsafe { imp::call::<NR_ANY>(nr, a) }
}

/// Makes one `nccall`: `nccall!(number, args...)`, at most six argument
/// words, each converted with `as usize`. The number must be a constant (a
/// [`nr`](crate::nr) item); the site is pinned. Evaluates to a [`Ret`].
///
/// ```ignore
/// use nanochrono_sys::{nccall, nr};
/// let msg = b"hello\n";
/// // SAFETY: write(2) reads `msg.len()` bytes from `msg`.
/// let r = unsafe { nccall!(nr::posix::WRITE, 1, msg.as_ptr(), msg.len()) };
/// ```
///
/// # Safety
/// The macro expands to a call of the unsafe [`pinned`]; see there.
#[macro_export]
macro_rules! nccall {
    ($nr:expr $(, $arg:expr)* $(,)?) => {
        $crate::raw::pinned::<{ $nr }>($crate::raw::args([$(($arg) as usize),*]))
    };
}

// ---------------------------------------------------------------------------
// x86-64: syscall. rax = number; rdi rsi rdx r10 r8 r9; rax, rdx; CF.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
mod imp {
    use super::Ret;

    #[inline(always)]
    pub(super) unsafe fn call<const PIN: u32>(nr: u32, a: [usize; 6]) -> Ret {
        let (value, value2, failed): (usize, usize, u8);
        // SAFETY: the caller's contract (see `pinned`). `syscall` writes rcx
        // and r11, which clobber_abi("C") already covers; the flag goes out
        // through cl, which the instruction has just overwritten anyway.
        unsafe {
            core::arch::asm!(
                "2: syscall",
                "setc cl",
                pin!(),
                nr = const PIN,
                lateout("cl") failed,
                inlateout("rax") nr as usize => value,
                inlateout("rdi") a[0] => _,
                inlateout("rsi") a[1] => _,
                inlateout("rdx") a[2] => value2,
                inlateout("r10") a[3] => _,
                inlateout("r8") a[4] => _,
                inlateout("r9") a[5] => _,
                clobber_abi("C"),
                options(nostack),
            );
        }
        Ret { value, value2, failed: failed != 0 }
    }
}

// ---------------------------------------------------------------------------
// i386: int $0x80. eax = number; the arguments on the stack above a
// return-address slot; eax, edx; CF.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86")]
mod imp {
    use super::Ret;

    #[inline(always)]
    pub(super) unsafe fn call<const PIN: u32>(nr: u32, a: [usize; 6]) -> Ret {
        let (value, value2, failed): (usize, usize, u8);
        // SAFETY: the caller's contract. The block pushes seven words and
        // pops them before it ends, so the stack pointer comes back as it
        // went in; `a` is a register holding the array's address, unmoved
        // by the pushes.
        unsafe {
            core::arch::asm!(
                "push dword ptr [{a} + 20]",
                "push dword ptr [{a} + 16]",
                "push dword ptr [{a} + 12]",
                "push dword ptr [{a} + 8]",
                "push dword ptr [{a} + 4]",
                "push dword ptr [{a}]",
                // Where a called stub's return address would be: the kernel
                // reads the arguments from 4(%esp) up, as the BSDs do.
                "push eax",
                "2: int 0x80",
                "setc cl",
                "add esp, 28",
                pin!(),
                nr = const PIN,
                a = in(reg) a.as_ptr(),
                lateout("cl") failed,
                inlateout("eax") nr as usize => value,
                lateout("edx") value2,
                clobber_abi("C"),
            );
        }
        Ret { value, value2, failed: failed != 0 }
    }
}

// ---------------------------------------------------------------------------
// AArch64: svc #0. x8 = number; x0-x5; x0, x1; PSTATE.C.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "aarch64")]
mod imp {
    use super::Ret;

    #[inline(always)]
    pub(super) unsafe fn call<const PIN: u32>(nr: u32, a: [usize; 6]) -> Ret {
        let (value, value2, failed): (usize, usize, usize);
        // SAFETY: the caller's contract. The flag comes out in x9, a
        // temporary. `dsb nsh; isb` after the `svc` keep
        // the next instructions from running speculatively past it
        // (straight-line speculation), as OpenBSD's stubs do.
        unsafe {
            core::arch::asm!(
                "2: svc #0",
                "dsb nsh",
                "isb",
                "cset w9, cs",
                pin!(),
                nr = const PIN,
                lateout("x9") failed,
                inlateout("x8") nr as usize => _,
                inlateout("x0") a[0] => value,
                inlateout("x1") a[1] => value2,
                inlateout("x2") a[2] => _,
                inlateout("x3") a[3] => _,
                inlateout("x4") a[4] => _,
                inlateout("x5") a[5] => _,
                clobber_abi("C"),
                options(nostack),
            );
        }
        Ret { value, value2, failed: failed != 0 }
    }
}

// ---------------------------------------------------------------------------
// ARM32: svc #0. r12 = number; r0-r5; r0, r1; CPSR.C.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "arm")]
mod imp {
    use super::Ret;

    #[inline(always)]
    pub(super) unsafe fn call<const PIN: u32>(nr: u32, a: [usize; 6]) -> Ret {
        let (value, value2, failed): (usize, usize, usize);
        // SAFETY: the caller's contract. r4 and r5 are callee-saved: inputs
        // only, which the kernel hands back unchanged. The flag comes out in
        // r2, whose argument the kernel has consumed. `it cs` makes the
        // conditional move valid in Thumb too; in ARM state it assembles to
        // nothing.
        unsafe {
            core::arch::asm!(
                "2: svc #0",
                "dsb nsh",
                "isb",
                "mov r2, #0",
                "it cs",
                "movcs r2, #1",
                pin!(),
                nr = const PIN,
                inlateout("r12") nr as usize => _,
                inlateout("r0") a[0] => value,
                inlateout("r1") a[1] => value2,
                inlateout("r2") a[2] => failed,
                inlateout("r3") a[3] => _,
                in("r4") a[4],
                in("r5") a[5],
                clobber_abi("C"),
                options(nostack),
            );
        }
        Ret { value, value2, failed: failed != 0 }
    }
}

// ---------------------------------------------------------------------------
// PowerPC, 32- and 64-bit: sc. r0 = number; r3-r8; r3, r4; CR0[SO].
// ---------------------------------------------------------------------------
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
mod imp {
    use super::Ret;

    #[inline(always)]
    pub(super) unsafe fn call<const PIN: u32>(nr: u32, a: [usize; 6]) -> Ret {
        let (value, value2, failed): (usize, usize, usize);
        // SAFETY: the caller's contract. CR0[SO] is bit 3 of the condition
        // register in the architecture's numbering (0x1000_0000): rotating
        // the CR left by 4 and keeping the low bit extracts it, into r9 — a
        // volatile register no `nccall` argument uses.
        unsafe {
            core::arch::asm!(
                "2: sc",
                "mfcr 9",
                "rlwinm 9, 9, 4, 31, 31",
                pin!(),
                nr = const PIN,
                lateout("r9") failed,
                inlateout("r0") nr as usize => _,
                inlateout("r3") a[0] => value,
                inlateout("r4") a[1] => value2,
                inlateout("r5") a[2] => _,
                inlateout("r6") a[3] => _,
                inlateout("r7") a[4] => _,
                inlateout("r8") a[5] => _,
                clobber_abi("C"),
                options(nostack),
            );
        }
        Ret { value, value2, failed: failed != 0 }
    }
}

// ---------------------------------------------------------------------------
// RISC-V, 32- and 64-bit: ecall. t0 = number in, error flag out; a0-a5;
// a0, a1.
// ---------------------------------------------------------------------------
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
mod imp {
    use super::Ret;

    #[inline(always)]
    pub(super) unsafe fn call<const PIN: u32>(nr: u32, a: [usize; 6]) -> Ret {
        let (value, value2, failed): (usize, usize, usize);
        // SAFETY: the caller's contract.
        unsafe {
            core::arch::asm!(
                "2: ecall",
                pin!(),
                nr = const PIN,
                inlateout("t0") nr as usize => failed,
                inlateout("a0") a[0] => value,
                inlateout("a1") a[1] => value2,
                inlateout("a2") a[2] => _,
                inlateout("a3") a[3] => _,
                inlateout("a4") a[4] => _,
                inlateout("a5") a[5] => _,
                clobber_abi("C"),
                options(nostack),
            );
        }
        Ret { value, value2, failed: failed != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_pads_with_zeros() {
        assert_eq!(args([]), [0; 6]);
        assert_eq!(args([7, 8]), [7, 8, 0, 0, 0, 0]);
        assert_eq!(args([1, 2, 3, 4, 5, 6]), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn results_and_errors() {
        let ok = Ret { value: 5, value2: 0, failed: false };
        assert_eq!(ok.result(), Ok(5));
        let err = Ret { value: 14, value2: 0, failed: true };
        assert_eq!(err.result(), Err(Errno::EFAULT));
        assert_eq!(err.result64(), Err(Errno::EFAULT));
        let wide = Ret { value: 0x1234, value2: 0x1, failed: false };
        let want = if usize::BITS == 64 { 0x1234 } else { 0x1_0000_1234 };
        assert_eq!(wide.result64(), Ok(want));
    }
}
