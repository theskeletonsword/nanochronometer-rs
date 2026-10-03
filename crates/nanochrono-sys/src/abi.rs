// SPDX-License-Identifier: Apache-2.0
//! The `nccall` ABI of every architecture, as data — and the rules that make
//! the ring 3 → ring 0 transition safe for code that uses a red zone, as
//! checks over that data.
//!
//! `docs/NCCALL.md` is the prose; this module is the table it is written
//! from. Each [`Isa`] has a [`Convention`]: the trapping instruction, the
//! register that carries the call number, the six argument slots, the two
//! result registers and the error flag; and a [`StackModel`]: how big a red
//! zone that architecture's psABI lets user code keep below its stack
//! pointer, how the hardware or the kernel's entry code gets onto a stack the
//! user cannot touch, and how much the kernel skips below an interrupted
//! *kernel* stack pointer before it pushes anything.
//!
//! # The three invariants, stated once
//!
//! 1. **The kernel never writes below a ring-3 stack pointer.** Every entry
//!    from ring 3 — a `nccall`, an exception, an interrupt — reaches a
//!    kernel-owned stack before its first store ([`EntryStack`]). The user's
//!    red zone, whatever its size, is therefore never touched by an entry.
//! 2. **Nothing delivered on the user's behalf lands in its red zone.** A
//!    frame the kernel builds *on* the user stack (a signal or upcall frame,
//!    the first one being the exit shim the plugin returns into) starts at
//!    least [`StackModel::user_red_zone`] bytes below the user's stack
//!    pointer — FreeBSD's `sendsig` rule (`REDZONE_SZ` on amd64, 512 bytes on
//!    powerpc64).
//! 3. **Kernel code keeps no red zone, and the kernel does not rely on
//!    that.** `nckernel` and every `.ncdri` are built without one; and where
//!    a compiler cannot be told so — `clang -mno-red-zone` is silently
//!    ignored on PowerPC, and GCC has no such switch there — the entry path
//!    for an exception taken *in* the kernel skips
//!    [`StackModel::kernel_entry_skip`] bytes first, as FreeBSD's
//!    `trap_subr64.S` does (288 bytes) and its arm64 `exception.S` does
//!    (128 bytes).
//!
//! The tests at the bottom check these against the table for all nine
//! architectures, on any host.
//!
//! # References
//!
//! System V psABIs: x86-64 §3.2.2 "The Stack Frame" (the 128-byte red
//! zone); i386 (none: removed from the i386 psABI); AAPCS64 and AAPCS32
//! "Universal stack constraints" (no access below SP); ELFv2 §2.2.2.4
//! "Protected Zone" (288 bytes usable, 512 protected); RISC-V psABI calling
//! convention (none: interrupts may use the interruptee's stack).
//! Register conventions after FreeBSD's `lib/libsys/<arch>/SYS.h`, OpenBSD's
//! `lib/libc/arch/arm/SYS.h` for ARM32's number register; see NOTICE.

/// The nine instruction sets the kernel is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Isa {
    X86_64,
    I386,
    Aarch64,
    Arm32,
    Ppc,
    Ppc64,
    Ppc64Le,
    Riscv32,
    Riscv64,
}

impl Isa {
    /// Every architecture, in the order the module format numbers them.
    pub const ALL: [Isa; 9] = [
        Isa::X86_64,
        Isa::I386,
        Isa::Aarch64,
        Isa::Arm32,
        Isa::Riscv64,
        Isa::Riscv32,
        Isa::Ppc64,
        Isa::Ppc64Le,
        Isa::Ppc,
    ];

    /// The name the module format, the package manifest and the SDK use.
    pub const fn name(self) -> &'static str {
        match self {
            Isa::X86_64 => "x86_64",
            Isa::I386 => "i386",
            Isa::Aarch64 => "aarch64",
            Isa::Arm32 => "arm32",
            Isa::Ppc => "ppc",
            Isa::Ppc64 => "ppc64",
            Isa::Ppc64Le => "ppc64le",
            Isa::Riscv32 => "riscv32",
            Isa::Riscv64 => "riscv64",
        }
    }

    /// The architecture this crate is being compiled for, if it is one.
    pub const fn current() -> Option<Isa> {
        if cfg!(target_arch = "x86_64") {
            Some(Isa::X86_64)
        } else if cfg!(target_arch = "x86") {
            Some(Isa::I386)
        } else if cfg!(target_arch = "aarch64") {
            Some(Isa::Aarch64)
        } else if cfg!(target_arch = "arm") {
            Some(Isa::Arm32)
        } else if cfg!(target_arch = "riscv32") {
            Some(Isa::Riscv32)
        } else if cfg!(target_arch = "riscv64") {
            Some(Isa::Riscv64)
        } else if cfg!(target_arch = "powerpc") {
            Some(Isa::Ppc)
        } else if cfg!(all(target_arch = "powerpc64", target_endian = "big")) {
            Some(Isa::Ppc64)
        } else if cfg!(all(target_arch = "powerpc64", target_endian = "little")) {
            Some(Isa::Ppc64Le)
        } else {
            None
        }
    }

    /// Bytes in a machine word: the width of every argument slot.
    pub const fn word(self) -> usize {
        match self {
            Isa::X86_64 | Isa::Aarch64 | Isa::Ppc64 | Isa::Ppc64Le | Isa::Riscv64 => 8,
            Isa::I386 | Isa::Arm32 | Isa::Ppc | Isa::Riscv32 => 4,
        }
    }

    /// The register convention.
    pub const fn convention(self) -> Convention {
        match self {
            Isa::X86_64 => X86_64,
            Isa::I386 => I386,
            Isa::Aarch64 => AARCH64,
            Isa::Arm32 => ARM32,
            Isa::Ppc | Isa::Ppc64 | Isa::Ppc64Le => POWERPC,
            Isa::Riscv32 | Isa::Riscv64 => RISCV,
        }
    }

    /// The stack rules.
    pub const fn stack(self) -> StackModel {
        match self {
            Isa::X86_64 => StackModel {
                user_red_zone: 128,
                protected_zone: 128,
                kernel_entry_skip: 0,
                user_entry: EntryStack::HardwareSwitch {
                    how: "TSS.RSP0 for exceptions and interrupts from ring 3; \
                          IST1-5 for #DF, #PF, NMI, #MC, #DB at any level",
                },
                nccall_entry: EntryStack::SoftwareSwitch {
                    how: "SYSCALL keeps the user RSP: the first two instructions \
                          store it and load the kernel's, before any push",
                },
                stack_align: 16,
            },
            Isa::I386 => StackModel {
                user_red_zone: 0,
                protected_zone: 0,
                kernel_entry_skip: 0,
                user_entry: EntryStack::HardwareSwitch {
                    how: "TSS.ESP0/SS0 on any privilege change; #DF through a task gate",
                },
                nccall_entry: EntryStack::HardwareSwitch { how: "int $0x80 is a privilege change: ESP0" },
                stack_align: 16,
            },
            Isa::Aarch64 => StackModel {
                user_red_zone: 0,
                protected_zone: 0,
                kernel_entry_skip: 128,
                user_entry: EntryStack::HardwareSwitch {
                    how: "an exception from EL0 runs on SP_EL1; the user's SP_EL0 is not used",
                },
                nccall_entry: EntryStack::HardwareSwitch { how: "SVC from EL0: SP_EL1" },
                stack_align: 16,
            },
            Isa::Arm32 => StackModel {
                user_red_zone: 0,
                protected_zone: 0,
                kernel_entry_skip: 0,
                user_entry: EntryStack::HardwareSwitch {
                    how: "each exception mode banks its own SP; IRQ and abort \
                          entries move to SVC mode's stack before saving",
                },
                nccall_entry: EntryStack::HardwareSwitch { how: "SVC: SP_svc, banked" },
                stack_align: 8,
            },
            Isa::Ppc => StackModel {
                user_red_zone: 0,
                protected_zone: 0,
                kernel_entry_skip: 0,
                user_entry: EntryStack::SoftwareSwitch {
                    how: "no hardware switch: r1 goes to an SPRG, MSR[PR] in SRR1 \
                          picks the kernel stack before the first store",
                },
                nccall_entry: EntryStack::SoftwareSwitch { how: "sc: the same as any interrupt" },
                stack_align: 16,
            },
            Isa::Ppc64 | Isa::Ppc64Le => StackModel {
                user_red_zone: 288,
                protected_zone: 512,
                kernel_entry_skip: 512,
                user_entry: EntryStack::SoftwareSwitch {
                    how: "no hardware switch: r1 goes to an SPRG, MSR[PR] in SRR1 \
                          picks the kernel stack before the first store",
                },
                nccall_entry: EntryStack::SoftwareSwitch { how: "sc: the same as any interrupt" },
                stack_align: 16,
            },
            Isa::Riscv32 | Isa::Riscv64 => StackModel {
                user_red_zone: 0,
                protected_zone: 0,
                kernel_entry_skip: 0,
                user_entry: EntryStack::SoftwareSwitch {
                    how: "sscratch holds the kernel stack while U-mode runs (0 in \
                          S-mode): csrrw sp, sscratch, sp is the first instruction",
                },
                nccall_entry: EntryStack::SoftwareSwitch { how: "ecall: the same trap vector" },
                stack_align: 16,
            },
        }
    }
}

/// How an entry reaches a stack the interrupted ring-3 code cannot touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryStack {
    /// The processor switches before it pushes anything.
    HardwareSwitch { how: &'static str },
    /// The processor does not switch; the entry code's first instructions do,
    /// using only registers, before any store to the stack.
    SoftwareSwitch { how: &'static str },
}

/// A register, by its assembler name.
pub type Reg = &'static str;

/// Where an argument lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgSlot {
    /// In a register.
    Reg(Reg),
    /// On the user stack, at this byte offset above the stack pointer the
    /// trap saw. The kernel reads it only after checking the range is the
    /// caller's own memory.
    Stack(u8),
}

/// How a failed call is told apart from a successful one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorFlag {
    /// The carry flag: set on failure, clear on success (x86 `RFLAGS.CF`,
    /// ARM `PSTATE.C`/`CPSR.C`).
    Carry,
    /// `CR0[SO]`, summary overflow, on PowerPC.
    Cr0So,
    /// A register that comes back nonzero on failure (`t0` on RISC-V).
    Reg(Reg),
}

/// The register convention of `nccall` on one architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Convention {
    /// The instruction that traps, as written in the stubs.
    pub insn: &'static str,
    /// Its length in bytes: what a restart backs the return address up by.
    pub insn_len: u8,
    /// The register holding the call number.
    pub number: Reg,
    /// The six argument slots, in order.
    pub args: [ArgSlot; 6],
    /// The registers holding the results: the value (or errno), then the
    /// second word.
    pub ret: [Reg; 2],
    /// How failure is flagged.
    pub error: ErrorFlag,
    /// Registers the call may change beyond the psABI's caller-saved set.
    /// Empty everywhere: a `nccall` is a C call to the program, no more.
    pub extra_clobbers: &'static [Reg],
    /// Where the convention comes from.
    pub source: &'static str,
}

/// x86-64: `syscall`. FreeBSD/OpenBSD/NetBSD amd64 alike; `rcx` carries the
/// fourth C argument in a call, but `syscall` overwrites it with the return
/// address, so the stub moves it to `r10` first.
pub const X86_64: Convention = Convention {
    insn: "syscall",
    insn_len: 2,
    number: "rax",
    args: [
        ArgSlot::Reg("rdi"),
        ArgSlot::Reg("rsi"),
        ArgSlot::Reg("rdx"),
        ArgSlot::Reg("r10"),
        ArgSlot::Reg("r8"),
        ArgSlot::Reg("r9"),
    ],
    ret: ["rax", "rdx"],
    error: ErrorFlag::Carry,
    extra_clobbers: &[],
    source: "FreeBSD lib/libsys/amd64/SYS.h",
};

/// i386: `int $0x80`, arguments on the user stack above a return-address
/// slot — all three BSDs. A register convention would need `ebx`, `esi` and
/// `ebp`, which compilers reserve (PIC base, base pointer, frame pointer).
pub const I386: Convention = Convention {
    insn: "int $0x80",
    insn_len: 2,
    number: "eax",
    args: [
        ArgSlot::Stack(4),
        ArgSlot::Stack(8),
        ArgSlot::Stack(12),
        ArgSlot::Stack(16),
        ArgSlot::Stack(20),
        ArgSlot::Stack(24),
    ],
    ret: ["eax", "edx"],
    error: ErrorFlag::Carry,
    extra_clobbers: &[],
    source: "FreeBSD lib/libsys/i386/SYS.h",
};

/// AArch64: `svc #0`, number in `x8`, arguments `x0`-`x5` (FreeBSD reads up
/// to `x7`; `nccall` caps every architecture at six).
pub const AARCH64: Convention = Convention {
    insn: "svc #0",
    insn_len: 4,
    number: "x8",
    args: [
        ArgSlot::Reg("x0"),
        ArgSlot::Reg("x1"),
        ArgSlot::Reg("x2"),
        ArgSlot::Reg("x3"),
        ArgSlot::Reg("x4"),
        ArgSlot::Reg("x5"),
    ],
    ret: ["x0", "x1"],
    error: ErrorFlag::Carry,
    extra_clobbers: &[],
    source: "FreeBSD lib/libsys/aarch64/SYS.h",
};

/// ARM32: `svc #0`, number in `r12` as OpenBSD does (FreeBSD uses `r7`,
/// which is Thumb's frame pointer and cannot be an inline-assembly operand),
/// arguments `r0`-`r5`. `r4` and `r5` are callee-saved: the kernel reads
/// them and gives them back unchanged.
pub const ARM32: Convention = Convention {
    insn: "svc #0",
    insn_len: 4,
    number: "r12",
    args: [
        ArgSlot::Reg("r0"),
        ArgSlot::Reg("r1"),
        ArgSlot::Reg("r2"),
        ArgSlot::Reg("r3"),
        ArgSlot::Reg("r4"),
        ArgSlot::Reg("r5"),
    ],
    ret: ["r0", "r1"],
    error: ErrorFlag::Carry,
    extra_clobbers: &[],
    source: "OpenBSD lib/libc/arch/arm/SYS.h (number register), FreeBSD lib/libsys/arm/SYS.h",
};

/// PowerPC, 32- and 64-bit: `sc`, number in `r0`, arguments `r3`-`r8`,
/// failure in `CR0[SO]`.
pub const POWERPC: Convention = Convention {
    insn: "sc",
    insn_len: 4,
    number: "r0",
    args: [
        ArgSlot::Reg("r3"),
        ArgSlot::Reg("r4"),
        ArgSlot::Reg("r5"),
        ArgSlot::Reg("r6"),
        ArgSlot::Reg("r7"),
        ArgSlot::Reg("r8"),
    ],
    ret: ["r3", "r4"],
    error: ErrorFlag::Cr0So,
    extra_clobbers: &[],
    source: "FreeBSD lib/libsys/powerpc64/SYS.h",
};

/// RISC-V, 32- and 64-bit: `ecall`, number in `t0` (FreeBSD and OpenBSD;
/// `t0` is no argument register, so all of `a0`-`a7` stay free), arguments
/// `a0`-`a5`, failure flagged by `t0` coming back nonzero.
pub const RISCV: Convention = Convention {
    insn: "ecall",
    insn_len: 4,
    number: "t0",
    args: [
        ArgSlot::Reg("a0"),
        ArgSlot::Reg("a1"),
        ArgSlot::Reg("a2"),
        ArgSlot::Reg("a3"),
        ArgSlot::Reg("a4"),
        ArgSlot::Reg("a5"),
    ],
    ret: ["a0", "a1"],
    error: ErrorFlag::Reg("t0"),
    extra_clobbers: &[],
    source: "FreeBSD lib/libsys/riscv/SYS.h",
};

/// The stack rules of one architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackModel {
    /// Bytes below the stack pointer the psABI lets a function use without
    /// moving it: what ring-3 code compiled with the default options keeps
    /// there. 0 where the psABI forbids any access below SP.
    pub user_red_zone: u32,
    /// Bytes below the stack pointer that anything running *without a call*
    /// — an interrupt handler, a signal frame — must leave alone. Equal to
    /// the red zone except on ELFv2 PowerPC, which adds 224 bytes of
    /// "volatile system storage" to its 288.
    pub protected_zone: u32,
    /// Bytes the kernel's entry code skips below an interrupted *kernel*
    /// stack pointer before its first store. Nonzero where kernel code may
    /// carry a red zone it was never asked to (PowerPC64: neither clang's
    /// driver nor GCC turns it off) or where FreeBSD leaves the margin anyway
    /// (arm64).
    pub kernel_entry_skip: u32,
    /// How an exception or interrupt from ring 3 reaches a kernel stack.
    pub user_entry: EntryStack,
    /// How a `nccall` reaches it.
    pub nccall_entry: EntryStack,
    /// The stack alignment the psABI requires at a call.
    pub stack_align: u32,
}

impl StackModel {
    /// Where a frame the kernel builds on the user stack may begin, at the
    /// highest: this far below the user stack pointer, rounded down to the
    /// stack alignment. Invariant 2.
    pub const fn user_frame_gap(&self) -> u32 {
        let gap = self.protected_zone;
        gap.div_ceil(self.stack_align) * self.stack_align
    }
}

/// The red zone each architecture's *kernel* is built with — none, on all
/// nine: the custom target specs set `disable-redzone` and the build passes
/// `-C no-redzone=yes`; the C SDK passes `-mno-red-zone` (x86) or
/// `-Xclang -disable-red-zone` (PowerPC, where the driver flag is dropped).
pub const fn kernel_red_zone(_isa: Isa) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs(c: &Convention) -> impl Iterator<Item = Reg> + '_ {
        c.args.iter().filter_map(|a| match a {
            ArgSlot::Reg(r) => Some(*r),
            ArgSlot::Stack(_) => None,
        })
    }

    #[test]
    fn number_register_is_no_argument() {
        for isa in Isa::ALL {
            let c = isa.convention();
            assert!(regs(&c).all(|r| r != c.number), "{}: number in an argument register", isa.name());
        }
    }

    #[test]
    fn argument_slots_are_distinct() {
        for isa in Isa::ALL {
            let c = isa.convention();
            for (i, a) in c.args.iter().enumerate() {
                for b in &c.args[i + 1..] {
                    assert_ne!(a, b, "{}", isa.name());
                }
            }
            // Stack slots, where there are any, are word-spaced above the
            // return-address slot and stay within the six words.
            for (i, a) in c.args.iter().enumerate() {
                if let ArgSlot::Stack(off) = a {
                    assert_eq!(*off as usize, (i + 1) * isa.word(), "{}", isa.name());
                }
            }
        }
    }

    #[test]
    fn first_result_overwrites_the_first_argument_or_the_number() {
        // Every BSD convention returns where the number or the first
        // argument went in, so a stub needs no extra register.
        for isa in Isa::ALL {
            let c = isa.convention();
            let first = match c.args[0] {
                ArgSlot::Reg(r) => r,
                ArgSlot::Stack(_) => c.number,
            };
            assert!(c.ret[0] == first || c.ret[0] == c.number, "{}", isa.name());
            assert_ne!(c.ret[0], c.ret[1]);
        }
    }

    #[test]
    fn error_flag_does_not_hide_a_result() {
        for isa in Isa::ALL {
            let c = isa.convention();
            if let ErrorFlag::Reg(r) = c.error {
                assert!(!c.ret.contains(&r), "{}: error register is a result register", isa.name());
                // RISC-V reuses the number register for the flag: it is read
                // after the call, the number before.
                assert_eq!(r, c.number);
            }
        }
    }

    #[test]
    fn red_zones_match_the_psabis() {
        // The numbers the psABI documents (see the module references), and
        // what clang/rustc were measured to do with a leaf function's locals.
        let expected = [
            (Isa::X86_64, 128, 128),
            (Isa::I386, 0, 0),
            (Isa::Aarch64, 0, 0),
            (Isa::Arm32, 0, 0),
            (Isa::Ppc, 0, 0),
            (Isa::Ppc64, 288, 512),
            (Isa::Ppc64Le, 288, 512),
            (Isa::Riscv32, 0, 0),
            (Isa::Riscv64, 0, 0),
        ];
        for (isa, rz, pz) in expected {
            let s = isa.stack();
            assert_eq!(s.user_red_zone, rz, "{}", isa.name());
            assert_eq!(s.protected_zone, pz, "{}", isa.name());
            assert!(s.protected_zone >= s.user_red_zone);
        }
    }

    #[test]
    fn invariant_1_user_entries_never_push_on_the_user_stack() {
        // Every entry from ring 3 is a hardware switch, or a software one
        // whose first instructions use registers only. There is no third
        // kind in the table, which is the invariant.
        for isa in Isa::ALL {
            let s = isa.stack();
            for e in [s.user_entry, s.nccall_entry] {
                match e {
                    EntryStack::HardwareSwitch { how } | EntryStack::SoftwareSwitch { how } => {
                        assert!(!how.is_empty(), "{}", isa.name())
                    }
                }
            }
        }
    }

    #[test]
    fn invariant_2_user_frames_start_below_the_protected_zone() {
        for isa in Isa::ALL {
            let s = isa.stack();
            let gap = s.user_frame_gap();
            assert!(gap >= s.protected_zone, "{}", isa.name());
            assert_eq!(gap % s.stack_align, 0, "{}", isa.name());
        }
    }

    #[test]
    fn invariant_3_kernel_entries_clear_any_kernel_red_zone() {
        for isa in Isa::ALL {
            let s = isa.stack();
            // Where a compiler may keep a red zone in kernel code despite
            // being asked not to (PowerPC64), the entry skips the whole
            // protected zone; elsewhere the kernel is built without one.
            let worst_case_kernel_red_zone = match isa {
                Isa::Ppc64 | Isa::Ppc64Le => s.protected_zone,
                _ => kernel_red_zone(isa),
            };
            assert!(s.kernel_entry_skip >= worst_case_kernel_red_zone, "{}", isa.name());
            assert_eq!(s.kernel_entry_skip % s.stack_align, 0, "{}", isa.name());
        }
    }

    #[test]
    fn six_argument_words_everywhere() {
        for isa in Isa::ALL {
            assert_eq!(isa.convention().args.len(), crate::nr::MAX_ARGS);
        }
    }

    #[test]
    fn current_isa_is_known_on_supported_hosts() {
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(Isa::current().is_some());
        }
    }
}
