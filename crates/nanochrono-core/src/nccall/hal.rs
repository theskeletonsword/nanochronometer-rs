// SPDX-License-Identifier: Apache-2.0
//! Where each ISA's `nccall` trap leaves the number, the six arguments and
//! the way back, and where the two results and the error flag go — the
//! registers of `nanochrono_sys::abi`, as slots of the frame the kernel's
//! entry for that ISA saves. Each map is checked against `nanochrono_sys::abi`
//! by the tests below, and the kernel's glue reads and writes its frames
//! through them: the convention is written down once.

use super::{Call, Ending, Reply};
use nanochrono_sys::abi::Isa;

/// Where a value lives: slot `n` of the frame's register array, or a word
/// at that offset from the caller's stack pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Reg(usize),
    Stack(usize),
}

/// How failure is flagged on the way back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// The carry bit of the saved status word, at this bit position.
    Carry(u32),
    /// `CR0[SO]` in the saved condition register.
    Cr0So,
    /// A register set to 1 (failed) or 0.
    Reg(usize),
}

/// One ISA's convention, as slots of its frame.
#[derive(Debug)]
pub struct Map {
    pub isa: Isa,
    /// The frame's register array, slot by slot.
    pub names: &'static [&'static str],
    pub number: usize,
    pub args: [Slot; 6],
    pub ret: [usize; 2],
    pub error: Flag,
}

const fn regs6(first: usize) -> [Slot; 6] {
    [
        Slot::Reg(first),
        Slot::Reg(first + 1),
        Slot::Reg(first + 2),
        Slot::Reg(first + 3),
        Slot::Reg(first + 4),
        Slot::Reg(first + 5),
    ]
}

/// x86-64: `SyscallFrame`'s first seven words (`ring3.rs`); the results go
/// back in RAX and RDX.
pub const X86_64: Map = Map {
    isa: Isa::X86_64,
    names: &["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
    number: 0,
    args: regs6(1),
    ret: [0, 3],
    error: Flag::Carry(0),
};

/// i386: `pusha`'s eight words; the arguments on the caller's stack, where
/// FreeBSD puts them (past a return-address slot).
pub const I386: Map = Map {
    isa: Isa::I386,
    names: &["edi", "esi", "ebp", "esp", "ebx", "edx", "ecx", "eax"],
    number: 7,
    args: [Slot::Stack(4), Slot::Stack(8), Slot::Stack(12), Slot::Stack(16), Slot::Stack(20), Slot::Stack(24)],
    ret: [7, 5],
    error: Flag::Carry(0),
};

const AARCH64_NAMES: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
    "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
];

/// AArch64: x0..x30; PSTATE.C is bit 29 of the saved SPSR.
pub const AARCH64: Map =
    Map { isa: Isa::Aarch64, names: &AARCH64_NAMES, number: 8, args: regs6(0), ret: [0, 1], error: Flag::Carry(29) };

/// ARM32: r0..r12 (the return address and SPSR follow); the C flag is bit 29.
pub const ARM32: Map = Map {
    isa: Isa::Arm32,
    names: &["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"],
    number: 12,
    args: regs6(0),
    ret: [0, 1],
    error: Flag::Carry(29),
};

const PPC_NAMES: [&str; 32] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16",
    "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
];

/// PowerPC, 32- and 64-bit: r0..r31 (r1's slot holds the caller's stack
/// pointer); the error is CR0[SO].
pub const POWERPC: Map =
    Map { isa: Isa::Ppc, names: &PPC_NAMES, number: 0, args: regs6(3), ret: [3, 4], error: Flag::Cr0So };

const RISCV_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
];

/// RISC-V, 32- and 64-bit: x0..x31 by ABI name; the error flag is t0.
pub const RISCV: Map =
    Map { isa: Isa::Riscv64, names: &RISCV_NAMES, number: 5, args: regs6(10), ret: [10, 11], error: Flag::Reg(5) };

/// The call in a frame whose arguments are all registers.
pub fn read(map: &Map, regs: &[usize], site: usize, sp: usize) -> Call {
    let args = map.args.map(|slot| match slot {
        Slot::Reg(i) => regs[i],
        // A stack slot is the glue's to read (it knows whose stack it is).
        Slot::Stack(_) => 0,
    });
    Call { nr: regs[map.number], args, site, sp }
}

/// Writes `reply` into the frame: the results in their registers and the
/// error flag, set or clear. Returns why the caller is ended, if it is; the
/// glue decides what that means on its ISA.
pub fn answer(map: &Map, reply: Reply, regs: &mut [usize], status: &mut usize) -> Option<Ending> {
    let (value, value2, failed) = match reply {
        Reply::Ok(value, value2) => (value, value2, false),
        Reply::Err(e) => (e.get() as usize, 0, true),
        Reply::End(why) => return Some(why),
    };
    regs[map.ret[0]] = value;
    regs[map.ret[1]] = value2;
    let bit = match map.error {
        Flag::Carry(bit) => 1usize << bit,
        Flag::Cr0So => 0x1000_0000,
        Flag::Reg(r) => {
            regs[r] = failed as usize;
            return None;
        }
    };
    if failed {
        *status |= bit;
    } else {
        *status &= !bit;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanochrono_sys::Errno;
    use nanochrono_sys::abi::{ArgSlot, Convention, ErrorFlag};

    fn check(map: &Map, conv: &Convention) {
        assert_eq!(map.names[map.number], conv.number, "{:?}: number", map.isa);
        for (i, (slot, arg)) in map.args.iter().zip(conv.args.iter()).enumerate() {
            match (*slot, *arg) {
                (Slot::Reg(r), ArgSlot::Reg(name)) => assert_eq!(map.names[r], name, "{:?}: argument {i}", map.isa),
                (Slot::Stack(off), ArgSlot::Stack(o)) => assert_eq!(off, o as usize, "{:?}: argument {i}", map.isa),
                other => panic!("{:?}: argument {i}: {other:?}", map.isa),
            }
        }
        assert_eq!([map.names[map.ret[0]], map.names[map.ret[1]]], conv.ret, "{:?}: results", map.isa);
        match (map.error, conv.error) {
            (Flag::Carry(_), ErrorFlag::Carry) | (Flag::Cr0So, ErrorFlag::Cr0So) => {}
            (Flag::Reg(r), ErrorFlag::Reg(name)) => assert_eq!(map.names[r], name, "{:?}: error", map.isa),
            other => panic!("{:?}: error flag {other:?}", map.isa),
        }
    }

    #[test]
    fn every_map_is_the_abi() {
        for isa in Isa::ALL {
            let map = match isa {
                Isa::X86_64 => &X86_64,
                Isa::I386 => &I386,
                Isa::Aarch64 => &AARCH64,
                Isa::Arm32 => &ARM32,
                Isa::Ppc | Isa::Ppc64 | Isa::Ppc64Le => &POWERPC,
                Isa::Riscv32 | Isa::Riscv64 => &RISCV,
            };
            check(map, &isa.convention());
        }
    }

    #[test]
    fn answers_land_where_the_convention_says() {
        let mut regs = [0usize; 32];
        let mut status = 0usize;
        // AArch64: x0/x1 and PSTATE.C.
        assert!(answer(&AARCH64, Reply::Err(Errno::EBADF), &mut regs, &mut status).is_none());
        assert_eq!((regs[0], status), (Errno::EBADF.get() as usize, 1 << 29));
        assert!(answer(&AARCH64, Reply::Ok(7, 8), &mut regs, &mut status).is_none());
        assert_eq!((regs[0], regs[1], status), (7, 8, 0));
        // PowerPC: r3/r4 and CR0[SO], the other CR bits untouched.
        status = 0x2000_0000;
        assert!(answer(&POWERPC, Reply::Err(Errno::ENOSYS), &mut regs, &mut status).is_none());
        assert_eq!((regs[3], status), (78, 0x3000_0000));
        // RISC-V: a0/a1 and t0.
        assert!(answer(&RISCV, Reply::Err(Errno::EIO), &mut regs, &mut status).is_none());
        assert_eq!((regs[10], regs[5]), (5, 1));
        assert!(answer(&RISCV, Reply::Ok(3, 4), &mut regs, &mut status).is_none());
        assert_eq!((regs[10], regs[11], regs[5]), (3, 4, 0));
        // An ending is the glue's to handle; the frame is left alone.
        regs[0] = 99;
        assert_eq!(answer(&AARCH64, Reply::End(Ending::Exit(0)), &mut regs, &mut status), Some(Ending::Exit(0)));
        assert_eq!(regs[0], 99);
    }
}
