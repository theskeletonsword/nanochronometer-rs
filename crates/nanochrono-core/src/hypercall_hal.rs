// SPDX-License-Identifier: Apache-2.0
//! The x86-64 hypercall HAL: which instruction this CPU's vendor defines.
//!
//! Intel VMX defines `VMCALL`; AMD SVM defines `VMMCALL`. Each is `#UD` on
//! the other vendor's silicon unless the hypervisor chooses to emulate it —
//! KVM happens to patch the wrong one, Hyper-V, VMware and others inject the
//! `#UD` — and an unhandled `#UD` in ring 0 is a crash (a bugcheck on
//! Windows, a triple fault on bare metal).
//!
//! So the instruction is **never** fixed at build time. It is chosen at run
//! time, every load and every boot, from `CPUID.0H`: one installed system —
//! an OS on an external SSD, say — moves between an Intel laptop and an AMD
//! desktop, and must issue the right instruction on each.
//!
//! | Vendor string    | Lineage              | Instruction |
//! |------------------|----------------------|-------------|
//! | `GenuineIntel`   | Intel (VMX)          | `VMCALL`    |
//! | `  Shanghai  `   | Zhaoxin (VMX)        | `VMCALL`    |
//! | `CentaurHauls`   | VIA/Centaur (VMX)    | `VMCALL`    |
//! | `AuthenticAMD`   | AMD (SVM)            | `VMMCALL`   |
//! | `HygonGenuine`   | Hygon (AMD-derived)  | `VMMCALL`   |
//! | anything else    | unknown              | none        |
//!
//! An unknown vendor gets no hypercall at all: guessing costs the machine.
//!
//! This table is the reference. The Linux module (`kernel/linux`) and the
//! Windows driver (`kernel/windows`) are built without this crate and carry
//! the same table; the bare-metal kernel uses this one directly.

/// The hypercall instruction of an x86-64 vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypercallInsn {
    /// Intel VMX `VMCALL` (`0F 01 C1`).
    Vmcall,
    /// AMD SVM `VMMCALL` (`0F 01 D9`).
    Vmmcall,
}

impl HypercallInsn {
    /// The mnemonic, lower case.
    pub const fn name(self) -> &'static str {
        match self {
            HypercallInsn::Vmcall => "vmcall",
            HypercallInsn::Vmmcall => "vmmcall",
        }
    }
}

/// The instruction for the vendor string `CPUID.0H` returns (EBX, EDX, ECX),
/// or `None` for a vendor this does not know.
pub const fn for_vendor_signature(signature: &[u8; 12]) -> Option<HypercallInsn> {
    match signature {
        b"GenuineIntel" | b"  Shanghai  " | b"CentaurHauls" => Some(HypercallInsn::Vmcall),
        b"AuthenticAMD" | b"HygonGenuine" => Some(HypercallInsn::Vmmcall),
        _ => None,
    }
}

/// The instruction for the CPU this runs on.
#[cfg(target_arch = "x86_64")]
pub fn detect() -> Option<HypercallInsn> {
    let v = crate::cpu::vendor_signature();
    for_vendor_signature(&v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_vendor_maps_to_its_instruction() {
        assert_eq!(for_vendor_signature(b"GenuineIntel"), Some(HypercallInsn::Vmcall));
        assert_eq!(for_vendor_signature(b"  Shanghai  "), Some(HypercallInsn::Vmcall));
        assert_eq!(for_vendor_signature(b"CentaurHauls"), Some(HypercallInsn::Vmcall));
        assert_eq!(for_vendor_signature(b"AuthenticAMD"), Some(HypercallInsn::Vmmcall));
        assert_eq!(for_vendor_signature(b"HygonGenuine"), Some(HypercallInsn::Vmmcall));
    }

    #[test]
    fn an_unknown_vendor_gets_no_hypercall() {
        assert_eq!(for_vendor_signature(b"GenuineIotel"), None);
        assert_eq!(for_vendor_signature(&[0; 12]), None);
    }
}
