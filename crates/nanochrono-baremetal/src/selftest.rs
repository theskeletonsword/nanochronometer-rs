// SPDX-License-Identifier: Apache-2.0
//! What the freestanding kernel actually measures.
//!
//! Everything here runs with interrupts masked on a core nothing else is
//! using, which is the condition a hosted benchmark spends most of its effort
//! approximating. The numbers are therefore the floor: whatever a hosted
//! process measures for the same work is that floor plus the operating
//! system.

use crate::pmu::{CorePmu, CounterRoute};
#[cfg(x86_any)]
use crate::progress::{self, Phase};
use crate::{arch, println};
use nanochrono_core::arch as counters;
#[cfg(x86_any)]
use nanochrono_core::aml::{GpioInterrupt, Namespace, Provenance};
use nanochrono_core::redundancy::Protected;

/// Runs every check and reports it over the serial port.
///
/// # Safety
/// Programs the PMU, so it requires ring 0 / EL1.
pub unsafe fn run() {
    println!("NanoChronometer {} — freestanding", crate::VERSION);
    println!("arch: {}", counters::ARCH.name());
    println!();

    #[cfg(x86_any)]
    progress::phase(Phase::CpuFeatures, report_cpu);
    #[cfg(not(x86_any))]
    report_cpu();

    // SAFETY: forwarded from this function's own contract.
    #[cfg(x86_any)]
    progress::enter(Phase::Pmu);
    // SAFETY: forwarded from this function's own contract.
    unsafe { report_pmu() };
    #[cfg(x86_any)]
    progress::leave(Phase::Pmu);
    #[cfg(x86_any)]
    progress::phase(Phase::Counter, report_counter);
    #[cfg(not(x86_any))]
    report_counter();

    #[cfg(x86_any)]
    {
        progress::enter(Phase::Pci);
        // SAFETY: forwarded from this function's own contract.
        unsafe { report_usb() };
        // SAFETY: as above; reads firmware tables only.
        unsafe { report_dma() };
        // SAFETY: as above; reads firmware tables only.
        unsafe { report_acpi_namespace() };
        progress::leave(Phase::Pci);
    }
    #[cfg(x86_any)]
    progress::enter(Phase::Hypervisor);
    // SAFETY: forwarded from this function's own contract.
    unsafe { report_hypervisor() };
    #[cfg(x86_any)]
    progress::leave(Phase::Hypervisor);

    report_integrity();
}

/// What USB host controllers this machine has.
///
/// Reports what PCI enumeration found and stops there. Bringing a controller
/// up is deliberately *not* done here: `Input::init` does it, once, and doing
/// it in both places meant resetting a controller that already had a device
/// addressed and an endpoint configured. Under an emulator a second reset is
/// survivable; on real hardware it is a controller that stops answering, and
/// three bounded waits of ten million iterations each looks exactly like a
/// hang.
///
/// # Safety
/// Reads PCI configuration space; requires ring 0.
#[cfg(x86_any)]
unsafe fn report_usb() {
    use crate::pci;

    println!("== USB host controllers ==");
    let mut found = 0;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        pci::scan(|dev| {
            if let Some(kind) = dev.usb_kind() {
                found += 1;
                println!("  {:04x}:{:04x}  {}", dev.vendor, dev.device, kind.name());
                println!(
                    "    {:02x}:{:02x}.{}  bar0={}",
                    dev.bus,
                    dev.slot,
                    dev.function,
                    Hex(dev.bar0)
                );
                if kind == pci::UsbKind::Xhci {
                    // The two bring-up steps an emulator never exercises. A
                    // controller that asks for scratchpad pages and a
                    // firmware that owns it are both real-hardware-only, and
                    // both are silent failures when skipped.
                    // SAFETY: reads capability registers only.
                    let (scratchpad, firmware_owned) = crate::xhci::survey(&dev);
                    println!("    scratchpad pages : {scratchpad}");
                    println!(
                        "    owned by firmware: {}",
                        if firmware_owned { "yes" } else { "no" }
                    );
                }
            }
            true
        })
    };
    if found == 0 {
        println!("  none; input is whatever firmware translated to the 8042");
    } else {
        println!("  brought up by the input layer, once, when PS/2 finds nothing");
    }
    println!();
}

/// Who can write memory behind the CPU's back.
///
/// # Safety
/// Reads ACPI tables; requires ring 0.
#[cfg(x86_any)]
unsafe fn report_dma() {
    println!("== DMA protection ==");
    let mut iommu = None;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        crate::acpi::for_each_table_signature(|sig| {
            match &sig {
                b"DMAR" => iommu = Some("Intel VT-d (DMAR)"),
                b"IVRS" => iommu = Some("AMD-Vi (IVRS)"),
                _ => {}
            }
            iommu.is_none()
        })
    };
    let lockdown = crate::pci::dma_lockdown();
    println!("  iommu          : {} (not programmed by this kernel)", iommu.unwrap_or("none described"));
    println!("  bus mastering  : revoked on {}, kept on {}", lockdown.revoked, lockdown.kept);
    println!("  kept devices (bridges, display, USB hosts) can still reach all of memory");
    println!();
}

/// What the firmware's AML says is on this machine.
///
/// Printed because the namespace walk is the least verifiable thing in this
/// kernel from the outside: an I2C-HID touchpad that does not appear could be
/// a machine with no touchpad, a table that would not parse, or a walk that
/// stopped after three objects. The device count separates those — a real
/// DSDT holds dozens, and a number in the single digits means the walk gave
/// up rather than the machine being empty.
///
/// # Safety
/// Reads firmware tables; requires ring 0 and an identity map.
#[cfg(x86_any)]
unsafe fn report_acpi_namespace() {
    use nanochrono_core::aml::{Namespace, I2C_HID_CID};

    println!("== ACPI namespace ==");
    // SAFETY: forwarded from this function's own contract.
    let (source, xsdt) = unsafe { crate::acpi::root_source() };
    println!(
        "  root table     : {} ({})",
        source.name(),
        if xsdt { "xsdt" } else { "rsdt" }
    );
    // SAFETY: as above.
    println!(
        "  legacy scan    : {}",
        if unsafe { crate::acpi::legacy_scan_works() } {
            "finds an RSDP (BIOS boot)"
        } else {
            "finds nothing (UEFI boot: only the loader knows)"
        }
    );

    // SAFETY: as above.
    let Some(table) = (unsafe { crate::acpi::dsdt() }) else {
        println!("  no DSDT, or one whose checksum did not verify");
        println!();
        return;
    };
    println!("  dsdt           : {} bytes", table.len());

    let Some(namespace) = Namespace::new(table) else {
        println!("  the table's length field does not fit the table");
        println!();
        return;
    };

    let mut devices = 0u32;
    let mut with_ids = 0u32;
    namespace.for_each_device(|device| {
        devices += 1;
        if device.hid.is_some() || device.cid.is_some() {
            with_ids += 1;
        }
        true
    });
    println!("  devices        : {devices} ({with_ids} with a _HID or _CID)");

    // The SSDTs are part of the namespace, not an extra. Firmware routinely
    // declares a device in the DSDT and the bus it sits on in an SSDT, so
    // "how many are there, and do they walk" is worth a line of its own.
    // SAFETY: reads firmware tables; ring 0 and an identity map, as above.
    let mut ssdts = 0usize;
    let mut ssdt_devices = 0u32;
    let mut ssdt_bytes = 0usize;
    unsafe {
        crate::acpi::for_each_ssdt(|table| {
            ssdts += 1;
            ssdt_bytes += table.len();
            if let Some(ssdt) = Namespace::new(table) {
                ssdt.for_each_device(|_| {
                    ssdt_devices += 1;
                    true
                });
            }
            true
        })
    };
    println!("  ssdts          : {ssdts} ({ssdt_bytes} bytes, {ssdt_devices} more devices)");

    // The inventory itself, so "no SSDTs" and "SSDTs this could not read"
    // are different answers rather than the same line.
    let mut inventory = crate::text::Text::<160>::new();
    // SAFETY: as above.
    unsafe {
        crate::acpi::for_each_table_signature(|signature| {
            if !inventory.is_empty() {
                inventory.push(b' ');
            }
            inventory.str(core::str::from_utf8(&signature).unwrap_or("????"));
            // The buffer is the bound, not a count: a machine with thirty
            // tables should list as many as fit rather than an arbitrary
            // prefix chosen here.
            inventory.has_room_for(5)
        })
    };
    println!("  tables         : {}", inventory.as_str());

    // Looked for across every table, the way the driver does.
    let mut in_ssdt = None;
    if namespace.find_device(|device| device.is(I2C_HID_CID)).is_none() {
        // SAFETY: as above.
        unsafe {
            crate::acpi::for_each_ssdt(|table| {
                let Some(ssdt) = Namespace::new(table) else {
                    return true;
                };
                if let Some(device) = ssdt.find_device(|device| device.is(I2C_HID_CID)) {
                    in_ssdt = Some(device.path);
                    return false;
                }
                true
            })
        };
        if let Some(path) = in_ssdt {
            let mut rendered = [0u8; 64];
            let used = path.render(&mut rendered);
            println!(
                "  i2c-hid        : {} (in an SSDT, not the DSDT)",
                core::str::from_utf8(&rendered[..used]).unwrap_or("?")
            );
        }
    }

    match namespace.find_device(|device| device.is(I2C_HID_CID)) {
        Some(device) => {
            let mut path = [0u8; 64];
            let used = device.path.render(&mut path);
            println!(
                "  i2c-hid        : {}",
                core::str::from_utf8(&path[..used]).unwrap_or("?")
            );
            if let Some(hid) = device.hid {
                println!("    _HID         : {}", hid.as_str());
            }
            let mut scratch = [0u8; 32];
            match namespace.find_i2c_hid(&mut scratch) {
                Some(found) => {
                    println!("    slave        : {}", Hex(found.bus.slave_address as u64));
                    println!("    bus speed    : {} Hz", found.bus.connection_speed);
                    match found.descriptor_register {
                        Some(register) => {
                            println!("    descriptor   : {}", Hex(register as u64))
                        }
                        None => println!(
                            "    descriptor   : _DSM not evaluable; the driver will probe for it"
                        ),
                    }
                    println!("    resources    : {}", match found.provenance {
                        Provenance::Crs => "from _CRS",
                        Provenance::DeclaredBuffers => {
                            "_CRS not evaluable; read from the device's declared buffers"
                        }
                    });
                    report_controller(&namespace, &found.bus.controller);
                    match found.interrupt {
                        Some(interrupt) => {
                            println!("    gpio pin     : {}", interrupt.pin);
                            #[cfg(x86_any)]
                            report_gpio(&namespace, interrupt);
                        }
                        None => println!("    gpio pin     : none declared"),
                    }
                }
                None => println!("    _CRS/_DSM    : not readable by this interpreter"),
            }
        }
        None => println!("  i2c-hid        : no PNP0C50 device on this machine"),
    }
    println!();
}

/// Reports where the I2C controller a `_CRS` names was found, and its `_ADR`.
///
/// The step that failed on the machine this was written against. The
/// touchpad's `Device (TPD0)` is in the DSDT; the `Device (I2C5)` it hangs
/// off is in one of sixteen SSDTs, and a reader that looks only at the DSDT
/// resolves the controller by name and then finds nothing declaring it.
/// Printing which table it came from is what tells those two apart.
///
/// # Safety
///
/// Reads firmware tables. Reads only, and every failure is a printed line.
#[cfg(x86_any)]
fn report_controller(namespace: &Namespace, wanted: &nanochrono_core::aml::Path) {
    use nanochrono_core::aml::Value;

    let mut rendered = [0u8; 64];
    let used = wanted.render(&mut rendered);
    println!(
        "    controller   : {}",
        core::str::from_utf8(&rendered[..used]).unwrap_or("?")
    );

    let adr = |ns: &Namespace| -> Option<u64> {
        let device = ns.find_device(|candidate| candidate.path.ends_with(wanted))?;
        match ns.evaluate(&device, b"_ADR", &[]) {
            Some(Value::Integer(value)) => Some(value),
            _ => None,
        }
    };

    let mut source = "";
    let mut address = adr(namespace);
    if address.is_some() {
        source = "dsdt";
    } else {
        let mut index = 0usize;
        let mut which = 0usize;
        // SAFETY: reads firmware tables; ring 0 and an identity map.
        unsafe {
            crate::acpi::for_each_ssdt(|table| {
                index += 1;
                let Some(ssdt) = Namespace::new(table) else {
                    return true;
                };
                if let Some(found) = adr(&ssdt) {
                    address = Some(found);
                    which = index;
                    return false;
                }
                true
            })
        };
        if address.is_some() {
            source = "ssdt";
            println!("    found in     : ssdt #{which}");
        }
    }

    match address {
        Some(address) => println!(
            "    _ADR         : {} -> {:02}.{} ({source})",
            Hex(address),
            (address >> 16) & 0x1F,
            address & 0x07
        ),
        None => println!("    _ADR         : no table declares this controller with one"),
    }
}

/// Reports whether the pin an I2C-HID device declared can actually be read.
///
/// This is the readiness gate's own diagnostic: it says which route the
/// driver would take before the driver takes it, so a machine where the gate
/// does not close can be told apart from one where it was never tried.
///
/// # Safety
///
/// Reads firmware-declared MMIO. Reads only, and every failure is a printed
/// line rather than a fault.
#[cfg(x86_any)]
fn report_gpio(namespace: &Namespace, interrupt: GpioInterrupt) {
    let mut path = [0u8; 64];
    let used = interrupt.controller.render(&mut path);
    println!(
        "    gpio ctrl    : {}",
        core::str::from_utf8(&path[..used]).unwrap_or("?")
    );

    let device = namespace.find_device(|candidate| candidate.path.ends_with(&interrupt.controller));
    let hid = device.and_then(|candidate| candidate.hid);
    let hid_str = hid.as_ref().map(|id| id.as_str());

    // SAFETY: the windows come from `_CRS` and are inside the identity map;
    // `Controller::open` only reads.
    let Some(controller) =
        (unsafe { crate::gpio::Controller::open(namespace, &interrupt.controller, hid_str) })
    else {
        println!("    gpio windows : none usable; the gate will poll blind");
        return;
    };
    println!(
        "    gpio windows : {} communit{}, part {}",
        controller.communities(),
        if controller.communities() == 1 {
            "y"
        } else {
            "ies"
        },
        controller.platform().unwrap_or("unrecognised")
    );

    match controller.resolve(interrupt.pin) {
        Some(pad) if controller.verify(pad) => {
            println!("    readiness    : gated by pin {} (table)", interrupt.pin)
        }
        Some(_) => println!("    readiness    : table maps the pin, hardware disagrees; will calibrate"),
        None => {
            let calibration = controller.begin_calibration();
            println!(
                "    readiness    : no table; calibrating against {} candidate pads",
                calibration.watching()
            );
        }
    }
}

/// Detection and host-time negotiation.
///
/// Mandatory here, unlike the hosted build: at ring 0 the hypercall is
/// available, it cannot be spoofed by clearing a CPUID bit, and it is the only
/// way to express a guest timestamp on the host's timebase.
///
/// # Safety
/// Issues a hypercall; requires ring 0 / EL1.
unsafe fn report_hypervisor() {
    println!("== Hypervisor ==");
    // SAFETY: forwarded from this function's own contract.
    let report = unsafe { crate::hypervisor::detect() };

    println!("  cpuid bit      : {}", yes_no(report.cpuid_bit));
    let sig = report.signature_str();
    println!(
        "  signature      : {}",
        if sig.is_empty() { "none" } else { sig }
    );
    if report.max_leaf != 0 {
        println!("  max hv leaf    : {}", Hex(report.max_leaf as u64));
    }
    println!("  hypercall      : {}", yes_no(report.hypercall_ok));
    #[cfg(x86_any)]
    println!(
        "  hypercall HAL  : {} (by CPU vendor {})",
        report.hypercall_insn.map_or("none (unknown vendor)", |i| i.name()),
        nanochrono_core::cpu::vendor().name()
    );
    // The number that has to stay small. See `hypervisor::hypercalls`.
    println!(
        "  hypercalls     : {} (boot negotiation only; the stopwatch reads the counter)",
        report.hypercalls
    );
    println!(
        "  probes run     : {} (boot negotiation; re-probe waits {} s between)",
        report.probes,
        nanochrono_core::reprobe::DEFAULT_COOLDOWN_S
    );

    match report.pairing {
        Some(p) => {
            println!("  host clock     : {} ns", p.host_ns);
            println!("  paired counter : {}", p.counter);
            println!("  the guest timebase can be expressed on the host's");
        }
        None if report.is_virtualized() => {
            println!("  no clock pairing: this hypervisor does not offer one");
        }
        None => println!("  bare metal: the counter is physical"),
    }
    println!();
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

/// Hexadecimal, for a build with no formatter beyond `core`.
struct Hex(u64);

impl core::fmt::Display for Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

fn report_cpu() {
    let f = nanochrono_core::cpu::features();
    println!("== CPU ==");
    let irq = crate::irq_priority::state();
    println!("  irq priority   : {} = {}", irq.register, irq.outcome);
    #[cfg(target_arch = "arm")]
    println!("  AArch32 (ARMv7-A)  neon={}", f.neon);
    // Only the extensions this crate can dispatch to are listed; the full set
    // needs formatting machinery an allocator-free build does not have.
    #[cfg(x86_any)]
    {
        // Who made the part, and what follows from it. Not decoration: the
        // vendor decides whether `CPUID.15H`/`16H` may be believed as a
        // counter rate, which is the number every measurement below is
        // divided by. See `nanochrono_core::cpu::Vendor`.
        let vendor = nanochrono_core::cpu::vendor();
        println!("  vendor         : {} ({})", vendor.name(), vendor.as_str());
        let centaur = nanochrono_core::cpu::centaur_max_leaf();
        if centaur != 0 {
            // Only the Centaur/Zhaoxin lineage implements this range, so a
            // value here identifies the part even where the vendor string
            // has been overridden.
            println!("  centaur leaves : up to {}", Hex(centaur as u64));
        }
        println!(
            "  tsc leaves     : {}",
            if vendor.states_a_trustworthy_tsc_rate() {
                "CPUID.15H/16H trusted (Intel)"
            } else {
                "not trusted for this vendor; the counter is measured instead"
            }
        );
        println!("  sse2={} avx={} avx2={}", f.sse2, f.avx, f.avx2);
        println!(
            "  avx512f={} aesni={} shani={}",
            f.avx512f, f.aesni, f.shani
        );
        println!("  invariant tsc={}", f.invariant_counter);

        // The boot stub is what makes the wide register files usable, so what
        // it managed to enable is worth reporting: CPUID can advertise AVX or
        // AVX-512 while XCR0 says the state is not being saved, and then
        // every VEX or EVEX instruction is #UD. Printing both sides makes a
        // mismatch visible instead of silently disabling a feature.
        use nanochrono_core::arch::x86::cpuid;
        let xcr0 = nanochrono_core::arch::x86::xcr0_safe();
        println!("  xcr0={xcr0:#x} (supported {:#x})", cpuid(0x0D, 0)[0]);
        println!(
            "  cpuid avx512f={} osxsave={}",
            cpuid(7, 0)[1] & (1 << 16) != 0,
            cpuid(1, 0)[2] & (1 << 27) != 0
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        println!("  neon={} sve={} sve2={}", f.neon, f.sve, f.sve2);
        println!("  aes={} sha2={} sme={}", f.arm_aes, f.arm_sha2, f.sme);
        println!("  el={}", crate::arch::arm::current_el());
        println!(
            "  mmu            : {}",
            if crate::arch::arm::mmu_enabled() {
                "on (identity; image normal write-back, the rest device)"
            } else {
                "off (all memory device-nGnRnE)"
            }
        );
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        use crate::arch::riscv;
        println!("  rvv={}", f.rvv);
        let sstatus = riscv::sstatus();
        println!(
            "  sstatus={} fs={} vs={}",
            Hex(sstatus as u64),
            (sstatus >> 13) & 3,
            (sstatus >> 9) & 3
        );
        let (spec, id, version) = riscv::sbi_identity();
        println!(
            "  sbi            : {} {} (spec {}.{})",
            riscv::sbi::impl_name(id),
            Hex(version as u64),
            (spec >> 24) & 0x7F,
            spec & 0xFF_FFFF
        );
        println!(
            "  counters       : cycle={} instret={} (mcounteren, as firmware left it)",
            riscv::cycle_readable(),
            riscv::instret_readable()
        );
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        use crate::arch::ppc;
        let pvr = ppc::pvr();
        println!("  core           : {} (pvr {})", ppc::core_name(pvr), Hex(pvr as u64));
        println!("  altivec={} vsx={} vec-crypto={}", f.altivec, f.vsx, f.ppc_vec_crypto);
        println!(
            "  isa 2.07={} 3.0={} 3.1={}",
            f.ppc_isa207, f.ppc_isa300, f.ppc_isa31
        );
        let msr = ppc::msr();
        println!(
            "  msr={} fp={} vec={} vsx={}",
            Hex(msr),
            msr & ppc::MSR_FP != 0,
            msr & ppc::MSR_VEC != 0,
            msr & ppc::MSR_VSX != 0
        );
        #[cfg(target_arch = "powerpc64")]
        println!(
            "  state          : {}",
            if msr & ppc::MSR_HV != 0 { "hypervisor (bare metal)" } else { "supervisor (guest)" }
        );
        println!(
            "  byte order     : {}",
            if cfg!(target_endian = "little") { "little-endian" } else { "big-endian" }
        );
    }
    println!("  backend: {}", nanochrono_core::Backend::best().name());
    println!();

    report_simd();
}

/// Runs the SIMD probes, which is the point of enabling the state at boot.
///
/// Only built when the `simd` feature is on, which needs the custom target:
/// the stable `x86_64-unknown-none` has a soft-float ABI where no vector
/// register can be allocated at all. If this prints numbers, the boot stub's
/// CR0/CR4/XCR0 sequence worked — a vector instruction with any of that
/// missing is `#UD`, not a slow path, so the probe either runs or the machine
/// stops.
#[cfg(feature = "simd")]
fn report_simd() {
    use nanochrono_core::simd::{self, ProbeBuffers, ProbeKind};
    use nanochrono_core::SimdFamily;

    println!("== SIMD (state enabled by the boot stub) ==");

    // Stack buffers: there is no allocator. 64 bytes covers every family up
    // to AVX-512's 64-byte vectors.
    let mut a = [0x5Au8; 64];
    let mut b = [0xA5u8; 64];
    let mut out = [0u8; 64];

    let mut ran = 0;
    for family in SimdFamily::ALL.iter().copied() {
        if !family.is_available() {
            continue;
        }
        let buffers = ProbeBuffers {
            a: &mut a,
            b: &mut b,
            out: &mut out,
        };
        match simd::probe(family, ProbeKind::VectorXor, Some(buffers), 1) {
            Some(r) => {
                println!("  {:<12} xor {} units", family.name(), r.raw_units);
                ran += 1;
            }
            None => println!("  {:<12} probe declined", family.name()),
        }
    }
    if ran == 0 {
        println!("  no family available on this CPU");
    }
    println!();
}

#[cfg(not(feature = "simd"))]
fn report_simd() {
    println!("== SIMD ==");
    println!("  not built: the `simd` feature is off");
    if cfg!(x86_any) {
        println!("  (x86_64-unknown-none is soft-float; use x86_64-nanochrono-none)");
    }
    println!();
}

/// The part that needs no kernel and could not be done with one.
///
/// # Safety
/// Programs the PMU; requires ring 0 / EL1.
unsafe fn report_pmu() {
    println!("== PMU (direct, no kernel) ==");
    let mut pmu = CorePmu::detect();

    println!("  core type      : {}", pmu.core_type.name());
    // Which register interface the counters live behind, decided from the
    // vendor before any MSR was touched. On a part this does not recognise it
    // reads `unknown` and nothing was programmed — which is the safe answer,
    // not a failure to try.
    println!("  interface      : {}", pmu.kind.name());
    println!("  version        : {}", pmu.leaf.version);
    println!(
        "  general        : {} counters, {} bits",
        pmu.leaf.general_counters, pmu.leaf.general_width
    );
    println!(
        "  fixed          : {} counters, {} bits",
        pmu.leaf.fixed_counters, pmu.leaf.fixed_width
    );

    if !pmu.is_available() {
        println!("  no PMU on this core; skipping the measurement");
        println!();
        return;
    }

    // Programming the PMU can succeed and still leave a counter that never
    // moves, so `enable` proves one counts before reporting which.
    // SAFETY: forwarded from this function's own contract.
    let route = unsafe { pmu.enable() };
    println!("  counter route  : {}", route.name());
    if route == CounterRoute::None {
        println!("  no counter advanced; the measurement would be zeros");
        println!();
        return;
    }

    // A dependent chain: each iteration needs the previous result, so the
    // core cannot overlap them and the cycle count reflects real work rather
    // than how wide the machine is.
    const ITERATIONS: u64 = 100_000;
    let mut acc = 0u64;
    // The instruction count is bracketed around the same run as the cycles,
    // so both describe the same work; an instruction counter the route does
    // not have simply reads `None`.
    // SAFETY: as below.
    let insns_before = unsafe { pmu.read_instructions() };
    // SAFETY: the PMU was just enabled on this core, at ring 0 / EL1.
    let (acc_out, cycles) = unsafe {
        pmu.measure(|| {
            for i in 0..ITERATIONS {
                acc = acc.wrapping_add(i).rotate_left(3);
            }
            acc
        })
    };
    core::hint::black_box(acc_out);
    // SAFETY: as above.
    let insns_after = unsafe { pmu.read_instructions() };

    match cycles {
        Some(cycles) => {
            println!("  {ITERATIONS} dependent ops");
            println!("    cycles       : {cycles}");
            // Integer arithmetic only: there is no floating-point formatter
            // here, and this is exact enough to read.
            println!(
                "    cycles/op    : {}.{:02}",
                cycles / ITERATIONS,
                (cycles % ITERATIONS) * 100 / ITERATIONS
            );
        }
        None => println!("  measurement discarded: the core type changed mid-run"),
    }

    // The instruction count is meaningful from more than the fixed counter:
    // on AMD it is a general-purpose counter programmed with the architectural
    // retired-instructions event, read back over the same MSR route. It used
    // to be printed as the counter's absolute value after the run, next to a
    // "core cycles" line that was the same kind of absolute reading — numbers
    // that looked like this run's totals and were not. Both are now the
    // difference over the run, width-aware like the cycle count.
    let width = match route {
        CounterRoute::General(_) => pmu.leaf.general_width,
        _ => pmu.leaf.fixed_width,
    };
    if let (Some(before), Some(after)) = (insns_before, insns_after) {
        if let Some(insns) = after.delta_since_width(before, width) {
            println!("    instructions : {insns}");
            if let Some(cycles) = cycles.filter(|&c| c > 0) {
                // Instructions per cycle, two decimals, integer arithmetic.
                println!(
                    "    ipc          : {}.{:02}",
                    insns / cycles,
                    (insns % cycles) * 100 / cycles
                );
            }
        }
    }
    println!();
}

/// The architectural counter, and what one read of it costs.
fn report_counter() {
    println!("== Counter ==");

    // Minimum of N: anything above the minimum is interference, and with
    // interrupts masked there should be very little of it — which is itself
    // worth seeing.
    const ROUNDS: u32 = 1024;
    let mut min = u64::MAX;
    let mut max = 0u64;
    for _ in 0..ROUNDS {
        // The freestanding read, which on AArch64 is the virtual counter by
        // default, or the physical one when the physical counter is enabled.
        let a = arch::counter_ordered();
        let b = arch::counter_ordered();
        let d = b.wrapping_sub(a);
        if d < min {
            min = d;
        }
        if d > max {
            max = d;
        }
    }
    println!("  read overhead  : {min} units (min of {ROUNDS})");
    println!("  worst read     : {max} units");

    // With no scheduler and no interrupts, the spread between the best and
    // worst read is the machine's own jitter and nothing else. On a hosted
    // build this number is dominated by the kernel.
    println!("  jitter         : {} units", max - min);

    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        match counters::declared_counter_hz() {
            Some(hz) => println!("  counter        : time base ({hz} Hz, from the device tree)"),
            None => println!("  counter        : time base (rate unknown: no timebase-frequency)"),
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        match counters::declared_counter_hz() {
            Some(hz) => println!("  counter        : rdtime ({hz} Hz, from the device tree)"),
            None => println!("  counter        : rdtime (rate unknown: no timebase-frequency)"),
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        println!(
            "  counter        : {} ({} Hz)",
            arch::counter_source().name(),
            counters::aarch64::cntfrq()
        );
        if arch::counter_source() == crate::arch::CounterSource::Physical {
            println!(
                "  warning        : physical counter — not recommended inside a VM"
            );
        }
    }
    println!();
}

/// The ECC/TMR machinery, which needs no kernel either — and matters more
/// here, since a freestanding kernel has no one to report a corrupted value
/// to and no ECC DRAM guarantee beneath it.
fn report_integrity() {
    println!("== Stored-state integrity ==");

    const VALUE: u64 = 0x0000_0002_4126_D2BC;
    let mut p = Protected::new(VALUE);
    println!("  clean          : {}", p.verify().name());

    p.inject_flip(40);
    let outcome = p.verify();
    println!(
        "  one bit        : {} (recovered: {})",
        outcome.name(),
        p.get() == VALUE
    );

    p.inject_flip(5);
    p.inject_flip(37);
    let outcome = p.verify();
    println!(
        "  two bits       : {} (recovered: {})",
        outcome.name(),
        p.get() == VALUE
    );

    let stats = nanochrono_core::redundancy::stats();
    println!(
        "  checks={} ecc={} tmr={} lost={}",
        stats.checks, stats.ecc_corrections, stats.tmr_corrections, stats.unrecoverable
    );
    println!();

    println!("selftest complete; halting");
}
