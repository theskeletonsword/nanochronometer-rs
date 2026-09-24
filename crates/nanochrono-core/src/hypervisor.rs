// SPDX-License-Identifier: Apache-2.0
//! Hypervisor and emulation detection.
//!
//! # Why a timing library cares
//!
//! Virtualization changes what a counter reading *means*, and it does so
//! differently depending on how the platform is virtualized:
//!
//! * **Bare metal** — `RDTSC` is a few tens of cycles and the value is the
//!   core's own counter. A nanosecond figure is a nanosecond figure.
//! * **Hardware-assisted** (KVM, VMware, Hyper-V, Xen HVM) — the TSC is
//!   usually passed through with an offset, so reads stay cheap, but the
//!   guest loses time to VM exits and to steal time it cannot see. Short
//!   intervals are trustworthy; anything spanning a scheduling decision is
//!   not.
//! * **Emulated** (QEMU TCG, Rosetta, an ISA simulator) — the counter is
//!   *synthesised*. It has no fixed relationship to wall time or to the
//!   host's cycles, and a nanosecond reading measures the emulator's
//!   bookkeeping rather than any real work.
//!
//! Reporting which of those applies is the difference between a number and a
//! number you can act on, which is why [`HypervisorReport::timing_impact`]
//! exists and why the CLI and GUI surface it next to every measurement.
//!
//! # Two layers
//!
//! This module is the ring 3 / EL0 layer: CPUID plus platform signatures. It
//! needs no privileges and is always available.
//!
//! The optional kernel module in `kernel/linux/` complements it with probes
//! that only ring 0 can perform — `vmcall`, `vmmcall`, `hvc`, and the VMX/SVM
//! MSRs. It is **not required**: without it detection still works, it is just
//! less certain against a hypervisor that hides its CPUID leaf. When the
//! module is loaded, [`HypervisorReport::detect`] merges its findings and
//! raises the confidence accordingly.

use std::fmt;
use std::path::Path;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::arch;

/// A hypervisor or emulator, identified by its published signature.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Hypervisor {
    /// Nothing detected. On a well-behaved platform this means bare metal.
    #[default]
    None,
    Kvm,
    /// QEMU's pure-software interpreter. Everything is emulated, including
    /// the counter.
    QemuTcg,
    VMware,
    HyperV,
    Xen,
    VirtualBox,
    Parallels,
    Bhyve,
    Acrn,
    Jailhouse,
    /// Apple's Virtualization.framework.
    AppleVz,
    Qnx,
    /// Windows Subsystem for Linux (Hyper-V based, but reports distinctly).
    Wsl,
    /// A signature that was found but is not in the table.
    Other(String),
}

impl Hypervisor {
    pub fn name(&self) -> &str {
        match self {
            Hypervisor::None => "none",
            Hypervisor::Kvm => "KVM",
            Hypervisor::QemuTcg => "QEMU TCG",
            Hypervisor::VMware => "VMware",
            Hypervisor::HyperV => "Hyper-V",
            Hypervisor::Xen => "Xen",
            Hypervisor::VirtualBox => "VirtualBox",
            Hypervisor::Parallels => "Parallels",
            Hypervisor::Bhyve => "bhyve",
            Hypervisor::Acrn => "ACRN",
            Hypervisor::Jailhouse => "Jailhouse",
            Hypervisor::AppleVz => "Apple Virtualization",
            Hypervisor::Qnx => "QNX",
            Hypervisor::Wsl => "WSL",
            Hypervisor::Other(s) => s,
        }
    }

    /// Whether this platform emulates the instruction set rather than running
    /// it natively — the case where counter readings stop being physical.
    pub fn is_emulated(&self) -> bool {
        matches!(self, Hypervisor::QemuTcg)
    }
}

impl fmt::Display for Hypervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The 12-byte CPUID vendor signatures, as published by each vendor.
///
/// Read from `CPUID.40000000H` in `EBX:ECX:EDX`. The list is ordered by how
/// often they turn up in practice, since matching stops at the first hit.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const CPUID_SIGNATURES: &[(&str, Hypervisor)] = &[
    ("KVMKVMKVM\0\0\0", Hypervisor::Kvm),
    ("TCGTCGTCGTCG", Hypervisor::QemuTcg),
    ("VMwareVMware", Hypervisor::VMware),
    ("Microsoft Hv", Hypervisor::HyperV),
    ("XenVMMXenVMM", Hypervisor::Xen),
    ("VBoxVBoxVBox", Hypervisor::VirtualBox),
    ("prl hyperv  ", Hypervisor::Parallels),
    (" lrpepyh vr ", Hypervisor::Parallels),
    ("bhyve bhyve ", Hypervisor::Bhyve),
    ("ACRNACRNACRN", Hypervisor::Acrn),
    ("Jailhouse\0\0\0", Hypervisor::Jailhouse),
    ("Apple VZ\0\0\0\0", Hypervisor::AppleVz),
    ("QNXQVMBSQG\0\0", Hypervisor::Qnx),
    ("MicrosoftXTA", Hypervisor::HyperV),
];

/// How a conclusion was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSource {
    /// `CPUID.1:ECX[31]`, the architectural "hypervisor present" bit.
    CpuidFeatureBit,
    /// The vendor signature at `CPUID.40000000H`.
    CpuidVendorLeaf,
    /// `CNTFRQ_EL0` reports a tick rate no physical SoC uses.
    ///
    /// The AArch64 counterpart of the CPUID vendor leaf, and the only
    /// identification signal readable from EL0 without a trap: the register
    /// is architecturally unprivileged, and a virtual machine has to pick a
    /// frequency for its virtual timer.
    ArmCounterFrequency,
    /// `MIDR_EL1` names an implementer or part that only appears under
    /// emulation.
    ArmMidr,
    /// Darwin's `kern.hv_vmm_present` sysctl.
    ///
    /// The macOS counterpart of the CPUID feature bit, and the only detector
    /// that works on Apple Silicon, where there is no CPUID: the kernel
    /// answers whether it is itself running under a VMM.
    MacSysctl,
    /// A registry key Windows only creates inside a guest.
    ///
    /// The path that works on ARM64 Windows, where there is no CPUID to ask.
    WindowsRegistry,
    /// SMBIOS/DMI strings under `/sys/class/dmi/id/`.
    Dmi,
    /// `/sys/hypervisor/type`.
    SysHypervisor,
    /// `/proc/device-tree/hypervisor/compatible`, the AArch64 route.
    DeviceTree,
    /// The `hypervisor` flag in `/proc/cpuinfo`.
    ProcCpuinfo,
    /// A paravirtual clocksource, e.g. `kvm-clock` or `hyperv_clocksource`.
    Clocksource,
    /// Paravirtual devices: virtio, VMBus, or the Xen bus.
    ParavirtualBus,
    /// The optional ring 0 kernel module.
    KernelModule,
    /// A measured trap cost, not a declaration.
    ExitCostTiming,
}

impl DetectionSource {
    pub const fn name(self) -> &'static str {
        match self {
            DetectionSource::CpuidFeatureBit => "cpuid-feature-bit",
            DetectionSource::CpuidVendorLeaf => "cpuid-vendor-leaf",
            DetectionSource::ArmCounterFrequency => "arm-cntfrq-el0",
            DetectionSource::ArmMidr => "arm-midr-el1",
            DetectionSource::MacSysctl => "mac-sysctl",
            DetectionSource::WindowsRegistry => "windows-registry",
            DetectionSource::Dmi => "dmi",
            DetectionSource::SysHypervisor => "sys-hypervisor",
            DetectionSource::DeviceTree => "device-tree",
            DetectionSource::ProcCpuinfo => "proc-cpuinfo",
            DetectionSource::Clocksource => "clocksource",
            DetectionSource::ParavirtualBus => "paravirtual-bus",
            DetectionSource::KernelModule => "kernel-module",
            DetectionSource::ExitCostTiming => "exit-cost-timing",
        }
    }

    /// Whether the source is a declaration by the platform rather than an
    /// inference. A hypervisor that wants to stay hidden can suppress every
    /// declared source; it cannot easily suppress the cost of a trap.
    pub const fn is_declared(self) -> bool {
        // A timing ratio and an unusual register value are both inferences:
        // nothing announced itself, the number merely looks wrong. They can
        // raise suspicion but must not confirm on their own, or an unusual
        // piece of silicon becomes a false positive.
        !matches!(
            self,
            DetectionSource::ExitCostTiming
                | DetectionSource::ArmCounterFrequency
                | DetectionSource::ArmMidr
        )
    }
}

/// How much weight the evidence carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Confidence {
    /// No evidence of virtualization.
    #[default]
    None,
    /// Something is off — usually an anomalous trap cost — but nothing
    /// declared itself.
    Suspected,
    /// The platform declared itself, or ring 0 confirmed a hypercall.
    Confirmed,
}

impl Confidence {
    pub const fn name(self) -> &'static str {
        match self {
            Confidence::None => "none",
            Confidence::Suspected => "suspected",
            Confidence::Confirmed => "confirmed",
        }
    }
}

/// What virtualization means for the numbers this library produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimingImpact {
    /// Bare metal. Counter readings are physical; nanosecond figures mean
    /// what they say.
    #[default]
    Native,
    /// Hardware-assisted virtualization. The counter is usually passed
    /// through with an offset, so reads stay cheap and short intervals hold
    /// up. Longer ones absorb steal time the guest cannot observe.
    HardwareAssisted,
    /// Instruction-set emulation. The counter is synthesised and bears no
    /// fixed relation to wall time; nanosecond figures describe the emulator.
    Emulated,
}

impl TimingImpact {
    pub const fn name(self) -> &'static str {
        match self {
            TimingImpact::Native => "native",
            TimingImpact::HardwareAssisted => "hardware-assisted",
            TimingImpact::Emulated => "emulated",
        }
    }

    /// One sentence on what to trust, for the status bar and report headers.
    pub const fn advice(self) -> &'static str {
        match self {
            TimingImpact::Native => {
                "Bare metal: counter readings are physical and nanosecond figures are meaningful."
            }
            TimingImpact::HardwareAssisted => {
                "Virtualized: short intervals are sound, but anything spanning a VM exit or steal \
                 time is not. Pin the vCPU and prefer minimum-of-N over the mean."
            }
            TimingImpact::Emulated => {
                "Emulated: the counter is synthesised, so nanosecond figures measure the emulator, \
                 not the workload. Use these numbers for correctness checks only, never for \
                 performance claims."
            }
        }
    }
}

/// A measured trap cost.
///
/// `CPUID` is serializing and, on most hypervisors, unconditionally exits to
/// the VMM. Comparing it against a plain counter read pair gives a number that
/// no amount of CPUID spoofing can hide, and which also directly quantifies
/// the per-exit latency the caller is worried about.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ExitCost {
    /// Minimum cycles observed for one `CPUID`.
    pub trap_cycles: u64,
    /// Minimum cycles observed for a bare counter read pair.
    pub baseline_cycles: u64,
    /// `trap_cycles / baseline_cycles`.
    pub ratio: f64,
    /// Whether the ratio exceeds [`EXIT_RATIO_THRESHOLD`].
    pub suggests_exit: bool,
}

/// Ratio above which a `CPUID` is taken to be trapping to a VMM.
///
/// Native `CPUID` runs 100–250 cycles against roughly 30 for a fenced counter
/// pair, so a native ratio sits under 10. A VM exit and re-entry costs at
/// least ~1000 cycles even on modern hardware, which lands well above 20 —
/// wide enough that the threshold does not need to be precise.
pub const EXIT_RATIO_THRESHOLD: f64 = 20.0;

/// SMBIOS strings, when the platform exposes them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DmiHints {
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub bios_vendor: Option<String>,
}

impl DmiHints {
    /// macOS has no DMI to read. Darwin's sysctl namespace carries the same
    /// kind of identifying strings, so those stand in — `hw.model` is what
    /// names a virtual Mac, and the CPU brand string names an emulated core.
    #[cfg(target_os = "macos")]
    fn read() -> DmiHints {
        use crate::platform::darwin;
        DmiHints {
            sys_vendor: darwin::sysctl_string("hw.model"),
            product_name: darwin::sysctl_string("machdep.cpu.brand_string"),
            bios_vendor: darwin::sysctl_string("hw.target"),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    fn read() -> DmiHints {
        DmiHints {
            sys_vendor: read_trimmed("/sys/class/dmi/id/sys_vendor"),
            product_name: read_trimmed("/sys/class/dmi/id/product_name"),
            bios_vendor: read_trimmed("/sys/class/dmi/id/bios_vendor"),
        }
    }

    /// Windows has no `/sys/class/dmi`; the same SMBIOS table comes from
    /// `GetSystemFirmwareTable('RSMB')`.
    ///
    /// Rather than walk the SMBIOS type-1/type-0 structures — which would mean
    /// parsing a binary format for three strings — the raw table is scanned
    /// for the vendor names. A hypervisor that writes "VMware" into SMBIOS
    /// writes it as a NUL-terminated string in that blob either way, and this
    /// signal is corroboration for CPUID rather than the primary evidence.
    #[cfg(target_os = "windows")]
    fn read() -> DmiHints {
        let Some(table) = read_smbios_table() else {
            return DmiHints::default();
        };
        // Strings in SMBIOS are NUL-terminated ASCII; split on NUL and keep
        // the ones long enough to be a vendor name.
        let strings: Vec<String> = table
            .split(|&b| b == 0)
            .filter(|s| s.len() >= 3 && s.iter().all(|&b| (0x20..0x7f).contains(&b)))
            .map(|s| String::from_utf8_lossy(s).trim().to_string())
            .collect();

        DmiHints {
            // The whole blob is offered under `product_name` because the
            // identifier below matches on substrings and does not care which
            // SMBIOS field a vendor string came from.
            product_name: (!strings.is_empty()).then(|| strings.join(" | ")),
            sys_vendor: None,
            bios_vendor: None,
        }
    }

    /// Matches the strings against known virtual platforms.
    fn identify(&self) -> Option<Hypervisor> {
        // Ordered so that a specific product name wins over a generic vendor:
        // "QEMU" as sys_vendor appears under both KVM and TCG, and only the
        // CPUID leaf can tell those apart.
        const TABLE: &[(&str, Hypervisor)] = &[
            ("vmware", Hypervisor::VMware),
            ("virtualbox", Hypervisor::VirtualBox),
            ("innotek", Hypervisor::VirtualBox),
            ("parallels", Hypervisor::Parallels),
            ("xen", Hypervisor::Xen),
            ("bhyve", Hypervisor::Bhyve),
            ("kvm", Hypervisor::Kvm),
            ("qemu", Hypervisor::Kvm),
            ("bochs", Hypervisor::QemuTcg),
            ("apple virtualization", Hypervisor::AppleVz),
            // What Virtualization.framework reports in `hw.model`.
            ("virtualmac", Hypervisor::AppleVz),
        ];

        for field in [&self.product_name, &self.sys_vendor, &self.bios_vendor]
            .into_iter()
            .flatten()
        {
            let lowered = field.to_ascii_lowercase();
            for (needle, hv) in TABLE {
                if lowered.contains(needle) {
                    return Some(hv.clone());
                }
            }
        }
        None
    }
}

/// What the optional kernel module reported.
///
/// Every field is `None` when the module is not loaded, which is the normal
/// case — see the module note in [the module docs](self).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KernelProbe {
    /// The module's own format version, so a stale module is not misparsed.
    pub version: u32,
    /// `VMCALL` executed without faulting. Intel VMX guest.
    pub vmcall_ok: Option<bool>,
    /// `VMMCALL` executed without faulting. AMD SVM guest.
    pub vmmcall_ok: Option<bool>,
    /// `HVC #0` executed without faulting. AArch64 guest under an EL2 handler.
    pub hvc_ok: Option<bool>,
    /// Value the hypercall returned, when one answered.
    pub hypercall_result: Option<i64>,
    /// The host CPU exposes VMX, so nested virtualization is possible.
    pub vmx_available: Option<bool>,
    /// The host CPU exposes SVM.
    pub svm_available: Option<bool>,
    /// Exception level the kernel runs at, on AArch64.
    pub current_el: Option<u32>,
    /// Trap cost measured from ring 0, free of userspace scheduling noise.
    pub exit_cycles: Option<u64>,
    /// The lineage the module named — `intel`, `amd`, `zhaoxin`, `centaur`.
    ///
    /// Read from ring 0, where `CPUID.0H` cannot have been filtered on the
    /// way out the way a hypervisor can filter what a guest sees.
    pub cpu_family: Option<String>,
    /// The highest Centaur extended leaf the part answers, if it has the
    /// range at all. Only the VIA/Centaur lineage and Zhaoxin do, so a value
    /// here identifies the part even where the vendor string was overridden.
    pub centaur_max_leaf: Option<u32>,
    /// The AArch64 vendor hypervisor UID, as the four words SMCCC returns.
    ///
    /// Only a hypervisor implements the vendor range at all, so an answer
    /// here is proof of one regardless of what it turns out to say. The words
    /// are kept raw because the byte order that assembles them into a UUID is
    /// a convention this code has never been able to test against a real
    /// AArch64 guest — reporting them verbatim lets a human identify the
    /// hypervisor without this code guessing.
    pub hvc_vendor_uid: Option<[u32; 4]>,
    /// How many times the module has run its exit-inducing probes since it
    /// loaded (1 = only the load-time probe). Format version 4 on.
    pub hypercall_probes: Option<u32>,
    /// Milliseconds since that last probe, as of the read.
    pub hypercall_age_ms: Option<u64>,
    /// The module's re-probe cooldown in seconds; 0 = disabled.
    pub hypercall_cooldown_s: Option<u32>,
    /// Milliseconds until the module accepts a re-probe.
    pub hypercall_next_ms: Option<u64>,
}

impl KernelProbe {
    /// Whether any hypercall instruction was accepted.
    ///
    /// This is the module's whole reason to exist: a hypercall that returns
    /// instead of faulting is proof of a hypervisor even when CPUID says
    /// nothing, because the instruction is only valid inside a guest.
    pub fn hypercall_accepted(&self) -> bool {
        [self.vmcall_ok, self.vmmcall_ok, self.hvc_ok]
            .into_iter()
            .flatten()
            .any(|ok| ok)
    }
}

/// The complete finding.
#[derive(Debug, Clone, Default)]
pub struct HypervisorReport {
    pub hypervisor: Hypervisor,
    pub confidence: Confidence,
    pub timing_impact: TimingImpact,
    /// Every source that contributed, in the order they were consulted.
    pub sources: Vec<DetectionSource>,
    /// The raw 12-byte CPUID signature, if one was found.
    pub signature: Option<String>,
    /// Highest hypervisor CPUID leaf the platform answers.
    pub max_hypervisor_leaf: Option<u32>,
    /// TSC frequency the hypervisor declares, in kHz.
    ///
    /// KVM and VMware publish this at `CPUID.40000010H`. When present it is
    /// more trustworthy than calibrating against the guest's own clock, since
    /// both are supplied by the same hypervisor.
    pub declared_tsc_khz: Option<u32>,
    pub exit_cost: Option<ExitCost>,
    pub dmi: DmiHints,
    pub kernel: Option<KernelProbe>,
    /// `CNTFRQ_EL0`, the AArch64 timer frequency in Hz. Zero elsewhere.
    pub arm_counter_hz: u64,
    /// `CTR_EL0`, the AArch64 Cache Type Register. Zero elsewhere.
    pub arm_ctr_el0: u64,
    /// `MIDR_EL1`, the AArch64 Main ID Register. Zero elsewhere or unreadable.
    pub arm_midr_el1: u64,
}

/// Where the optional kernel module publishes its findings.
///
/// `/proc` and mode 0444, so an unprivileged measurement process can read it —
/// which is the whole point, and why the module declares the procfs ABI itself
/// rather than using the debugfs abstraction the kernel's Rust crate offers
/// (debugfs is mode 0700).
pub const KERNEL_MODULE_PATHS: &[&str] = &["/proc/nanochrono"];

/// The process-wide detection, run once.
///
/// [`HypervisorReport::detect`] costs a few microseconds, most of it the trap
/// probe, and the answer cannot change while the process runs — so callers
/// that annotate every measurement should come through here rather than
/// re-detecting.
///
/// It is also the anti-DoS rule of [`crate::reprobe`]: the exit-cost probe
/// makes a guest exit 128 times, and a process that did that on every panel
/// refresh would look like an attack to a cloud host. Everything reads this
/// cache; only [`reprobe`] probes again, behind the cooldown.
pub fn cached() -> &'static HypervisorReport {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HypervisorReport> = OnceLock::new();
    CACHE.get_or_init(|| {
        let report = HypervisorReport::detect();
        let now = crate::platform::monotonic_ns();
        // The load-time probe counts as the first: a re-probe waits the
        // cooldown from here.
        let _ = reprobe_gate().try_begin(now);
        report
    })
}

fn reprobe_gate() -> std::sync::MutexGuard<'static, crate::reprobe::Gate> {
    static GATE: std::sync::Mutex<crate::reprobe::Gate> =
        std::sync::Mutex::new(crate::reprobe::Gate::new());
    GATE.lock().unwrap_or_else(|p| p.into_inner())
}

fn latest_slot() -> std::sync::MutexGuard<'static, Option<HypervisorReport>> {
    static LATEST: std::sync::Mutex<Option<HypervisorReport>> = std::sync::Mutex::new(None);
    LATEST.lock().unwrap_or_else(|p| p.into_inner())
}

/// The most recent detection: the last successful [`reprobe`], else
/// [`cached`]. Never probes.
pub fn latest() -> HypervisorReport {
    if let Some(report) = latest_slot().as_ref() {
        return report.clone();
    }
    cached().clone()
}

/// Seconds until [`reprobe`] is allowed (0 = now).
pub fn reprobe_wait_s() -> u32 {
    let _ = cached();
    reprobe_gate().remaining_s(crate::platform::monotonic_ns())
}

/// Whether this process enforces the re-probe cooldown.
pub fn reprobe_cooldown_enabled() -> bool {
    reprobe_gate().cooldown_enabled()
}

/// Turns this process's re-probe cooldown on (10 s) or off. Off is the
/// user's risk: see [`crate::reprobe::COOLDOWN_OFF_WARNING`].
pub fn set_reprobe_cooldown_enabled(on: bool) {
    reprobe_gate().set_cooldown_enabled(on);
}

/// How [`reprobe`] went.
#[derive(Debug)]
pub enum ReprobeError {
    /// This process's cooldown: try again in this many seconds.
    CoolingDown { wait_s: u32 },
}

impl std::fmt::Display for ReprobeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReprobeError::CoolingDown { wait_s } => {
                write!(f, "re-probe cooling down: wait {wait_s} s (anti-abuse limit for cloud hosts)")
            }
        }
    }
}

/// Probes the hypervisor again — the button, not the refresh.
///
/// Refused while this process's cooldown runs. When the ring-0 module is
/// loaded it is asked to re-probe too; the module has its own cooldown and
/// may refuse (or the caller may not be root), in which case its cached
/// report is merged as it is. The second value carries that outcome.
pub fn reprobe() -> Result<(HypervisorReport, Option<std::io::Error>), ReprobeError> {
    let _ = cached();
    let now = crate::platform::monotonic_ns();
    if let Err(crate::reprobe::Refused::CoolingDown { remaining_ns }) =
        reprobe_gate().try_begin(now)
    {
        return Err(ReprobeError::CoolingDown {
            wait_s: remaining_ns.div_ceil(1_000_000_000) as u32,
        });
    }
    let module = if std::path::Path::new(KERNEL_MODULE_PATH).exists() {
        kernel_module_reprobe().err()
    } else {
        None
    };
    let report = HypervisorReport::detect();
    *latest_slot() = Some(report.clone());
    Ok((report, module))
}

impl HypervisorReport {
    /// Runs every detection this process can perform.
    ///
    /// Costs a few microseconds: the CPUID leaves are cheap, the file reads
    /// are a handful of `open`/`read` pairs, and the trap measurement is a
    /// short minimum-of-N loop.
    pub fn detect() -> HypervisorReport {
        let mut report = HypervisorReport {
            dmi: DmiHints::read(),
            ..Default::default()
        };

        report.detect_cpuid();
        report.detect_platform_files();
        report.detect_windows_registry();
        report.detect_mac_sysctl();
        report.detect_dmi();
        report.measure_exit_cost();
        report.merge_kernel_module();
        report.conclude();
        report
    }

    /// Detection without the timing probe, for callers that cannot afford
    /// even a few microseconds or that are themselves inside a measurement.
    pub fn detect_declared_only() -> HypervisorReport {
        let mut report = HypervisorReport {
            dmi: DmiHints::read(),
            ..Default::default()
        };
        report.detect_cpuid();
        report.detect_platform_files();
        report.detect_windows_registry();
        report.detect_mac_sysctl();
        report.detect_dmi();
        report.merge_kernel_module();
        report.conclude();
        report
    }

    /// Whether anything indicates virtualization.
    pub fn is_virtualized(&self) -> bool {
        self.confidence != Confidence::None
    }

    /// Whether the optional kernel module contributed.
    pub fn has_kernel_module(&self) -> bool {
        self.kernel.is_some()
    }

    fn note(&mut self, source: DetectionSource) {
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn detect_cpuid(&mut self) {
        use arch::x86::cpuid;

        // CPUID.1:ECX[31]. Architecturally reserved on real hardware, which is
        // why every hypervisor uses it to announce itself.
        if cpuid(1, 0)[2] & (1 << 31) != 0 {
            self.note(DetectionSource::CpuidFeatureBit);
        }

        // The vendor leaf. Hyper-V nested under another hypervisor moves its
        // signature up in 0x100 steps, so a few slots are scanned rather than
        // just the first.
        for base in [0x4000_0000u32, 0x4000_0100, 0x4000_0200] {
            let r = cpuid(base, 0);
            let signature = signature_bytes(r[1], r[2], r[3]);
            let Some(text) = decode_signature(&signature) else {
                continue;
            };

            self.note(DetectionSource::CpuidVendorLeaf);
            self.signature = Some(text.trim_end().to_string());
            self.max_hypervisor_leaf = Some(r[0]);

            if let Some(hv) = match_signature(&signature) {
                self.hypervisor = hv;
            } else {
                self.hypervisor = Hypervisor::Other(text.trim_end().to_string());
            }

            // CPUID.40000010H:EAX — the TSC frequency in kHz, published by KVM
            // and VMware. Only meaningful if the leaf is in range.
            if r[0] >= 0x4000_0010 {
                let freq = cpuid(0x4000_0010, 0)[0];
                if freq > 0 {
                    self.declared_tsc_khz = Some(freq);
                }
            }
            break;
        }
    }

    /// AArch64 has no CPUID, so the equivalent evidence comes from the few
    /// system registers the architecture lets EL0 read.
    ///
    /// `MRS` on an EL1 register traps, and the kernel emulates some of those
    /// transparently — which means a trap tells you nothing about a
    /// hypervisor underneath and risks a `SIGILL` where it does not. So only
    /// the architecturally unprivileged registers are read here: `CNTFRQ_EL0`
    /// and `CTR_EL0`. `MIDR_EL1` is EL1-only by architecture and is read from
    /// sysfs, where Linux publishes it, rather than by taking a trap.
    #[cfg(target_arch = "aarch64")]
    fn detect_cpuid(&mut self) {
        use crate::arch::aarch64;

        // A virtual machine has to pick a frequency for its virtual timer,
        // and the common ones are not values physical SoCs use. This is a
        // corroborating signal rather than a declaration: a future SoC could
        // legitimately pick one, so it never confirms on its own.
        let hz = aarch64::cntfrq();
        if let Some(hv) = counter_frequency_signature(hz) {
            self.note(DetectionSource::ArmCounterFrequency);
            if self.hypervisor == Hypervisor::None {
                self.hypervisor = hv;
            }
        }
        self.arm_counter_hz = hz;

        // CTR_EL0 is EL0-readable by architecture. A zero line size is not a
        // configuration any silicon ships; it means nothing modelled caches.
        let ctr = aarch64::ctr_el0();
        self.arm_ctr_el0 = ctr;

        if let Some(midr) = read_midr_el1() {
            self.arm_midr_el1 = midr;
            if let Some(hv) = midr_signature(midr) {
                self.note(DetectionSource::ArmMidr);
                if self.hypervisor == Hypervisor::None {
                    self.hypervisor = hv;
                }
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    fn detect_cpuid(&mut self) {
        // No CPU identification path on this architecture; detection rests on
        // the platform files below and the kernel module.
    }

    /// Asks the Darwin kernel directly.
    ///
    /// `kern.hv_vmm_present` is the whole answer on macOS: the kernel knows
    /// whether it booted under a VMM and says so. It is a declaration, not an
    /// inference, and unlike everything else here it works identically on
    /// Intel and Apple Silicon — which matters, because Apple Silicon has no
    /// CPUID and none of the Linux files exist.
    #[cfg(target_os = "macos")]
    fn detect_mac_sysctl(&mut self) {
        use crate::platform::darwin;

        if darwin::sysctl_u64("kern.hv_vmm_present") != Some(1) {
            return;
        }
        self.note(DetectionSource::MacSysctl);
        if self.hypervisor != Hypervisor::None {
            return;
        }
        // The kernel reports that a VMM is present but does not name it, so
        // the hardware model is the only identifying string available. Under
        // Apple's own Virtualization.framework it reads "VirtualMac2,1".
        self.hypervisor = match darwin::sysctl_string("hw.model") {
            Some(model) if model.to_ascii_lowercase().contains("virtualmac") => Hypervisor::AppleVz,
            Some(model) => Hypervisor::Other(model),
            None => Hypervisor::Other("unidentified (kern.hv_vmm_present)".to_string()),
        };
    }

    #[cfg(not(target_os = "macos"))]
    fn detect_mac_sysctl(&mut self) {}

    /// Reads the places Windows records virtualization.
    ///
    /// The registry is the identification path that does not need CPUID,
    /// which is what makes it the primary one on ARM64 Windows and a useful
    /// second opinion on x86.
    #[cfg(target_os = "windows")]
    fn detect_windows_registry(&mut self) {
        let Some((hv, _which)) = read_registry_evidence() else {
            return;
        };
        self.note(DetectionSource::WindowsRegistry);
        if self.hypervisor == Hypervisor::None {
            self.hypervisor = hv;
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn detect_windows_registry(&mut self) {}

    /// Reads the places Linux records virtualization.
    ///
    /// Every path here is Linux-specific and simply does not exist on Windows,
    /// where the CPUID leaf and the SMBIOS table carry the evidence instead.
    /// That is why the passive CPUID leaf is the primary detector on both
    /// platforms: it is the only source common to them.
    fn detect_platform_files(&mut self) {
        if let Some(kind) = read_trimmed("/sys/hypervisor/type") {
            self.note(DetectionSource::SysHypervisor);
            if self.hypervisor == Hypervisor::None {
                self.hypervisor = match kind.to_ascii_lowercase().as_str() {
                    "xen" => Hypervisor::Xen,
                    other => Hypervisor::Other(other.to_string()),
                };
            }
        }

        // The AArch64 route: the firmware describes the hypervisor in the
        // device tree because there is no CPUID to ask.
        if let Some(compatible) = read_trimmed("/proc/device-tree/hypervisor/compatible") {
            self.note(DetectionSource::DeviceTree);
            let lowered = compatible.to_ascii_lowercase();
            if self.hypervisor == Hypervisor::None {
                self.hypervisor = if lowered.contains("xen") {
                    Hypervisor::Xen
                } else if lowered.contains("kvm") {
                    Hypervisor::Kvm
                } else {
                    Hypervisor::Other(compatible.trim_end_matches('\0').to_string())
                };
            }
        }

        // WSL identifies itself in the kernel release string rather than
        // through any of the usual channels.
        if let Some(release) = read_trimmed("/proc/sys/kernel/osrelease") {
            if release.to_ascii_lowercase().contains("microsoft") {
                self.note(DetectionSource::ProcCpuinfo);
                if matches!(self.hypervisor, Hypervisor::None | Hypervisor::HyperV) {
                    self.hypervisor = Hypervisor::Wsl;
                }
            }
        }

        // The clocksource the kernel settled on names the hypervisor directly
        // when a paravirtual one is in use, and the kernel picks it from its
        // own detection — so this corroborates CPUID without depending on it.
        if let Some(clocksource) =
            read_trimmed("/sys/devices/system/clocksource/clocksource0/current_clocksource")
        {
            let identified = match clocksource.as_str() {
                "kvm-clock" => Some(Hypervisor::Kvm),
                "xen" => Some(Hypervisor::Xen),
                s if s.starts_with("hyperv") => Some(Hypervisor::HyperV),
                "vmware" => Some(Hypervisor::VMware),
                _ => None,
            };
            if let Some(hv) = identified {
                self.note(DetectionSource::Clocksource);
                if self.hypervisor == Hypervisor::None {
                    self.hypervisor = hv;
                }
            }
        }

        // Paravirtual buses only exist inside a guest: the host has no reason
        // to enumerate virtio devices or a VMBus.
        for (path, hv) in [
            ("/sys/bus/vmbus/devices", Some(Hypervisor::HyperV)),
            ("/proc/xen", Some(Hypervisor::Xen)),
            ("/sys/bus/virtio/devices", None),
        ] {
            let populated = std::fs::read_dir(path)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(false);
            if !populated {
                continue;
            }
            self.note(DetectionSource::ParavirtualBus);
            if let (Some(hv), Hypervisor::None) = (hv, &self.hypervisor) {
                self.hypervisor = hv;
            }
        }

        if let Some(cpuinfo) = read_trimmed("/proc/cpuinfo") {
            if cpuinfo
                .lines()
                .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"))
            {
                self.note(DetectionSource::ProcCpuinfo);
            }
        }
    }

    fn detect_dmi(&mut self) {
        if let Some(hv) = self.dmi.identify() {
            self.note(DetectionSource::Dmi);
            if self.hypervisor == Hypervisor::None {
                self.hypervisor = hv;
            }
        }
    }

    /// Times a `CPUID` against a bare counter read.
    ///
    /// Minimum-of-N on both sides: any sample above the minimum contains
    /// interference, and interference is exactly what must not leak into a
    /// ratio that decides whether an exit happened.
    fn measure_exit_cost(&mut self) {
        let Some(cost) = measure_trap_cost() else {
            return;
        };
        if cost.suggests_exit {
            self.note(DetectionSource::ExitCostTiming);
        }
        self.exit_cost = Some(cost);
    }

    fn merge_kernel_module(&mut self) {
        let Some(probe) = KERNEL_MODULE_PATHS.iter().find_map(read_kernel_module) else {
            return;
        };
        self.note(DetectionSource::KernelModule);

        // Ring 0 can distinguish what ring 3 can only infer, so its verdict on
        // the exit cost replaces the userspace estimate.
        if let (Some(exit), Some(cost)) = (probe.exit_cycles, self.exit_cost.as_mut()) {
            cost.trap_cycles = exit;
            if cost.baseline_cycles > 0 {
                cost.ratio = exit as f64 / cost.baseline_cycles as f64;
                cost.suggests_exit = cost.ratio >= EXIT_RATIO_THRESHOLD;
            }
        }

        // A hypercall that returns instead of faulting is proof, and it holds
        // even against a hypervisor that clears the CPUID bit.
        if probe.hypercall_accepted() && self.hypervisor == Hypervisor::None {
            self.hypervisor = if probe.vmmcall_ok == Some(true) {
                // VMMCALL is AMD SVM; KVM on AMD answers it.
                Hypervisor::Kvm
            } else {
                Hypervisor::Other("unidentified (hypercall accepted)".to_string())
            };
        }

        self.kernel = Some(probe);
    }

    /// Weighs the evidence into a verdict and a timing impact.
    fn conclude(&mut self) {
        let declared = self.sources.iter().any(|s| s.is_declared());
        let hypercall = self
            .kernel
            .as_ref()
            .is_some_and(KernelProbe::hypercall_accepted);

        // Nothing declared itself, but something looks wrong: a trap cost an
        // order of magnitude more than it should, or a register holds a value
        // no physical part ships. Worth reporting, not worth asserting.
        let inferred = self.sources.iter().any(|s| !s.is_declared());

        self.confidence = if declared || hypercall {
            Confidence::Confirmed
        } else if inferred {
            Confidence::Suspected
        } else {
            Confidence::None
        };

        self.timing_impact = if self.hypervisor.is_emulated() {
            TimingImpact::Emulated
        } else if self.confidence == Confidence::None {
            TimingImpact::Native
        } else {
            TimingImpact::HardwareAssisted
        };
    }

    /// A one-line summary for a status bar.
    pub fn summary(&self) -> String {
        if !self.is_virtualized() {
            return format!("native ({})", self.timing_impact.name());
        }
        let mut s = format!(
            "{} [{}, {}]",
            self.hypervisor.name(),
            self.confidence.name(),
            self.timing_impact.name()
        );
        if let Some(cost) = &self.exit_cost {
            if cost.suggests_exit {
                s.push_str(&format!(" exit≈{} cyc", cost.trap_cycles));
            }
        }
        s
    }

    /// A multi-line report for the CLI.
    pub fn detailed(&self) -> String {
        use fmt::Write as _;
        let mut out = String::new();

        let _ = writeln!(out, "hypervisor    : {}", self.hypervisor.name());
        let _ = writeln!(out, "confidence    : {}", self.confidence.name());
        let _ = writeln!(out, "timing impact : {}", self.timing_impact.name());

        // The CPU's own vendor, distinct from any hypervisor's. Zhaoxin is
        // why it earns a line: its parts are x86-64 out of VIA's Centaur
        // lineage, they carry Intel-style architectural PMUs and VMX — so a
        // guest on one answers `VMCALL` exactly like an Intel part, and the
        // probe needs no special case — but Linux does not read their
        // `CPUID.15H`/`16H` counter-rate leaves, and code that treats "not
        // AMD" as "Intel" would read them and build every later measurement
        // on the answer.
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            let vendor = crate::cpu::vendor();
            let _ = writeln!(
                out,
                "cpu vendor    : {} ({})",
                vendor.name(),
                vendor.as_str()
            );
            let centaur = crate::cpu::centaur_max_leaf();
            if centaur != 0 {
                let _ = writeln!(out, "centaur leaves: up to {centaur:#x}");
            }
            if !vendor.states_a_trustworthy_tsc_rate() {
                let _ = writeln!(
                    out,
                    "counter rate  : measured, not read from CPUID (not an Intel part)"
                );
            }
        }
        if let Some(sig) = &self.signature {
            let _ = writeln!(out, "cpuid vendor  : {sig:?}");
        }
        if let Some(leaf) = self.max_hypervisor_leaf {
            let _ = writeln!(out, "max hv leaf   : {leaf:#010x}");
        }
        if let Some(khz) = self.declared_tsc_khz {
            let _ = writeln!(
                out,
                "declared tsc  : {khz} kHz ({:.3} MHz)",
                khz as f64 / 1000.0
            );
        }

        let _ = writeln!(
            out,
            "sources       : {}",
            if self.sources.is_empty() {
                "none".to_string()
            } else {
                self.sources
                    .iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        );

        // The AArch64 registers, when there are any. `CNTFRQ_EL0` is the one
        // that carries a signature; the others are shown because they are
        // free to read and useful when reporting an odd machine.
        if self.arm_counter_hz != 0 {
            let _ = writeln!(
                out,
                "cntfrq_el0    : {} Hz ({:.3} MHz){}",
                self.arm_counter_hz,
                self.arm_counter_hz as f64 / 1e6,
                if self.sources.contains(&DetectionSource::ArmCounterFrequency) {
                    "  <- virtual timer frequency"
                } else {
                    ""
                }
            );
        }
        if self.arm_midr_el1 != 0 {
            let _ = writeln!(
                out,
                "midr_el1      : {:#018x}  implementer={:#04x} part={:#05x}",
                self.arm_midr_el1,
                (self.arm_midr_el1 >> 24) & 0xFF,
                (self.arm_midr_el1 >> 4) & 0xFFF
            );
        }
        if self.arm_ctr_el0 != 0 {
            let _ = writeln!(out, "ctr_el0       : {:#018x}", self.arm_ctr_el0);
        }
        if let Some(uid) = self.kernel.as_ref().and_then(|k| k.hvc_vendor_uid) {
            let _ = writeln!(
                out,
                "hvc vendor uid: {:08x} {:08x} {:08x} {:08x}",
                uid[0], uid[1], uid[2], uid[3]
            );
        }

        if let Some(cost) = &self.exit_cost {
            // The two architectures probe different things, so they are
            // labelled differently rather than sharing a misleading name.
            let (what, verdict) = if cfg!(target_arch = "aarch64") {
                ("isb", if cost.suggests_exit { "emulated" } else { "no" })
            } else {
                ("cpuid", if cost.suggests_exit { "likely" } else { "no" })
            };
            let _ = writeln!(
                out,
                "trap probe    : {what}={} cyc  baseline={} cyc  ratio={:.1}x  exit={verdict}",
                cost.trap_cycles, cost.baseline_cycles, cost.ratio,
            );
        }

        for (label, value) in [
            ("dmi sys_vendor", &self.dmi.sys_vendor),
            ("dmi product   ", &self.dmi.product_name),
            ("dmi bios      ", &self.dmi.bios_vendor),
        ] {
            if let Some(v) = value {
                let _ = writeln!(out, "{label}: {v}");
            }
        }

        match &self.kernel {
            Some(k) => {
                let _ = writeln!(out, "kernel module : loaded (v{})", k.version);
                let flag = |v: Option<bool>| match v {
                    Some(true) => "accepted",
                    Some(false) => "faulted",
                    None => "not probed",
                };
                let _ = writeln!(
                    out,
                    "  vmcall={} vmmcall={} hvc={}",
                    flag(k.vmcall_ok),
                    flag(k.vmmcall_ok),
                    flag(k.hvc_ok)
                );
                if let Some(result) = k.hypercall_result {
                    let _ = writeln!(out, "  hypercall returned {result}");
                }
                if let (Some(vmx), Some(svm)) = (k.vmx_available, k.svm_available) {
                    let _ = writeln!(out, "  vmx={vmx} svm={svm}");
                }
                if let Some(el) = k.current_el {
                    let _ = writeln!(out, "  current_el={el}");
                }
                if let Some(n) = k.hypercall_probes {
                    let age = k.hypercall_age_ms.map(|ms| ms / 1000).unwrap_or(0);
                    let limit = match k.hypercall_cooldown_s {
                        Some(0) => "cooldown OFF (the user assumes the provider's reaction)".to_string(),
                        Some(s) => format!("re-probe every {s} s at most"),
                        None => "cooldown unknown".to_string(),
                    };
                    let _ = writeln!(out, "  probes run={n} (last {age} s ago), {limit}");
                }
            }
            None => {
                let _ = writeln!(
                    out,
                    "kernel module : not loaded (optional; see kernel/linux/README.md)"
                );
            }
        }

        // Host time synchronisation, which only means anything in a guest.
        // The cache, not a fresh read: this is a display function and a
        // pairing costs a hypercall. See `kvmclock::HOST_QUERIES`.
        let sync = crate::kvmclock::cached();
        if let Some(clocksource) = &sync.paravirtual_clocksource {
            let _ = writeln!(
                out,
                "host clocksource: {clocksource} (monotonic follows the host)"
            );
        }
        if let Some(pairing) = &sync.pairing {
            let offset = pairing.host_offset_ns();
            let _ = writeln!(
                out,
                "host clock pair : offset={offset} ns  host={} ns  guest={} ns",
                pairing.host_ns, pairing.guest_realtime_ns
            );
        }
        // The count, not a claim. A pairing is a hypercall out of this guest

        // and into a host other tenants share, so it is taken once per process

        // and applied as arithmetic afterwards — see `kvmclock::HOST_QUERIES`.

        let _ = writeln!(
            out,
            "host queries  : {} (once per process; the offset is then arithmetic)",
            crate::kvmclock::host_queries()
        );
        if sync.paravirtual_clocksource.is_some() || sync.pairing.is_some() {
            let _ = writeln!(out, "                  {}", sync.advice());
        }

        let _ = write!(out, "\n{}", self.timing_impact.advice());
        out
    }
}

/// Splits the three CPUID registers into the 12 signature bytes.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn signature_bytes(ebx: u32, ecx: u32, edx: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&ebx.to_le_bytes());
    out[4..8].copy_from_slice(&ecx.to_le_bytes());
    out[8..12].copy_from_slice(&edx.to_le_bytes());
    out
}

/// Renders a signature as text, or `None` if it is empty or not printable.
///
/// A leaf that is not implemented reads back as zeros or as whatever the last
/// leaf returned, so the printability check is what stops garbage being
/// reported as a hypervisor.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn decode_signature(bytes: &[u8; 12]) -> Option<String> {
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let text: String = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    Some(text)
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn match_signature(bytes: &[u8; 12]) -> Option<Hypervisor> {
    CPUID_SIGNATURES
        .iter()
        .find_map(|(sig, hv)| (sig.len() == 12 && sig.as_bytes() == bytes).then(|| hv.clone()))
}

/// Matches `CNTFRQ_EL0` against the frequencies virtual timers use.
///
/// A physical SoC derives this from an oscillator, and the values in the
/// field cluster around 19.2, 24, 25 and 100 MHz. These are the ones the
/// common virtual implementations invented instead.
#[cfg(target_arch = "aarch64")]
fn counter_frequency_signature(hz: u64) -> Option<Hypervisor> {
    match hz {
        // QEMU's `virt` board, under both TCG and KVM.
        62_500_000 => Some(Hypervisor::Other("qemu/kvm (virt board)".to_string())),
        // QEMU's linux-user mode drives the virtual counter straight off a
        // nanosecond clock, so a round gigahertz identifies it as emulation
        // rather than merely something unusual.
        1_000_000_000 => Some(Hypervisor::QemuTcg),
        _ => None,
    }
}

/// Reads `MIDR_EL1` from where Linux publishes it.
///
/// The register is EL1-only by architecture. Linux emulates some EL0 reads of
/// the ID space, but not dependably across versions, and a guess that lands
/// wrong is a `SIGILL` rather than an error — so this reads the file the
/// kernel exports instead of taking the trap.
#[cfg(target_arch = "aarch64")]
fn read_midr_el1() -> Option<u64> {
    let raw = read_trimmed("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1")?;
    let digits = raw.trim().trim_start_matches("0x");
    u64::from_str_radix(digits, 16).ok()
}

/// Implementer codes that only an emulator reports.
///
/// `MIDR_EL1[31:24]` is the implementer. Emulators usually copy a real one —
/// QEMU reports ARM's `0x41` for the core it models — so this catches only
/// the ones that do not bother, and is weak evidence by design.
#[cfg(target_arch = "aarch64")]
fn midr_signature(midr: u64) -> Option<Hypervisor> {
    let implementer = (midr >> 24) & 0xFF;
    match implementer {
        // No implementer at all: nothing that shipped reports zero here.
        0x00 => Some(Hypervisor::Other("unidentified (null MIDR)".to_string())),
        _ => None,
    }
}

/// Times `CPUID` against a bare counter read pair.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn measure_trap_cost() -> Option<ExitCost> {
    use arch::x86::cpuid;

    const ROUNDS: u32 = 256;

    let baseline = (0..ROUNDS).map(|_| arch::read_overhead()).min()?;
    let trap = (0..ROUNDS)
        .map(|_| {
            let start = arch::counter_start();
            // Leaf 0 is the cheapest CPUID there is, so whatever this costs
            // above the baseline is the trap, not the work.
            core::hint::black_box(cpuid(0, 0));
            arch::counter_end().wrapping_sub(start)
        })
        .min()?;

    let ratio = if baseline > 0 {
        trap as f64 / baseline as f64
    } else {
        0.0
    };
    Some(ExitCost {
        trap_cycles: trap,
        baseline_cycles: baseline,
        ratio,
        suggests_exit: ratio >= EXIT_RATIO_THRESHOLD,
    })
}

/// Times a synchronised counter read against a bare one.
///
/// AArch64 has no unprivileged instruction that traps to the hypervisor the
/// way `CPUID` does, so there is no exit to time. What this times instead is
/// the difference between executing and *emulating*: `ISB` forces an
/// instruction re-fetch, which real silicon absorbs in a few dozen cycles but
/// which costs an emulator a translation-block exit and a trip back through
/// its dispatch loop. A high ratio therefore means emulation, not a
/// hypervisor exit; hardware-assisted virtualization runs `ISB` natively and
/// looks like bare metal, which for timing purposes it very nearly is.
///
/// **This probe is the weakest signal here and is not load-bearing.** The
/// virtual counter is often too coarse to resolve either side: under
/// `qemu-user` both measurements floor at zero and it reports nothing at all.
/// It never confirms on its own — [`DetectionSource::ExitCostTiming`] is
/// inferred evidence — so a silent probe costs nothing and a noisy one cannot
/// produce a false positive by itself. The identification that actually works
/// on AArch64 is `CNTFRQ_EL0`, the device tree, and the kernel module.
#[cfg(target_arch = "aarch64")]
fn measure_trap_cost() -> Option<ExitCost> {
    let (bare, synchronised) = crate::arch::aarch64::barrier_cost_pair();

    // A counter tick is coarse: at 24 MHz one tick is 41 ns, so a bare read
    // pair on real silicon rounds to zero. That is the healthy case, and a
    // ratio cannot be formed from it — which is the answer, not a failure.
    if bare == 0 {
        return Some(ExitCost {
            trap_cycles: synchronised,
            baseline_cycles: 0,
            ratio: 0.0,
            suggests_exit: false,
        });
    }

    let ratio = synchronised as f64 / bare as f64;
    Some(ExitCost {
        trap_cycles: synchronised,
        baseline_cycles: bare,
        ratio,
        suggests_exit: ratio >= EXIT_RATIO_THRESHOLD,
    })
}

/// No CPU-level probe on this architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
fn measure_trap_cost() -> Option<ExitCost> {
    None
}

/// Reads the hypervisor evidence Windows keeps in the registry.
///
/// This is the identification path that does not depend on CPUID, which
/// matters twice: it is the only one available on ARM64 Windows, and on x86 it
/// still works against a hypervisor configured to hide its CPUID leaf.
///
/// Nothing here is a heuristic on a version number — each key is one Windows
/// only creates in the situation it names.
#[cfg(target_os = "windows")]
fn read_registry_evidence() -> Option<(Hypervisor, &'static str)> {
    // The guest integration key. Windows creates it inside a Hyper-V guest
    // and nowhere else — the host does not have it, even with the Hyper-V
    // role installed, which is what separates this from looking for the
    // VMBus driver.
    if registry_key_exists(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") {
        return Some((Hypervisor::HyperV, "hyper-v guest parameters"));
    }

    // The same strings SMBIOS carries, which Windows also publishes here.
    // Reading both means a vendor that fills in one but not the other is
    // still caught.
    for value in ["SystemManufacturer", "SystemProductName", "BIOSVendor"] {
        let Some(text) = registry_string(r"HARDWARE\DESCRIPTION\System\BIOS", value) else {
            continue;
        };
        let hints = DmiHints {
            product_name: Some(text),
            ..Default::default()
        };
        if let Some(hv) = hints.identify() {
            return Some((hv, "bios description key"));
        }
    }
    None
}

/// Whether a key exists under `HKEY_LOCAL_MACHINE`.
#[cfg(target_os = "windows")]
fn registry_key_exists(sub_key: &str) -> bool {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let wide = to_wide(sub_key);
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
    // call, and `handle` is a writable out-parameter.
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_ptr(), 0, KEY_READ, &mut handle) };
    if status != ERROR_SUCCESS {
        return false;
    }
    // SAFETY: the handle came from a successful RegOpenKeyExW.
    unsafe { RegCloseKey(handle) };
    true
}

/// Reads one string value from under `HKEY_LOCAL_MACHINE`.
#[cfg(target_os = "windows")]
fn registry_string(sub_key: &str, value: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let key = to_wide(sub_key);
    let name = to_wide(value);
    // Firmware strings are short; a fixed buffer avoids a second call and
    // the truncation it would have to handle.
    let mut buffer = [0u16; 256];
    let mut size = std::mem::size_of_val(&buffer) as u32;

    // SAFETY: both strings are NUL-terminated and outlive the call; `buffer`
    // and `size` are a matched out-parameter pair, with `size` in bytes as
    // the API requires.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }

    // `size` counts bytes including the terminator; trim to the actual text.
    let chars = (size as usize / 2).min(buffer.len());
    let text: String = String::from_utf16_lossy(&buffer[..chars])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

/// NUL-terminated UTF-16, as every `W` entry point expects.
#[cfg(target_os = "windows")]
fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads the raw SMBIOS table Windows exposes.
#[cfg(target_os = "windows")]
fn read_smbios_table() -> Option<Vec<u8>> {
    use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;

    // 'RSMB', the raw SMBIOS provider, as a little-endian FOURCC.
    const RSMB: u32 = u32::from_le_bytes(*b"RSMB");

    // SAFETY: a null buffer with zero length is the documented way to ask for
    // the required size.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) };
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` is `size` writable bytes, which is what the call above
    // asked for.
    let written = unsafe { GetSystemFirmwareTable(RSMB, 0, buffer.as_mut_ptr().cast(), size) };
    if written == 0 || written > size {
        return None;
    }
    buffer.truncate(written as usize);
    Some(buffer)
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Parses the kernel module's `key=value` output.
///
/// Unknown keys are ignored so an older library keeps working against a newer
/// module, and a malformed value leaves its field `None` rather than failing
/// the whole parse — the module is a complement, and a broken one must not
/// take the userspace detection down with it.
/// Where the ring-0 module publishes and takes commands.
pub const KERNEL_MODULE_PATH: &str = "/proc/nanochrono";

/// Asks the ring-0 module to run its hypervisor probes again.
///
/// The module probes once at load and serves a cache; this is the only way
/// to repeat the probe, and the module itself refuses it (`WouldBlock`)
/// until its cooldown — 10 s by default — has passed. Needs root.
pub fn kernel_module_reprobe() -> std::io::Result<()> {
    std::fs::write(KERNEL_MODULE_PATH, "reprobe")
}

/// Sets the module's re-probe cooldown; `0` disables it. Needs root.
///
/// Disabling it is the user's decision and the user's risk: see
/// [`crate::reprobe::COOLDOWN_OFF_WARNING`].
pub fn kernel_module_set_cooldown(seconds: u32) -> std::io::Result<()> {
    std::fs::write(KERNEL_MODULE_PATH, format!("cooldown={seconds}"))
}

/// The module's report as it stands, without asking it to probe again.
pub fn kernel_module_probe() -> Option<KernelProbe> {
    read_kernel_module(KERNEL_MODULE_PATH)
}

fn read_kernel_module(path: impl AsRef<Path>) -> Option<KernelProbe> {
    let text = std::fs::read_to_string(path).ok()?;
    // The old standalone perf module (`source=perf`) published at the same
    // path with no hypervisor section. Its report is not an (empty)
    // hypervisor probe, so skip it and let the caller try the next path. The
    // current single module carries both sections (`perf_*` keys).
    if text.lines().any(|l| l.trim() == "source=perf") {
        return None;
    }
    let probe = parse_kernel_report(&text);
    // A file with no hypervisor keys at all is not this module either.
    if probe.version == 0
        && probe.vmcall_ok.is_none()
        && probe.vmmcall_ok.is_none()
        && probe.hvc_ok.is_none()
        && probe.exit_cycles.is_none()
    {
        return None;
    }
    Some(probe)
}

/// Parses the module's `key=value` report.
///
/// Split from the file read so it can be tested directly: the parser is where
/// the interesting behaviour lives, and driving it through a temporary file
/// only adds a filesystem race between tests.
fn parse_kernel_report(text: &str) -> KernelProbe {
    let mut probe = KernelProbe::default();

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let flag = || match value {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        };
        match key {
            "version" => probe.version = value.parse().unwrap_or(0),
            "vmcall_ok" => probe.vmcall_ok = flag(),
            "vmmcall_ok" => probe.vmmcall_ok = flag(),
            "hvc_ok" => probe.hvc_ok = flag(),
            "hypercall_result" => probe.hypercall_result = value.parse().ok(),
            "vmx_available" => probe.vmx_available = flag(),
            "svm_available" => probe.svm_available = flag(),
            "current_el" => probe.current_el = value.parse().ok(),
            "exit_cycles" => probe.exit_cycles = value.parse().ok(),
            "cpu_family" => probe.cpu_family = Some(value.to_string()),
            "hypercall_probes" => probe.hypercall_probes = value.parse().ok(),
            "hypercall_age_ms" => probe.hypercall_age_ms = value.parse().ok(),
            "hypercall_cooldown_s" => probe.hypercall_cooldown_s = value.parse().ok(),
            "hypercall_next_ms" => probe.hypercall_next_ms = value.parse().ok(),
            "centaur_max_leaf" => {
                probe.centaur_max_leaf = value
                    .strip_prefix("0x")
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            }
            "hvc_vendor_uid" => {
                let words: Vec<u32> = value
                    .split_whitespace()
                    .filter_map(|w| u32::from_str_radix(w, 16).ok())
                    .collect();
                // Four words or nothing: a partial UID is a malformed line,
                // and padding it out would invent data.
                if let Ok(uid) = <[u32; 4]>::try_from(words.as_slice()) {
                    probe.hvc_vendor_uid = Some(uid);
                }
            }
            _ => {}
        }
    }
    probe
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apple's own hypervisor names itself in `hw.model`, and that string is
    /// what macOS detection has to match on — `kern.hv_vmm_present` says a
    /// VMM exists but never which.
    #[test]
    fn a_virtual_mac_is_identified_from_its_model_string() {
        let hints = DmiHints {
            sys_vendor: Some("VirtualMac2,1".to_string()),
            ..Default::default()
        };
        assert_eq!(hints.identify(), Some(Hypervisor::AppleVz));

        // A real Mac must not be mistaken for one.
        for real in ["Mac16,10", "MacBookPro18,3", "iMacPro1,1"] {
            let hints = DmiHints {
                sys_vendor: Some(real.to_string()),
                ..Default::default()
            };
            assert_eq!(hints.identify(), None, "{real} was called a VM");
        }
    }

    /// Each platform's native query is a declaration, not an inference: the
    /// OS is reporting what it knows, so it confirms on its own.
    #[test]
    fn native_platform_queries_confirm() {
        for source in [
            DetectionSource::MacSysctl,
            DetectionSource::WindowsRegistry,
            DetectionSource::CpuidVendorLeaf,
            DetectionSource::DeviceTree,
        ] {
            assert!(source.is_declared(), "{} must confirm", source.name());
            let mut report = HypervisorReport {
                sources: vec![source],
                ..Default::default()
            };
            report.conclude();
            assert_eq!(report.confidence, Confidence::Confirmed);
        }
    }

    /// The AArch64 signals are inferences, so they must raise suspicion and
    /// never confirm. A machine with an unusual oscillator is not a VM.
    #[test]
    fn inferred_sources_never_confirm_on_their_own() {
        for source in [
            DetectionSource::ArmCounterFrequency,
            DetectionSource::ArmMidr,
            DetectionSource::ExitCostTiming,
        ] {
            assert!(!source.is_declared(), "{} must not confirm", source.name());
            let mut report = HypervisorReport {
                sources: vec![source],
                ..Default::default()
            };
            report.conclude();
            assert_eq!(
                report.confidence,
                Confidence::Suspected,
                "{} produced the wrong confidence",
                source.name()
            );
        }
    }

    /// A declared source still confirms, even alongside an inferred one.
    #[test]
    fn a_declaration_outranks_an_inference() {
        let mut report = HypervisorReport {
            sources: vec![
                DetectionSource::ArmCounterFrequency,
                DetectionSource::DeviceTree,
            ],
            ..Default::default()
        };
        report.conclude();
        assert_eq!(report.confidence, Confidence::Confirmed);
    }

    /// The frequencies virtual timers pick, and the ones real silicon uses.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn counter_frequencies_separate_virtual_from_physical() {
        // QEMU's virt board cannot say which of TCG or KVM is underneath, so
        // it must not claim either.
        let qemu = counter_frequency_signature(62_500_000).expect("virt board recognised");
        assert!(!qemu.is_emulated(), "the virt board may well be KVM");

        // linux-user mode runs the counter off a nanosecond clock, which is
        // emulation and is reported as such.
        assert_eq!(
            counter_frequency_signature(1_000_000_000),
            Some(Hypervisor::QemuTcg)
        );

        // The rates real parts actually run at must stay silent.
        for hz in [19_200_000, 24_000_000, 25_000_000, 26_000_000, 100_000_000] {
            assert_eq!(
                counter_frequency_signature(hz),
                None,
                "{hz} Hz is a physical oscillator and was flagged"
            );
        }
    }

    /// The module reports the UID as four hex words; a partial line is
    /// malformed and must not be padded out into invented data.
    #[test]
    fn vendor_uid_parses_only_when_complete() {
        let complete = parse_kernel_report(
            "version=1
hvc_ok=1
hvc_vendor_uid=b66fb428 e911c52e 564bcaa9 743a004d
",
        );
        assert_eq!(
            complete.hvc_vendor_uid,
            Some([0xb66f_b428, 0xe911_c52e, 0x564b_caa9, 0x743a_004d])
        );

        for malformed in [
            "hvc_vendor_uid=b66fb428 e911c52e",
            "hvc_vendor_uid=",
            "hvc_vendor_uid=b66fb428 e911c52e 564bcaa9 743a004d deadbeef",
            "hvc_vendor_uid=not hex at all here",
        ] {
            assert_eq!(
                parse_kernel_report(malformed).hvc_vendor_uid,
                None,
                "{malformed:?} was accepted"
            );
        }
    }

    #[test]
    fn detection_is_self_consistent() {
        let report = HypervisorReport::detect();

        // The verdict and the evidence must agree in both directions.
        assert_eq!(
            report.is_virtualized(),
            report.confidence != Confidence::None
        );
        if report.confidence == Confidence::None {
            assert!(report.sources.is_empty(), "{:?}", report.sources);
            assert_eq!(report.hypervisor, Hypervisor::None);
            assert_eq!(report.timing_impact, TimingImpact::Native);
        } else {
            assert!(!report.sources.is_empty());
        }
    }

    #[test]
    fn emulation_is_never_reported_as_native() {
        let mut report = HypervisorReport {
            hypervisor: Hypervisor::QemuTcg,
            sources: vec![DetectionSource::CpuidVendorLeaf],
            ..Default::default()
        };
        report.conclude();
        assert_eq!(report.timing_impact, TimingImpact::Emulated);
        assert_eq!(report.confidence, Confidence::Confirmed);
    }

    /// A trap cost alone is evidence, not proof: it must raise suspicion
    /// without claiming to name a hypervisor.
    #[test]
    fn timing_alone_only_suspects() {
        let mut report = HypervisorReport {
            sources: vec![DetectionSource::ExitCostTiming],
            ..Default::default()
        };
        report.conclude();
        assert_eq!(report.confidence, Confidence::Suspected);
        assert_eq!(report.hypervisor, Hypervisor::None);
        assert_eq!(report.timing_impact, TimingImpact::HardwareAssisted);
    }

    /// The module's whole point: a hypercall that returns proves a hypervisor
    /// even when nothing declared itself.
    #[test]
    fn a_hypercall_confirms_without_any_declaration() {
        let mut report = HypervisorReport {
            kernel: Some(KernelProbe {
                version: 1,
                vmcall_ok: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        report.conclude();
        assert_eq!(report.confidence, Confidence::Confirmed);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn every_signature_is_exactly_twelve_bytes() {
        for (sig, hv) in CPUID_SIGNATURES {
            assert_eq!(
                sig.len(),
                12,
                "{} signature is {} bytes; CPUID returns exactly 12",
                hv.name(),
                sig.len()
            );
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn known_signatures_resolve() {
        let kvm = signature_bytes(
            u32::from_le_bytes(*b"KVMK"),
            u32::from_le_bytes(*b"VMKV"),
            u32::from_le_bytes(*b"M\0\0\0"),
        );
        assert_eq!(match_signature(&kvm), Some(Hypervisor::Kvm));
        assert_eq!(decode_signature(&kvm).as_deref(), Some("KVMKVMKVM"));

        let tcg = signature_bytes(
            u32::from_le_bytes(*b"TCGT"),
            u32::from_le_bytes(*b"CGTC"),
            u32::from_le_bytes(*b"GTCG"),
        );
        assert_eq!(match_signature(&tcg), Some(Hypervisor::QemuTcg));
        assert!(Hypervisor::QemuTcg.is_emulated());
    }

    /// An unimplemented leaf reads back as zeros or as stale register
    /// contents; neither may be reported as a hypervisor.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn empty_and_binary_signatures_are_rejected() {
        assert_eq!(decode_signature(&[0u8; 12]), None);
        assert_eq!(decode_signature(&[0xFFu8; 12]), None);
        let mut mixed = [0u8; 12];
        mixed[0] = 0x01;
        assert_eq!(decode_signature(&mixed), None);
    }

    #[test]
    fn kernel_probe_parses_and_tolerates_junk() {
        let dir = std::env::temp_dir().join(format!("nc-hv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe");
        std::fs::write(
            &path,
            "version=1\nvmcall_ok=1\nvmmcall_ok=0\nhypercall_result=-1000\n\
             exit_cycles=1832\nunknown_key=whatever\nmalformed line\nvmx_available=1\n",
        )
        .unwrap();

        let probe = read_kernel_module(&path).expect("file exists");
        assert_eq!(probe.version, 1);
        assert_eq!(probe.vmcall_ok, Some(true));
        assert_eq!(probe.vmmcall_ok, Some(false));
        assert_eq!(probe.hvc_ok, None);
        assert_eq!(probe.hypercall_result, Some(-1000));
        assert_eq!(probe.exit_cycles, Some(1832));
        assert_eq!(probe.vmx_available, Some(true));
        assert!(probe.hypercall_accepted());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_module_is_not_an_error() {
        assert!(read_kernel_module("/nonexistent/nanochrono_hv").is_none());
        let report = HypervisorReport::detect();
        // Whether or not the module is loaded, detection produced a verdict.
        assert!(!report.detailed().is_empty());
    }

    #[test]
    fn merged_module_report_is_a_hypervisor_probe() {
        let dir = std::env::temp_dir().join(format!("nc-hv-merged-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe");
        std::fs::write(
            &path,
            "version=4\narch=x86\nvmcall_ok=1\nexit_cycles=900\n\
             hypercall_probes=1\nhypercall_age_ms=2500\nhypercall_cooldown_s=10\n\
             hypercall_next_ms=7500\nperf_event=cycles\nperf_npmu=8\n",
        )
        .unwrap();
        let probe = read_kernel_module(&path).expect("merged report");
        assert_eq!(probe.vmcall_ok, Some(true));
        assert_eq!(probe.hypercall_probes, Some(1));
        assert_eq!(probe.hypercall_cooldown_s, Some(10));
        assert_eq!(probe.hypercall_next_ms, Some(7500));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn perf_module_report_is_not_a_hypervisor_probe() {
        let dir = std::env::temp_dir().join(format!("nc-hv-perf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe");
        std::fs::write(
            &path,
            "source=perf\nevent=cycles\nenabled=1\nnpmu=8\nraw=1\n\
             enabled_ns=2\nrunning_ns=2\nscaled=1\n",
        )
        .unwrap();
        assert!(read_kernel_module(&path).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dmi_matching_prefers_the_specific_product() {
        let hints = DmiHints {
            sys_vendor: Some("QEMU".into()),
            product_name: Some("VMware Virtual Platform".into()),
            bios_vendor: None,
        };
        assert_eq!(hints.identify(), Some(Hypervisor::VMware));

        let bare = DmiHints {
            sys_vendor: Some("LENOVO".into()),
            product_name: Some("83DF".into()),
            bios_vendor: Some("LENOVO".into()),
        };
        assert_eq!(bare.identify(), None);
    }

    // x86 only, as the name says: the AArch64 probe documents that a coarse
    // counter floors both sides at zero, which is a valid answer there.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[test]
    fn trap_probe_returns_a_usable_ratio_on_x86() {
        let Some(cost) = measure_trap_cost() else {
            return; // not an x86 target
        };
        assert!(cost.trap_cycles > 0, "CPUID measured as free");
        assert!(cost.baseline_cycles > 0, "counter read measured as free");
        assert!(cost.ratio > 0.0);
    }

    #[test]
    fn every_impact_carries_advice() {
        for impact in [
            TimingImpact::Native,
            TimingImpact::HardwareAssisted,
            TimingImpact::Emulated,
        ] {
            assert!(!impact.advice().is_empty());
            assert!(!impact.name().is_empty());
        }
    }
}

#[cfg(test)]
mod zhaoxin_tests {
    use super::*;

    /// The module's Zhaoxin lines are read back.
    ///
    /// Ring 0 is where this reading is worth having: a hypervisor can filter
    /// what `CPUID.0H` shows a guest, and the module reads it on the other
    /// side of that.
    #[test]
    fn a_zhaoxin_module_report_parses() {
        let probe = parse_kernel_report(
            "version=3\n\
             arch=x86\n\
             cpu_vendor=  Shanghai  \n\
             cpu_family=zhaoxin\n\
             centaur_max_leaf=0xc0000004\n\
             cpuid_hypervisor_bit=0\n\
             vmx_available=1\n\
             svm_available=0\n\
             vmcall_ok=0\n\
             vmmcall_ok=0\n",
        );
        assert_eq!(probe.cpu_family.as_deref(), Some("zhaoxin"));
        assert_eq!(probe.centaur_max_leaf, Some(0xC000_0004));
        // Zhaoxin virtualization is VMX-shaped, so VMX is the extension that
        // should be reported present — and `VMCALL` is what a guest on one
        // would answer, which is the path the probe already takes.
        assert_eq!(probe.vmx_available, Some(true));
        assert_eq!(probe.svm_available, Some(false));
    }

    /// An Intel report carries no Centaur range, and that is not a parse
    /// failure — the key is simply absent.
    #[test]
    fn an_intel_report_has_no_centaur_range() {
        let probe = parse_kernel_report("version=3\narch=x86\ncpu_family=intel\nvmcall_ok=1\n");
        assert_eq!(probe.cpu_family.as_deref(), Some("intel"));
        assert_eq!(probe.centaur_max_leaf, None);
    }

    /// A malformed leaf value is dropped rather than parsed as zero, which
    /// would read as "the range exists and is empty".
    #[test]
    fn a_malformed_centaur_leaf_is_not_taken_as_zero() {
        let probe = parse_kernel_report("centaur_max_leaf=not-a-number\n");
        assert_eq!(probe.centaur_max_leaf, None);
        let probe = parse_kernel_report("centaur_max_leaf=c0000004\n");
        assert_eq!(
            probe.centaur_max_leaf, None,
            "the module writes this with an 0x prefix; anything else is not its output"
        );
    }
}
