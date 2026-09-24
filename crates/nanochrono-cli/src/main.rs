// SPDX-License-Identifier: Apache-2.0
//! NanoChronometer command-line front end.
//!
//! Every subcommand from the C CLI is here, plus three the C build could not
//! offer: `dispatch` (what the runtime ISA dispatcher selected and why), `tls`
//! (a rustls handshake, timed by phase) and `bench` (the benchmark harness,
//! which used to be GUI-only).

use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use nanochrono_bench::{BenchConfig, BenchKernel, BenchMode};
use nanochrono_core::{
    clock::{self, ClockRoute, StableClockConfig, WrapperKind},
    dispatch::Dispatcher,
    format::{self, DetailMode, TimeZoneMode},
    ntp, platform,
    probe::{self, AuditConfig, CacheProbe},
    simd::{ProbeBuffers, ProbeKind},
    Backend, Chronometer, HypervisorReport, NanoclockSnapshot, SimdFamily, Stopwatch,
};

#[derive(Parser)]
#[command(
    name = "nanochrono",
    version,
    about = "Nanosecond-resolution chronometer, precision clock and ISA measurement toolkit",
    long_about = None,
)]
struct Cli {
    /// Force a timer backend instead of the dispatcher's choice.
    #[arg(long, global = true, value_name = "NAME")]
    backend: Option<String>,

    /// Pin the measuring thread to a CPU before doing anything.
    #[arg(long, global = true, value_name = "INDEX")]
    pin_cpu: Option<u32>,

    /// AArch64: time with the physical counter (CNTPCT_EL0) instead of the
    /// virtual one (CNTVCT_EL0). Meant for real hardware: inside a VM the
    /// hypervisor may trap every read, and under nested virtualization it is
    /// slow and unstable. Allowed anyway, with a warning.
    #[arg(long, global = true)]
    physical_counter: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Live stopwatch until Ctrl+C (the default with no subcommand).
    Stopwatch,
    /// Print one diagnostic timing sample and exit.
    Once,
    /// Show what the runtime ISA dispatcher selected, and why.
    Dispatch,
    /// Report the state-integrity counters, and optionally drill the repair
    /// paths with injected bit flips.
    Integrity {
        /// Inject faults into a scratch calibration and show each tier
        /// repairing them. Touches nothing the process actually uses.
        #[arg(long)]
        drill: bool,
    },
    /// Detect a hypervisor or emulator, and say what it means for the numbers.
    Hypervisor {
        /// Skip the trap-cost probe, which costs a few microseconds.
        #[arg(long)]
        no_timing: bool,
        /// Ask the kernel module (`/proc/nanochrono`) to run its hypervisor
        /// probes again. It probes once at load; repeats are refused until
        /// its cooldown (10 s by default) passes. Needs root.
        #[arg(long)]
        reprobe: bool,
        /// Set the kernel module's re-probe cooldown in seconds. 0 disables
        /// it — and the user then assumes the cloud provider's reaction
        /// (throttling, a ban) to repeated VM exits. Needs root.
        #[arg(long, value_name = "SECONDS")]
        cooldown: Option<u32>,
    },
    /// Report how the guest's nanoseconds relate to the host's.
    HostSync,
    /// List every timer backend and SIMD family with its availability.
    Catalog,
    /// Live precision clock.
    Clock(ClockArgs),
    /// One precision-clock sample.
    ClockOnce(ClockArgs),
    /// Live nanosecond clock with every raw counter route.
    NsClock,
    /// One nanosecond-clock snapshot.
    NsClockOnce,
    /// Calibrate the selected counter route against wall time.
    CalibrateClock(CalibrateArgs),
    /// Calibrate cycles-per-nanosecond for raw counter conversion.
    StableCalibrate(CalibrateArgs),
    /// Convert raw cycles to nanoseconds with a known factor.
    CyclesToNs {
        /// Raw counter units to convert.
        cycles: u64,
        /// Calibrated units per nanosecond.
        #[arg(long)]
        cycles_per_ns: f64,
    },
    /// Query an NTP server and report offset, delay and overhead.
    Ntp {
        /// Server hostname.
        #[arg(default_value = ntp::DEFAULT_SERVER)]
        server: String,
        #[arg(long, default_value_t = ntp::DEFAULT_TIMEOUT_MS)]
        timeout_ms: u32,
    },
    /// Time a TLS 1.3 handshake, phase by phase.
    Tls {
        /// Host to connect to.
        #[arg(default_value = "www.rust-lang.org")]
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Also list the provider's cipher suites and key exchange groups.
        #[arg(long)]
        suites: bool,
    },
    /// Run a benchmark.
    Bench(BenchArgs),
    /// Measure native and language-wrapper call overhead baselines.
    WrapperOverhead,
    /// Run local cache and branch timing probes.
    AsmProbe,
    /// Run per-family SIMD probes, gated by CPUID.
    AsmSimd,
    /// Run a constant-time timing audit on a demo candidate.
    SctAudit {
        #[arg(long, default_value_t = 2000)]
        samples: u32,
    },
    /// Compare per-thread perf counters (ring 3) with the kernel module
    /// counters (ring 0, `/proc/nanochrono`). Needs the kernel module for
    /// the ring-0 half: `cd kernel/linux && make load`.
    Perf(PerfArgs),
}

#[derive(Args, Clone)]
struct ClockArgs {
    /// Show mm:ss.mmm instead of full nanosecond detail.
    #[arg(long, conflicts_with = "nano")]
    simple: bool,
    /// Show hh:mm:ss:mmm:uuu:nnn.
    #[arg(long)]
    nano: bool,
    /// Render in UTC.
    #[arg(long, conflicts_with = "utc_offset")]
    utc: bool,
    /// Render at a fixed offset from UTC, in minutes.
    #[arg(long, value_name = "MINUTES", allow_negative_numbers = true)]
    utc_offset: Option<i32>,
    /// Also discipline against this NTP server.
    #[arg(long, value_name = "SERVER")]
    ntp: Option<String>,
}

impl ClockArgs {
    fn detail(&self) -> DetailMode {
        if self.simple {
            DetailMode::Simple
        } else {
            DetailMode::Nano
        }
    }

    fn zone(&self) -> TimeZoneMode {
        match (self.utc, self.utc_offset) {
            (true, _) => TimeZoneMode::Utc,
            (_, Some(m)) => TimeZoneMode::CustomOffset(m),
            _ => TimeZoneMode::Local,
        }
    }
}

#[derive(Args, Clone)]
struct CalibrateArgs {
    /// Length of the calibration window.
    #[arg(long, default_value_t = 500)]
    ms: u32,
    /// Samples for the busy-loop route calibration.
    #[arg(long, default_value_t = 200_000)]
    samples: u32,
}

#[derive(Args, Clone)]
struct PerfArgs {
    /// Select what the ring-0 module counts before reading: `cycles` or `instr`.
    /// Needs write access to /proc/nanochrono (usually root).
    #[arg(long, value_name = "EVENT")]
    event: Option<String>,
    /// Enable counting in the ring-0 module.
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    /// Disable counting in the ring-0 module.
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
}

#[derive(Args, Clone)]
struct BenchArgs {
    /// Which family of work to measure.
    #[arg(long, value_enum, default_value_t = BenchModeArg::Isa)]
    mode: BenchModeArg,
    /// Kernel to run: a backend name, an algorithm name, `scalar`, or `all`.
    #[arg(long, default_value = "all")]
    kernel: String,
    /// Host for the TLS mode.
    #[arg(long, default_value = "www.rust-lang.org")]
    host: String,
    #[arg(long, default_value_t = 443)]
    port: u16,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum BenchModeArg {
    Isa,
    Crypto,
    Tls,
    /// The kernel's own crypto, through `AF_ALG`. Linux only, and not
    /// offered as an argument at all elsewhere: `AF_ALG` is a Linux socket
    /// family with no equivalent to point this at on Windows or macOS.
    #[cfg(target_os = "linux")]
    Kernel,
    /// The same, measured inside the kernel by the optional module. Linux
    /// only, for the same reason and more so — it is a Linux kernel module.
    #[cfg(target_os = "linux")]
    Ring0,
    /// The bare crypto instructions in the project's own kernels (AES
    /// round, SHA-256 round, carry-less multiply, VAES, VPCLMULQDQ). Speed
    /// only: no key schedule, no mode, no authentication. `crypto` is the
    /// mode for real, secure crypto.
    CryptoRaw,
}

impl From<BenchModeArg> for BenchMode {
    fn from(a: BenchModeArg) -> BenchMode {
        match a {
            BenchModeArg::Isa => BenchMode::CpuIsa,
            BenchModeArg::Crypto => BenchMode::Crypto,
            BenchModeArg::Tls => BenchMode::TlsHandshake,
            #[cfg(target_os = "linux")]
            BenchModeArg::Kernel => BenchMode::KernelCrypto,
            #[cfg(target_os = "linux")]
            BenchModeArg::Ring0 => BenchMode::KernelCryptoRing0,
            BenchModeArg::CryptoRaw => BenchMode::CryptoRaw,
        }
    }
}

fn main() -> ExitCode {
    // Before any output: a closed pipe should end the process, not panic.
    platform::restore_default_sigpipe();

    let cli = Cli::parse();

    if let Some(cpu) = cli.pin_cpu {
        if !platform::pin_thread_to_cpu(cpu) {
            eprintln!("warning: could not pin to CPU {cpu}; results will be noisier");
        }
    }

    // Before the chronometer exists, so its calibration and every read use
    // the counter asked for.
    if cli.physical_counter {
        if let Err(code) = enable_physical_counter() {
            return code;
        }
    }

    let chrono = match &cli.backend {
        Some(name) => match Backend::parse(name) {
            Some(b) if b.is_available() => Chronometer::with_backend(b),
            Some(b) => {
                eprintln!(
                    "warning: backend '{}' is not supported on this CPU; using the detected best",
                    b.name()
                );
                Chronometer::new()
            }
            None => {
                eprintln!("error: unknown backend '{name}'");
                eprintln!(
                    "        known backends: {}",
                    Backend::ALL
                        .iter()
                        .map(|b| b.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                return ExitCode::from(2);
            }
        },
        None => Chronometer::new(),
    };

    let result = match cli.command.unwrap_or(Command::Stopwatch) {
        Command::Stopwatch => run_stopwatch(chrono),
        Command::Once => run_once(chrono),
        Command::Dispatch => run_dispatch(),
        Command::Hypervisor {
            no_timing,
            reprobe,
            cooldown,
        } => run_hypervisor(no_timing, reprobe, cooldown),
        Command::HostSync => run_host_sync(),
        Command::Integrity { drill } => run_integrity(drill),
        Command::Catalog => run_catalog(),
        Command::Clock(args) => run_clock(chrono, args, true),
        Command::ClockOnce(args) => run_clock(chrono, args, false),
        Command::NsClock => run_ns_clock(chrono, true),
        Command::NsClockOnce => run_ns_clock(chrono, false),
        Command::CalibrateClock(args) => run_calibrate_route(chrono, args),
        Command::StableCalibrate(args) => run_stable_calibrate(chrono, args, cli.pin_cpu),
        Command::CyclesToNs {
            cycles,
            cycles_per_ns,
        } => run_cycles_to_ns(cycles, cycles_per_ns),
        Command::Ntp { server, timeout_ms } => run_ntp(&chrono, &server, timeout_ms),
        Command::Tls { host, port, suites } => run_tls(&host, port, suites),
        Command::Bench(args) => run_bench(&chrono, args),
        Command::WrapperOverhead => run_wrapper_overhead(&chrono),
        Command::AsmProbe => run_asm_probe(),
        Command::AsmSimd => run_asm_simd(&chrono),
        Command::SctAudit { samples } => run_sct_audit(&chrono, samples),
        Command::Perf(args) => run_perf(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Ctrl+C flag shared with the live views.
fn interrupt_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&flag);
    // A failed handler registration is not fatal: the loop still runs, the
    // user just has to interrupt it the blunt way.
    let _ = ctrlc::set_handler(move || handler_flag.store(true, Ordering::SeqCst));
    flag
}

fn run_stopwatch(chrono: Chronometer) -> Result<(), String> {
    let stop = interrupt_flag();
    let mut stopwatch = Stopwatch::new();

    println!("NanoChronometer stopwatch");
    println!(
        "backend={}  counter={:.3} MHz  route={}",
        chrono.backend().name(),
        chrono.counter_hz() as f64 / 1e6,
        ClockRoute::best().name()
    );
    let platform = nanochrono_core::hypervisor::cached();
    if platform.is_virtualized() {
        println!(
            "platform={}  {}",
            platform.summary(),
            platform.timing_impact.advice()
        );
    }
    println!("Press Ctrl+C to stop.\n");

    stopwatch.start();
    let mut chrono = chrono;
    while !stop.load(Ordering::SeqCst) {
        print!("\relapsed={}", stopwatch.format(&chrono, DetailMode::Nano));
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(25));

        // A stopwatch left running for days is precisely the workload an upset
        // has time to hit, so the calibration is scrubbed as it runs.
        let integrity = chrono.verify_calibration();
        if integrity.was_repaired() {
            println!("\nnote: calibration repaired ({})", integrity.name());
        } else if !integrity.is_usable() {
            return Err("calibration is unrecoverable; recalibrate before trusting output".into());
        }
    }
    println!("\relapsed={}", stopwatch.format(&chrono, DetailMode::Nano));
    Ok(())
}

fn run_once(mut chrono: Chronometer) -> Result<(), String> {
    chrono.start();
    chrono.spin_us(1_000);
    let elapsed = chrono.elapsed_ns();

    let platform = nanochrono_core::hypervisor::cached();
    println!("backend={}", chrono.backend().name());
    println!("platform={}", platform.summary());
    println!("counter_hz={}", chrono.counter_hz());
    println!("elapsed={}", format::format_elapsed_nano(elapsed));
    println!("counter_read_overhead={} units", chrono.overhead_units());
    println!("ffi_overhead={} units", chrono.measure_ffi_overhead(1_000));
    println!("drift={:+.3} ppm", chrono.drift_ppm());
    println!(
        "calibration_integrity={}",
        chrono.verify_calibration().name()
    );
    if platform.is_virtualized() {
        println!("\nnote: {}", platform.timing_impact.advice());
    }
    Ok(())
}

fn run_dispatch() -> Result<(), String> {
    let d = Dispatcher::global();
    println!("{}", d.report());
    println!();
    println!("{:<16} {:>10} {:>10}", "BACKEND", "AVAILABLE", "SELECTED");
    for (backend, available, selected) in d.backend_matrix() {
        println!(
            "{:<16} {:>10} {:>10}",
            backend.name(),
            yes_no(available),
            yes_no(selected)
        );
    }
    Ok(())
}

fn run_host_sync() -> Result<(), String> {
    let sync = nanochrono_core::kvmclock::cached();

    println!(
        "paravirtual clocksource : {}",
        sync.paravirtual_clocksource.as_deref().unwrap_or("none")
    );
    println!(
        "monotonic follows host  : {}",
        yes_no(sync.monotonic_follows_host())
    );

    match &sync.pairing {
        Some(p) => {
            println!("host clock pairing      : available (ptp_kvm)");
            println!("  host clock            : {} ns", p.host_ns);
            println!("  guest realtime        : {} ns", p.guest_realtime_ns);
            println!("  guest monotonic raw   : {} ns", p.guest_monotonic_raw_ns);
            println!("  host is ahead by      : {} ns", p.host_offset_ns());
        }
        None => {
            println!("host clock pairing      : unavailable");
            // Three separate reasons, two of which an operator can fix.
            println!("  needs a KVM guest, ptp_kvm loaded, and read access to /dev/ptpN");
            println!("  (the device is usually root:clock, so this often needs a group)");
        }
    }
    println!();
    println!("{}", sync.advice());
    Ok(())
}

fn run_hypervisor(no_timing: bool, reprobe: bool, cooldown: Option<u32>) -> Result<(), String> {
    use nanochrono_core::hypervisor as hv;
    use nanochrono_core::reprobe::{COOLDOWN_NOTE, COOLDOWN_OFF_WARNING};

    if let Some(seconds) = cooldown {
        if seconds == 0 {
            eprintln!("WARNING: {COOLDOWN_OFF_WARNING}");
        }
        hv::kernel_module_set_cooldown(seconds)
            .map_err(|e| format!("cannot set the module's cooldown ({}): {e}", hv::KERNEL_MODULE_PATH))?;
        println!("module re-probe cooldown = {seconds} s");
    }
    if reprobe {
        match hv::kernel_module_reprobe() {
            Ok(()) => println!("module re-probed the hypervisor"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let wait = hv::kernel_module_probe()
                    .and_then(|p| p.hypercall_next_ms)
                    .map(|ms| format!(" — {} s left", ms.div_ceil(1000)))
                    .unwrap_or_default();
                return Err(format!("the module refused: still cooling down{wait}. {COOLDOWN_NOTE}"));
            }
            Err(e) => {
                return Err(format!(
                    "cannot ask the module to re-probe ({}): {e}",
                    hv::KERNEL_MODULE_PATH
                ))
            }
        }
    }

    // `--no-timing` is the only reason to detect afresh: it deliberately
    // skips the trap-cost probe, which the cached report has already paid
    // for. Everything else comes from the process-wide cache, so a program
    // that asks twice does not probe twice.
    let cached = nanochrono_core::hypervisor::cached();
    let report;
    let report = if no_timing {
        report = HypervisorReport::detect_declared_only();
        &report
    } else {
        cached
    };
    println!("{}", report.detailed());
    Ok(())
}

fn run_integrity(drill: bool) -> Result<(), String> {
    use nanochrono_core::redundancy::{self, Protected};

    if drill {
        println!("Fault-injection drill on a scratch value — nothing live is touched.\n");
        println!("{:<34} {:<22} RECOVERED", "INJECTED", "TIER");

        let cases: [(&str, &[u32]); 4] = [
            ("nothing", &[]),
            ("one data bit (40)", &[40]),
            ("one check bit (66)", &[66]),
            ("two data bits (5, 37)", &[5, 37]),
        ];
        for (label, bits) in cases {
            let original = 0x0000_0002_4126_D2BCu64; // a plausible counter_hz
            let mut value = Protected::new(original);
            for &bit in bits {
                value.inject_flip(bit);
            }
            let outcome = value.verify();
            println!(
                "{:<34} {:<22} {}",
                label,
                outcome.name(),
                yes_no(value.get() == original)
            );
        }

        // Each replica carries its own code, so single-bit damage to one is
        // repaired by that replica rather than merely outvoted.
        let original = 0x0000_0002_4126_D2BCu64;
        let mut battered = Protected::new(original);
        for bit in [1, 2, 72 + 3, 136 + 4] {
            battered.inject_flip(bit);
        }
        let outcome = battered.verify();
        println!(
            "{:<34} {:<22} {}",
            "two data bits + one per replica",
            outcome.name(),
            yes_no(battered.get() == original)
        );

        // Damage past what every copy can repair. The point is that it
        // reports rather than guesses.
        let mut hopeless = Protected::new(original);
        for bit in [1, 2, 72 + 3, 72 + 35, 136 + 4, 136 + 36] {
            hopeless.inject_flip(bit);
        }
        let outcome = hopeless.verify();
        println!(
            "{:<34} {:<22} {}",
            "two bits in all three copies",
            outcome.name(),
            yes_no(outcome.is_usable())
        );
        println!();

        // The same drill against live state, which is what a caller actually
        // holds: a running total and a session calibration.
        println!("Live state — the flip lands in a real stopwatch and a real calibration.\n");
        println!("{:<34} {:<22} READING HELD", "INJECTED", "TIER");

        let chrono = Chronometer::new();
        let mut sw = Stopwatch::new();
        sw.start();
        std::thread::sleep(std::time::Duration::from_millis(20));
        sw.pause(&chrono);
        let truth = sw.elapsed_ns(&chrono);

        sw.inject_total_flip(40);
        let held = sw.elapsed_ns(&chrono) == truth;
        let outcome = sw.verify();
        println!(
            "{:<34} {:<22} {}",
            "stopwatch total, one bit (40)",
            outcome.name(),
            yes_no(held)
        );

        sw.inject_total_flip(11);
        sw.inject_total_flip(46);
        let held = sw.elapsed_ns(&chrono) == truth;
        let outcome = sw.verify();
        println!(
            "{:<34} {:<22} {}",
            "stopwatch total, two bits",
            outcome.name(),
            yes_no(held)
        );

        let config = clock::StableClockConfig {
            calibration_ms: 50,
            ..Default::default()
        };
        let mut calibration = clock::calibrate_cycles_per_ns(&chrono, &config);
        let factor = calibration.cycles_per_ns();
        // Bit 52 sits in the exponent: a flip there rescales every duration
        // derived from this calibration by a power of two.
        calibration.inject_factor_flip(52);
        let held = calibration.cycles_per_ns() == factor;
        let outcome = calibration.verify();
        println!(
            "{:<34} {:<22} {}",
            "clock factor, one exponent bit",
            outcome.name(),
            yes_no(held)
        );
        println!();
    }

    let stats = redundancy::stats();
    println!("checks          : {}", stats.checks);
    println!("ecc corrections : {}", stats.ecc_corrections);
    println!("tmr corrections : {}", stats.tmr_corrections);
    println!("unrecoverable   : {}", stats.unrecoverable);
    println!();
    if stats.is_clean() {
        println!("No stored-state corruption observed.");
    } else {
        println!(
            "State was repaired during this run. At sea level that usually means failing\n\
             memory rather than radiation — check the hardware before trusting a long run."
        );
    }
    Ok(())
}

fn run_catalog() -> Result<(), String> {
    let features = nanochrono_core::cpu::features();
    if let Some(brand) = nanochrono_core::cpu::brand_string() {
        println!("cpu: {brand}");
    }
    println!("invariant counter: {}", yes_no(features.invariant_counter));
    println!(
        "platform: {}",
        nanochrono_core::hypervisor::cached().summary()
    );

    println!("\nTIMER BACKENDS");
    for backend in Backend::ALL {
        println!(
            "  {:<16} {}",
            backend.name(),
            yes_no(backend.is_available())
        );
    }

    println!("\nSIMD FAMILIES");
    for family in SimdFamily::ALL {
        println!(
            "  {:<16} {:>4} B  {}",
            family.name(),
            family.vector_bytes(),
            yes_no(family.is_available())
        );
    }

    println!("\nCLOCK ROUTES");
    for route in ClockRoute::ALL {
        println!("  {:<26} {}", route.name(), yes_no(route.is_available()));
    }

    println!("\nBENCHMARK MODES");
    for mode in BenchMode::ALL {
        println!("  {:<32} {}", mode.label(), yes_no(mode.is_available()));
    }
    Ok(())
}

/// Switches every counter read to `CNTPCT_EL0`, with the warning.
///
/// Refused only where the read cannot run at all (the kernel makes it an
/// illegal instruction for user space). A VM — nested or not — is not a
/// refusal: the counter works there, it is just trapped, slow or unstable,
/// and saying so is the warning's job, not a reason to deny the flag.
fn enable_physical_counter() -> Result<(), ExitCode> {
    use nanochrono_core::arch::{self, CounterSource};
    if let Err(e) = arch::set_counter_source(CounterSource::Physical) {
        eprintln!("error: --physical-counter: {e}");
        return Err(ExitCode::from(2));
    }
    eprintln!("counter: {} (physical)", CounterSource::Physical.name());
    eprintln!("warning: {}", arch::PHYSICAL_COUNTER_WARNING);
    let report = nanochrono_core::hypervisor::cached();
    if report.is_virtualized() {
        eprintln!(
            "warning: this system is virtualized ({}); expect trapped, jittery reads",
            report.hypervisor
        );
    }
    if let Some(check) = arch::physical_counter_check() {
        eprintln!(
            "counter: one read costs {} ns physical vs {} ns virtual{}",
            check.physical_read_ns,
            check.virtual_read_ns,
            if check.trapped { " — the physical read is being trapped" } else { "" }
        );
    }
    Ok(())
}

fn run_clock(chrono: Chronometer, args: ClockArgs, live: bool) -> Result<(), String> {
    let stop = interrupt_flag();
    let zone = args.zone();
    let detail = args.detail();

    loop {
        let snapshot = NanoclockSnapshot::capture(&chrono);
        println!(
            "display_time={}",
            format::format_unix_zoned(snapshot.unix_time_ns, zone)
        );
        println!(
            "raw_local_no_ntp={}",
            format::format_unix_zoned(snapshot.unix_time_ns, TimeZoneMode::Local)
        );
        println!(
            "clock_face={}",
            format::format_clock_face(snapshot.unix_time_ns, zone, detail == DetailMode::Nano)
        );

        if detail == DetailMode::Nano {
            println!(
                "route={} simd={} cpu={} raw={} selected_ns={} read_overhead={} \
                 kernel_timecall={} api_call={}",
                snapshot.route.name(),
                snapshot.simd_name(),
                snapshot.cpu_index,
                snapshot.selected_raw_units,
                snapshot.selected_ns,
                snapshot.native_overhead_units,
                clock::measure_kernel_timecall_overhead(&chrono, 256),
                clock::measure_api_call_overhead(&chrono, 256),
            );
            print_counters(&snapshot);
        }

        if let Some(server) = &args.ntp {
            match ntp::query(&chrono, server, ntp::DEFAULT_TIMEOUT_MS, ClockRoute::Auto) {
                Ok(s) => println!(
                    "ntp_server={} stratum={} offset={:+.3} ms (+/- {:.3} ms) delay={:.3} ms \
                     setup={} units send_recv={} units migrated={}",
                    s.server,
                    s.stratum,
                    s.offset_ms(),
                    s.offset_uncertainty_ns() as f64 / 1e6,
                    s.delay_ms(),
                    s.socket_setup_units,
                    s.send_recv_units,
                    yes_no(s.migrated),
                ),
                Err(e) => println!("ntp_server={server} status={e}"),
            }
        }

        if !live || stop.load(Ordering::SeqCst) {
            break;
        }
        println!("---");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(if detail == DetailMode::Nano {
            100
        } else {
            250
        }));
    }
    Ok(())
}

fn run_ns_clock(chrono: Chronometer, live: bool) -> Result<(), String> {
    let stop = interrupt_flag();
    loop {
        let s = NanoclockSnapshot::capture(&chrono);
        println!("time_utc={}", format::format_unix_utc(s.unix_time_ns));
        println!(
            "monotonic_ns={} process_ns={} thread_ns={}",
            s.monotonic_ns, s.process_time_ns, s.thread_time_ns
        );
        println!(
            "route={} simd={} backend={} raw={} selected_ns={} barrier_overhead={}",
            s.route.name(),
            s.simd_name(),
            s.backend.name(),
            s.selected_raw_units,
            s.selected_ns,
            s.selected_overhead_units,
        );
        print_counters(&s);
        println!(
            "overhead native={} units  ffi={} units",
            s.native_overhead_units, s.ffi_overhead_units
        );

        if !live || stop.load(Ordering::SeqCst) {
            break;
        }
        println!("---");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

fn print_counters(s: &NanoclockSnapshot) {
    if cfg!(target_arch = "x86_64") {
        println!(
            "x64 rdtsc={} lfence_rdtsc={} mfence_lfence_rdtsc={} rdtscp_lfence={} aux={}",
            s.rdtsc_raw, s.rdtsc_lfence, s.rdtsc_mfence, s.rdtscp_lfence, s.rdtscp_aux
        );
    } else if cfg!(target_arch = "aarch64") {
        println!(
            "arm64 cntfrq_el0={} cntvct_el0={} cntvct_isb={} cntvct_ns={}",
            s.cntfrq_el0, s.cntvct_el0, s.cntvct_isb, s.cntvct_ns,
        );
    } else if cfg!(any(
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "arm"
    )) {
        println!(
            "{} timebase={} timebase_hz={}",
            nanochrono_core::arch::ARCH.name(),
            nanochrono_core::arch::counter_raw(),
            nanochrono_core::arch::declared_counter_hz().unwrap_or(0),
        );
    }
    println!(
        "perf_cycles={} ({} PMU event(s), via perf_event_open)",
        s.perf_cycles
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unavailable".to_string()),
        s.perf_pmu_count,
    );
    // Ring 0, when the perf module owns /proc/nanochrono. System-wide
    // per-CPU counts, not per-thread: a different question from the line
    // above, which is why both are shown rather than merged.
    #[cfg(target_os = "linux")]
    match nanochrono_core::ring0_perf::Ring0Perf::read() {
        Some(r) => println!(
            "ring0_{}={} (raw={} npmu={} enabled_ns={} running_ns={}, via /proc/nanochrono)",
            r.event.name(),
            r.scaled,
            r.raw,
            r.npmu,
            r.enabled_ns,
            r.running_ns,
        ),
        None => println!("ring0=unavailable (module not loaded; see kernel/linux/README.md)"),
    }
}

fn run_perf(args: PerfArgs) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        return Err("perf ring 0 is Linux-only; ring 3 is reported via `once` on this platform"
            .to_string());
    }
    #[cfg(target_os = "linux")]
    {
        use nanochrono_core::ring0_perf::{Ring0Event, Ring0Perf};

        if let Some(name) = args.event.as_deref() {
            let event = Ring0Event::parse(name)
                .ok_or_else(|| format!("unknown event '{name}': use cycles or instr"))?;
            Ring0Perf::select(event).map_err(|e| {
                format!(
                    "could not select {} in /proc/nanochrono: {e} \
                     (module loaded? writable? try sudo)",
                    event.name()
                )
            })?;
            println!("ring0 event selected: {}", event.name());
        }
        if args.enable {
            Ring0Perf::set_enabled(true).map_err(|e| {
                format!("could not enable /proc/nanochrono: {e} (try sudo)")
            })?;
            println!("ring0 enabled");
        }
        if args.disable {
            Ring0Perf::set_enabled(false).map_err(|e| {
                format!("could not disable /proc/nanochrono: {e} (try sudo)")
            })?;
            println!("ring0 disabled");
        }

        // Ring 3: per-thread, follows this thread.
        let r3 = nanochrono_core::perf::read_thread_cycles();
        println!(
            "ring3_cycles={} ({} PMU event(s), via perf_event_open, per-thread)",
            r3.map(|v| v.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            nanochrono_core::perf::pmu_count(),
        );

        // Ring 0: system-wide per-CPU sums from the module.
        match Ring0Perf::read() {
            Some(r) => {
                println!("ring0_source=perf (/proc/nanochrono, nanochrono.ko)");
                println!("ring0_event={}", r.event.name());
                println!("ring0_enabled={}", yes_no(r.enabled));
                println!("ring0_npmu={}", r.npmu);
                println!("ring0_raw={}", r.raw);
                println!("ring0_enabled_ns={}", r.enabled_ns);
                println!("ring0_running_ns={}", r.running_ns);
                println!("ring0_scaled={} (multiplexing-corrected; the number to use)", r.scaled);
                if !r.enabled {
                    println!("note: counting is disabled; `perf --enable` to resume");
                }
            }
            None => {
                println!("ring0=unavailable");
                println!(
                    "  the kernel module is not loaded, or this machine exposes no \
                     PMU events to it (perf_available=0 in /proc/nanochrono)."
                );
                println!("  cd kernel/linux && sudo make load");
            }
        }
        Ok(())
    }
}

fn run_calibrate_route(chrono: Chronometer, args: CalibrateArgs) -> Result<(), String> {
    let r = clock::calibrate_route(&chrono, ClockRoute::Auto, args.samples, false, 0);
    println!(
        "route={} samples={} pinned={} cpu_before={} cpu_after={} migrated={}",
        r.route.name(),
        r.samples,
        yes_no(r.pinned),
        r.cpu_before,
        r.cpu_after,
        yes_no(r.migrated)
    );
    println!(
        "elapsed_raw={} elapsed_ns={} units_per_second={:.3} ns_per_unit={:.12}",
        r.elapsed_raw_units, r.elapsed_ns, r.units_per_second, r.ns_per_unit
    );
    println!(
        "overhead read={} kernel_timecall={} api_call={}",
        r.read_overhead_units, r.kernel_timecall_overhead_units, r.api_call_overhead_units
    );
    if r.migrated {
        println!("warning: the thread migrated during calibration; re-run with --pin-cpu N");
    }
    Ok(())
}

fn run_stable_calibrate(
    chrono: Chronometer,
    args: CalibrateArgs,
    pin_cpu: Option<u32>,
) -> Result<(), String> {
    let config = StableClockConfig {
        pin_cpu: pin_cpu.is_some(),
        cpu_index: pin_cpu.unwrap_or(0),
        calibration_ms: args.ms,
        ..Default::default()
    };
    let s = clock::calibrate_cycles_per_ns(&chrono, &config);

    println!(
        "route={} pinned={} cpu_before={} cpu_after={} migrated={} invariant={}",
        s.route.name(),
        yes_no(s.pinned),
        s.cpu_before,
        s.cpu_after,
        yes_no(s.migrated),
        yes_no(s.invariant)
    );
    println!(
        "raw_start={} raw_end={} elapsed_units={} elapsed_ns={}",
        s.raw_start, s.raw_end, s.elapsed_units, s.elapsed_ns
    );
    println!(
        "cycles_per_ns={:.12} ns_per_cycle={:.12} read_overhead={} kernel={} api={}",
        s.cycles_per_ns(),
        s.ns_per_cycle(),
        s.read_overhead_units,
        s.kernel_timecall_overhead_units,
        s.api_call_overhead_units
    );
    println!("formula: ns = cycles / cycles_per_ns");
    println!("usable: {}", yes_no(s.is_usable()));
    println!("advice: {}", clock::STABILITY_ADVICE);
    Ok(())
}

fn run_cycles_to_ns(cycles: u64, cycles_per_ns: f64) -> Result<(), String> {
    if !cycles_per_ns.is_finite() || cycles_per_ns <= 0.0 {
        return Err("--cycles-per-ns must be a positive, finite number".to_string());
    }
    println!(
        "cycles={cycles} cycles_per_ns={cycles_per_ns:.12} ns={}",
        clock::units_to_ns_calibrated(cycles, cycles_per_ns)
    );
    Ok(())
}

fn run_ntp(chrono: &Chronometer, server: &str, timeout_ms: u32) -> Result<(), String> {
    let s = ntp::query(chrono, server, timeout_ms, ClockRoute::Auto)
        .map_err(|e| format!("NTP query failed: {e}"))?;

    println!("server={}", s.server);
    println!(
        "stratum={} version={} leap={} precision_exp={}",
        s.stratum, s.version, s.leap_indicator, s.precision_exp
    );
    println!(
        "server_time={}",
        format::format_unix_utc(s.ntp_transmit_unix_ns)
    );
    println!(
        "offset={:+.6} ms (+/- {:.6} ms)  delay={:.6} ms",
        s.offset_ms(),
        s.offset_uncertainty_ns() as f64 / 1e6,
        s.delay_ms()
    );
    println!(
        "socket_setup={} units  send_recv={} units  kernel_timecall={} units  api_call={} units",
        s.socket_setup_units,
        s.send_recv_units,
        s.kernel_timecall_overhead_units,
        s.api_call_overhead_units
    );
    println!("migrated={}", yes_no(s.migrated));
    Ok(())
}

fn run_tls(host: &str, port: u16, suites: bool) -> Result<(), String> {
    use nanochrono_crypto::tls;

    println!("provider: {}", nanochrono_crypto::PROVIDER);
    if suites {
        println!("cipher suites:");
        for s in tls::supported_cipher_suites() {
            println!("  {s}");
        }
        println!("key exchange groups:");
        for g in tls::supported_key_exchange_groups() {
            println!("  {g}");
        }
        println!();
    }

    let t = tls::probe_handshake(host, port, tls::DEFAULT_TIMEOUT)
        .map_err(|e| format!("handshake failed: {e}"))?;

    println!("host={}:{}", t.host, t.port);
    println!("protocol={} cipher_suite={}", t.protocol, t.cipher_suite);
    println!(
        "peer_certificates={} resumed={}",
        t.peer_certificates,
        yes_no(t.resumed)
    );
    println!("resolve={:.3} ms", t.resolve_ns as f64 / 1e6);
    println!("tcp_connect={:.3} ms", t.tcp_connect_ns as f64 / 1e6);
    println!("tls_handshake={:.3} ms", t.tls_handshake_ns as f64 / 1e6);
    println!(
        "total={:.3} ms (TLS is {:.1}% of it)",
        t.total_ms(),
        t.tls_fraction() * 100.0
    );
    Ok(())
}

fn run_bench(chrono: &Chronometer, args: BenchArgs) -> Result<(), String> {
    let mode: BenchMode = args.mode.into();
    let rows = BenchKernel::rows_for(mode);

    let selected: Vec<BenchKernel> = if args.kernel.eq_ignore_ascii_case("all") {
        rows.into_iter().filter(|k| k.is_available()).collect()
    } else {
        // Matched on the display name, and — for the kernel-crypto mode —
        // on the algorithm's own name too. `--kernel sha256` is the obvious
        // thing to type, and "SHA-256 (kernel)" is not.
        let wanted = rows.into_iter().find(|k| {
            k.name().eq_ignore_ascii_case(&args.kernel)
                || matches!(k, BenchKernel::Kernel(a) | BenchKernel::Ring0(a)
                    if a.algorithm().eq_ignore_ascii_case(&args.kernel))
                // `vaes` as well as `vaes (ymm)`: the register width is a
                // label, not something anyone types.
                || matches!(k, BenchKernel::CryptoRaw(c)
                    if c.name().eq_ignore_ascii_case(&args.kernel)
                        || c.name().split(" (").next().is_some_and(|short| short.eq_ignore_ascii_case(&args.kernel)))
        });
        match wanted {
            Some(k) => vec![k],
            None => {
                return Err(format!(
                    "unknown kernel '{}' for mode {}",
                    args.kernel,
                    mode.name()
                ))
            }
        }
    };

    // An empty selection is not success. `--kernel all` filters by
    // availability, and a mode whose rows are all unavailable would otherwise
    // print nothing at all and exit zero — which reads as "it ran and found
    // nothing to say" rather than "this needs something you have not done".
    if selected.is_empty() {
        return Err(format!(
            "no runnable kernels for mode {}: {}",
            mode.name(),
            if mode == BenchMode::KernelCryptoRing0 {
                "the kernel module is not loaded. Build and insert it with \
                 `cd kernel/linux && make load`, or use `--mode kernel` for the \
                 ring-3 measurement, which needs nothing."
            } else {
                "nothing this machine offers matches it."
            }
        ));
    }

    for kernel in selected {
        let config = BenchConfig {
            mode,
            kernel,
            tls_host: args.host.clone(),
            tls_port: args.port,
        };
        let report = nanochrono_bench::run(chrono, &config);
        print!("{}", report.log);
        println!();
    }
    Ok(())
}

fn run_wrapper_overhead(chrono: &Chronometer) -> Result<(), String> {
    println!(
        "Native call-overhead baselines. Interpreted wrappers must add their own\n\
         marshalling cost on top: this process cannot measure another runtime.\n"
    );
    println!("{:<18} {:>10} {:>10}  SOURCE", "WRAPPER", "UNITS", "NS");
    for kind in WrapperKind::ALL {
        let units = clock::measure_wrapper_overhead(chrono, *kind, 20_000);
        println!(
            "{:<18} {:>10} {:>10}  {}",
            kind.name(),
            units,
            chrono.units_to_ns(units),
            if kind.is_measured_natively() {
                "measured"
            } else {
                "baseline"
            }
        );
    }
    Ok(())
}

fn run_asm_probe() -> Result<(), String> {
    let mut buffer = vec![0x5Au8; 4096];

    println!("{:<18} {:>12}", "PROBE", "UNITS");
    for kind in [
        CacheProbe::Counter,
        CacheProbe::Load,
        CacheProbe::LoadFenced,
        CacheProbe::FlushReload,
        CacheProbe::PrefetchReload,
        CacheProbe::Store,
        CacheProbe::Branch,
        CacheProbe::Barrier,
    ] {
        match probe::run(kind, &mut buffer, 64) {
            Some(units) => println!("{:<18} {units:>12}", kind.name()),
            None => println!("{:<18} {:>12}", kind.name(), "unsupported"),
        }
    }

    if let Some(audit) = probe::cache_audit(&mut buffer) {
        println!(
            "\ncache separation: cached={} flushed={} prefetched={} threshold={} delta={:.1}",
            audit.cached_units,
            audit.flushed_units,
            audit.prefetched_units,
            audit.threshold_units,
            audit.separation
        );
    }
    Ok(())
}

fn run_asm_simd(chrono: &Chronometer) -> Result<(), String> {
    println!("SIMD probes (available families only, CPUID-gated):\n");
    println!(
        "{:<16} {:>6} {:>14} {:>14} {:>12}",
        "FAMILY", "WIDTH", "VECTOR_LOAD", "VECTOR_XOR", "BARRIER"
    );

    for family in SimdFamily::available() {
        let width = family.vector_bytes();
        let a = vec![0xA5u8; width];
        let b = vec![0x5Au8; width];
        let mut out = vec![0u8; width];

        let load = nanochrono_core::simd::probe(
            family,
            ProbeKind::VectorLoad,
            Some(ProbeBuffers {
                a: &a,
                b: &b,
                out: &mut out,
            }),
            0,
        );
        let xor = nanochrono_core::simd::probe(
            family,
            ProbeKind::VectorXor,
            Some(ProbeBuffers {
                a: &a,
                b: &b,
                out: &mut out,
            }),
            0,
        );
        let barrier = nanochrono_core::simd::probe(family, ProbeKind::Barrier, None, 32);

        println!(
            "{:<16} {:>4} B {:>14} {:>14} {:>12}",
            family.name(),
            width,
            load.map(|r| r.raw_units).unwrap_or(0),
            xor.map(|r| r.raw_units).unwrap_or(0),
            barrier.map(|r| r.raw_units).unwrap_or(0),
        );
    }

    println!(
        "\nunits are {} ({:.3} MHz calibrated)",
        if cfg!(target_arch = "x86_64") {
            "TSC cycles"
        } else {
            "counter ticks"
        },
        chrono.counter_hz() as f64 / 1e6
    );
    Ok(())
}

fn run_sct_audit(chrono: &Chronometer, samples: u32) -> Result<(), String> {
    let config = AuditConfig {
        samples,
        ..Default::default()
    };

    // The demo candidate accumulates over every byte with no early exit, so a
    // correct run should *not* flag it. Treat a leak verdict here as a sign
    // the machine is too noisy to audit on, not as a finding.
    let verdict = probe::audit_constant_time(
        chrono,
        |input, output| {
            let mut acc = 0u8;
            for b in input {
                acc |= b ^ 0xA5;
            }
            for b in output.iter_mut() {
                *b = acc;
            }
        },
        &config,
    );

    println!("samples={} per class", verdict.fixed.count);
    println!(
        "fixed:  min={} median={} mean={:.1} p99={}",
        verdict.fixed.min, verdict.fixed.median, verdict.fixed.mean, verdict.fixed.p99
    );
    println!(
        "random: min={} median={} mean={:.1} p99={}",
        verdict.random.min, verdict.random.median, verdict.random.mean, verdict.random.p99
    );
    println!("welch_t={:.3}", verdict.welch_t);
    println!(
        "verdict: {}",
        if verdict.likely_leak {
            "timing difference detected — investigate, or re-run pinned to a quiet core"
        } else {
            "no timing difference indicated"
        }
    );
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
