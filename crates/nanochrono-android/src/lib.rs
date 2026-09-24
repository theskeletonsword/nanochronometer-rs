// SPDX-License-Identifier: Apache-2.0
//! The JNI bridge behind the Android app (`packaging/android/app`).
//!
//! Hand-written against the JNI function table rather than through a binding
//! crate: the app needs one JNI call (`NewStringUTF`), everything else crosses
//! as primitives, and a dependency for that would be larger than the bridge.
//!
//! Every export is `Java_io_github_nanochronometer_Native_*`, a static
//! method on `io.github.nanochronometer.Native`. None of them panics across
//! the boundary: a panic unwinding into the JVM is undefined behaviour, so
//! each body runs under `catch_unwind` and reports the panic as text.
//!
//! What an unprivileged Android app may and may not do is decided at run
//! time, not assumed: the physical counter is probed, `perf_event_open` is
//! attempted, and the report says what happened. `SMC`/`HVC` are not probed
//! at all — from EL0 both are architecturally undefined, on every device,
//! rooted or not.

#![allow(non_snake_case)]

use std::ffi::{c_char, c_void, CString};
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

use nanochrono_bench::{BenchConfig, BenchKernel, BenchMode};
use nanochrono_core::underwater::{self, Crystal, Exposure, IpRating, SubmersionGuard};
use nanochrono_core::{Backend, Chronometer, SimdFamily};

// ---------------------------------------------------------------------------
// JNI, the part used
// ---------------------------------------------------------------------------

type JNIEnv = *mut *const *const c_void;
type JClass = *mut c_void;
type JString = *mut c_void;

/// `NewStringUTF`'s slot in `JNINativeInterface`, fixed since JNI 1.1.
const NEW_STRING_UTF: usize = 167;

/// Makes a Java string. JNI wants modified UTF-8, which differs from UTF-8
/// only for NUL and for characters outside the BMP; both are replaced.
fn java_string(env: JNIEnv, text: &str) -> JString {
    let clean: String = text
        .chars()
        .map(|c| if c == '\0' || (c as u32) > 0xFFFF { '?' } else { c })
        .collect();
    let Ok(c) = CString::new(clean) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `env` is the JNIEnv the VM passed to this native method; its
    // first word points at the function table, and slot 167 is
    // `jstring NewStringUTF(JNIEnv*, const char*)`.
    unsafe {
        let table = *env;
        let f: extern "system" fn(JNIEnv, *const c_char) -> JString =
            std::mem::transmute(*table.add(NEW_STRING_UTF));
        f(env, c.as_ptr())
    }
}

/// Runs `body`, turning a panic into text instead of unwinding into the VM.
fn guarded(body: impl FnOnce() -> String) -> String {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|e| {
        let why = e
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown".into());
        format!("error=native panic: {why}\n")
    })
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

fn chrono() -> &'static Chronometer {
    static CHRONO: OnceLock<Chronometer> = OnceLock::new();
    CHRONO.get_or_init(Chronometer::new)
}

fn guard() -> &'static Mutex<SubmersionGuard> {
    static GUARD: OnceLock<Mutex<SubmersionGuard>> = OnceLock::new();
    GUARD.get_or_init(|| Mutex::new(SubmersionGuard::new()))
}

// ---------------------------------------------------------------------------
// Device report
// ---------------------------------------------------------------------------

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// What `perf_event_open` says to this process: a cycle counter on itself,
/// user space only — the least any PMU access could ask for. Android ships
/// `perf_event_paranoid` at 3, which refuses it to apps; this asks rather
/// than assumes, so a device that allows it is reported as allowing it.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn pmu_probe() -> String {
    // perf_event_attr, zeroed, with the fields this sets: type (0 = HARDWARE)
    // at 0, size at 4, config (0 = CPU_CYCLES) at 8, and the flag word at 40
    // with exclude_kernel (bit 5) and exclude_hv (bit 6).
    let mut attr = [0u8; 128];
    attr[4..8].copy_from_slice(&128u32.to_ne_bytes());
    attr[40..48].copy_from_slice(&((1u64 << 5) | (1u64 << 6)).to_ne_bytes());
    // SAFETY: the attribute buffer is valid for its declared size; the
    // returned descriptor is closed below.
    let fd = unsafe {
        libc::syscall(libc::SYS_perf_event_open, attr.as_ptr(), 0, -1, -1, 0u64)
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());
        // Level 2 and above refuse even a user-space-only self-monitor; below
        // that the sysctl allows this request. A refusal the sysctl does not
        // explain is Android's SELinux policy, which keeps `perf_event` from
        // untrusted apps whatever the sysctl says.
        let why = match paranoid {
            Some(p) if p >= 2 => format!("perf_event_paranoid={p} refuses it"),
            Some(p) => format!("SELinux policy (perf_event_paranoid={p} would allow it)"),
            None => "perf_event_paranoid unreadable".into(),
        };
        return format!("denied ({err}): {why}");
    }
    let mut value = 0u64;
    // SAFETY: `fd` is a perf event descriptor; the read fills eight bytes.
    let n = unsafe { libc::read(fd as i32, (&mut value as *mut u64).cast(), 8) };
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(fd as i32) };
    if n == 8 {
        format!("ALLOWED (cycles so far: {value})")
    } else {
        "opened, but the read failed".into()
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn pmu_probe() -> String {
    "not applicable".into()
}

fn device_report() -> String {
    let mut r = String::new();
    let features = nanochrono_core::cpu::features();
    let _ = writeln!(r, "abi={}", std::env::consts::ARCH);
    if let Some(brand) = nanochrono_core::cpu::brand_string() {
        let _ = writeln!(r, "cpu={brand}");
    }
    let _ = writeln!(r, "invariant_counter={}", yes_no(features.invariant_counter));
    let c = chrono();
    let _ = writeln!(r, "timer_backend={}", c.backend().name());
    let _ = writeln!(r, "counter={}", nanochrono_core::arch::counter_source().name());
    #[cfg(target_arch = "aarch64")]
    {
        let _ = writeln!(r, "counter_hz={}", nanochrono_core::arch::aarch64::cntfrq());
        let permitted = nanochrono_core::arch::aarch64::physical_permitted();
        let _ = writeln!(
            r,
            "cntpct_el0={}",
            if permitted {
                "PERMITTED at EL0 on this device"
            } else {
                "not permitted (the kernel leaves only CNTVCT_EL0 to user space)"
            }
        );
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = writeln!(r, "cntpct_el0=not applicable (not AArch64)");
    }
    let _ = writeln!(r, "pmu={}", pmu_probe());
    let _ = writeln!(
        r,
        "smc_hvc=not attempted: undefined at EL0 by the architecture, on every device"
    );
    let _ = writeln!(r, "platform={}", nanochrono_core::hypervisor::cached().summary());
    for backend in Backend::ALL.iter().filter(|b| for_this_architecture(BenchKernel::Isa(**b))) {
        let _ = writeln!(r, "backend.{}={}", backend.name(), yes_no(backend.is_available()));
    }
    for family in SimdFamily::ALL.iter().filter(|f| f.is_native()) {
        let _ = writeln!(
            r,
            "simd.{}={} ({} B)",
            family.name(),
            yes_no(family.is_available()),
            family.vector_bytes()
        );
    }
    r
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_deviceReport(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    java_string(env, &guarded(device_report))
}

/// Monotonic nanoseconds from the architectural counter (`CNTVCT_EL0`, or
/// the TSC on x86), converted with its calibration. For the stopwatch.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_nowNs(
    _env: JNIEnv,
    _class: JClass,
) -> i64 {
    catch_unwind(|| {
        let c = chrono();
        c.units_to_ns(c.now_units()) as i64
    })
    .unwrap_or(-1)
}

/// Switches to the physical counter if the device allows it. Returns
/// whether the physical counter is now in use.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_usePhysicalCounter(
    _env: JNIEnv,
    _class: JClass,
    on: u8,
) -> u8 {
    use nanochrono_core::arch::{self, CounterSource};
    catch_unwind(|| {
        let wanted = if on != 0 { CounterSource::Physical } else { CounterSource::Virtual };
        let _ = arch::set_counter_source(wanted);
        (arch::counter_source() == CounterSource::Physical) as u8
    })
    .unwrap_or(0)
}

/// Every benchmark row, one per line: `mode<TAB>kernel<TAB>mode label<TAB>
/// kernel name<TAB>available<TAB>this architecture`. The app shows only the
/// available ones unless asked for all.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_benchRows(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    let text = guarded(|| {
        let mut r = String::new();
        for (m, mode) in BenchMode::ALL.iter().enumerate() {
            for (k, kernel) in BenchKernel::rows_for(*mode).iter().enumerate() {
                let _ = writeln!(
                    r,
                    "{m}\t{k}\t{}\t{}\t{}\t{}",
                    mode.label(),
                    kernel.name(),
                    (mode.is_available() && kernel.is_available()) as u8,
                    for_this_architecture(*kernel) as u8
                );
            }
        }
        r
    });
    java_string(env, &text)
}

/// Whether a row's family belongs to this architecture, so "show all" can
/// tell "this CPU lacks it" from "another architecture's".
fn for_this_architecture(kernel: BenchKernel) -> bool {
    match kernel {
        BenchKernel::Isa(backend) => backend.is_native(),
        _ => true,
    }
}

/// Runs one benchmark row and returns its log and summary. Blocks for as
/// long as the benchmark takes; call it off the UI thread.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_runBench(
    env: JNIEnv,
    _class: JClass,
    mode: i32,
    kernel: i32,
) -> JString {
    let text = guarded(|| {
        let Some(&mode) = BenchMode::ALL.get(mode as usize) else {
            return "error=no such mode\n".into();
        };
        let rows = BenchKernel::rows_for(mode);
        let Some(&kernel) = rows.get(kernel as usize) else {
            return "error=no such kernel\n".into();
        };
        let config = BenchConfig {
            mode,
            kernel,
            ..BenchConfig::default()
        };
        let chrono = Chronometer::new();
        let report = nanochrono_bench::run(&chrono, &config);
        let mut r = report.log.clone();
        if let Some(e) = report.error {
            let _ = writeln!(r, "error={e}");
        } else {
            let s = &report.summary;
            let _ = writeln!(r, "best_mops={:.3}", s.best_mops);
            let _ = writeln!(r, "mean_mops={:.3}", s.mean_mops);
            let _ = writeln!(r, "best_ns_per_op={:.3}", s.best_ns_per_op);
        }
        r
    });
    java_string(env, &text)
}

/// Feeds a barometer reading. Returns bit 0 = submerged, bit 1 = touch
/// locked.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_barometer(
    _env: JNIEnv,
    _class: JClass,
    hpa: f64,
    now_ns: i64,
) -> i32 {
    catch_unwind(|| {
        let mut g = guard().lock().unwrap_or_else(|p| p.into_inner());
        let submerged = g.sample(hpa, now_ns.max(0) as u64);
        (submerged as i32) | ((g.touch_locked() as i32) << 1)
    })
    .unwrap_or(0)
}

/// Estimated depth in metres for a reading, against the tracked surface.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_depthM(
    _env: JNIEnv,
    _class: JClass,
    hpa: f64,
) -> f64 {
    catch_unwind(|| guard().lock().map(|g| g.depth_m(hpa)).unwrap_or(0.0)).unwrap_or(0.0)
}

/// Judges a dive against a rating. `rating`: 0 none, 1 jets (IPx5/x6),
/// 2 IPx7, 3 IPx8 (with the declared depth and minutes), 4 IP69K/IPx9.
/// Returns 0 within, 1 near, 2 beyond.
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_exposure(
    _env: JNIEnv,
    _class: JClass,
    rating: i32,
    declared_depth_m: f64,
    declared_minutes: i32,
    depth_m: f64,
    submerged_ns: i64,
) -> i32 {
    let rating = match rating {
        1 => IpRating::Jets,
        2 => IpRating::Immersion1m,
        3 => IpRating::ImmersionDeclared {
            depth_m: declared_depth_m.max(0.1),
            minutes: declared_minutes.max(1) as u32,
        },
        4 => IpRating::HighPressureJets,
        _ => IpRating::None,
    };
    match rating.exposure(depth_m, submerged_ns.max(0) as u64) {
        Exposure::Within => 0,
        Exposure::Near => 1,
        Exposure::Beyond => 2,
    }
}

/// ± ppm a crystal may sit from nominal at a temperature. `crystal`: 0
/// AT-cut (a SoC's reference), 1 tuning fork (32 kHz).
#[no_mangle]
pub extern "system" fn Java_io_github_nanochronometer_Native_thermalPpm(
    _env: JNIEnv,
    _class: JClass,
    crystal: i32,
    celsius: f64,
) -> f64 {
    let crystal = if crystal == 1 { Crystal::TuningFork } else { Crystal::AtCut };
    underwater::thermal_uncertainty_ppm(crystal, celsius)
}
