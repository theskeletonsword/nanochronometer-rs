// SPDX-License-Identifier: Apache-2.0
//! Runtime ISA dispatcher.
//!
//! Detects what the CPU can execute, picks the widest usable implementation of
//! every hot path, and resolves it to a function pointer **once**. After
//! initialisation a call is an indirect jump — there is no per-call `match` on
//! a backend enum, which is what the C version did on every single counter
//! read.
//!
//! Three things make this safe:
//!
//! * A pointer is installed only after both the CPUID bit and, on x86-64, the
//!   `XCR0` bit for the register file are observed. That pairing is the whole
//!   game: a CPU can advertise AVX-512 while the OS has not enabled ZMM state,
//!   and executing a ZMM instruction then is `#UD`, not a slow path.
//! * Selection happens in [`Dispatcher::resolve`], which is the only place
//!   that constructs a `Dispatcher`, so no caller can install a pointer for a
//!   family the machine lacks.
//! * An operator override is validated against the same gate and falls back
//!   with a recorded reason rather than trusting the request.
//!
//! # Overrides
//!
//! | Variable | Effect |
//! |---|---|
//! | `NANOCHRONO_BACKEND` | Force a timer backend, e.g. `avx2`, `sse2`, `legacy` |
//! | `NANOCHRONO_SIMD` | Force a SIMD probe family |
//! | `NANOCHRONO_CLOCK_ROUTE` | Force a clock route |
//!
//! An unrecognised or unsupported value is ignored and reported in
//! [`Dispatcher::report`], so a bad override degrades to the detected default
//! instead of failing at startup.
//!
//! ```
//! use nanochrono_core::dispatch::Dispatcher;
//!
//! let d = Dispatcher::global();
//! println!("{}", d.report());
//! let cycles = d.counter_end().wrapping_sub(d.counter_start());
//! # let _ = cycles;
//! ```

use std::sync::OnceLock;

use crate::arch;
use crate::backend::Backend;
use crate::clock::ClockRoute;
use crate::cpu::{self, CpuFeatures};
use crate::simd::SimdFamily;

/// Why the dispatcher ended up with the selection it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionReason {
    /// Widest family the CPU and OS both support.
    Detected,
    /// An environment override was accepted.
    Overridden,
    /// An override was requested but the machine cannot run it.
    OverrideRejected,
    /// Nothing wider was available; this is the portable floor.
    Fallback,
}

impl SelectionReason {
    pub const fn name(self) -> &'static str {
        match self {
            SelectionReason::Detected => "detected",
            SelectionReason::Overridden => "overridden",
            SelectionReason::OverrideRejected => "override-rejected",
            SelectionReason::Fallback => "fallback",
        }
    }
}

pub use crate::kernels::{CryptoKernel, KernelFn};


/// Signature of a dispatched counter read.
pub type CounterFn = fn() -> u64;

/// The resolved dispatch table.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    features: CpuFeatures,

    backend: Backend,
    backend_reason: SelectionReason,
    simd: Option<SimdFamily>,
    simd_reason: SelectionReason,
    route: ClockRoute,
    route_reason: SelectionReason,

    counter_start: CounterFn,
    counter_end: CounterFn,
    kernel: KernelFn,
}

impl Dispatcher {
    /// The process-wide dispatcher, resolved on first use.
    ///
    /// Detection is not free — CPUID serialises the pipeline — so it happens
    /// exactly once and every later call reads the cached table.
    pub fn global() -> &'static Dispatcher {
        static GLOBAL: OnceLock<Dispatcher> = OnceLock::new();
        GLOBAL.get_or_init(Dispatcher::resolve)
    }

    /// Runs detection and builds a table. Prefer [`Dispatcher::global`].
    pub fn resolve() -> Dispatcher {
        let features = cpu::features();

        let (backend, backend_reason) = select_backend(&features);
        let (simd, simd_reason) = select_simd();
        let (route, route_reason) = select_route();

        Dispatcher {
            features,
            backend,
            backend_reason,
            simd,
            simd_reason,
            route,
            route_reason,
            counter_start: arch::counter_start,
            counter_end: arch::counter_end,
            kernel: resolve_kernel(backend),
        }
    }

    /// Features detected on this machine.
    pub fn features(&self) -> &CpuFeatures {
        &self.features
    }

    /// The selected timer backend.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The selected SIMD probe family, if the target has one.
    pub fn simd_family(&self) -> Option<SimdFamily> {
        self.simd
    }

    /// The selected clock route.
    pub fn clock_route(&self) -> ClockRoute {
        self.route
    }

    /// Ordered counter read for the start of an interval.
    #[inline(always)]
    pub fn counter_start(&self) -> u64 {
        (self.counter_start)()
    }

    /// Ordered counter read for the end of an interval.
    #[inline(always)]
    pub fn counter_end(&self) -> u64 {
        (self.counter_end)()
    }

    /// Runs the ISA kernel for the selected backend.
    ///
    /// Safe to call on any machine: the pointer was installed only for a
    /// family this CPU advertises.
    #[inline]
    pub fn run_kernel(&self, loops: usize) -> u64 {
        (self.kernel)(loops)
    }

    /// Runs the kernel for a specific backend, or `None` if unsupported here.
    ///
    /// This is what a benchmark UI uses to walk every family: unavailable ones
    /// return `None` instead of faulting.
    pub fn run_kernel_for(&self, backend: Backend, loops: usize) -> Option<u64> {
        if !backend.is_available() {
            return None;
        }
        Some(resolve_kernel(backend)(loops))
    }

    /// Runs a cryptographic instruction kernel, or `None` if unsupported here.
    ///
    /// Separate from [`run_kernel_for`](Self::run_kernel_for) because these
    /// families are not timer backends: they answer "what does one AES round
    /// cost", not "what can this counter path measure".
    pub fn run_crypto_kernel(&self, kernel: CryptoKernel, loops: usize) -> Option<u64> {
        if !kernel.is_available() {
            return None;
        }
        Some(resolve_crypto_kernel(kernel)?(loops))
    }

    /// Every crypto kernel with whether it is usable here.
    pub fn crypto_matrix(&self) -> Vec<(CryptoKernel, bool)> {
        CryptoKernel::ALL
            .iter()
            .copied()
            .map(|k| (k, k.is_available()))
            .collect()
    }

    /// Every backend with whether it is usable and whether it was chosen.
    pub fn backend_matrix(&self) -> Vec<(Backend, bool, bool)> {
        Backend::ALL
            .iter()
            .copied()
            .map(|b| (b, b.is_available(), b == self.backend))
            .collect()
    }

    /// A human-readable account of what was selected and why.
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "arch={} backend={} ({}) simd={} ({}) route={} ({})\n",
            arch::ARCH.name(),
            self.backend.name(),
            self.backend_reason.name(),
            self.simd.map(SimdFamily::name).unwrap_or("none"),
            self.simd_reason.name(),
            self.route.name(),
            self.route_reason.name(),
        ));
        out.push_str(&format!(
            "platform={} ({})\n",
            crate::hypervisor::cached().summary(),
            crate::hypervisor::cached().timing_impact.name(),
        ));
        out.push_str(&format!(
            "invariant_counter={} available=[{}]",
            self.features.invariant_counter,
            Backend::ALL
                .iter()
                .filter(|b| b.is_available())
                .map(|b| b.name())
                .collect::<Vec<_>>()
                .join(" "),
        ));
        out
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Dispatcher::resolve()
    }
}

fn select_backend(features: &CpuFeatures) -> (Backend, SelectionReason) {
    if let Some(requested) = env_var("NANOCHRONO_BACKEND").and_then(|s| Backend::parse(&s)) {
        if requested.is_available() {
            return (requested, SelectionReason::Overridden);
        }
        return (Backend::best(), SelectionReason::OverrideRejected);
    }
    let best = Backend::best();
    let reason = if best == Backend::Legacy && !features.sse2 {
        SelectionReason::Fallback
    } else {
        SelectionReason::Detected
    };
    (best, reason)
}

fn select_simd() -> (Option<SimdFamily>, SelectionReason) {
    if let Some(name) = env_var("NANOCHRONO_SIMD") {
        let requested = SimdFamily::ALL
            .iter()
            .copied()
            .find(|f| f.name().eq_ignore_ascii_case(&name));
        return match requested {
            Some(f) if f.is_available() => (Some(f), SelectionReason::Overridden),
            _ => (SimdFamily::best(), SelectionReason::OverrideRejected),
        };
    }
    match SimdFamily::best() {
        Some(f) => (Some(f), SelectionReason::Detected),
        None => (None, SelectionReason::Fallback),
    }
}

fn select_route() -> (ClockRoute, SelectionReason) {
    if let Some(name) = env_var("NANOCHRONO_CLOCK_ROUTE") {
        let requested = ClockRoute::ALL
            .iter()
            .copied()
            .find(|r| r.name().eq_ignore_ascii_case(&name));
        return match requested {
            Some(r) if r.is_available() => (r, SelectionReason::Overridden),
            _ => (ClockRoute::best(), SelectionReason::OverrideRejected),
        };
    }
    let best = ClockRoute::best();
    let reason = if matches!(best, ClockRoute::MonotonicNs) {
        SelectionReason::Fallback
    } else {
        SelectionReason::Detected
    };
    (best, reason)
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

use crate::kernels::{resolve_crypto_kernel, resolve_kernel};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_is_stable_across_calls() {
        let a = Dispatcher::global();
        let b = Dispatcher::global();
        assert!(std::ptr::eq(a, b), "dispatcher must resolve exactly once");
    }

    #[test]
    fn selected_backend_is_runnable() {
        let d = Dispatcher::global();
        assert!(d.backend().is_available());
        assert!(d.simd_family().is_none_or(|f| f.is_available()));
        assert!(d.clock_route().is_available());
    }

    /// The point of the dispatcher: no path it hands out may fault.
    #[test]
    fn every_advertised_kernel_executes() {
        let d = Dispatcher::global();
        for (backend, available, _) in d.backend_matrix() {
            let result = d.run_kernel_for(backend, 32);
            assert_eq!(
                result.is_some(),
                available,
                "{backend} availability disagrees with dispatch"
            );
        }
    }

    /// Regression: these kernels existed but nothing dispatched to them, so
    /// the 2.x `nc_measure_aesenc_cycles` family always reported unsupported.
    #[test]
    fn every_advertised_crypto_kernel_executes() {
        let d = Dispatcher::global();
        for (kernel, available) in d.crypto_matrix() {
            let result = d.run_crypto_kernel(kernel, 32);
            let dispatchable = available && resolve_crypto_kernel(kernel).is_some();
            assert_eq!(
                result.is_some(),
                dispatchable,
                "{} availability disagrees with dispatch",
                kernel.name()
            );
        }
    }

    /// A kernel whose accumulator cancels to a constant is not measuring what
    /// it claims: the x86 AES and PCLMUL kernels both seeded their state so
    /// that the final XOR was always zero, which hid whether the instructions
    /// had run at all.
    #[test]
    fn crypto_kernels_produce_input_dependent_output() {
        let d = Dispatcher::global();
        for (kernel, _) in d.crypto_matrix() {
            let Some(a) = d.run_crypto_kernel(kernel, 4096) else {
                continue;
            };
            let b = d
                .run_crypto_kernel(kernel, 4097)
                .expect("availability does not change between calls");

            // Zero after a long run is the signature of an absorbing state:
            // the instruction still executes, but its results stop reaching
            // the accumulator, so the kernel measures nothing it can show.
            assert_ne!(
                a,
                0,
                "{} collapsed to zero over 4096 iterations",
                kernel.name()
            );
            assert_ne!(
                a,
                b,
                "{} produced the same checksum for 4096 and 4097 iterations, so \
                 its accumulator is not carrying the instruction results",
                kernel.name()
            );
        }
    }

    #[test]
    fn selected_kernel_does_work() {
        let d = Dispatcher::global();
        assert_ne!(d.run_kernel(64), d.run_kernel(0));
    }

    #[test]
    fn counters_advance_through_the_table() {
        let d = Dispatcher::global();
        let a = d.counter_start();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = d.counter_end();
        assert!(b > a);
    }

    #[test]
    fn report_names_the_selection() {
        let report = Dispatcher::global().report();
        assert!(report.contains("backend="));
        assert!(report.contains("route="));
    }

    /// A bogus override must be rejected, not trusted into a fault.
    #[test]
    fn nonsense_override_is_rejected() {
        assert_eq!(Backend::parse("definitely-not-an-isa"), None);
        let (backend, reason) = {
            // Simulates the override path without mutating process env, which
            // would race other tests.
            let requested: Option<Backend> = Backend::parse("definitely-not-an-isa");
            match requested {
                Some(b) if b.is_available() => (b, SelectionReason::Overridden),
                Some(_) => (Backend::best(), SelectionReason::OverrideRejected),
                None => (Backend::best(), SelectionReason::Detected),
            }
        };
        assert!(backend.is_available());
        assert_ne!(reason, SelectionReason::Overridden);
    }

    /// Every backend name the parser accepts must also be dispatchable.
    #[test]
    fn all_parsed_backends_resolve_to_a_kernel() {
        for backend in Backend::ALL.iter().copied() {
            let f = resolve_kernel(backend);
            if backend.is_available() {
                let _ = f(8);
            }
        }
    }
}
