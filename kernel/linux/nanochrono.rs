// SPDX-License-Identifier: (GPL-2.0-only OR MIT)

//! Ring 0 hypervisor detection for NanoChronometer.
//!
//! OPTIONAL. The userspace library detects hypervisors on its own through
//! CPUID and platform signatures, and that works without privileges. This
//! module only sharpens the answer.
//!
//! # What ring 0 adds
//!
//! `VMCALL`, `VMMCALL` and `HVC #0` are only valid inside a guest and require
//! CPL 0 / EL1. Outside a guest they raise an undefined-instruction fault, so
//! userspace cannot even attempt them. An instruction that *returns* is
//! therefore proof of a hypervisor — and it holds even against one that clears
//! the CPUID hypervisor bit. That is this module's whole reason to exist.
//!
//! Ring 0 also measures a trap with preemption disabled, which removes the
//! scheduling noise that makes the userspace estimate fuzzy.
//!
//! # Fault recovery
//!
//! Each probe emits its own `__ex_table` entry, so a fault on bare metal
//! resumes at the fixup label instead of oopsing. There is no Rust
//! abstraction for kernel exception tables, so the entries are written by hand
//! from `asm!` in the exact layout `arch/x86/include/asm/asm.h` defines:
//! three 32-bit relative words — faulting insn, fixup target, handler type —
//! in a 12-byte-aligned `__ex_table` section, with `EX_TYPE_DEFAULT` (1)
//! meaning "resume at the fixup".
//!
//! # One probe per load: the anti-DoS rule
//!
//! Every probe that makes a guest exit to its hypervisor — the hypercalls,
//! the `CPUID` exit-cost loop, the `CNTPCT_EL0` read-cost measurement (every
//! read of which may trap) — runs **once**, when the module loads, and the
//! result is cached. Reading `/proc/nanochrono` never repeats them. On a
//! shared cloud host (Azure, GCP, AWS, Vultr…) a guest that hammers its
//! hypervisor with exits looks like an attack, and providers throttle or
//! ban for it; a `watch cat /proc/nanochrono` must not be able to do that.
//!
//! They can be run again deliberately, `echo reprobe > /proc/nanochrono`,
//! at most once per `hypercall_cooldown` seconds (default 10), enforced here
//! in the kernel where no user program can skip it. `cooldown=0` (or the
//! parameter) removes the limit — and with it, the protection: whoever does
//! that assumes the provider's reaction.
//!
//! # Perf counters
//!
//! The same module owns the system-wide perf counters (formerly a separate
//! `nanochrono_perf.ko`): one kernel perf event per CPU, summed and
//! corrected for multiplexing, published as `perf_*` keys. They are read on
//! every `/proc` read; they are the kernel's own PMU bookkeeping, not probes.
//! `echo cycles|instr|enable|disable > /proc/nanochrono` drives them.
//!
//! # Output
//!
//! One `key=value` per line at `/proc/nanochrono`, readable by any process
//! (mode 0644; writing needs root). Keys are stable; the userspace parser
//! ignores ones it does not know, so this can grow without breaking an older
//! library.
//!
//! The kernel's Rust crate exposes debugfs but not procfs, so the procfs ABI
//! is declared here directly. `/proc` is the right home for this: debugfs is
//! mode 0700, which would have limited the report to root, and the whole point
//! is for an unprivileged measurement process to read it.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::fmt::{self, Write as _};
use core::ptr::NonNull;

use kernel::prelude::*;
use kernel::{new_mutex, sync::Mutex};

/// A hand-written `#[repr(C)]` mirror of a kernel struct is only valid while
/// the kernel does not shuffle field order.
#[cfg(not(CONFIG_RANDSTRUCT_NONE))]
compile_error!(
    "this module mirrors `struct proc_ops` by hand, which is only sound with \
     CONFIG_RANDSTRUCT_NONE. Rebuild against a kernel without struct \
     randomisation, or use the CPUID-only userspace detection."
);

module! {
    type: Nanochrono,
    name: "nanochrono",
    authors: ["NanoChronometer contributors"],
    description: "NanoChronometer ring 0: hypervisor probe (once per load), counters, perf",
    license: "Dual MIT/GPL",
    params: {
        physical_counter: u32 {
            default: 0,
            description: "AArch64: time with CNTPCT_EL0 (physical) instead of CNTVCT_EL0 \
                (virtual). Stable on bare metal; inside a VM the hypervisor may trap every \
                read, and under nested virtualization it is slow and unstable. Ignored \
                on other architectures.",
        },
        hypercall_cooldown: u32 {
            default: 10,
            description: "Seconds between hypervisor re-probes (echo reprobe > \
                /proc/nanochrono). The probe runs once at load; this limits repeats. 0 \
                removes the limit: the user then assumes the cloud provider's reaction \
                (throttling or a ban) to repeated VM exits.",
        },
    },
}

/// Bumped when the report gains or changes fields.
///
/// Version 2 added the CPU's own vendor and lineage, the Centaur extended
/// leaf maximum, and the in-kernel crypto timings. Version 3 added the
/// `counter*` keys. Version 4 made the probes once-per-load (the
/// `hypercall_*` bookkeeping keys) and merged the perf counters in
/// (`perf_*` keys).
const FORMAT_VERSION: u32 = 4;

/// Rounds for the minimum-of-N trap measurement. Enough to find the floor,
/// short enough that preemption stays disabled for a negligible time.
const TRAP_ROUNDS: u32 = 128;

const PROC_NAME: &core::ffi::CStr = c"nanochrono";

/// Each cached section, and the assembled report, fit in this.
const REPORT_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct State {
    /// The probe report — hypervisor, counter, crypto — as of the last probe.
    probe: ReportBuffer,
    /// How many times the probes have run since load (1 after `init`).
    probes: u32,
    /// `ktime_get()` at the last probe.
    last_probe_ns: i64,
    /// Seconds between allowed re-probes; 0 = no limit.
    cooldown_s: u32,
    /// The assembled report handed to readers.
    out: ReportBuffer,
    perf: PerfState,
}

/// The kernel `Mutex` is built in place (pin-init): it holds a lock class
/// key and must not move, so the state lives pinned on the heap from `init`
/// to `Drop`.
#[pin_data]
struct Shared {
    #[pin]
    lock: Mutex<State>,
}

// Installed once in `init` (KBox::into_raw), freed once in `Drop`
// (KBox::from_raw) after `remove_proc_entry`. The proc callbacks only run
// between the two, because the entry is removed first in `Drop`.
static mut GLOBAL: *mut Shared = core::ptr::null_mut();

fn with_shared<R>(f: impl FnOnce(&Shared) -> R) -> R {
    // SAFETY: called only from proc callbacks and init/Drop, inside the
    // lifetime described above, where GLOBAL is non-null.
    let shared: &Shared = unsafe { &*GLOBAL };
    f(shared)
}

extern "C" {
    /// Monotonic nanoseconds (`ktime_t` is `s64`).
    fn ktime_get() -> i64;
    /// Highest possible CPU id + 1.
    static nr_cpu_ids: c_uint;
}

fn now_ns() -> i64 {
    // SAFETY: no preconditions.
    unsafe { ktime_get() }
}

/// Runs every exit-inducing probe and caches the result.
fn run_probes(st: &mut State) {
    st.probe = ReportBuffer::new();
    let f = &mut st.probe;
    // A truncated section is still worth keeping; the formatter only fails
    // when the buffer is full.
    let _ = write_arch_report(f);
    let _ = write_counter_report(f);
    let _ = write_crypto_report(f);
    st.probes = st.probes.saturating_add(1);
    st.last_probe_ns = now_ns();
}

struct Nanochrono;

impl kernel::Module for Nanochrono {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        counter_init();
        let pinned = KBox::pin_init(
            pin_init!(Shared {
                lock <- new_mutex!(State {
                    probe: ReportBuffer::new(),
                    probes: 0,
                    last_probe_ns: 0,
                    cooldown_s: *module_parameters::hypercall_cooldown.value(),
                    out: ReportBuffer::new(),
                    perf: PerfState::new(),
                }),
            }),
            GFP_KERNEL,
        )?;
        // SAFETY: the value never moves: it becomes a raw pointer here and a
        // `KBox` again only to be freed in place, which honours `Pin`.
        // Nothing can have run yet: the /proc entry does not exist.
        unsafe { GLOBAL = KBox::into_raw(Pin::into_inner_unchecked(pinned)) };

        with_shared(|s| {
            let mut st = s.lock.lock();
            // The one probe of this load.
            run_probes(&mut st);
            // Perf is optional: a VM or container without a PMU still gets
            // the hypervisor and counter report.
            // SAFETY: a plain read of a boot-time constant.
            let cpus = unsafe { core::ptr::read_volatile(&raw const nr_cpu_ids) };
            if st.perf.rebuild(cpus as i32).is_err() {
                pr_info!("nanochrono: no PMU events available; perf keys report 0\n");
            }
        });

        // SAFETY: `PROC_NAME` is a NUL-terminated literal and `PROC_OPS` is a
        // 'static struct whose function pointers outlive the entry.
        let entry = unsafe {
            proc_create(
                PROC_NAME.as_ptr().cast(),
                0o644,
                core::ptr::null_mut(),
                &raw const PROC_OPS,
            )
        };
        if entry.is_null() {
            with_shared(|s| s.lock.lock().perf.events.clear());
            // SAFETY: allocated above, freed once, nothing else holds it.
            unsafe { drop(KBox::from_raw(GLOBAL)) };
            unsafe { GLOBAL = core::ptr::null_mut() };
            pr_err!("nanochrono: could not create /proc/nanochrono\n");
            return Err(ENOMEM);
        }
        pr_info!("nanochrono: probed once; reporting at /proc/nanochrono\n");
        Ok(Nanochrono)
    }
}

impl Drop for Nanochrono {
    fn drop(&mut self) {
        // Strict order: remove /proc first (no new callers), then release the
        // perf events and the state.
        // SAFETY: the entry was created by `init` with this exact name and a
        // NULL parent, and is removed exactly once.
        unsafe { remove_proc_entry(PROC_NAME.as_ptr().cast(), core::ptr::null_mut()) };
        with_shared(|s| s.lock.lock().perf.events.clear());
        // SAFETY: as in `init`'s error path.
        unsafe { drop(KBox::from_raw(GLOBAL)) };
        unsafe { GLOBAL = core::ptr::null_mut() };
        pr_info!("nanochrono: unloaded\n");
    }
}

// ---------------------------------------------------------------------------
// procfs
// ---------------------------------------------------------------------------

/// `struct proc_ops` from `include/linux/proc_fs.h`.
///
/// Declared here because `proc_fs.h` is not in the kernel's Rust bindings.
/// Field order and the `CONFIG_COMPAT` conditional must match the kernel
/// exactly; the `CONFIG_RANDSTRUCT_NONE` guard above is what makes that sound.
#[repr(C)]
struct ProcOps {
    proc_flags: u32,
    proc_open: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    proc_read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut i64) -> isize>,
    proc_read_iter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize>,
    proc_write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize, *mut i64) -> isize>,
    proc_lseek: Option<unsafe extern "C" fn(*mut c_void, i64, c_int) -> i64>,
    proc_release: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    proc_poll: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32>,
    proc_ioctl: Option<unsafe extern "C" fn(*mut c_void, u32, usize) -> isize>,
    #[cfg(CONFIG_COMPAT)]
    proc_compat_ioctl: Option<unsafe extern "C" fn(*mut c_void, u32, usize) -> isize>,
    proc_mmap: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    proc_get_unmapped_area:
        Option<unsafe extern "C" fn(*mut c_void, usize, usize, usize, usize) -> usize>,
}

// SAFETY: every field is either a plain integer or a function pointer to a
// `'static` function; the struct is immutable after construction.
unsafe impl Sync for ProcOps {}

static PROC_OPS: ProcOps = ProcOps {
    proc_flags: 0,
    proc_open: None,
    proc_read: Some(proc_read),
    proc_read_iter: None,
    proc_write: Some(proc_write),
    proc_lseek: Some(default_llseek),
    proc_release: None,
    proc_poll: None,
    proc_ioctl: None,
    #[cfg(CONFIG_COMPAT)]
    proc_compat_ioctl: None,
    proc_mmap: None,
    proc_get_unmapped_area: None,
};

extern "C" {
    fn proc_create(
        name: *const c_char,
        mode: u16,
        parent: *mut c_void,
        proc_ops: *const ProcOps,
    ) -> *mut c_void;
    fn remove_proc_entry(name: *const c_char, parent: *mut c_void);
    /// Handles the offset and end-of-file bookkeeping a `read` needs, so this
    /// module does not reimplement it.
    fn simple_read_from_buffer(
        to: *mut c_void,
        count: usize,
        ppos: *mut i64,
        from: *const c_void,
        available: usize,
    ) -> isize;
    fn default_llseek(file: *mut c_void, offset: i64, whence: c_int) -> i64;
}

/// `cat /proc/nanochrono`: the cached probe, the bookkeeping, live perf.
///
/// Nothing here makes the guest exit: the probes are not re-run.
///
/// # Safety
/// Called by the kernel with a valid file, a userspace buffer of `count`
/// bytes, and a valid offset pointer.
unsafe extern "C" fn proc_read(
    _file: *mut c_void,
    buf: *mut c_char,
    count: usize,
    ppos: *mut i64,
) -> isize {
    with_shared(|s| {
        let mut st = s.lock.lock();
        let st = &mut *st;
        st.out = ReportBuffer::new();
        if write_report(st).is_err() {
            return -(kernel::error::code::EIO.to_errno() as isize);
        }
        let bytes = st.out.as_bytes();
        // SAFETY: the kernel guarantees `buf` is `count` writable userspace
        // bytes and `ppos` is valid; `bytes` lives under the lock.
        unsafe {
            simple_read_from_buffer(buf.cast(), count, ppos, bytes.as_ptr().cast(), bytes.len())
        }
    })
}

fn write_report(st: &mut State) -> fmt::Result {
    let f = &mut st.out;
    writeln!(f, "version={FORMAT_VERSION}")?;
    f.write_str(core::str::from_utf8(st.probe.as_bytes()).unwrap_or(""))?;

    // The once-per-load bookkeeping: how often the exit-inducing probes ran,
    // how long ago, and when a re-probe is next allowed.
    let age_ns = now_ns().saturating_sub(st.last_probe_ns).max(0);
    let cooldown_ns = st.cooldown_s as i64 * 1_000_000_000;
    writeln!(f, "hypercall_probes={}", st.probes)?;
    writeln!(f, "hypercall_age_ms={}", age_ns / 1_000_000)?;
    writeln!(f, "hypercall_cooldown_s={}", st.cooldown_s)?;
    writeln!(f, "hypercall_next_ms={}", (cooldown_ns - age_ns).max(0) / 1_000_000)?;
    if st.cooldown_s == 0 {
        writeln!(
            f,
            "hypercall_warning=re-probe limit disabled: repeated VM exits may get this guest throttled or banned by the provider"
        )?;
    }

    let (kind, enabled, npmu, raw, enabled_ns, running_ns, scaled) = st.perf.snapshot();
    writeln!(f, "perf_available={}", u32::from(npmu > 0))?;
    writeln!(f, "perf_event={}", kind.as_str())?;
    writeln!(f, "perf_enabled={}", u32::from(enabled))?;
    writeln!(f, "perf_npmu={npmu}")?;
    writeln!(f, "perf_raw={raw}")?;
    writeln!(f, "perf_enabled_ns={enabled_ns}")?;
    writeln!(f, "perf_running_ns={running_ns}")?;
    writeln!(f, "perf_scaled={scaled}")
}

/// `echo <command> > /proc/nanochrono` (root):
///
/// * `reprobe` — run the exit-inducing probes again, if the cooldown allows;
///   `EAGAIN` otherwise.
/// * `cooldown=<seconds>` — change the cooldown; `0` removes it (the writer
///   assumes the provider's reaction to repeated exits).
/// * `cycles`, `instr`, `enable`, `disable` — the perf counters.
///
/// # Safety
/// `buf` is `__user` memory of `count` bytes; it is only read through
/// `UserSlice`, which handles faults (`copy_from_user` is inline in C and not
/// an exported symbol a module can link).
unsafe extern "C" fn proc_write(
    _file: *mut c_void,
    buf: *const c_char,
    count: usize,
    _ppos: *mut i64,
) -> isize {
    if count == 0 || count > 32 {
        return -(kernel::error::code::EINVAL.to_errno() as isize);
    }
    let mut kbuf = [0u8; 32];
    let mut reader =
        kernel::uaccess::UserSlice::new(kernel::uaccess::UserPtr::from_ptr(buf as *mut c_void), count)
            .reader();
    if reader.read_slice(&mut kbuf[..count]).is_err() {
        return -(kernel::error::code::EFAULT.to_errno() as isize);
    }
    // Lower case, no whitespace.
    let mut cmd = [0u8; 32];
    let mut n = 0usize;
    for &b in kbuf[..count].iter() {
        if matches!(b, b'\n' | b'\r' | b' ' | b'\t' | 0) {
            continue;
        }
        cmd[n] = b.to_ascii_lowercase();
        n += 1;
    }
    let word = &cmd[..n];
    let rc: Result = with_shared(|s| {
        let mut st = s.lock.lock();
        if word == b"reprobe" {
            let cooldown_ns = st.cooldown_s as i64 * 1_000_000_000;
            if st.cooldown_s != 0 && now_ns().saturating_sub(st.last_probe_ns) < cooldown_ns {
                return Err(EAGAIN);
            }
            run_probes(&mut st);
            Ok(())
        } else if let Some(value) = word.strip_prefix(b"cooldown=") {
            let mut seconds: u32 = 0;
            if value.is_empty() || value.len() > 6 {
                return Err(EINVAL);
            }
            for &d in value {
                if !d.is_ascii_digit() {
                    return Err(EINVAL);
                }
                seconds = seconds * 10 + (d - b'0') as u32;
            }
            st.cooldown_s = seconds;
            if seconds == 0 {
                pr_warn!("nanochrono: re-probe cooldown disabled; the user assumes the provider's reaction to repeated VM exits\n");
            }
            Ok(())
        } else if word == b"cycles" || word == b"instr" || word == b"instructions" {
            st.perf.kind = if word == b"cycles" { EventKind::Cycles } else { EventKind::Instructions };
            // SAFETY: a plain read of a boot-time constant.
            let cpus = unsafe { core::ptr::read_volatile(&raw const nr_cpu_ids) };
            st.perf.rebuild(cpus as i32)
        } else if word == b"enable" || word == b"disable" {
            let on = word == b"enable";
            for ev in st.perf.events.iter() {
                // SAFETY: live events, owned under the lock.
                unsafe {
                    if on {
                        perf_event_enable(ev.raw.as_ptr())
                    } else {
                        perf_event_disable(ev.raw.as_ptr())
                    }
                };
            }
            st.perf.enabled = on;
            Ok(())
        } else {
            Err(EINVAL)
        }
    });
    match rc {
        Ok(()) => count as isize,
        Err(e) => -(e.to_errno() as isize),
    }
}

/// A fixed-capacity sink so formatting allocates nothing.
struct ReportBuffer {
    data: [u8; REPORT_CAPACITY],
    len: usize,
}

impl ReportBuffer {
    fn new() -> Self {
        ReportBuffer {
            data: [0; REPORT_CAPACITY],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl fmt::Write for ReportBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let end = self.len.checked_add(bytes.len()).ok_or(fmt::Error)?;
        if end > self.data.len() {
            return Err(fmt::Error);
        }
        self.data[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Perf counters (system-wide, one kernel event per CPU)
// ---------------------------------------------------------------------------
//
// `struct perf_event_attr` is UAPI: a frozen layout that RANDSTRUCT never
// touches, so a `#[repr(C)]` mirror is sound. `struct perf_event` is opaque:
// only ever held as a pointer and handed back.

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64, // bit 5 exclude_kernel, bit 6 exclude_hv
    wakeup: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
    aux_sample_size: u32,
    __reserved_3: u32,
    sig_data: u64,
    config3: u64,
}

impl PerfEventAttr {
    fn for_kind(kind: EventKind) -> Self {
        // SAFETY: all integers; zero is a valid value for each.
        let mut a: Self = unsafe { core::mem::zeroed() };
        a.size = core::mem::size_of::<Self>() as u32;
        a.type_ = PERF_TYPE_HARDWARE;
        a.config = match kind {
            EventKind::Cycles => PERF_COUNT_HW_CPU_CYCLES,
            EventKind::Instructions => PERF_COUNT_HW_INSTRUCTIONS,
        };
        // User space only, as in the library's perf.rs: the most useful for
        // benchmarks and the most permissive under perf_event_paranoid.
        a.flags = (1 << 5) | (1 << 6);
        a
    }
}

extern "C" {
    fn perf_event_create_kernel_counter(
        attr: *mut PerfEventAttr,
        cpu: c_int,
        task: *mut c_void,
        overflow_handler: *mut c_void,
        context: *mut c_void,
    ) -> *mut c_void;
    fn perf_event_release_kernel(event: *mut c_void);
    fn perf_event_read_value(event: *mut c_void, enabled: *mut u64, running: *mut u64) -> u64;
    fn perf_event_enable(event: *mut c_void);
    fn perf_event_disable(event: *mut c_void);
}

/// One live kernel event. The pointer is never dereferenced from Rust.
struct KernelEvent {
    raw: NonNull<c_void>,
}

// SAFETY: create/release are paired in Drop; the event is only touched under
// the state's Mutex, and the perf_* functions are thread-safe.
unsafe impl Send for KernelEvent {}

impl Drop for KernelEvent {
    fn drop(&mut self) {
        // SAFETY: `raw` came from create_kernel_counter; released once.
        unsafe { perf_event_release_kernel(self.raw.as_ptr()) };
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum EventKind {
    Cycles,
    Instructions,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            EventKind::Cycles => "cycles",
            EventKind::Instructions => "instructions",
        }
    }
}

struct PerfState {
    kind: EventKind,
    enabled: bool,
    events: KVec<KernelEvent>,
}

impl PerfState {
    fn new() -> Self {
        PerfState {
            kind: EventKind::Cycles,
            enabled: true,
            events: KVec::new(),
        }
    }

    /// One system-wide counter per possible CPU; CPUs that refuse (offline,
    /// no PMU) are skipped. `ENODEV` when none accepted.
    fn rebuild(&mut self, ncpus: i32) -> Result {
        let mut attr = PerfEventAttr::for_kind(self.kind);
        let mut fresh = KVec::new();
        for cpu in 0..ncpus {
            // SAFETY: `attr` lives across the call; task NULL = system-wide on
            // that CPU; no overflow handler.
            let p = unsafe {
                perf_event_create_kernel_counter(
                    &mut attr,
                    cpu as c_int,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            if p.is_null() || (p as usize) >= ERR_PTR_FLOOR {
                continue;
            }
            // SAFETY: null and ERR_PTR filtered just above.
            let ev = KernelEvent { raw: unsafe { NonNull::new_unchecked(p) } };
            if self.enabled {
                // SAFETY: a live event this function owns.
                unsafe { perf_event_enable(ev.raw.as_ptr()) };
            }
            // On allocation failure `ev` is dropped (releasing its counter)
            // along with those already in `fresh`.
            fresh.push(ev, GFP_KERNEL)?;
        }
        self.events.clear();
        if fresh.is_empty() {
            return Err(ENODEV);
        }
        self.events = fresh;
        Ok(())
    }

    fn snapshot(&self) -> (EventKind, bool, usize, u64, u64, u64, u64) {
        let (mut raw, mut enabled_ns, mut running_ns) = (0u64, 0u64, 0u64);
        for ev in self.events.iter() {
            let (mut e, mut r) = (0u64, 0u64);
            // SAFETY: a live event under the lock; valid out-parameters.
            let v = unsafe { perf_event_read_value(ev.raw.as_ptr(), &mut e, &mut r) };
            raw = raw.saturating_add(v);
            enabled_ns = enabled_ns.saturating_add(e);
            running_ns = running_ns.saturating_add(r);
        }
        // The same correction as `scale()` in the library's perf.rs.
        let scaled = if running_ns == 0 {
            0
        } else if running_ns >= enabled_ns {
            raw
        } else {
            mul_div(raw, enabled_ns, running_ns)
        };
        (self.kind, self.enabled, self.events.len(), raw, enabled_ns, running_ns, scaled)
    }
}

/// `a * b / c` without overflow and without a 128-bit division.
///
/// The kernel links no `__udivti3` (what a `u128 / u128` would need), and
/// `mul_u64_u64_div_u64` is inline on x86 rather than exported. The product
/// fits a `u128` — one 64×64 multiply — and the quotient comes from a
/// bit-by-bit restoring division: 64 steps, only on a `/proc` read.
/// Saturates at `u64::MAX`.
fn mul_div(a: u64, b: u64, c: u64) -> u64 {
    if c == 0 {
        return 0;
    }
    let product = a as u128 * b as u128;
    let mut rem = (product >> 64) as u64;
    let mut low = product as u64;
    if rem >= c {
        return u64::MAX;
    }
    let mut quotient = 0u64;
    for _ in 0..64 {
        let carry = rem >> 63;
        rem = (rem << 1) | (low >> 63);
        low <<= 1;
        quotient <<= 1;
        if carry != 0 || rem >= c {
            rem = rem.wrapping_sub(c);
            quotient |= 1;
        }
    }
    quotient
}

// ---------------------------------------------------------------------------
// Ring 0 crypto, the optional half of the crypto benchmark
// ---------------------------------------------------------------------------

// The userspace side of this measurement reaches the kernel's crypto API
// through `AF_ALG`: a socket, a `sendmsg` and a `read` per operation. That
// number is the honest cost of *using* kernel crypto from a program, and it
// is the one that always gets measured, because it needs no module.
//
// It cannot separate the primitive from the transport. This can: the same
// algorithms called here run with no socket, no syscall and no copy across
// the privilege boundary, so the difference between the two numbers is what
// `AF_ALG` costs. That is the whole reason this half exists, and it is why
// it is optional — it answers a sharper question, at the price of building
// and loading a module.
//
// Hashes only. A `shash` is a single exported call over a flat buffer;
// a symmetric cipher needs a request object, scatterlists and a completion,
// and a benchmark that got any of those wrong would report a number for
// something other than what it named. What is here is certainly right.

/// `struct crypto_shash` is opaque to this module: it is only ever held as a
/// pointer and handed back to the kernel.
#[repr(C)]
struct CryptoShash {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    /// `crypto_alloc_shash(const char *alg_name, u32 type, u32 mask)`.
    ///
    /// Returns an `ERR_PTR` rather than null on failure, which is why the
    /// caller checks the pointer's magnitude rather than testing for null.
    fn crypto_alloc_shash(alg_name: *const c_char, ty: u32, mask: u32) -> *mut CryptoShash;
    /// `crypto_shash_tfm_digest(tfm, data, len, out)` — hash a flat buffer in
    /// one call, with the descriptor allocated by the kernel. Exported since
    /// 5.8 precisely so a caller need not build a `SHASH_DESC_ON_STACK`.
    fn crypto_shash_tfm_digest(
        tfm: *mut CryptoShash,
        data: *const u8,
        len: c_uint,
        out: *mut u8,
    ) -> c_int;
    /// `crypto_destroy_tfm(void *mem, struct crypto_tfm *tfm)`. The shash
    /// free is a macro over this in C; from here it is the exported symbol.
    fn crypto_destroy_tfm(mem: *mut c_void, tfm: *mut CryptoShash);
}

/// The last address that can be an `ERR_PTR`.
///
/// The kernel returns errors as pointers in the top page. Anything at or
/// above this is a negative errno wearing a pointer's clothes, and
/// dereferencing it is how a module oopses.
const ERR_PTR_FLOOR: usize = usize::MAX - 4095;

/// Algorithms measured here, by the kernel's own names.
///
/// The same five the userspace side asks for through `AF_ALG`, so every row
/// of the ring-0 mode has a ring-3 row measuring the same algorithm over the
/// same buffer, and the two can simply be subtracted. An algorithm this
/// kernel was not built with is skipped rather than reported as zero.
const CRYPTO_ALGORITHMS: &[&str] = &["sha1", "sha256", "sha512", "sha3-256", "crc32c"];

/// Bytes hashed per operation.
///
/// The same size the userspace benchmark uses, so the two numbers are
/// comparable. A different buffer would make the comparison meaningless
/// while still looking like one.
const CRYPTO_PAYLOAD: usize = 16 * 1024;

/// Operations per algorithm. Small: this runs inside a `/proc` read, with
/// preemption enabled and no business holding a CPU for long.
const CRYPTO_ROUNDS: usize = 64;

/// The largest digest any algorithm here produces.
const MAX_DIGEST: usize = 64;

/// Times each algorithm and writes one line per success.
///
/// Emitted as repeated `crypto=` keys rather than one key per algorithm,
/// because an algorithm's kernel name can contain characters — `cbc(aes)` —
/// that have no place on the left of an `=`.
///
/// A failure is silent by design: an algorithm this kernel was not built with
/// is an ordinary kernel, and a missing line says that more clearly than an
/// error line would.
fn write_crypto_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "crypto_payload_bytes={CRYPTO_PAYLOAD}")?;
    writeln!(f, "crypto_rounds={CRYPTO_ROUNDS}")?;

    for name in CRYPTO_ALGORITHMS {
        if let Some(cycles) = time_shash(name) {
            writeln!(f, "crypto={name},{cycles}")?;
        }
    }
    Ok(())
}

/// Best-of-N cycles for one full digest of [`CRYPTO_PAYLOAD`] bytes.
///
/// Best rather than mean, for the same reason every other measurement in this
/// project takes a minimum: the fastest observed run is the one least
/// disturbed by everything else the machine was doing, and in a kernel with
/// preemption on that is the only figure with a defensible meaning.
///
/// `None` when the algorithm is not available, which is not an error.
fn time_shash(name: &str) -> Option<u64> {
    // The C API takes a NUL-terminated name and these are compile-time
    // constants, so the terminator is added here rather than requiring every
    // entry in the table to carry one.
    let mut zname = [0u8; 32];
    let bytes = name.as_bytes();
    if bytes.len() >= zname.len() {
        return None;
    }
    zname[..bytes.len()].copy_from_slice(bytes);

    // SAFETY: `zname` is NUL-terminated and outlives the call; type and mask
    // of zero ask for any implementation, which is what the kernel's own
    // callers pass.
    let tfm = unsafe { crypto_alloc_shash(zname.as_ptr().cast(), 0, 0) };
    if tfm.is_null() || (tfm as usize) >= ERR_PTR_FLOOR {
        return None;
    }

    let mut best = u64::MAX;
    let mut digest = [0u8; MAX_DIGEST];
    // A static rather than a stack buffer: sixteen kilobytes is far past what
    // a kernel stack will hold, and this runs single-threaded under the
    // procfs read lock.
    let payload = payload_buffer();

    for _ in 0..CRYPTO_ROUNDS {
        let start = counter_start();
        // SAFETY: `tfm` was allocated above and not freed; the payload and
        // digest pointers are valid for the lengths given, and the digest
        // buffer is the largest any listed algorithm produces.
        let rc = unsafe {
            crypto_shash_tfm_digest(
                tfm,
                payload.as_ptr(),
                CRYPTO_PAYLOAD as c_uint,
                digest.as_mut_ptr(),
            )
        };
        let end = counter_end();
        if rc != 0 {
            best = u64::MAX;
            break;
        }
        let elapsed = end.wrapping_sub(start);
        if elapsed != 0 && elapsed < best {
            best = elapsed;
        }
    }

    // SAFETY: `tfm` came from `crypto_alloc_shash` and is freed exactly once.
    unsafe { crypto_destroy_tfm(core::ptr::null_mut(), tfm) };

    (best != u64::MAX).then_some(best)
}

/// The buffer every digest runs over.
///
/// Zero-filled and never written: its contents do not change what a hash
/// costs, and a constant makes runs comparable across boots.
fn payload_buffer() -> &'static [u8; CRYPTO_PAYLOAD] {
    static PAYLOAD: [u8; CRYPTO_PAYLOAD] = [0u8; CRYPTO_PAYLOAD];
    &PAYLOAD
}

// ---------------------------------------------------------------------------
// x86
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn write_arch_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "arch=x86")?;

    let leaf1 = cpuid(1, 0);
    writeln!(
        f,
        "cpuid_hypervisor_bit={}",
        u32::from(leaf1[2] & (1 << 31) != 0)
    )?;
    // CPUID.1:ECX[5] is VMX, CPUID.80000001H:ECX[2] is SVM. Both say the CPU
    // *could* host a guest, which distinguishes "not virtualized" from "not
    // virtualized but nested virtualization is available".
    writeln!(f, "vmx_available={}", u32::from(leaf1[2] & (1 << 5) != 0))?;
    let ext1 = cpuid(0x8000_0001, 0);
    writeln!(f, "svm_available={}", u32::from(ext1[2] & (1 << 2) != 0))?;

    // Who made the part. Read before anything else because it decides how the
    // rest is interpreted — and because a Zhaoxin is close enough to an Intel
    // that code assuming "not AMD means Intel" runs on one and misreads it.
    //
    // The register order is EBX, EDX, ECX. That is not a transcription slip:
    // it is the order `CPUID.0H` defines, and reading them as EBX, ECX, EDX
    // spells `GenuntelineI`.
    let identity = cpuid(0, 0);
    let mut cpu_vendor = [0u8; 12];
    cpu_vendor[0..4].copy_from_slice(&identity[1].to_le_bytes());
    cpu_vendor[4..8].copy_from_slice(&identity[3].to_le_bytes());
    cpu_vendor[8..12].copy_from_slice(&identity[2].to_le_bytes());
    write!(f, "cpu_vendor=")?;
    for &byte in cpu_vendor.iter() {
        if (0x20..0x7f).contains(&byte) {
            write!(f, "{}", byte as char)?;
        }
    }
    writeln!(f)?;
    writeln!(f, "cpu_family={}", cpu_family_name(&cpu_vendor))?;

    // The Centaur extended range. Only the VIA/Centaur lineage and its
    // Zhaoxin successor implement it — it is to them what `0x8000_0000` is to
    // AMD — so a maximum inside the range it describes is positive
    // identification even where the vendor string has been overridden, which
    // firmware and hypervisors both do.
    let centaur_max = cpuid(0xC000_0000, 0)[0];
    if (0xC000_0000..=0xC000_FFFF).contains(&centaur_max) {
        writeln!(f, "centaur_max_leaf={centaur_max:#x}")?;
    }

    let vendor = cpuid(0x4000_0000, 0);
    let mut signature = [0u8; 12];
    signature[0..4].copy_from_slice(&vendor[1].to_le_bytes());
    signature[4..8].copy_from_slice(&vendor[2].to_le_bytes());
    signature[8..12].copy_from_slice(&vendor[3].to_le_bytes());
    write!(f, "cpuid_vendor=")?;
    for &byte in signature.iter().take_while(|&&b| b != 0) {
        // Anything unprintable means the leaf is not implemented and the
        // registers hold stale values, so it is dropped rather than reported.
        if (0x20..0x7f).contains(&byte) {
            write!(f, "{}", byte as char)?;
        }
    }
    writeln!(f)?;

    // The hypercall HAL: one instruction, the one this CPU's vendor
    // defines, chosen now — at every load, because the same installed system
    // (an OS on an external SSD) boots on Intel one day and AMD the next.
    // The other vendor's instruction is never executed; an unknown vendor
    // gets no hypercall. See `hypercall_insn`.
    match hypercall_insn(&cpu_vendor) {
        Some(HypercallInsn::Vmcall) => {
            writeln!(f, "hypercall_insn=vmcall")?;
            // SAFETY: the probe recovers from its #UD through the exception
            // table entry it emits, so executing it outside a guest is safe.
            let r = unsafe { probe_vmcall() };
            writeln!(f, "vmcall_ok={}", u32::from(r.is_some()))?;
            if let Some(result) = r {
                writeln!(f, "hypercall_result={result}")?;
            }
        }
        Some(HypercallInsn::Vmmcall) => {
            writeln!(f, "hypercall_insn=vmmcall")?;
            // SAFETY: as above.
            let r = unsafe { probe_vmmcall() };
            writeln!(f, "vmmcall_ok={}", u32::from(r.is_some()))?;
            if let Some(result) = r {
                writeln!(f, "hypercall_result={result}")?;
            }
        }
        None => writeln!(f, "hypercall_insn=none")?,
    }

    let (trap, baseline) = measure_exit_cost();
    writeln!(f, "exit_cycles={trap}")?;
    writeln!(f, "baseline_cycles={baseline}")?;
    Ok(())
}

/// The x86-64 hypercall instruction of a vendor.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
enum HypercallInsn {
    Vmcall,
    Vmmcall,
}

/// The hypercall HAL: Intel, Zhaoxin and Centaur (VMX) use `VMCALL`; AMD and
/// Hygon (SVM) use `VMMCALL`; anything else, none. The same table as
/// `nanochrono_core::hypercall_hal`, which this module cannot link.
#[cfg(target_arch = "x86_64")]
fn hypercall_insn(signature: &[u8; 12]) -> Option<HypercallInsn> {
    match signature {
        b"GenuineIntel" | b"  Shanghai  " | b"CentaurHauls" => Some(HypercallInsn::Vmcall),
        b"AuthenticAMD" | b"HygonGenuine" => Some(HypercallInsn::Vmmcall),
        _ => None,
    }
}

/// Names the lineage a vendor signature belongs to.
///
/// Zhaoxin is the reason this exists. Its parts are x86-64 descended from
/// VIA's Centaur line: they carry Intel-style architectural performance
/// counters, Intel-style machine-check banks, and VMX — so KVM drives them
/// through the same `VMCALL` path an Intel part uses, and the hypercall probe
/// below needs no special case. What they do *not* share is Intel's
/// trustworthy `CPUID.15H`/`16H` counter-rate leaves, which Linux reads on
/// Intel alone. Naming the part is what lets a reader of this report know
/// which of those two facts applies.
fn cpu_family_name(signature: &[u8; 12]) -> &'static str {
    match signature {
        b"GenuineIntel" => "intel",
        b"AuthenticAMD" => "amd",
        b"HygonGenuine" => "hygon",
        // Spaces included: the string is exactly twelve bytes and Zhaoxin
        // pads it on both sides.
        b"  Shanghai  " => "zhaoxin",
        b"CentaurHauls" => "centaur",
        _ => "unknown",
    }
}

/// `CPUID` with an explicit subleaf.
///
/// LLVM reserves `rbx`, so the value is shuttled through a scratch register.
#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32, subleaf: u32) -> [u32; 4] {
    let (eax, ebx, ecx, edx);
    // SAFETY: CPUID has no operands beyond its registers and no side effects.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    [eax, ebx, ecx, edx]
}

/// A hypercall function number no hypervisor implements.
///
/// KVM answers an unknown number with `-KVM_ENOSYS` (-1000), which is exactly
/// what is wanted: a defined "I am here, and I do not implement that" with no
/// side effect.
#[cfg(target_arch = "x86_64")]
const PROBE_HYPERCALL_NR: u64 = 0xffff;

/// Emits a hypercall probe with its own exception-table entry.
///
/// The generated sequence sets the success flag *after* the instruction, so a
/// fault — which resumes at the fixup label, skipping that store — leaves the
/// flag clear.
#[cfg(target_arch = "x86_64")]
macro_rules! hypercall_probe {
    ($name:ident, $insn:literal) => {
        /// # Safety
        /// Safe to call anywhere: the exception-table entry below catches the
        /// `#UD` this raises outside a guest.
        unsafe fn $name() -> Option<i64> {
            let ok: u64;
            let result: u64;
            // SAFETY: the __ex_table entry makes the fault recoverable, and
            // the instruction has no effect on a hypervisor that rejects an
            // unknown function number.
            unsafe {
                core::arch::asm!(
                    "xor {ok}, {ok}",
                    concat!("2: ", $insn),
                    "mov {ok}, 1",
                    "3:",
                    // arch/x86/include/asm/asm.h: three 32-bit relative words
                    // in a 12-byte-entry section. EX_TYPE_DEFAULT (1) resumes
                    // execution at the fixup label.
                    ".pushsection __ex_table, \"aM\", @progbits, 12",
                    ".balign 4",
                    ".long (2b) - .",
                    ".long (3b) - .",
                    ".long 1",
                    ".popsection",
                    ok = out(reg) ok,
                    inout("rax") PROBE_HYPERCALL_NR => result,
                    out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                    options(nostack),
                );
            }
            (ok != 0).then_some(result as i64)
        }
    };
}

#[cfg(target_arch = "x86_64")]
hypercall_probe!(probe_vmcall, "vmcall");
#[cfg(target_arch = "x86_64")]
hypercall_probe!(probe_vmmcall, "vmmcall");

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn counter_start() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: RDTSC has no operands beyond its outputs.
    unsafe {
        core::arch::asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn counter_end() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: RDTSCP has no operands beyond its outputs.
    unsafe {
        core::arch::asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _,
                         options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// x86 has one timestamp counter; nothing to choose.
#[cfg(target_arch = "x86_64")]
fn counter_init() {}

#[cfg(target_arch = "x86_64")]
fn write_counter_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "counter=tsc")?;
    // The parameter is accepted everywhere so one command line works on any
    // machine; on x86 there is no physical/virtual pair for it to pick from.
    if *module_parameters::physical_counter.value() != 0 {
        writeln!(f, "counter_note=physical_counter ignored: x86 has only the TSC")?;
    }
    Ok(())
}

/// Times `CPUID` against a bare counter pair.
///
/// `CPUID` is serializing and, on essentially every hypervisor, exits to the
/// VMM unconditionally. The gap is the exit cost, which is the number a caller
/// actually wants: how much latency virtualization adds per trap on this host.
///
/// The C version disabled preemption around this loop. The Rust kernel crate
/// exports no preemption abstraction, so instead the minimum over
/// [`TRAP_ROUNDS`] samples is taken — which discards exactly the samples a
/// scheduling decision would have inflated. The floor is the same; only the
/// number of rounds needed to find it goes up.
#[cfg(target_arch = "x86_64")]
fn measure_exit_cost() -> (u64, u64) {
    let mut best_trap = u64::MAX;
    let mut best_base = u64::MAX;

    for _ in 0..TRAP_ROUNDS {
        let a = counter_start();
        let b = counter_end();
        let d = b.wrapping_sub(a);
        if d != 0 && d < best_base {
            best_base = d;
        }

        let a = counter_start();
        core::hint::black_box(cpuid(0, 0));
        let b = counter_end();
        let d = b.wrapping_sub(a);
        if d != 0 && d < best_trap {
            best_trap = d;
        }
    }

    (
        if best_trap == u64::MAX { 0 } else { best_trap },
        if best_base == u64::MAX { 0 } else { best_base },
    )
}

// ---------------------------------------------------------------------------
// AArch64
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
fn write_arch_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "arch=arm64")?;

    let current_el: u64;
    // SAFETY: CurrentEL is readable at every exception level.
    unsafe {
        core::arch::asm!("mrs {v}, CurrentEL", v = out(reg) current_el,
                         options(nomem, nostack, preserves_flags));
    }
    let el = (current_el >> 2) & 3;
    writeln!(f, "current_el={el}")?;

    // When `HVC` is safe to execute, and why the old exception-table guard
    // was not the answer:
    //
    // * At EL2 — a VHE host kernel — `HVC` traps to this kernel's own vectors
    //   as an exception class nothing handles, and the kernel panics.
    // * At EL1 with no EL2, `HVC` is undefined, and arm64 does not consult
    //   `__ex_table` for an undefined instruction in kernel mode: it goes
    //   straight to `die()`. The entry the probe used to carry never helped.
    // * At EL1 on a host whose EL2 is the kernel's own hyp stub or KVM's nVHE
    //   hyp, `HVC` is answered — by this very kernel, which says nothing
    //   about a hypervisor.
    //
    // The kernel already knows the one case that matters: it probed PSCI at
    // boot and records the SMCCC conduit. HVC as the conduit means something
    // at EL2 answers SMCCC calls — which is a hypervisor. So the probe runs
    // only at EL1 with an HVC conduit; otherwise it reports why not.
    // SAFETY: an exported query with no preconditions.
    let conduit = unsafe { arm_smccc_1_1_get_conduit() };
    writeln!(
        f,
        "smccc_conduit={}",
        match conduit {
            SMCCC_CONDUIT_SMC => "smc",
            SMCCC_CONDUIT_HVC => "hvc",
            _ => "none",
        }
    )?;
    if el != 1 || conduit != SMCCC_CONDUIT_HVC {
        writeln!(f, "hvc_ok=0")?;
        writeln!(
            f,
            "hvc_skipped={}",
            if el == 2 { "running at EL2: this kernel is the hypervisor level" } else { "SMCCC conduit is not HVC" }
        )?;
        return Ok(());
    }

    // SAFETY: at EL1 with the SMCCC conduit HVC, so EL2 answers SMCCC calls.
    // SMCCC_VERSION (0x80000000) is a read-only query.
    let version = unsafe { smccc_hvc(SMCCC_VERSION_FUNC_ID) };
    writeln!(f, "hvc_ok=1")?;
    writeln!(f, "hypercall_result={}", version[0] as i64)?;
    if version[0] as i64 != SMCCC_RET_NOT_SUPPORTED {
        writeln!(f, "smccc_version={:#x}", version[0])?;
    }

    // The vendor-specific hypervisor UID. Only a hypervisor implements this
    // range at all, so an answer identifies one — and the four words are
    // reported raw rather than matched against a table here, so that the
    // byte order is interpreted once, in userspace, where it can be tested.
    // SAFETY: as above; a read-only query.
    let uid = unsafe { smccc_hvc(SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID) };
    if uid[0] as i64 != SMCCC_RET_NOT_SUPPORTED {
        writeln!(
            f,
            "hvc_vendor_uid={:08x} {:08x} {:08x} {:08x}",
            uid[0] as u32, uid[1] as u32, uid[2] as u32, uid[3] as u32
        )?;
    }
    Ok(())
}

/// `enum arm_smccc_conduit` from `include/linux/arm-smccc.h`.
#[cfg(target_arch = "aarch64")]
const SMCCC_CONDUIT_SMC: u32 = 1;
#[cfg(target_arch = "aarch64")]
const SMCCC_CONDUIT_HVC: u32 = 2;

#[cfg(target_arch = "aarch64")]
extern "C" {
    /// `arm_smccc_1_1_get_conduit()`: how this kernel reaches SMCCC firmware
    /// or a hypervisor, as decided when PSCI was probed at boot.
    fn arm_smccc_1_1_get_conduit() -> u32;
}

/// `ARM_SMCCC_VERSION_FUNC_ID`: fast call, SMC32, owner 0, function 0.
#[cfg(target_arch = "aarch64")]
const SMCCC_VERSION_FUNC_ID: u64 = 0x8000_0000;

/// `ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID`: fast call, SMC32, owner 6
/// (vendor hypervisor), function 0xff01 (query call UID).
#[cfg(target_arch = "aarch64")]
const SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID: u64 = 0x8600_ff01;

/// `SMCCC_RET_NOT_SUPPORTED`, per `include/linux/arm-smccc.h`.
#[cfg(target_arch = "aarch64")]
const SMCCC_RET_NOT_SUPPORTED: i64 = -1;

/// `HVC #0` carrying an SMCCC function ID; returns x0-x3.
///
/// SMCCC 1.1 preserves x4-x17, but a 1.0 implementation may clobber them,
/// so they are declared clobbered.
///
/// # Safety
/// EL1, with the SMCCC conduit HVC — see `write_arch_report`.
#[cfg(target_arch = "aarch64")]
unsafe fn smccc_hvc(function_id: u64) -> [u64; 4] {
    let mut regs = [0u64; 4];
    // SAFETY: forwarded from this function's contract.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") function_id => regs[0],
            inout("x1") 0u64 => regs[1],
            inout("x2") 0u64 => regs[2],
            inout("x3") 0u64 => regs[3],
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            options(nostack),
        );
    }
    regs
}

// -- the counter -------------------------------------------------------------
//
// CNTVCT_EL0 is CNTPCT_EL0 minus CNTVOFF_EL2: the timeline a hypervisor gives
// a guest. It is the default because it is what every kernel and the vDSO
// use, and a hypervisor never has to trap it.
//
// CNTPCT_EL0 is what the hardware ticks. On bare metal the two cost the
// same. In a guest, the hypervisor decides with CNTHCTL_EL2.EL1PCTEN whether
// EL1 may read it directly; KVM traps it whenever it has to apply an offset
// the silicon cannot (no FEAT_ECV), and then every read is an exit — hundreds
// of nanoseconds, or far worse and jittery under nested virtualization, where
// the exit is forwarded through a second hypervisor. The report measures it
// rather than guessing: `counter_physical_read_ns` next to the virtual one
// says directly whether reads are being trapped on this machine.

#[cfg(target_arch = "aarch64")]
static USE_PHYSICAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(target_arch = "aarch64")]
fn counter_init() {
    let physical = *module_parameters::physical_counter.value() != 0;
    USE_PHYSICAL.store(physical, core::sync::atomic::Ordering::Relaxed);
    if physical {
        pr_info!("nanochrono: timing with CNTPCT_EL0 (physical_counter=1)\n");
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn cntvct() -> u64 {
    let v: u64;
    // SAFETY: CNTVCT_EL0 is readable at EL1 and above.
    unsafe {
        core::arch::asm!("isb", "mrs {v}, cntvct_el0", v = out(reg) v,
                         options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn cntpct() -> u64 {
    let v: u64;
    // SAFETY: CNTPCT_EL0 is readable at EL1 and above; a hypervisor may trap
    // the read, which costs time but never faults.
    unsafe {
        core::arch::asm!("isb", "mrs {v}, cntpct_el0", v = out(reg) v,
                         options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "aarch64")]
fn cntfrq() -> u64 {
    let v: u64;
    // SAFETY: CNTFRQ_EL0 is readable at every exception level.
    unsafe {
        core::arch::asm!("mrs {v}, cntfrq_el0", v = out(reg) v,
                         options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn counter_start() -> u64 {
    if USE_PHYSICAL.load(core::sync::atomic::Ordering::Relaxed) {
        cntpct()
    } else {
        cntvct()
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn counter_end() -> u64 {
    counter_start()
}

/// Nanoseconds for one read of `read`, as the best of several batches timed
/// with the virtual counter (which a hypervisor never traps).
#[cfg(target_arch = "aarch64")]
fn read_cost_ns(read: fn() -> u64, hz: u64) -> u64 {
    const BATCH: u64 = 64;
    let mut best = u64::MAX;
    for _ in 0..16 {
        let a = cntvct();
        for _ in 0..BATCH {
            core::hint::black_box(read());
        }
        let b = cntvct();
        best = best.min(b.wrapping_sub(a));
    }
    if hz == 0 {
        return 0;
    }
    best.saturating_mul(1_000_000_000) / hz / BATCH
}

#[cfg(target_arch = "aarch64")]
fn write_counter_report(f: &mut ReportBuffer) -> fmt::Result {
    let physical = USE_PHYSICAL.load(core::sync::atomic::Ordering::Relaxed);
    writeln!(f, "counter={}", if physical { "cntpct_el0" } else { "cntvct_el0" })?;
    let hz = cntfrq();
    writeln!(f, "counter_hz={hz}")?;
    let virtual_ns = read_cost_ns(cntvct, hz);
    let physical_ns = read_cost_ns(cntpct, hz);
    writeln!(f, "counter_virtual_read_ns={virtual_ns}")?;
    writeln!(f, "counter_physical_read_ns={physical_ns}")?;
    // A trapped read is an exit to EL2: an order of magnitude or more over
    // the untrapped one. The threshold leaves room for ISB cost on slow
    // cores without mistaking a trap for one.
    let trapped = physical_ns > 100 && physical_ns > virtual_ns.saturating_mul(10);
    writeln!(f, "counter_physical_trapped={}", u32::from(trapped))?;
    if physical && trapped {
        writeln!(
            f,
            "counter_warning=CNTPCT_EL0 is being trapped by a hypervisor; timings include the exit"
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RISC-V
// ---------------------------------------------------------------------------

#[cfg(target_arch = "riscv64")]
fn write_arch_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "arch=riscv64")
}

// -- the counter -------------------------------------------------------------
//
// RDCYCLE counts this hart's clock cycles: the RISC-V counterpart of the TSC
// as a *cycle* count, where `time` is a fixed-rate platform timer. Whether
// S-mode may read it is firmware's decision (`mcounteren.CY`, set by OpenSBI
// on most boards); inside a KVM guest it is the host's (`hcounteren.CY`),
// and where it is clear the read raises an illegal-instruction trap — or a
// virtual-instruction trap that KVM reflects as one. Nothing is assumed:
// the first read carries an exception-table entry, so a trap resumes at the
// fixup and the module falls back to `rdtime`, which the kernel itself
// depends on and every configuration allows.
//
// Under a hypervisor `cycle` is not virtualized the way `time` is (there is
// no htimedelta for it): a guest reads the physical hart's count, which is
// right for a short interval and meaningless across a vCPU migration.

/// 0 = not probed, 1 = RDCYCLE works, 2 = RDTIME only.
#[cfg(target_arch = "riscv64")]
static COUNTER_KIND: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Reads `cycle` once, recovering if the read traps.
///
/// The exception-table entry follows `arch/riscv/include/asm/asm-extable.h`:
/// two 32-bit relative words (instruction, fixup) and a 16-bit type and data,
/// 4-byte aligned; type 1 is `EX_TYPE_FIXUP`, "resume at the fixup". RISC-V
/// consults the table for an illegal instruction in kernel mode
/// (`do_trap_insn_illegal` → `fixup_exception`), so this is recoverable.
///
/// # Safety
/// Kernel mode.
#[cfg(target_arch = "riscv64")]
unsafe fn probe_rdcycle() -> Option<u64> {
    let ok: u64;
    let value: u64;
    // SAFETY: the __ex_table entry makes the trap recoverable.
    unsafe {
        core::arch::asm!(
            "li {ok}, 0",
            "li {v}, 0",
            ".option push",
            ".option norvc",
            "2: rdcycle {v}",
            ".option pop",
            "li {ok}, 1",
            "3:",
            ".pushsection __ex_table, \"a\"",
            ".balign 4",
            ".long (2b - .)",
            ".long (3b - .)",
            ".short 1",
            ".short 0",
            ".popsection",
            ok = out(reg) ok,
            v = out(reg) value,
            options(nostack),
        );
    }
    (ok != 0).then_some(value)
}

#[cfg(target_arch = "riscv64")]
fn counter_init() {
    // SAFETY: kernel mode; the probe recovers from its own trap.
    let kind = if unsafe { probe_rdcycle() }.is_some() { 1 } else { 2 };
    COUNTER_KIND.store(kind, core::sync::atomic::Ordering::Relaxed);
    if kind == 2 {
        pr_info!("nanochrono: rdcycle is not permitted to S-mode here; timing with rdtime\n");
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn rdtime() -> u64 {
    let v: u64;
    // SAFETY: `time` is readable in S-mode on every platform Linux runs on.
    unsafe { core::arch::asm!("fence", "rdtime {v}", v = out(reg) v, options(nostack)) };
    v
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn counter_start() -> u64 {
    if COUNTER_KIND.load(core::sync::atomic::Ordering::Relaxed) == 1 {
        let v: u64;
        // SAFETY: `counter_init` proved RDCYCLE legal on this system.
        unsafe { core::arch::asm!("fence", "rdcycle {v}", v = out(reg) v, options(nostack)) };
        v
    } else {
        rdtime()
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn counter_end() -> u64 {
    counter_start()
}

#[cfg(target_arch = "riscv64")]
extern "C" {
    /// The `time` CSR's rate, from the device tree, exported by
    /// `arch/riscv/kernel/time.c`.
    static riscv_timebase: core::ffi::c_ulong;
}

#[cfg(target_arch = "riscv64")]
fn write_counter_report(f: &mut ReportBuffer) -> fmt::Result {
    let cycle = COUNTER_KIND.load(core::sync::atomic::Ordering::Relaxed) == 1;
    writeln!(f, "counter={}", if cycle { "rdcycle" } else { "rdtime" })?;
    writeln!(f, "rdcycle_ok={}", u32::from(cycle))?;
    // SAFETY: written once at boot, read-only afterwards.
    let hz = unsafe { core::ptr::read_volatile(&raw const riscv_timebase) } as u64;
    writeln!(f, "time_hz={hz}")?;
    if *module_parameters::physical_counter.value() != 0 {
        writeln!(f, "counter_note=physical_counter ignored: RISC-V has no virtual/physical pair")?;
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
fn write_arch_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "arch=unsupported")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
fn counter_init() {}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
fn write_counter_report(f: &mut ReportBuffer) -> fmt::Result {
    writeln!(f, "counter=none")
}

/// No architectural counter this module knows: the crypto timings report
/// zero rather than a number with no unit.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
fn counter_start() -> u64 {
    0
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
fn counter_end() -> u64 {
    0
}
