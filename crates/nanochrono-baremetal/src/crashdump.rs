// SPDX-License-Identifier: Apache-2.0
//! Crash dumps: what the CPU was doing when the kernel stopped, as a file.
//!
//! A fault on bare metal leaves nothing behind unless the kernel writes it
//! down. The exception stubs in `boot32.S` save every general register next
//! to the frame the CPU pushed, [`record_exception`] adds the control
//! registers, and the panic handler turns the lot into a `.DMP` image —
//! [`build`] — and sends it out over COM1, framed in base64 so it survives a
//! terminal log. `tools/nanodump.py` cuts it back out of the log, checks it
//! and prints it, symbolised against the kernel ELF.
//!
//! # Where the dump goes
//!
//! COM1 and the stop screen, and nowhere else. Writing it to a disk from a
//! kernel that has just faulted means trusting a storage stack running on
//! exactly the state the fault says is not trustworthy, and the partition
//! most likely to be reachable — the machine's own EFI System Partition — is
//! the one a stray write makes unbootable. See `docs/CRASH_DUMPS.md`.
//!
//! # What is read, and what is not
//!
//! Only memory this kernel knows is mapped: its own stacks and its own
//! `.text`, located through linker symbols. A register value is never
//! dereferenced just because it looks like a pointer — one that is not
//! would page-fault inside the dump writer, and the dump would be lost to
//! the very thing it is recording.
//!
//! # Format (version 1, little-endian)
//!
//! ```text
//! header, 64 bytes
//!   0  magic "DUMP"            4  u16 version        6  u16 header size (64)
//!   8  u32 total size         12  u32 CRC-32 (IEEE) of bytes [64, total)
//!  16  u16 machine (0x8664)   18  u16 flags         20  u32 section count
//!  24  u32 section table off  28  u32 reserved
//!  32  [u8; 16] kernel version, NUL-padded
//!  48  u64 counter at capture 56  u64 reserved
//! section table: count × { u32 kind, u32 offset, u32 size, u32 reserved }
//! ```
//!
//! Section kinds are [`Section`]; flags are the `FLAG_*` constants.

use core::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Breadcrumb: which driver was running
// ---------------------------------------------------------------------------

/// The subsystem that was running, recorded in the dump.
///
/// A fault's RIP says which instruction; this says which *driver*, which is
/// the question asked first when a machine stops during bring-up. Kept as a
/// byte so setting it is one store that an exception cannot interrupt
/// halfway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Driver {
    Boot,
    CpuFeatures,
    Pmu,
    Counter,
    Pci,
    Hypervisor,
    Acpi,
    Ps2,
    Xhci,
    I2cHid,
    InputPoll,
    Interface,
    Bench,
    CrashTest,
}

impl Driver {
    const ALL: [Driver; 14] = [
        Driver::Boot,
        Driver::CpuFeatures,
        Driver::Pmu,
        Driver::Counter,
        Driver::Pci,
        Driver::Hypervisor,
        Driver::Acpi,
        Driver::Ps2,
        Driver::Xhci,
        Driver::I2cHid,
        Driver::InputPoll,
        Driver::Interface,
        Driver::Bench,
        Driver::CrashTest,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Driver::Boot => "boot",
            Driver::CpuFeatures => "cpu features",
            Driver::Pmu => "pmu",
            Driver::Counter => "counter calibration",
            Driver::Pci => "pci",
            Driver::Hypervisor => "hypervisor",
            Driver::Acpi => "acpi",
            Driver::Ps2 => "ps/2 (8042)",
            Driver::Xhci => "usb (xhci)",
            Driver::I2cHid => "i2c-hid",
            Driver::InputPoll => "input poll",
            Driver::Interface => "interface",
            Driver::Bench => "benchmark",
            Driver::CrashTest => "crash test",
        }
    }

    /// Makes this the current driver until the returned guard is dropped.
    pub fn enter(self) -> Scope {
        Scope(CURRENT.swap(self as u8, Ordering::Relaxed))
    }

    /// Makes this the current driver, with no scope to restore.
    pub fn set(self) {
        CURRENT.store(self as u8, Ordering::Relaxed);
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(Driver::Boot as u8);

/// The driver running now.
pub fn current() -> Driver {
    Driver::ALL
        .get(CURRENT.load(Ordering::Relaxed) as usize)
        .copied()
        .unwrap_or(Driver::Boot)
}

/// Restores the previous driver when dropped. See [`Driver::enter`].
pub struct Scope(u8);

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.store(self.0, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Capture (x86-64)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub use capture::*;

#[cfg(target_arch = "x86_64")]
mod capture {
    /// What `isr_common` in `boot32.S` leaves on the stack: the general
    /// registers it pushed, then the vector and error code the stub pushed,
    /// then the frame the CPU pushed. The order is the reverse of the pushes.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct TrapFrame {
        pub rax: u64,
        pub rbx: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub rbp: u64,
        pub r8: u64,
        pub r9: u64,
        pub r10: u64,
        pub r11: u64,
        pub r12: u64,
        pub r13: u64,
        pub r14: u64,
        pub r15: u64,
        pub vector: u64,
        pub error: u64,
        pub rip: u64,
        pub cs: u64,
        pub rflags: u64,
        pub rsp: u64,
        pub ss: u64,
    }

    /// The vector recorded for a Rust `panic!` that no CPU exception raised.
    pub const SOFTWARE_PANIC: u64 = u64::MAX;

    /// The registers, in the order the CPU-state section stores them.
    pub const REGISTER_NAMES: [&str; REGISTERS] = [
        "vector", "error", "rip", "cs", "rflags", "rsp", "ss", "rax", "rbx", "rcx", "rdx",
        "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cr0",
        "cr2", "cr3", "cr4", "efer",
    ];
    pub const REGISTERS: usize = 27;

    /// The processor's state at the fault.
    #[derive(Debug, Clone, Copy)]
    pub struct CpuState {
        pub words: [u64; REGISTERS],
    }

    impl CpuState {
        const fn index(name: &str) -> usize {
            let mut i = 0;
            while i < REGISTERS {
                if const_eq(REGISTER_NAMES[i], name) {
                    return i;
                }
                i += 1;
            }
            panic!("no such register");
        }

        pub fn get(&self, name: &str) -> u64 {
            REGISTER_NAMES
                .iter()
                .position(|n| *n == name)
                .map_or(0, |i| self.words[i])
        }

        pub fn vector(&self) -> u64 {
            self.words[Self::index("vector")]
        }
        pub fn rip(&self) -> u64 {
            self.words[Self::index("rip")]
        }
        pub fn rsp(&self) -> u64 {
            self.words[Self::index("rsp")]
        }
        pub fn rbp(&self) -> u64 {
            self.words[Self::index("rbp")]
        }
    }

    const fn const_eq(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// CR0, CR3, CR4 and EFER. CR2 is read by the caller, first: it is only
    /// meaningful until the next page fault, which a dump writer could take.
    fn control_registers() -> [u64; 4] {
        let (cr0, cr3, cr4): (u64, u64, u64);
        // SAFETY: reading control registers at CPL 0 has no side effects;
        // EFER exists on every CPU in long mode, which this one is in.
        unsafe {
            core::arch::asm!(
                "mov {0}, cr0", "mov {1}, cr3", "mov {2}, cr4",
                out(reg) cr0, out(reg) cr3, out(reg) cr4,
                options(nomem, nostack, preserves_flags),
            );
            [cr0, cr3, cr4, crate::arch::x86::rdmsr(0xC000_0080)]
        }
    }

    /// Set once by [`record_exception`], read by [`super::build`]. Single
    /// core, interrupts masked, and written before the panic that reads it.
    static mut STATE: Option<CpuState> = None;

    /// Records the state at a CPU exception, for the dump the panic that
    /// follows will write.
    ///
    /// # Safety
    /// Call once, from the exception handler, before it panics.
    pub unsafe fn record_exception(f: &TrapFrame, cr2: u64) {
        let [cr0, cr3, cr4, efer] = control_registers();
        let words = [
            f.vector, f.error, f.rip, f.cs, f.rflags, f.rsp, f.ss, f.rax, f.rbx, f.rcx, f.rdx,
            f.rsi, f.rdi, f.rbp, f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15, cr0, cr2,
            cr3, cr4, efer,
        ];
        // SAFETY: see `STATE`.
        unsafe { STATE = Some(CpuState { words }) };
    }

    /// The state at a software panic: where the panic handler is, which is
    /// as close as a `panic!` gets to a faulting instruction. The general
    /// registers other than RSP and RBP hold whatever the handler put there
    /// and are recorded as zero rather than as something misleading.
    #[inline(always)]
    fn capture_here() -> CpuState {
        let (rip, rsp, rbp, rflags): (u64, u64, u64, u64);
        // SAFETY: reads RIP, RSP, RBP and RFLAGS; `pushfq`/`pop` leave the
        // stack as they found it.
        unsafe {
            core::arch::asm!(
                "lea {0}, [rip]", "mov {1}, rsp", "mov {2}, rbp", "pushfq", "pop {3}",
                out(reg) rip, out(reg) rsp, out(reg) rbp, out(reg) rflags,
                options(preserves_flags),
            );
        }
        let cr2: u64;
        // SAFETY: as `control_registers`.
        unsafe {
            core::arch::asm!("mov {0}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        }
        let [cr0, cr3, cr4, efer] = control_registers();
        let mut words = [0u64; REGISTERS];
        words[CpuState::index("vector")] = SOFTWARE_PANIC;
        words[CpuState::index("rip")] = rip;
        words[CpuState::index("cs")] = 0x08;
        words[CpuState::index("rflags")] = rflags;
        words[CpuState::index("rsp")] = rsp;
        words[CpuState::index("rbp")] = rbp;
        words[CpuState::index("cr0")] = cr0;
        words[CpuState::index("cr2")] = cr2;
        words[CpuState::index("cr3")] = cr3;
        words[CpuState::index("cr4")] = cr4;
        words[CpuState::index("efer")] = efer;
        CpuState { words }
    }

    /// The recorded exception state, or the state here if there is none.
    #[inline(always)]
    pub(super) fn state() -> (CpuState, bool) {
        // SAFETY: see `STATE`.
        match unsafe { STATE } {
            Some(state) => (state, true),
            None => (capture_here(), false),
        }
    }

    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
        static nc_stack_bottom: u8;
        static nc_stack_top: u8;
        static nc_ist1_bottom: u8;
        static nc_ist1_top: u8;
        static nc_ist2_bottom: u8;
        static nc_ist2_top: u8;
    }

    /// The kernel's `.text`, as the linker laid it out.
    pub(super) fn text() -> (u64, u64) {
        (&raw const __text_start as u64, &raw const __text_end as u64)
    }

    /// The stack `address` lies in — the kernel stack or one of the IST
    /// stacks — as `[bottom, top)`. `None` for an address in none of them,
    /// which is what a corrupted RSP or RBP looks like.
    pub(super) fn stack_containing(address: u64) -> Option<(u64, u64)> {
        let stacks = [
            (&raw const nc_stack_bottom as u64, &raw const nc_stack_top as u64),
            (&raw const nc_ist1_bottom as u64, &raw const nc_ist1_top as u64),
            (&raw const nc_ist2_bottom as u64, &raw const nc_ist2_top as u64),
        ];
        // And the NMI, #MC and #DB stacks kstack installs.
        stacks
            .into_iter()
            .chain(crate::kstack::own_stacks())
            .find(|&(lo, hi)| (lo..hi).contains(&address))
    }
}

// ---------------------------------------------------------------------------
// The image
// ---------------------------------------------------------------------------

/// Section kinds.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Section {
    /// `REGISTERS` little-endian u64, in `REGISTER_NAMES` order.
    CpuState = 1,
    /// The panic message, UTF-8.
    Reason = 2,
    /// The driver breadcrumb, UTF-8.
    Driver = 3,
    /// Return addresses, u64 each, innermost first; entry 0 is RIP.
    StackTrace = 4,
    /// Values on the stack that point into `.text`: return-address
    /// candidates, for a build without frame pointers.
    StackScan = 5,
    /// `{ u64 address, u32 offset into Memory, u32 size }` per region.
    MemoryTable = 6,
    /// The bytes of every region in the table, back to back.
    Memory = 7,
}

#[cfg(target_arch = "x86_64")]
pub const FLAG_CPU_EXCEPTION: u16 = 1 << 0;
#[cfg(target_arch = "x86_64")]
pub const FLAG_FRAME_POINTER_WALK: u16 = 1 << 1;
#[cfg(target_arch = "x86_64")]
pub const FLAG_TRUNCATED: u16 = 1 << 2;

#[cfg(target_arch = "x86_64")]
const HEADER_SIZE: usize = 64;
#[cfg(target_arch = "x86_64")]
const SECTIONS: usize = 7;
#[cfg(target_arch = "x86_64")]
const CAPACITY: usize = 16 * 1024;
#[cfg(target_arch = "x86_64")]
const MAX_FRAMES: usize = 32;
#[cfg(target_arch = "x86_64")]
const MAX_SCAN: usize = 32;
/// How much of the faulting stack is kept, from RSP up.
#[cfg(target_arch = "x86_64")]
const STACK_BYTES: u64 = 4096;
/// How much code is kept either side of RIP.
#[cfg(target_arch = "x86_64")]
const CODE_BYTES: u64 = 64;

/// The image, in `.bss`: nothing can be allocated in a panic.
#[cfg(target_arch = "x86_64")]
static mut IMAGE: [u8; CAPACITY] = [0; CAPACITY];

/// What the stop screen shows, kept from the last [`build`].
#[cfg(target_arch = "x86_64")]
static mut SUMMARY: Option<Summary> = None;

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct Summary {
    state: CpuState,
    exception: bool,
    driver: Driver,
    trace: [u64; 6],
    trace_len: usize,
    size: usize,
}

/// A bounded writer over the image.
#[cfg(target_arch = "x86_64")]
struct Cursor<'a> {
    buf: &'a mut [u8],
    len: usize,
    truncated: bool,
}

#[cfg(target_arch = "x86_64")]
impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let room = self.buf.len() - self.len;
        let n = bytes.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        self.truncated |= n < bytes.len();
    }
    fn u16_at(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn u32_at(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn u64_at(&mut self, at: usize, v: u64) {
        self.buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn align8(&mut self) {
        while self.len % 8 != 0 && self.len < self.buf.len() {
            self.buf[self.len] = 0;
            self.len += 1;
        }
    }
}

/// Writes the dump for a panic with message `reason`, and returns it.
///
/// Uses the state [`record_exception`] saved if a CPU exception led here,
/// and the panic handler's own otherwise.
///
/// # Safety
/// Call only from the panic handler: single core, interrupts masked, and
/// once — the image is a static the next call overwrites.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn build(reason: &str) -> &'static [u8] {
    let (state, exception) = state();
    // SAFETY: the caller guarantees exclusive access to the static.
    unsafe { build_from(state, exception, reason) }
}

/// # Safety
/// As [`build`].
#[cfg(target_arch = "x86_64")]
unsafe fn build_from(state: CpuState, exception: bool, reason: &str) -> &'static [u8] {
    let driver = current();
    // SAFETY: the caller guarantees exclusive access.
    let buf: &'static mut [u8; CAPACITY] = unsafe { &mut *(&raw mut IMAGE) };
    buf.fill(0);
    let mut c = Cursor { buf, len: HEADER_SIZE + SECTIONS * 16, truncated: false };
    let mut table = [(0u32, 0u32, 0u32); SECTIONS];
    let mut flags = if exception { FLAG_CPU_EXCEPTION } else { 0 };

    // Each section starts 8-aligned and is recorded in the table.
    let mut section = |c: &mut Cursor, i: usize, kind: Section, body: &mut dyn FnMut(&mut Cursor)| {
        c.align8();
        let start = c.len;
        body(c);
        table[i] = (kind as u32, start as u32, (c.len - start) as u32);
    };

    section(&mut c, 0, Section::CpuState, &mut |c| {
        for w in state.words {
            c.put(&w.to_le_bytes());
        }
    });
    section(&mut c, 1, Section::Reason, &mut |c| c.put(reason.as_bytes()));
    section(&mut c, 2, Section::Driver, &mut |c| c.put(driver.name().as_bytes()));

    // The stack trace: RIP, then the frame-pointer chain. Every RBP must lie
    // in the same stack as the first, above the last, and 8-aligned; the
    // first one that does not ends the walk, so a build without frame
    // pointers gives one entry here and relies on the scan below. The walk
    // starts from RBP's stack, not RSP's: a double fault from a wrecked RSP
    // still has the caller's frame chain intact.
    let mut trace = [0u64; MAX_FRAMES];
    let mut frames = 0;
    trace[frames] = state.rip();
    frames += 1;
    let mut rbp = state.rbp();
    if let Some((lo, hi)) = stack_containing(rbp) {
        while frames < MAX_FRAMES && rbp % 8 == 0 && rbp >= lo && rbp + 16 <= hi {
            // SAFETY: both words are inside a stack this kernel mapped.
            let (next, ret) = unsafe {
                (core::ptr::read_volatile(rbp as *const u64), core::ptr::read_volatile((rbp + 8) as *const u64))
            };
            if ret == 0 {
                break;
            }
            trace[frames] = ret;
            frames += 1;
            if next <= rbp {
                break;
            }
            rbp = next;
        }
    }
    if frames > 1 {
        flags |= FLAG_FRAME_POINTER_WALK;
    }
    section(&mut c, 3, Section::StackTrace, &mut |c| {
        for &a in &trace[..frames] {
            c.put(&a.to_le_bytes());
        }
    });

    // The memory regions: the stack from RSP up — or from RBP, when RSP is
    // not in any kernel stack — and the code around RIP.
    let (text_lo, text_hi) = text();
    let mut regions = [(0u64, 0u64); 2];
    let mut count = 0;
    let stack_from = [state.rsp(), state.rbp()]
        .into_iter()
        .find_map(|at| stack_containing(at).map(|(_, hi)| (at & !7, hi)));
    if let Some((lo, hi)) = stack_from {
        regions[count] = (lo, (hi - lo).min(STACK_BYTES));
        count += 1;
    }
    if (text_lo..text_hi).contains(&state.rip()) {
        let lo = state.rip().saturating_sub(CODE_BYTES).max(text_lo);
        let hi = (state.rip() + CODE_BYTES).min(text_hi);
        regions[count] = (lo, hi - lo);
        count += 1;
    }

    // Values on the kept stack that point into `.text`. Not a trace — a
    // stale return address from a finished call looks the same — but with
    // no frame pointers it is the list a trace is reconstructed from.
    section(&mut c, 4, Section::StackScan, &mut |c| {
        let mut found = 0;
        if count > 0 && stack_containing(regions[0].0).is_some() {
            let (lo, len) = regions[0];
            let mut at = lo;
            while at + 8 <= lo + len && found < MAX_SCAN {
                // SAFETY: inside the stack region checked above.
                let v = unsafe { core::ptr::read_volatile(at as *const u64) };
                if (text_lo..text_hi).contains(&v) {
                    c.put(&v.to_le_bytes());
                    found += 1;
                }
                at += 8;
            }
        }
    });

    section(&mut c, 5, Section::MemoryTable, &mut |c| {
        let mut offset = 0u32;
        for &(address, len) in &regions[..count] {
            c.put(&address.to_le_bytes());
            c.put(&offset.to_le_bytes());
            c.put(&(len as u32).to_le_bytes());
            offset += len as u32;
        }
    });
    section(&mut c, 6, Section::Memory, &mut |c| {
        for &(address, len) in &regions[..count] {
            // SAFETY: every region is inside a kernel stack or `.text`,
            // which the boot map covers.
            let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, len as usize) };
            c.put(bytes);
        }
    });

    if c.truncated {
        flags |= FLAG_TRUNCATED;
    }
    let total = c.len;

    // The header and the table, now that the offsets are known.
    c.buf[0..4].copy_from_slice(b"DUMP");
    c.u16_at(4, 1);
    c.u16_at(6, HEADER_SIZE as u16);
    c.u32_at(8, total as u32);
    c.u16_at(16, 0x8664);
    c.u16_at(18, flags);
    c.u32_at(20, SECTIONS as u32);
    c.u32_at(24, HEADER_SIZE as u32);
    let version = crate::VERSION.as_bytes();
    let n = version.len().min(16);
    c.buf[32..32 + n].copy_from_slice(&version[..n]);
    c.u64_at(48, crate::arch::counter_ordered());
    for (i, &(kind, offset, size)) in table.iter().enumerate() {
        let at = HEADER_SIZE + i * 16;
        c.u32_at(at, kind);
        c.u32_at(at + 4, offset);
        c.u32_at(at + 8, size);
    }
    let crc = crc32(&c.buf[HEADER_SIZE..total]);
    c.u32_at(12, crc);

    let mut shown = [0u64; 6];
    let shown_len = frames.min(shown.len());
    shown[..shown_len].copy_from_slice(&trace[..shown_len]);
    // SAFETY: as `IMAGE`.
    unsafe {
        SUMMARY = Some(Summary {
            state,
            exception,
            driver,
            trace: shown,
            trace_len: shown_len,
            size: total,
        });
    }

    &c.buf[..total]
}

/// CRC-32 (IEEE 802.3, reflected), bit by bit: the dump is a few KiB and
/// written once, so a 1 KiB table would cost more than it saves.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// The USB sink: a pre-resolved CRASH.DMP on a stick
// ---------------------------------------------------------------------------

/// Everything the crash path needs to write the dump to a USB stick, resolved
/// at boot while the machine was healthy.
///
/// The `xhci` pointer is to the live controller inside the input stack, which
/// stays at a fixed address for the whole run (the interface loop never
/// returns). At crash time nothing else is running — single core, interrupts
/// masked — so re-entering the controller through it does not race the poll
/// that may have been interrupted.
#[cfg(target_arch = "x86_64")]
struct UsbSink {
    xhci: *mut crate::xhci::Xhci,
    file: crate::usb_storage::CrashFile,
    block_size: u32,
}

#[cfg(target_arch = "x86_64")]
static mut USB_SINK: Option<UsbSink> = None;

/// How many bytes the last [`write_to_usb`] put on the stick; zero when it
/// did not run or failed. Read by the stop screen.
#[cfg(target_arch = "x86_64")]
static USB_WRITTEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Records where on a USB stick the dump may be written. Called once at boot,
/// after [`crate::usb_storage::find_crash_file`] resolved the file.
///
/// # Safety
/// `xhci` must point at a controller that stays live and fixed for the rest
/// of the run, with the mass-storage device it enumerated still addressed.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_usb_sink(
    xhci: *mut crate::xhci::Xhci,
    file: crate::usb_storage::CrashFile,
    block_size: u32,
) {
    // SAFETY: single core, interrupts masked, called once before any panic.
    unsafe { USB_SINK = Some(UsbSink { xhci, file, block_size }) };
}

/// Whether a USB dump target was found at boot.
#[cfg(target_arch = "x86_64")]
pub fn usb_sink_ready() -> bool {
    // SAFETY: see `set_usb_sink`; read on the panic path, single core.
    unsafe { (*core::ptr::addr_of!(USB_SINK)).is_some() }
}

/// A short description of the USB target, for the boot log and stop screen.
#[cfg(target_arch = "x86_64")]
pub fn usb_sink_summary() -> Option<(usize, u64)> {
    // SAFETY: as `usb_sink_ready`.
    let sink = unsafe { (*core::ptr::addr_of!(USB_SINK)).as_ref()? };
    Some((sink.file.extent_count, sink.file.capacity()))
}

/// Writes `dump` into the pre-resolved CRASH.DMP blocks. Returns how many
/// bytes were written, or `None` if there is no stick or a write failed.
///
/// Only the raw blocks the file already occupies are touched: no filesystem
/// metadata, no allocation. A dump larger than the file is refused rather
/// than truncated silently — the serial copy is then the whole record.
///
/// # Safety
/// Call only from the panic handler: single core, interrupts masked.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_to_usb(dump: &[u8]) -> Option<u64> {
    // SAFETY: see `set_usb_sink`.
    let sink = unsafe { (*core::ptr::addr_of!(USB_SINK)).as_ref()? };
    let bs = sink.block_size as usize;
    // The dump must fit both the file's size and the blocks resolved for it:
    // a FAT whose chain is shorter than its directory entry claims would
    // otherwise end in a partial write reported as a whole one.
    let room = (sink.file.size as u64).min(sink.file.capacity());
    if bs == 0 || bs > 4096 || dump.len() as u64 > room {
        return None;
    }
    // SAFETY: the pointer is to the live, fixed controller (see `UsbSink`).
    let xhci = unsafe { &mut *sink.xhci };

    let mut written = 0usize;
    for extent in &sink.file.extents[..sink.file.extent_count] {
        for b in 0..extent.blocks {
            if written >= dump.len() {
                USB_WRITTEN.store(written as u64, Ordering::Relaxed);
                return Some(written as u64);
            }
            let end = (written + bs).min(dump.len());
            // SAFETY: forwarded from this function's own contract.
            unsafe { xhci.write_block(extent.lba + b, &dump[written..end])? };
            written = end;
        }
    }
    USB_WRITTEN.store(written as u64, Ordering::Relaxed);
    Some(written as u64)
}

/// The lines `tools/nanodump.py` looks for around the base64.
pub const BEGIN_MARKER: &str = "-----BEGIN NANOCHRONO DUMP-----";
pub const END_MARKER: &str = "-----END NANOCHRONO DUMP-----";

/// Sends `dump` over COM1 as base64 between the two markers, 76 characters
/// a line. Only to the UART: on a text-mode screen it would scroll the
/// reason away.
#[cfg(target_arch = "x86_64")]
pub fn emit_serial(dump: &[u8]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out = crate::serial::write_uart_only;
    out(b"\r\n");
    out(BEGIN_MARKER.as_bytes());
    out(b"\r\n");
    let mut line = [0u8; 76];
    let mut used = 0;
    for chunk in dump.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        let quad = [
            ALPHABET[(n >> 18) as usize & 63],
            ALPHABET[(n >> 12) as usize & 63],
            if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] } else { b'=' },
            if chunk.len() > 2 { ALPHABET[n as usize & 63] } else { b'=' },
        ];
        line[used..used + 4].copy_from_slice(&quad);
        used += 4;
        if used == line.len() {
            out(&line);
            out(b"\r\n");
            used = 0;
        }
    }
    if used > 0 {
        out(&line[..used]);
        out(b"\r\n");
    }
    out(END_MARKER.as_bytes());
    out(b"\r\n");
}

/// The stop screen's register block, a line at a time.
#[cfg(target_arch = "x86_64")]
pub fn summary_lines(mut each: impl FnMut(&str)) {
    // SAFETY: written once by `build`, in the same panic, before this runs.
    let Some(s) = (unsafe { SUMMARY }) else {
        return;
    };
    let mut line = crate::text::Text::<120>::new();
    let row = |line: &mut crate::text::Text<120>, names: &[&str]| {
        line.clear();
        for name in names {
            line.str(name).str(" ");
            hex(line, s.state.get(name));
            line.str("   ");
        }
    };
    line.str("driver: ").str(s.driver.name()).str(if s.exception {
        "   (cpu exception)"
    } else {
        "   (software panic)"
    });
    each(line.as_str());
    for names in [
        &["rip", "cs", "rflags", "error"][..],
        &["rax", "rbx", "rcx", "rdx"],
        &["rsi", "rdi", "rbp", "rsp"],
        &["r8", "r9", "r10", "r11"],
        &["r12", "r13", "r14", "r15"],
        &["cr0", "cr2", "cr3", "cr4"],
    ] {
        row(&mut line, names);
        each(line.as_str());
    }
    line.clear();
    line.str("trace:");
    for &a in &s.trace[..s.trace_len] {
        line.str(" ");
        hex(&mut line, a);
    }
    each(line.as_str());
    line.clear();
    line.str("dump: ").num(s.size as u64).str(" bytes, sent over COM1 (tools/nanodump.py extract)");
    each(line.as_str());
    line.clear();
    let usb = USB_WRITTEN.load(Ordering::Relaxed);
    if usb > 0 {
        line.str("usb:  written to CRASH.DMP on the stick (").num(usb).str(" bytes)");
    } else if usb_sink_ready() {
        line.str("usb:  CRASH.DMP was found at boot, but the write failed");
    } else {
        line.str("usb:  no stick with CRASH.DMP was found at boot");
    }
    each(line.as_str());
}

#[cfg(target_arch = "x86_64")]
fn hex<const N: usize>(line: &mut crate::text::Text<N>, v: u64) {
    line.str("0x");
    for i in (0..16).rev() {
        let d = (v >> (i * 4)) as u8 & 0xF;
        line.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
    }
}

/// Writes `v` as 16 hex digits straight to the UART, without `core::fmt`:
/// for the nested-fault path, which must not depend on anything that could
/// have been the thing that faulted.
#[cfg(x86_any)]
pub fn raw_hex(v: u64) {
    let mut digits = [0u8; 18];
    digits[0] = b'0';
    digits[1] = b'x';
    for i in 0..16 {
        let d = (v >> ((15 - i) * 4)) as u8 & 0xF;
        digits[2 + i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
    }
    crate::serial::write_uart_only(&digits);
}

// ---------------------------------------------------------------------------
// Forced faults, to prove the path end to end
// ---------------------------------------------------------------------------

/// A fault to raise on purpose, named on the kernel command line as
/// `crashtest=<name>`.
#[cfg(x86_any)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashTest {
    /// `#DE`: `div` by zero, in assembly (Rust would check and panic).
    Divide,
    /// `#PF`: a read past the boot identity map — at 512 GiB on x86_64, the
    /// first canonical address the map leaves out; at 0xFFC0_0000 on i386,
    /// the top 4 MiB its page directory leaves unmapped.
    PageFault,
    /// `#GP`: on x86_64 a read through a non-canonical address; on i386 a
    /// data segment register loaded with a selector past the GDT's limit.
    Protection,
    /// `#UD`: `ud2`.
    Invalid,
    /// `#PF` on the guard page by unbounded recursion — a stack overflow,
    /// taken on IST2. (The i386 kernel has no guard page.)
    #[cfg(target_arch = "x86_64")]
    StackOverflow,
    /// `#DF`, the case that is a triple fault without a stack of its own for
    /// it. x86_64: RSP made non-canonical, then a push — the fault that
    /// raises (`#SS` on Intel silicon, `#GP` under TCG) cannot be delivered
    /// on that stack, and IST1 delivers the `#DF`. i386: SS loaded with a
    /// segment one byte long, then a push — the `#SS` cannot be delivered on
    /// that stack either, and a task gate delivers the `#DF` on its own.
    DoubleFault,
    /// `#XM`: an SSE division by zero with the exception unmasked in MXCSR.
    SimdFloatingPoint,
    /// `#MF`: an x87 0/0 with the invalid-operation exception unmasked in
    /// the control word, reported at the next x87 instruction.
    X87FloatingPoint,
    /// `#NM`: an SSE instruction with CR0.TS set.
    DeviceNotAvailable,
    /// A plain Rust `panic!`.
    Panic,
}

/// A crashtest armed on the command line, waiting to be fired once the USB
/// dump target is in place. See [`arm_crashtest`].
#[cfg(x86_any)]
static mut PENDING_CRASHTEST: Option<CrashTest> = None;

/// Arms a forced fault to fire later, from [`fire_pending_crashtest`]. Set
/// once at boot, on a single core before anything can panic.
#[cfg(x86_any)]
pub fn arm_crashtest(test: CrashTest) {
    // SAFETY: single core, interrupts masked, called once at boot.
    unsafe { PENDING_CRASHTEST = Some(test) };
}

/// Raises the armed crashtest, if any. Called after the interface has handed
/// the dumper its USB stick, so the forced dump reaches USB as well as
/// serial. Does nothing when none was armed.
///
/// # Safety
/// Deliberately faults when one is armed; call only at CPL 0 with the IDT
/// installed.
#[cfg(x86_any)]
pub unsafe fn fire_pending_crashtest() {
    // SAFETY: see `arm_crashtest`; single core.
    if let Some(test) = unsafe { (*core::ptr::addr_of_mut!(PENDING_CRASHTEST)).take() } {
        // SAFETY: forwarded from this function's own contract.
        unsafe { test.raise() }
    }
}

#[cfg(x86_any)]
impl CrashTest {
    /// Finds `crashtest=<name>` in a kernel command line.
    pub fn from_command_line(line: &str) -> Option<CrashTest> {
        let value = line.split_ascii_whitespace().find_map(|w| w.strip_prefix("crashtest="))?;
        Some(match value {
            "de" => CrashTest::Divide,
            "pf" => CrashTest::PageFault,
            "gp" => CrashTest::Protection,
            "ud" => CrashTest::Invalid,
            #[cfg(target_arch = "x86_64")]
            "so" => CrashTest::StackOverflow,
            "df" => CrashTest::DoubleFault,
            "xm" => CrashTest::SimdFloatingPoint,
            "mf" => CrashTest::X87FloatingPoint,
            "nm" => CrashTest::DeviceNotAvailable,
            "panic" => CrashTest::Panic,
            _ => return None,
        })
    }

    /// Raises the fault. Does not return.
    ///
    /// # Safety
    /// Deliberately faults; call only at CPL 0 with the IDT installed.
    #[inline(never)]
    pub unsafe fn raise(self) -> ! {
        Driver::CrashTest.set();
        crate::println!("crashtest: raising {:?}", self);
        // PML4 entry 1: `boot32.S` fills only entry 0, the first 512 GiB.
        #[cfg(target_arch = "x86_64")]
        const UNMAPPED: usize = 512 << 30;
        #[cfg(target_arch = "x86")]
        const UNMAPPED: usize = 0xFFC0_0000;
        // MXCSR's default with the divide-by-zero mask (ZM, bit 9) clear, and
        // the x87 control word's with the invalid-operation mask (IM, bit 0)
        // clear: 0/0 is invalid whichever way the operands are taken.
        let mxcsr: u32 = 0x1F80 & !(1 << 9);
        let fcw: u16 = 0x037F & !1;
        // SAFETY: every arm faults on purpose; the handler never returns.
        unsafe {
            match self {
                CrashTest::Divide => core::arch::asm!(
                    "xor edx, edx", "mov eax, 1", "xor ecx, ecx", "div ecx",
                    out("eax") _, out("ecx") _, out("edx") _, options(nomem, nostack),
                ),
                CrashTest::PageFault => {
                    let _ = core::ptr::read_volatile(UNMAPPED as *const u32);
                }
                #[cfg(target_arch = "x86_64")]
                CrashTest::Protection => {
                    let _ = core::ptr::read_volatile(0x8000_0000_0000_0000u64 as *const u64);
                }
                #[cfg(target_arch = "x86")]
                CrashTest::Protection => core::arch::asm!(
                    "mov ds, {sel:x}",
                    sel = in(reg) 0xFFF8u32, options(nomem, nostack),
                ),
                CrashTest::Invalid => core::arch::asm!("ud2", options(nomem, nostack)),
                #[cfg(target_arch = "x86_64")]
                CrashTest::StackOverflow => {
                    recurse(0);
                }
                #[cfg(target_arch = "x86_64")]
                CrashTest::DoubleFault => core::arch::asm!(
                    "mov rsp, {bad}", "push rax",
                    bad = in(reg) 0x8000_0000_0000_0000u64, options(nomem),
                ),
                // 0x28: the one-byte stack segment boot_i386.S keeps for this.
                #[cfg(target_arch = "x86")]
                CrashTest::DoubleFault => core::arch::asm!(
                    "mov ss, {sel:x}", "push eax",
                    sel = in(reg) 0x28u32, options(nomem),
                ),
                CrashTest::SimdFloatingPoint => core::arch::asm!(
                    "ldmxcsr [{m}]",
                    "xorps xmm0, xmm0",
                    "movd xmm1, {one:e}",
                    "divss xmm1, xmm0",
                    m = in(reg) &mxcsr,
                    one = in(reg) 0x3F80_0000u32, // 1.0
                    out("xmm0") _, out("xmm1") _, options(nostack),
                ),
                CrashTest::X87FloatingPoint => core::arch::asm!(
                    "fninit",
                    "fldcw [{cw}]",
                    "fldz",
                    "fldz",
                    "fdivp st(1), st(0)",
                    "fwait",
                    cw = in(reg) &fcw,
                    out("st(0)") _, out("st(1)") _, options(nostack),
                ),
                CrashTest::DeviceNotAvailable => core::arch::asm!(
                    "mov {t}, cr0",
                    "or {t}, 8", // CR0.TS
                    "mov cr0, {t}",
                    "xorps xmm0, xmm0",
                    t = out(reg) _, out("xmm0") _, options(nomem, nostack),
                ),
                CrashTest::Panic => panic!("crashtest: a deliberate panic"),
            }
        }
        panic!("crashtest: {:?} did not fault", self);
    }
}

/// Recurses until the stack guard stops it. `black_box` keeps the frame and
/// the call: without it the optimiser turns this into a loop.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[allow(unconditional_recursion)] // the point: it ends at the guard page
fn recurse(depth: u64) -> u64 {
    let pad = core::hint::black_box([depth; 64]);
    recurse(core::hint::black_box(depth + 1)) + pad[0]
}
