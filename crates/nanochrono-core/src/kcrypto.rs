// SPDX-License-Identifier: Apache-2.0
//! The Linux kernel's crypto API, reached from ring 3 and timed.
//!
//! # What this measures that the userspace provider does not
//!
//! [`crate`]'s benchmark modes time `ring`: code compiled into this process,
//! running in ring 3, on buffers this process owns. That answers "what does a
//! byte of AES cost *here*". It does not answer "what does this machine's
//! kernel do with AES", and on a modern machine those are different questions
//! with different answers, because the kernel has drivers userspace does not:
//!
//! ```console
//! $ head -3 /proc/crypto
//! name         : ccm(aes)
//! driver       : ccm_base(ctr-aes-vaes-avx2,cbcmac-aes-lib)
//! ```
//!
//! `ctr-aes-vaes-avx2` is a VAES implementation the kernel selected for this
//! part. Whether it is faster than the userspace one, and by how much, is a
//! measurement — and it is the measurement that tells you whether pushing
//! bulk crypto through the kernel (`AF_ALG`, kTLS, dm-crypt) is worth the
//! syscalls it costs.
//!
//! # Ring 3: `AF_ALG`, and it is always here
//!
//! Linux exposes its crypto API to userspace as a socket family. Bind a
//! socket to an algorithm by name, `accept` an operation from it, write
//! plaintext and read ciphertext. It needs no privileges, no module of ours,
//! and nothing but `libc` — so this path is compiled in unconditionally and
//! is the one that always runs.
//!
//! What it measures honestly includes the syscall: a `sendmsg`/`read` pair
//! per operation, plus the kernel's copy in and out. That is not overhead to
//! be subtracted, it is what using the kernel's crypto from userspace
//! actually costs, and reporting it separately from the per-byte cost is how
//! a caller can tell which one dominates at their buffer size.
//!
//! # Ring 0: the module, and it is optional
//!
//! `kernel/linux/` can call the same algorithms with no socket, no syscall
//! and no copy, and publish what it measured. That isolates the primitive
//! from the transport — the difference between the two numbers *is* the cost
//! of `AF_ALG`. It is optional by construction: the module is licensed
//! separately, has to be built and loaded by hand, and everything here works
//! without it. See [`Ring0`].
//!
//! # Not a security boundary
//!
//! Nothing here should be used to *do* cryptography. `AF_ALG` hands keys to
//! the kernel over a socket option, which is fine for a benchmark with a
//! throwaway key and wrong for anything real. The keys below are fixed
//! constants for exactly that reason: they are inputs to a stopwatch, not
//! secrets.

#[cfg(target_os = "linux")]
use std::io;

/// One algorithm the kernel offers, as `/proc/crypto` describes it.
///
/// The `driver` is the interesting field. `name` is what an algorithm is
/// called — `sha256`, `cbc(aes)` — and several implementations may answer to
/// it; `driver` is which one the kernel picked, and it carries the ISA in its
/// text: `sha256-avx2`, `aes-aesni`, `sha256-ce` on AArch64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driver {
    pub name: String,
    pub driver: String,
    /// `skcipher`, `hash`, `shash`, `aead`, `cipher`, …
    pub kind: String,
    /// Higher wins when several implementations offer the same `name`.
    pub priority: i32,
    pub module: String,
    /// Internal algorithms are building blocks the API will not hand out.
    pub internal: bool,
    pub selftest_passed: bool,
}

impl Driver {
    /// Whether the driver name suggests a hardware-accelerated path.
    ///
    /// A guess from a string, and labelled as one wherever it is shown. The
    /// kernel does not publish "this uses AES-NI" as a flag; it publishes a
    /// driver name that its author chose, and these are the suffixes that
    /// convention has settled on. A `false` here means "nothing in the name
    /// says so", not "the CPU is not helping".
    pub fn looks_accelerated(&self) -> bool {
        const MARKERS: &[&str] = &[
            "aesni", "vaes", "avx", "sse", "ssse3", "neon", "-ce", "ce-", "sha_ni", "shani", "asm",
            "clmul", "pclmul", "armv8", "vpmsum", "s390",
        ];
        let driver = self.driver.to_ascii_lowercase();
        MARKERS.iter().any(|marker| driver.contains(marker))
    }
}

/// Everything `/proc/crypto` lists.
///
/// Empty where the file does not exist, which is every non-Linux platform and
/// a Linux kernel built without `CONFIG_CRYPTO_USER_API` — neither of which
/// is an error, so neither returns one.
pub fn drivers() -> Vec<Driver> {
    let Ok(text) = std::fs::read_to_string("/proc/crypto") else {
        return Vec::new();
    };
    parse_proc_crypto(&text)
}

/// The implementation the kernel would choose for `name`.
///
/// Highest priority wins, which is the kernel's own rule. Internal algorithms
/// are skipped: they are components of composite modes and cannot be bound to
/// directly.
pub fn driver_for(name: &str) -> Option<Driver> {
    drivers()
        .into_iter()
        .filter(|d| d.name == name && !d.internal)
        .max_by_key(|d| d.priority)
}

/// Parses the `name: value` stanzas `/proc/crypto` is made of.
///
/// Split out from [`drivers`] so it can be tested against captured text
/// rather than against whatever kernel happens to be running the tests.
fn parse_proc_crypto(text: &str) -> Vec<Driver> {
    let mut out = Vec::new();
    let mut current: Option<Driver> = None;

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            if let Some(driver) = current.take() {
                out.push(driver);
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());

        // A stanza starts at its `name`. Anything before the first one is
        // a header this does not need.
        if key == "name" {
            if let Some(driver) = current.take() {
                out.push(driver);
            }
            current = Some(Driver {
                name: value.to_string(),
                driver: String::new(),
                kind: String::new(),
                priority: 0,
                module: String::new(),
                internal: false,
                selftest_passed: false,
            });
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        match key {
            "driver" => entry.driver = value.to_string(),
            "type" => entry.kind = value.to_string(),
            "priority" => entry.priority = value.parse().unwrap_or(0),
            "module" => entry.module = value.to_string(),
            "internal" => entry.internal = value == "yes",
            "selftest" => entry.selftest_passed = value == "passed",
            _ => {}
        }
    }
    if let Some(driver) = current.take() {
        out.push(driver);
    }
    out
}

// ---------------------------------------------------------------------------
// Ring 3: AF_ALG
// ---------------------------------------------------------------------------

/// Which of the kernel's algorithm types a session speaks.
///
/// Only the two whose transport is simple enough to be worth having. AEAD
/// needs an associated-data length and an authentication size negotiated over
/// the same control message, and a benchmark that got either wrong would
/// report a number for something other than what it named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `hash` — SHA-256 and friends. No key, no IV: write, then read.
    Hash,
    /// `skcipher` — CBC, CTR, XTS. Key by socket option, IV per operation.
    Skcipher,
}

impl Kind {
    // Only the Linux `AF_ALG` path binds a socket; elsewhere nothing asks.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const fn salg_type(self) -> &'static [u8] {
        match self {
            Kind::Hash => b"hash",
            Kind::Skcipher => b"skcipher",
        }
    }
}

/// An open operation on a kernel algorithm.
///
/// Two file descriptors, because that is how `AF_ALG` works: one bound to the
/// algorithm and one accepted from it for the actual data. Both are closed on
/// drop.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Session {
    bound: libc::c_int,
    op: libc::c_int,
    kind: Kind,
}

#[cfg(target_os = "linux")]
impl Session {
    /// Opens a hash algorithm — `"sha256"`, `"sha1"`, `"crc32c"`.
    pub fn hash(algorithm: &str) -> io::Result<Session> {
        Session::open(Kind::Hash, algorithm, None)
    }

    /// Opens a symmetric cipher — `"cbc(aes)"`, `"ctr(aes)"`, `"xts(aes)"`.
    ///
    /// The key is handed to the kernel as a socket option before any
    /// operation is accepted. It is a benchmark key; see the module docs.
    pub fn skcipher(algorithm: &str, key: &[u8]) -> io::Result<Session> {
        Session::open(Kind::Skcipher, algorithm, Some(key))
    }

    fn open(kind: Kind, algorithm: &str, key: Option<&[u8]>) -> io::Result<Session> {
        let mut address: libc::sockaddr_alg = unsafe { core::mem::zeroed() };
        address.salg_family = libc::AF_ALG as libc::sa_family_t;

        let kind_bytes = kind.salg_type();
        if kind_bytes.len() >= address.salg_type.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        address.salg_type[..kind_bytes.len()].copy_from_slice(kind_bytes);

        let name = algorithm.as_bytes();
        // The kernel's field is 64 bytes and the name must be terminated
        // inside it. A name that does not fit is rejected here rather than
        // silently truncated into a request for a different algorithm.
        if name.len() >= address.salg_name.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        address.salg_name[..name.len()].copy_from_slice(name);

        // SAFETY: a plain socket call with constant arguments.
        let bound = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        // Built once and mutated, never rebuilt.
        //
        // An earlier version finished with `Ok(Session { op, ..session })`,
        // which looks like a move and is not: `bound` and `kind` are `Copy`,
        // so the update syntax *copies* them and leaves the original
        // `session` alive to be dropped at the end of this function — closing
        // `bound` while the returned value still holds the same descriptor
        // number. The kernel then handed that number to the next `open`, and
        // this type's `Drop` closed somebody else's file. It surfaced as
        // `closedir: Bad file descriptor` in an unrelated test, which is what
        // a double close looks like from the outside: a failure with no
        // connection to the code that caused it.
        let mut session = Session {
            bound,
            op: -1,
            kind,
        };

        // SAFETY: `address` is a fully initialised `sockaddr_alg`, and its
        // length is what the kernel expects for this family.
        let bind = unsafe {
            libc::bind(
                bound,
                core::ptr::addr_of!(address).cast::<libc::sockaddr>(),
                core::mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t,
            )
        };
        if bind < 0 {
            // `session` closes `bound` on drop.
            return Err(io::Error::last_os_error());
        }

        if let Some(key) = key {
            // SAFETY: the pointer and length describe `key`, which outlives
            // the call.
            let set = unsafe {
                libc::setsockopt(
                    bound,
                    libc::SOL_ALG,
                    libc::ALG_SET_KEY,
                    key.as_ptr().cast(),
                    key.len() as libc::socklen_t,
                )
            };
            if set < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        // SAFETY: accepting on a bound ALG socket yields the operation fd.
        let op = unsafe { libc::accept(bound, core::ptr::null_mut(), core::ptr::null_mut()) };
        if op < 0 {
            return Err(io::Error::last_os_error());
        }
        session.op = op;
        Ok(session)
    }

    /// Hashes `data` into `out`, returning how many bytes the digest took.
    pub fn digest(&self, data: &[u8], out: &mut [u8]) -> io::Result<usize> {
        if self.kind != Kind::Hash {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        write_all(self.op, data)?;
        // SAFETY: `out` is a valid writable slice of the length given.
        let read = unsafe { libc::read(self.op, out.as_mut_ptr().cast(), out.len()) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read as usize)
    }

    /// Encrypts `data` into `out` under `iv`.
    ///
    /// `out` must be at least as long as `data`: a block cipher in a
    /// streaming mode produces exactly as many bytes as it consumes, and a
    /// short buffer would be a partial read reported as a fast one.
    pub fn encrypt(&self, iv: &[u8], data: &[u8], out: &mut [u8]) -> io::Result<usize> {
        if self.kind != Kind::Skcipher || out.len() < data.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        send_cipher_request(self.op, iv, data)?;

        // The kernel returns as much as it has; a large buffer can come back
        // in several reads, and stopping at the first would time a fraction
        // of the work.
        let mut filled = 0usize;
        while filled < data.len() {
            // SAFETY: the pointer and length stay inside `out`.
            let read = unsafe {
                libc::read(
                    self.op,
                    out.as_mut_ptr().add(filled).cast(),
                    data.len() - filled,
                )
            };
            if read < 0 {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                break;
            }
            filled += read as usize;
        }
        Ok(filled)
    }
}

#[cfg(target_os = "linux")]
impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: both descriptors are ours, and -1 is the sentinel for one
        // that was never accepted.
        unsafe {
            if self.op >= 0 {
                libc::close(self.op);
            }
            if self.bound >= 0 {
                libc::close(self.bound);
            }
        }
    }
}

/// Writes a whole buffer, looping over short writes.
#[cfg(target_os = "linux")]
fn write_all(fd: libc::c_int, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        // SAFETY: the pointer and length describe `data`.
        let written = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        data = &data[written as usize..];
    }
    Ok(())
}

/// `struct af_alg_iv`: a length and the bytes after it.
///
/// Declared here rather than taken from `libc`, which does not carry it. The
/// kernel reads a `__u32` followed by that many bytes, so the fixed array is
/// a maximum rather than the shape of the wire format — only `ivlen` bytes
/// are sent.
#[cfg(target_os = "linux")]
#[repr(C)]
struct AfAlgIv {
    ivlen: u32,
    iv: [u8; MAX_IV],
}

/// The longest IV any mode here uses. AES block modes need sixteen bytes.
#[cfg(target_os = "linux")]
const MAX_IV: usize = 16;

/// Sends one cipher request: the operation, the IV, and the data.
///
/// All three go in a single `sendmsg`, because that is the interface — the
/// operation and IV ride in control messages alongside the payload, and
/// splitting them across calls would start an operation the kernel has not
/// been told how to perform.
#[cfg(target_os = "linux")]
fn send_cipher_request(fd: libc::c_int, iv: &[u8], data: &[u8]) -> io::Result<()> {
    if iv.len() > MAX_IV {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    // Two control messages: what to do, and what to do it with.
    let op_space = unsafe { libc::CMSG_SPACE(core::mem::size_of::<u32>() as u32) } as usize;
    let iv_payload = core::mem::size_of::<u32>() + iv.len();
    let iv_space = unsafe { libc::CMSG_SPACE(iv_payload as u32) } as usize;

    let mut control = vec![0u8; op_space + iv_space];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;

    // SAFETY: `control` is large enough for both messages, computed with the
    // kernel's own `CMSG_SPACE`, and every write below stays inside the
    // region `CMSG_DATA` points at.
    unsafe {
        let first = libc::CMSG_FIRSTHDR(&message);
        if first.is_null() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        (*first).cmsg_level = libc::SOL_ALG;
        (*first).cmsg_type = libc::ALG_SET_OP as libc::c_int;
        (*first).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<u32>() as u32) as _;
        let operation: u32 = libc::ALG_OP_ENCRYPT as u32;
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(operation).cast::<u8>(),
            libc::CMSG_DATA(first),
            core::mem::size_of::<u32>(),
        );

        let second = libc::CMSG_NXTHDR(&message, first);
        if second.is_null() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        (*second).cmsg_level = libc::SOL_ALG;
        (*second).cmsg_type = libc::ALG_SET_IV as libc::c_int;
        (*second).cmsg_len = libc::CMSG_LEN(iv_payload as u32) as _;
        let mut block = AfAlgIv {
            ivlen: iv.len() as u32,
            iv: [0; MAX_IV],
        };
        block.iv[..iv.len()].copy_from_slice(iv);
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(block).cast::<u8>(),
            libc::CMSG_DATA(second),
            iv_payload,
        );

        let sent = libc::sendmsg(fd, &message, 0);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Whether `AF_ALG` can be used at all here.
///
/// Opening a socket is the only honest test: the family may be compiled out
/// (`CONFIG_CRYPTO_USER_API`), and a container's seccomp filter may refuse it
/// even where the kernel supports it. `/proc/crypto` existing says nothing
/// about either.
#[cfg(target_os = "linux")]
pub fn available() -> bool {
    // SAFETY: a plain socket call with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
    if fd < 0 {
        return false;
    }
    // SAFETY: the descriptor was just returned by `socket`.
    unsafe { libc::close(fd) };
    true
}

/// The same shape off Linux, so callers need no `cfg` of their own.
///
/// `AF_ALG` is Linux's, and nothing on another platform stands in for it — but
/// a benchmark crate that had to bracket every mention of this type in
/// `#[cfg(target_os = "linux")]` would grow the platform split through code
/// that has nothing to do with platforms. The type exists everywhere and
/// refuses to open anywhere else, which keeps the difference in one file.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct Session {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
impl Session {
    pub fn hash(_algorithm: &str) -> std::io::Result<Session> {
        Err(Session::unsupported())
    }

    pub fn skcipher(_algorithm: &str, _key: &[u8]) -> std::io::Result<Session> {
        Err(Session::unsupported())
    }

    pub fn digest(&self, _data: &[u8], _out: &mut [u8]) -> std::io::Result<usize> {
        Err(Session::unsupported())
    }

    pub fn encrypt(&self, _iv: &[u8], _data: &[u8], _out: &mut [u8]) -> std::io::Result<usize> {
        Err(Session::unsupported())
    }

    fn unsupported() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the kernel crypto API is reached through AF_ALG, which is Linux's",
        )
    }
}

/// `AF_ALG` is Linux's. Nothing on another platform stands in for it.
#[cfg(not(target_os = "linux"))]
pub fn available() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Ring 0: the optional module
// ---------------------------------------------------------------------------

/// What the kernel module reported, if it is loaded.
///
/// Optional by construction. `kernel/linux/` is licensed separately from the
/// rest of the project — the kernel accepts no Apache-2.0 module — has to be
/// built and inserted by hand, and communicates only through a file in
/// `/proc`. Everything in this module works without it; what it adds is the
/// same algorithms measured with no socket, no syscall and no copy, which is
/// the only way to separate the cost of the primitive from the cost of
/// reaching it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ring0 {
    /// Algorithm name to the best cycle count the module observed for one
    /// digest of [`Ring0::payload_bytes`].
    ///
    /// Cycles rather than nanoseconds because that is what the module can
    /// measure without a calibration of its own: it reads the same counter
    /// this process does, and converting is the reader's job — it already
    /// knows the counter's rate.
    pub timings: Vec<(String, u64)>,
    /// Bytes per operation, so the two sides can be compared only when they
    /// measured the same amount of work.
    pub payload_bytes: usize,
    /// How many operations the module timed, taking the best.
    pub rounds: usize,
}

impl Ring0 {
    /// Reads the module's report, if it is loaded and readable.
    ///
    /// `None` is the ordinary case: no module, or a module whose `/proc` file
    /// this user cannot read. Neither is an error.
    /// The oldest module format that publishes crypto timings.
    ///
    /// A module built before those existed answers version 1 and simply has
    /// no `crypto=` lines, so this is belt and braces — but it makes the
    /// difference between "no module" and "a module too old to ask" nameable,
    /// which matters when the module you just rebuilt is not the one the
    /// kernel still has loaded.
    pub const MINIMUM_FORMAT: u32 = 2;

    pub fn read() -> Option<Ring0> {
        for path in crate::hypervisor::KERNEL_MODULE_PATHS {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let report = parse_ring0(&text);
            if !report.timings.is_empty() {
                return Some(report);
            }
        }
        None
    }
}

/// Parses the module's crypto lines out of its `key=value` report.
///
/// The timings come as repeated `crypto=` keys rather than one key per
/// algorithm, because a kernel algorithm name can contain characters —
/// `cbc(aes)` — that have no business on the left of an `=`:
///
/// ```text
/// crypto_payload_bytes=16384
/// crypto_rounds=64
/// crypto=sha256,10431
/// crypto=sha512,24887
/// ```
///
/// Unrecognised keys are skipped rather than failing the read, so a module
/// that gains a field keeps working with an older reader and the reverse.
fn parse_ring0(text: &str) -> Ring0 {
    let mut report = Ring0::default();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        match key {
            "crypto_payload_bytes" => report.payload_bytes = value.parse().unwrap_or(0),
            "crypto_rounds" => report.rounds = value.parse().unwrap_or(0),
            "crypto" => {
                // Split from the right: the name may contain commas of its
                // own — `ccm_base(ctr-aes,cbcmac-aes)` — and the count never
                // does.
                if let Some((name, cycles)) = value.rsplit_once(',') {
                    if let Ok(cycles) = cycles.trim().parse() {
                        report.timings.push((name.to_string(), cycles));
                    }
                }
            }
            _ => {}
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stanza parser, against text captured from a real kernel rather
    /// than against whatever is running the tests.
    #[test]
    fn proc_crypto_stanzas_parse() {
        let text = "\
name         : ccm(aes)
driver       : ccm_base(ctr-aes-vaes-avx2,cbcmac-aes-lib)
module       : kernel
priority     : 450
refcnt       : 3
selftest     : passed
internal     : no
type         : aead

name         : sha256
driver       : sha256-generic
module       : kernel
priority     : 100
selftest     : passed
internal     : no
type         : shash

name         : sha256
driver       : sha256-avx2
module       : kernel
priority     : 170
selftest     : passed
internal     : no
type         : shash
";
        let drivers = parse_proc_crypto(text);
        assert_eq!(drivers.len(), 3);
        assert_eq!(drivers[0].name, "ccm(aes)");
        assert_eq!(drivers[0].priority, 450);
        assert_eq!(drivers[0].kind, "aead");
        assert!(drivers[0].selftest_passed);
        assert!(!drivers[0].internal);
    }

    /// The kernel picks by priority, and so does this.
    #[test]
    fn the_highest_priority_implementation_wins() {
        let text = "\
name         : sha256
driver       : sha256-generic
priority     : 100
internal     : no
type         : shash

name         : sha256
driver       : sha256-avx2
priority     : 170
internal     : no
type         : shash
";
        let drivers = parse_proc_crypto(text);
        let best = drivers
            .iter()
            .filter(|d| d.name == "sha256" && !d.internal)
            .max_by_key(|d| d.priority)
            .expect("an implementation");
        assert_eq!(best.driver, "sha256-avx2");
    }

    /// An internal algorithm is a building block, not something to bind to.
    #[test]
    fn internal_algorithms_are_flagged() {
        let text = "\
name         : cbcmac(aes)
driver       : cbcmac-aes-lib
priority     : 300
internal     : yes
type         : shash
";
        let drivers = parse_proc_crypto(text);
        assert!(drivers[0].internal);
        assert_eq!(driver_for_in(&drivers, "cbcmac(aes)"), None);
    }

    /// Test-only mirror of [`driver_for`] that takes its input rather than
    /// reading `/proc`, so the rule can be checked off a real machine.
    fn driver_for_in(drivers: &[Driver], name: &str) -> Option<Driver> {
        drivers
            .iter()
            .filter(|d| d.name == name && !d.internal)
            .max_by_key(|d| d.priority)
            .cloned()
    }

    /// The accelerated-driver heuristic recognises what it claims to, and is
    /// not fooled by a generic name.
    #[test]
    fn accelerated_driver_names_are_recognised() {
        let accelerated = ["sha256-avx2", "aes-aesni", "sha256-ce", "ctr-aes-vaes-avx2"];
        for driver in accelerated {
            let d = Driver {
                name: "x".into(),
                driver: driver.into(),
                kind: "shash".into(),
                priority: 0,
                module: "kernel".into(),
                internal: false,
                selftest_passed: true,
            };
            assert!(d.looks_accelerated(), "{driver} should read as accelerated");
        }
        let generic = Driver {
            name: "sha256".into(),
            driver: "sha256-generic".into(),
            kind: "shash".into(),
            priority: 100,
            module: "kernel".into(),
            internal: false,
            selftest_passed: true,
        };
        assert!(!generic.looks_accelerated());
    }

    /// The module's report is parsed if present, unrecognised lines are
    /// skipped, and a name containing a comma survives the split.
    #[test]
    fn the_modules_crypto_lines_parse() {
        let text = "\
version=3
arch=x86
crypto_payload_bytes=16384
crypto_rounds=64
crypto=sha256,10431
crypto=sha512,24887
crypto=ccm_base(ctr-aes,cbcmac-aes),91002
something else entirely
";
        let report = parse_ring0(text);
        assert_eq!(report.payload_bytes, 16384);
        assert_eq!(report.rounds, 64);
        assert_eq!(
            report.timings,
            vec![
                ("sha256".to_string(), 10431),
                ("sha512".to_string(), 24887),
                ("ccm_base(ctr-aes,cbcmac-aes)".to_string(), 91002),
            ]
        );
    }

    /// On a machine with `AF_ALG` this must actually hash, and agree with a
    /// known answer. Skipped where the family is unavailable, which is every
    /// non-Linux platform and any container that filters the socket call.
    #[cfg(target_os = "linux")]
    #[test]
    fn af_alg_sha256_matches_a_known_digest() {
        if !available() {
            eprintln!("no AF_ALG here; skipping");
            return;
        }
        let Ok(session) = Session::hash("sha256") else {
            eprintln!("sha256 not offered through AF_ALG; skipping");
            return;
        };
        let mut digest = [0u8; 32];
        let n = session.digest(b"abc", &mut digest).expect("digest");
        assert_eq!(n, 32);
        // The SHA-256 of "abc", which is fixed by the standard and so is a
        // real check on the transport rather than on the kernel.
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    /// And must encrypt, reversibly in the sense that matters here: the same
    /// input under the same key and IV gives the same output, and it is not
    /// the plaintext.
    /// A session must not close a descriptor it does not own.
    ///
    /// The regression this pins was a double close. `Session::open` finished
    /// with struct-update syntax over `Copy` fields, so the intermediate
    /// value stayed alive and closed the bound socket on its way out, while
    /// the returned session kept the same descriptor *number*. Dropping that
    /// session later closed the number a second time — by then belonging to
    /// something else entirely. It first showed up as `closedir: Bad file
    /// descriptor` in a test that had nothing to do with crypto.
    ///
    /// Detecting it needs the fd to be *reused*, not merely freed, so the
    /// test arranges that rather than hoping for it: POSIX hands out the
    /// lowest free descriptor, so a file opened while a session is alive
    /// lands exactly on the number the bug leaked. Dropping the session then
    /// closes the file, and reading it fails.
    ///
    /// Written against a live session on purpose — a loop of opens and drops
    /// does not reliably collide, which an earlier version of this test found
    /// out by passing with the bug present.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_session_does_not_close_a_descriptor_it_does_not_own() {
        use std::io::Read as _;

        if !available() {
            eprintln!("no AF_ALG here; skipping");
            return;
        }
        let Ok(session) = Session::hash("sha256") else {
            eprintln!("sha256 not offered through AF_ALG; skipping");
            return;
        };

        // Opened *after* the session, so it takes the lowest free descriptor
        // — which, if the session leaked one, is the session's own.
        let mut victim = std::fs::File::open("/proc/self/status").expect("a file to hold");

        drop(session);

        let mut text = String::new();
        victim.read_to_string(&mut text).expect(
            "reading a file opened alongside a Session failed after the session was \
             dropped: the session closed a descriptor it did not own",
        );
        assert!(!text.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn af_alg_aes_cbc_encrypts() {
        if !available() {
            eprintln!("no AF_ALG here; skipping");
            return;
        }
        let key = [0x42u8; 32];
        let Ok(session) = Session::skcipher("cbc(aes)", &key) else {
            eprintln!("cbc(aes) not offered through AF_ALG; skipping");
            return;
        };
        let iv = [0x24u8; 16];
        let plaintext = [0u8; 64];
        let mut first = [0u8; 64];
        let n = session
            .encrypt(&iv, &plaintext, &mut first)
            .expect("encrypt");
        assert_eq!(n, 64);
        assert_ne!(first, plaintext, "the ciphertext is the plaintext");

        let session = Session::skcipher("cbc(aes)", &key).expect("second session");
        let mut second = [0u8; 64];
        session
            .encrypt(&iv, &plaintext, &mut second)
            .expect("encrypt");
        assert_eq!(first, second, "the same input gave two different outputs");
    }
}
