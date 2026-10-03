// SPDX-License-Identifier: Apache-2.0
//! `NCSYS-DEMO.NCAPP`: Rust at ring 3 reaching the kernel the way any ported
//! program will — POSIX-class `nccall`s through `nanochrono-sys` — instead of
//! the `NcApi` table. Built for `x86_64-unknown-nanochronometer`, the ring-3
//! target whose red zone is on, so it also shows the one thing the boundary
//! must never do: write below a ring-3 stack pointer.
//!
//! Every check prints what it got; the app returns 0 when all of them pass.
//! `build.sh boot x86_64 plugin=ncsys-demo` runs it at boot.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use nanochrono_sys::alloc::NcAlloc;
use nanochrono_sys::nr::{self, map, prot};
use nanochrono_sys::{nccall, posix, println, Errno};

#[global_allocator]
static ALLOC: NcAlloc = NcAlloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    posix::exit(101)
}

/// Keeps eight words in its red zone — a leaf function whose 64-byte frame
/// fits in the 128 bytes, so with the red zone on the compiler leaves them
/// below RSP without moving it — across a `nccall` made inline, and says
/// whether they survived. The kernel's `SYSCALL` entry must not push
/// anything before it has left this stack. (The disassembly is checked in
/// the build: `tools/check-redzone.py` reports this function.)
#[inline(never)]
fn red_zone_across_nccall(seed: u64) -> bool {
    let mut words = [0u64; 8];
    for (i, w) in words.iter_mut().enumerate() {
        // SAFETY: a local the loop owns; volatile, so it lives in memory.
        unsafe { core::ptr::write_volatile(w, seed.rotate_left(i as u32 * 8)) };
    }
    // SAFETY: getpid takes no arguments and touches no memory.
    let pid = unsafe { nccall!(nr::posix::GETPID) };
    let mut ok = !pid.failed && pid.value == 1;
    for (i, w) in words.iter().enumerate() {
        // SAFETY: as above.
        ok &= unsafe { core::ptr::read_volatile(w) } == seed.rotate_left(i as u32 * 8);
    }
    ok
}

/// Whether `got` is the error `want`, printed either way.
fn expect_err<T: core::fmt::Debug>(what: &str, got: Result<T, Errno>, want: Errno, failures: &mut u32) {
    match got {
        Err(e) if e == want => println!("  {what:<28} -> {e} (as it should)"),
        other => {
            println!("  {what:<28} -> {other:?}, wanted {want}: FAILED");
            *failures += 1;
        }
    }
}

#[no_mangle]
pub extern "C" fn ncplu_main(_api: *const core::ffi::c_void) -> i32 {
    println!("ncsys-demo: Rust at ring 3, POSIX-class nccalls (nanochrono-sys), red zone on");
    let mut failures = 0u32;

    match posix::getpid() {
        Ok(pid) => println!("  {:<28} -> {pid}", "getpid"),
        Err(e) => {
            println!("  getpid -> {e}: FAILED");
            failures += 1;
        }
    }

    match posix::clock_gettime(nr::clock::MONOTONIC) {
        Ok(ts) => println!("  {:<28} -> {}.{:09} s", "clock_gettime(MONOTONIC)", ts.tv_sec, ts.tv_nsec),
        Err(e) => {
            println!("  clock_gettime -> {e}: FAILED");
            failures += 1;
        }
    }
    expect_err("clock_gettime(REALTIME)", posix::clock_gettime(nr::clock::REALTIME), Errno::EINVAL, &mut failures);

    let mut seed = [0u8; 8];
    match posix::getrandom(&mut seed, 0) {
        Ok(8) => println!("  {:<28} -> {:02x?}", "getrandom(8)", seed),
        other => {
            println!("  getrandom -> {other:?}: FAILED");
            failures += 1;
        }
    }

    // The heap: a Vec grows through NcAlloc, which is mmap and munmap.
    let mut squares: Vec<u64> = Vec::new();
    for i in 0..4096u64 {
        squares.push(i * i);
    }
    let sum: u64 = squares.iter().sum();
    let want = 4095 * 4096 * 8191 / 6;
    if sum == want {
        println!("  {:<28} -> {} squares, sum {sum}", "Vec over mmap/munmap", squares.len());
    } else {
        println!("  Vec over mmap -> sum {sum}, wanted {want}: FAILED");
        failures += 1;
    }
    drop(squares);

    // SAFETY: anonymous mappings of our own; nothing else refers to them.
    unsafe {
        match posix::mmap(core::ptr::null_mut(), 8192, prot::READ | prot::WRITE, map::ANON | map::PRIVATE, -1, 0) {
            Ok(p) => {
                // Zeroed on arrival, ours to write.
                let fresh = core::slice::from_raw_parts_mut(p, 8192);
                let zero = fresh.iter().all(|&b| b == 0);
                fresh.fill(0xA5);
                println!("  {:<28} -> {p:p}, zeroed: {zero}", "mmap(8 KiB)");
                if !zero {
                    failures += 1;
                }
                if posix::munmap(p, 8192).is_err() {
                    println!("  munmap: FAILED");
                    failures += 1;
                }
            }
            Err(e) => {
                println!("  mmap -> {e}: FAILED");
                failures += 1;
            }
        }
        expect_err(
            "mmap(PROT_EXEC)",
            posix::mmap(core::ptr::null_mut(), 4096, prot::READ | prot::EXEC, map::ANON | map::PRIVATE, -1, 0),
            Errno::EACCES,
            &mut failures,
        );
        expect_err(
            "mmap(fd 3)",
            posix::mmap(core::ptr::null_mut(), 4096, prot::READ, map::PRIVATE, 3, 0),
            Errno::ENOTSUP,
            &mut failures,
        );
    }

    expect_err("write(fd 7)", posix::write(7, b"x"), Errno::EBADF, &mut failures);
    expect_err("socket(AF_INET)", posix::socket(2, 1, 0), Errno::ENOSYS, &mut failures);
    // A pointer that is not the app's: the kernel's own text, at 1 MiB. As a
    // raw call — no Rust reference may point there, even unread.
    // SAFETY: write reads the range, and the kernel refuses it before it does.
    let stray = unsafe { nccall!(nr::posix::WRITE, 1, 0x0010_0000usize, 16usize) }.result();
    expect_err("write(kernel memory)", stray, Errno::EFAULT, &mut failures);

    let rz = red_zone_across_nccall(u64::from_le_bytes(seed));
    println!("  {:<28} -> {}", "red zone across a nccall", if rz { "intact" } else { "CORRUPTED" });
    if !rz {
        failures += 1;
    }

    if failures == 0 {
        println!("ncsys-demo: all checks passed");
        0
    } else {
        println!("ncsys-demo: {failures} check(s) FAILED");
        1
    }
}
