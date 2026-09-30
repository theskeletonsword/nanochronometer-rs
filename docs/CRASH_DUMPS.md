# Crash dumps and debugging the bare-metal kernel

What happens when the x86-64 kernel faults, how to read what it leaves
behind, and how to step through it under GDB.

## What a fault does

Every architectural exception (vectors 0–31) has an IDT gate. `boot32.S`
installs them before `kmain`, together with a TSS whose Interrupt Stack Table
gives three of them a stack of their own:

| Vector | Stack | Why |
|---|---|---|
| `#DF` (8), NMI (2), `#MC` (18) | IST1, 32 KiB | A double fault is what a fault on a broken stack becomes. Delivered on that same stack it faults a third time: a triple fault, which is a reset |
| `#PF` (14) | IST2, 32 KiB | A kernel-stack overflow faults on the unmapped guard page *with RSP inside it* |
| everything else | the current stack | |

The stub for each vector pushes a uniform frame, `isr_common` pushes the
fifteen general registers, and `nanochrono_x86_exception` records them with
CR0, CR2, CR3, CR4 and EFER, then panics with a one-line reason. The panic
handler writes the crash dump, sends it over COM1, writes it to `CRASH.DMP`
on a USB stick when one was found at boot, and shows the stop screen with the
reason and the register block. It never returns and never restarts.

Two guards keep a failure in the reporting from hiding the original fault:

- A fault **inside** the exception handler prints the vector, RIP and CR2
  with nothing but port writes and halts.
- A panic **inside** the panic handler prints its message and halts.

Neither path recurses, so neither ends in a triple fault.

## The dump

A `.DMP` image, at most 16 KiB, built in `.bss`: nothing is allocated in a
panic. The layout is in `crates/nanochrono-baremetal/src/crashdump.rs`, and
`tools/nanodump.py` is its reader. It holds:

- the CPU state: vector, error code, RIP, CS, RFLAGS, RSP, SS, the fifteen
  general registers, CR0/2/3/4 and EFER;
- the panic message, and the **driver** that was running: a breadcrumb set by
  the boot phases, by the PS/2, xHCI and I2C-HID code (at bring-up and on every
  poll) and by the benchmark runner;
- a stack trace: RIP, then the RBP chain, walked only while each frame lies in
  a kernel stack. Release builds have no frame pointers, so a **stack scan** is
  added as well: every word on the kept stack that points into `.text`;
- memory: up to 4 KiB of the stack from RSP (or from RBP when RSP is not in a
  kernel stack) and 64 bytes of code either side of RIP.

Only memory the kernel knows is mapped is read: its three stacks and its
`.text`, located through linker symbols. A register is never dereferenced
because it looks like a pointer. One that is not would fault inside the
writer, and the dump would be lost.

It is CRC-32 protected and goes out over COM1 as base64 between
`-----BEGIN NANOCHRONO DUMP-----` and `-----END NANOCHRONO DUMP-----`, to the
UART only (a text-mode screen would scroll the reason away).

```console
$ tools/nanodump.py extract serial.log -o CRASH.DMP
$ tools/nanodump.py show CRASH.DMP --elf build/baremetal/x86_64/nanochrono-kernel.sym.elf
```

The release ISO boots a stripped kernel. `build.sh` keeps the symbols in
`nanochrono-kernel.sym.elf` beside it, and that is the file to give `--elf`.

### Where it is stored

Three copies, in the order they are made:

1. **COM1**, as base64 (above).
2. **`CRASH.DMP` on a USB stick**: the stick the machine booted from, or any
   other one plugged in. The first stick found with the file is used.
3. **The stop screen**, which shows the driver, every register, the first
   frames of the trace, and whether the USB write happened. On a notebook
   with no serial port and no stick, that screen is the only copy.

#### How the USB copy is written

Everything that could go wrong is done **at boot**, while the machine is
healthy:

- The xHCI driver enumerates each root port once and keeps the first
  Bulk-Only/SCSI mass-storage device next to the keyboard and pointer. It is
  brought up with `INQUIRY`, `TEST UNIT READY` and `READ CAPACITY`.
- `usb_storage.rs` reads the partition table (MBR, GPT, or none), the FAT16
  or FAT32 boot sector and root directory, finds `CRASH.DMP`, and resolves it
  into raw block ranges. The boot log then says:
  `crash dump target: USB stick, CRASH.DMP resolved (1 extent(s), 64 KiB)`.

At the crash, the handler does nothing but `WRITE(10)` the dump into those
blocks. It never allocates a cluster, never grows the file and never touches
the FAT or a directory entry, so a fault cannot damage the stick's
filesystem. A dump larger than the file, or than the blocks the chain really
has, is refused rather than written in part.

Verified under KVM with each forced fault below, on a FAT32 stick: the dump
read back from the stick has a valid CRC, `fsck.fat` reports the volume
clean, and every byte that changed on the stick lies inside `CRASH.DMP`'s
blocks.

#### Getting a stick with `CRASH.DMP`

**The boot stick itself.** The x86_64 ISO carries a 4 MiB FAT16 partition,
labelled `NANOCRASH`, holding a zeroed 64 KiB `CRASH.DMP` and a `README.TXT`.
It is appended to the hybrid ISO as a GPT partition, and the MBR stays purely
protective as UEFI expects. Write the ISO to a stick and boot from it. The
stick is then its own dump target:

```console
$ sudo dd if=build/baremetal/nanochronometer_x86_64.iso of=/dev/sdX bs=4M conv=fsync
```

After a crash, plug the stick into any PC. The `NANOCRASH` volume mounts on
its own:

```console
$ tools/nanodump.py show /run/media/$USER/NANOCRASH/CRASH.DMP \
      --elf build/baremetal/x86_64/nanochrono-kernel.sym.elf
```

A `CRASH.DMP` that is all zeros means nothing has crashed since the stick was
written. (A CD has no writable partition; booted from one, the dump goes to
whichever stick is plugged in.)

**Any other stick** works if it has a FAT16 or FAT32 volume (whole device, MBR
or GPT partition) with a `CRASH.DMP` of at least 16 KiB in its root
directory:

```console
$ head -c 65536 /dev/zero > /run/media/$USER/STICK/CRASH.DMP && sync
```

To read it back without mounting, as root:
`tools/nanodump.py extract-image /dev/sdX -o CRASH.DMP`.

#### Limits

- 512-byte logical sectors only. FAT12, exFAT and NTFS are not read.
- LUN 0 only, one block per command, no stall recovery: a stick that
  misbehaves is given up on, and the serial copy is the record.
- A `CRASH.DMP` fragmented into more than 64 pieces is not used.
- The internal disk and its EFI System Partition are **never** written. The
  ESP is the partition a stray write makes unbootable, and the kernel has no
  AHCI or NVMe driver to reach it anyway.

## Forcing a fault

`crashtest=<name>` on the kernel command line raises a fault once the
interface has brought up USB and handed the dumper its stick, so the forced
dump reaches the stick as well as serial. The text-mode console, which brings
up no USB, raises it just before it starts:

| Name | Fault | Path it proves |
|---|---|---|
| `de` | `#DE`, `div` by zero | a plain exception on the current stack |
| `pf` | `#PF`, read at 512 GiB (unmapped) | IST2 |
| `gp` | `#GP`, non-canonical read | |
| `ud` | `#UD`, `ud2` | |
| `so` | `#PF` on the stack guard, by recursion | IST2 with RSP in the guard |
| `df` | `#DF`: RSP made non-canonical, then a push | IST1: without it, a triple fault |
| `panic` | a Rust `panic!` | a software panic, no exception |

The debug ISO has a GRUB entry for each. On the release ISO, press `e` on the
entry and append the argument to the `multiboot2` line. Under QEMU,
`build.sh gdb x86_64 crashtest=df` builds an ISO that passes it and boots it
as a USB stick (see below). QEMU's own `-kernel` loader gives no framebuffer,
so it only reaches the text-mode console and the serial copy.

A fault that reaches the dump ends with QEMU still running and the stop
screen up. A triple fault under `-no-reboot` ends with QEMU exiting instead,
and with `-d cpu_reset` a third `CPU Reset` line in the log after the two at
power-on.

## Debugging under GDB

```console
$ packaging/baremetal/build.sh debug            # -O0 -g + frame pointers → build/baremetal-debug/
$ packaging/baremetal/build.sh gdb x86_64       # boots the debug ISO, stopped for GDB
$ packaging/baremetal/build.sh gdb x86_64 crashtest=df
$ gdb -x packaging/baremetal/gdb/x86_64.gdb     # in another terminal, from the repo root
```

The debug build is Cargo's dev profile (`-O0`, full DWARF) with
`force-frame-pointers=yes`, passed through `--config`. RUSTFLAGS would not
work: it replaces the target's rustflags in `.cargo/config.toml`, and the
kernel needs those.

`gdb` mode starts QEMU with `-s -S -no-reboot -d int,cpu_reset`, stopped at
the reset vector. The accelerator follows `accel_for`: KVM for an x86_64
guest on an x86_64 host, TCG anywhere else. Under KVM, `-d int` logs nothing,
because the exceptions are delivered by the CPU, not by QEMU. A triple fault
still shows, as QEMU exiting and an extra `CPU Reset`.

The ISO is booted **as a USB stick**, from a copy (`gdb-stick.img`) so
nothing in `build/` is written. That is how it runs on hardware, and it makes
the stick the dump's USB target. The serial output is shown and saved to
`build/baremetal-debug/serial.log`. When QEMU exits, the dump is extracted
from the serial log and also read back from the stick's `CRASH.DMP`. The two
are compared. `QEMU_DISPLAY=none` runs it without a window.

`packaging/baremetal/gdb/x86_64.gdb` works like this:

- It sets the architecture to `i386:x86-64` before connecting. The kernel
  enters in 32-bit mode, but QEMU's stub sends 64-bit registers.
- It stops at `kmain` with a **hardware** breakpoint. At the reset vector the
  kernel is not in memory yet, and the loader would copy it over a software
  breakpoint's `int3`.
- It then sets breakpoints on `nanochrono_x86_exception` (every CPU
  exception), `rust_begin_unwind` (the panic handler),
  `crashdump::build_from` (the dump writer) and `input::Input::keystroke`.
  The kernel has no IRQ1 handler: it polls with interrupts masked, and every
  PS/2 key byte goes through that decoder.
- It defines `nc-frame` (the trap frame), `nc-where` (the function, source
  line and instructions at the faulting RIP) and `nc-key` (the scan code).
  GDB is in Rust mode, so a field through a pointer is `(*frame).rip`.

Verified under KVM on an x86_64 host:

- `crashtest=gp` stops in the exception handler with `rax=0x8000000000000000`
  in the frame. The dump writer's return value starts with `DUMP`.
- `crashtest=df` stops in the handler with RSP in `nc_ist1_bottom + 32128`,
  on the IST1 stack. `nc-where` points at the `push %rax`. The dump's trace
  reads `CrashTest::raise → kmain → long_mode_start`.
- A key sent to the GUI stops in `Input::keystroke` with `byte=0x05` (the
  `4` key), then `0x85` (its release). The trace runs through `Input::poll`,
  `gui_frame::run` and `kmain`.
- `crashtest=df` booted as a USB stick: the dump is written from the IST1
  stack by `write_to_usb → write_block → bot → bulk → wait_event`. At that
  deepest point RSP is at `nc_ist1_bottom + 27312`, so the `-O0` build uses
  about 5.4 KiB of IST1's 32. The block written is inside the boot stick's
  own `NANOCRASH` partition. The copy read back from the stick is identical
  to the serial one.
- Tracing the stick's enumeration step by step (a GDB Python script with a
  `FinishBreakpoint` on every call) is how the one real bug on this path was
  found. The port had been enumerated twice, once for HID and once for
  storage, and Address Device on a port another slot still held came back
  with completion code 5, TRB Error. Each port is now enumerated once, and
  every device not kept has its slot disabled.

## The release build

`packaging/baremetal/build.sh [arch...]` builds `--release` (the crate's
release profile: optimised, `panic = "abort"`, no debug information). It
strips the kernel that goes into the ISO and keeps the symbol table in
`nanochrono-kernel.sym.elf`.
