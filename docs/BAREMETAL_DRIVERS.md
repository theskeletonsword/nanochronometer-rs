# Bare-metal drivers: what is here, and what is not

The freestanding build talks to four things: a display, a keyboard, a pointer,
and the power controller. This is what each one does, and — where the answer
is "nothing" — why.

FreeBSD's source tree was the reference for the
input path. No code was copied; the register names and the initialisation
order follow `sys/dev/atkbdc/atkbdcreg.h` and `psm.c` so the two can be read
side by side.

---

## Display — generic, and deliberately so

**Status: working.** Verified under QEMU with KVM at 1920×1200×32 booted from
the ISO, and at 800×600×32 on a machine that offers nothing better.

There is no vendor driver here and there should not be one. The kernel asks
the loader for a linear framebuffer through the multiboot2 header, and the
loader gets it from the firmware — VBE on a BIOS machine, GOP on a UEFI one.
The firmware talks to the card; the kernel gets an address, a pitch, a size
and a pixel format, and writes pixels.

That **is** the generic path, and it is generic in the way that matters:

| | Firmware framebuffer | Native driver |
|---|---|---|
| Intel integrated | works | needs an i915 driver |
| AMD integrated / discrete | works | needs an amdgpu driver |
| NVIDIA discrete | works | needs nouveau or the blob |
| A card released next year | works | needs a new driver |

A "generic driver for integrated and dedicated cards" that talks to hardware
directly does not exist, because there is no common register interface to talk
to. What exists is the firmware's mode-setting interface, which is what this
uses. The cost is that the mode is fixed at boot and there is no acceleration
— neither of which matters for drawing a static readout.

The one hardware-specific thing the kernel does is map the framebuffer:
firmware commonly places it high in MMIO space (QEMU's standard VGA lands near
`0xFD000000`), so `boot32.S` identity-maps the address space the framebuffer
can appear in, with everything above the first gigabyte marked uncached.

### Getting a mode out of the loader at all

Two things about GRUB's handover are not obvious, and both look like a hang
rather than a mode problem:

**`gfxpayload=keep` keeps the mode GRUB is *currently in*.** Without
`terminal_output gfxterm`, GRUB draws its own menu on the VGA text console, so
"keep" hands the kernel a text mode — which is not a linear framebuffer, which
is a kernel with nothing to draw on. The `grub.cfg` loads `gfxterm` and
switches output to it first, which is what makes `gfxmode` take effect.

**GRUB's `multiboot2` command overwrites `gfxpayload`.** It rewrites the
variable from the framebuffer tag in the kernel's own multiboot header, and a
tag asking the loader to choose becomes `gfxpayload=auto` — discarding
whatever was set before it. `auto` then lands on the video driver's default,
which on a BIOS machine is 800×600 regardless of what the panel can do. The
mode is not programmed until `boot`, so the `grub.cfg` sets `gfxpayload=keep`
**after** the `multiboot2` line, which is what sticks.

`gfxmode` carries a preference list rather than `auto` alone, stopping at
1920×1200 deliberately — see below.

### The back buffer

Firmware framebuffers are mapped uncached, because MMIO that is cached is MMIO
that does not work. A store to one is on the order of a hundred times slower
than a store to RAM, and drawing a glyph means *reading* every pixel it covers
to blend against.

So nothing is drawn on the device directly. `framebuffer.rs` keeps a
1920×1200×32 back buffer in `.bss` — about nine megabytes, zeroed once by the
boot stub — draws into that, and copies out only the rectangle that changed.
That is what makes an animated interface possible here: a full-screen uncached
redraw on a 1080p panel is tens of milliseconds, and a frame rate in single
digits is not an animation.

A mode larger than the buffer is not an error. The interface falls back to
drawing straight onto the device, which works and flickers, and the machine
card says which of the two is in use. The `gfxmode` list stops at 1920×1200 so
this fallback is not taken on a laptop that could have composited at a
slightly smaller mode.

---

## Keyboard and pointer — three stacks, brought up in order

**Status: working.** Verified under QEMU with KVM: PS/2 keyboard and mouse,
xHCI enumeration, a software cursor and clickable controls.

There are three stacks, and the kernel brings up as many as it needs:

`crates/nanochrono-baremetal/src/input.rs` drives the 8042 controller —
a presence probe (ports that float read `0xFF`), both ports disabled and the
output buffer drained, controller command byte, both port resets, explicit
enable of scanning, the IntelliMouse "magic knock" to unlock 4-byte packets,
packet resynchronisation on bit 3, and nine-bit sign extension on the
movement deltas. Every wait is timed on the counter, with an `io_wait` (a
write to port `0x80`) between status reads. Keys: the `0xE0` prefix, the fake
Shifts around extended keys and the Pause sequence are decoded, and command
replies (`0xFA`, `0xFE`) are not taken for keys. The kernel polls with
interrupts masked, so there is no IRQ1 handler and no EOI to send.

`crates/nanochrono-baremetal/src/xhci.rs` drives an xHCI controller found
through PCI — reset, DCBAA, command/event/transfer rings, Enable Slot, Address
Device, Configure Endpoint, and HID boot protocol over an interrupt IN
endpoint.

`crates/nanochrono-baremetal/src/i2c_hid.rs` reaches a built-in touchpad that
is on neither bus, by reading the firmware's AML. It is tried last, and only
for a pointer — see below.

### Why both, and not one as a fallback

An earlier version tried USB only when the 8042 reported **nothing at all**.
On a laptop that is never true: the built-in keyboard reaches the 8042 through
the embedded controller and answers every probe, so USB was skipped and a
plugged-in mouse was never found. A keyboard that works and a pointer that
does not is exactly what a notebook reports.

Three specific things this got wrong, all of which are fixed:

| Symptom | Cause |
|---|---|
| Keyboard detected, no keys arrive | Scanning was never enabled. The specification says a keyboard resumes scanning after a reset; enough embedded controllers do not that it has to be asked for. A missed reset is also no longer taken as an absent device — an EC that swallows the reset still delivers scancodes |
| Pointer never found on real hardware | USB was only tried when the 8042 found nothing |
| USB brought up but no input | Only the **first connected port** was enumerated. On a laptop that port is usually the webcam, the Bluetooth radio or the fingerprint reader. Every connected port is now tried, and a keyboard *and* a pointer are both kept |
| Boot stalls at "detecting input devices", then no key works (a UEFI PC with no 8042) | With no 8042 and no firmware emulating one, ports `0x60`/`0x64` float and read `0xFF`: "output full" and "input full" at once. Every wait spun its full million reads, over a minute in all, and afterwards `poll` read `0xFF` from the port forever and returned before USB was ever asked — the USB keyboard was enumerated and never read. The 8042 is now probed first and skipped when it is not there, waits are timed, and a PS/2 byte that completes no event no longer ends the turn |
| Interface unresponsive | `poll_report` waited for the interrupt transfer to complete. A keyboard with no key held never completes one, so every frame paid the full timeout. Polling is now non-blocking: the transfer is queued once and left outstanding, and each call drains whatever the controller has posted |

Where firmware translates USB to the 8042 — "legacy USB support", on by
default on most machines with a BIOS-compatible mode — the PS/2 view is
preferred, so a keypress that arrives by both routes is delivered once.

### Testing the USB path

Under QEMU the emulated 8042 always answers, so it always claims both roles
and the USB stack is never reached — which means the path a real notebook
depends on is the one an emulator cannot exercise. The crate carries a
test-only feature for that:

```console
$ cargo +nightly build --release --target x86_64-nanochrono-none \
      --features simd,force-usb
$ qemu-system-x86_64 -enable-kvm -cpu host -cdrom test.iso \
      -device qemu-xhci -device usb-kbd -device usb-mouse
```

`force-usb` skips the 8042 entirely. It is off by default and never in a
release build. With it, the interface reports `xhci: up`, `usb keyboard: yes`
and `usb pointer: yes` — two devices on two ports — and both deliver events.

A closer model of a UEFI machine with no legacy controller needs no feature
at all: QEMU can leave the 8042 out, and its ports then float exactly as they
do on such a PC.

```console
$ qemu-system-x86_64 -machine q35,i8042=off -accel kvm -cpu host \
      -cdrom build/baremetal/nanochronometer_x86_64.iso \
      -device qemu-xhci -device usb-kbd
```

The USB panel then reads `8042 bytes: no 8042 - usb/i2c only` and the keys
work. Before the fix this configuration reproduced the fault above: the panel
showed `FF FF FF FF FF FF FF FF` and no key did anything.

### The third stack: I2C-HID, and the AML interpreter under it

**Status: implemented. Verified in parts — see below.**

Many recent notebooks put the built-in touchpad on **I2C-HID**, which is on
neither of the buses above. It is the least discoverable device in the
machine: an I2C bus has no enumeration at all, so a master can only talk to an
address it already knows, and the address is written in the firmware's AML
bytecode and nowhere else.

Reaching one is a chain of four, and every link has to hold:

| Step | Where |
|---|---|
| Walk the DSDT for a `PNP0C50` device, read its `_CRS` and run its `_DSM` | `nanochrono-core/src/aml.rs` |
| Match the controller the `_CRS` named to a PCI device, through `_ADR` | `i2c_hid.rs` |
| Drive that controller — Intel LPSS / Synopsys DesignWare | `i2c.rs` |
| Parse the report descriptor and find the pointer report | `nanochrono-core/src/hid_report.rs` |

#### The AML interpreter

ACPICA, which Linux and FreeBSD both use, is around a hundred thousand lines.
It implements the whole language because a general-purpose kernel must — sleep
methods, thermal zones, operation regions backed by embedded controllers.

None of that is needed here, and the reason is that AML's encoding is
**self-delimiting**: every object carries its own length, so an object the
reader does not understand costs nothing to step over. That turns "interpret
ACPI" into two much smaller problems:

* **Walking the namespace** is parsing, not execution. Scopes and devices
  nest; each device carries a `_HID` and often a `_CID`. Finding "the device
  whose compatible ID is `PNP0C50`" is a tree walk.
* **Reading `_CRS`** is usually reading a `Name` holding a resource template —
  a byte buffer of self-delimiting descriptors, one of which is the
  `I2cSerialBus` carrying the slave address and the controller's path.
* **Running `_DSM`** is the only part that executes firmware, and its shape is
  narrow: compare a UUID, compare a function index, return a constant. The
  interpreter covers `If`/`Else`/`While`/`Return`, the logical and arithmetic
  operators, arguments and locals — and **fails rather than guesses** on
  anything else.

That last point is the design. A `_DSM` misread hands back a wrong register
address, and a wrong address on an I2C bus is not a wrong answer — it is a
transaction with whatever else is on that bus.

#### What is verified, and what is not

Honest split, because these are different kinds of confidence:

| Piece | How it is verified |
|---|---|
| AML encoding: package lengths, name strings, EISA IDs, the namespace walk | Unit tests over hand-assembled bytecode that states the encoding explicitly |
| `_CRS` resource templates, `_DSM` evaluation | Unit tests, including a `_DSM` that returns a *different* register so a reader that defaulted would fail |
| Robustness against malformed firmware | Every prefix of a table is walked; none may panic or read past the end |
| Namespace walk over real machine-generated firmware | **Runs at ring 0 under QEMU: 8617-byte DSDT, 53 devices, 18 with identifiers.** Printed by the self-test on every boot |
| HID report descriptor parsing | Unit tests against a **real Elan I2C-HID touchpad's 675-byte descriptor**, committed as a fixture. It picks report 1 (the relative mouse) and rejects report 84 (the digitizer) |
| DesignWare I2C transfers | **Not executed.** There is no emulator for an LPSS I2C controller with a touchpad behind it |
| The I2C-HID handshake itself | **Not executed**, for the same reason |

The last two are written from FreeBSD's `ig4_iic.c` and `iichid.c` against the
same hardware, and they compile — which is not the same as working. The
self-test prints what each step found, so a machine that gets part way says
where it stopped.

#### Why the device is in mouse mode

A Windows Precision Touchpad declares two collections in one descriptor: a
digitizer reporting absolute contacts, and an ordinary relative **mouse**. It
sends the mouse reports until the host writes an Input Mode feature report
asking for the other — which desktop drivers do, because they want gestures.

This deliberately does not. The interface wants a cursor, and the mouse
collection *is* a cursor, already integrated by the device's own firmware. No
contact tracking, no gesture recognition, and no report-descriptor machinery
beyond finding which report it is.

#### Polled, not interrupt-driven

The `_CRS` also declares a `GpioInt`: the pin the device raises when it has a
report. Servicing it would need a GPIO controller driver *and* an interrupt
controller, and this kernel has neither by design — a handler running between
two counter reads becomes part of what the chronometer measures.

The input register is read on a schedule instead. The specification defines
what that returns when nothing is waiting — a length of zero — which is what
makes polling legal rather than a guess.

### EHCI, OHCI and UHCI

Detected through PCI and reported, not driven. A machine whose only input is
behind a USB 1.1 or 2.0 controller falls back to PS/2.

### BadUSB

BadUSB is a USB device that declares itself a keyboard and types. Now that
there *is* a USB stack, the structural argument no longer applies and the
policy has to be stated:

1. **Enumerate once, at boot.** The kernel scans ports during `Input::init()`
   and never re-scans. A keystroke injector's entire method is arriving after
   the system has decided what is attached; a device plugged in later is not
   enumerated at all.
2. **Boot protocol only.** No report-descriptor parser runs, so a device
   cannot describe itself into a capability. A device that is not a
   boot-protocol keyboard or pointer is addressed and then ignored.
3. **Two devices, and no more.** `MAX_DEVICES` is 2. A hub full of HID
   devices cannot exhaust the driver's state.
4. **No storage class, no filesystem.** A composite device claiming mass
   storage gets nothing: there is no bulk transport and no filesystem to
   reach.

What is *not* claimed: this does not defend against a malicious device present
at boot. Nothing in the protocol distinguishes one, and a keyboard is a
keyboard. The bounded surface is the point — the kernel reads at most two
8-byte reports and acts on a fixed key table.

---

## Performance counters — the PMU, driven directly

**Status: working where the emulated hardware counts, and truthful where it
does not.** `crates/nanochrono-baremetal/src/pmu.rs` programs the
performance-monitoring unit itself — there is no kernel to ask, this *is* ring
0 — then reads it. The decode lives in `crates/nanochrono-core/src/pmu_leaf.rs`
so the layouts can be unit-tested from a host.

The register interface is decided by vendor **before** any MSR is written, and
the reason is a dead machine rather than a wrong number: `WRMSR` to an MSR the
part does not implement raises `#GP`, and this kernel has no interrupt
descriptor table to take it. So the order is fixed — vendor string from
`CPUID.0H`, then the interface the vendor implies, then the enumeration leaf:

| Interface | Where the counters live | Read with |
|---|---|---|
| Intel architectural | `IA32_PERFEVTSEL`/`IA32_PMC` + fixed counters, `CPUID.0AH` | `RDPMC` |
| AMD core | `0xC0010200`, `(select, counter)` pairs | `RDMSR` |
| AMD K8 | `0xC0010000`, four counters | `RDMSR` |
| AArch64 | `PMCCNTR_EL0` + `PMCR_EL0`/`PMCNTENSET_EL0` | `MRS` |

Cycles come from the fixed core-clock counter on Intel and AArch64, and from
AMD's `CPU Clocks not Halted` event (`0x76`) on a general-purpose counter.
Instructions retired come from fixed counter 0 on Intel and from AMD's
`Retired Instructions` event (`0xC0`) on a second general-purpose counter when
one exists — both `0x76` and `0xC0` are from AMD's BKDG, publication 32559.

**Nothing is reported until a counter has been seen to move.** Programming the
PMU can succeed while the counter stays frozen — firmware or a hypervisor can
leave one latched, a virtualizer can swallow the writes — and `RDPMC` then
returns a fixed, plausible-looking zero forever. So `enable` runs a short
dependent chain and checks the delta. An AMD counter whose write was accepted
by a virtualizer but never counted reports `none`, not garbage; that is the
line `counter route: none` in the self-test.

Two details that the FreeBSD driver forced and the manuals would not have:

- **AMD reads go through `RDMSR`, not `RDPMC`.** `RDPMC` is optional in a way
  that only faults when used: QEMU's TCG raises `#UD` for it unconditionally,
  and this kernel has no IDT — so the first read would be a reset. The MSR the
  counter was just written to is necessarily implemented, so it is read
  instead. Intel keeps `RDPMC`, where `CPUID.0AH` reporting a PMU at all
  already proves one exists.
- **Only implemented bits are written to `IA32_PERF_GLOBAL_OVF_CTRL`.** The
  register is mostly reserved, and a reserved bit set is `#GP` on the write —
  which works under an emulator and kills a laptop. Clearing overflow is built
  from what the leaf reports, never from `u64::MAX`.

### What an emulator can and cannot prove

| Emulation | What the self-test reports | What it proves |
|---|---|---|
| KVM, Intel (`-cpu host,pmu=on`) | `CPUID.0AH` version 0, skipping — *if the host does not expose the PMU* | the skip path; vendor dispatch; no MSR written to a part that reports none |
| TCG, AMD (`-cpu EPYC`) | AMD K8 interface, counters enumerated, `counter route: none` | AMD detection; evsel/ctr MSR writes fault-free; the "did it move" gate |
| TCG, AArch64 (`-cpu max`) | `counter route: fixed`, a real cycles number | the counting path end to end — `PMCCNTR_EL0` *does* count under TCG |

A real Intel part under KVM with the PMU exposed, and real AMD silicon, would
exercise the count-and-read paths the emulators leave cold. An AMD counter
that never moved under TCG is the driver being right about a lie, not a
failure to try.

### Reference terms

FreeBSD's `sys/dev/hwpmc/hwpmc_amd.c` and `hwpmc_amd.h` supplied the register
addresses, the `(select, counter)` pairing, the 48-bit width, the enumeration
order and the event-select encoding. They are BSD-2-Clause, and their
attribution is in `NOTICE`. Linux's `arch/x86/events/amd/core.c` was read for
facts the FreeBSD driver leaves out — which counters a family-15h event class
may use — and none of its expression crossed the licence boundary: this driver
has no event table, because a chronometer needs two events, not three hundred.

### The base counter on AArch64: virtual by default, physical on demand

Separate from the PMU, there is the question of *which* counter a freestanding
kernel reads for the interface's own time — the timestamp feeding the clock,
the readout and the frame pacing. On AArch64 there are two:

| Counter | What it reads | Safe under a hypervisor |
|---|---|---|
| `CNTVCT_EL0` (virtual) | `CNTPCT_EL0` minus `CNTVOFF_EL2` | yes — a guest sees a timeline that starts when it did |
| `CNTPCT_EL0` (physical) | what the hardware really ticks | no — it exposes and splices together the host's real timeline |

The default is the **virtual** counter. It is the safe choice for any kernel
that might run inside a VM, where the physical counter would let a guest peek
at — and, worse, blend intervals across — the host's actual clock. Bare metal
has no EL2 to set an offset, so on real silicon the physical counter is what
the hardware actually ticks and is the one to use there.

The selection is a mutable flag — [`crate::arch::set_counter_source`] — backing
the *Enable Physical Counter* interface toggle. It is reported by the
self-test (`counter: cntvct_el0` / `cntpct_el0`), with
`warning: physical counter — not recommended inside a VM` printed when the
physical one is selected. In the C ABI it is reached through
`nc_bm_counter_source` and `nc_bm_counter_source_set`, so a loader can opt in
to the physical counter on bare metal and leave the virtual one in force under
a hypervisor. Both reads are wrapped in `DSB`+`ISB` so the sample lands at the
end of the bracketed work; see
[`nanochrono_core::arch::aarch64::cntvct_ordered`] and
[`nanochrono_core::arch::aarch64::cntpct_ordered`].

---

## Filesystems — not here

**Status: not implemented, and not needed.**

The kernel does not need USB storage to be *booted from* USB. The ISO is a
hybrid image (see below); firmware and GRUB read the medium, and by the time
Rust runs the kernel is in memory and the medium is not touched again.

FAT32 and exFAT would be needed only to read files at run time, and there are
no files to read: the typeface is compiled in, and every measurement is taken
rather than loaded.

---

## Boot media

The ISO `packaging/baremetal/build.sh` produces is a **hybrid image**,
verified as such:

```console
$ python3 - <<'PY'
d = open('nanochrono.iso','rb').read(2048)
print('MBR signature:', d[510:512] == b'\x55\xaa')
PY
MBR signature: True

$ xorriso -indev nanochrono.iso -report_el_torito plain
El Torito boot img :   1  BIOS  y   none  ...
El Torito boot img :   2  UEFI  y   none  ...
```

An MBR with a boot signature and a protective partition, plus El Torito images
for **both** BIOS and UEFI. That is what each tool needs:

| Tool | How it uses the image |
|---|---|
| `dd` / Rufus in DD mode | Byte-for-byte to the stick; the MBR makes it bootable |
| Rufus in ISO mode | Extracts and installs its own loader; GRUB config is found |
| Ventoy | Chainloads the ISO from its own menu |
| YUMI, UNetbootin | Extract and chainload |

`dd if=nanochrono.iso of=/dev/sdX bs=4M status=progress` is the simplest path
and needs nothing else.

---

## Where these drivers came from, and the two licences involved

Every driver on this page talks to hardware with no portable interface, and
none of it was written from the register manuals alone. Two existing driver
trees were read while writing them. They were **not** read on the same terms,
and the difference is a licensing one, not a technical one.

### FreeBSD — the model, and it may be imitated

FreeBSD's drivers are BSD-2-Clause and BSD-3-Clause. Both are permissive and
both flow into an Apache-2.0 project in this direction. So where FreeBSD had
already worked out a register layout, a bit name, or the order a chip wants
its bring-up steps in, that form was reproduced here rather than reinvented:

| This file | FreeBSD source | What was taken |
|---|---|---|
| `src/i2c.rs` | `sys/dev/ichiic/ig4_reg.h`, `ig4_iic.c` | DesignWare/LPSS register offsets, `IG4_*` bit names, the reset sequence |
| `src/i2c_hid.rs` | `sys/dev/iicbus/iichid.c` | The power/reset order: `SET_POWER(ON)`, a millisecond, `RESET`, then wait for the zero-length acknowledgement |
| `src/xhci.rs` | `sys/dev/usb/controller/xhcireg.h`, `xhci_pci.c` | `XHCI_HCS2_SPB_MAX`'s split-field expression, the `BIOS_SEM`/`OS_SEM` byte handoff |
| `src/input.rs` | `sys/dev/atkbdc/atkbdc.c` | The 8042 command set and the order the controller wants it in |
| `../nanochrono-core/src/hid_report.rs` | `sys/dev/hid/hid.c` | The report-descriptor walk: locate fields, then extract by bit offset |

The condition those licences attach is attribution, and it is discharged in
`NOTICE`, which names each file and its authors. The BSD-3-Clause sources
(`ig4_*`, `atkbdc.c`) add a no-endorsement clause, also recorded there.

### What was innovated, because neither kernel has it

Reading Linux is not only about cross-checking registers. Its drivers are
newer than FreeBSD's and they handle situations FreeBSD's do not, and seeing
*which* situations is a fact about the hardware, not a piece of GPL
expression. Three of those became original work here, in a shape neither
kernel uses.

**A GPIO line read as a readiness signal, not serviced as an interrupt**
(`src/gpio.rs`). An I2C-HID device announces a waiting report by pulling a
GPIO pin; `_CRS` says which. Linux routes it to an interrupt controller and
sleeps. FreeBSD's `iichid` ignores GPIO entirely and polls the bus on a
timer. This kernel will not take interrupts — a handler between two counter
reads is part of what the chronometer would then be measuring — so it does
the third thing: it *reads* the pin, once per frame, and only touches the bus
when the pin says there is something there. Blind polling costs a thirty-byte
transfer at 400 kHz, about 700 µs, every frame regardless. One MMIO load
costs a few hundred nanoseconds and answers the same question.

**Finding the pad without a per-SoC table.** Both kernels convert an ACPI pin
number to a pad register through a hand-maintained table of pad groups; on a
part nobody has added, both fail. FreeBSD's tables for Alder Lake and Tiger
Lake H are ported here and used when they apply. When they do not, the driver
*learns* the pad instead: it samples every host-owned GPIO input before each
poll, labels the sample with what the poll then found, and keeps the pad whose
level always agrees with the outcome. A pad that never moves is eliminated by
the first disagreement; a pad that moves for its own reasons is eliminated as
soon as it moves at the wrong time. The answer is accepted only when exactly
one candidate survives, and it comes with the line's measured polarity rather
than the one `_CRS` claims.

**Reading the namespace the way firmware actually writes it.** Not innovation
— a set of gaps that had to close, all found the same way: by pointing the
reader at one real machine's tables and comparing what it found against what
was there. Every DSDT and SSDT differs from every other, so a reader validated
against one hand-built table has been shown almost nothing.

The measure used throughout was blunt and effective: count the raw `5B 82`
(`DeviceOp`) byte pairs in each table, and compare against the devices the walk
reports. Anything short is a derail.

| What was wrong | What it cost |
|---|---|
| SSDTs were never read at all | The whole namespace is the DSDT ∪ every SSDT. This machine has sixteen. |
| `If` blocks were stepped over | One 30 KB SSDT is two top-level `If`s containing **108 devices**; the walk found 0. |
| `CondRefOf` was an unknown opcode | It is the predicate of those `If`s. Not being able to step over it hid the bodies. |
| Statements ended the term list | Once inside conditionals the walk meets `Store`, `Notify`, `Release`. One `Store` hid every declaration after it. |
| `Scope (\_SB…)` was appended, not substituted | An absolute name *replaces* the enclosing scope. Appending produced paths past `MAX_PATH`, and the devices in them were dropped for having no nameable path. |
| `_ADR`/`_STA` inside `If` were invisible | See below — this is the one that broke the touchpad. |

Result on the reference machine: **255 → 499 devices** across the seventeen
tables, and the DSDT went from 221 to **343 of 343** raw `DeviceOp`s. Nothing
is missed.

**The conditional-member problem, and why it needs two answers.** An Intel LPSS
controller is declared once and configured two ways:

```asl
Device (I2C5)
{
    If (LEqual (IM05, 0x02)) {                              // ACPI-enumerated
        Method (_CRS, 0) { Return (I2CH (IC05)) }
        Name (_STA, 0x08)                                   // ← "not present"
    }
    If (LOr (LEqual (IM05, One), LEqual (IM05, Zero))) {     // PCI
        Method (_ADR, 0) { Return (0x00190001) }             // ← the address
    }
}
```

The `_ADR` that says where the controller sits on the PCI bus exists *only*
inside a conditional. So a lookup has to descend into `If` and `Else`. But the
other branch declares `_STA = 0x08` — bit 0 clear, meaning **not present** —
and nothing here can evaluate `IM05` to know that branch does not apply.
Descending naively finds the address and then throws the controller away.

So the lookup reports *where* it found a member. A conditional answer is good
enough for data — `_ADR`, `_CRS`, `_HID` — and not good enough for a claim
about whether the device exists: `present()` believes only an unconditional
`_STA`, and treats a conditional one the way ACPI treats a missing one.

Each table is walked as its own namespace rather than spliced into one. That is
not the whole of ACPI's model — a `Scope` in one table can add objects to a
device declared in another, and this will not see those — but it answers the
question being asked, and it needs no allocator. The self-test prints the root
table's inventory and the SSDT count, so "no SSDTs" and "SSDTs this could not
read" are different answers.

**Finding the device on the bus, rather than believing the firmware.** This
one was forced by real firmware. The machine this was developed against has a
touchpad node that supports four vendors and chooses at run time:

```asl
If (LEqual (TPTY, One))  { Store ("ELAN06FA", _HID); Store (0x15, BADR) }
If (LEqual (TPTY, 0x02)) { Store ("SYNA2BA6", _HID); Store (0x2C, BADR) }
If (LEqual (TPTY, 0x04)) { Store ("GXTP5100", _HID); Store (0x5D, BADR) }
If (LEqual (TPTY, 0x05)) { Store ("FTCS0038", _HID); Store (0x38, BADR) }
```

`_CRS` then builds its descriptor from `BADR` through a vendor helper method.
Without a full AML interpreter the only reachable descriptor is the plain
buffer the device also declares — and that buffer carries `0x2C`, the
*Synaptics* address, on a machine whose touchpad is the ELAN at `0x15`.
Trusting it addresses a device that is not there.

So the driver asks the bus. An I2C-HID descriptor is thirty bytes whose first
two fields are fixed by the specification and three of whose registers cannot
be zero, which makes it a strong enough acceptance test that a wrong address
or a wrong register is rejected rather than misread. Three rounds, cheapest
first: the firmware's address and register; the firmware's address with each
register the specification's examples use; then every address on the bus. A
NAK is reported immediately by the controller, so a full sweep is
milliseconds, and it only runs when the first two rounds have failed. Which
round succeeded is reported on screen — `(probed)`, `(found by scan)` — so a
number arrived at empirically never looks like one the firmware supplied.

### Linux — consulted, never imitated

Linux is GPL-2.0, which does not combine with Apache-2.0. `drivers/hid/i2c-hid/`
and `drivers/usb/` were read, and reading them was worth it — they are the most
thoroughly field-tested implementations of this hardware that exist, and they
document quirks no datasheet mentions. But what came back across that boundary
is only **facts about the hardware**: that a particular register exists, that a
device needs a settling delay after power-on, that some touchpads report a
bogus descriptor length. Facts about a machine are not copyrightable. The code
that expresses them is, and none of that expression is in this tree.

Concretely, that meant undoing work. An earlier draft of `src/xhci.rs` carried
Linux's `XHCI_LEGACY_DISABLE_SMI` mask spelled out as
`(0x7 << 1) | (0xFF << 5) | (0x7 << 17)`, and `src/i2c_hid.rs` carried Linux's
quirk timings and paraphrases of its comments. Both were removed and rewritten
from FreeBSD's form: the semaphore handoff in place of the SMI mask, `iichid`'s
timings in place of Linux's. Where the two kernels solve the same problem, the
FreeBSD version is the one written down here — not because it is better, but
because it is the one this project is allowed to keep.

The single exception is `kernel/linux/`, which *is* a Linux kernel module. It
is licensed `MIT OR GPL-2.0-only` for that reason, shares no source with the
rest of the project, and communicates only through a file in `/proc`. See
`NOTICE`.
