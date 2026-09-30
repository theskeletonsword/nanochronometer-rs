# SPDX-License-Identifier: Apache-2.0
#
# Attaches to `packaging/baremetal/build.sh gdb x86_64`, which leaves QEMU
# stopped at the reset vector with a GDB stub on localhost:1234. From the
# repository root:
#
#   gdb -x packaging/baremetal/gdb/x86_64.gdb
#
# Stops once at `kmain`, then arms breakpoints on the paths a fault and a key
# press take, and lets the kernel run. At a stop: `bt`, `info registers`;
# in the exception handler `nc-frame` and `nc-where`; in the keyboard decoder
# `nc-key`.

set pagination off
set confirm off
# The kernel is ELF64 but entered in 32-bit mode. QEMU's x86_64 stub always
# sends the 64-bit register file; GDB has to expect it before it connects, or
# it rejects the reply as too long.
set architecture i386:x86-64
file build/baremetal-debug/x86_64/nanochrono-kernel.elf
target remote localhost:1234

# A hardware breakpoint: at the reset vector the kernel is not in memory yet.
# GRUB, or QEMU's multiboot loader, copies it there later — over the `int3`
# a software breakpoint would have planted.
hbreak kmain
continue
delete

# The image is in place: software breakpoints from here on.

# Every CPU exception, with the vector, the error code and all the general
# registers at the fault in `*frame` (see `nc-frame`).
break nanochrono_x86_exception
# The panic handler, and the crash-dump writer it calls.
break rust_begin_unwind
break nanochrono_baremetal::crashdump::build_from
# The keyboard. There is no IRQ1 handler to break in: the kernel polls with
# interrupts masked (see input.rs), so every PS/2 key byte reaches this
# decoder instead.
break nanochrono_baremetal::input::Input::keystroke

define nc-frame
  print/x *frame
end
document nc-frame
The trap frame in nanochrono_x86_exception: general registers, vector,
error code, and the RIP/CS/RFLAGS/RSP/SS the CPU pushed.
end

# GDB is in Rust mode here, so a field through a pointer is `(*frame).rip`,
# not C's `frame->rip`.
define nc-where
  info symbol (*frame).rip
  list *(*frame).rip
  x/4i (*frame).rip
end
document nc-where
Where the fault happened, from nanochrono_x86_exception: the function and
source line of the saved RIP, and the instructions there. `bt` cannot show
it — it stops at isr_common, which has no unwind information.
end

define nc-key
  print/x byte
end
document nc-key
The byte Input::keystroke was handed: a set 1 (or set 2) scan code, or a
prefix (0xE0, 0xE1, 0xF0).
end

continue
