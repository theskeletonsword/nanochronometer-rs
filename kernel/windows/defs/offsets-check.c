/* SPDX-License-Identifier: MIT
 *
 * Offset check for the constants embedded in the Rust driver (src/nt.rs).
 * Compiled by the Makefile against the real mingw-w64 DDK headers for BOTH
 * x86_64 and ARM64. If any assertion fails the build aborts, so a mismatch
 * between the Rust mirror and the ABI is caught before linking.
 *
 * x86_64:  wdm.h natively (POINTER_ALIGNMENT pads the IO_STACK_LOCATION
 *          parameter block to offsets 8/24/32).
 * ARM64:   mingw wdm.h has no _M_ARM64 branch, so it must be built with
 *          -D_M_ARM=100 and -defs/armddk-shim in the include path. The IRP,
 *          DRIVER_OBJECT and DEVICE_OBJECT checks below hold there. The
 *          IO_STACK_LOCATION ones do NOT come from the header: mingw wraps
 *          that struct in pshpack4.h on every target but _AMD64_/_IA64_ (an
 *          x86-32 leftover), which the Microsoft WDK does not do for ARM64,
 *          so the header's answer (4/8/12/16) is wrong for real ARM64
 *          Windows. The ARM64 branch asserts the WDK layout on a mirror
 *          declared the way the WDK declares it instead.
 */
#include <stddef.h>
#include <ddk/wdm.h>

#define E(type, member, expect) \
    _Static_assert(offsetof(type, member) == (expect), #type "." #member " != " #expect)
#define S(type, expect) _Static_assert(sizeof(type) == (expect), "sizeof(" #type ") != " #expect)

#if defined(_M_AMD64)
/* IO_STACK_LOCATION_
   Parameters.DeviceIoControl start right after Major/Minor/Flags/Control
   re-aligned to pointer alignment on x64. */
E(IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength, 8);
E(IO_STACK_LOCATION, Parameters.DeviceIoControl.InputBufferLength, 16);
E(IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode, 24);
E(IO_STACK_LOCATION, Parameters.DeviceIoControl.Type3InputBuffer, 32);
S(IO_STACK_LOCATION, 72);
#elif defined(_M_ARM) || defined(_M_ARM64) || defined(_ARM64_)
/* ARM64, as the WDK lays it out: natural alignment, POINTER_ALIGNMENT = 8. */
struct wdk_arm64_isl_head {
    UCHAR MajorFunction, MinorFunction, Flags, Control;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG __attribute__((aligned(8))) InputBufferLength;
            ULONG __attribute__((aligned(8))) IoControlCode;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
        struct { PVOID Argument1, Argument2, Argument3, Argument4; } Others;
    } Parameters;
};
E(struct wdk_arm64_isl_head, Parameters.DeviceIoControl.OutputBufferLength, 8);
E(struct wdk_arm64_isl_head, Parameters.DeviceIoControl.InputBufferLength, 16);
E(struct wdk_arm64_isl_head, Parameters.DeviceIoControl.IoControlCode, 24);
E(struct wdk_arm64_isl_head, Parameters.DeviceIoControl.Type3InputBuffer, 32);
/* And proof the mingw header is the packed one, so this branch is needed. */
E(IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength, 4);
#else
#error "unsupported architecture for offsets-check.c"
#endif

/* IRP fields the driver reads. */
E(IRP, AssociatedIrp.SystemBuffer, 24);
E(IRP, IoStatus.Status, 48);
E(IRP, IoStatus.Information, 56);
E(IRP, Tail.Overlay.CurrentStackLocation, 184);
S(IRP, 208);

/* Called peripheral mirrors. */
E(DRIVER_OBJECT, DriverUnload, 104);
E(DRIVER_OBJECT, MajorFunction, 112);
S(DRIVER_OBJECT, 336);
E(DEVICE_OBJECT, Flags, 48);
E(DEVICE_OBJECT, DeviceExtension, 64);
S(DEVICE_OBJECT, 328);
S(UNICODE_STRING, 16);
S(IO_STATUS_BLOCK, 16);