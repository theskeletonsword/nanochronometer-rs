#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# User-mode client for the NanoChronometer Windows driver.
#
# The driver probes the hypervisor ONCE, when it starts, and caches the
# result: a plain query returns that cache and never makes the VM exit. On a
# cloud host (Azure, GCP, AWS, Vultr...) a guest that exits in a loop reads as
# abuse and can be throttled or banned, which is why re-probing is rationed.
#
# Usage (on the target Windows machine):
#   python query.py                 # the cached report
#   python query.py --wait          # retry while the driver comes up
#   python query.py --reprobe       # run the probes again;
#                                   # refused for 10 s after the last probe
#   python query.py --cooldown 0    # remove that wait — YOU
#                                   # assume the provider's reaction
#
# Every call needs an elevated Administrator prompt: the driver refuses to open
# for anyone else (the report carries a physical address, and --cooldown 0
# turns re-probing into a stream of VM exits).

import argparse
import ctypes
import sys
import time
from ctypes import wintypes

FILE_DEVICE_UNKNOWN = 0x22
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
FILE_WRITE_ACCESS = 2


def ctl_code(function: int, access: int) -> int:
    return (FILE_DEVICE_UNKNOWN << 16) | (access << 14) | (function << 2) | METHOD_BUFFERED


IOCTL_REPORT = ctl_code(0x801, FILE_ANY_ACCESS)  # 0x222004
IOCTL_REPROBE = ctl_code(0x802, FILE_WRITE_ACCESS)  # 0x22A008
IOCTL_SET_COOLDOWN = ctl_code(0x803, FILE_WRITE_ACCESS)  # 0x22A00C

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
ERROR_BUSY = 170
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

BAN_WARNING = (
    "WARNING: re-probe cooldown OFF. Every re-probe makes the guest exit to its "
    "hypervisor; repeated exits on a cloud VM (Azure, GCP, AWS, Vultr...) can look "
    "like an attack and get the instance throttled or banned. YOU assume that risk."
)


def kernel32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Without these, ctypes returns HANDLE as a C int and truncates it on
    # 64-bit Windows.
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    k32.DeviceIoControl.restype = wintypes.BOOL
    k32.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    return k32


def open_device(k32, device: str, access: int, tries: int = 1, delay: float = 0.0):
    for attempt in range(tries):
        h = k32.CreateFileW(device, access, 0, None, OPEN_EXISTING, 0, None)
        if h not in (None, INVALID_HANDLE_VALUE):
            return h
        if attempt + 1 < tries:
            time.sleep(delay)
    what = "is the driver loaded?" if access == 0 else "writing needs Administrator"
    sys.exit(f"error: cannot open {device} ({what}; GetLastError {ctypes.get_last_error()})")


def control(k32, h, code: int, inbuf: bytes = b"", out_len: int = 0) -> bytes:
    returned = wintypes.DWORD(0)
    size = max(len(inbuf), out_len, 1)
    buf = ctypes.create_string_buffer(inbuf, size)
    ok = k32.DeviceIoControl(
        h, code,
        buf if inbuf else None, len(inbuf),
        buf if out_len else None, out_len,
        ctypes.byref(returned), None,
    )
    if not ok:
        err = ctypes.get_last_error()
        if err == ERROR_BUSY:
            sys.exit("refused: the driver is still cooling down (one re-probe per 10 s)")
        sys.exit(f"error: DeviceIoControl {code:#x} failed (GetLastError {err})")
    return buf.raw[: returned.value]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default=r"\\.\NanoChronometer")
    ap.add_argument("--wait", action="store_true", help="poll until available")
    ap.add_argument("--reprobe", action="store_true",
                    help="run the hypervisor probes again (refused within the cooldown)")
    ap.add_argument("--cooldown", type=int, metavar="SECONDS",
                    help="set the re-probe cooldown; 0 disables it at your own risk")
    args = ap.parse_args()

    k32 = kernel32()
    tries = 60 if args.wait else 1

    if args.cooldown is not None or args.reprobe:
        h = open_device(k32, args.device, GENERIC_READ | GENERIC_WRITE, tries, 0.5)
        try:
            if args.cooldown is not None:
                if args.cooldown < 0:
                    sys.exit("error: the cooldown is a number of seconds, 0 or more")
                if args.cooldown == 0:
                    print(BAN_WARNING, file=sys.stderr)
                control(k32, h, IOCTL_SET_COOLDOWN, args.cooldown.to_bytes(4, "little"))
                print(f"cooldown = {args.cooldown} s")
            if args.reprobe:
                control(k32, h, IOCTL_REPROBE)
                print("re-probed")
        finally:
            k32.CloseHandle(h)

    h = open_device(k32, args.device, 0, tries, 0.5)
    try:
        report = control(k32, h, IOCTL_REPORT, out_len=2048)
        print(report.decode("utf-8", "replace"), end="")
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    main()
