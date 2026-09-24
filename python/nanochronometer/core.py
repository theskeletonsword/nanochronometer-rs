import ctypes
import os
import sys
from pathlib import Path

def _names():
    if sys.platform.startswith("win"):
        return ["nanochrono.dll"]
    if sys.platform == "darwin":
        return ["libnanochrono.dylib", "nanochrono.dylib"]
    return ["libnanochrono.so", "nanochrono.so"]

def load_library(path=None):
    if path:
        return ctypes.CDLL(str(path))
    roots = [Path(__file__).resolve().parent, Path.cwd()]
    env = os.environ.get("NANOCHRONO_LIB")
    if env:
        roots.insert(0, Path(env).resolve().parent)
        names = [Path(env).name]
    else:
        names = _names()
    for root in roots:
        for name in names:
            cand = root / name
            if cand.exists():
                return ctypes.CDLL(str(cand))
    for name in names:
        try:
            return ctypes.CDLL(name)
        except OSError:
            pass
    raise OSError("NanoChronometer native library not found; set NANOCHRONO_LIB")



class NanoClockSnapshot(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int), ("arch", ctypes.c_uint32), ("route", ctypes.c_uint32),
        ("best_simd_family", ctypes.c_uint32), ("backend", ctypes.c_uint32),
        # Explicit: see `_pad_backend` in include/nanochrono.h.
        ("_pad_backend", ctypes.c_uint32),
        ("unix_time_ns", ctypes.c_uint64), ("monotonic_ns", ctypes.c_uint64),
        ("process_time_ns", ctypes.c_uint64), ("thread_time_ns", ctypes.c_uint64),
        ("selected_raw_units", ctypes.c_uint64), ("selected_ns", ctypes.c_uint64),
        ("selected_overhead_units", ctypes.c_uint64),
        ("rdtsc_raw", ctypes.c_uint64), ("rdtsc_lfence", ctypes.c_uint64),
        ("rdtsc_mfence", ctypes.c_uint64), ("rdtscp_lfence", ctypes.c_uint64),
        ("rdtscp_aux", ctypes.c_uint32), ("_pad0", ctypes.c_uint32),
        ("arm64_cntfrq_el0", ctypes.c_uint64), ("arm64_cntvct_el0", ctypes.c_uint64),
        ("arm64_cntvct_isb", ctypes.c_uint64), ("arm64_cntvct_ns", ctypes.c_uint64),
        # perf_event_open thread cycles; occupies the slot 2.x used for
        # arm64_pmccntr_el0, which was removed (it traps unless privileged
        # and is not saved across context switches).
        ("perf_cycles", ctypes.c_uint64), ("perf_cycles_ns", ctypes.c_uint64),
        ("perf_available", ctypes.c_uint32), ("perf_status", ctypes.c_uint32),
        ("best_simd_counter", ctypes.c_uint64), ("best_simd_counter_ns", ctypes.c_uint64),
        ("native_overhead_cycles", ctypes.c_uint64), ("ffi_overhead_cycles", ctypes.c_uint64),
        ("dll_boundary_cycles", ctypes.c_uint64), ("wrapper_hint_cycles", ctypes.c_uint64),
    ]

class NanoChronometer:
    def __init__(self, library=None):
        self.lib = load_library(library)
        self.lib.nc_create.restype = ctypes.c_void_p
        self.lib.nc_destroy.argtypes = [ctypes.c_void_p]
        self.lib.nc_start.argtypes = [ctypes.c_void_p]
        self.lib.nc_elapsed_ns.argtypes = [ctypes.c_void_p]
        self.lib.nc_elapsed_ns.restype = ctypes.c_uint64
        self.lib.nc_measure_ffi_overhead_cycles.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.lib.nc_measure_ffi_overhead_cycles.restype = ctypes.c_uint64
        self.lib.nc_now_cycles.argtypes = [ctypes.c_void_p]
        self.lib.nc_now_cycles.restype = ctypes.c_uint64
        self.lib.nc_empty_call.restype = ctypes.c_uint64
        self.lib.nc_nanoclock_snapshot.argtypes = [ctypes.c_void_p, ctypes.POINTER(NanoClockSnapshot)]
        self.lib.nc_nanoclock_snapshot.restype = ctypes.c_int
        self.lib.nc_format_unix_time_ns.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]
        self.lib.nc_clock_route_name.argtypes = [ctypes.c_int]
        self.lib.nc_clock_route_name.restype = ctypes.c_char_p
        self.lib.nc_asm_simd_family_name.argtypes = [ctypes.c_int]
        self.lib.nc_asm_simd_family_name.restype = ctypes.c_char_p
        self.lib.nc_measure_wrapper_overhead_cycles.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
        self.lib.nc_measure_wrapper_overhead_cycles.restype = ctypes.c_uint64
        self.ctx = self.lib.nc_create()
        if not self.ctx:
            raise RuntimeError("nc_create failed")
    def close(self):
        if self.ctx:
            self.lib.nc_destroy(self.ctx)
            self.ctx = None
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self.close()
    def start(self):
        self.lib.nc_start(self.ctx)
    def elapsed_ns(self):
        return int(self.lib.nc_elapsed_ns(self.ctx))
    def ffi_overhead_cycles(self, iterations=10000):
        return int(self.lib.nc_measure_ffi_overhead_cycles(self.ctx, int(iterations)))
    def nanoclock_snapshot(self):
        snap = NanoClockSnapshot()
        if not self.lib.nc_nanoclock_snapshot(self.ctx, ctypes.byref(snap)):
            raise RuntimeError("nc_nanoclock_snapshot failed")
        return snap
    def format_unix_time_ns(self, unix_ns):
        buf = ctypes.create_string_buffer(80)
        self.lib.nc_format_unix_time_ns(ctypes.c_uint64(int(unix_ns)), buf, len(buf))
        return buf.value.decode("ascii", "replace")
    def clock_route_name(self, route):
        return self.lib.nc_clock_route_name(int(route)).decode("ascii", "replace")
    def simd_family_name(self, family):
        return self.lib.nc_asm_simd_family_name(int(family)).decode("ascii", "replace")
    def native_wrapper_baseline_cycles(self, iterations=10000):
        return int(self.lib.nc_measure_wrapper_overhead_cycles(self.ctx, 2, int(iterations)))
    def ctypes_call_overhead_cycles(self, iterations=10000):
        best = (1 << 64) - 1
        for _ in range(int(iterations)):
            a = self.lib.nc_now_cycles(self.ctx)
            self.lib.nc_empty_call()
            b = self.lib.nc_now_cycles(self.ctx)
            d = int(b - a) if b >= a else 0
            if d and d < best:
                best = d
        return 0 if best == (1 << 64) - 1 else best

class SampleStats(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint64),
        ("min_cycles", ctypes.c_uint64),
        ("max_cycles", ctypes.c_uint64),
        ("mean_cycles", ctypes.c_uint64),
        ("median_cycles", ctypes.c_uint64),
        ("p90_cycles", ctypes.c_uint64),
        ("p99_cycles", ctypes.c_uint64),
        ("variance_cycles", ctypes.c_double),
        ("stdev_cycles", ctypes.c_double),
    ]

def bind_toolkit(lib):
    lib.nc_toolkit_version.restype = ctypes.c_char_p
    lib.nc_wall_time_ns.restype = ctypes.c_uint64
    lib.nc_measure_dll_boundary_cycles.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.nc_measure_dll_boundary_cycles.restype = ctypes.c_uint64
    lib.nc_measure_python_wheel_boundary_cycles.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.nc_measure_python_wheel_boundary_cycles.restype = ctypes.c_uint64
    lib.nc_analyze_samples.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.POINTER(SampleStats)]
    lib.nc_analyze_samples.restype = ctypes.c_int
    lib.nc_welch_t_score.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32]
    lib.nc_welch_t_score.restype = ctypes.c_double
    lib.nc_time_memcmp_cycles.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int)]
    lib.nc_time_memcmp_cycles.restype = ctypes.c_uint64
    lib.nc_time_constant_time_eq_cycles.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int)]
    lib.nc_time_constant_time_eq_cycles.restype = ctypes.c_uint64
    lib.nc_time_flush_reload_cycles.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.nc_time_flush_reload_cycles.restype = ctypes.c_uint64
    return lib

# Monkey-patch convenience methods without breaking older wheels.
def _toolkit_version(self):
    bind_toolkit(self.lib)
    return self.lib.nc_toolkit_version().decode("utf-8", "replace")
def _dll_boundary_cycles(self, iterations=10000):
    bind_toolkit(self.lib)
    return int(self.lib.nc_measure_dll_boundary_cycles(self.ctx, int(iterations)))
def _wheel_boundary_cycles(self, iterations=10000):
    bind_toolkit(self.lib)
    return int(self.lib.nc_measure_python_wheel_boundary_cycles(self.ctx, int(iterations)))
def _memcmp_cycles(self, a: bytes, b: bytes):
    bind_toolkit(self.lib)
    aa = ctypes.create_string_buffer(a)
    bb = ctypes.create_string_buffer(b)
    out = ctypes.c_int()
    n = min(len(a), len(b))
    cyc = self.lib.nc_time_memcmp_cycles(self.ctx, aa, bb, n, ctypes.byref(out))
    return int(cyc), int(out.value)
def _constant_time_eq_cycles(self, a: bytes, b: bytes):
    bind_toolkit(self.lib)
    aa = ctypes.create_string_buffer(a)
    bb = ctypes.create_string_buffer(b)
    out = ctypes.c_int()
    n = min(len(a), len(b))
    cyc = self.lib.nc_time_constant_time_eq_cycles(self.ctx, aa, bb, n, ctypes.byref(out))
    return int(cyc), bool(out.value)
def _analyze_samples(self, samples):
    bind_toolkit(self.lib)
    arr = (ctypes.c_uint64 * len(samples))(*[int(x) for x in samples])
    st = SampleStats()
    if not self.lib.nc_analyze_samples(arr, len(samples), ctypes.byref(st)):
        raise RuntimeError("nc_analyze_samples failed")
    return {name: getattr(st, name) for name, _ in SampleStats._fields_}
def _welch_t_score(self, a, b):
    bind_toolkit(self.lib)
    aa = (ctypes.c_uint64 * len(a))(*[int(x) for x in a])
    bb = (ctypes.c_uint64 * len(b))(*[int(x) for x in b])
    return float(self.lib.nc_welch_t_score(aa, len(a), bb, len(b)))

NanoChronometer.toolkit_version = _toolkit_version
NanoChronometer.dll_boundary_cycles = _dll_boundary_cycles
NanoChronometer.wheel_boundary_cycles = _wheel_boundary_cycles
NanoChronometer.memcmp_cycles = _memcmp_cycles
NanoChronometer.constant_time_eq_cycles = _constant_time_eq_cycles
NanoChronometer.analyze_samples = _analyze_samples
NanoChronometer.welch_t_score = _welch_t_score

class InstructionResult(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int), ("family", ctypes.c_uint32), ("backend", ctypes.c_uint32),
        ("cycles", ctypes.c_uint64), ("ns", ctypes.c_uint64), ("blocks", ctypes.c_uint64), ("checksum", ctypes.c_uint64),
    ]
class SideChannelResult(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int), ("cached_cycles", ctypes.c_uint64), ("flushed_cycles", ctypes.c_uint64), ("prefetched_cycles", ctypes.c_uint64), ("threshold_cycles", ctypes.c_uint64), ("separation_score", ctypes.c_double)]
NC_INSTR_SCALAR=0; NC_INSTR_AES=1; NC_INSTR_SHA=2; NC_INSTR_PCLMULQDQ=3; NC_INSTR_CRC32=4; NC_INSTR_SSE2=5; NC_INSTR_AVX2=6; NC_INSTR_AVX512=7; NC_INSTR_NEON=8; NC_INSTR_SVE=9; NC_INSTR_SVE2=10; NC_INSTR_SME=11

def bind_instruction_api(lib):
    bind_toolkit(lib)
    lib.nc_instruction_family_name.argtypes=[ctypes.c_int]; lib.nc_instruction_family_name.restype=ctypes.c_char_p
    lib.nc_instruction_family_available.argtypes=[ctypes.c_int]; lib.nc_instruction_family_available.restype=ctypes.c_int
    lib.nc_measure_instruction_family_cycles.argtypes=[ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(InstructionResult)]; lib.nc_measure_instruction_family_cycles.restype=ctypes.c_uint64
    lib.nc_measure_aesenc_cycles.argtypes=[ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(InstructionResult)]; lib.nc_measure_aesenc_cycles.restype=ctypes.c_uint64
    lib.nc_measure_sha256msg_cycles.argtypes=[ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(InstructionResult)]; lib.nc_measure_sha256msg_cycles.restype=ctypes.c_uint64
    lib.nc_measure_pclmul_cycles.argtypes=[ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(InstructionResult)]; lib.nc_measure_pclmul_cycles.restype=ctypes.c_uint64
    lib.nc_measure_cache_probe_cycles.argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(SideChannelResult)]; lib.nc_measure_cache_probe_cycles.restype=ctypes.c_uint64
    lib.nc_crypto_backend_mask.restype=ctypes.c_int
    lib.nc_crypto_sha256_cycles.argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(InstructionResult)]; lib.nc_crypto_sha256_cycles.restype=ctypes.c_uint64
    return lib

def _instruction_available(self, family):
    bind_instruction_api(self.lib); return bool(self.lib.nc_instruction_family_available(int(family)))
def _measure_instruction(self, family, iterations=1024):
    bind_instruction_api(self.lib); r=InstructionResult(); self.lib.nc_measure_instruction_family_cycles(self.ctx, int(family), int(iterations), ctypes.byref(r)); return r
def _measure_aes(self, blocks=1024):
    bind_instruction_api(self.lib); r=InstructionResult(); self.lib.nc_measure_aesenc_cycles(self.ctx, int(blocks), ctypes.byref(r)); return r
def _measure_sha_instr(self, blocks=1024):
    bind_instruction_api(self.lib); r=InstructionResult(); self.lib.nc_measure_sha256msg_cycles(self.ctx, int(blocks), ctypes.byref(r)); return r
def _measure_pclmul(self, blocks=1024):
    bind_instruction_api(self.lib); r=InstructionResult(); self.lib.nc_measure_pclmul_cycles(self.ctx, int(blocks), ctypes.byref(r)); return r
def _crypto_backend_mask(self):
    bind_instruction_api(self.lib); return int(self.lib.nc_crypto_backend_mask())
def _crypto_sha256_cycles(self, data: bytes):
    bind_instruction_api(self.lib); buf=ctypes.create_string_buffer(data); digest=ctypes.create_string_buffer(32); r=InstructionResult(); self.lib.nc_crypto_sha256_cycles(self.ctx, buf, len(data), digest, ctypes.byref(r)); return r, bytes(digest)
NanoChronometer.instruction_available=_instruction_available
NanoChronometer.measure_instruction=_measure_instruction
NanoChronometer.measure_aes=_measure_aes
NanoChronometer.measure_sha_instr=_measure_sha_instr
NanoChronometer.measure_pclmul=_measure_pclmul
NanoChronometer.crypto_backend_mask=_crypto_backend_mask
NanoChronometer.crypto_sha256_cycles=_crypto_sha256_cycles
