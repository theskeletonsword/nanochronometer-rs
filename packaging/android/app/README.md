# NanoChronometer for Android

One APK for arm64-v8a, armeabi-v7a, x86_64 and x86. The native side is
`crates/nanochrono-android`, a JNI bridge over the same core, benchmark and
underwater code as the desktop and bare-metal builds.

```sh
ANDROID_HOME=~/Android/Sdk RUST_BIN=~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin \
    packaging/android/build-app.sh            # -> dist/android-app/nanochronometer-<version>.apk
```

The build uses no Gradle: aapt2, javac, d8, zipalign and apksigner come from
the SDK. Nightly Rust is only needed for an ABI whose standard library is not
installed, which is then built from `rust-src`. Release signing reads
`packaging/android/keystore/keystore.properties`. That file and the keystore
are gitignored. Without them, the APK is signed with the debug key.

## What it measures, and what Android does not allow

| | |
|---|---|
| Stopwatch | Uses the architectural counter (`CNTVCT_EL0` on ARM, TSC on x86) with nanosecond display. |
| SIMD and crypto | The benchmark crate's CPU-ISA, crypto (ring) and TLS modes. The AF_ALG and ring-0 modes are Linux-only and are not listed. |
| TEE / StrongBox | AndroidKeyStore round trips to KeyMint/Keymaster: EC and RSA keygen, ECDSA sign, AES-GCM, HMAC. Each key's real security level is printed next to its numbers. |
| `CNTPCT_EL0` | Probed at run time. Kernels normally leave only the virtual counter to user space. Where the probe passes, the DEVICE tab lets you switch to the physical counter. |
| PMU | `perf_event_open` is attempted and the errno reported. Android ships `perf_event_paranoid=3`, which denies it to apps. |
| `SMC` / `HVC` | Not attempted. Both are undefined at EL0 by the architecture, on every device, rooted or not. |

Under water, the barometer switches off the touchscreen, because a wet panel
reports phantom touches, and the volume keys take over. Pressure never
corrects the reading: the counter runs off the SoC crystal.
