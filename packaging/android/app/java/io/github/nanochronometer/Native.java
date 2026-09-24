// SPDX-License-Identifier: Apache-2.0
package io.github.nanochronometer;

/** The Rust side: crates/nanochrono-android. Every method is thread-safe. */
final class Native {
    static {
        System.loadLibrary("nanochrono_jni");
    }

    private Native() {}

    /** key=value lines: CPU, counter, CNTPCT and PMU access, SIMD families. */
    static native String deviceReport();

    /** Monotonic nanoseconds from the architectural counter. */
    static native long nowNs();

    /** Switches to CNTPCT_EL0 if the device allows it; returns whether in use. */
    static native boolean usePhysicalCounter(boolean on);

    /** Benchmark rows: mode TAB kernel TAB mode label TAB kernel name TAB available. */
    static native String benchRows();

    /** Runs one row; blocks. Call off the UI thread. */
    static native String runBench(int mode, int kernel);

    /** Feeds a barometer reading; bit 0 submerged, bit 1 touch locked. */
    static native int barometer(double hPa, long nowNs);

    static native double depthM(double hPa);

    /** 0 within, 1 near, 2 beyond. Rating: 0 none, 1 jets, 2 IPx7, 3 IPx8, 4 IP69K. */
    static native int exposure(int rating, double declaredDepthM, int declaredMinutes,
                               double depthM, long submergedNs);

    /** Thermal bound in ppm; crystal 0 AT-cut, 1 tuning fork. */
    static native double thermalPpm(int crystal, double celsius);
}
