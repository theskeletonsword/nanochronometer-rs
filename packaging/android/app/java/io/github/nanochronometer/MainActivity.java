// SPDX-License-Identifier: Apache-2.0
package io.github.nanochronometer;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Choreographer;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The whole interface, built in code: four tabs over one frame.
 *
 * STOPWATCH reads the architectural counter through the native library.
 * Under water it listens to the barometer: once submerged the touchscreen is
 * ignored — a wet panel invents touches — and the volume keys drive it
 * (up: start/stop, down: lap, or reset when stopped).
 */
public final class MainActivity extends Activity
        implements Choreographer.FrameCallback, SensorEventListener {

    // Palette of the bare-metal interface.
    private static final int BG = 0xFF0B0F14;
    private static final int PANEL = 0xFF121821;
    private static final int TEXT = 0xFFE6EDF3;
    private static final int MUTED = 0xFF8B98A5;
    private static final int ACCENT = 0xFF3DDC97;
    private static final int DANGER = 0xFFFF6B6B;
    private static final int WARN = 0xFFFFC857;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private LinearLayout content;
    private final Button[] tabButtons = new Button[4];
    private View[] pages;

    // --- stopwatch state
    private boolean running;
    private long startedNs;
    private long bankedNs;
    private final List<Long> laps = new ArrayList<>();
    private TextView readout;
    private TextView lapsView;
    private Button startButton;

    // --- underwater
    private SensorManager sensors;
    private Sensor barometer;
    private boolean submerged;
    private boolean touchLocked;
    private long submergedSinceNs;
    private int lastExposure;
    private TextView waterView;
    private TextView lockBanner;
    private Spinner ratingSpinner;
    private EditText declaredDepth;
    private EditText declaredMinutes;
    private float batteryCelsius = Float.NaN;

    // --- bench
    private final List<int[]> benchIds = new ArrayList<>();
    private TextView benchOut;
    private Button benchRun;
    private Button benchAll;
    private Spinner benchSpinner;
    /** Every row from the native side: mode, kernel, available, this arch. */
    private final List<int[]> allRows = new ArrayList<>();
    private final List<String> allLabels = new ArrayList<>();
    private boolean showAllRows;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setFitsSystemWindows(true);

        // The logo: stopwatch, green "Nano", white "Chronometer" — the same
        // artwork as every other build, rendered by tools/gen-icons.py.
        ImageView title = new ImageView(this);
        title.setImageResource(R.drawable.nanochronometer_wordmark);
        title.setAdjustViewBounds(true);
        title.setScaleType(ImageView.ScaleType.FIT_START);
        title.setContentDescription("NanoChronometer");
        title.setPadding(dp(16), dp(12), dp(16), dp(4));
        root.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(36) + dp(16)));

        LinearLayout tabs = new LinearLayout(this);
        tabs.setPadding(dp(8), 0, dp(8), dp(4));
        String[] names = {"STOPWATCH", "BENCH", "KEYSTORE", "DEVICE"};
        for (int i = 0; i < names.length; i++) {
            final int index = i;
            Button b = flatButton(names[i]);
            b.setOnClickListener(v -> select(index));
            tabs.addView(b, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
            tabButtons[i] = b;
        }
        root.addView(tabs);

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        root.addView(content, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        pages = new View[]{stopwatchPage(), benchPage(), keystorePage(), devicePage()};
        setContentView(root);
        select(0);

        sensors = (SensorManager) getSystemService(Context.SENSOR_SERVICE);
        barometer = sensors == null ? null : sensors.getDefaultSensor(Sensor.TYPE_PRESSURE);
        updateWater(Double.NaN);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (barometer != null) {
            sensors.registerListener(this, barometer, SensorManager.SENSOR_DELAY_NORMAL);
        }
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            int tenths = battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
            if (tenths != Integer.MIN_VALUE) {
                batteryCelsius = tenths / 10f;
            }
        }
        Choreographer.getInstance().postFrameCallback(this);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (sensors != null) {
            sensors.unregisterListener(this);
        }
        Choreographer.getInstance().removeFrameCallback(this);
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    private void select(int index) {
        content.removeAllViews();
        content.addView(pages[index], new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        for (int i = 0; i < tabButtons.length; i++) {
            tabButtons[i].setTextColor(i == index ? ACCENT : MUTED);
        }
    }

    // ------------------------------------------------------------------
    // Stopwatch
    // ------------------------------------------------------------------

    private View stopwatchPage() {
        LinearLayout page = column();

        lockBanner = text("", 15, BG);
        lockBanner.setBackgroundColor(DANGER);
        lockBanner.setPadding(dp(12), dp(10), dp(12), dp(10));
        lockBanner.setVisibility(View.GONE);
        page.addView(lockBanner);

        readout = text("00:00:00.000 000 000", 30, TEXT);
        readout.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        readout.setGravity(Gravity.CENTER);
        readout.setPadding(0, dp(28), 0, dp(20));
        page.addView(readout);

        LinearLayout buttons = new LinearLayout(this);
        startButton = pillButton("START");
        startButton.setOnClickListener(v -> toggle());
        Button lap = pillButton("LAP");
        lap.setOnClickListener(v -> lap());
        Button reset = pillButton("RESET");
        reset.setOnClickListener(v -> reset());
        for (Button b : new Button[]{startButton, lap, reset}) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(52), 1);
            lp.setMargins(dp(4), 0, dp(4), 0);
            buttons.addView(b, lp);
        }
        page.addView(buttons);

        lapsView = text("", 14, MUTED);
        lapsView.setTypeface(Typeface.MONOSPACE);
        lapsView.setPadding(dp(8), dp(12), dp(8), dp(12));
        page.addView(lapsView);

        page.addView(heading("WATER"));
        waterView = text("", 13, TEXT);
        waterView.setTypeface(Typeface.MONOSPACE);
        page.addView(card(waterView));

        page.addView(heading("INGRESS RATING"));
        ratingSpinner = new Spinner(this);
        ratingSpinner.setAdapter(adapter(new String[]{
                "not rated / unknown",
                "IPx5 / IPx6 (IP56, IP65, IP66) - jets only",
                "IPx7 (IP57, IP67) - 1 m, 30 min",
                "IPx8 (IP58, IP68) - declared depth",
                "IPx9 / IP69K (IP69) - hot jets only"}));
        ratingSpinner.setSelection(3);
        page.addView(ratingSpinner);
        LinearLayout declared = new LinearLayout(this);
        declaredDepth = number("1.5");
        declaredMinutes = number("30");
        declared.addView(text("depth m ", 13, MUTED));
        declared.addView(declaredDepth, new LinearLayout.LayoutParams(dp(80), ViewGroup.LayoutParams.WRAP_CONTENT));
        declared.addView(text("  minutes ", 13, MUTED));
        declared.addView(declaredMinutes, new LinearLayout.LayoutParams(dp(80), ViewGroup.LayoutParams.WRAP_CONTENT));
        page.addView(declared);
        TextView note = text("Pressure never changes the reading: the counter runs off the SoC crystal. "
                + "The barometer only decides when to ignore the touchscreen. Under water: "
                + "VOLUME UP start/stop, VOLUME DOWN lap (reset when stopped).", 12, MUTED);
        note.setPadding(0, dp(8), 0, dp(24));
        page.addView(note);
        return scroll(page);
    }

    private long elapsedNs() {
        return running ? bankedNs + (Native.nowNs() - startedNs) : bankedNs;
    }

    private void toggle() {
        long now = Native.nowNs();
        if (running) {
            bankedNs += now - startedNs;
            running = false;
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        } else {
            startedNs = now;
            running = true;
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }
        startButton.setText(running ? "STOP" : "START");
        paint();
    }

    private void lap() {
        if (!running) {
            return;
        }
        laps.add(0, elapsedNs());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < laps.size() && i < 50; i++) {
            sb.append(String.format(Locale.ROOT, "lap %-3d %s%n", laps.size() - i, format(laps.get(i))));
        }
        lapsView.setText(sb.toString());
    }

    private void reset() {
        running = false;
        bankedNs = 0;
        laps.clear();
        lapsView.setText("");
        startButton.setText("START");
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        paint();
    }

    private void paint() {
        readout.setText(format(elapsedNs()));
    }

    static String format(long ns) {
        long s = ns / 1_000_000_000L;
        long frac = ns % 1_000_000_000L;
        return String.format(Locale.ROOT, "%02d:%02d:%02d.%03d %03d %03d",
                s / 3600, (s / 60) % 60, s % 60, frac / 1_000_000, (frac / 1_000) % 1000, frac % 1000);
    }

    @Override
    public void doFrame(long frameTimeNanos) {
        if (running) {
            paint();
        }
        Choreographer.getInstance().postFrameCallback(this);
    }

    /** The volume keys are the one input water cannot fake. */
    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_VOLUME_UP || keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) {
            if (event.getRepeatCount() == 0) {
                if (keyCode == KeyEvent.KEYCODE_VOLUME_UP) {
                    toggle();
                } else if (running) {
                    lap();
                } else {
                    reset();
                }
            }
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    /** While submerged, the touchscreen is not listened to at all. */
    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (touchLocked) {
            return true;
        }
        return super.dispatchTouchEvent(ev);
    }

    @Override
    public void onSensorChanged(SensorEvent event) {
        if (event.sensor.getType() == Sensor.TYPE_PRESSURE) {
            updateWater(event.values[0]);
        }
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {}

    private void updateWater(double hPa) {
        StringBuilder sb = new StringBuilder();
        if (barometer == null) {
            sb.append("barometer: none on this device; touch lock unavailable\n");
        } else if (Double.isNaN(hPa)) {
            sb.append("barometer: waiting for a reading\n");
        } else {
            long now = Native.nowNs();
            int state = Native.barometer(hPa, now);
            boolean nowSubmerged = (state & 1) != 0;
            if (nowSubmerged && !submerged) {
                submergedSinceNs = now;
            }
            submerged = nowSubmerged;
            touchLocked = (state & 2) != 0;
            double depth = Native.depthM(hPa);
            sb.append(String.format(Locale.ROOT, "pressure  %.1f hPa%n", hPa));
            sb.append(String.format(Locale.ROOT, "state     %s%n", submerged ? "SUBMERGED" : "surface"));
            sb.append(String.format(Locale.ROOT, "depth     %.2f m (estimate)%n", depth));
            int exposure = 0;
            if (submerged) {
                // The spinner's order is the native rating code's order.
                exposure = Native.exposure(ratingSpinner.getSelectedItemPosition(),
                        parse(declaredDepth, 1.5), (int) parse(declaredMinutes, 30),
                        depth, now - submergedSinceNs);
                sb.append("rating    ").append(new String[]{"within rating", "NEAR THE RATED LIMIT",
                        "BEYOND THE RATING - SURFACE"}[exposure]).append('\n');
            }
            if (exposure > lastExposure) {
                buzz();
            }
            lastExposure = exposure;
            lockBanner.setVisibility(touchLocked ? View.VISIBLE : View.GONE);
            lockBanner.setBackgroundColor(exposure == 2 ? DANGER : WARN);
            lockBanner.setText(exposure == 2
                    ? "BEYOND THE INGRESS RATING - SURFACE NOW. Touch locked: use the volume keys."
                    : "SUBMERGED - touch locked. VOLUME UP start/stop, VOLUME DOWN lap/reset.");
        }
        if (!Float.isNaN(batteryCelsius)) {
            sb.append(String.format(Locale.ROOT, "temp      %.1f C (battery)%n", batteryCelsius));
            sb.append(String.format(Locale.ROOT, "thermal   +/-%.1f ppm (SoC crystal bound, not corrected)%n",
                    Native.thermalPpm(0, batteryCelsius)));
        }
        waterView.setText(sb.toString());
    }

    private void buzz() {
        Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        if (v == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            v.vibrate(VibrationEffect.createWaveform(new long[]{0, 400, 200, 400}, -1));
        } else {
            v.vibrate(new long[]{0, 400, 200, 400}, -1);
        }
    }

    private static double parse(EditText e, double fallback) {
        try {
            return Double.parseDouble(e.getText().toString());
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    // ------------------------------------------------------------------
    // Bench
    // ------------------------------------------------------------------

    private View benchPage() {
        LinearLayout page = column();
        page.addView(heading("BENCHMARK (SIMD, CRYPTO, TLS)"));
        for (String line : Native.benchRows().split("\n")) {
            String[] f = line.split("\t");
            if (f.length < 6) {
                continue;
            }
            boolean available = "1".equals(f[4]);
            boolean thisArch = "1".equals(f[5]);
            allRows.add(new int[]{Integer.parseInt(f[0]), Integer.parseInt(f[1]),
                    available ? 1 : 0, thisArch ? 1 : 0});
            allLabels.add(f[2].replaceFirst("^Mode \\d+: ", "") + " / " + f[3]
                    + (available ? "" : thisArch ? "  (not on this CPU)" : "  (other architecture)"));
        }
        benchSpinner = new Spinner(this);
        page.addView(benchSpinner);
        Switch showAll = new Switch(this);
        showAll.setText("Show all instructions (including unavailable)");
        showAll.setTextColor(MUTED);
        showAll.setOnCheckedChangeListener((b, on) -> {
            showAllRows = on;
            fillBenchRows();
        });
        page.addView(showAll);
        fillBenchRows();

        LinearLayout buttons = new LinearLayout(this);
        benchRun = pillButton("RUN");
        benchRun.setOnClickListener(v -> runBench(false));
        benchAll = pillButton("RUN ALL SIMD");
        benchAll.setOnClickListener(v -> runBench(true));
        for (Button b : new Button[]{benchRun, benchAll}) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(48), 1);
            lp.setMargins(dp(4), dp(8), dp(4), dp(8));
            buttons.addView(b, lp);
        }
        page.addView(buttons);

        benchOut = text("Each row runs three passes. Rows marked unavailable are ISA families this CPU "
                + "does not have.", 12, TEXT);
        benchOut.setTypeface(Typeface.MONOSPACE);
        benchOut.setTextIsSelectable(true);
        page.addView(card(benchOut));
        return scroll(page);
    }

    /** Only what can run here, unless every row was asked for. */
    private void fillBenchRows() {
        benchIds.clear();
        List<String> labels = new ArrayList<>();
        for (int i = 0; i < allRows.size(); i++) {
            int[] row = allRows.get(i);
            if (showAllRows || row[2] == 1) {
                benchIds.add(row);
                labels.add(allLabels.get(i));
            }
        }
        benchSpinner.setAdapter(adapter(labels.toArray(new String[0])));
    }

    private void runBench(boolean allSimd) {
        final List<int[]> rows = new ArrayList<>();
        if (allSimd) {
            for (int[] id : benchIds) {
                if (id[0] == 0 && id[2] == 1) {
                    rows.add(id);
                }
            }
        } else {
            int pos = benchSpinner.getSelectedItemPosition();
            if (pos < 0 || pos >= benchIds.size()) {
                return;
            }
            rows.add(benchIds.get(pos));
        }
        benchRun.setEnabled(false);
        benchAll.setEnabled(false);
        benchOut.setText("running...\n");
        worker.execute(() -> {
            StringBuilder all = new StringBuilder();
            for (int[] id : rows) {
                String result = Native.runBench(id[0], id[1]);
                all.append(result).append('\n');
                final String partial = all.toString();
                ui.post(() -> benchOut.setText(partial));
            }
            ui.post(() -> {
                benchRun.setEnabled(true);
                benchAll.setEnabled(true);
            });
        });
    }

    // ------------------------------------------------------------------
    // Keystore
    // ------------------------------------------------------------------

    private View keystorePage() {
        LinearLayout page = column();
        page.addView(heading("TEE / STRONGBOX LATENCY (KEYSTORE API)"));
        final TextView out = text("Times the AndroidKeyStore round trip to KeyMint in the TEE and, where "
                + "present, to the StrongBox secure element: key generation, ECDSA signing, AES-GCM, "
                + "HMAC. Each key's real security level is read back and printed next to it. "
                + "Temporary keys are deleted afterwards.", 12, TEXT);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextIsSelectable(true);
        final Button run = pillButton("RUN");
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        lp.setMargins(dp(4), dp(8), dp(4), dp(8));
        page.addView(run, lp);
        page.addView(card(out));
        run.setOnClickListener(v -> {
            run.setEnabled(false);
            out.setText("");
            worker.execute(() -> {
                new KeystoreBench(this, line -> ui.post(() -> out.append(line + "\n"))).run();
                ui.post(() -> run.setEnabled(true));
            });
        });
        return scroll(page);
    }

    // ------------------------------------------------------------------
    // Device
    // ------------------------------------------------------------------

    private View devicePage() {
        LinearLayout page = column();
        page.addView(heading("DEVICE"));
        final TextView info = text("", 12, TEXT);
        info.setTypeface(Typeface.MONOSPACE);
        info.setTextIsSelectable(true);

        final Switch physical = new Switch(this);
        physical.setText("Physical counter (CNTPCT_EL0), if this device allows it");
        physical.setTextColor(TEXT);
        physical.setOnCheckedChangeListener((b, on) -> {
            boolean inUse = Native.usePhysicalCounter(on);
            if (on && !inUse) {
                b.setChecked(false);
            }
            info.setText(deviceText());
        });
        page.addView(physical);
        page.addView(card(info));
        info.setText("probing...");
        worker.execute(() -> {
            String text = deviceText();
            ui.post(() -> info.setText(text));
        });
        return scroll(page);
    }

    private String deviceText() {
        StringBuilder sb = new StringBuilder();
        sb.append("model=").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        if (Build.VERSION.SDK_INT >= 31) {
            sb.append("soc=").append(Build.SOC_MANUFACTURER).append(' ').append(Build.SOC_MODEL).append('\n');
        }
        sb.append("android=").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT)
                .append(")\n");
        sb.append("abis=").append(String.join(",", Build.SUPPORTED_ABIS)).append('\n');
        sb.append("strongbox=").append(KeystoreBench.hasStrongBox(this) ? "yes" : "no").append('\n');
        sb.append(Native.deviceReport());
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Widgets
    // ------------------------------------------------------------------

    private int dp(int v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                getResources().getDisplayMetrics());
    }

    private TextView text(String s, int sp, int colour) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(colour);
        return t;
    }

    private TextView heading(String s) {
        TextView t = text(s, 13, ACCENT);
        t.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        t.setPadding(0, dp(16), 0, dp(6));
        return t;
    }

    private LinearLayout column() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(16), dp(8), dp(16), dp(16));
        return l;
    }

    private ScrollView scroll(View child) {
        ScrollView s = new ScrollView(this);
        s.addView(child);
        return s;
    }

    private View card(View child) {
        LinearLayout c = new LinearLayout(this);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(PANEL);
        bg.setCornerRadius(dp(12));
        c.setBackground(bg);
        c.setPadding(dp(12), dp(12), dp(12), dp(12));
        c.addView(child);
        return c;
    }

    private Button flatButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(12);
        b.setTextColor(MUTED);
        b.setBackgroundColor(Color.TRANSPARENT);
        return b;
    }

    private Button pillButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextColor(BG);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(ACCENT);
        bg.setCornerRadius(dp(26));
        b.setBackground(bg);
        return b;
    }

    private EditText number(String initial) {
        EditText e = new EditText(this);
        e.setText(initial);
        e.setTextColor(TEXT);
        e.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_DECIMAL);
        return e;
    }

    private ArrayAdapter<String> adapter(String[] items) {
        ArrayAdapter<String> a = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, items) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                TextView v = (TextView) super.getView(position, convertView, parent);
                v.setTextColor(TEXT);
                return v;
            }
        };
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return a;
    }
}
