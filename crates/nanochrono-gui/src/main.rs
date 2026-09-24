// SPDX-License-Identifier: Apache-2.0
//! NanoChronometer desktop application.
//!
//! A port of the Win32 GUI to `iced`. The structure is preserved verbatim —
//! navigation tabs, the large timer face, the three readout panels, the
//! benchmark panel with its mode rows and log, and the status bar — but the
//! rendering is now retained-mode and portable, so the same binary runs on
//! Linux, Windows and macOS instead of Win32 only.
//!
//! What changed on purpose:
//!
//! * The window uses native decorations. The C build drew its own title bar
//!   and reimplemented dragging and hit-testing, which was several hundred
//!   lines of `WM_NCHITTEST` handling that behaved differently under every
//!   window manager.
//! * The NTP and calibration panels show live measurements. In the C build
//!   those numbers were hard-coded placeholders in `paint()` — "+112 ns",
//!   "Stratum: 2", "0.38 ppm" were string literals, not readings.
//! * Benchmarks and NTP queries run off the UI thread, so a three-pass run no
//!   longer freezes the window.

mod clockface;
mod style;

use std::sync::Arc;
use std::time::Duration;

use iced::widget::{
    button, canvas, column, container, horizontal_rule, image as picture, row, scrollable, text,
    text_input, Space,
};
use iced::{keyboard, window, Alignment, Element, Font, Length, Subscription, Task, Theme};

use nanochrono_bench::{BenchConfig, BenchKernel, BenchMode, BenchReport};
use nanochrono_core::{
    clock::{self, StableClockConfig, StableClockState},
    dispatch::Dispatcher,
    format::{self, DetailMode, TimeZoneMode},
    ntp::{self, NtpSample},
    Chronometer, ClockView, NanoclockSnapshot, SimdFamily, Stopwatch, StopwatchState,
};

const MONO: Font = Font::MONOSPACE;

/// Refresh interval. 60 Hz: fast enough that the nanosecond digits read as
/// motion, slow enough to stay off the CPU the measurements run on.
const FRAME_INTERVAL: Duration = Duration::from_millis(16);

fn main() -> iced::Result {
    // Installed once at startup so every rustls config in the process — the
    // TLS benchmark included — uses the same provider as the primitives.
    nanochrono_crypto::install_default_provider();

    iced::application(NanoChrono::title, NanoChrono::update, NanoChrono::view)
        .subscription(NanoChrono::subscription)
        .theme(|_| Theme::Dark)
        .window(window_settings())
        .antialiasing(true)
        .run_with(NanoChrono::new)
}

/// The window, with per-platform desktop integration.
fn window_settings() -> window::Settings {
    window::Settings {
        size: iced::Size::new(1060.0, 680.0),
        min_size: Some(iced::Size::new(820.0, 520.0)),
        icon: window_icon(),
        platform_specific: platform_settings(),
        ..window::Settings::default()
    }
}

/// The application icon, as bytes, for every platform that wants it.
///
/// One asset for all three desktops: `assets/nanochrono.ico`, which is an ICO
/// container around a single 256x256 PNG. Windows takes the `.ico` directly,
/// macOS wants it converted to an `.icns` at packaging time, and Linux needs
/// both a PNG in the icon theme and this, decoded, for the window itself.
pub const ICON_ICO: &[u8] = include_bytes!("../../../assets/nanochrono.ico");

/// The wordmark shown in the header: the stopwatch, green "Nano", white
/// "Chronometer", for the black theme. Rendered by `tools/gen-icons.py` at
/// 80 px tall and drawn at half that, so it stays sharp on 2x displays.
const WORDMARK_PNG: &[u8] = include_bytes!("../../../assets/nanochronometer_wordmark_dark.png");

/// Decodes the bundled application icon.
///
/// Used by the X11 window manager for the title bar and task switcher, and by
/// Windows for the window's own icon. Wayland ignores it and takes the icon
/// from the `.desktop` entry matched by `application_id` instead, which is why
/// both are set — and why a missing `.desktop` icon shows as a generic
/// placeholder however good this one is.
///
/// The format is named rather than sniffed. `from_file_data(.., None)` asks
/// the `image` crate to guess, and guessing only works if the ICO decoder was
/// compiled in — which it was not, because `iced` does not enable that feature
/// on its copy of `image`. The call failed on every start, the `.ok()` here
/// threw the error away, and the window ran with no icon at all. Decoding
/// explicitly makes the dependency real, and the log below makes a failure
/// something you can see.
fn window_icon() -> Option<window::Icon> {
    let decoded = match image::load_from_memory_with_format(ICON_ICO, image::ImageFormat::Ico) {
        Ok(image) => image.to_rgba8(),
        Err(error) => {
            eprintln!("nanochrono-gui: could not decode the application icon: {error}");
            return None;
        }
    };
    let (width, height) = decoded.dimensions();
    match window::icon::from_rgba(decoded.into_raw(), width, height) {
        Ok(icon) => Some(icon),
        Err(error) => {
            eprintln!("nanochrono-gui: could not build the application icon: {error}");
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_settings() -> window::settings::PlatformSpecific {
    window::settings::PlatformSpecific {
        // Wayland has no window class: compositors match a surface to its
        // `.desktop` file through the app id, and that match is what gives the
        // window an icon and groups it in the dock. On X11 winit uses the same
        // string for WM_CLASS, so one value covers both display servers.
        application_id: APP_ID.to_string(),
        ..Default::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn platform_settings() -> window::settings::PlatformSpecific {
    window::settings::PlatformSpecific::default()
}

/// Reverse-DNS application id, matching `packaging/linux/*.desktop`.
pub const APP_ID: &str = "io.nanochronometer.NanoChrono";

/// Which body panel fills the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    /// The clock, stopwatch or timer face.
    Clock,
    /// The benchmark modes, rows and log.
    Bench,
    /// Hypervisor and emulation detection.
    Hypervisor,
    /// Settings: the counter source.
    Settings,
}

/// Which clock face the CLOCK view renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockDesign {
    Digital,
    Analog,
}

impl ClockDesign {
    fn toggled(self) -> Self {
        match self {
            ClockDesign::Digital => ClockDesign::Analog,
            ClockDesign::Analog => ClockDesign::Digital,
        }
    }

    fn name(self) -> &'static str {
        match self {
            ClockDesign::Digital => "DIGITAL",
            ClockDesign::Analog => "ANALOG",
        }
    }
}

struct NanoChrono {
    chrono: Chronometer,
    stopwatch: Stopwatch,
    snapshot: NanoclockSnapshot,
    calibration: StableClockState,

    view: ClockView,
    detail: DetailMode,
    zone: TimeZoneMode,
    design: ClockDesign,

    /// Which body panel is showing. The clock views are selected separately.
    panel: Panel,

    bench_mode: BenchMode,
    bench_rows: Vec<BenchKernel>,
    bench_selected: Option<usize>,
    bench_running: bool,
    bench_report: Option<Arc<BenchReport>>,

    ntp_server: String,
    ntp_in_flight: bool,
    ntp_result: Option<Result<NtpSample, String>>,

    /// Countdown target for the TIMER view, in seconds.
    timer_preset: String,

    dispatch_line: String,
    notice: String,

    /// What the last physical-counter check measured, if it could run.
    counter_check: Option<nanochrono_core::arch::PhysicalCounterCheck>,
    /// Why the physical counter could not be enabled, if it could not.
    counter_error: Option<String>,
    /// The hypervisor report on screen: the start-up probe, or the last
    /// re-probe. Rendering never probes (see `nanochrono_core::reprobe`).
    hv_report: nanochrono_core::hypervisor::HypervisorReport,
    /// The outcome of the last RE-PROBE or cooldown change.
    reprobe_status: Option<(bool, String)>,
}

#[derive(Debug, Clone)]
enum Message {
    Tick,
    SelectView(ClockView),
    SetDetail(DetailMode),
    SetZone(TimeZoneMode),
    ToggleDesign,
    ShowPanel(Panel),

    SelectBenchMode(BenchMode),
    RunBench(usize),
    BenchFinished(Arc<BenchReport>),
    SaveLog,

    NtpServerChanged(String),
    QueryNtp,
    NtpFinished(Arc<Result<NtpSample, String>>),

    Recalibrate,
    CalibrationFinished(Box<StableClockState>),

    SetPhysicalCounter(bool),
    Reprobe,
    SetReprobeCooldown(bool),

    TimerPresetChanged(String),
    StopwatchToggle,
    StopwatchStop,
    StopwatchReset,
    StopwatchLap,
    Quit,
}

impl NanoChrono {
    fn new() -> (Self, Task<Message>) {
        let chrono = Chronometer::new();
        let snapshot = NanoclockSnapshot::capture(&chrono);
        let dispatcher = Dispatcher::global();

        let app = NanoChrono {
            calibration: StableClockState::default(),
            snapshot,
            stopwatch: Stopwatch::new(),
            view: ClockView::Stopwatch,
            detail: DetailMode::Nano,
            zone: TimeZoneMode::Local,
            design: ClockDesign::Digital,
            panel: Panel::Clock,
            bench_mode: BenchMode::CpuIsa,
            bench_rows: BenchKernel::rows_for(BenchMode::CpuIsa),
            bench_selected: None,
            bench_running: false,
            bench_report: None,
            ntp_server: ntp::DEFAULT_SERVER.to_string(),
            ntp_in_flight: false,
            ntp_result: None,
            timer_preset: "60".to_string(),
            dispatch_line: format!(
                "{} | crypto {}",
                dispatcher.report().lines().next().unwrap_or_default(),
                nanochrono_crypto::PROVIDER
            ),
            notice: if nanochrono_core::hypervisor::cached().is_virtualized() {
                // Surfaced at startup rather than buried: a user reading
                // nanoseconds off an emulated platform needs to know before
                // they draw a conclusion, not after.
                nanochrono_core::hypervisor::cached()
                    .timing_impact
                    .advice()
                    .to_string()
            } else {
                String::new()
            },
            counter_check: None,
            counter_error: None,
            hv_report: nanochrono_core::hypervisor::cached().clone(),
            reprobe_status: None,
            chrono,
        };

        // Calibration sleeps for half a second, so it runs off the UI thread;
        // the panel shows "calibrating" until the result lands.
        (
            app,
            Task::perform(calibrate(), |s| Message::CalibrationFinished(Box::new(s))),
        )
    }

    fn title(&self) -> String {
        format!(
            "NanoChronometer {} — {}",
            env!("CARGO_PKG_VERSION"),
            self.view.name()
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                self.snapshot = NanoclockSnapshot::capture(&self.chrono);

                // Scrub the stored state. A window left open for days is
                // exactly where an upset has time to land, and a verify is a
                // handful of popcounts — microseconds per second at this rate.
                //
                // The stopwatch is scrubbed alongside the calibration because
                // a paused run is the longest-lived number here: it can sit
                // untouched for hours, and nothing else would look at it
                // until someone pressed resume.
                let calibration = self.chrono.verify_calibration();
                let stopwatch = self.stopwatch.verify();

                if !calibration.is_usable() {
                    self.notice =
                        "calibration unrecoverable — recalibrate before trusting readings"
                            .to_string();
                } else if !stopwatch.is_usable() {
                    self.notice =
                        "stopwatch total unrecoverable — the elapsed reading is lost".to_string();
                } else if stopwatch.was_repaired() {
                    self.notice = format!(
                        "stopwatch repaired ({}) — check memory health",
                        stopwatch.name()
                    );
                } else if calibration.was_repaired() {
                    self.notice = format!(
                        "calibration repaired ({}) — check memory health",
                        calibration.name()
                    );
                }
            }
            Message::SelectView(view) => {
                self.view = view;
                self.panel = Panel::Clock;
            }
            Message::SetDetail(detail) => self.detail = detail,
            Message::SetZone(zone) => self.zone = zone,
            Message::ToggleDesign => self.design = self.design.toggled(),
            Message::ShowPanel(panel) => {
                // Clicking the active panel's button returns to the clock, so
                // the buttons toggle rather than trapping the user in a view.
                self.panel = if self.panel == panel {
                    Panel::Clock
                } else {
                    panel
                };
            }

            Message::SelectBenchMode(mode) => {
                // Also reached from the digit keys, which should land on the
                // panel that shows the mode they picked.
                self.panel = Panel::Bench;
                self.bench_mode = mode;
                self.bench_rows = BenchKernel::rows_for(mode);
                self.bench_selected = None;
            }
            Message::RunBench(index) => {
                if self.bench_running {
                    return Task::none();
                }
                let Some(&kernel) = self.bench_rows.get(index) else {
                    return Task::none();
                };
                if !kernel.is_available() {
                    self.notice = format!("{} is not available on this CPU", kernel.name());
                    return Task::none();
                }
                self.bench_selected = Some(index);
                self.bench_running = true;
                self.notice = format!("running {}...", kernel.name());

                let config = BenchConfig {
                    mode: self.bench_mode,
                    kernel,
                    tls_host: self.ntp_host_for_tls(),
                    tls_port: 443,
                };
                return Task::perform(run_bench(config), Message::BenchFinished);
            }
            Message::BenchFinished(report) => {
                self.bench_running = false;
                self.notice = match &report.error {
                    Some(e) => format!("benchmark failed: {e}"),
                    None => format!("{} complete", report.summary.kernel_name),
                };
                self.bench_report = Some(report);
            }
            Message::SaveLog => {
                self.notice = match self.save_log() {
                    Ok(path) => format!("log written to {path}"),
                    Err(e) => format!("could not write log: {e}"),
                };
            }

            Message::NtpServerChanged(server) => self.ntp_server = server,
            Message::QueryNtp => {
                if self.ntp_in_flight {
                    return Task::none();
                }
                self.ntp_in_flight = true;
                let server = self.ntp_server.clone();
                return Task::perform(query_ntp(server), |r| Message::NtpFinished(Arc::new(r)));
            }
            Message::NtpFinished(result) => {
                self.ntp_in_flight = false;
                self.ntp_result = Some((*result).clone());
            }

            Message::Recalibrate => {
                self.notice = "recalibrating...".to_string();
                return Task::perform(calibrate(), |s| Message::CalibrationFinished(Box::new(s)));
            }
            Message::CalibrationFinished(state) => {
                self.calibration = *state;
                self.notice = if state.is_usable() {
                    String::new()
                } else {
                    "calibration is unreliable: the thread migrated between cores".to_string()
                };
            }

            Message::Reprobe => {
                use nanochrono_core::hypervisor;
                self.reprobe_status = Some(match hypervisor::reprobe() {
                    Ok((report, module_error)) => {
                        self.hv_report = report;
                        match module_error {
                            None => (true, "re-probed".to_string()),
                            Some(e) if e.kind() == std::io::ErrorKind::WouldBlock => (
                                false,
                                "re-probed in userspace; the kernel module is still cooling down \
                                 and kept its cached probe"
                                    .to_string(),
                            ),
                            Some(e) => (
                                false,
                                format!("re-probed in userspace; the kernel module was not asked again: {e}"),
                            ),
                        }
                    }
                    Err(e) => (false, e.to_string()),
                });
            }

            Message::SetReprobeCooldown(on) => {
                use nanochrono_core::hypervisor;
                hypervisor::set_reprobe_cooldown_enabled(on);
                let seconds = if on { nanochrono_core::reprobe::DEFAULT_COOLDOWN_S } else { 0 };
                // The module keeps its own limit, enforced in the kernel; it
                // follows this switch when the GUI may write to it (root).
                self.reprobe_status = Some(if self.hv_report.kernel.is_some() {
                    match hypervisor::kernel_module_set_cooldown(seconds) {
                        Ok(()) => (true, format!("cooldown {seconds} s (GUI and kernel module)")),
                        Err(e) => (
                            false,
                            format!(
                                "cooldown {seconds} s in the GUI; the kernel module keeps its own \
                                 ({e}; writing /proc/nanochrono needs root)"
                            ),
                        ),
                    }
                } else {
                    (true, format!("cooldown {seconds} s"))
                });
            }

            Message::SetPhysicalCounter(on) => {
                use nanochrono_core::arch::{self, CounterSource};
                let source = if on { CounterSource::Physical } else { CounterSource::Virtual };
                match arch::set_counter_source(source) {
                    Ok(()) => {
                        self.counter_error = None;
                        self.counter_check = arch::physical_counter_check();
                        // In a VM the two counters differ by CNTVOFF_EL2: a run
                        // started on one and stopped on the other measures that
                        // offset, not time. So the stopwatch starts over.
                        self.stopwatch.reset();
                        self.notice = format!(
                            "counter: {} — stopwatch reset{}",
                            source.name(),
                            if on && hypervisor_present() { "; virtualized system, see the warning" } else { "" }
                        );
                    }
                    Err(e) => {
                        self.counter_error = Some(e.to_string());
                        self.notice = format!("physical counter unavailable: {e}");
                    }
                }
            }
            Message::TimerPresetChanged(value) => {
                if value.chars().all(|c| c.is_ascii_digit()) && value.len() <= 6 {
                    self.timer_preset = value;
                }
            }
            Message::StopwatchToggle => self.stopwatch.toggle(&self.chrono),
            Message::StopwatchStop => self.stopwatch.stop(&self.chrono),
            Message::StopwatchReset => self.stopwatch.reset(),
            Message::StopwatchLap => {
                let lap = self.stopwatch.lap(&self.chrono);
                self.notice = format!(
                    "lap {}: {}",
                    self.stopwatch.lap_count(),
                    format::format_elapsed(lap, self.detail)
                );
            }
            Message::Quit => return iced::exit(),
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        let ticks = iced::time::every(FRAME_INTERVAL).map(|_| Message::Tick);
        let keys = keyboard::on_key_press(|key, _modifiers| {
            use keyboard::key::Named;
            match key.as_ref() {
                keyboard::Key::Named(Named::Space) => Some(Message::StopwatchToggle),
                keyboard::Key::Named(Named::Escape) => Some(Message::Quit),
                keyboard::Key::Character("p") => Some(Message::StopwatchToggle),
                keyboard::Key::Character("s") => Some(Message::StopwatchStop),
                keyboard::Key::Character("r") => Some(Message::StopwatchReset),
                keyboard::Key::Character("l") => Some(Message::StopwatchLap),
                keyboard::Key::Character("b") => Some(Message::ShowPanel(Panel::Bench)),
                keyboard::Key::Character("h") => Some(Message::ShowPanel(Panel::Hypervisor)),
                keyboard::Key::Character("g") => Some(Message::ShowPanel(Panel::Settings)),
                keyboard::Key::Character("c") => Some(Message::ToggleDesign),
                keyboard::Key::Character("m") => Some(Message::SetDetail(DetailMode::Simple)),
                keyboard::Key::Character("n") => Some(Message::SetDetail(DetailMode::Nano)),
                // Digits pick a benchmark mode by its number in the list:
                // 6 is Crypto RAW on Linux, 4 elsewhere (see `BenchMode::ALL`).
                keyboard::Key::Character(d) => d
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|i| BenchMode::ALL.get(i).copied())
                    .map(Message::SelectBenchMode),
                _ => None,
            }
        });
        Subscription::batch([ticks, keys])
    }

    fn view(&self) -> Element<'_, Message> {
        let body = match self.panel {
            Panel::Clock => self.clock_panel(),
            Panel::Bench => self.bench_panel(),
            Panel::Hypervisor => self.hypervisor_panel(),
            Panel::Settings => self.settings_panel(),
        };

        let layout = column![
            self.header(),
            container(body).height(Length::Fill).padding(16),
            self.hint_bar(),
            self.status_bar(),
        ];

        container(layout)
            .style(style::root)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    // -- header ------------------------------------------------------------

    fn header(&self) -> Element<'_, Message> {
        let title_line = row![
            picture(picture::Handle::from_bytes(WORDMARK_PNG)).height(Length::Fixed(40.0)),
            Space::with_width(Length::Fixed(18.0)),
            text(format::format_unix_utc(self.snapshot.unix_time_ns))
                .font(MONO)
                .size(13)
                .color(style::TIMER),
            Space::with_width(Length::Fixed(18.0)),
            text(self.snapshot.backend.name())
                .font(MONO)
                .size(13)
                .color(style::INFO),
            Space::with_width(Length::Fixed(12.0)),
            text(self.design.name())
                .font(MONO)
                .size(13)
                .color(style::MUTED),
            Space::with_width(Length::Fill),
            text(&self.dispatch_line)
                .font(MONO)
                .size(12)
                .color(style::MUTED),
        ]
        .align_y(Alignment::Center);

        let tabs = row![
            self.tab(
                "CLOCK",
                self.panel == Panel::Clock && self.view == ClockView::Clock,
                Message::SelectView(ClockView::Clock)
            ),
            self.tab(
                "STOPWATCH",
                self.panel == Panel::Clock && self.view == ClockView::Stopwatch,
                Message::SelectView(ClockView::Stopwatch)
            ),
            self.tab(
                "TIMER",
                self.panel == Panel::Clock && self.view == ClockView::Timer,
                Message::SelectView(ClockView::Timer)
            ),
            self.tab(self.design.name(), false, Message::ToggleDesign),
            Space::with_width(Length::Fill),
            self.tab(
                "SIMPLE",
                self.detail == DetailMode::Simple,
                Message::SetDetail(DetailMode::Simple)
            ),
            self.tab(
                "NANO",
                self.detail == DetailMode::Nano,
                Message::SetDetail(DetailMode::Nano)
            ),
            Space::with_width(Length::Fixed(12.0)),
            self.tab(
                "LOCAL",
                self.zone == TimeZoneMode::Local,
                Message::SetZone(TimeZoneMode::Local)
            ),
            self.tab(
                "UTC",
                self.zone == TimeZoneMode::Utc,
                Message::SetZone(TimeZoneMode::Utc)
            ),
            Space::with_width(Length::Fixed(12.0)),
            self.tab(
                "BENCH",
                self.panel == Panel::Bench,
                Message::ShowPanel(Panel::Bench)
            ),
            self.tab(
                "HYPERVISOR",
                self.panel == Panel::Hypervisor,
                Message::ShowPanel(Panel::Hypervisor)
            ),
            self.tab(
                "SETTINGS",
                self.panel == Panel::Settings,
                Message::ShowPanel(Panel::Settings)
            ),
        ]
        .spacing(6)
        .align_y(Alignment::Center);

        container(column![title_line, Space::with_height(Length::Fixed(8.0)), tabs].padding(12))
            .style(style::nav)
            .width(Length::Fill)
            .into()
    }

    fn tab<'a>(&self, label: &'a str, active: bool, message: Message) -> Element<'a, Message> {
        button(text(label).font(MONO).size(12))
            .padding([6, 12])
            .style(style::tab(active))
            .on_press(message)
            .into()
    }

    // -- clock / stopwatch / timer -----------------------------------------

    fn clock_panel(&self) -> Element<'_, Message> {
        let face: Element<'_, Message> =
            if self.view == ClockView::Clock && self.design == ClockDesign::Analog {
                let offset = self.zone.offset_minutes(self.snapshot.unix_time_ns);
                let local_ns = (self.snapshot.unix_time_ns as i128
                    + offset as i128 * 60 * 1_000_000_000)
                    .max(0) as u64;
                canvas(clockface::AnalogClock::new(local_ns))
                    .width(Length::Fixed(220.0))
                    .height(Length::Fixed(220.0))
                    .into()
            } else {
                let (value, colour) = self.face_text();
                // The Win32 build drew the digits twice — a dark green copy offset
                // by three pixels, then the bright face over it — for a CRT-style
                // bloom. Stacking two padded containers reproduces it.
                let glow = container(
                    text(value.clone())
                        .font(MONO)
                        .size(58)
                        .color(style::TIMER_GLOW),
                )
                .padding(iced::Padding {
                    top: 6.0,
                    right: 0.0,
                    bottom: 0.0,
                    left: 6.0,
                })
                .center_x(Length::Fill)
                .center_y(Length::Fixed(160.0));

                let face = container(text(value).font(MONO).size(58).color(colour))
                    .center_x(Length::Fill)
                    .center_y(Length::Fixed(160.0));

                iced::widget::stack![glow, face].into()
            };

        let date_line = row![
            text(format::format_offset(
                self.zone.offset_minutes(self.snapshot.unix_time_ns)
            ))
            .font(MONO)
            .size(12)
            .color(style::TIMER),
            Space::with_width(Length::Fill),
            text(format::format_long_date(
                self.snapshot.unix_time_ns,
                self.zone
            ))
            .font(MONO)
            .size(12)
            .color(style::INFO),
            Space::with_width(Length::Fill),
            text(self.snapshot.route.name())
                .font(MONO)
                .size(12)
                .color(style::TIMER),
        ];

        column![
            container(face)
                .style(style::inset)
                .width(Length::Fill)
                .padding(12)
                .center_x(Length::Fill),
            Space::with_height(Length::Fixed(10.0)),
            date_line,
            Space::with_height(Length::Fixed(12.0)),
            row![
                self.raw_clock_panel(),
                self.ntp_panel(),
                self.calibration_panel(),
            ]
            .spacing(12)
            .height(Length::Fixed(210.0)),
            Space::with_height(Length::Fixed(10.0)),
            self.controls_row(),
        ]
        .into()
    }

    /// The big readout, and the colour that says what state it is in.
    fn face_text(&self) -> (String, iced::Color) {
        match self.view {
            ClockView::Clock => (
                format::format_clock_face(
                    self.snapshot.unix_time_ns,
                    self.zone,
                    self.detail == DetailMode::Nano,
                ),
                style::TIMER,
            ),
            ClockView::Stopwatch => (
                self.stopwatch.format(&self.chrono, self.detail),
                style::timer_color(self.stopwatch.state()),
            ),
            ClockView::Timer => {
                let target_ns = self
                    .timer_preset
                    .parse::<u64>()
                    .unwrap_or(0)
                    .saturating_mul(1_000_000_000);
                let elapsed = self.stopwatch.elapsed_ns(&self.chrono);
                let remaining = target_ns.saturating_sub(elapsed);
                let colour = if remaining == 0 && target_ns > 0 {
                    style::ALERT
                } else {
                    style::timer_color(self.stopwatch.state())
                };
                (format::format_elapsed(remaining, self.detail), colour)
            }
        }
    }

    fn raw_clock_panel(&self) -> Element<'_, Message> {
        let body = column![
            panel_title("LOCAL CLOCK (RAW)"),
            readout(
                "time",
                &format::format_clock_face(self.snapshot.unix_time_ns, self.zone, true)
            ),
            readout("raw counter", &self.snapshot.selected_raw_units.to_string()),
            readout("route", self.snapshot.route.name()),
            readout("simd", self.snapshot.simd_name()),
            readout(
                "read overhead",
                &format!("{} units", self.snapshot.native_overhead_units)
            ),
            readout(
                "perf cycles",
                &match self.snapshot.perf_cycles {
                    Some(cycles) => {
                        format!("{cycles} ({} PMU, ring3 per-thread)", self.snapshot.perf_pmu_count)
                    }
                    None => "unavailable (ring3)".to_string(),
                }
            ),
            readout(
                "perf ring0",
                &match nanochrono_core::ring0_perf::Ring0Perf::read() {
                    Some(p) => {
                        format!("{} {} ({} CPU, system-wide)", p.scaled, p.event.name(), p.npmu)
                    }
                    None => "unavailable (module not loaded)".to_string(),
                }
            ),
            readout(
                "cpu",
                &if self.snapshot.cpu_index == nanochrono_core::platform::CPU_UNKNOWN {
                    "unknown".to_string()
                } else {
                    self.snapshot.cpu_index.to_string()
                }
            ),
        ]
        .spacing(4);

        container(body)
            .style(style::panel)
            .padding(12)
            .width(Length::Fill)
            .into()
    }

    fn ntp_panel(&self) -> Element<'_, Message> {
        // The C build painted "+112 ns / 452 us / Stratum: 2" as string
        // literals. These are readings, and say so when there are none.
        let body: Element<'_, Message> = match &self.ntp_result {
            _ if self.ntp_in_flight => text("querying...")
                .font(MONO)
                .size(12)
                .color(style::MUTED)
                .into(),
            Some(Ok(sample)) => column![
                readout(
                    "server time",
                    &format::format_unix_utc(sample.ntp_transmit_unix_ns)
                ),
                readout(
                    "offset",
                    &format!(
                        "{:+.3} ms ±{:.3}",
                        sample.offset_ms(),
                        sample.offset_uncertainty_ns() as f64 / 1e6
                    )
                ),
                readout("delay", &format!("{:.3} ms", sample.delay_ms())),
                readout("stratum", &sample.stratum.to_string()),
                readout("setup", &format!("{} units", sample.socket_setup_units)),
                readout("send/recv", &format!("{} units", sample.send_recv_units)),
            ]
            .spacing(4)
            .into(),
            Some(Err(e)) => text(e).font(MONO).size(12).color(style::ALERT).into(),
            None => text("not queried")
                .font(MONO)
                .size(12)
                .color(style::MUTED)
                .into(),
        };

        let controls = row![
            text_input("server", &self.ntp_server)
                .on_input(Message::NtpServerChanged)
                .font(MONO)
                .size(12)
                .padding(4)
                .style(style::input),
            button(text("QUERY").font(MONO).size(11))
                .padding([4, 10])
                .style(style::action)
                .on_press(Message::QueryNtp),
        ]
        .spacing(6)
        .align_y(Alignment::Center);

        container(
            column![
                panel_title("NTP"),
                body,
                Space::with_height(Length::Fill),
                controls
            ]
            .spacing(4),
        )
        .style(style::panel)
        .padding(12)
        .width(Length::Fill)
        .into()
    }

    fn calibration_panel(&self) -> Element<'_, Message> {
        let c = &self.calibration;
        let body: Element<'_, Message> = if c.cycles_per_ns() > 0.0 {
            column![
                readout("cycles_per_ns", &format!("{:.9}", c.cycles_per_ns())),
                readout("ns_per_cycle", &format!("{:.9}", c.ns_per_cycle())),
                readout("window", &format!("{:.3} ms", c.elapsed_ns as f64 / 1e6)),
                readout("pinned", yes_no(c.pinned)),
                readout("migrated", yes_no(c.migrated)),
                readout("invariant", yes_no(c.invariant)),
            ]
            .spacing(4)
            .into()
        } else {
            text("calibrating...")
                .font(MONO)
                .size(12)
                .color(style::MUTED)
                .into()
        };

        container(
            column![
                panel_title("CALIBRATION"),
                body,
                Space::with_height(Length::Fill),
                button(text("RECALIBRATE").font(MONO).size(11))
                    .padding([4, 10])
                    .style(style::action)
                    .on_press(Message::Recalibrate),
            ]
            .spacing(4),
        )
        .style(style::panel)
        .padding(12)
        .width(Length::Fill)
        .into()
    }

    fn controls_row(&self) -> Element<'_, Message> {
        let primary = match self.stopwatch.state() {
            StopwatchState::Running => "PAUSE",
            StopwatchState::Reset => "START",
            _ => "RESUME",
        };

        let mut controls = row![
            button(text(primary).font(MONO).size(12))
                .padding([6, 16])
                .style(style::tab(
                    self.stopwatch.state() == StopwatchState::Running
                ))
                .on_press(Message::StopwatchToggle),
            button(text("STOP").font(MONO).size(12))
                .padding([6, 16])
                .style(style::action)
                .on_press(Message::StopwatchStop),
            button(text("LAP").font(MONO).size(12))
                .padding([6, 16])
                .style(style::action)
                .on_press(Message::StopwatchLap),
            button(text("RESET").font(MONO).size(12))
                .padding([6, 16])
                .style(style::action)
                .on_press(Message::StopwatchReset),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        if self.view == ClockView::Timer {
            controls = controls.push(Space::with_width(Length::Fixed(16.0)));
            controls = controls.push(
                text("countdown (s)")
                    .font(MONO)
                    .size(12)
                    .color(style::MUTED),
            );
            controls = controls.push(
                text_input("60", &self.timer_preset)
                    .on_input(Message::TimerPresetChanged)
                    .font(MONO)
                    .size(12)
                    .padding(4)
                    .width(Length::Fixed(90.0))
                    .style(style::input),
            );
        }

        if let Some(last_lap) = self.stopwatch.last_lap() {
            controls = controls.push(Space::with_width(Length::Fill));
            controls = controls.push(
                text(format!(
                    "last lap: {}",
                    format::format_elapsed(last_lap, self.detail)
                ))
                .font(MONO)
                .size(12)
                .color(style::MUTED),
            );
        }

        controls.into()
    }

    // -- benchmark panel ---------------------------------------------------

    fn bench_panel(&self) -> Element<'_, Message> {
        let mut modes = column![panel_title("BENCHMARK MODE")].spacing(4);
        for mode in BenchMode::ALL.iter().copied() {
            let selected = mode == self.bench_mode;
            modes = modes.push(
                button(
                    row![
                        text(mode.label()).font(MONO).size(12),
                        Space::with_width(Length::Fill),
                        text(if selected { "SELECTED" } else { "AVAILABLE" })
                            .font(MONO)
                            .size(11),
                    ]
                    .width(Length::Fill),
                )
                .padding([5, 10])
                .width(Length::Fill)
                .style(style::row(selected, true))
                .on_press(Message::SelectBenchMode(mode)),
            );
        }

        let mut rows = column![panel_title("FEATURE / OPERATION")].spacing(2);
        for (index, kernel) in self.bench_rows.iter().enumerate() {
            let available = kernel.is_available();
            let selected = self.bench_selected == Some(index);
            let entry = button(
                row![
                    text(kernel.name()).font(MONO).size(12),
                    Space::with_width(Length::Fill),
                    text(if available {
                        "AVAILABLE"
                    } else {
                        "NOT AVAILABLE"
                    })
                    .font(MONO)
                    .size(11),
                ]
                .width(Length::Fill),
            )
            .padding([4, 10])
            .width(Length::Fill)
            .style(style::row(selected, available));

            // An unavailable row stays visible but inert: the panel is meant
            // to show the whole ISA landscape, including what this CPU lacks.
            rows = rows.push(if available && !self.bench_running {
                entry.on_press(Message::RunBench(index))
            } else {
                entry
            });
        }

        let log_text = self
            .bench_report
            .as_ref()
            .map(|r| r.log.as_str())
            .unwrap_or(
                "Select a mode, then click a feature row.\n\n\
                 Mode 1 runs inline-asm ISA kernels gated by CPUID + XGETBV.\n\
                 Mode 2 runs real AEAD and hash calls through the rustls crypto provider.\n\
                 Mode 3 performs full rustls TLS 1.3 handshakes and splits the cost by phase.\n\
                 Crypto RAW times the bare crypto instructions (AES round, SHA-256 round,\n\
                 carry-less multiply, VAES, VPCLMULQDQ): speed only, no cipher, no security.\n\n\
                 Keys 1-9 pick a mode by its number.",
            );

        let log = container(
            scrollable(text(log_text).font(MONO).size(12).color(style::INFO))
                .height(Length::Fill)
                .width(Length::Fill),
        )
        .style(style::inset)
        .padding(10)
        .height(Length::Fill)
        .width(Length::Fill);

        let footer = row![
            text(if self.bench_running {
                "running benchmark..."
            } else {
                "click a row to run it"
            })
            .font(MONO)
            .size(12)
            .color(if self.bench_running {
                style::TIMER
            } else {
                style::MUTED
            }),
            Space::with_width(Length::Fill),
            button(text("SAVE LOG").font(MONO).size(11))
                .padding([4, 12])
                .style(style::action)
                .on_press(Message::SaveLog),
        ]
        .align_y(Alignment::Center);

        column![
            row![
                container(column![modes, Space::with_height(Length::Fixed(14.0)), rows].spacing(4))
                    .style(style::panel)
                    .padding(12)
                    .width(Length::FillPortion(2))
                    .height(Length::Fill),
                log.width(Length::FillPortion(3)),
            ]
            .spacing(12)
            .height(Length::Fill),
            Space::with_height(Length::Fixed(10.0)),
            footer,
        ]
        .into()
    }

    // -- hypervisor panel --------------------------------------------------

    /// Virtualization detection, and what it means for every other number the
    /// window shows.
    ///
    /// This is the panel a reader should visit *before* trusting a nanosecond
    /// figure, so the verdict and its consequence sit at the top and the
    /// evidence underneath.
    fn settings_panel(&self) -> Element<'_, Message> {
        use nanochrono_core::arch::{self, CounterSource};

        let available = arch::has_physical_counter();
        let enabled = arch::counter_source() == CounterSource::Physical;
        let virtualized = hypervisor_present();

        let switch = button(
            text(if enabled { "ON" } else { "OFF" })
                .font(MONO)
                .size(13),
        )
        .padding([6, 18])
        .style(style::tab(enabled));
        let switch = if available {
            switch.on_press(Message::SetPhysicalCounter(!enabled))
        } else {
            switch
        };

        let mut section = column![
            panel_title("COUNTER"),
            row![
                text("Enable Physical Counter").font(MONO).size(14).color(style::VALUE),
                Space::with_width(Length::Fill),
                switch,
            ]
            .align_y(Alignment::Center),
            text(format!(
                "in use: {}  ·  default: {}",
                arch::counter_source().name(),
                CounterSource::Virtual.name()
            ))
            .font(MONO)
            .size(12)
            .color(style::INFO),
        ]
        .spacing(8);

        if !available {
            section = section.push(
                text(
                    "Not applicable on this architecture: only AArch64 has a separate \
                     physical counter (CNTPCT_EL0). x86 has one TSC; RISC-V and PowerPC \
                     have one user-visible timebase.",
                )
                .font(MONO)
                .size(12)
                .color(style::MUTED),
            );
        } else {
            // The warning is always visible, not only once enabled: it is
            // the information needed to decide whether to enable it.
            section = section.push(
                container(
                    text(arch::PHYSICAL_COUNTER_WARNING)
                        .font(MONO)
                        .size(12)
                        .color(if virtualized { style::ALERT } else { style::PAUSED }),
                )
                .style(style::inset)
                .padding(12)
                .width(Length::Fill),
            );
            if virtualized {
                section = section.push(
                    text(format!(
                        "This system is virtualized ({}). The counter can still be enabled; \
                         expect trapped, jittery reads — worse under nested virtualization.",
                        nanochrono_core::hypervisor::cached().hypervisor
                    ))
                    .font(MONO)
                    .size(12)
                    .color(style::ALERT),
                );
            }
            if let Some(check) = &self.counter_check {
                section = section.push(
                    text(format!(
                        "one read: {} ns physical vs {} ns virtual{}",
                        check.physical_read_ns,
                        check.virtual_read_ns,
                        if check.trapped { "  —  the physical read is being trapped" } else { "" }
                    ))
                    .font(MONO)
                    .size(12)
                    .color(if check.trapped { style::ALERT } else { style::OK }),
                );
            }
            if let Some(error) = &self.counter_error {
                section = section.push(
                    text(format!("could not enable: {error}"))
                        .font(MONO)
                        .size(12)
                        .color(style::ALERT),
                );
            }
            section = section.push(
                text("Switching counters resets the stopwatch: in a VM the two differ by an offset.")
                    .font(MONO)
                    .size(11)
                    .color(style::MUTED),
            );
        }

        let cooldown_on = nanochrono_core::hypervisor::reprobe_cooldown_enabled();
        let cooldown_switch = button(
            text(if cooldown_on { "ON" } else { "OFF" }).font(MONO).size(13),
        )
        .padding([6, 18])
        .style(style::tab(cooldown_on))
        .on_press(Message::SetReprobeCooldown(!cooldown_on));
        let mut reprobe = column![
            panel_title("HYPERVISOR RE-PROBE"),
            row![
                text(format!(
                    "Re-probe cooldown ({} s)",
                    nanochrono_core::reprobe::DEFAULT_COOLDOWN_S
                ))
                .font(MONO)
                .size(14)
                .color(style::VALUE),
                Space::with_width(Length::Fill),
                cooldown_switch,
            ]
            .align_y(Alignment::Center),
            text(nanochrono_core::reprobe::COOLDOWN_NOTE)
                .font(MONO)
                .size(12)
                .color(style::INFO),
        ]
        .spacing(8);
        // The warning shows whether or not the wait is off: it is what the
        // user needs to read before turning it off.
        reprobe = reprobe.push(
            container(
                text(nanochrono_core::reprobe::COOLDOWN_OFF_WARNING)
                    .font(MONO)
                    .size(12)
                    .color(if cooldown_on { style::PAUSED } else { style::ALERT }),
            )
            .style(style::inset)
            .padding(12)
            .width(Length::Fill),
        );
        if let Some((ok, message)) = &self.reprobe_status {
            reprobe = reprobe.push(
                text(message.as_str())
                    .font(MONO)
                    .size(12)
                    .color(if *ok { style::OK } else { style::ALERT }),
            );
        }

        scrollable(
            column![
                container(section).style(style::panel).padding(18).width(Length::Fill),
                container(reprobe).style(style::panel).padding(18).width(Length::Fill),
            ]
            .spacing(12),
        )
        .into()
    }

    fn hypervisor_panel(&self) -> Element<'_, Message> {
        use nanochrono_core::hypervisor::{self, Confidence, TimingImpact};

        let report = &self.hv_report;

        let verdict_colour = match report.timing_impact {
            TimingImpact::Native => style::OK,
            TimingImpact::HardwareAssisted => style::PAUSED,
            TimingImpact::Emulated => style::ALERT,
        };

        let verdict = container(
            column![
                text(report.hypervisor.name().to_uppercase())
                    .font(MONO)
                    .size(34)
                    .color(verdict_colour),
                Space::with_height(Length::Fixed(6.0)),
                text(format!(
                    "{}  ·  confidence: {}",
                    report.timing_impact.name(),
                    report.confidence.name()
                ))
                .font(MONO)
                .size(13)
                .color(style::INFO),
                Space::with_height(Length::Fixed(10.0)),
                text(report.timing_impact.advice())
                    .font(MONO)
                    .size(12)
                    .color(if report.is_virtualized() {
                        style::VALUE
                    } else {
                        style::MUTED
                    }),
            ]
            .align_x(Alignment::Center),
        )
        .style(style::inset)
        .width(Length::Fill)
        .padding(18)
        .center_x(Length::Fill);

        // --- ring 3 evidence
        let mut ring3 = column![panel_title("RING 3 / EL0 — always available")].spacing(4);

        // x86 identifies through CPUID; AArch64 has none, and identifies
        // through the registers EL0 is allowed to read. Showing whichever
        // applies keeps the panel from listing a row that is always "none".
        if report.arm_counter_hz != 0 {
            ring3 = ring3.push(readout(
                "cntfrq_el0",
                &format!("{:.3} MHz", report.arm_counter_hz as f64 / 1e6),
            ));
            if report.arm_midr_el1 != 0 {
                ring3 = ring3.push(readout(
                    "midr_el1",
                    &format!(
                        "impl {:#04x} part {:#05x}",
                        (report.arm_midr_el1 >> 24) & 0xFF,
                        (report.arm_midr_el1 >> 4) & 0xFFF
                    ),
                ));
            }
        } else {
            ring3 = ring3.push(readout(
                "cpuid vendor",
                report.signature.as_deref().unwrap_or("none"),
            ));
        }
        if let Some(leaf) = report.max_hypervisor_leaf {
            ring3 = ring3.push(readout("max hv leaf", &format!("{leaf:#010x}")));
        }
        if let Some(khz) = report.declared_tsc_khz {
            ring3 = ring3.push(readout(
                "declared tsc",
                &format!("{:.3} MHz", khz as f64 / 1000.0),
            ));
        }
        if let Some(cost) = &report.exit_cost {
            // The two architectures probe different things: a CPUID exit on
            // x86, an ISB re-fetch on AArch64. Labelling them the same would
            // invite reading one as the other.
            let trap_label = if report.arm_counter_hz != 0 {
                "isb cost"
            } else {
                "cpuid trap"
            };
            ring3 = ring3.push(readout(trap_label, &format!("{} cyc", cost.trap_cycles)));
            ring3 = ring3.push(readout(
                "counter baseline",
                &format!("{} cyc", cost.baseline_cycles),
            ));
            ring3 = ring3.push(readout(
                "ratio",
                &format!(
                    "{:.1}x — {}",
                    cost.ratio,
                    if cost.suggests_exit {
                        "exits to a VMM"
                    } else {
                        "no exit"
                    }
                ),
            ));
        }
        for (label, value) in [
            ("dmi vendor", &report.dmi.sys_vendor),
            ("dmi product", &report.dmi.product_name),
        ] {
            if let Some(v) = value {
                ring3 = ring3.push(readout(label, v));
            }
        }

        // --- ring 0 evidence, or an explanation of what is missing.
        let mut ring0 = column![panel_title("RING 0 — optional kernel module")].spacing(4);
        match &report.kernel {
            Some(k) => {
                ring0 = ring0.push(readout("module", &format!("nanochrono.ko (v{})", k.version)));
                let flag = |v: Option<bool>| match v {
                    Some(true) => "accepted".to_string(),
                    Some(false) => "faulted".to_string(),
                    None => "not probed".to_string(),
                };
                ring0 = ring0.push(readout("vmcall", &flag(k.vmcall_ok)));
                ring0 = ring0.push(readout("vmmcall", &flag(k.vmmcall_ok)));
                ring0 = ring0.push(readout("hvc", &flag(k.hvc_ok)));
                if let Some(result) = k.hypercall_result {
                    ring0 = ring0.push(readout("returned", &result.to_string()));
                }
                if let (Some(vmx), Some(svm)) = (k.vmx_available, k.svm_available) {
                    ring0 = ring0.push(readout("vmx / svm", &format!("{vmx} / {svm}")));
                }
                if let Some(el) = k.current_el {
                    ring0 = ring0.push(readout("current el", &el.to_string()));
                }
                if let Some(n) = k.hypercall_probes {
                    ring0 = ring0.push(readout(
                        "probes run",
                        &format!(
                            "{n} (cooldown {})",
                            match k.hypercall_cooldown_s {
                                Some(0) => "OFF".to_string(),
                                Some(s) => format!("{s} s"),
                                None => "?".to_string(),
                            }
                        ),
                    ));
                }
                // Reading the perf keys re-runs no probe: the module serves
                // its cached hypervisor report and live PMU sums.
                match nanochrono_core::ring0_perf::Ring0Perf::read() {
                    Some(p) => {
                        ring0 = ring0.push(readout(
                            "perf ring0",
                            &format!("{} over {} CPU events", p.event.name(), p.npmu),
                        ));
                        ring0 = ring0.push(readout(
                            "scaled",
                            &format!("{} (raw {})", p.scaled, p.raw),
                        ));
                        ring0 = ring0.push(readout(
                            "scheduled",
                            &format!("{} / {} ns", p.running_ns, p.enabled_ns),
                        ));
                    }
                    None => {
                        ring0 = ring0.push(readout("perf ring0", "no PMU events available"));
                    }
                }
            }
            None => {
                ring0 = ring0.push(
                    text(
                        "Not loaded — and not required. Detection above works without it.\n\n\
                         The module adds what ring 3 cannot do at all: VMCALL, VMMCALL and HVC \
                         need CPL 0 / EL1, so from userspace they fault whether or not a \
                         hypervisor is present. A hypercall that returns is proof, and it holds \
                         even against a hypervisor that clears its CPUID bit. It probes once \
                         when it loads, and also publishes system-wide PMU counters beside the \
                         per-thread ring-3 ones.\n\n\
                         cd kernel/linux && sudo make load",
                    )
                    .font(MONO)
                    .size(11)
                    .color(style::MUTED),
                );
            }
        }

        // --- re-probe: once at start, then the button, behind the cooldown.
        let wait = hypervisor::reprobe_wait_s();
        let label = if wait > 0 {
            format!("RE-PROBE ({wait} s)")
        } else {
            "RE-PROBE".to_string()
        };
        let reprobe_button = button(text(label).font(MONO).size(13))
            .padding([6, 18])
            .style(style::tab(wait == 0));
        let reprobe_button = if wait == 0 {
            reprobe_button.on_press(Message::Reprobe)
        } else {
            reprobe_button
        };
        let mut reprobe = column![
            row![
                text(if hypervisor::reprobe_cooldown_enabled() {
                    nanochrono_core::reprobe::COOLDOWN_NOTE
                } else {
                    "Re-probe cooldown is OFF (Settings) — the provider-ban risk is yours."
                })
                .font(MONO)
                .size(11)
                .color(if hypervisor::reprobe_cooldown_enabled() { style::MUTED } else { style::ALERT }),
                Space::with_width(Length::Fill),
                reprobe_button,
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        ];
        if let Some((ok, message)) = &self.reprobe_status {
            reprobe = reprobe.push(
                text(message.as_str())
                    .font(MONO)
                    .size(11)
                    .color(if *ok { style::OK } else { style::ALERT }),
            );
        }
        ring0 = ring0.push(reprobe);

        // --- where the evidence came from
        let sources = if report.sources.is_empty() {
            "none — nothing on this platform claims to be virtualized".to_string()
        } else {
            report
                .sources
                .iter()
                .map(|s| s.name())
                .collect::<Vec<_>>()
                .join("   ")
        };

        // --- stored-state integrity, the other way a number goes quietly wrong
        let integrity = nanochrono_core::redundancy::stats();
        let integrity_line = format!(
            "state integrity: {}  ({})",
            integrity.summary(),
            if integrity.is_clean() {
                "ECC verified, TMR never needed"
            } else {
                "repairs occurred — check memory health"
            }
        );

        // --- how the PMU is being read, which the same panel should answer.
        // Ring 3 is per-thread (this process); ring 0 is system-wide per-CPU
        // sums from the perf module, when it owns /proc/nanochrono.
        let pmu = nanochrono_core::pmu::backend();
        let mut pmu_line = format!(
            "PMU ring3 via {} ({}), {} event(s)",
            pmu.name(),
            if pmu.is_hardware_counter() {
                "hardware counter"
            } else {
                "kernel accounting"
            },
            nanochrono_core::pmu::pmu_count(),
        );
        if let Some(p) = nanochrono_core::ring0_perf::Ring0Perf::read() {
            pmu_line.push_str(&format!(
                "   ·   ring0 {} scaled={} (raw {}, {} CPU events{})",
                p.event.name(),
                p.scaled,
                p.raw,
                p.npmu,
                if p.enabled { "" } else { ", disabled" },
            ));
        }

        column![
            verdict,
            Space::with_height(Length::Fixed(12.0)),
            row![
                container(ring3)
                    .style(style::panel)
                    .padding(12)
                    .width(Length::FillPortion(1))
                    .height(Length::Fill),
                container(ring0)
                    .style(style::panel)
                    .padding(12)
                    .width(Length::FillPortion(1))
                    .height(Length::Fill),
            ]
            .spacing(12)
            .height(Length::Fill),
            Space::with_height(Length::Fixed(10.0)),
            container(column![
                row![
                    text("evidence").font(MONO).size(11).color(style::MUTED),
                    Space::with_width(Length::Fixed(12.0)),
                    text(sources).font(MONO).size(11).color(
                        if report.confidence == Confidence::Confirmed {
                            style::TIMER
                        } else {
                            style::INFO
                        }
                    ),
                ],
                Space::with_height(Length::Fixed(4.0)),
                text(pmu_line).font(MONO).size(11).color(style::MUTED),
                Space::with_height(Length::Fixed(4.0)),
                text(integrity_line)
                    .font(MONO)
                    .size(11)
                    .color(if integrity.is_clean() {
                        style::MUTED
                    } else {
                        style::ALERT
                    }),
            ])
            .style(style::inset)
            .width(Length::Fill)
            .padding(10),
        ]
        .into()
    }

    // -- bars --------------------------------------------------------------

    fn hint_bar(&self) -> Element<'_, Message> {
        let hint = match self.panel {
            Panel::Bench => {
                "[B] clock   [H] hypervisor   [C] clock design   click a feature row to run it   [ESC] exit"
            }
            Panel::Hypervisor => "[H] clock   [B] bench   [ESC] exit",
            Panel::Settings => "[G] clock   [H] hypervisor   [B] bench   [ESC] exit",
            Panel::Clock => match self.stopwatch.state() {
                StopwatchState::Running => {
                    "[SPACE/P] pause   [S] stop   [L] lap   [R] reset   [B] bench   [H] hypervisor"
                }
                StopwatchState::Reset => {
                    "[SPACE/P] start   [B] bench   [H] hypervisor   [M] simple   [N] nano   [ESC] exit"
                }
                _ => "[SPACE/P] resume   [R] reset   [B] bench   [H] hypervisor   [ESC] exit",
            },
        };

        column![
            horizontal_rule(1),
            container(
                row![
                    text(hint).font(MONO).size(11).color(style::MUTED),
                    Space::with_width(Length::Fill),
                    text(&self.notice).font(MONO).size(11).color(style::TIMER),
                ]
                .align_y(Alignment::Center)
            )
            .padding([4, 14]),
        ]
        .into()
    }

    fn status_bar(&self) -> Element<'_, Message> {
        let left = format!(
            "overhead: {} units   drift: {:+.2} ppm   route: {}   simd: {}   cpn: {:.6}",
            self.snapshot.native_overhead_units,
            self.chrono.drift_ppm(),
            self.snapshot.route.name(),
            self.snapshot.simd_name(),
            self.calibration.cycles_per_ns(),
        );
        let platform = nanochrono_core::hypervisor::cached();
        let integrity = nanochrono_core::redundancy::stats();
        let right = format!(
            "{}  {:.3} MHz  |  {}  |  {}",
            self.chrono.backend().name(),
            self.chrono.counter_hz() as f64 / 1e6,
            self.detail.name(),
            SimdFamily::best()
                .map(SimdFamily::name)
                .unwrap_or("no simd"),
        );

        container(
            row![
                text(left).font(MONO).size(11),
                Space::with_width(Length::Fill),
                // The platform qualifies every other figure on this line, so
                // it sits between them, coloured when it is not bare metal.
                text(platform.summary())
                    .font(MONO)
                    .size(11)
                    .color(if platform.is_virtualized() {
                        style::PAUSED
                    } else {
                        style::MUTED
                    }),
                // Silent while nothing has needed repair: a permanent
                // "0 corrections" counter is noise, and the point is to be
                // noticed the moment it stops being zero.
                text(if integrity.is_clean() {
                    String::new()
                } else {
                    format!("  {}", integrity.summary())
                })
                .font(MONO)
                .size(11)
                .color(style::ALERT),
                Space::with_width(Length::Fixed(14.0)),
                text(right).font(MONO).size(11),
            ]
            .align_y(Alignment::Center),
        )
        .style(style::status_bar)
        .width(Length::Fill)
        .padding([4, 14])
        .into()
    }

    // -- helpers -----------------------------------------------------------

    fn ntp_host_for_tls(&self) -> String {
        // The TLS benchmark reuses whatever host the operator typed, so one
        // field configures both network probes.
        if self.ntp_server.trim().is_empty() {
            "www.rust-lang.org".to_string()
        } else {
            self.ntp_server.trim().to_string()
        }
    }

    fn save_log(&self) -> Result<String, String> {
        let Some(report) = &self.bench_report else {
            return Err("no benchmark has been run yet".to_string());
        };
        let stamp = self.snapshot.unix_time_ns / 1_000_000_000;
        let path = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(format!("nanochrono-bench-{stamp}.log"));
        std::fs::write(&path, &report.log).map_err(|e| e.to_string())?;
        Ok(path.display().to_string())
    }
}

// -- widget helpers --------------------------------------------------------

fn panel_title(label: &str) -> Element<'_, Message> {
    text(label).font(MONO).size(12).color(style::LABEL).into()
}

/// A `label ......... value` line, the panel's basic unit.
fn readout<'a>(label: &'a str, value: &str) -> Element<'a, Message> {
    row![
        text(label).font(MONO).size(12).color(style::MUTED),
        Space::with_width(Length::Fill),
        text(value.to_string())
            .font(MONO)
            .size(12)
            .color(style::VALUE),
    ]
    .width(Length::Fill)
    .into()
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

// -- background work -------------------------------------------------------

/// Runs a benchmark off the UI thread.
///
/// Three passes of a million-iteration kernel takes hundreds of milliseconds;
/// on the UI thread that is a visibly frozen window, which is what the C build
/// avoided with a raw `CreateThread` and a `CRITICAL_SECTION` around the log.
async fn run_bench(config: BenchConfig) -> Arc<BenchReport> {
    let handle = tokio::task::spawn_blocking(move || {
        // A fresh chronometer per run: it calibrates on construction, so the
        // conversion factor matches the conditions the benchmark ran under.
        let chrono = Chronometer::new();
        nanochrono_bench::run(&chrono, &config)
    });

    match handle.await {
        Ok(report) => Arc::new(report),
        Err(e) => Arc::new(BenchReport {
            summary: Default::default(),
            log: format!("benchmark task panicked: {e}\n"),
            error: Some(e.to_string()),
        }),
    }
}

/// Queries NTP off the UI thread; the socket blocks for up to a timeout.
async fn query_ntp(server: String) -> Result<NtpSample, String> {
    tokio::task::spawn_blocking(move || {
        let chrono = Chronometer::new();
        ntp::query(
            &chrono,
            &server,
            ntp::DEFAULT_TIMEOUT_MS,
            Default::default(),
        )
        .map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("NTP task panicked: {e}")))
}

/// Calibrates off the UI thread; the window would otherwise stall for the
/// whole calibration window.
async fn calibrate() -> StableClockState {
    tokio::task::spawn_blocking(|| {
        let chrono = Chronometer::new();
        let config = StableClockConfig {
            // Not pinned: pinning the UI thread to a core for the life of the
            // process is the wrong trade for a desktop app. The panel reports
            // `migrated` so the number can be judged.
            pin_cpu: false,
            warmup_ms: 10,
            calibration_ms: 300,
            require_no_migration: false,
            ..Default::default()
        };
        clock::calibrate_cycles_per_ns(&chrono, &config)
    })
    .await
    .unwrap_or_default()
}

#[cfg(test)]
mod icon_tests {
    use super::*;

    /// The application icon must actually decode.
    ///
    /// This is the test the project did not have, and its absence cost a
    /// release: `window::icon::from_file_data(.., None)` asks the `image`
    /// crate to sniff the format, which only works if the ICO decoder was
    /// compiled in — and `iced` does not enable that feature on its copy of
    /// `image`. The call failed on every start, the `.ok()` discarded the
    /// error, and the window ran with no icon while everything still built
    /// and ran. Nothing but an assertion catches a failure that is designed
    /// to be silent.
    #[test]
    fn the_application_icon_decodes() {
        assert!(
            window_icon().is_some(),
            "the bundled icon did not decode; the window would run without one"
        );
    }

    /// And it must be square, because every platform's icon slot is.
    ///
    /// The repository also contains a 1020x225 wordmark, and installing that
    /// as the desktop icon is what made Linux show an illegible sliver of
    /// lettering instead of the logo. Pointing this constant at the wrong
    /// asset should fail here rather than on somebody's desktop.
    #[test]
    fn the_application_icon_is_square() {
        let decoded = image::load_from_memory_with_format(ICON_ICO, image::ImageFormat::Ico)
            .expect("the icon decodes");
        let (width, height) = (decoded.width(), decoded.height());
        assert_eq!(
            width, height,
            "the icon is {width}x{height}; an icon has to be square"
        );
        assert!(
            width >= 256,
            "the icon is {width}px; desktops ask for 256 and macOS for 512"
        );
    }
}

/// Whether a hypervisor or emulator was detected (cached; cheap).
fn hypervisor_present() -> bool {
    nanochrono_core::hypervisor::cached().is_virtualized()
}
