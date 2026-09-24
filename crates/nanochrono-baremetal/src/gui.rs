// SPDX-License-Identifier: Apache-2.0
//! The interface.
//!
//! One implementation, [`gui_frame`](crate::gui_frame), for every
//! architecture. What differs between machines — where keys come from (the
//! 8042 and USB on x86, the serial console elsewhere), how the machine is
//! turned off (ACPI, PSCI, SBI, OPAL), which clocks the counter is checked
//! against — is chosen inside it by `cfg`, so the screen, the stopwatch and
//! every rule about them are the same code on all of them.

pub use crate::gui_frame::*;
