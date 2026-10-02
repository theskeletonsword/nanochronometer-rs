// SPDX-License-Identifier: Apache-2.0
//! About NanoChronometer: the logo, the version, the machine, the licences.

use super::{Ctx, Event, Response};
use crate::desktop::surface::Rect;
use crate::desktop::theme;
use crate::fonts::{UI13, UI15, UI15_SEMIBOLD};
use crate::framebuffer::Framebuffer;
use crate::text::Text;
use core::fmt::Write;

pub struct About;

impl About {
    pub fn new() -> About {
        About
    }

    pub fn paint(&mut self, fb: &Framebuffer, w: i32, h: i32, _ctx: &Ctx) {
        theme::fill(fb, Rect::new(0, 0, w, h), theme::WINDOW);
        let logo = crate::logo::for_height(52);
        let lx = (w - logo.width as i32) / 2;
        crate::logo::draw(fb, logo, lx.max(0) as u32, 28);
        let mut y = 28 + logo.height as i32 + 18;
        let line = |y: &mut i32, face: &crate::fonts::UiFace, s: &str, colour: u32| {
            face.draw_centred(fb, 0, w as u32, *y, s, colour);
            *y += face.line_height as i32 + 4;
        };
        let mut v = Text::<64>::new();
        let _ = write!(v, "Version {} · {}", crate::VERSION, crate::system::MACHINE);
        line(&mut y, &UI15_SEMIBOLD, v.as_str(), theme::TEXT);
        line(&mut y, &UI13, "Desktop Experience · freestanding, no operating system underneath", theme::TEXT_DIM);
        y += 10;
        if let Some(system) = crate::system::get() {
            let mut m = Text::<64>::new();
            if system.memory.total > 0 {
                let _ = write!(m, "{} MiB of memory · counter {} MHz", system.memory.total >> 20, system.hz() / 1_000_000);
            } else {
                let _ = write!(m, "counter {} MHz", system.hz() / 1_000_000);
            }
            line(&mut y, &UI15, m.as_str(), theme::TEXT);
            let hv = if system.hypervisor.is_virtualized() { "running under a hypervisor" } else { "running on bare metal" };
            line(&mut y, &UI13, hv, theme::TEXT_DIM);
        }
        y += 14;
        line(&mut y, &UI13, "Apache License 2.0", theme::TEXT_DIM);
        line(&mut y, &UI13, "Interface face: Adwaita Sans · terminal face: Source Code Pro", theme::TEXT_FAINT);
        line(&mut y, &UI13, "(SIL Open Font License 1.1)", theme::TEXT_FAINT);
        line(&mut y, &UI13, "Built with Rust and LLVM", theme::TEXT_FAINT);
        let _ = h;
    }

    pub fn event(&mut self, _ev: Event, _ctx: &Ctx) -> Response {
        Response::default()
    }
}
