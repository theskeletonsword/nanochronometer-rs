// SPDX-License-Identifier: Apache-2.0
//! Firmware and devices are inputs, not authorities.
//!
//! The AML walker and interpreter read tables a BIOS wrote; the HID parser
//! reads descriptors a USB or I2C device sent. Both run in ring 0 with no
//! watchdog behind them, so a loop whose bound comes from those bytes is a
//! hang at boot. These tests feed them generated and mutated input — biased
//! towards the opcodes and item tags that open loops — and require every call
//! to return, without panicking, within a fixed time.
//!
//! Deterministic (a fixed-seed generator), so a failure reproduces by case
//! number.

use nanochrono_core::aml::Namespace;
use nanochrono_core::hid_report::{find_keyboard, find_pointer};
use std::time::{Duration, Instant};

/// xorshift64*: enough to vary bytes, and reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

/// Per call. The slowest legitimate input here finishes in microseconds; a
/// second is a hang, not a slow machine.
const LIMIT: Duration = Duration::from_secs(1);

fn timed(case: usize, what: &str, f: impl FnOnce()) {
    let start = Instant::now();
    f();
    let spent = start.elapsed();
    assert!(spent < LIMIT, "case {case}: {what} took {spent:?}");
}

/// A PkgLength-prefixed body. The length counts its own encoding bytes,
/// which is the detail a generator gets wrong and a parser must survive.
fn pkg(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let n = body.len();
    if n < 0x3F {
        out.push((n + 1) as u8);
    } else if n + 2 <= 0xFFF {
        let t = n + 2;
        out.push(0x40 | (t & 0x0F) as u8);
        out.push((t >> 4) as u8);
    } else {
        let t = n + 3;
        out.push(0x80 | (t & 0x0F) as u8);
        out.push((t >> 4) as u8);
        out.push((t >> 12) as u8);
    }
    out.extend_from_slice(body);
    out
}

/// An expression the interpreter evaluates: constants, locals, arguments
/// and the comparisons a loop condition is made of.
fn aml_expr(rng: &mut Rng, depth: u32) -> Vec<u8> {
    let leaf = depth == 0 || rng.below(3) == 0;
    if leaf {
        return match rng.below(6) {
            0 => vec![0x00],                        // Zero
            1 => vec![0x01],                        // One
            2 => vec![0xFF],                        // Ones
            3 => vec![0x0A, rng.byte()],            // ByteConst
            4 => vec![0x60 + rng.below(8) as u8],   // LocalN
            _ => vec![0x68 + rng.below(7) as u8],   // ArgN (none are passed)
        };
    }
    let op = [0x93u8, 0x95, 0x94, 0x92, 0x72, 0x74][rng.below(6) as usize];
    let mut out = vec![op];
    out.extend(aml_expr(rng, depth - 1));
    if op != 0x92 {
        out.extend(aml_expr(rng, depth - 1));
    }
    if op == 0x72 || op == 0x74 {
        out.push(0x00); // no target
    }
    out
}

/// Statements: the loops and branches whose bounds the table controls.
fn aml_stmts(rng: &mut Rng, depth: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(4) {
        match rng.below(if depth == 0 { 3 } else { 6 }) {
            0 => {
                out.push(0x70); // Store (expr, LocalN)
                out.extend(aml_expr(rng, 2));
                out.push(0x60 + rng.below(8) as u8);
            }
            1 => {
                out.push(0x75); // Increment (LocalN)
                out.push(0x60 + rng.below(8) as u8);
            }
            2 => {
                out.push(0xA4); // Return
                out.extend(aml_expr(rng, 2));
            }
            3 | 4 => {
                // While, or If with an optional Else
                let op = if rng.below(2) == 0 { 0xA2 } else { 0xA0 };
                let mut body = aml_expr(rng, 2);
                body.extend(aml_stmts(rng, depth - 1));
                out.push(op);
                out.extend(pkg(&body));
                if op == 0xA0 && rng.below(2) == 0 {
                    out.push(0xA1);
                    out.extend(pkg(&aml_stmts(rng, depth - 1)));
                }
            }
            _ => {
                out.push(0xA5); // Break
            }
        }
    }
    out
}

fn aml_device(rng: &mut Rng, depth: u32) -> Vec<u8> {
    let mut body = b"DEV".to_vec();
    body.push(b'0' + rng.below(10) as u8);
    // Name (_HID, "PNP0C50") or an EISA id
    body.push(0x08);
    body.extend_from_slice(b"_HID");
    if rng.below(2) == 0 {
        body.push(0x0D);
        body.extend_from_slice(b"PNP0C50\0");
    } else {
        body.push(0x0C);
        body.extend_from_slice(&(rng.next() as u32).to_le_bytes());
    }
    for name in [b"_STA", b"_CRS", b"_UID"] {
        if rng.below(3) != 0 {
            let mut m = name.to_vec();
            m.push(0x00); // no arguments
            m.extend(aml_stmts(rng, 3));
            body.push(0x14);
            body.extend(pkg(&m));
        }
    }
    if depth > 0 && rng.below(3) == 0 {
        body.extend(aml_device(rng, depth - 1));
    }
    let mut out = vec![0x5B, 0x82];
    out.extend(pkg(&body));
    out
}

fn aml_table(rng: &mut Rng) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..1 + rng.below(4) {
        let mut scope = b"\\_SB_".to_vec();
        for _ in 0..1 + rng.below(3) {
            scope.extend(aml_device(rng, 2));
        }
        body.push(0x10);
        body.extend(pkg(&scope));
    }
    // Then lie: flip a few bytes, the way a corrupt or hostile table would,
    // but leave most cases well-formed so the interpreter is reached.
    if rng.below(2) == 0 {
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(body.len() as u64) as usize;
            body[at] = if rng.below(2) == 0 { rng.byte() } else { 0xFF };
        }
    }
    let mut table = b"DSDT".to_vec();
    table.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
    table.resize(36, 0);
    table.extend_from_slice(&body);
    table
}

/// Walks and evaluates, returning (devices seen, evaluations attempted).
fn exercise_aml(case: usize, table: &[u8]) -> (usize, usize) {
    let mut devices = 0;
    let mut evals = 0;
    timed(case, "AML walk and evaluate", || {
        let Some(ns) = Namespace::new(table) else { return };
        ns.for_each_device(|device| {
            let _ = ns.present(&device);
            for name in [b"_STA", b"_CRS", b"_HID", b"_UID"] {
                let _ = ns.evaluate(&device, name, &[]);
                evals += 1;
            }
            devices += 1;
            devices < 64
        });
        let mut scratch = [0u8; 256];
        let _ = ns.find_i2c_hid(&mut scratch);
    });
    (devices, evals)
}

#[test]
fn aml_generated_tables_terminate() {
    let mut rng = Rng(0x0DDC_0FFE_E0DD_F00D);
    let mut devices = 0;
    for case in 0..20_000 {
        let table = aml_table(&mut rng);
        devices += exercise_aml(case, &table).0;
    }
    // A generator that never reaches a device tests only the header check.
    assert!(devices > 20_000, "generator reached only {devices} devices");
}

#[test]
fn aml_infinite_while_is_cut_off() {
    // Device (DEV0) { Method (_STA) { While (One) { } } }
    let body: &[u8] = &[
        0x5B, 0x82, 0x10, b'D', b'E', b'V', b'0', //   Device, PkgLength 16
        0x14, 0x0A, b'_', b'S', b'T', b'A', 0x00, //   Method _STA, 0 args
        0xA2, 0x02, 0x01, //                           While (One) {}
        0x00, 0x00,
    ];
    let mut table = b"DSDT".to_vec();
    table.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
    table.resize(36, 0);
    table.extend_from_slice(body);
    let (devices, evals) = exercise_aml(0, &table);
    assert_eq!(devices, 1, "the looping method was never reached");
    assert!(evals > 0);
}

/// One short item: tag byte with its size bits, then the value.
fn item(out: &mut Vec<u8>, tag: u8, value: u32, size: u8) {
    let code = match size { 0 => 0, 1 => 1, 2 => 2, _ => 3 };
    out.push(tag | code);
    out.extend_from_slice(&value.to_le_bytes()[..[0, 1, 2, 4][code as usize]]);
}

/// A size field of the kind a hostile descriptor declares: zero, the
/// edges of the report, and far past them.
fn hostile_size(rng: &mut Rng) -> (u32, u8) {
    match rng.below(8) {
        0 => (0, 1),
        1 => (32, 1),
        2 => (33, 1),
        3 => (255, 1),
        4 => (0xFFFF, 2),
        5 => (u32::MAX, 4),
        _ => (1 + rng.below(16) as u32, 1),
    }
}

/// A mouse or keyboard collection shaped like a real one — so the parser
/// accepts it and the decoder runs — with sizes, counts and IDs drawn from
/// [`hostile_size`], then optionally corrupted.
fn hid_descriptor(rng: &mut Rng) -> Vec<u8> {
    let mut d = Vec::new();
    let keyboard = rng.below(2) == 0;
    item(&mut d, 0x04, 0x01, 1); // Usage Page (Generic Desktop)
    item(&mut d, 0x08, if keyboard { 0x06 } else { 0x02 }, 1);
    item(&mut d, 0xA0, 0x01, 1); // Collection (Application)
    if rng.below(2) == 0 {
        item(&mut d, 0x84, rng.below(256) as u32, 1); // Report ID
    }
    for _ in 0..1 + rng.below(4) {
        if rng.below(4) == 0 {
            item(&mut d, 0xA4, 0, 0); // Push
        }
        let page = if keyboard { 0x07 } else { [0x09, 0x01][rng.below(2) as usize] };
        item(&mut d, 0x04, page, 1);
        if page == 0x01 {
            item(&mut d, 0x08, 0x30, 1); // X
            item(&mut d, 0x08, 0x31, 1); // Y
        } else {
            item(&mut d, 0x18, 0, 1);
            item(&mut d, 0x28, rng.below(256) as u32, 1);
        }
        item(&mut d, 0x14, 0x81, 1);
        item(&mut d, 0x24, 0x7F, 1);
        let (size, sw) = hostile_size(rng);
        item(&mut d, 0x74, size, sw);
        let (count, cw) = hostile_size(rng);
        item(&mut d, 0x94, count, cw);
        item(&mut d, 0x80, [0x02, 0x06, 0x00][rng.below(3) as usize], 1); // Input
        if rng.below(4) == 0 {
            item(&mut d, 0xB4, 0, 0); // Pop, balanced or not
        }
    }
    if rng.below(4) != 0 {
        item(&mut d, 0xC0, 0, 0); // End Collection, sometimes missing
    }
    if rng.below(3) == 0 {
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(d.len() as u64) as usize;
            d[at] = rng.byte();
        }
    }
    d
}

/// Parses and decodes; returns how many layouts were found.
fn exercise_hid(case: usize, rng: &mut Rng, descriptor: &[u8]) -> usize {
    let mut found = 0;
    timed(case, "HID parse and decode", || {
        if let Some(layout) = find_pointer(descriptor) {
            found += 1;
            for _ in 0..8 {
                let report: Vec<u8> = (0..rng.below(80)).map(|_| rng.byte()).collect();
                let _ = layout.decode(&report);
            }
        }
        if let Some(layout) = find_keyboard(descriptor) {
            found += 1;
            for _ in 0..8 {
                let report: Vec<u8> = (0..rng.below(80)).map(|_| rng.byte()).collect();
                let _ = layout.decode(&report);
            }
        }
    });
    found
}

#[test]
fn hid_generated_descriptors_terminate() {
    let mut rng = Rng(0xBADC_0DE5_EED5_1234);
    let mut found = 0;
    for case in 0..20_000 {
        let d = hid_descriptor(&mut rng);
        found += exercise_hid(case, &mut rng, &d);
    }
    assert!(found > 2_000, "generator produced only {found} parseable layouts");
}

#[test]
fn hid_mutated_real_descriptors_terminate() {
    let fixtures: [&[u8]; 2] = [
        include_bytes!("fixtures/elan-i2c-hid.rdesc"),
        include_bytes!("fixtures/ite-notebook-keyboard.rdesc"),
    ];
    let mut rng = Rng(0x0005_EED0_FF1C_70E5);
    let mut found = 0;
    for case in 0..20_000 {
        let mut d = fixtures[case % 2].to_vec();
        for _ in 0..1 + rng.below(6) {
            let at = rng.below(d.len() as u64) as usize;
            match rng.below(3) {
                0 => d[at] = rng.byte(),
                1 => d[at] = 0xFF,
                _ => d.truncate(at),
            }
            if d.is_empty() {
                break;
            }
        }
        found += exercise_hid(case, &mut rng, &d);
    }
    assert!(found > 1_000, "mutations left only {found} parseable layouts");
}
