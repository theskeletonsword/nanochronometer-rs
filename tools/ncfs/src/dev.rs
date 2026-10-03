// SPDX-License-Identifier: Apache-2.0
//! Volumes on the host: an image file or a block device, a clock, and the
//! reference library's ZSTD compressor.

use nanochrono_core::ncfs::format::{Compression, BLOCK};
use nanochrono_core::ncfs::write::{BlockDevMut, Clock, Encoder};
use nanochrono_core::ncfs::{BlockDev, Error};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::Path;

/// A volume in a file or on a device, read and written at block offsets.
#[derive(Debug)]
pub struct FileDev {
    file: File,
    blocks: u64,
}

impl FileDev {
    /// Opens an existing image or device; its size decides the volume's.
    pub fn open(path: &Path, writable: bool) -> std::io::Result<FileDev> {
        let mut file = OpenOptions::new().read(true).write(writable).open(path)?;
        // A block device reports its size through seeking, not metadata.
        let size = file.seek(SeekFrom::End(0))?;
        Ok(FileDev { file, blocks: size / BLOCK as u64 })
    }

    /// Creates (or truncates) an image file of `size` bytes, sparse.
    pub fn create(path: &Path, size: u64) -> std::io::Result<FileDev> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
        file.set_len(size)?;
        Ok(FileDev { file, blocks: size / BLOCK as u64 })
    }

    /// Cuts an image file to `blocks` blocks.
    pub fn truncate(&mut self, blocks: u64) -> std::io::Result<()> {
        self.file.set_len(blocks * BLOCK as u64)?;
        self.blocks = blocks;
        Ok(())
    }
}

impl BlockDev for FileDev {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, block: u64, buf: &mut [u8]) -> Result<(), Error> {
        let at = block.checked_mul(BLOCK as u64).ok_or(Error::Io)?;
        self.file.read_exact_at(buf, at).map_err(|_| Error::Io)
    }
}

impl BlockDevMut for FileDev {
    fn write(&mut self, block: u64, data: &[u8]) -> Result<(), Error> {
        let at = block.checked_mul(BLOCK as u64).ok_or(Error::Io)?;
        self.file.write_all_at(data, at).map_err(|_| Error::Io)
    }

    fn flush(&mut self) -> Result<(), Error> {
        // The barrier NCFS's crash safety rests on.
        self.file.sync_data().map_err(|_| Error::Io)
    }
}

/// The host's clock, in nanoseconds since the epoch.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&mut self) -> i64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i64,
            Err(e) => -(e.duration().as_nanos() as i64),
        }
    }
}

/// ZSTD through the reference library: what images built here use. The
/// kernel only ever decodes, with nanochrono-core's own decoder.
#[derive(Debug, Clone, Copy)]
pub struct Zstd {
    pub level: i32,
}

impl Encoder for Zstd {
    fn encode(&mut self, compression: Compression, input: &[u8]) -> Option<Vec<u8>> {
        match compression {
            Compression::Zstd => zstd::bulk::compress(input, self.level).ok(),
            _ => None,
        }
    }
}

/// Nanoseconds since the epoch as NanoChronometer prints time:
/// `2026-10-03 14:05:09:123:456:789` (UTC).
pub fn timestamp(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let frac = ns.rem_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Civil from days (H. Hinnant's algorithm), proleptic Gregorian.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}:{:03}:{:03}:{:03}",
        tod / 3600,
        tod / 60 % 60,
        tod % 60,
        frac / 1_000_000,
        frac / 1000 % 1000,
        frac % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_read_like_the_taskbar_clock() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00:000:000:000");
        assert_eq!(timestamp(1_700_000_000_123_456_789), "2023-11-14 22:13:20:123:456:789");
        assert_eq!(timestamp(-1), "1969-12-31 23:59:59:999:999:999");
        assert_eq!(timestamp(951_782_400_000_000_000), "2000-02-29 00:00:00:000:000:000");
    }
}
