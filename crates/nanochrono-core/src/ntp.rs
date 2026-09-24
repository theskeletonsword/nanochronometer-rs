// SPDX-License-Identifier: Apache-2.0
//! SNTP client with measured overhead.
//!
//! NTP is deliberately kept off the critical path: the local clock never waits
//! on the network. A query is an explicit, separately accounted synchronisation
//! step, and the counter is read around each phase so the reported offset comes
//! with the cost of obtaining it.
//!
//! This speaks SNTP over UDP (RFC 4330), which is what the protocol is — there
//! is no TLS layer to migrate here. Authenticated time would be NTS
//! (RFC 8915), whose key exchange runs over TLS 1.3; if that is added, it
//! should use the `rustls` client already configured in `nanochrono-crypto`.

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::clock::ClockRoute;
use crate::context::Chronometer;
use crate::platform;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch.
const NTP_UNIX_DELTA: u64 = 2_208_988_800;

/// An SNTP packet is exactly 48 bytes without extensions.
const PACKET_LEN: usize = 48;

/// Default server when none is given.
pub const DEFAULT_SERVER: &str = "pool.ntp.org";

/// Default timeout. Short: a slow server is not worth stalling a clock UI for.
pub const DEFAULT_TIMEOUT_MS: u32 = 750;

/// One completed NTP exchange.
#[derive(Debug, Clone, Default)]
pub struct NtpSample {
    pub server: String,
    pub route: ClockRoute,

    pub stratum: u8,
    /// Log2 of the server's clock precision in seconds; negative.
    pub precision_exp: i8,
    pub leap_indicator: u8,
    pub version: u8,
    pub mode: u8,

    pub cpu_before: u32,
    pub cpu_after: u32,
    /// The thread changed cores mid-query; the counter deltas span two cores.
    pub migrated: bool,

    /// T1: local time the request left.
    pub local_send_unix_ns: u64,
    /// T4: local time the reply arrived.
    pub local_recv_unix_ns: u64,
    /// T3: the server's transmit timestamp.
    pub ntp_transmit_unix_ns: u64,

    /// How far the local clock is from the server's, in nanoseconds.
    pub offset_ns: i64,
    /// Round-trip delay.
    pub delay_ns: u64,

    /// Counter units spent resolving the name and opening the socket.
    pub socket_setup_units: u64,
    /// Counter units spent in `send`/`recv`.
    pub send_recv_units: u64,
    pub kernel_timecall_overhead_units: u64,
    pub api_call_overhead_units: u64,
}

impl NtpSample {
    /// Offset in milliseconds, for display.
    pub fn offset_ms(&self) -> f64 {
        self.offset_ns as f64 / 1e6
    }

    /// Round-trip delay in milliseconds.
    pub fn delay_ms(&self) -> f64 {
        self.delay_ns as f64 / 1e6
    }

    /// Uncertainty on the offset: half the round trip.
    ///
    /// The offset calculation assumes the network is symmetric. It usually is
    /// not, and half the delay is the honest bound on how wrong that
    /// assumption can make the answer.
    pub fn offset_uncertainty_ns(&self) -> u64 {
        self.delay_ns / 2
    }
}

/// Why a query failed.
#[derive(Debug)]
pub enum NtpError {
    /// The hostname did not resolve, or resolved to nothing usable.
    Resolve(io::Error),
    /// Socket setup, send or receive failed — including timeouts.
    Io(io::Error),
    /// The reply was too short, or its mode/transmit timestamp were invalid.
    BadResponse(&'static str),
}

impl std::fmt::Display for NtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtpError::Resolve(e) => write!(f, "could not resolve server: {e}"),
            NtpError::Io(e) => write!(f, "network error: {e}"),
            NtpError::BadResponse(why) => write!(f, "invalid NTP response: {why}"),
        }
    }
}

impl std::error::Error for NtpError {}

/// Queries an NTP server and measures the cost of doing so.
///
/// `server` may omit the port, in which case 123 is used.
pub fn query(
    chrono: &Chronometer,
    server: &str,
    timeout_ms: u32,
    route: ClockRoute,
) -> Result<NtpSample, NtpError> {
    let server = if server.is_empty() {
        DEFAULT_SERVER
    } else {
        server
    };
    let timeout_ms = if timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    };
    let route = route.resolve();

    let mut sample = NtpSample {
        server: server.to_string(),
        route,
        cpu_before: platform::current_cpu(),
        kernel_timecall_overhead_units: crate::clock::measure_kernel_timecall_overhead(chrono, 128),
        api_call_overhead_units: crate::clock::measure_api_call_overhead(chrono, 128),
        ..Default::default()
    };

    let target = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:123")
    };

    let setup0 = route.read_raw(chrono);
    let addresses: Vec<_> = target
        .to_socket_addrs()
        .map_err(NtpError::Resolve)?
        .collect();
    let socket = open_socket(&addresses, timeout_ms).map_err(NtpError::Io)?;
    let setup1 = route.read_raw(chrono);
    sample.socket_setup_units = setup1.saturating_sub(setup0);

    if addresses.is_empty() {
        return Err(NtpError::Resolve(io::Error::new(
            io::ErrorKind::NotFound,
            "hostname resolved to no addresses",
        )));
    }

    // LI = 0 (no warning), VN = 4, Mode = 3 (client).
    let mut last_error = None;
    for addr in &addresses {
        // A fresh request per address: the buffer is reused for the reply,
        // and resending a previous server's reply as a request is not a
        // request. The transmit timestamp carries a random nonce, which a
        // server copies into the reply's originate field (RFC 5905 §8) — the
        // check that a reply answers *this* request and was not injected by
        // someone who merely guessed the source port.
        let nonce = request_nonce();
        let mut packet = [0u8; PACKET_LEN];
        packet[0] = 0x23; // LI 0, version 4, mode 3 (client)
        packet[40..48].copy_from_slice(&nonce.to_be_bytes());

        sample.local_send_unix_ns = platform::unix_time_ns();
        let sr0 = route.read_raw(chrono);

        let exchange = socket
            .send_to(&packet, addr)
            .and_then(|_| socket.recv_from(&mut packet));
        // Only the address the request went to may answer it.
        let exchange = match exchange {
            Ok((_, from)) if from != *addr => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reply came from an address the request was not sent to",
            )),
            other => other,
        };

        let sr1 = route.read_raw(chrono);
        sample.local_recv_unix_ns = platform::unix_time_ns();
        sample.send_recv_units = sr1.saturating_sub(sr0);

        match exchange {
            Ok((len, _)) if len >= PACKET_LEN && packet[24..32] != nonce.to_be_bytes() => {
                last_error = Some(NtpError::BadResponse(
                    "reply does not answer this request (originate timestamp mismatch)",
                ));
            }
            Ok((len, _)) if len >= PACKET_LEN => {
                finish(&mut sample, &packet)?;
                sample.cpu_after = platform::current_cpu();
                sample.migrated = sample.cpu_before != platform::CPU_UNKNOWN
                    && sample.cpu_after != platform::CPU_UNKNOWN
                    && sample.cpu_before != sample.cpu_after;
                return Ok(sample);
            }
            Ok(_) => last_error = Some(NtpError::BadResponse("reply shorter than 48 bytes")),
            Err(e) => last_error = Some(NtpError::Io(e)),
        }
    }

    Err(last_error.unwrap_or(NtpError::BadResponse("no address answered")))
}

fn open_socket(addresses: &[std::net::SocketAddr], timeout_ms: u32) -> io::Result<UdpSocket> {
    // Bind a wildcard address in the same family as the target, so an
    // IPv6-only resolution still works.
    let bind_addr = if addresses.first().is_some_and(|a| a.is_ipv6()) {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    let timeout = Duration::from_millis(timeout_ms as u64);
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    Ok(socket)
}

fn finish(sample: &mut NtpSample, packet: &[u8; PACKET_LEN]) -> Result<(), NtpError> {
    sample.leap_indicator = (packet[0] >> 6) & 0x3;
    sample.version = (packet[0] >> 3) & 0x7;
    sample.mode = packet[0] & 0x7;
    sample.stratum = packet[1];
    sample.precision_exp = packet[3] as i8;

    // Mode 4 is "server"; a broadcast or control reply is not an answer to us.
    if sample.mode != 4 && sample.mode != 5 {
        return Err(NtpError::BadResponse("reply was not from a server"));
    }
    // Stratum 0 carries a kiss-of-death code instead of a time.
    if sample.stratum == 0 {
        return Err(NtpError::BadResponse("server returned a kiss-of-death"));
    }
    // Stratum 16 means unsynchronised, as does leap indicator 3 ("alarm");
    // either way the server's clock is not a reference.
    if sample.stratum >= 16 || sample.leap_indicator == 3 {
        return Err(NtpError::BadResponse("server is not synchronised"));
    }

    sample.ntp_transmit_unix_ns = ntp_timestamp_to_unix_ns(&packet[40..48]);
    if sample.ntp_transmit_unix_ns == 0 {
        return Err(NtpError::BadResponse("transmit timestamp was zero"));
    }

    let t1 = sample.local_send_unix_ns;
    let t3 = sample.ntp_transmit_unix_ns;
    let t4 = sample.local_recv_unix_ns;
    if t4 < t1 {
        return Err(NtpError::BadResponse(
            "local clock stepped during the query",
        ));
    }

    sample.delay_ns = t4 - t1;
    // The server's timestamp is compared against the midpoint of our send and
    // receive, which is the best estimate of "when the server read its clock,
    // in our timebase" under a symmetric-network assumption.
    let midpoint = t1 as i128 + (sample.delay_ns / 2) as i128;
    sample.offset_ns = (t3 as i128 - midpoint) as i64;
    Ok(())
}

/// Converts a 64-bit NTP timestamp (32.32 fixed point since 1900) to Unix
/// nanoseconds. Returns 0 for a zero or pre-epoch timestamp.
fn ntp_timestamp_to_unix_ns(bytes: &[u8]) -> u64 {
    if bytes.len() < 8 {
        return 0;
    }
    let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
    let fraction = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64;
    // All zeros is how NTP spells "not set".
    if seconds == 0 && fraction == 0 {
        return 0;
    }
    // NTP seconds are 32 bits and wrap on 2036-02-07 (era 1). A value below
    // the Unix epoch's is read as era 1 rather than refused: this client has
    // no use for dates before 1970, and refusing them would stop it working
    // in 2036.
    let unix_seconds = if seconds >= NTP_UNIX_DELTA {
        seconds - NTP_UNIX_DELTA
    } else {
        seconds + (1u64 << 32) - NTP_UNIX_DELTA
    };
    // fraction / 2^32 seconds, scaled to nanoseconds without losing precision.
    let ns_fraction = (fraction * 1_000_000_000) >> 32;
    unix_seconds * 1_000_000_000 + ns_fraction
}

/// 64 unpredictable bits for the request's transmit timestamp.
///
/// `RandomState` is keyed from the operating system's random source once per
/// process and perturbed per instance, which is enough for a nonce whose job
/// is to be unguessable by an off-path sender; it is not used as key material.
fn request_nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(platform::monotonic_ns());
    // Never zero: a zero transmit timestamp is how "not set" is spelled.
    h.finish() | 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_epoch_maps_to_unix_epoch() {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&(NTP_UNIX_DELTA as u32).to_be_bytes());
        assert_eq!(ntp_timestamp_to_unix_ns(&bytes), 0);
    }

    #[test]
    fn half_second_fraction_decodes() {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&((NTP_UNIX_DELTA + 1) as u32).to_be_bytes());
        bytes[4..].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        assert_eq!(ntp_timestamp_to_unix_ns(&bytes), 1_500_000_000);
    }

    #[test]
    fn unset_and_short_input_are_rejected() {
        assert_eq!(ntp_timestamp_to_unix_ns(&[0u8; 8]), 0);
        assert_eq!(ntp_timestamp_to_unix_ns(&[0u8; 4]), 0);
    }

    /// After 2036-02-07 the 32-bit seconds field wraps; era 1 must decode
    /// forward, not as "before 1970".
    #[test]
    fn era_one_decodes_after_2036() {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&1u32.to_be_bytes());
        let expected = ((1u64 << 32) + 1 - NTP_UNIX_DELTA) * 1_000_000_000;
        assert_eq!(ntp_timestamp_to_unix_ns(&bytes), expected);
    }

    #[test]
    fn unsynchronised_server_is_rejected() {
        let mut sample = NtpSample::default();
        let mut packet = [0u8; PACKET_LEN];
        packet[0] = 0xE4; // LI 3 (alarm), mode 4
        packet[1] = 2;
        assert!(finish(&mut sample, &packet).is_err());
        packet[0] = 0x24;
        packet[1] = 16; // stratum 16: unsynchronised
        assert!(finish(&mut sample, &packet).is_err());
    }

    #[test]
    fn nonces_differ_and_are_never_zero() {
        let a = request_nonce();
        let b = request_nonce();
        assert_ne!(a, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn kiss_of_death_is_not_accepted_as_time() {
        let mut sample = NtpSample::default();
        let mut packet = [0u8; PACKET_LEN];
        packet[0] = 0x24; // mode 4, server
        packet[1] = 0; // stratum 0 => KoD
        assert!(finish(&mut sample, &packet).is_err());
    }

    #[test]
    fn client_mode_reply_is_rejected() {
        let mut sample = NtpSample::default();
        let mut packet = [0u8; PACKET_LEN];
        packet[0] = 0x23; // mode 3, client
        packet[1] = 2;
        assert!(finish(&mut sample, &packet).is_err());
    }

    #[test]
    fn offset_is_measured_against_the_round_trip_midpoint() {
        let mut sample = NtpSample {
            local_send_unix_ns: 1_000_000_000,
            local_recv_unix_ns: 1_000_100_000, // 100 us round trip
            ..Default::default()
        };
        let mut packet = [0u8; PACKET_LEN];
        packet[0] = 0x24;
        packet[1] = 2;
        // Server time = midpoint + 500 ns.
        let server_unix_ns = 1_000_050_500u64;
        let secs = server_unix_ns / 1_000_000_000 + NTP_UNIX_DELTA;
        let frac = ((server_unix_ns % 1_000_000_000) << 32) / 1_000_000_000;
        packet[40..44].copy_from_slice(&(secs as u32).to_be_bytes());
        packet[44..48].copy_from_slice(&(frac as u32).to_be_bytes());

        finish(&mut sample, &packet).expect("well-formed reply");
        assert_eq!(sample.delay_ns, 100_000);
        assert!(
            (sample.offset_ns - 500).abs() < 10,
            "offset was {}",
            sample.offset_ns
        );
        assert_eq!(sample.offset_uncertainty_ns(), 50_000);
    }
}
