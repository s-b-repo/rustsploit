// Native DoS utilities — shared spoofing, RNG, and checksum infrastructure.
//
// Provides a unified FastRng (XorShift128+), random public IPv4 generation,
// Internet checksum (RFC 1071), and a global `spoof_ip` option check.
// Used by all raw-packet DoS modules to eliminate code duplication.

use std::net::Ipv4Addr;
use std::time::SystemTime;

// ============================================================================
// FAST RNG (XorShift128+)
// ============================================================================

/// High-performance non-cryptographic PRNG for packet field randomization.
/// Each worker thread should create its own instance via `with_thread_seed()`.
pub struct FastRng {
    s0: u64,
    s1: u64,
}

impl FastRng {
    /// Create a new RNG seeded from system time + thread ID.
    /// The 16-round warmup eliminates seed correlation across threads.
    pub fn with_thread_seed(thread_id: usize) -> Self {
        let time_seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let s0 = time_seed ^ (thread_id as u64).wrapping_mul(0x9E3779B97F4A7C15);
        let s1 = time_seed.rotate_left(17) ^ (thread_id as u64).wrapping_mul(0xBF58476D1CE4E5B9);
        let mut rng = Self { s0, s1 };
        for _ in 0..16 { rng.next_u64(); }
        rng
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s0;
        let y = self.s1;
        self.s0 = y;
        x ^= x << 23;
        self.s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        self.s1.wrapping_add(y)
    }

    #[inline(always)]
    pub fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }

    #[inline(always)]
    pub fn next_u16(&mut self) -> u16 { self.next_u64() as u16 }

    /// Generate a random public IPv4 address, avoiding private/reserved/multicast ranges.
    #[inline(always)]
    pub fn gen_ipv4_public(&mut self) -> Ipv4Addr {
        loop {
            let octets = self.next_u32().to_be_bytes();
            match octets[0] {
                0 | 10 | 127 => continue,
                224..=255 => continue,
                172 if (16..=31).contains(&octets[1]) => continue,
                192 if octets[1] == 168 => continue,
                169 if octets[1] == 254 => continue,
                100 if (64..=127).contains(&octets[1]) => continue,
                _ => return Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
            }
        }
    }

    /// Generate a random ephemeral port (49152–65535).
    #[inline(always)]
    pub fn gen_ephemeral_port(&mut self) -> u16 {
        (self.next_u16() % 16384) + 49152
    }
}

// ============================================================================
// INTERNET CHECKSUM (RFC 1071)
// ============================================================================

/// Compute the Internet checksum (one's-complement sum) over a byte slice.
/// Used for IP, TCP, UDP, and ICMP header checksums.
#[inline(always)]
pub fn checksum_16(data: &[u8]) -> u16 {
    let mut sum = sum_16(data, 0);
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Accumulate a 16-bit one's-complement sum with an initial value.
/// Processes 4 bytes at a time for throughput.
#[inline(always)]
pub fn sum_16(data: &[u8], init: u32) -> u32 {
    let mut sum = init;
    let mut i = 0;
    let len = data.len();
    while i + 3 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum += u16::from_be_bytes([data[i + 2], data[i + 3]]) as u32;
        i += 4;
    }
    if i + 1 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < len {
        sum += u16::from_be_bytes([data[i], 0]) as u32;
    }
    sum
}

// ============================================================================
// GLOBAL SPOOF OPTION
// ============================================================================

/// Check if the global `spoof_ip` option is enabled (`setg spoof_ip true`).
/// Returns false if not set or set to anything other than true/1/yes.
pub fn is_spoof_enabled() -> bool {
    crate::global_options::GLOBAL_OPTIONS.try_get("spoof_ip")
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}
