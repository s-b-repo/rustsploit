//! Shared IPv4 packet-header construction for the raw-socket DoS modules.
//!
//! The 20-byte IPv4 header layout and its per-packet checksum are identical
//! across every raw flood / amplification module — only *which* fields are
//! static vs per-packet differs (spoofers vary the source address; reflectors
//! vary the destination). This module owns those byte offsets + the header
//! checksum so the layout lives in one place. Built on
//! [`crate::native::dos_utils::checksum_16`].

use std::net::{Ipv4Addr, Ipv6Addr};

use super::dos_utils::{checksum_16, sum_16};

/// IPv4 header length with no options.
pub const IPV4_HEADER_LEN: usize = 20;

/// Write the static IPv4 header fields into `buf[..20]`: version/IHL (`0x45`),
/// DSCP/ECN = 0, total length, flags/frag = 0, TTL, protocol. The ID, source,
/// destination, and checksum are written separately because they vary per
/// packet in the spoofing/reflection senders.
///
/// `buf` must be at least [`IPV4_HEADER_LEN`] bytes — callers size it from
/// `total_len`; a shorter slice is a programming error.
#[inline]
pub fn write_ipv4_static(buf: &mut [u8], total_len: usize, ttl: u8, protocol: u8) {
    buf[0] = 0x45; // Version = 4, IHL = 5 (no options)
    buf[1] = 0; // DSCP / ECN
    buf[2] = (total_len >> 8) as u8; // Total length hi
    buf[3] = total_len as u8; // Total length lo
    buf[6] = 0; // Flags / fragment offset
    buf[7] = 0;
    buf[8] = ttl;
    buf[9] = protocol;
}

/// Write the IPv4 source address (offset 12).
#[inline]
pub fn set_src(buf: &mut [u8], ip: Ipv4Addr) {
    buf[12..16].copy_from_slice(&ip.octets());
}

/// Write the IPv4 destination address (offset 16).
#[inline]
pub fn set_dst(buf: &mut [u8], ip: Ipv4Addr) {
    buf[16..20].copy_from_slice(&ip.octets());
}

/// Write the IPv4 identification field (offset 4).
#[inline]
pub fn set_id(buf: &mut [u8], id: u16) {
    buf[4] = (id >> 8) as u8;
    buf[5] = id as u8;
}

/// Zero then compute and write the IPv4 header checksum (offset 10) over
/// `buf[..20]`. Call after every other header field is set.
#[inline]
pub fn finalize_checksum(buf: &mut [u8]) {
    buf[10] = 0;
    buf[11] = 0;
    let cksum = checksum_16(&buf[..IPV4_HEADER_LEN]);
    buf[10] = (cksum >> 8) as u8;
    buf[11] = cksum as u8;
}

// ============================================================================
// IPv6 (40-byte fixed header; no header checksum)
// ============================================================================

/// IPv6 fixed header length.
pub const IPV6_HEADER_LEN: usize = 40;

/// Write the static IPv6 header fields into `buf[..40]`: version (6), zero
/// traffic-class/flow-label, payload length, next header, hop limit. Source and
/// destination addresses are written separately. IPv6 has no header checksum.
///
/// `buf` must be at least [`IPV6_HEADER_LEN`] bytes.
#[inline]
pub fn write_ipv6_static(buf: &mut [u8], payload_len: u16, hop_limit: u8, next_header: u8) {
    buf[0] = 0x60; // Version = 6, traffic class hi nibble = 0
    buf[1] = 0; // traffic class lo / flow label hi
    buf[2] = 0; // flow label
    buf[3] = 0; // flow label
    buf[4] = (payload_len >> 8) as u8;
    buf[5] = payload_len as u8;
    buf[6] = next_header;
    buf[7] = hop_limit;
}

/// Write the IPv6 source address (offset 8, 16 bytes).
#[inline]
pub fn set_src_v6(buf: &mut [u8], ip: Ipv6Addr) {
    buf[8..24].copy_from_slice(&ip.octets());
}

/// Write the IPv6 destination address (offset 24, 16 bytes).
#[inline]
pub fn set_dst_v6(buf: &mut [u8], ip: Ipv6Addr) {
    buf[24..40].copy_from_slice(&ip.octets());
}

/// Compute the upper-layer (UDP/TCP/ICMPv6) checksum over the IPv6 pseudo-header
/// (src + dst + 32-bit upper-layer length + next-header) plus `l4_segment`.
/// Returns the folded one's-complement; for UDP the caller maps a 0 result to
/// 0xFFFF (a 0 checksum is illegal in IPv6 UDP).
pub fn ipv6_upper_checksum(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    l4_segment: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    let s = src.octets();
    let d = dst.octets();
    let mut i = 0;
    while i < 16 {
        sum += u16::from_be_bytes([s[i], s[i + 1]]) as u32;
        sum += u16::from_be_bytes([d[i], d[i + 1]]) as u32;
        i += 2;
    }
    // Upper-layer length (32-bit) + next header (3 zero bytes + nh).
    let ulen = l4_segment.len() as u32;
    sum += (ulen >> 16) & 0xFFFF;
    sum += ulen & 0xFFFF;
    sum += next_header as u32;
    // Fold in the L4 segment.
    sum = sum_16(l4_segment, sum);
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A correct one's-complement checksum makes the 16-bit-word sum of the
    /// covered region (checksum field included) fold to 0xFFFF.
    fn checksum_ok(region: &[u8]) -> bool {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < region.len() {
            sum += u16::from_be_bytes([region[i], region[i + 1]]) as u32;
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }

    #[test]
    fn ipv4_header_fields_and_checksum() {
        let mut buf = vec![0u8; IPV4_HEADER_LEN + 8];
        let total = buf.len();
        write_ipv4_static(&mut buf, total, 64, 17);
        set_src(&mut buf, Ipv4Addr::new(198, 51, 100, 7));
        set_dst(&mut buf, Ipv4Addr::new(203, 0, 113, 9));
        set_id(&mut buf, 0xABCD);
        finalize_checksum(&mut buf);

        assert_eq!(buf[0], 0x45); // audit-allow: test
        assert_eq!(((buf[2] as usize) << 8) | buf[3] as usize, total); // audit-allow: test
        assert_eq!(buf[8], 64); // audit-allow: test
        assert_eq!(buf[9], 17); // audit-allow: test
        assert_eq!([buf[4], buf[5]], [0xAB, 0xCD]); // audit-allow: test
        assert_eq!(&buf[12..16], &[198, 51, 100, 7]); // audit-allow: test
        assert_eq!(&buf[16..20], &[203, 0, 113, 9]); // audit-allow: test
        assert!(checksum_ok(&buf[..IPV4_HEADER_LEN])); // audit-allow: test
    }

    #[test]
    fn ipv6_header_and_udp_checksum() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let udp_len: u16 = 8 + 4; // UDP header + 4-byte payload
        let mut buf = vec![0u8; IPV6_HEADER_LEN + udp_len as usize];
        write_ipv6_static(&mut buf, udp_len, 64, 17);
        set_src_v6(&mut buf, src);
        set_dst_v6(&mut buf, dst);

        let u = IPV6_HEADER_LEN;
        buf[u] = 0x30;
        buf[u + 1] = 0x39; // src port 12345
        buf[u + 2] = 0;
        buf[u + 3] = 53; // dst port 53
        buf[u + 4] = (udp_len >> 8) as u8;
        buf[u + 5] = udp_len as u8;
        buf[u + 8] = 0xDE;
        buf[u + 9] = 0xAD;
        buf[u + 10] = 0xBE;
        buf[u + 11] = 0xEF;
        buf[u + 6] = 0;
        buf[u + 7] = 0;
        let c = ipv6_upper_checksum(src, dst, 17, &buf[u..]);
        let c = if c == 0 { 0xFFFF } else { c };
        buf[u + 6] = (c >> 8) as u8;
        buf[u + 7] = c as u8;

        assert_eq!(buf[0], 0x60); // audit-allow: test
        assert_eq!(buf[6], 17); // audit-allow: test
        assert_eq!(&buf[8..24], &src.octets()[..]); // audit-allow: test
        assert_eq!(&buf[24..40], &dst.octets()[..]); // audit-allow: test
        // Re-summing incl. the checksum field folds to 0 for a valid packet.
        assert_eq!(ipv6_upper_checksum(src, dst, 17, &buf[u..]), 0); // audit-allow: test
    }
}
