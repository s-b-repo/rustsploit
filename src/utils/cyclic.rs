//! ZMap-style stateless cyclic-group IPv4 address iterator.
//!
//! Ported to Rust from ZMap's address-generation algorithm (`lib/cyclic.c` /
//! `lib/random.c`; Durumeric, Wustrow & Halderman, *"ZMap: Fast Internet-Wide
//! Scanning and its Security Applications"*, USENIX Security 2013 — Apache-2.0).
//!
//! ## Why
//!
//! The naïve random scanner samples addresses uniformly and remembers every one
//! it has already emitted in a `HashSet` to avoid repeats. That has two fatal
//! problems at internet scale:
//!   * **memory** — the "seen" set grows with every host, so covering a large
//!     fraction of the 2³² space needs gigabytes of state, and
//!   * **coupon-collector waste** — as the seen set fills up, an ever-larger
//!     share of fresh samples are duplicates that get thrown away.
//!
//! ## How ZMap solves it
//!
//! Treat the address space as the multiplicative group of integers modulo a
//! prime `P` just larger than 2³². If `g` is a *primitive root* of that group
//! (its powers generate every nonzero residue), then starting from any element
//! and repeatedly multiplying by `g (mod P)` walks **every** value in
//! `1..=P-1` exactly once before returning to the start — a full pseudo-random
//! permutation of the address space.
//!
//! The entire iterator state is three integers (`generator`, `start`,
//! `current`): O(1) memory, no dedup table, and **no repeats** until the whole
//! space is covered. A fresh random `start` each run gives a different ordering.
//!
//! `P = 4_294_967_311` is the smallest prime greater than 2³². Group elements
//! `1..=2³²` map to addresses `0..=2³²-1` (element `v` → address `v-1`); the 14
//! elements in `(2³², P-1]` are not real addresses and are skipped. Reserved /
//! excluded addresses are filtered by the caller, not here — this type's job is
//! purely to enumerate the space once, in permuted order.

use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};

/// Smallest prime greater than 2³²; the order-defining modulus of the group.
const P: u64 = 4_294_967_311;
/// Size of the IPv4 address space (2³²).
const IPV4_SPACE: u64 = 1 << 32;
/// Distinct prime factors of `P - 1` (= 2 · 3² · 5 · 131 · 364289). Used to
/// test whether a candidate is a primitive root of `Z_P*`. Validated against
/// `P - 1` in the unit tests so a typo can't silently weaken the test.
const PRIME_FACTORS: [u64; 5] = [2, 3, 5, 131, 364_289];

/// `(a * b) mod m` via a 128-bit intermediate so the 32-bit-scale operands
/// never overflow.
#[inline]
fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// `base^exp mod m` by square-and-multiply.
fn powmod(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut acc = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mulmod(acc, base, m);
        }
        base = mulmod(base, base, m);
        exp >>= 1;
    }
    acc
}

/// `g` is a primitive root of `Z_P*` iff `g^((P-1)/q) != 1 (mod P)` for every
/// distinct prime factor `q` of `P-1`.
fn is_primitive_root(g: u64) -> bool {
    g % P != 0 && PRIME_FACTORS.iter().all(|&q| powmod(g, (P - 1) / q, P) != 1)
}

/// First primitive root of `Z_P*`. The smallest one for this prime is tiny
/// (well under 100), so the bounded search always succeeds on the first few
/// candidates; the `Err` arm exists only so a (theoretically impossible) bad
/// factorisation surfaces instead of being swallowed.
fn find_primitive_root() -> Result<u64> {
    (2..10_000)
        .find(|&g| is_primitive_root(g))
        .ok_or_else(|| anyhow!("no primitive root found for P={P}; PRIME_FACTORS is wrong"))
}

/// Stateless permutation of the entire IPv4 address space (see module docs).
pub struct CyclicIp {
    generator: u64,
    start: u64,
    current: u64,
    started: bool,
    done: bool,
}

impl CyclicIp {
    /// Build an iterator whose permutation starts at `seed` (any `u64`, mapped
    /// into the group's `1..=P-1` range). Deterministic for a given seed, which
    /// makes the permutation reproducible (and unit-testable).
    pub fn with_seed(seed: u64) -> Result<Self> {
        let generator = find_primitive_root()?;
        // Group elements are 1..=P-1; fold the seed into that range.
        let start = seed % (P - 1) + 1;
        Ok(Self {
            generator,
            start,
            current: start,
            started: false,
            done: false,
        })
    }

    /// Build an iterator from a fresh random start, so each run walks the space
    /// in a different pseudo-random order.
    pub fn random() -> Result<Self> {
        let seed: u64 = rand::random();
        Self::with_seed(seed)
    }
}

impl Iterator for CyclicIp {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        loop {
            if self.done {
                return None;
            }
            if self.started {
                self.current = mulmod(self.current, self.generator, P);
                // A primitive root has order P-1, so the orbit returns to
                // `start` only after every one of the P-1 elements has been
                // visited. That return is the natural end-of-space marker.
                if self.current == self.start {
                    self.done = true;
                    return None;
                }
            } else {
                self.started = true;
            }
            let val = self.current; // 1..=P-1
            if (1..=IPV4_SPACE).contains(&val) {
                return Some(Ipv4Addr::from((val - 1) as u32));
            }
            // val in (2^32, P-1]: not a real address — skip, keep cycling.
        }
    }
}

/// Coarse reserved-range filter, matching the old `generate_random_public_ip`
/// rejection rules so the cyclic scanner covers the same target set: skip
/// `0/8`, `10/8`, `127/8`, multicast/reserved (`>=224`), and the per-subnet
/// network (`.0`) and broadcast (`.255`) host addresses. Finer ranges
/// (RFC1918 172.16/12, link-local, Cloudflare, ...) are handled by the
/// operator's exclusion set, not here.
pub fn is_reserved_ipv4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 0 || o[0] == 10 || o[0] == 127 || o[0] >= 224 || o[3] == 0 || o[3] == 255
}

/// Total count of public IPv4 addresses reachable by the cyclic scanner under
/// the [`is_reserved_ipv4`] filter — i.e. the size of the address set the
/// scanner will actually iterate over when targeting `random` / `0.0.0.0/0`.
///
/// Computed from the same rules as [`is_reserved_ipv4`]:
///   * 35 of 256 `/8` blocks are reserved (`0`, `10`, `127`, plus `224..=255`).
///   * Inside each remaining `/8`, the last-octet `.0` and `.255` addresses
///     are skipped — so each of the 65,536 `/24`s contributes 254 hosts.
///
/// Result: `(256 - 35) * 65_536 * 254 = 3_678_797_824` host addresses.
pub const fn total_public_ipv4_count() -> u64 {
    let reserved_slash8 = 1u64           // 0/8
        + 1                              // 10/8
        + 1                              // 127/8
        + (255 - 224 + 1);               // 224/4 + class E (224..=255 inclusive)
    let usable_slash8 = 256u64 - reserved_slash8;
    // 65_536 /24s per /8, 254 hosts per /24 (.0 and .255 skipped).
    usable_slash8 * 65_536 * 254
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The whole construction hinges on `PRIME_FACTORS` being the *complete*
    /// set of distinct prime factors of `P-1`. Verify both that each listed
    /// factor is prime and that, with the right multiplicities, they multiply
    /// back to `P-1` — together that proves the set is complete and correct,
    /// which in turn makes `is_primitive_root` sound.
    #[test]
    fn prime_factorisation_of_p_minus_one_is_correct() {
        fn is_prime(n: u64) -> bool {
            if n < 2 {
                return false;
            }
            let mut d = 2u64;
            while d * d <= n {
                if n % d == 0 {
                    return false;
                }
                d += 1;
            }
            true
        }
        for &q in &PRIME_FACTORS {
            assert!(is_prime(q), "{q} listed in PRIME_FACTORS is not prime");
        }
        // P-1 = 2^1 · 3^2 · 5^1 · 131^1 · 364289^1
        assert_eq!(2u64 * 3 * 3 * 5 * 131 * 364_289, P - 1);
    }

    #[test]
    fn generator_is_a_primitive_root() {
        let g = find_primitive_root().expect("primitive root must exist");
        assert!(is_primitive_root(g));
        // Sanity: g^(P-1) == 1 but no proper divisor exponent yields 1.
        assert_eq!(powmod(g, P - 1, P), 1);
    }

    #[test]
    fn early_prefix_has_no_repeats_and_is_in_range() {
        // A full 2^32 coverage test is infeasible, but the primitive-root
        // property guarantees full coverage; here we just confirm the first
        // chunk of the walk is repeat-free and only yields real addresses.
        let mut it = CyclicIp::with_seed(0x1234_5678_9abc_def0).expect("ctor");
        let mut seen = HashSet::new();
        for _ in 0..200_000 {
            let a = it.next().expect("space not exhausted this early");
            assert!(seen.insert(a), "duplicate address {a} in permutation prefix");
        }
    }

    #[test]
    fn small_seed_maps_into_group() {
        // seed 0 must still produce a valid in-range start (not 0).
        let it = CyclicIp::with_seed(0).expect("ctor");
        assert!((1..=(P - 1)).contains(&it.start));
    }

    /// The closed-form `total_public_ipv4_count()` MUST equal the count of
    /// addresses that survive `is_reserved_ipv4()` over the full 32-bit
    /// space — otherwise the constant we expose to operators would silently
    /// disagree with what the scanner actually iterates.
    #[test]
    fn total_public_ipv4_count_matches_filter() {
        let mut counted: u64 = 0;
        // Counting all 2^32 addresses in a Rust test takes ~10s on a laptop,
        // which is fine for `cargo test` and keeps the invariant honest.
        for raw in 0u64..=u32::MAX as u64 {
            let addr = Ipv4Addr::from(raw as u32);
            if !is_reserved_ipv4(addr) {
                counted += 1;
            }
        }
        assert_eq!(counted, total_public_ipv4_count());
    }
}
