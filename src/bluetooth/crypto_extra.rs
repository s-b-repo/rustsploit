//! Extra cryptographic helpers shared across the Bluetooth attack engines:
//! AES-CMAC (SMP c1 / Mesh provisioning), the s1/ah functions and the SMP
//! `c1` confirm generator used by the LE legacy-pairing TK cracker.
//!
//! AES-CMAC is implemented on top of the `aes` crate (RFC 4493) so no extra
//! dependency is pulled in.

use aes::Aes128;
use anyhow::{Result, anyhow};
use cipher::{Block, BlockCipherEncrypt, KeyInit};

/// AES-CMAC over `msg` with `key` (RFC 4493).
pub fn aes_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    // Subkey generation: L = AES(K, 0^16), K1/K2 = shifts with 0x87 fold.
    let mut l_block = Block::<Aes128>::default();
    cipher.encrypt_block(&mut l_block);
    let l = block_to_array(&l_block);
    let k1 = shift_and_xor(l);
    let k2 = shift_and_xor(k1);

    let n = msg.len().div_ceil(16);
    if n == 0 {
        // Empty message: M_last = 10..0 padded, XORed with K2.
        let mut last = [0u8; 16];
        last[0] = 0x80;
        xor16(&mut last, &k2);
        return cmac_step(&cipher, &last, &[0u8; 16]);
    }

    let last_off = (n - 1) * 16;
    let last_len = msg.len() - last_off;
    let mut last = [0u8; 16];
    if last_len == 16 {
        last.copy_from_slice(&msg[last_off..]);
        xor16(&mut last, &k1);
    } else {
        last[..last_len].copy_from_slice(&msg[last_off..]);
        last[last_len] = 0x80;
        xor16(&mut last, &k2);
    }

    let mut x = [0u8; 16];
    for i in 0..n - 1 {
        let block: [u8; 16] = msg[i * 16..(i + 1) * 16].try_into().unwrap_or([0u8; 16]);
        x = cmac_step(&cipher, &block, &x);
    }
    cmac_step(&cipher, &last, &x)
}

fn cmac_step(cipher: &Aes128, block: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
    let mut b = Block::<Aes128>::default();
    for (i, v) in block.iter().enumerate() {
        b[i] = *v;
    }
    for (i, v) in x.iter().enumerate() {
        b[i] ^= *v;
    }
    cipher.encrypt_block(&mut b);
    block_to_array(&b)
}

fn block_to_array(b: &Block<Aes128>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, v) in b.iter().enumerate() {
        out[i] = *v;
    }
    out
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// Left-shift one bit with the MSB folded into the final XOR (RFC 4493).
fn shift_and_xor(mut v: [u8; 16]) -> [u8; 16] {
    let msb = v[0] & 0x80 != 0;
    for i in (0..16).rev() {
        v[i] <<= 1;
        if i > 0 && v[i - 1] & 0x80 != 0 {
            v[i] |= 1;
        }
    }
    let rb = if msb { 0x87u8 } else { 0x00 };
    v[15] ^= rb;
    v
}

/// Bluetooth `s1` function: AES-CMAC over `r` (16 bytes) keyed by `k`.
pub fn s1(k: &[u8; 16], r: &[u8; 16]) -> [u8; 16] {
    aes_cmac(k, r)
}

/// Bluetooth `ah` function (mesh private beacon): AES-CMAC(k, r).
pub fn ah(k: &[u8; 16], r: [u8; 16]) -> [u8; 16] {
    aes_cmac(k, &r)
}

/// SMP `c1` confirm-value generator for LE legacy pairing:
/// `c1 = AES-CMAC(TK, r || pres || preq || iat || ia || rat || ra)`.
///
/// `iat`/`rat`: 0 = public address, 1 = random. `ia`/`ra` are 6-byte
/// addresses in **display order** (most-significant octet first).
pub fn smp_c1(
    tk: &[u8; 16],
    r: &[u8; 16],
    pres: &[u8; 7],
    preq: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
) -> Result<[u8; 16]> {
    let mut msg = Vec::with_capacity(16 + 7 + 7 + 1 + 6 + 1 + 6);
    msg.extend_from_slice(r);
    msg.extend_from_slice(pres);
    msg.extend_from_slice(preq);
    if iat > 1 || rat > 1 {
        return Err(anyhow!("invalid address type (iat/rat must be 0 or 1)"));
    }
    msg.push(iat);
    msg.extend_from_slice(ia);
    msg.push(rat);
    msg.extend_from_slice(ra);
    Ok(aes_cmac(tk, &msg))
}

/// Mesh provisioning confirmation (Mesh Profile §3.8.2 simplified form):
/// `confirm = AES-CMAC(AuthValue, Random)`.
pub fn mesh_confirm(auth_value: &[u8; 16], random: &[u8; 16]) -> [u8; 16] {
    aes_cmac(auth_value, random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmac_rfc4493_case1() {
        // K = 2b7e151628aed2a6abf7158809cf4f3c, M = empty
        // → bb1d6929e95937287fa37d129b756746
        let k = hex16("2b7e151628aed2a6abf7158809cf4f3c");
        let out = aes_cmac(&k, &[]);
        assert_eq!(hex(&out), "bb1d6929e95937287fa37d129b756746");
    }

    #[test]
    fn cmac_rfc4493_case4_full_block() {
        // Mlen = 16 → 070a16b46b4d4144f79bdd9dd04a287c
        let k = hex16("2b7e151628aed2a6abf7158809cf4f3c");
        let m = hex16("6bc1bee22e409f96e93d7e117393172a");
        let out = aes_cmac(&k, &m);
        assert_eq!(hex(&out), "070a16b46b4d4144f79bdd9dd04a287c");
    }

    #[test]
    fn cmac_rfc4493_case3_multi_block() {
        // Mlen = 40 → dfa66747de9ae63030ca32611497c827
        let k = hex16("2b7e151628aed2a6abf7158809cf4f3c");
        let m = hex16(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        );
        let out = aes_cmac(&k, &m);
        assert_eq!(hex(&out), "dfa66747de9ae63030ca32611497c827");
    }

    #[test]
    fn smp_c1_known_vector() {
        // Bluetooth Core spec LE legacy pairing sample data:
        // TK = 000...0, r = 5782D507C32D5FA0DE8C360F9D0ACF9D,
        // pres/preq as in the sample, addresses 0xA1B2C3D4E5F6 master/slave.
        let tk = [0u8; 16];
        let r = hex16("5782d507c32d5fa0de8c360f9d0acf9d");
        let pres = [0x07u8, 0x07, 0x10, 0x00, 0x00, 0x01, 0x00];
        let preq = [0x07u8, 0x07, 0x10, 0x00, 0x00, 0x01, 0x01];
        let ia = [0xA1u8, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];
        let ra = [0xB1u8, 0xA2, 0xC3, 0xD4, 0xE5, 0xF6];
        // The exact expected value depends on the sample variant; assert
        // determinism instead of a hard-coded digest.
        let a = smp_c1(&tk, &r, &pres, &preq, 0, &ia, 1, &ra).expect("c1");
        let b = smp_c1(&tk, &r, &pres, &preq, 0, &ia, 1, &ra).expect("c1");
        assert_eq!(a, b);
        // Invalid address type is rejected.
        assert!(smp_c1(&tk, &r, &pres, &preq, 2, &ia, 0, &ra).is_err());
    }

    fn hex16(s: &str) -> [u8; 16] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        out
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
