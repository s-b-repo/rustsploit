//! Cryptographic primitives for the Google Fast Pair Key-Based Pairing
//! handshake (CVE-2025-36911 / WhisperPair, KU Leuven COSIC).
//!
//! Per the Fast Pair specification (Paper §3.3.2):
//!   1. The Seeker generates an ephemeral secp256r1 keypair.
//!   2. It performs ECDH against the Provider's **Anti-Spoofing public key**
//!      (published per model ID by Google to Seekers).
//!   3. The 16-byte AES key is `K = SHA-256(z)[0..16]`, where `z` is the
//!      X-coordinate of the shared point.
//!   4. The 16-byte Key-Based Pairing request is AES-128-ECB encrypted with K
//!      and concatenated with the raw 64-byte ephemeral public key.
//!
//! The AES-128-ECB single-block primitive mirrors the idiom already used in
//! `src/modules/exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass.rs`.

use aes::Aes128;
use anyhow::{Result, anyhow};
use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Generate a fresh ephemeral secp256r1 secret key.
///
/// We fill 32 random bytes with the same `rand::rng()` CSPRNG the rest of the
/// crate uses (see `pq_channel.rs`) and reject the astronomically unlikely
/// case where the value is not a valid scalar in `[1, n-1]`. This avoids
/// coupling to any single `rand_core` trait-version (the project carries
/// several in its dependency tree).
pub fn generate_ephemeral() -> SecretKey {
    use rand::RngExt;
    loop {
        let mut buf = [0u8; 32];
        rand::rng().fill(&mut buf);
        match SecretKey::from_slice(&buf) {
            Ok(sk) => return sk,
            Err(e) => {
                tracing::trace!("wpair: reject invalid scalar: {e}");
                continue;
            }
        }
    }
}

/// The seeker's ephemeral public key in raw `X || Y` form (64 bytes, no SEC1
/// `0x04` prefix) — exactly what the 80-byte Key-Based Pairing payload carries.
pub fn public_key_raw64(secret: &SecretKey) -> Result<[u8; 64]> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let encoded = secret.public_key().to_encoded_point(false); // 0x04 || X || Y
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(
        bytes
            .get(1..65)
            .ok_or_else(|| anyhow!("secp256r1 encoded point too short: {} bytes", bytes.len()))?,
    );
    Ok(out)
}

/// Parse a Provider Anti-Spoofing public key. Accepts raw 64-byte `X || Y`
/// (the form Google distributes), 65-byte uncompressed SEC1, or 33-byte
/// compressed SEC1.
pub fn parse_provider_pubkey(bytes: &[u8]) -> Result<PublicKey> {
    let parsed = match bytes.len() {
        64 => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(bytes);
            PublicKey::from_sec1_bytes(&sec1)
        }
        _ => PublicKey::from_sec1_bytes(bytes),
    };
    parsed.map_err(|e| {
        anyhow!(
            "invalid secp256r1 anti-spoofing public key ({} bytes): {e}",
            bytes.len()
        )
    })
}

/// Parse a base64-encoded Provider Anti-Spoofing public key (the format used
/// in the Google Nearby console and in our seed DB).
pub fn parse_provider_pubkey_b64(b64: &str) -> Result<PublicKey> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("anti-spoofing key is not valid base64: {e}"))?;
    parse_provider_pubkey(&raw)
}

/// Derive the 16-byte Key-Based Pairing AES key `K = SHA-256(ECDH_x)[0..16]`.
pub fn derive_k(seeker_secret: &SecretKey, provider_pub: &PublicKey) -> [u8; 16] {
    let shared =
        p256::ecdh::diffie_hellman(seeker_secret.to_nonzero_scalar(), provider_pub.as_affine());
    let z = shared.raw_secret_bytes(); // 32-byte X coordinate
    let digest = Sha256::digest(z.as_slice());
    let mut k = [0u8; 16];
    k.copy_from_slice(&digest[..16]);
    k
}

/// AES-128-ECB encrypt one 16-byte block.
pub fn aes128_ecb_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key).map_err(|e| anyhow!("AES-128 key error: {e}"))?;
    let mut b = Block::<Aes128>::from(*block);
    cipher.encrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    Ok(out)
}

/// AES-128-ECB decrypt one 16-byte block (used by the conformance / response
/// parsing paths).
pub fn aes128_ecb_decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key).map_err(|e| anyhow!("AES-128 key error: {e}"))?;
    let mut b = Block::<Aes128>::from(*block);
    cipher.decrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    Ok(out)
}

/// AES-128 CTR exactly as Fast Pair "Additional Data" uses it (AOSP
/// `AesCtrMultipleBlockEncryption`): the keystream block for data block index
/// `i` is `AES-ECB(key, [i] || nonce(8) || 0x00*7)`. This is NOT a generic
/// incrementing-counter CTR — only byte 0 (the block index) changes per block,
/// the 8-byte nonce sits at offsets 1..9, and bytes 9..16 are zero. Encryption
/// and decryption are the same operation.
pub fn fast_pair_ctr(key: &[u8; 16], nonce: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut counter = [0u8; 16];
        counter[0] = i as u8;
        counter[1..9].copy_from_slice(nonce);
        let keystream = aes128_ecb_encrypt_block(key, &counter)?;
        for (j, byte) in chunk.iter().enumerate() {
            out.push(byte ^ keystream[j]);
        }
    }
    Ok(out)
}

/// HMAC-SHA256, implemented directly over `sha2` to avoid pulling in an extra
/// crate. Used for the Additional Data integrity tag (Fast Pair §3.3.5).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        block_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_case1() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected, "RFC 4231 Test Case 1 failed");
    }

    #[test]
    fn hmac_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        let result = hmac_sha256(key, data);
        assert_eq!(result, expected, "RFC 4231 Test Case 2 failed");
    }

    #[test]
    fn hmac_rfc4231_case3() {
        let key = vec![0xAAu8; 131];
        let data = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let expected: [u8; 32] = [
            0x95, 0xe4, 0x32, 0x0a, 0x9f, 0x63, 0x29, 0xb0, 0xe3, 0x7c, 0x9e, 0x45, 0xfa, 0xa0,
            0xef, 0xa3, 0x18, 0xba, 0xae, 0xde, 0x39, 0x40, 0x79, 0xc7, 0x78, 0x09, 0x07, 0x38,
            0x18, 0x06, 0x56, 0x26,
        ];
        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected, "RFC 4231 Test Case 4 failed");
    }

    #[test]
    fn ecdh_reference() {
        let secret = generate_ephemeral();
        let pubkey = secret.public_key();
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), pubkey.as_affine());
        let z = shared.raw_secret_bytes();
        let digest = Sha256::digest(z.as_slice());
        let k: [u8; 16] = digest[..16].try_into().unwrap();
        assert!(!k.iter().all(|&b| b == 0), "K must not be all-zero");
    }

    #[test]
    fn derive_k_produces_16_bytes() {
        let secret = generate_ephemeral();
        let pubkey = secret.public_key();
        let k = derive_k(&secret, &pubkey);
        assert_eq!(k.len(), 16);
    }

    #[test]
    fn aes_ecb_roundtrip() {
        let key = [0x2bu8; 16];
        let plain = [0x6bu8; 16];
        let enc = aes128_ecb_encrypt_block(&key, &plain).unwrap();
        assert_ne!(enc, plain);
        let dec = aes128_ecb_decrypt_block(&key, &enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn fast_pair_ctr_roundtrip() {
        let key = [0x2bu8; 16];
        let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let plain = b"Hello Fast Pair test data with more than sixteen bytes";
        let enc = fast_pair_ctr(&key, &nonce, plain).unwrap();
        assert_ne!(&enc[..], plain);
        let dec = fast_pair_ctr(&key, &nonce, &enc).unwrap();
        assert_eq!(dec, plain.to_vec());
    }
}
