//! Google Fast Pair protocol primitives (service 0xFE2C) shared by the
//! WhisperPair exploit (`exploits/bluetooth/wpair`), the rogue-beacon module
//! and the invalid-curve probe.
//!
//! `crypto.rs` — secp256r1 ECDH / AES-128-ECB / HMAC / AES-CTR primitives.
//! `protocol.rs` — Key-Based Pairing message construction + GATT UUIDs.
//! `db.rs` — COSIC WhisperPair model-ID dataset + Anti-Spoofing key resolution.

#[cfg(feature = "bluetooth")]
pub mod crypto;
#[cfg(feature = "bluetooth")]
pub mod db;
#[cfg(feature = "bluetooth")]
pub mod protocol;
