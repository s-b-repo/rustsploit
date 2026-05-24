//! Post-Quantum Encrypted Channel — Rustsploit Server Side
//!
//! SSH-style identity model with ML-KEM-768 + X25519 hybrid encryption.
//! This is the SOLE transport security — no TLS, no API keys.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use ml_kem::{Encapsulate, Generate, Key, KeyExport, MlKem768};
use sha2::{Sha256, Sha512};
use tokio::sync::RwLock;
use rand_core::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const PROTOCOL_VERSION: &str = "pqxdh-v2-identity";
// HKDF "labels" — these are the protocol-version domain separators that
// get mixed with the server's long-term identity to produce per-deployment
// salts. They are NOT used directly as HKDF salts; see `derive_salt`. This
// way two independent deployments derive different KDF domains even though
// they speak the same protocol, and the salts are cryptographically bound
// to the host identity (which is verified during the handshake).
const KDF_LABEL_HANDSHAKE: &[u8] = b"Rustsploit-PQXDH-v2/handshake";
const KDF_LABEL_RATCHET:   &[u8] = b"Rustsploit-PQXDH-v2/ratchet";
const KDF_LABEL_WS_V1:     &[u8] = b"Rustsploit-PQXDH-v2/ws-v1";
const DEFAULT_REKEY_AFTER: u64 = 100;

/// Produce a per-(server, client) HKDF salt that requires possession of one
/// of the two identity private keys to compute.
///
/// Definition:
///
///   salt = SHA-256(label || server_x25519_pub || client_x25519_pub
///                        || identity_dh)
///
/// where:
///   - `server_x25519_pub` and `client_x25519_pub` are the two long-term
///     identity *public* keys (the "2 keys together" property).
///   - `identity_dh` = `X25519(server_id_priv, client_id_pub)` =
///     `X25519(client_id_priv, server_id_pub)`. The two keypairs only
///     produce matching DH bytes if both sides hold their respective
///     legitimate private keys — that's the "if they match" property.
///   - `label` provides domain separation between handshake / ratchet /
///     ws-subsession contexts so the same identity pair derives distinct
///     salts for each protocol layer.
///
/// ML-KEM keys are no longer mixed in here. They were redundant: the
/// ML-KEM shared secret already enters the handshake IKM directly, and
/// hashing the encapsulation keys into the salt added bytes without
/// adding security. The X25519 identity DH is the right cryptographic
/// hook for "did the peer prove possession of the matching private key".
fn derive_salt(
    label: &[u8],
    server_x25519_pub: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    identity_dh: &[u8; 32],
) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(label);
    h.update(server_x25519_pub);
    h.update(client_x25519_pub);
    h.update(identity_dh);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Identity Keys
// ---------------------------------------------------------------------------

pub struct HostIdentity {
    pub x25519_secret: StaticSecret,
    pub x25519_public: PublicKey,
    /// ML-KEM-768 decapsulation key bytes. Wrapped in `Zeroizing` so the
    /// secret material is wiped on drop — `Vec<u8>` does not zero its
    /// backing buffer, and ml-kem's `DecapsulationKey` zeroes only itself,
    /// not the serialized form we keep here.
    pub mlkem_dk: Zeroizing<Vec<u8>>,
    pub mlkem_ek: Vec<u8>,
}

#[derive(Clone)]
pub struct ClientPublicIdentity {
    pub name: String,
    pub x25519_public: [u8; 32],
    pub mlkem_ek: Vec<u8>,
}

pub fn fingerprint(x25519_pub: &[u8], mlkem_pub: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(x25519_pub);
    hasher.update(mlkem_pub);
    let hash = hasher.finalize();
    format!("PQ256:{}", hex::encode(&hash[..16]))
}

impl HostIdentity {
    /// Generate a fresh host identity. ML-KEM keygen pulls from the OS RNG
    /// — failure is rare but possible (RNG exhaustion, bad entropy source);
    /// propagate as `Result` instead of panicking the daemon at startup.
    pub fn generate() -> anyhow::Result<Self> {
        let x25519_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let x25519_public = PublicKey::from(&x25519_secret);
        // `rand::rng()` returns `ThreadRng` (ChaCha12 reseeded from `OsRng`),
        // which is cryptographically secure. We can't pass `rand_core::OsRng`
        // directly here because `ml-kem` requires `rand_core 0.10`'s
        // `TryCryptoRng`, but the project pins `rand_core 0.6`'s `OsRng`
        // (used by x25519-dalek above).
        let dk = ml_kem::DecapsulationKey::<MlKem768>::try_generate_from_rng(&mut rand::rng())
            .map_err(|e| anyhow::anyhow!("ML-KEM key generation failed: {e:?}"))?;
        let ek = dk.encapsulation_key().clone();
        // Serialize keys to bytes
        let dk_bytes: Vec<u8> = dk.to_bytes().to_vec();
        let ek_bytes: Vec<u8> = ek.to_bytes().to_vec();

        Ok(HostIdentity {
            x25519_secret,
            x25519_public,
            mlkem_dk: Zeroizing::new(dk_bytes),
            mlkem_ek: ek_bytes,
        })
    }

    pub fn save(&self, path: &Path, passphrase: Option<&str>) -> anyhow::Result<()> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        let data = match passphrase {
            Some(pass) => {
                let plaintext_secrets = serde_json::json!({
                    "x25519_secret": b64.encode(self.x25519_secret.as_bytes()),
                    "mlkem_dk": b64.encode(&self.mlkem_dk),
                });
                let plaintext = serde_json::to_vec(&plaintext_secrets)?;

                let salt: [u8; 32] = {
                    let mut s = [0u8; 32];
                    rand_core::OsRng.fill_bytes(&mut s);
                    s
                };
                let key = Self::derive_key_from_passphrase(pass, &salt)?;
                let nonce_bytes: [u8; 12] = {
                    let mut n = [0u8; 12];
                    rand_core::OsRng.fill_bytes(&mut n);
                    n
                };

                let cipher = ChaCha20Poly1305::new((&*key).into());
                let nonce: chacha20poly1305::Nonce = nonce_bytes.into();
                let mut aad = Vec::with_capacity(32 + self.mlkem_ek.len() + PROTOCOL_VERSION.len());
                aad.extend_from_slice(self.x25519_public.as_bytes());
                aad.extend_from_slice(&self.mlkem_ek);
                aad.extend_from_slice(PROTOCOL_VERSION.as_bytes());
                let ciphertext = cipher
                    .encrypt(&nonce, Payload { msg: &plaintext, aad: &aad })
                    .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

                serde_json::json!({
                    "version": PROTOCOL_VERSION,
                    "encrypted": true,
                    "argon2_salt": b64.encode(salt),
                    "nonce": b64.encode(nonce_bytes),
                    "ciphertext": b64.encode(&ciphertext),
                    "x25519_public": b64.encode(self.x25519_public.as_bytes()),
                    "mlkem_ek": b64.encode(&self.mlkem_ek),
                })
            }
            None => {
                serde_json::json!({
                    "version": PROTOCOL_VERSION,
                    "x25519_secret": b64.encode(self.x25519_secret.as_bytes()),
                    "x25519_public": b64.encode(self.x25519_public.as_bytes()),
                    "mlkem_dk": b64.encode(&self.mlkem_dk),
                    "mlkem_ek": b64.encode(&self.mlkem_ek),
                })
            }
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut file = opts.open(&tmp)?;
            std::io::Write::write_all(&mut file, serde_json::to_string_pretty(&data)?.as_bytes())?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn derive_key_from_passphrase(passphrase: &str, salt: &[u8; 32]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        use argon2::Argon2;
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(131072, 4, 2, Some(32))
                .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
            .map_err(|e| anyhow::anyhow!("argon2 KDF failed: {e}"))?;
        Ok(key)
    }

    fn check_symlink_and_perms(path: &Path) -> anyhow::Result<()> {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("stat host-key file {}", path.display()))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "Refusing to read host identity through symlink: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "Host identity file {} has mode {:o} (should be 600). Anyone with read access can impersonate this server.",
                    path.display(),
                    mode
                );
            }
        }
        Ok(())
    }

    pub fn load(path: &Path, passphrase: Option<&str>) -> anyhow::Result<Self> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        Self::check_symlink_and_perms(path)?;

        let content = std::fs::read_to_string(path)?;
        let data: serde_json::Value = serde_json::from_str(&content)?;

        let encrypted = data.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);

        if encrypted {
            let pass = passphrase
                .ok_or_else(|| anyhow::anyhow!(
                    "Host key is encrypted but no passphrase provided (use --pq-key-passphrase)"
                ))?;

            let salt_bytes = b64.decode(data["argon2_salt"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing argon2_salt"))?)?;
            let salt: [u8; 32] = salt_bytes.try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("invalid argon2 salt length (got {} bytes)", v.len()))?;
            let nonce_vec = b64.decode(data["nonce"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing nonce"))?)?;
            let nonce_arr: [u8; 12] = nonce_vec.try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("invalid nonce length (got {} bytes)", v.len()))?;
            let ciphertext = b64.decode(data["ciphertext"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing ciphertext"))?)?;

            let x25519_pub_bytes = b64.decode(data["x25519_public"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing x25519_public"))?)?;
            let mlkem_ek = b64.decode(data["mlkem_ek"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing mlkem_ek"))?)?;
            let version = data["version"].as_str().unwrap_or("");

            let key = Self::derive_key_from_passphrase(pass, &salt)?;
            let cipher = ChaCha20Poly1305::new((&*key).into());
            let nonce: chacha20poly1305::Nonce = nonce_arr.into();
            let mut aad = Vec::with_capacity(x25519_pub_bytes.len() + mlkem_ek.len() + version.len());
            aad.extend_from_slice(&x25519_pub_bytes);
            aad.extend_from_slice(&mlkem_ek);
            aad.extend_from_slice(version.as_bytes());
            let plaintext = cipher
                .decrypt(&nonce, Payload { msg: &ciphertext, aad: &aad })
                .map_err(|e| anyhow::anyhow!("decryption failed — wrong passphrase or tampered key file? {e:?}"))?;

            let secrets: serde_json::Value = serde_json::from_slice(&plaintext)?;

            let secret_bytes = b64.decode(secrets["x25519_secret"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing x25519_secret in decrypted payload"))?)?;
            let secret_arr: [u8; 32] = secret_bytes.try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("invalid x25519 secret length (got {} bytes)", v.len()))?;
            let x25519_secret = StaticSecret::from(secret_arr);
            let x25519_public = PublicKey::from(&x25519_secret);
            let mlkem_dk = b64.decode(secrets["mlkem_dk"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing mlkem_dk in decrypted payload"))?)?;

            Ok(HostIdentity {
                x25519_secret,
                x25519_public,
                mlkem_dk: Zeroizing::new(mlkem_dk),
                mlkem_ek,
            })
        } else {
            if passphrase.is_some() {
                tracing::warn!(
                    "Host key at {} is plaintext but a passphrase was provided. \
                     Re-saving with encryption.",
                    path.display()
                );
            }

            let secret_bytes = b64.decode(data["x25519_secret"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing x25519_secret"))?)?;
            let secret_arr: [u8; 32] = secret_bytes.try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("invalid x25519 secret length (got {} bytes)", v.len()))?;
            let x25519_secret = StaticSecret::from(secret_arr);
            let x25519_public = PublicKey::from(&x25519_secret);
            let mlkem_dk = b64.decode(data["mlkem_dk"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing mlkem_dk"))?)?;
            let mlkem_ek = b64.decode(data["mlkem_ek"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing mlkem_ek"))?)?;

            let identity = HostIdentity {
                x25519_secret,
                x25519_public,
                mlkem_dk: Zeroizing::new(mlkem_dk),
                mlkem_ek,
            };

            if passphrase.is_some() {
                identity.save(path, passphrase)?;
            }

            Ok(identity)
        }
    }

    pub fn load_or_generate(path: &Path, passphrase: Option<&str>) -> anyhow::Result<Self> {
        if path.exists() {
            Self::load(path, passphrase)
        } else {
            let id = Self::generate()?;
            id.save(path, passphrase)?;
            Ok(id)
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(self.x25519_public.as_bytes(), &self.mlkem_ek)
    }
}

pub fn load_authorized_keys(path: &Path) -> anyhow::Result<Vec<ClientPublicIdentity>> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    if !path.exists() { return Ok(Vec::new()); }
    let content = std::fs::read_to_string(path)?;
    let mut keys = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let data: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("Line {}: invalid JSON: {}", i + 1, e))?;
        let name = data["name"].as_str().unwrap_or("unnamed").to_string();
        let x25519_bytes = b64.decode(data["x25519_pub"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Line {}: missing x25519_pub", i + 1))?)?;
        let x25519_pub: [u8; 32] = x25519_bytes.try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("Line {}: invalid x25519 pub length (got {} bytes)", i + 1, v.len()))?;
        let mlkem_ek = b64.decode(data["mlkem_ek"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Line {}: missing mlkem_ek", i + 1))?)?;
        keys.push(ClientPublicIdentity { name, x25519_public: x25519_pub, mlkem_ek });
    }
    Ok(keys)
}

/// Append (or replace, by `name`) one client identity into the
/// authorized_keys file. Used by `/pq/register-key` so a remote panel can
/// bootstrap itself without filesystem access on the server. Refuses to
/// follow symlinks.
pub fn upsert_authorized_key(path: &Path, key: &ClientPublicIdentity) -> anyhow::Result<()> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if path.exists() {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing to write through symlink at {}", path.display());
        }
    }

    // Read existing entries (skip the one we're replacing) and append.
    let mut lines: Vec<String> = Vec::new();
    if path.exists() {
        for line in std::fs::read_to_string(path)?.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                lines.push(line.to_string());
                continue;
            }
            // Replace any existing entry for the same name.
            let keep = match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => v.get("name").and_then(|n| n.as_str()) != Some(key.name.as_str()),
                Err(e) => { tracing::debug!("preserving malformed authorized-key line: {e}"); true }
            };
            if keep {
                lines.push(line.to_string());
            }
        }
    }
    lines.push(
        serde_json::json!({
            "name": key.name,
            "x25519_pub": b64.encode(key.x25519_public),
            "mlkem_ek": b64.encode(&key.mlkem_ek),
        })
        .to_string(),
    );

    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&tmp)?;
        std::io::Write::write_all(&mut file, (lines.join("\n") + "\n").as_bytes())?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Remove an authorized key entry by `name` from the on-disk file. Returns
/// `Ok(true)` if a row was removed, `Ok(false)` if no matching row existed.
/// Refuses to follow symlinks. The in-memory `authorized_keys` list must
/// also be updated by the caller — this helper only touches disk.
pub fn remove_authorized_key(path: &Path, name: &str) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("refusing to write through symlink at {}", path.display());
    }

    let mut lines: Vec<String> = Vec::new();
    let mut removed = false;
    for line in std::fs::read_to_string(path)?.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines.push(line.to_string());
            continue;
        }
        let keep = match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(v) => {
                if v.get("name").and_then(|n| n.as_str()) == Some(name) {
                    removed = true;
                    false
                } else {
                    true
                }
            }
            Err(e) => { tracing::debug!("preserving malformed authorized-key line: {e}"); true }
        };
        if keep {
            lines.push(line.to_string());
        }
    }

    if !removed {
        return Ok(false);
    }

    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&tmp)?;
        std::io::Write::write_all(&mut file, (lines.join("\n") + "\n").as_bytes())?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// Generate a one-time human-readable enrollment token (URL-safe base64 of
/// 24 random bytes ≈ 32 chars). Compared in constant time on the
/// `/pq/register-key` endpoint via `subtle::ConstantTimeEq`.
pub fn generate_enrollment_token() -> String {
    use base64::Engine;
    let mut buf = [0u8; 24];
    use rand::RngExt;
    rand::rng().fill(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub struct PqSession {
    pub session_id: [u8; 16],
    pub client_name: String,
    pub root_key: Zeroizing<Vec<u8>>,
    pub send_chain_key: Zeroizing<Vec<u8>>,
    pub recv_chain_key: Zeroizing<Vec<u8>>,
    pub send_counter: u64,
    pub recv_counter: u64,
    pub my_x25519_secret: StaticSecret,
    pub my_x25519_public: PublicKey,
    pub their_x25519_public: PublicKey,
    pub rekey_after: u64,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub epoch: u64,
    /// Per-deployment HKDF salt for the DH ratchet path (`KDF_LABEL_RATCHET`
    /// hashed with the server's identity). Bound at handshake time so the
    /// ratchet doesn't have to keep the server keys around.
    pub ratchet_salt: [u8; 32],
    /// Per-deployment HKDF salt for WebSocket sub-session derivation
    /// (`KDF_LABEL_WS_V1` hashed with the server's identity).
    pub ws_salt: [u8; 32],
}

/// Sessions are stored as `Arc<Mutex<PqSession>>` so concurrent requests for
/// **different** tenants don't serialize through one top-level lock, and
/// concurrent requests for the **same** tenant serialize on a per-session
/// mutex (independent of the map lock — so the map can stay readable while
/// any single session's chain advances).
pub type SessionStore = Arc<RwLock<HashMap<[u8; 16], Arc<tokio::sync::Mutex<PqSession>>>>>;

pub fn new_session_store() -> SessionStore {
    Arc::new(RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct HandshakeRequest {
    pub client_name: String,
    pub client_x25519_pub: String,
    pub client_identity_x25519_pub: String,
    pub client_mlkem_ek: String,
    pub protocol_version: String,
}

#[derive(serde::Serialize)]
pub struct HandshakeResponse {
    pub session_id: String,
    pub server_x25519_pub: String,
    pub server_identity_x25519_pub: String,
    pub server_mlkem_ek: String,
    pub mlkem_ciphertext: String,
    pub identity_proof: String,
    pub rekey_after: u64,
    pub server_version: String,
    pub server_fingerprint: String,
}

pub fn process_handshake(
    request: &HandshakeRequest,
    host_identity: &HostIdentity,
    authorized_keys: &[ClientPublicIdentity],
    instance_id: &str,
) -> anyhow::Result<(HandshakeResponse, PqSession)> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    if request.protocol_version != PROTOCOL_VERSION {
        anyhow::bail!("Protocol mismatch: expected {}, got {}", PROTOCOL_VERSION, request.protocol_version);
    }

    let client_eph_bytes = b64.decode(&request.client_x25519_pub)?;
    let client_eph_arr: [u8; 32] = client_eph_bytes.try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("Invalid ephemeral X25519 pub (got {} bytes)", v.len()))?;

    let client_id_bytes = b64.decode(&request.client_identity_x25519_pub)?;
    let client_id_arr: [u8; 32] = client_id_bytes.try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("Invalid identity X25519 pub (got {} bytes)", v.len()))?;

    // Verify authorized. The compared value is a public key (not secret), so
    // a non-constant-time compare wouldn't leak anything meaningful — but the
    // cost of `ct_eq` is trivial and it removes the question entirely. Walk
    // the whole list before returning so the failure path doesn't reveal
    // partial-match position via timing either.
    use subtle::ConstantTimeEq;
    let mut matched: Option<&ClientPublicIdentity> = None;
    for k in authorized_keys.iter() {
        if bool::from(k.x25519_public.ct_eq(&client_id_arr)) {
            matched = Some(k);
        }
    }
    let authorized = matched
        .ok_or_else(|| anyhow::anyhow!("Client not in authorized_keys"))?;

    // Ephemeral X25519 DH
    let server_eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let server_eph_public = PublicKey::from(&server_eph_secret);
    let ss_eph = server_eph_secret.diffie_hellman(&PublicKey::from(client_eph_arr));

    // Identity X25519 DH
    let client_id_pub = PublicKey::from(client_id_arr);
    let ss_id = host_identity.x25519_secret.diffie_hellman(&client_id_pub);

    // ML-KEM encapsulation
    let client_mlkem_bytes = b64.decode(&request.client_mlkem_ek)?;
    // Parse client's ML-KEM encapsulation key and encapsulate
    let ek_key: Key<ml_kem::EncapsulationKey<MlKem768>> = client_mlkem_bytes.as_slice()
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM encapsulation key length: {e:?}"))?;
    let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&ek_key)
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM encapsulation key: {e:?}"))?;
    let (ct, ss_mlkem) = ek.encapsulate_with_rng(&mut rand::rng());

    // Combine 3 shared secrets
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(ss_eph.as_bytes());
    ikm.extend_from_slice(ss_id.as_bytes());
    ikm.extend_from_slice(ss_mlkem.as_slice());

    // Derive per-(server, client) HKDF salts from the protocol label + BOTH
    // long-term identities + the X25519 identity DH. The handshake salt is
    // used here once; the ratchet and ws-subsession salts are stored in the
    // PqSession and used by `dh_ratchet_*` and `derive_ws_subsession`.
    // Mixing in `ss_id` (the identity DH) means an eavesdropper who captures
    // the handshake on the wire still cannot derive the salt without one of
    // the two identity private keys.
    let host_x25519_pub_arr: [u8; 32] = *host_identity.x25519_public.as_bytes();
    let id_dh_bytes: [u8; 32] = *ss_id.as_bytes();
    // New salt scheme (per the operator's request): the two long-term
    // X25519 public keys plus the identity DH. The DH is what enforces
    // "if they match" — without one of the private keys, neither side
    // can compute it. The two pubs ensure each (server, client) pairing
    // gets a distinct salt even if `identity_dh` were ever leaked.
    let handshake_salt = derive_salt(
        KDF_LABEL_HANDSHAKE,
        &host_x25519_pub_arr,
        &authorized.x25519_public,
        &id_dh_bytes,
    );
    let ratchet_salt = derive_salt(
        KDF_LABEL_RATCHET,
        &host_x25519_pub_arr,
        &authorized.x25519_public,
        &id_dh_bytes,
    );
    let ws_salt = derive_salt(
        KDF_LABEL_WS_V1,
        &host_x25519_pub_arr,
        &authorized.x25519_public,
        &id_dh_bytes,
    );

    let hk = Hkdf::<Sha512>::new(Some(&handshake_salt), &ikm);
    let mut root_key = Zeroizing::new(vec![0u8; 64]);
    hk.expand(instance_id.as_bytes(), &mut root_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e:?}"))?;

    // Directional labels: s2c (server→client) feeds the server's send chain
    // and the client's recv chain; c2s (client→server) feeds the opposite
    // direction. Using direction labels eliminates the
    // "is 'send' from whose perspective?" footgun that previously caused the
    // initial-handshake/dh-ratchet asymmetry bug.
    let send_chain = derive_chain_key(&root_key, b"s2c")?;
    let recv_chain = derive_chain_key(&root_key, b"c2s")?;

    let mut session_id = [0u8; 16];
    { use rand::RngExt; rand::rng().fill(&mut session_id); }

    let ratchet_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let ratchet_public = PublicKey::from(&ratchet_secret);

    // Identity proof
    let proof = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(ss_id.as_bytes());
        h.update(server_eph_public.as_bytes());
        h.update(client_eph_arr);
        hex::encode(h.finalize())
    };

    let session = PqSession {
        session_id,
        client_name: authorized.name.clone(),
        root_key,
        send_chain_key: send_chain,
        recv_chain_key: recv_chain,
        send_counter: 0,
        recv_counter: 0,
        my_x25519_secret: ratchet_secret,
        my_x25519_public: ratchet_public,
        their_x25519_public: PublicKey::from(client_eph_arr),
        rekey_after: DEFAULT_REKEY_AFTER,
        created_at: Instant::now(),
        last_activity: Instant::now(),
        epoch: 0,
        ratchet_salt,
        ws_salt,
    };

    let ct_bytes: Vec<u8> = ct.as_slice().to_vec();

    let response = HandshakeResponse {
        session_id: b64.encode(session_id),
        server_x25519_pub: b64.encode(server_eph_public.as_bytes()),
        server_identity_x25519_pub: b64.encode(host_identity.x25519_public.as_bytes()),
        server_mlkem_ek: b64.encode(&host_identity.mlkem_ek),
        mlkem_ciphertext: b64.encode(&ct_bytes),
        identity_proof: proof,
        rekey_after: DEFAULT_REKEY_AFTER,
        server_version: PROTOCOL_VERSION.to_string(),
        server_fingerprint: host_identity.fingerprint(),
    };

    Ok((response, session))
}

// ---------------------------------------------------------------------------
// Double Ratchet
// ---------------------------------------------------------------------------

fn derive_chain_key(root_key: &[u8], label: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    hk.expand(label, &mut out).map_err(|e| anyhow::anyhow!("HKDF chain key failed: {e:?}"))?;
    Ok(out)
}

fn ratchet_step(chain_key: &[u8], counter: u64) -> anyhow::Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let info = format!("msg:{counter}");
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut derived = Zeroizing::new(vec![0u8; 64]);
    hk.expand(info.as_bytes(), &mut derived)
        .map_err(|e| anyhow::anyhow!("HKDF ratchet step failed: {e:?}"))?;
    let new_chain = Zeroizing::new(derived[..32].to_vec());
    let msg_key = derived[32..64].to_vec();
    Ok((new_chain, msg_key))
}

/// Common HKDF that turns `(root_key, dh_shared, session_id, epoch)` into a
/// fresh root + send/recv chain pair. Both sides of a rekey land here with
/// the same DH input (X25519 commutativity), so they derive identical chains
/// and root.
fn ratchet_root(
    session: &mut PqSession,
    dh: &[u8; 32],
) -> anyhow::Result<()> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + session.root_key.len()));
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(&session.root_key);
    // Info = raw 16-byte session_id || ":epoch" ASCII. Matches the TS
    // implementation byte-for-byte (the previous hex-encoded form silently
    // diverged the root key across implementations).
    let mut info = Vec::with_capacity(16 + 8);
    info.extend_from_slice(&session.session_id);
    info.extend_from_slice(format!(":{}", session.epoch).as_bytes());
    let hk = Hkdf::<Sha512>::new(Some(&session.ratchet_salt), &ikm);
    let mut new_root = Zeroizing::new(vec![0u8; 64]);
    hk.expand(&info, &mut new_root)
        .map_err(|e| anyhow::anyhow!("HKDF DH ratchet failed: {e:?}"))?;
    session.send_chain_key = derive_chain_key(&new_root, b"s2c")?;
    session.recv_chain_key = derive_chain_key(&new_root, b"c2s")?;
    session.root_key = new_root;
    session.send_counter = 0;
    session.recv_counter = 0;
    session.epoch += 1;
    Ok(())
}

/// Receive-side ratchet. Triggered when the peer attaches a new public key
/// to a message. Uses **own current** secret + **peer's new** public, so the
/// DH input matches what the sender computed with its new secret + our
/// current public. Does NOT rotate our own keypair.
fn dh_ratchet_receive(session: &mut PqSession, their_new_pub: PublicKey) -> anyhow::Result<()> {
    let dh_shared = session.my_x25519_secret.diffie_hellman(&their_new_pub);
    let dh_bytes: [u8; 32] = *dh_shared.as_bytes();
    session.their_x25519_public = their_new_pub;
    ratchet_root(session, &dh_bytes)?;
    Ok(())
}

/// Send-side ratchet. Generates a fresh own keypair and DH's it against the
/// peer's current public. Returns the new own public so the caller can attach
/// it to the outgoing wire as `rekey_pub`. The peer, on receipt, will run the
/// receive ratchet with our new public + its current secret — the two DHs are
/// equal by X25519 commutativity, so both ends end up with the same new root.
fn dh_ratchet_send(session: &mut PqSession) -> anyhow::Result<PublicKey> {
    let new_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let new_public = PublicKey::from(&new_secret);
    let dh_shared = new_secret.diffie_hellman(&session.their_x25519_public);
    let dh_bytes: [u8; 32] = *dh_shared.as_bytes();
    session.my_x25519_secret = new_secret;
    session.my_x25519_public = new_public;
    ratchet_root(session, &dh_bytes)?;
    Ok(new_public)
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

/// Decrypt an inbound message. The AAD is built by the caller-provided
/// closure with the *post-ratchet* epoch so that, when a `rekey_pub` is
/// attached to this very message, the AAD aligns with what the sender used
/// (which was also the post-ratchet epoch).
pub fn decrypt_request<F>(
    session: &mut PqSession,
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
    aad_builder: F,
    rekey_pub: Option<&[u8; 32]>,
) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(u64) -> Vec<u8>,
{
    if let Some(pub_bytes) = rekey_pub {
        // Peer attached its new pub — advance our recv chain to match.
        dh_ratchet_receive(session, PublicKey::from(*pub_bytes))?;
    }
    let aad = aad_builder(session.epoch);
    let (new_chain, msg_key) = ratchet_step(&session.recv_chain_key, session.recv_counter)?;
    session.recv_chain_key = new_chain;
    session.recv_counter += 1;
    session.last_activity = Instant::now();
    let key: [u8; 32] = msg_key.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("Bad key len (got {} bytes)", v.len()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    cipher
        .decrypt(nonce_bytes.into(), Payload { msg: ciphertext, aad: &aad })
        .map_err(|e| anyhow::anyhow!("PQ decrypt failed: {e}"))
}

/// Result of encrypting an outbound message: (ciphertext, nonce, rekey_pub, effective_epoch).
type EncryptedResponse = (Vec<u8>, [u8; 12], Option<PublicKey>, u64);

/// Encrypt an outbound message. Returns `(ciphertext, nonce, rekey_pub,
/// effective_epoch)`. The caller MUST surface `effective_epoch` in the
/// `X-PQ-Epoch` header — it is the post-ratchet epoch, which the receiver
/// will use when reconstructing the AAD.
pub fn encrypt_response<F>(
    session: &mut PqSession,
    plaintext: &[u8],
    aad_builder: F,
) -> anyhow::Result<EncryptedResponse>
where
    F: FnOnce(u64) -> Vec<u8>,
{
    // At threshold we MUST advance both our keypair AND chain BEFORE
    // encrypting, because the receiver ratchets on receipt and decrypts the
    // very same message with the new chain. The previous code attached the
    // OLD pub and used the OLD chain — first post-rekey message broke.
    let rekey_pub = if session.send_counter >= session.rekey_after {
        Some(dh_ratchet_send(session)?)
    } else {
        None
    };
    let aad = aad_builder(session.epoch);
    let (new_chain, msg_key) = ratchet_step(&session.send_chain_key, session.send_counter)?;
    session.send_chain_key = new_chain;
    session.send_counter += 1;
    session.last_activity = Instant::now();
    let key: [u8; 32] = msg_key.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("Bad key len (got {} bytes)", v.len()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    let mut nonce_bytes = [0u8; 12];
    {
        use rand::RngExt;
        rand::rng().fill(&mut nonce_bytes);
    }
    let ct = cipher
        .encrypt((&nonce_bytes).into(), Payload { msg: plaintext, aad: &aad })
        .map_err(|e| anyhow::anyhow!("PQ encrypt failed: {e}"))?;
    Ok((ct, nonce_bytes, rekey_pub, session.epoch))
}

// ---------------------------------------------------------------------------
// WebSocket Sub-Session
// ---------------------------------------------------------------------------

/// Per-connection symmetric ratchet for WebSocket frames.
///
/// **Forward-secrecy property**: frames are protected by the chain
/// ratchet alone — there is no in-band DH rekey on the WS path. By
/// contrast, the HTTP path performs a full DH ratchet every
/// `DEFAULT_REKEY_AFTER` messages.
///
/// Mitigation already in place (audit finding F1, partially addressed):
/// each WS connection derives chains bound to a unique 16-byte
/// `connection_nonce` (see `derive_ws_subsession`), so two concurrent
/// connections from the same parent session never derive the same
/// keys.
///
/// Residual concern: a leaked chain key still compromises every later
/// frame on *that* connection until tear-down. Callers should keep WS
/// connections short-lived relative to the threat model, or re-derive
/// the sub-session after the parent rotates its DH keys.
pub struct WsSubSession {
    pub session_id: [u8; 16],
    pub send_chain_key: Zeroizing<Vec<u8>>,
    pub recv_chain_key: Zeroizing<Vec<u8>>,
    pub send_counter: u64,
    pub recv_counter: u64,
    /// Reserved for future DH-rekey on the WS path. Currently always 0 —
    /// `derive_ws_subsession` initialises it and nothing advances it.
    /// The `epoch > u32::MAX` guard in `encrypt_ws_frame` is dead-code
    /// kept for forward-compat; see audit finding F1.
    pub epoch: u64,
}

/// Role of the local end in a WS sub-session. Determines which HKDF label
/// becomes the send chain vs the recv chain — Server: send=s2c, recv=c2s;
/// Client: send=c2s, recv=s2c. Without this distinction both ends would
/// derive identical chains and the first frame each side sent would reuse
/// `(key, nonce)` (the AEAD nonce is `epoch || send_counter`, both starting
/// at zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsRole {
    Server,
    Client,
}

/// Derive a fresh WS sub-session bound to this connection's `connection_nonce`.
///
/// The nonce MUST be unique per WebSocket connection — the server picks it
/// at upgrade time and sends it (in the clear) as the first 16 bytes of the
/// WS stream so the client can derive matching chains. Without it, two
/// concurrent WS opens from the same parent session derive identical chain
/// keys and any send-counter overlap is catastrophic.
pub fn derive_ws_subsession(
    session: &PqSession,
    role: WsRole,
    connection_nonce: &[u8; 16],
) -> anyhow::Result<WsSubSession> {
    let hk = Hkdf::<Sha256>::new(Some(&session.ws_salt), &session.root_key);
    let mut info = Vec::with_capacity(b"ws-channel|".len() + 16);
    info.extend_from_slice(b"ws-channel|");
    info.extend_from_slice(connection_nonce);
    let mut ws_root = Zeroizing::new(vec![0u8; 64]);
    hk.expand(&info, &mut ws_root)
        .map_err(|e| anyhow::anyhow!("HKDF WS sub-session derivation failed: {e:?}"))?;
    let (send_label, recv_label): (&[u8], &[u8]) = match role {
        WsRole::Server => (b"ws-s2c", b"ws-c2s"),
        WsRole::Client => (b"ws-c2s", b"ws-s2c"),
    };
    let send_chain = derive_chain_key(&ws_root, send_label)?;
    let recv_chain = derive_chain_key(&ws_root, recv_label)?;
    Ok(WsSubSession {
        session_id: session.session_id,
        send_chain_key: send_chain,
        recv_chain_key: recv_chain,
        send_counter: 0,
        recv_counter: 0,
        epoch: 0,
    })
}

pub fn encrypt_ws_frame(sub: &mut WsSubSession, plaintext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (new_chain, msg_key) = ratchet_step(&sub.send_chain_key, sub.send_counter)?;
    sub.send_chain_key = new_chain;
    sub.send_counter += 1;
    let key: [u8; 32] = msg_key.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("Bad key len (got {} bytes)", v.len()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    if sub.epoch > u32::MAX as u64 {
        anyhow::bail!("WS sub-session epoch exhausted");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&(sub.epoch as u32).to_le_bytes());
    nonce_bytes[4..].copy_from_slice(&(sub.send_counter - 1).to_le_bytes());
    let ct = cipher.encrypt((&nonce_bytes).into(), Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("WS encrypt failed: {e}"))?;
    let mut frame = Vec::with_capacity(12 + ct.len());
    frame.extend_from_slice(&nonce_bytes);
    frame.extend_from_slice(&ct);
    Ok(frame)
}

pub fn decrypt_ws_frame(sub: &mut WsSubSession, frame: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    if frame.len() < 12 {
        anyhow::bail!("WS frame too short (need at least 12 bytes for nonce)");
    }
    let nonce_bytes: [u8; 12] = frame[..12].try_into()
        .map_err(|e| anyhow::anyhow!("Invalid nonce slice: {e:?}"))?;
    let ciphertext = &frame[12..];
    let (candidate_chain, msg_key) = ratchet_step(&sub.recv_chain_key, sub.recv_counter)?;
    let key: [u8; 32] = msg_key.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("Bad key len (got {} bytes)", v.len()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    let plaintext = cipher
        .decrypt((&nonce_bytes).into(), Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow::anyhow!("WS decrypt failed: {e}"))?;
    sub.recv_chain_key = candidate_chain;
    sub.recv_counter += 1;
    Ok(plaintext)
}
