//! Post-Quantum Encrypted Channel — Rustsploit Server Side
//!
//! SSH-style identity model with ML-KEM-768 + X25519 hybrid encryption.
//! This is the SOLE transport security — no TLS, no API keys.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use kem::Encapsulate;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

const PROTOCOL_VERSION: &str = "pqxdh-v2-identity";
const HKDF_SALT_HANDSHAKE: &[u8] = b"ArcticAlopex-PQXDH-v2";
const HKDF_SALT_RATCHET: &[u8] = b"ArcticAlopex-ratchet-v2";
const DEFAULT_REKEY_AFTER: u64 = 100;

// ---------------------------------------------------------------------------
// Identity Keys
// ---------------------------------------------------------------------------

pub struct HostIdentity {
    pub x25519_secret: StaticSecret,
    pub x25519_public: PublicKey,
    pub mlkem_dk: Vec<u8>,
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
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        let x25519_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let x25519_public = PublicKey::from(&x25519_secret);
        let (dk, ek) = MlKem768::generate(&mut rng);
        // Serialize keys to bytes
        let dk_bytes: Vec<u8> = dk.as_bytes().to_vec();
        let ek_bytes: Vec<u8> = ek.as_bytes().to_vec();

        HostIdentity { x25519_secret, x25519_public, mlkem_dk: dk_bytes, mlkem_ek: ek_bytes }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let data = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "x25519_secret": b64.encode(self.x25519_secret.as_bytes()),
            "x25519_public": b64.encode(self.x25519_public.as_bytes()),
            "mlkem_dk": b64.encode(&self.mlkem_dk),
            "mlkem_ek": b64.encode(&self.mlkem_ek),
        });
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&data)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let content = std::fs::read_to_string(path)?;
        let data: serde_json::Value = serde_json::from_str(&content)?;

        let secret_bytes = b64.decode(data["x25519_secret"].as_str()
            .ok_or_else(|| anyhow::anyhow!("missing x25519_secret"))?)?;
        let secret_arr: [u8; 32] = secret_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("invalid x25519 secret length"))?;
        let x25519_secret = StaticSecret::from(secret_arr);
        let x25519_public = PublicKey::from(&x25519_secret);
        let mlkem_dk = b64.decode(data["mlkem_dk"].as_str()
            .ok_or_else(|| anyhow::anyhow!("missing mlkem_dk"))?)?;
        let mlkem_ek = b64.decode(data["mlkem_ek"].as_str()
            .ok_or_else(|| anyhow::anyhow!("missing mlkem_ek"))?)?;

        Ok(HostIdentity { x25519_secret, x25519_public, mlkem_dk, mlkem_ek })
    }

    pub fn load_or_generate(path: &Path) -> anyhow::Result<Self> {
        if path.exists() { Self::load(path) } else {
            let id = Self::generate();
            id.save(path)?;
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
            .map_err(|_| anyhow::anyhow!("Line {}: invalid x25519 pub length", i + 1))?;
        let mlkem_ek = b64.decode(data["mlkem_ek"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Line {}: missing mlkem_ek", i + 1))?)?;
        keys.push(ClientPublicIdentity { name, x25519_public: x25519_pub, mlkem_ek });
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub struct PqSession {
    pub session_id: [u8; 16],
    pub client_name: String,
    pub root_key: Vec<u8>,
    pub send_chain_key: Vec<u8>,
    pub recv_chain_key: Vec<u8>,
    pub send_counter: u64,
    pub recv_counter: u64,
    pub my_x25519_secret: StaticSecret,
    pub my_x25519_public: PublicKey,
    pub their_x25519_public: PublicKey,
    pub rekey_after: u64,
    pub created_at: Instant,
    pub epoch: u64,
}

pub type SessionStore = Arc<RwLock<HashMap<[u8; 16], PqSession>>>;

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
    pub identity_proof: String,
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
        .map_err(|_| anyhow::anyhow!("Invalid ephemeral X25519 pub"))?;

    let client_id_bytes = b64.decode(&request.client_identity_x25519_pub)?;
    let client_id_arr: [u8; 32] = client_id_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid identity X25519 pub"))?;

    // Verify authorized
    let _authorized = authorized_keys.iter().find(|k| k.x25519_public == client_id_arr)
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
    let mut rng = rand_core::OsRng;

    // Parse client's ML-KEM encapsulation key and encapsulate
    let ek_arr = ml_kem::Encoded::<ml_kem::kem::EncapsulationKey<MlKem768Params>>::try_from(client_mlkem_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("Invalid ML-KEM encapsulation key length"))?;
    let ek = ml_kem::kem::EncapsulationKey::<MlKem768Params>::from_bytes(&ek_arr);
    let (ct, ss_mlkem) = ek.encapsulate(&mut rng)
        .map_err(|_| anyhow::anyhow!("ML-KEM encapsulation failed"))?;

    // Combine 3 shared secrets
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(ss_eph.as_bytes());
    ikm.extend_from_slice(ss_id.as_bytes());
    ikm.extend_from_slice(ss_mlkem.as_ref());

    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_HANDSHAKE), &ikm);
    let mut root_key = vec![0u8; 64];
    hk.expand(instance_id.as_bytes(), &mut root_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let send_chain = derive_chain_key(&root_key, b"recv")?;
    let recv_chain = derive_chain_key(&root_key, b"send")?;

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
        h.update(&client_eph_arr);
        hex::encode(h.finalize())
    };

    let session = PqSession {
        session_id,
        client_name: _authorized.name.clone(),
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
        epoch: 0,
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

fn derive_chain_key(root_key: &[u8], label: &[u8]) -> anyhow::Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = vec![0u8; 32];
    hk.expand(label, &mut out).map_err(|_| anyhow::anyhow!("HKDF chain key failed"))?;
    Ok(out)
}

fn ratchet_step(chain_key: &[u8], counter: u64) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let info = format!("msg:{counter}");
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut derived = vec![0u8; 64];
    hk.expand(info.as_bytes(), &mut derived)
        .map_err(|_| anyhow::anyhow!("HKDF ratchet step failed"))?;
    Ok((derived[..32].to_vec(), derived[32..64].to_vec()))
}

fn dh_ratchet(session: &mut PqSession, their_new_pub: PublicKey) -> anyhow::Result<()> {
    let new_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let new_public = PublicKey::from(&new_secret);
    let dh = new_secret.diffie_hellman(&their_new_pub);
    let mut ikm = Vec::with_capacity(32 + session.root_key.len());
    ikm.extend_from_slice(dh.as_bytes());
    ikm.extend_from_slice(&session.root_key);
    let info = format!("{}:{}", hex::encode(session.session_id), session.epoch);
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT_RATCHET), &ikm);
    let mut new_root = vec![0u8; 64];
    hk.expand(info.as_bytes(), &mut new_root).map_err(|_| anyhow::anyhow!("HKDF DH ratchet failed"))?;
    session.send_chain_key = derive_chain_key(&new_root, b"send")?;
    session.recv_chain_key = derive_chain_key(&new_root, b"recv")?;
    session.root_key = new_root;
    session.my_x25519_secret = new_secret;
    session.my_x25519_public = new_public;
    session.their_x25519_public = their_new_pub;
    session.send_counter = 0;
    session.recv_counter = 0;
    session.epoch += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

pub fn decrypt_request(
    session: &mut PqSession, ciphertext: &[u8], nonce_bytes: &[u8; 12],
    aad: &[u8], rekey_pub: Option<&[u8; 32]>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(pub_bytes) = rekey_pub {
        dh_ratchet(session, PublicKey::from(*pub_bytes))?;
    }
    let (new_chain, msg_key) = ratchet_step(&session.recv_chain_key, session.recv_counter)?;
    session.recv_chain_key = new_chain;
    session.recv_counter += 1;
    let key: [u8; 32] = msg_key.try_into().map_err(|_| anyhow::anyhow!("Bad key len"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    cipher.decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow::anyhow!("PQ decrypt failed: {e}"))
}

pub fn encrypt_response(
    session: &mut PqSession, plaintext: &[u8], aad: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 12], Option<PublicKey>)> {
    let rekey_pub = if session.send_counter >= session.rekey_after {
        Some(session.my_x25519_public)
    } else { None };
    let (new_chain, msg_key) = ratchet_step(&session.send_chain_key, session.send_counter)?;
    session.send_chain_key = new_chain;
    session.send_counter += 1;
    let key: [u8; 32] = msg_key.try_into().map_err(|_| anyhow::anyhow!("Bad key len"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    // Derive deterministic nonce from epoch + counter to eliminate birthday collision risk.
    // Format: [4 bytes: epoch LE][8 bytes: counter LE] — unique per message per session.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&(session.epoch as u32).to_le_bytes());
    nonce_bytes[4..].copy_from_slice(&(session.send_counter - 1).to_le_bytes());
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("PQ encrypt failed: {e}"))?;
    Ok((ct, nonce_bytes, rekey_pub))
}
