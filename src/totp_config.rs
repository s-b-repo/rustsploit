// src/totp_config.rs
//
// TOTP secret storage with 1:1 API token binding
// Each TOTP is linked to a specific API auth token
// Secrets stored in ~/.rustsploit/totp.json

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use totp_rs::{Algorithm, Secret, TOTP};

/// Maximum TOTP entries to prevent DoS
const MAX_TOTP_ENTRIES: usize = 100;

/// TOTP time step (standard 30 seconds)
const TOTP_STEP: u64 = 30;

/// TOTP digits (standard 6)
const TOTP_DIGITS: usize = 6;

/// Session validity duration (30 minutes in seconds)
pub const SESSION_DURATION_SECS: i64 = 30 * 60;

/// TOTP entry linked to a specific API token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEntry {
    /// Base32-encoded secret
    pub secret: String,
    /// SHA256 hash of the linked API token
    pub linked_token_hash: String,
    /// Human-readable label
    pub label: String,
    /// When this entry was created
    pub created_at: String,
    /// Whether this entry is enabled
    pub enabled: bool,
}

/// TOTP configuration storage with token binding
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TotpConfig {
    /// Map of token_hash -> TOTP entry (1:1 binding)
    entries: HashMap<String, TotpEntry>,
    /// Global TOTP enabled flag
    pub totp_enabled: bool,
}

impl TotpConfig {
    /// Hash an API token for storage (never store plaintext tokens)
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Get the config file path
    fn config_path() -> Result<PathBuf> {
        let home = home::home_dir()
            .ok_or_else(|| anyhow!("Cannot determine home directory"))?;
        let config_dir = home.join(".rustsploit");
        
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)
                .context("Failed to create .rustsploit directory")?;
        }
        
        Ok(config_dir.join("totp.json"))
    }
    
    /// Load configuration from disk
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        
        if !path.exists() {
            return Ok(Self::default());
        }
        
        let mut file = File::open(&path)
            .context("Failed to open TOTP config file")?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .context("Failed to read TOTP config file")?;
        
        serde_json::from_str(&contents)
            .context("Failed to parse TOTP config file")
    }
    
    /// Save configuration to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        
        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize TOTP config")?;
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .context("Failed to create TOTP config file")?;
        
        file.write_all(contents.as_bytes())
            .context("Failed to write TOTP config file")?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .context("Failed to set TOTP config permissions")?;
        }
        
        Ok(())
    }
    
    /// Generate a new TOTP secret linked to a specific API token
    pub fn generate_secret_for_token(&mut self, token: &str, label: &str) -> Result<(String, String, String)> {
        if self.entries.len() >= MAX_TOTP_ENTRIES {
            return Err(anyhow!("Maximum TOTP entries ({}) reached", MAX_TOTP_ENTRIES));
        }
        
        let token_hash = Self::hash_token(token);
        
        // Check if token already has TOTP
        if self.entries.contains_key(&token_hash) {
            return Err(anyhow!("TOTP already exists for this token. Remove it first."));
        }
        
        // Generate random secret
        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            1,
            TOTP_STEP,
            secret.to_bytes()?,
            Some("RustSploit".to_string()),
            label.to_string(),
        ).map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;
        
        let otpauth_url = totp.get_url();
        
        let entry = TotpEntry {
            secret: secret_base32.clone(),
            linked_token_hash: token_hash.clone(),
            label: label.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            enabled: true,
        };
        
        self.entries.insert(token_hash.clone(), entry);
        self.totp_enabled = true;
        self.save()?;
        
        Ok((secret_base32, otpauth_url, token_hash))
    }
    
    /// Generate QR code PNG for a token's TOTP
    pub fn generate_qr_png_for_token(&self, token: &str) -> Result<Vec<u8>> {
        let token_hash = Self::hash_token(token);
        let entry = self.entries.get(&token_hash)
            .ok_or_else(|| anyhow!("No TOTP entry for this token"))?;
        
        let secret = Secret::Encoded(entry.secret.clone());
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            1,
            TOTP_STEP,
            secret.to_bytes()?,
            Some("RustSploit".to_string()),
            entry.label.clone(),
        ).map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;
        
        totp.get_qr_png()
            .map_err(|e| anyhow!("Failed to generate QR code: {}", e))
    }
    
    /// Verify a TOTP code for a specific token (1:1 binding enforced)
    pub fn verify_code_for_token(&self, token: &str, code: &str) -> Result<bool> {
        let token_hash = Self::hash_token(token);
        
        let entry = self.entries.get(&token_hash)
            .ok_or_else(|| anyhow!("No TOTP configured for this token"))?;
        
        if !entry.enabled {
            return Err(anyhow!("TOTP is disabled for this token"));
        }
        
        // Verify the entry's token hash matches (enforce 1:1 binding)
        if entry.linked_token_hash != token_hash {
            return Err(anyhow!("Token does not match TOTP binding"));
        }
        
        self.verify_entry(entry, code)
    }
    
    /// Verify code against a specific entry
    fn verify_entry(&self, entry: &TotpEntry, code: &str) -> Result<bool> {
        let secret = Secret::Encoded(entry.secret.clone());
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            1,
            TOTP_STEP,
            secret.to_bytes()?,
            Some("RustSploit".to_string()),
            entry.label.clone(),
        ).map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;
        
        Ok(totp.check_current(code).unwrap_or(false))
    }
    
    /// Check if TOTP is configured for a specific token
    pub fn is_configured_for_token(&self, token: &str) -> bool {
        let token_hash = Self::hash_token(token);
        self.entries.contains_key(&token_hash)
    }
    
    /// Check if any TOTP is configured
    pub fn is_configured(&self) -> bool {
        self.totp_enabled && !self.entries.is_empty()
    }
    
    /// Get the text secret for a token (for manual entry in authenticator)
    pub fn get_text_secret_for_token(&self, token: &str) -> Option<String> {
        let token_hash = Self::hash_token(token);
        self.entries.get(&token_hash).map(|e| e.secret.clone())
    }
    
    /// Remove TOTP entry for a token
    pub fn remove_entry_by_token(&mut self, token: &str) -> Result<bool> {
        let token_hash = Self::hash_token(token);
        self.remove_entry_by_hash(&token_hash)
    }
    
    /// Remove TOTP entry by token hash
    pub fn remove_entry_by_hash(&mut self, token_hash: &str) -> Result<bool> {
        let removed = self.entries.remove(token_hash).is_some();
        if removed {
            if self.entries.is_empty() {
                self.totp_enabled = false;
            }
            self.save()?;
        }
        Ok(removed)
    }
    
    /// List all TOTP accounts (shows partial hash for identification)
    pub fn list_accounts(&self) -> Vec<(String, &TotpEntry)> {
        self.entries
            .iter()
            .map(|(hash, entry)| {
                // Show first 8 chars of hash for identification
                let short_hash = if hash.len() >= 8 {
                    format!("{}...", &hash[..8])
                } else {
                    hash.clone()
                };
                (short_hash, entry)
            })
            .collect()
    }
    
    /// Get entry by full token hash
    pub fn get_entry_by_hash(&self, token_hash: &str) -> Option<&TotpEntry> {
        self.entries.get(token_hash)
    }
    
    /// Get all token hashes (for wizard selection)
    pub fn get_all_token_hashes(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}
