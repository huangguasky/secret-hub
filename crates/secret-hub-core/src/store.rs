use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    AuthMode, Result, SecretHubError, VaultData,
    crypto::{EncryptedPayload, decode_key, decrypt_bytes, encode_key, encrypt_bytes},
    paths::HubPaths,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub auth: AuthMode,
    pub wrapped_key: EncryptedPayload,
    pub data: EncryptedPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub expires_at: DateTime<Utc>,
    pub vault_key: String,
}

pub fn read_vault_file(paths: &HubPaths) -> Result<VaultFile> {
    if !paths.vault_file.exists() {
        return Err(SecretHubError::VaultNotInitialized);
    }
    let text = std::fs::read_to_string(&paths.vault_file)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn write_vault_file(paths: &HubPaths, vault: &VaultFile) -> Result<()> {
    paths.ensure_dir()?;
    let text = serde_json::to_string_pretty(vault)?;
    std::fs::write(&paths.vault_file, text)?;
    Ok(())
}

pub fn write_key_file(paths: &HubPaths, key: &[u8; 32]) -> Result<()> {
    paths.ensure_dir()?;
    std::fs::write(&paths.key_file, encode_key(key))?;
    Ok(())
}

pub fn read_key_file(paths: &HubPaths) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(&paths.key_file)?;
    decode_key(text.trim())
}

pub fn delete_key_file(paths: &HubPaths) -> Result<()> {
    if paths.key_file.exists() {
        std::fs::remove_file(&paths.key_file)?;
    }
    Ok(())
}

pub fn save_session(
    paths: &HubPaths,
    vault_key: &[u8; 32],
    expires_at: DateTime<Utc>,
) -> Result<()> {
    paths.ensure_dir()?;
    let session = SessionFile {
        expires_at,
        vault_key: encode_key(vault_key),
    };
    std::fs::write(&paths.session_file, serde_json::to_string_pretty(&session)?)?;
    Ok(())
}

pub fn load_session(paths: &HubPaths) -> Result<Option<[u8; 32]>> {
    if !paths.session_file.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&paths.session_file)?;
    let session: SessionFile = serde_json::from_str(&text)?;
    if session.expires_at <= Utc::now() {
        clear_session(paths)?;
        return Ok(None);
    }
    decode_key(&session.vault_key).map(Some)
}

pub fn clear_session(paths: &HubPaths) -> Result<()> {
    if paths.session_file.exists() {
        std::fs::remove_file(&paths.session_file)?;
    }
    Ok(())
}

pub fn encrypt_vault_data(vault_key: &[u8; 32], data: &VaultData) -> Result<EncryptedPayload> {
    let mut json = serde_json::to_vec(data)?;
    let encrypted = encrypt_bytes(vault_key, &json)?;
    json.zeroize();
    Ok(encrypted)
}

pub fn decrypt_vault_data(vault_key: &[u8; 32], payload: &EncryptedPayload) -> Result<VaultData> {
    let mut json = decrypt_bytes(vault_key, payload)?;
    let data = serde_json::from_slice(&json)?;
    json.zeroize();
    Ok(data)
}
