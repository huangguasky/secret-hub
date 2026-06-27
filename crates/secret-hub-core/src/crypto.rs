use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Result, SecretHubError};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub version: u32,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn random_key() -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    random_fill(&mut key).map_err(|_| SecretHubError::Crypto)?;
    Ok(key)
}

pub fn random_salt() -> Result<String> {
    let mut bytes = [0u8; 16];
    random_fill(&mut bytes).map_err(|_| SecretHubError::Crypto)?;
    Ok(STANDARD.encode(bytes))
}

pub fn derive_key(password: &str, salt_b64: &str) -> Result<[u8; KEY_LEN]> {
    let salt_bytes = STANDARD
        .decode(salt_b64)
        .map_err(|_| SecretHubError::InvalidPassword)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| SecretHubError::Crypto)?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| SecretHubError::Crypto)?;
    let hash = hash.hash.ok_or(SecretHubError::Crypto)?;
    let bytes = hash.as_bytes();
    if bytes.len() < KEY_LEN {
        return Err(SecretHubError::Crypto);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes[..KEY_LEN]);
    Ok(key)
}

pub fn encrypt_bytes(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<EncryptedPayload> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    random_fill(&mut nonce).map_err(|_| SecretHubError::Crypto)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| SecretHubError::Crypto)?;
    Ok(EncryptedPayload {
        version: 1,
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_bytes(key: &[u8; KEY_LEN], payload: &EncryptedPayload) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = STANDARD
        .decode(&payload.nonce)
        .map_err(|_| SecretHubError::Crypto)?;
    let ciphertext = STANDARD
        .decode(&payload.ciphertext)
        .map_err(|_| SecretHubError::Crypto)?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| SecretHubError::InvalidPassword)
}

pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    STANDARD.encode(key)
}

pub fn decode_key(value: &str) -> Result<[u8; KEY_LEN]> {
    let mut decoded = STANDARD.decode(value).map_err(|_| SecretHubError::Crypto)?;
    if decoded.len() != KEY_LEN {
        decoded.zeroize();
        return Err(SecretHubError::Crypto);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}
