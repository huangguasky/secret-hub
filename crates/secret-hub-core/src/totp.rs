use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::{Result, SecretHubError};

type HmacSha1 = Hmac<Sha1>;

pub fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

pub fn generate_code(secret: &str, digits: u32, period: u64) -> Result<String> {
    if digits == 0 || digits > 10 || period == 0 {
        return Err(SecretHubError::InvalidTotpSecret);
    }
    let secret = normalize_secret(secret);
    let key = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|_| SecretHubError::InvalidTotpSecret)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SecretHubError::Time)?
        .as_secs();
    let counter = now / period;
    hotp(&key, counter, digits)
}

fn hotp(key: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| SecretHubError::InvalidTotpSecret)?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((u32::from(result[offset]) & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);
    let modulo = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = digits as usize
    ))
}
