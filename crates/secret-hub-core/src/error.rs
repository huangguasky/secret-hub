use thiserror::Error;

pub type Result<T> = std::result::Result<T, SecretHubError>;

#[derive(Debug, Error)]
pub enum SecretHubError {
    #[error("vault already exists")]
    VaultAlreadyExists,
    #[error("vault is not initialized")]
    VaultNotInitialized,
    #[error("login required")]
    LoginRequired,
    #[error("invalid password")]
    InvalidPassword,
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("unsupported operation in current auth mode")]
    UnsupportedAuthMode,
    #[error("invalid TOTP secret")]
    InvalidTotpSecret,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error")]
    Crypto,
    #[error("time error")]
    Time,
    #[error("configuration directory is unavailable")]
    ConfigDirUnavailable,
}
