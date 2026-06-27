use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub entries: Vec<SecretEntry>,
}

impl VaultData {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            version: 1,
            created_at: now,
            updated_at: now,
            entries: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: Uuid,
    pub name: String,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub kind: SecretKind,
}

impl SecretEntry {
    pub fn new(name: String, tags: Vec<String>, notes: Option<String>, kind: SecretKind) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            tags,
            notes,
            created_at: now,
            updated_at: now,
            kind,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SecretKind {
    Totp(TotpEntry),
    ApiKey(ApiKeyEntry),
    Password(PasswordEntry),
    Token(TokenEntry),
}

impl SecretKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Totp(_) => "totp",
            Self::ApiKey(_) => "api-key",
            Self::Password(_) => "password",
            Self::Token(_) => "token",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEntry {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub secret: String,
    pub digits: u32,
    pub period: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    pub provider: Option<String>,
    pub key: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub service: Option<String>,
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum AuthMode {
    NoPassword { key_file: String },
    Password { salt: String },
}
