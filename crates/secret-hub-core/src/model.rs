use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
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
    Env(EnvProfile),
}

impl SecretKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Totp(_) => "totp",
            Self::ApiKey(_) => "api-key",
            Self::Password(_) => "password",
            Self::Token(_) => "token",
            Self::Env(_) => "env",
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
pub struct EnvProfile {
    pub project: String,
    pub profile: String,
    pub variables: Vec<EnvVariable>,
}

impl EnvProfile {
    pub fn new(project: String, profile: String) -> Self {
        Self {
            project,
            profile,
            variables: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVariable {
    pub key: String,
    pub value: EnvValue,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum EnvValue {
    Literal {
        value: String,
    },
    SecretRef {
        kind: EnvSecretRefKind,
        name: String,
    },
}

impl EnvValue {
    pub fn literal(value: String) -> Self {
        Self::Literal { value }
    }
}

impl<'de> Deserialize<'de> for EnvValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum EnvValueCompat {
            LegacyLiteral(String),
            Tagged {
                source: String,
                value: Option<String>,
                kind: Option<EnvSecretRefKind>,
                name: Option<String>,
            },
        }

        match EnvValueCompat::deserialize(deserializer)? {
            EnvValueCompat::LegacyLiteral(value) => Ok(EnvValue::Literal { value }),
            EnvValueCompat::Tagged {
                source,
                value,
                kind,
                name,
            } => match source.as_str() {
                "literal" => Ok(EnvValue::Literal {
                    value: value.unwrap_or_default(),
                }),
                "secret-ref" => Ok(EnvValue::SecretRef {
                    kind: kind.ok_or_else(|| serde::de::Error::missing_field("kind"))?,
                    name: name.ok_or_else(|| serde::de::Error::missing_field("name"))?,
                }),
                _ => Err(serde::de::Error::unknown_variant(
                    &source,
                    &["literal", "secret-ref"],
                )),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvSecretRefKind {
    ApiKey,
    Token,
}

impl EnvSecretRefKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "api-key",
            Self::Token => "token",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum AuthMode {
    NoPassword { key_file: String },
    Password { salt: String },
}
