use std::path::PathBuf;

use crate::{Result, SecretHubError};

#[derive(Debug, Clone)]
pub struct HubPaths {
    pub config_dir: PathBuf,
    pub vault_file: PathBuf,
    pub key_file: PathBuf,
    pub session_file: PathBuf,
}

impl HubPaths {
    pub fn resolve() -> Result<Self> {
        let config_dir = match std::env::var_os("SECRET_HUB_HOME") {
            Some(path) => PathBuf::from(path),
            None => dirs::config_dir()
                .ok_or(SecretHubError::ConfigDirUnavailable)?
                .join("secret-hub"),
        };
        Ok(Self {
            vault_file: config_dir.join("vault.json"),
            key_file: config_dir.join("vault.key"),
            session_file: config_dir.join("session.json"),
            config_dir,
        })
    }

    pub fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        Ok(())
    }
}
