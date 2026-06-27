use chrono::{Duration, Utc};

use crate::{
    ApiKeyEntry, AuthMode, EnvProfile, EnvVariable, PasswordEntry, Result, SecretEntry,
    SecretHubError, SecretKind, TokenEntry, TotpEntry, VaultData,
    crypto::{derive_key, encrypt_bytes, random_key, random_salt},
    envfile::{parse_env, render_env, validate_key},
    paths::HubPaths,
    store::{
        VaultFile, clear_session, decrypt_vault_data, delete_key_file, encrypt_vault_data,
        load_session, read_key_file, read_vault_file, save_session, write_key_file,
        write_vault_file,
    },
};

#[derive(Debug, Clone)]
pub struct SecretHub {
    paths: HubPaths,
}

#[derive(Debug, Clone)]
pub enum NewSecret {
    Totp {
        name: String,
        issuer: Option<String>,
        account: Option<String>,
        secret: String,
        digits: u32,
        period: u64,
        tags: Vec<String>,
        notes: Option<String>,
    },
    ApiKey {
        name: String,
        provider: Option<String>,
        key: String,
        scopes: Vec<String>,
        tags: Vec<String>,
        notes: Option<String>,
    },
    Password {
        name: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        tags: Vec<String>,
        notes: Option<String>,
    },
    Token {
        name: String,
        service: Option<String>,
        token: String,
        tags: Vec<String>,
        notes: Option<String>,
    },
    Env {
        project: String,
        profile: String,
        variables: Vec<EnvVariable>,
        tags: Vec<String>,
        notes: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct VaultStatus {
    pub initialized: bool,
    pub auth_mode: Option<&'static str>,
    pub logged_in: bool,
    pub vault_file: String,
}

impl SecretHub {
    pub fn new() -> Result<Self> {
        Ok(Self {
            paths: HubPaths::resolve()?,
        })
    }

    pub fn status(&self) -> Result<VaultStatus> {
        let initialized = self.paths.vault_file.exists();
        let auth_mode = if initialized {
            Some(match read_vault_file(&self.paths)?.auth {
                AuthMode::NoPassword { .. } => "no-password",
                AuthMode::Password { .. } => "password",
            })
        } else {
            None
        };
        let logged_in = if initialized {
            self.unlock_without_prompt().is_ok()
        } else {
            false
        };
        Ok(VaultStatus {
            initialized,
            auth_mode,
            logged_in,
            vault_file: self.paths.vault_file.display().to_string(),
        })
    }

    pub fn init_no_password(&self) -> Result<()> {
        self.init(None, 0)
    }

    pub fn init_with_password(&self, password: &str, session_minutes: i64) -> Result<()> {
        self.init(Some(password), session_minutes)
    }

    fn init(&self, password: Option<&str>, session_minutes: i64) -> Result<()> {
        if self.paths.vault_file.exists() {
            return Err(SecretHubError::VaultAlreadyExists);
        }
        self.paths.ensure_dir()?;
        let vault_key = random_key()?;
        let data = VaultData::new();
        let encrypted_data = encrypt_vault_data(&vault_key, &data)?;

        let (auth, wrapping_key) = match password {
            Some(password) => {
                let salt = random_salt()?;
                let wrapping_key = derive_key(password, &salt)?;
                (AuthMode::Password { salt }, wrapping_key)
            }
            None => {
                let wrapping_key = random_key()?;
                write_key_file(&self.paths, &wrapping_key)?;
                (
                    AuthMode::NoPassword {
                        key_file: self.paths.key_file.display().to_string(),
                    },
                    wrapping_key,
                )
            }
        };

        let wrapped_key = encrypt_bytes(&wrapping_key, &vault_key)?;
        let vault_file = VaultFile {
            version: 1,
            auth,
            wrapped_key,
            data: encrypted_data,
        };
        write_vault_file(&self.paths, &vault_file)?;
        if password.is_some() && session_minutes > 0 {
            save_session(
                &self.paths,
                &vault_key,
                Utc::now() + Duration::minutes(session_minutes),
            )?;
        }
        Ok(())
    }

    pub fn login(&self, password: &str, session_minutes: i64) -> Result<()> {
        let vault_file = read_vault_file(&self.paths)?;
        let AuthMode::Password { salt } = &vault_file.auth else {
            return Err(SecretHubError::UnsupportedAuthMode);
        };
        let wrapping_key = derive_key(password, salt)?;
        let vault_key = crate::crypto::decrypt_bytes(&wrapping_key, &vault_file.wrapped_key)?;
        let vault_key = fixed_key(vault_key)?;
        let expires_at = Utc::now() + Duration::minutes(session_minutes.max(1));
        save_session(&self.paths, &vault_key, expires_at)
    }

    pub fn logout(&self) -> Result<()> {
        clear_session(&self.paths)
    }

    pub fn set_password(&self, password: &str, session_minutes: i64) -> Result<()> {
        let (mut vault_file, vault_key) = self.load_unlocked()?;
        let salt = random_salt()?;
        let wrapping_key = derive_key(password, &salt)?;
        vault_file.auth = AuthMode::Password { salt };
        vault_file.wrapped_key = encrypt_bytes(&wrapping_key, &vault_key)?;
        write_vault_file(&self.paths, &vault_file)?;
        delete_key_file(&self.paths)?;
        if session_minutes > 0 {
            save_session(
                &self.paths,
                &vault_key,
                Utc::now() + Duration::minutes(session_minutes),
            )?;
        }
        Ok(())
    }

    pub fn remove_password(&self) -> Result<()> {
        let (mut vault_file, vault_key) = self.load_unlocked()?;
        let wrapping_key = random_key()?;
        write_key_file(&self.paths, &wrapping_key)?;
        vault_file.auth = AuthMode::NoPassword {
            key_file: self.paths.key_file.display().to_string(),
        };
        vault_file.wrapped_key = encrypt_bytes(&wrapping_key, &vault_key)?;
        write_vault_file(&self.paths, &vault_file)?;
        clear_session(&self.paths)
    }

    pub fn list(&self, kind: Option<&str>) -> Result<Vec<SecretEntry>> {
        let (_, _, data) = self.load_data()?;
        Ok(data
            .entries
            .into_iter()
            .filter(|entry| kind.is_none_or(|kind| entry.kind.label() == kind))
            .collect())
    }

    pub fn get(&self, name: &str) -> Result<SecretEntry> {
        let (_, _, data) = self.load_data()?;
        data.entries
            .into_iter()
            .find(|entry| entry.name == name || entry.id.to_string() == name)
            .ok_or_else(|| SecretHubError::SecretNotFound(name.to_string()))
    }

    pub fn add(&self, secret: NewSecret) -> Result<SecretEntry> {
        let (mut vault_file, vault_key, mut data) = self.load_data()?;
        let entry = match secret {
            NewSecret::Totp {
                name,
                issuer,
                account,
                secret,
                digits,
                period,
                tags,
                notes,
            } => SecretEntry::new(
                name,
                tags,
                notes,
                SecretKind::Totp(TotpEntry {
                    issuer,
                    account,
                    secret: crate::totp::normalize_secret(&secret),
                    digits,
                    period,
                }),
            ),
            NewSecret::ApiKey {
                name,
                provider,
                key,
                scopes,
                tags,
                notes,
            } => SecretEntry::new(
                name,
                tags,
                notes,
                SecretKind::ApiKey(ApiKeyEntry {
                    provider,
                    key,
                    scopes,
                    expires_at: None,
                }),
            ),
            NewSecret::Password {
                name,
                username,
                password,
                url,
                tags,
                notes,
            } => SecretEntry::new(
                name,
                tags,
                notes,
                SecretKind::Password(PasswordEntry {
                    username,
                    password,
                    url,
                }),
            ),
            NewSecret::Token {
                name,
                service,
                token,
                tags,
                notes,
            } => SecretEntry::new(
                name,
                tags,
                notes,
                SecretKind::Token(TokenEntry {
                    service,
                    token,
                    expires_at: None,
                }),
            ),
            NewSecret::Env {
                project,
                profile,
                variables,
                tags,
                notes,
            } => SecretEntry::new(
                env_entry_name(&project, &profile),
                tags,
                notes,
                SecretKind::Env(EnvProfile {
                    project,
                    profile,
                    variables,
                }),
            ),
        };
        data.entries.push(entry.clone());
        self.save_data(&mut vault_file, &vault_key, data)?;
        Ok(entry)
    }

    pub fn delete(&self, name: &str) -> Result<SecretEntry> {
        let (mut vault_file, vault_key, mut data) = self.load_data()?;
        let index = data
            .entries
            .iter()
            .position(|entry| entry.name == name || entry.id.to_string() == name)
            .ok_or_else(|| SecretHubError::SecretNotFound(name.to_string()))?;
        let removed = data.entries.remove(index);
        self.save_data(&mut vault_file, &vault_key, data)?;
        Ok(removed)
    }

    pub fn totp_code(&self, name: &str) -> Result<String> {
        let entry = self.get(name)?;
        let SecretKind::Totp(totp) = entry.kind else {
            return Err(SecretHubError::InvalidTotpSecret);
        };
        crate::totp::generate_code(&totp.secret, totp.digits, totp.period)
    }

    pub fn list_env_profiles(
        &self,
        project: Option<&str>,
        profile: Option<&str>,
    ) -> Result<Vec<SecretEntry>> {
        let (_, _, data) = self.load_data()?;
        Ok(data
            .entries
            .into_iter()
            .filter(|entry| match &entry.kind {
                SecretKind::Env(env) => {
                    project.is_none_or(|project| env.project == project)
                        && profile.is_none_or(|profile| env.profile == profile)
                }
                _ => false,
            })
            .collect())
    }

    pub fn import_env(
        &self,
        project: &str,
        profile: &str,
        text: &str,
        replace: bool,
    ) -> Result<SecretEntry> {
        let variables = parse_env(text)?;
        if replace {
            self.replace_env_profile(project, profile, variables)
        } else {
            self.merge_env_variables(project, profile, variables)
        }
    }

    pub fn set_env_var(
        &self,
        project: &str,
        profile: &str,
        key: &str,
        value: String,
    ) -> Result<SecretEntry> {
        validate_key(key)?;
        self.merge_env_variables(
            project,
            profile,
            vec![EnvVariable {
                key: key.to_string(),
                value,
            }],
        )
    }

    pub fn remove_env_var(&self, project: &str, profile: &str, key: &str) -> Result<SecretEntry> {
        let (mut vault_file, vault_key, mut data) = self.load_data()?;
        let index = find_env_index(&data.entries, project, profile)
            .ok_or_else(|| SecretHubError::SecretNotFound(env_entry_name(project, profile)))?;
        let SecretKind::Env(env) = &mut data.entries[index].kind else {
            unreachable!("find_env_index only returns env entries");
        };
        let before = env.variables.len();
        env.variables.retain(|variable| variable.key != key);
        if before == env.variables.len() {
            return Err(SecretHubError::SecretNotFound(key.to_string()));
        }
        data.entries[index].updated_at = Utc::now();
        let entry = data.entries[index].clone();
        self.save_data(&mut vault_file, &vault_key, data)?;
        Ok(entry)
    }

    pub fn render_env(&self, project: &str, profile: &str) -> Result<String> {
        let entry = self.get_env_profile(project, profile)?;
        let SecretKind::Env(env) = entry.kind else {
            unreachable!("get_env_profile only returns env entries");
        };
        Ok(render_env(&env))
    }

    fn get_env_profile(&self, project: &str, profile: &str) -> Result<SecretEntry> {
        let (_, _, data) = self.load_data()?;
        data.entries
            .into_iter()
            .find(|entry| match &entry.kind {
                SecretKind::Env(env) => env.project == project && env.profile == profile,
                _ => false,
            })
            .ok_or_else(|| SecretHubError::SecretNotFound(env_entry_name(project, profile)))
    }

    fn replace_env_profile(
        &self,
        project: &str,
        profile: &str,
        variables: Vec<EnvVariable>,
    ) -> Result<SecretEntry> {
        let (mut vault_file, vault_key, mut data) = self.load_data()?;
        let entry = upsert_env_entry(&mut data, project, profile, variables, true);
        self.save_data(&mut vault_file, &vault_key, data)?;
        Ok(entry)
    }

    fn merge_env_variables(
        &self,
        project: &str,
        profile: &str,
        variables: Vec<EnvVariable>,
    ) -> Result<SecretEntry> {
        let (mut vault_file, vault_key, mut data) = self.load_data()?;
        let entry = upsert_env_entry(&mut data, project, profile, variables, false);
        self.save_data(&mut vault_file, &vault_key, data)?;
        Ok(entry)
    }

    fn load_data(&self) -> Result<(VaultFile, [u8; 32], VaultData)> {
        let (vault_file, vault_key) = self.load_unlocked()?;
        let data = decrypt_vault_data(&vault_key, &vault_file.data)?;
        Ok((vault_file, vault_key, data))
    }

    fn save_data(
        &self,
        vault_file: &mut VaultFile,
        vault_key: &[u8; 32],
        mut data: VaultData,
    ) -> Result<()> {
        data.touch();
        vault_file.data = encrypt_vault_data(vault_key, &data)?;
        write_vault_file(&self.paths, vault_file)
    }

    fn load_unlocked(&self) -> Result<(VaultFile, [u8; 32])> {
        let vault_file = read_vault_file(&self.paths)?;
        let vault_key = match &vault_file.auth {
            AuthMode::NoPassword { .. } => {
                let wrapping_key = read_key_file(&self.paths)?;
                let key = crate::crypto::decrypt_bytes(&wrapping_key, &vault_file.wrapped_key)?;
                fixed_key(key)?
            }
            AuthMode::Password { .. } => {
                load_session(&self.paths)?.ok_or(SecretHubError::LoginRequired)?
            }
        };
        Ok((vault_file, vault_key))
    }

    fn unlock_without_prompt(&self) -> Result<[u8; 32]> {
        let vault_file = read_vault_file(&self.paths)?;
        match &vault_file.auth {
            AuthMode::NoPassword { .. } => {
                let wrapping_key = read_key_file(&self.paths)?;
                fixed_key(crate::crypto::decrypt_bytes(
                    &wrapping_key,
                    &vault_file.wrapped_key,
                )?)
            }
            AuthMode::Password { .. } => {
                load_session(&self.paths)?.ok_or(SecretHubError::LoginRequired)
            }
        }
    }
}

fn fixed_key(mut key: Vec<u8>) -> Result<[u8; 32]> {
    if key.len() != 32 {
        return Err(SecretHubError::Crypto);
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&key);
    key.fill(0);
    Ok(fixed)
}

fn env_entry_name(project: &str, profile: &str) -> String {
    format!("{project}/{profile}")
}

fn find_env_index(entries: &[SecretEntry], project: &str, profile: &str) -> Option<usize> {
    entries.iter().position(|entry| match &entry.kind {
        SecretKind::Env(env) => env.project == project && env.profile == profile,
        _ => false,
    })
}

fn upsert_env_entry(
    data: &mut VaultData,
    project: &str,
    profile: &str,
    variables: Vec<EnvVariable>,
    replace: bool,
) -> SecretEntry {
    if let Some(index) = find_env_index(&data.entries, project, profile) {
        let SecretKind::Env(env) = &mut data.entries[index].kind else {
            unreachable!("find_env_index only returns env entries");
        };
        if replace {
            env.variables = variables;
        } else {
            for variable in variables {
                if let Some(existing) = env
                    .variables
                    .iter_mut()
                    .find(|existing| existing.key == variable.key)
                {
                    existing.value = variable.value;
                } else {
                    env.variables.push(variable);
                }
            }
        }
        data.entries[index].updated_at = Utc::now();
        data.entries[index].clone()
    } else {
        let entry = SecretEntry::new(
            env_entry_name(project, profile),
            vec!["env".to_string()],
            None,
            SecretKind::Env(EnvProfile {
                project: project.to_string(),
                profile: profile.to_string(),
                variables,
            }),
        );
        data.entries.push(entry.clone());
        entry
    }
}
