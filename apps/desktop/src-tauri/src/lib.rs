use secret_hub_core::{
    EditSecret, EnvSecretRefKind, EnvValue, EnvVariable, NewSecret, SecretEntry, SecretHub,
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

struct AppState {
    hub: Mutex<SecretHub>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopStatus {
    initialized: bool,
    auth_mode: Option<String>,
    logged_in: bool,
    vault_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddSecretRequest {
    kind: String,
    name: String,
    issuer: Option<String>,
    account: Option<String>,
    secret: Option<String>,
    digits: Option<u32>,
    period: Option<u64>,
    provider: Option<String>,
    key: Option<String>,
    scopes: Option<Vec<String>>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    service: Option<String>,
    token: Option<String>,
    tags: Option<Vec<String>>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditSecretRequest {
    kind: String,
    name: String,
    issuer: Option<String>,
    account: Option<String>,
    secret: Option<String>,
    digits: Option<u32>,
    period: Option<u64>,
    provider: Option<String>,
    key: Option<String>,
    scopes: Option<Vec<String>>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    service: Option<String>,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvSetRequest {
    project: String,
    profile: String,
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvRefRequest {
    project: String,
    profile: String,
    key: String,
    ref_kind: String,
    secret_name: String,
}

type CommandResult<T> = Result<T, String>;

#[tauri::command]
fn vault_status(state: tauri::State<'_, AppState>) -> CommandResult<DesktopStatus> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    let status = hub.status().map_err(error_message)?;
    Ok(DesktopStatus {
        initialized: status.initialized,
        auth_mode: status.auth_mode.map(str::to_string),
        logged_in: status.logged_in,
        vault_file: status.vault_file,
    })
}

#[tauri::command]
fn init_vault(
    state: tauri::State<'_, AppState>,
    password: Option<String>,
    session_minutes: Option<i64>,
) -> CommandResult<()> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    match password {
        Some(password) if !password.is_empty() => hub
            .init_with_password(&password, session_minutes.unwrap_or(30))
            .map_err(error_message),
        _ => hub.init_no_password().map_err(error_message),
    }
}

#[tauri::command]
fn login_vault(
    state: tauri::State<'_, AppState>,
    password: String,
    session_minutes: Option<i64>,
) -> CommandResult<()> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.login(&password, session_minutes.unwrap_or(30))
        .map_err(error_message)
}

#[tauri::command]
fn logout_vault(state: tauri::State<'_, AppState>) -> CommandResult<()> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.logout().map_err(error_message)
}

#[tauri::command]
fn list_entries(
    state: tauri::State<'_, AppState>,
    kind: Option<String>,
) -> CommandResult<Vec<SecretEntry>> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.list(kind.as_deref()).map_err(error_message)
}

#[tauri::command]
fn get_entries(
    state: tauri::State<'_, AppState>,
    name: String,
    kind: Option<String>,
) -> CommandResult<Vec<SecretEntry>> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.get(&name, kind.as_deref()).map_err(error_message)
}

#[tauri::command]
fn add_entry(
    state: tauri::State<'_, AppState>,
    request: AddSecretRequest,
) -> CommandResult<SecretEntry> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.add(request.into_new_secret()?).map_err(error_message)
}

#[tauri::command]
fn edit_entry(
    state: tauri::State<'_, AppState>,
    request: EditSecretRequest,
) -> CommandResult<SecretEntry> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    let name = request.name.clone();
    hub.edit(&name, request.into_edit_secret()?)
        .map_err(error_message)
}

#[tauri::command]
fn delete_entry(
    state: tauri::State<'_, AppState>,
    name: String,
    kind: String,
) -> CommandResult<SecretEntry> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.delete(&name, &kind).map_err(error_message)
}

#[tauri::command]
fn generate_totp_code(state: tauri::State<'_, AppState>, name: String) -> CommandResult<String> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.totp_code(&name).map_err(error_message)
}

#[tauri::command]
fn set_env_value(
    state: tauri::State<'_, AppState>,
    request: EnvSetRequest,
) -> CommandResult<SecretEntry> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.set_env_var(
        &request.project,
        &request.profile,
        &request.key,
        request.value,
    )
    .map_err(error_message)
}

#[tauri::command]
fn set_env_ref(
    state: tauri::State<'_, AppState>,
    request: EnvRefRequest,
) -> CommandResult<SecretEntry> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.set_env_secret_ref(
        &request.project,
        &request.profile,
        &request.key,
        parse_env_ref_kind(&request.ref_kind)?,
        request.secret_name,
    )
    .map_err(error_message)
}

#[tauri::command]
fn remove_env_value(
    state: tauri::State<'_, AppState>,
    project: String,
    profile: String,
    key: String,
) -> CommandResult<SecretEntry> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.remove_env_var(&project, &profile, &key)
        .map_err(error_message)
}

#[tauri::command]
fn render_env_profile(
    state: tauri::State<'_, AppState>,
    project: String,
    profile: String,
) -> CommandResult<String> {
    let hub = state
        .hub
        .lock()
        .map_err(|_| "vault state is busy".to_string())?;
    hub.render_env(&project, &profile).map_err(error_message)
}

impl AddSecretRequest {
    fn into_new_secret(self) -> CommandResult<NewSecret> {
        let tags = self.tags.unwrap_or_default();
        match self.kind.as_str() {
            "totp" => Ok(NewSecret::Totp {
                name: self.name,
                issuer: self.issuer,
                account: self.account,
                secret: required(self.secret, "secret")?,
                digits: self.digits.unwrap_or(6),
                period: self.period.unwrap_or(30),
                tags,
                notes: self.notes,
            }),
            "api-key" => Ok(NewSecret::ApiKey {
                name: self.name,
                provider: self.provider,
                key: required(self.key, "key")?,
                scopes: self.scopes.unwrap_or_default(),
                tags,
                notes: self.notes,
            }),
            "password" => Ok(NewSecret::Password {
                name: self.name,
                username: self.username,
                password: required(self.password, "password")?,
                url: self.url,
                tags,
                notes: self.notes,
            }),
            "token" => Ok(NewSecret::Token {
                name: self.name,
                service: self.service,
                token: required(self.token, "token")?,
                tags,
                notes: self.notes,
            }),
            "env" => Ok(NewSecret::Env {
                project: self.name,
                profile: self.account.unwrap_or_else(|| "default".to_string()),
                variables: vec![EnvVariable {
                    key: required(self.key, "key")?,
                    value: EnvValue::literal(required(self.secret, "value")?),
                }],
                tags,
                notes: self.notes,
            }),
            _ => Err(format!("unsupported secret type: {}", self.kind)),
        }
    }
}

impl EditSecretRequest {
    fn into_edit_secret(self) -> CommandResult<EditSecret> {
        match self.kind.as_str() {
            "totp" => Ok(EditSecret::Totp {
                issuer: self.issuer,
                account: self.account,
                secret: self.secret,
                digits: self.digits,
                period: self.period,
            }),
            "api-key" => Ok(EditSecret::ApiKey {
                provider: self.provider,
                key: self.key,
                scopes: self.scopes,
            }),
            "password" => Ok(EditSecret::Password {
                username: self.username,
                password: self.password,
                url: self.url,
            }),
            "token" => Ok(EditSecret::Token {
                service: self.service,
                token: self.token,
            }),
            _ => Err(format!("unsupported editable secret type: {}", self.kind)),
        }
    }
}

fn required(value: Option<String>, field: &str) -> CommandResult<String> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{field} is required"))
}

fn parse_env_ref_kind(kind: &str) -> CommandResult<EnvSecretRefKind> {
    match kind {
        "api-key" => Ok(EnvSecretRefKind::ApiKey),
        "token" => Ok(EnvSecretRefKind::Token),
        _ => Err(format!("unsupported env reference type: {kind}")),
    }
}

fn error_message(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub fn run() {
    let hub = SecretHub::new().expect("failed to resolve Secret Hub paths");
    tauri::Builder::default()
        .manage(AppState {
            hub: Mutex::new(hub),
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            init_vault,
            login_vault,
            logout_vault,
            list_entries,
            get_entries,
            add_entry,
            edit_entry,
            delete_entry,
            generate_totp_code,
            set_env_value,
            set_env_ref,
            remove_env_value,
            render_env_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running Secret Hub desktop");
}
