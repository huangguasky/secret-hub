use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};
use secret_hub_core::{EditSecret, EnvSecretRefKind, EnvValue, NewSecret, SecretHub, SecretKind};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "shub")]
#[command(about = "Local-first secret manager for developers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        password: bool,
        #[arg(long, default_value_t = 30)]
        session_minutes: i64,
    },
    Login {
        #[arg(long, default_value_t = 30)]
        session_minutes: i64,
    },
    Logout,
    Status,
    SetPassword {
        #[arg(long, default_value_t = 30)]
        session_minutes: i64,
    },
    RemovePassword,
    Add {
        #[command(subcommand)]
        command: AddCommand,
    },
    Edit {
        #[command(subcommand)]
        command: EditCommand,
    },
    List {
        #[arg(long)]
        kind: Option<EntryKind>,
    },
    Get {
        first: String,
        second: Option<String>,
        #[arg(long)]
        kind: Option<EntryKind>,
        #[arg(long)]
        reveal: bool,
    },
    Delete {
        kind: EntryKind,
        name: String,
    },
    Totp(TotpArgs),
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AddCommand {
    Totp {
        name: String,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        account: Option<String>,
        #[arg(long, default_value_t = 6)]
        digits: u32,
        #[arg(long, default_value_t = 30)]
        period: u64,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    ApiKey {
        name: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    Password {
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    Token {
        name: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        service: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum EditCommand {
    Totp {
        name: String,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        digits: Option<u32>,
        #[arg(long)]
        period: Option<u64>,
    },
    ApiKey {
        name: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
    },
    Password {
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    Token {
        name: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        service: Option<String>,
    },
}

#[derive(Debug, Args)]
struct TotpArgs {
    name: Option<String>,
    #[arg(long)]
    copy: bool,
    #[command(subcommand)]
    command: Option<TotpCommand>,
}

#[derive(Debug, Subcommand)]
enum TotpCommand {
    Code {
        name: String,
        #[arg(long)]
        copy: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EnvCommand {
    Import {
        project: String,
        file: PathBuf,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        replace: bool,
    },
    Set {
        project: String,
        key: String,
        #[arg(long)]
        value: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    SetRef {
        project: String,
        key: String,
        secret_name: String,
        #[arg(long)]
        kind: EnvRefKind,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    Remove {
        project: String,
        key: String,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    Render {
        project: String,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum EntryKind {
    Totp,
    ApiKey,
    Password,
    Token,
    Env,
}

#[derive(Debug, Clone, ValueEnum)]
enum EnvRefKind {
    ApiKey,
    Token,
}

impl From<EnvRefKind> for EnvSecretRefKind {
    fn from(value: EnvRefKind) -> Self {
        match value {
            EnvRefKind::ApiKey => Self::ApiKey,
            EnvRefKind::Token => Self::Token,
        }
    }
}

impl EntryKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::ApiKey => "api-key",
            Self::Password => "password",
            Self::Token => "token",
            Self::Env => "env",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "totp" => Some(Self::Totp),
            "api-key" | "api_key" | "apikey" => Some(Self::ApiKey),
            "password" => Some(Self::Password),
            "token" => Some(Self::Token),
            "env" => Some(Self::Env),
            _ => None,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let hub = SecretHub::new()?;

    match cli.command {
        Command::Init {
            password,
            session_minutes,
        } => {
            if password {
                let password = prompt_new_password()?;
                hub.init_with_password(&password, session_minutes)?;
                println!("vault initialized with login password");
            } else {
                hub.init_no_password()?;
                println!("vault initialized without login password");
            }
        }
        Command::Login { session_minutes } => {
            let password = rpassword::prompt_password("Password: ")?;
            hub.login(&password, session_minutes)?;
            println!("logged in for {session_minutes} minute(s)");
        }
        Command::Logout => {
            hub.logout()?;
            println!("logged out");
        }
        Command::Status => {
            let status = hub.status()?;
            println!("initialized: {}", status.initialized);
            println!("auth mode: {}", status.auth_mode.unwrap_or("none"));
            println!("logged in: {}", status.logged_in);
            println!("vault: {}", status.vault_file);
        }
        Command::SetPassword { session_minutes } => {
            let password = prompt_new_password()?;
            hub.set_password(&password, session_minutes)?;
            println!("login password enabled");
        }
        Command::RemovePassword => {
            hub.remove_password()?;
            println!("login password removed");
        }
        Command::Add { command } => {
            let entry = add_secret(&hub, command)?;
            println!("added {} {}", entry.kind.label(), entry.name);
        }
        Command::Edit { command } => {
            let entry = edit_secret(&hub, command)?;
            println!("edited {} {}", entry.kind.label(), entry.name);
        }
        Command::List { kind } => {
            let entries = hub.list(kind.as_ref().map(EntryKind::as_str))?;
            for entry in entries {
                println!("{}\t{}\t{}", entry.id, entry.kind.label(), entry.name);
            }
        }
        Command::Get {
            first,
            second,
            kind,
            reveal,
        } => {
            let (name, kind) = resolve_get_args(first, second, kind)?;
            let entries = hub.get(&name, kind.as_ref().map(EntryKind::as_str))?;
            for (index, entry) in entries.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                print_entry(entry, reveal);
            }
        }
        Command::Delete { kind, name } => {
            let entry = hub.delete(&name, kind.as_str())?;
            println!("deleted {} {}", entry.kind.label(), entry.name);
        }
        Command::Totp(args) => run_totp_command(&hub, args)?,
        Command::Env { command } => run_env_command(&hub, command)?,
    }

    Ok(())
}

fn edit_secret(hub: &SecretHub, command: EditCommand) -> Result<secret_hub_core::SecretEntry> {
    let (name, edit) = match command {
        EditCommand::Totp {
            name,
            secret,
            issuer,
            account,
            digits,
            period,
        } => (
            name,
            EditSecret::Totp {
                issuer,
                account,
                secret,
                digits,
                period,
            },
        ),
        EditCommand::ApiKey {
            name,
            key,
            provider,
            scopes,
        } => (
            name,
            EditSecret::ApiKey {
                provider,
                key,
                scopes: if scopes.is_empty() {
                    None
                } else {
                    Some(scopes)
                },
            },
        ),
        EditCommand::Password {
            name,
            username,
            password,
            url,
        } => (
            name,
            EditSecret::Password {
                username,
                password,
                url,
            },
        ),
        EditCommand::Token {
            name,
            token,
            service,
        } => (name, EditSecret::Token { service, token }),
    };
    hub.edit(&name, edit).map_err(Into::into)
}

fn run_totp_command(hub: &SecretHub, args: TotpArgs) -> Result<()> {
    let (name, copy) = match args.command {
        Some(TotpCommand::Code { name, copy }) => (name, copy || args.copy),
        None => {
            let name = args
                .name
                .ok_or_else(|| anyhow!("missing TOTP name; usage: shub totp <name>"))?;
            (name, args.copy)
        }
    };
    let code = hub.totp_code(&name)?;
    if copy {
        copy_to_clipboard(&code)?;
        println!("copied TOTP code for {name}");
    } else {
        println!("{code}");
    }
    Ok(())
}

fn copy_to_clipboard(value: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().with_context(|| "failed to open clipboard")?;
    clipboard
        .set_text(value.to_string())
        .with_context(|| "failed to copy to clipboard")
}

fn resolve_get_args(
    first: String,
    second: Option<String>,
    kind: Option<EntryKind>,
) -> Result<(String, Option<EntryKind>)> {
    match (second, kind) {
        (Some(name), None) => {
            let kind =
                EntryKind::parse(&first).ok_or_else(|| anyhow!("unknown secret type: {first}"))?;
            Ok((name, Some(kind)))
        }
        (Some(_), Some(_)) => Err(anyhow!(
            "pass either `shub get <type> <name>` or `shub get <name> --kind <type>`, not both"
        )),
        (None, kind) => Ok((first, kind)),
    }
}

fn add_secret(hub: &SecretHub, command: AddCommand) -> Result<secret_hub_core::SecretEntry> {
    let secret = match command {
        AddCommand::Totp {
            name,
            secret,
            issuer,
            account,
            digits,
            period,
            tags,
            notes,
        } => NewSecret::Totp {
            name,
            issuer,
            account,
            secret: secret.unwrap_or_else_prompt("TOTP secret: ")?,
            digits,
            period,
            tags,
            notes,
        },
        AddCommand::ApiKey {
            name,
            key,
            provider,
            scopes,
            tags,
            notes,
        } => NewSecret::ApiKey {
            name,
            provider,
            key: key.unwrap_or_else_prompt("API key: ")?,
            scopes,
            tags,
            notes,
        },
        AddCommand::Password {
            name,
            username,
            password,
            url,
            tags,
            notes,
        } => NewSecret::Password {
            name,
            username,
            password: password.unwrap_or_else_prompt("Account password: ")?,
            url,
            tags,
            notes,
        },
        AddCommand::Token {
            name,
            token,
            service,
            tags,
            notes,
        } => NewSecret::Token {
            name,
            service,
            token: token.unwrap_or_else_prompt("Token: ")?,
            tags,
            notes,
        },
    };
    hub.add(secret).map_err(Into::into)
}

fn print_entry(entry: &secret_hub_core::SecretEntry, reveal: bool) {
    println!("id: {}", entry.id);
    println!("name: {}", entry.name);
    println!("kind: {}", entry.kind.label());
    if !entry.tags.is_empty() {
        println!("tags: {}", entry.tags.join(","));
    }
    if let Some(notes) = &entry.notes {
        println!("notes: {notes}");
    }

    match &entry.kind {
        SecretKind::Totp(totp) => {
            println!("issuer: {}", totp.issuer.as_deref().unwrap_or(""));
            println!("account: {}", totp.account.as_deref().unwrap_or(""));
            println!("digits: {}", totp.digits);
            println!("period: {}", totp.period);
            println!("secret: {}", reveal_value(&totp.secret, reveal));
        }
        SecretKind::ApiKey(api_key) => {
            println!("provider: {}", api_key.provider.as_deref().unwrap_or(""));
            println!("scopes: {}", api_key.scopes.join(","));
            println!("key: {}", reveal_value(&api_key.key, reveal));
        }
        SecretKind::Password(password) => {
            println!("username: {}", password.username.as_deref().unwrap_or(""));
            println!("url: {}", password.url.as_deref().unwrap_or(""));
            println!("password: {}", reveal_value(&password.password, reveal));
        }
        SecretKind::Token(token) => {
            println!("service: {}", token.service.as_deref().unwrap_or(""));
            println!("token: {}", reveal_value(&token.token, reveal));
        }
        SecretKind::Env(env) => {
            println!("project: {}", env.project);
            println!("profile: {}", env.profile);
            println!("variables: {}", env.variables.len());
            for variable in &env.variables {
                println!(
                    "{}={}",
                    variable.key,
                    env_value_display(&variable.value, reveal)
                );
            }
        }
    }
}

fn run_env_command(hub: &SecretHub, command: EnvCommand) -> Result<()> {
    match command {
        EnvCommand::Import {
            project,
            file,
            profile,
            replace,
        } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read {}", file.display()))?;
            let entry = hub.import_env(&project, &profile, &text, replace)?;
            let SecretKind::Env(env) = entry.kind else {
                unreachable!("import_env always returns env entries");
            };
            println!(
                "imported {} variable(s) into {}/{}",
                env.variables.len(),
                env.project,
                env.profile
            );
        }
        EnvCommand::Set {
            project,
            key,
            value,
            profile,
        } => {
            let value = value.unwrap_or_else_prompt("Value: ")?;
            hub.set_env_var(&project, &profile, &key, value)?;
            println!("set {key} in {project}/{profile}");
        }
        EnvCommand::SetRef {
            project,
            key,
            secret_name,
            kind,
            profile,
        } => {
            let ref_kind = EnvSecretRefKind::from(kind);
            hub.set_env_secret_ref(&project, &profile, &key, ref_kind, secret_name.clone())?;
            println!(
                "set {key} in {project}/{profile} as ref:{}:{secret_name}",
                ref_kind.label()
            );
        }
        EnvCommand::Remove {
            project,
            key,
            profile,
        } => {
            hub.remove_env_var(&project, &profile, &key)?;
            println!("removed {key} from {project}/{profile}");
        }
        EnvCommand::List {
            project,
            profile,
            reveal,
        } => {
            let entries = hub.list_env_profiles(project.as_deref(), profile.as_deref())?;
            for entry in entries {
                let SecretKind::Env(env) = entry.kind else {
                    continue;
                };
                println!(
                    "{}\t{}\t{} variable(s)",
                    env.project,
                    env.profile,
                    env.variables.len()
                );
                if reveal {
                    for variable in env.variables {
                        println!(
                            "  {}={}",
                            variable.key,
                            env_value_display(&variable.value, true)
                        );
                    }
                } else {
                    for variable in env.variables {
                        println!(
                            "  {}={}",
                            variable.key,
                            env_value_display(&variable.value, false)
                        );
                    }
                }
            }
        }
        EnvCommand::Render {
            project,
            profile,
            out,
            force,
        } => {
            let rendered = hub.render_env(&project, &profile)?;
            if let Some(out) = out {
                if out.exists() && !force {
                    return Err(anyhow!(
                        "{} already exists; pass --force to overwrite",
                        out.display()
                    ));
                }
                std::fs::write(&out, rendered)
                    .with_context(|| format!("failed to write {}", out.display()))?;
                println!("rendered {project}/{profile} to {}", out.display());
            } else {
                print!("{rendered}");
            }
        }
    }
    Ok(())
}

fn reveal_value(value: &str, reveal: bool) -> String {
    if reveal {
        value.to_string()
    } else if value.is_empty() {
        String::new()
    } else {
        "********".to_string()
    }
}

fn env_value_display(value: &EnvValue, reveal: bool) -> String {
    match value {
        EnvValue::Literal { value } => reveal_value(value, reveal),
        EnvValue::SecretRef { kind, name } => format!("<ref:{}:{}>", kind.label(), name),
    }
}

fn prompt_new_password() -> Result<String> {
    let password = rpassword::prompt_password("New password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err(anyhow!("passwords do not match"));
    }
    if password.is_empty() {
        return Err(anyhow!("password cannot be empty"));
    }
    Ok(password)
}

trait PromptOption {
    fn unwrap_or_else_prompt(self, prompt: &str) -> Result<String>;
}

impl PromptOption for Option<String> {
    fn unwrap_or_else_prompt(self, prompt: &str) -> Result<String> {
        match self {
            Some(value) => Ok(value),
            None => rpassword::prompt_password(prompt).with_context(|| "failed to read secret"),
        }
    }
}
