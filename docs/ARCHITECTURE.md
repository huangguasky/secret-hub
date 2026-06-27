# Architecture

## Product Scope

Secret Hub should manage four related secret types:

- TOTP entries: issuer, account name, algorithm, digits, period, and encrypted seed.
- API keys: provider, key name, secret value, scopes, expiry, rotation metadata.
- Account passwords: service, username, password, URL, notes, tags.
- Developer `.env` values: project profiles, environment variables, comments, and generated `.env` output.

The first version should be local-first. Sync can be added later, but the storage
format should be versioned from day one so migrations are possible.

## Workspace Layout

Use a Rust workspace with separate crates for core logic, CLI, and Tauri commands:

```text
secret-hub/
  crates/
    secret-hub-core/      # crypto, domain model, repository traits, services
    secret-hub-cli/       # clap commands
  apps/
    desktop/              # Tauri + Vue + TypeScript
      src-tauri/          # Rust Tauri shell, depends on secret-hub-core
      src/                # Vue UI
```

Keep secret handling in `secret-hub-core`; both CLI and desktop should call the
same service layer. That avoids security behavior drifting between interfaces.

## Core Modules

- `model`: typed entities such as `SecretEntry`, `TotpEntry`, `ApiKeyEntry`,
  `PasswordEntry`, `EnvProfile`, `EnvVariable`.
- `crypto`: key derivation, authenticated encryption, nonce generation,
  encrypted envelope versioning, zeroization helpers.
- `storage`: database schema, migrations, repository implementations.
- `vault`: lock/unlock lifecycle, master key handling, CRUD orchestration.
- `totp`: otpauth URI import/export and current-code generation.
- `envfile`: `.env` parser/renderer and conflict-safe export logic.
- `audit`: local event log for create/update/delete/read/export operations.

## Security Model

Recommended baseline:

- Derive a key-encryption key from the master password using Argon2id.
- Generate a random data-encryption key for the vault.
- Encrypt the data-encryption key with the derived key.
- Encrypt each secret value with AEAD, such as XChaCha20-Poly1305 or AES-GCM.
- Store non-secret metadata separately where it improves search UX, but treat
  names, URLs, and tags as potentially sensitive and allow stricter encrypted
  metadata mode later.
- Use unique nonces per encrypted field and version every encrypted envelope.
- Keep decrypted values in memory for the shortest practical lifetime and use
  `secrecy`/`zeroize` for sensitive buffers.
- Require explicit confirmation before copying, exporting, revealing, or
  writing `.env` files.

A practical v1 storage choice is SQLite plus encrypted fields. Full-database
encryption can be added later with SQLCipher if packaging and licensing choices
fit the project.

The current CLI MVP stores a single encrypted JSON vault in the user config
directory. Secret data is encrypted with a random vault key. In no-password mode,
a local key file unwraps that vault key automatically. In password mode, Argon2id
derives the unwrap key from the login password, and successful login writes a
time-limited local session file.

## Suggested Rust Crates

- CLI: `clap`, `clap_complete`
- Serialization: `serde`, `serde_json`
- Errors/logging: `thiserror`, `anyhow` at app edges, `tracing`
- Storage: `rusqlite` or `sqlx`, plus migrations
- Crypto: `argon2`, `chacha20poly1305`, `rand_core`, `secrecy`, `zeroize`
- TOTP: `totp-rs` or a small wrapper around `hmac` + `sha1`/`sha2`
- Clipboard: CLI optional via `arboard`; desktop via Tauri clipboard plugin
- OS keychain optional unlock helper: `keyring`

## CLI Shape

```text
secret-hub vault init
secret-hub vault unlock
secret-hub add password
secret-hub add api-key
secret-hub add totp
secret-hub totp code <name>
secret-hub get <name> --copy
secret-hub env set <project> <KEY>
secret-hub env render <project> --profile dev --out .env
secret-hub import otpauth <file>
secret-hub export --format encrypted-json
```

## Desktop Shape

The Tauri app should expose narrow commands instead of database access:

- `unlock_vault`
- `lock_vault`
- `list_entries`
- `get_entry_detail`
- `create_entry`
- `update_entry`
- `delete_entry`
- `generate_totp_code`
- `render_env_profile`
- `copy_secret`

The Vue UI can start with views for Vault, TOTP, Passwords/API Keys, Env
Profiles, and Settings. Avoid showing raw secret values by default.

## MVP Milestones

1. Rust workspace and core domain model.
2. Encrypted local vault initialization and unlock.
3. CLI CRUD for password/API key entries.
4. TOTP import and code generation.
5. `.env` profile storage and render-to-file.
6. Tauri desktop shell using the same core service.
7. Backup/export, restore, and migration tests.
