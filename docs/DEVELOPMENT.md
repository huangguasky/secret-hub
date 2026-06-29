# Development Environment

## Current Machine Status

Checked on Windows PowerShell:

- Node.js: installed, `node --version` returned `v22.14.0`.
- npm: installed, `npm.cmd --version` returned `10.9.2`.
- Rust: installed with rustup during setup; current shell verified:
  - `rustc 1.96.0`
  - `cargo 1.96.0`
- PowerShell blocks `npm.ps1`, so use `npm.cmd` or relax the PowerShell
  execution policy intentionally.
- `winget` was not found.
- MSVC `cl.exe` was not found.
- WebView2 was not detected from the registry check used here.

After opening a new terminal, Cargo should be on PATH automatically. If not,
temporarily run:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
```

## Required Tooling

Minimum:

- Git
- Rust stable via rustup
- Node.js LTS/current with npm
- Visual Studio Build Tools 2022 with the C++ desktop workload for Windows
- Xcode Command Line Tools for macOS
- Microsoft Edge WebView2 Runtime for the Windows Tauri desktop app

Recommended:

- VS Code or RustRover
- `rustfmt` and `clippy`
- `cargo-audit`
- `cargo-deny`
- `cargo-nextest`

## Windows Setup Notes

Tauri on Windows needs the Microsoft C++ toolchain. Install Visual Studio Build
Tools 2022 and select:

- Desktop development with C++
- MSVC v143 build tools
- Windows 10/11 SDK
- C++ CMake tools for Windows

Install the WebView2 Runtime if it is not already present:

https://developer.microsoft.com/microsoft-edge/webview2/

## macOS Setup Notes

For CLI development on macOS:

```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo test --workspace
cargo build --release -p shub
./target/release/shub status
```

For Tauri desktop development on macOS, install Node.js as well. Distribution
outside local development will eventually need Apple code signing and
notarization.

## npm on This Machine

Because PowerShell blocks `npm.ps1`, prefer:

```powershell
npm.cmd --version
npm.cmd create vite@latest
```

Alternatively, if you decide to change the current user's execution policy:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## First Project Commands

Once the repository is scaffolded:

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm.cmd install
npm.cmd run dev
```

For Tauri development, prefer a project-local Tauri CLI through npm scripts
rather than requiring a global install.

## Local CLI Testing

Use `SECRET_HUB_HOME` to test without touching your real vault:

```powershell
$env:SECRET_HUB_HOME = "C:\tmp\secret-hub-dev"
cargo run -p shub -- init
cargo run -p shub -- status
cargo run -p shub -- totp github
```

To install the CLI locally from this repository:

```powershell
cargo install --path crates/secret-hub-cli
shub status
```

## Release Build

Build the standalone CLI executable:

```powershell
cargo build --release -p shub
```

The Windows artifact is:

```text
target\release\shub.exe
```

The release workflow builds:

- `shub-windows-x64.zip`
- `shub-linux-x64.tar.gz`
- `shub-macos-universal.tar.gz`

The macOS archive contains a universal `shub` binary for both Intel and Apple
Silicon Macs. The intended end-user command is always `shub`.
