# sshenv

**An SSH-key-backed encrypted vault that supplies secrets to commands without modifying the parent shell's environment.**

Store environment-variable profiles in an encrypted file, unlock with an authorized SSH private key, and run an application with only the selected profile injected. Optional shims make repeated commands convenient; the vault library can also be embedded in Rust applications.

> **Early alpha, security-sensitive software.** Read the [security model](SECURITY.md) before relying on it. Features and file formats are versioned, but this is not a claim of an independent security audit.

## Install

For the published CLI (check [crates.io](https://crates.io/crates/sshenv) for available versions):

```sh
cargo install sshenv --version 0.0.1-alpha.3 --locked
```

For the current repository version:

```sh
git clone https://github.com/BSteffaniak/sshenv.git
cd sshenv
cargo install --locked --path packages/cli
```

Use stable Rust and a native build toolchain. Published packages can lag `master`; use `sshenv --version` when reporting an issue. GitHub release automation defines binary targets, but that does not guarantee downloadable release artifacts exist.

## Quick start

You need a supported SSH key pair (`ssh-ed25519` or `ssh-rsa`) and access to its **private-key file**. An identity loaded only in `ssh-agent` is not sufficient for the default loader. Encrypted private keys prompt interactively for their passphrase.

```sh
sshenv init --recipient-key ~/.ssh/id_ed25519.pub
sshenv set development API_TOKEN             # hidden value prompt
sshenv run development -- your-command       # replace with an installed command
sshenv doctor
```

The default vault is `~/.sshenv/vault`; override it with `--vault` or `SSHENV_VAULT`. Never put real secret values in command-line arguments for convenience.

New vaults use **v1**. To opt into v2 generation tracking and additional factor capabilities:

```sh
sshenv migrate-vault --to v2 --recipient-key ~/.ssh/id_ed25519.pub
sshenv security status
```

Keep a recoverable encrypted backup and authorized key before changing recipients or factors. Local rollback protection rejects older v2 generations only when a newer baseline is available; it is not automatic protection against an attacker replacing both vault and local state.

### Optional command shims

```sh
sshenv shims bind development --command your-command
# Add once to your shell configuration:
export PATH="$HOME/.sshenv/bin:$PATH"
```

Replace `your-command` with an executable already installed on the machine. The generated shim contains command/profile names, not secret values. On Windows shims are `.cmd` files; add the shim directory to `PATH` using Windows configuration tools.

## Capabilities and feature boundaries

| Capability                                     | Scope                                                                                                           |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Encrypted profiles and SSH recipients          | Base CLI/library functionality                                                                                  |
| Key rotation, passphrase factors, profile keys | Enabled in the default CLI build; factors still require configuration                                           |
| Generation-based rollback checks               | Default CLI feature, v2 vaults, recorded local baseline                                                         |
| Core-dump/process hardening                    | Default CLI feature; OS-specific and not a child-program security boundary                                      |
| Shamir recovery                                | Optional `shamir-sharing` Cargo feature                                                                         |
| Device seals                                   | Optional platform features such as `macos-keychain`, `linux-secret-service`, `tpm-device-seal`, `windows-dpapi` |
| External/hardware factors                      | Optional adapters with their own setup and trust requirements                                                   |

For example, enable recovery in a source installation with:

```sh
cargo install --locked --path packages/cli --features shamir-sharing
```

Do not use `--all-features` as a recommended security preset: some features exist for testing or external adapters. Advisory policy metadata alone is not a cryptographic access boundary.

## Common operations

```text
sshenv run <profile> -- <command> [args...]
sshenv set <profile> <VAR>
sshenv show <profile>
sshenv export <profile>
sshenv add-recipient --key <public-key-path-or-line>
sshenv remove-recipient --fingerprint <fingerprint>
sshenv rotate-key --recipient-key <public-key-path-or-line>
sshenv security status
sshenv sessions list
```

Use `sshenv --help` and each subcommand's `--help` as the complete CLI reference. `show` and `export` deliberately reveal secrets; avoid redirected output, terminal recording, and shell `eval` unless you intend that exposure.

## Platform behavior

- **Linux/macOS:** `run` uses exec semantics. The parent shell remains unchanged; the executed program and its children can read or disclose injected values.
- **Windows:** `run` spawns and waits for the child. Session signaling supports termination rather than Unix `INT`/`HUP` semantics.
- **Private files:** Unix writes use owner-only permissions; Windows uses current-user ACL handling.
- **Hardening:** supported memory locking and process protections reduce exposure in sshenv itself. They do not guarantee all decrypted copies or subsequently executed programs remain locked or non-dumpable.

## Embed in Rust

[`sshenv_vault`](packages/vault) exposes `SshenvStore` with caller-selected paths and private-key identities. It does not require CLI shims or global paths. The CLI's rollback-baseline tracking and runtime-hardening setup are **not automatically inherited** by every library caller.

See [architecture](docs/architecture.md), [security details](docs/security.md), and [migration](docs/migration.md). Cryptography uses AES-256-SIV for payloads, SSH-recipient wrapping through Switchy Age, and Argon2id for configured passphrase factors. Long-lived key/payload buffers use dedicated locked storage where supported; short-lived secret values use zeroizing wrappers.

## Development

```sh
cargo fmt --all
cargo build --locked
cargo test --all --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

Use [GitHub Issues](https://github.com/BSteffaniak/sshenv/issues) for non-sensitive bugs. Report vulnerabilities through the private contact in [SECURITY.md](SECURITY.md), never with real credentials or vault contents in a public issue.

## License

[Mozilla Public License 2.0](LICENSE).
