# sshenv

SSH-key-backed encrypted vault for environment variables. Inject secrets into
commands on demand, unlock via the SSH key already in your `ssh-agent`, keep
zero plaintext on disk.

## Why

You have API tokens, AWS bearer tokens, database URLs, and other secrets that
tools want in environment variables. You don't want them in your shell rc.
You don't want them in your shell history. You don't want them scattered in
`.env` files. You don't want a keychain daemon or a cloud subscription.

What you _do_ have on every dev machine is an SSH key in a running
`ssh-agent`. `sshenv` uses that key as the unlock factor for a single
encrypted vault file.

## How it works

- One encrypted file at `~/.sshenv/vault` (override with `$SSHENV_VAULT`).
- Recipients are SSH public keys. The vault's data key is wrapped to each
  recipient using [`age`](https://github.com/FiloSottile/age)'s SSH support.
- Body is `{ profile: { VAR: value } }`, encrypted with AES-256-SIV using the
  data key; the format version is bound via AAD.
- To unlock: any SSH private key matching an authorized recipient
  (discovered from `~/.ssh/`, passphrase-prompted interactively if
  encrypted).
- To run a command with a profile's env loaded, `sshenv run <profile> --
<cmd> [args...]`. The command's env gets the profile's vars; your parent
  shell never sees them.
- To make invocation ergonomic, `sshenv shims bind <profile> --command <name>`
  writes a shim script at `~/.sshenv/bin/<name>` that execs
  `sshenv run <profile> -- <name> "$@"`. Add `~/.sshenv/bin` to the front of
  your `PATH`; then typing `pi-bedrock` (or whatever) transparently loads
  secrets before running.

## Quick start

```sh
# One-time setup on a new machine
sshenv init --recipient-key ~/.ssh/id_ed25519.pub
sshenv set pi-bedrock AWS_BEARER_TOKEN_BEDROCK    # prompts hidden
sshenv set pi-openai  OPENAI_API_KEY
sshenv shims bind pi-bedrock --command pi-bedrock
sshenv shims bind pi-openai  --command pi-openai

# Add to your shell rc (once)
export PATH="$HOME/.sshenv/bin:$PATH"

# Use — the shim injects the right secrets before exec'ing the real command
pi-bedrock
pi-openai
```

## Commands

```
# Vault lifecycle
sshenv init [--recipient-key <path-or-pubkey-line>] [--vault <path>]
sshenv doctor

# Recipients
sshenv add-recipient --key <path-or-pubkey-line>
sshenv list-recipients [--verbose]
sshenv remove-recipient --fingerprint <fp>

# Profiles
sshenv set <profile> <VAR> [--value <v>]          # hidden prompt if --value omitted
sshenv unset <profile> <VAR>
sshenv list [--prefix <p>]                         # profile names
sshenv list <profile>                              # VAR names in profile
sshenv show <profile>                              # values (warns loudly)
sshenv rename-profile <old> <new>                  # rename profile + shim bindings
sshenv rm-profile <profile>

# Execution
sshenv run <profile> -- <command> [args...]
sshenv export <profile>                            # prints `export VAR=value` lines

# Shims (auto-sync after bind/unbind)
sshenv shims bind <profile> --command <name>
sshenv shims unbind --command <name>
sshenv shims list
sshenv shims sync
sshenv shims dir
sshenv shims path
```

Environment variables: `SSHENV_VAULT`, `SSHENV_SHIM_DIR`, `SSHENV_BINDINGS`.

## Status

Early alpha (`0.0.1-alpha.0`). CLI surface is expected to be stable; vault
file format is versioned and upgrades will be explicit.

## Security model

See [`SECURITY.md`](SECURITY.md) and [`docs/security.md`](docs/security.md).

## Comparison

|                         | `envchain`         | `op run`                     | `sshenv`                       |
| ----------------------- | ------------------ | ---------------------------- | ------------------------------ |
| Backing store           | OS keychain        | 1Password vault              | Encrypted file, SSH recipients |
| Auth factor             | Keychain unlock    | 1Password unlock (biometric) | SSH key in `ssh-agent`         |
| Cross-host sync         | None               | Automatic (cloud)            | Copy the ciphertext file       |
| Cost                    | Free               | Subscription                 | Free                           |
| Secrets on disk         | No (in keyring DB) | No                           | Ciphertext only                |
| Works non-interactively | Yes                | Yes                          | Yes                            |

## License

MPL-2.0. See [`LICENSE`](LICENSE).
