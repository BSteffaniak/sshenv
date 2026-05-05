# Architecture

`sshenv` is built as a small Cargo workspace. The runtime model is
straightforward: one encrypted vault file, one bindings file, a
collection of PATH shims.

## Data model

### The vault (`~/.sshenv/vault`)

A single file containing everything secret:

- A list of **recipients** (SSH public keys authorized to decrypt).
- For each recipient, an `age`-wrapped copy of the 32-byte **data key**.
- A single **encrypted payload** containing all profiles and values,
  encrypted with that data key.

The payload uses AES-256-SIV with an AAD tag `"sshenv:v1:payload"`. The
same key is used for every write; the SIV mode tolerates deterministic
encryption and rejects ciphertext tampering. Integrity binding to the
tag prevents a downgrade attack that swaps in an older vault's body.

Key derivation: `HKDF-SHA-256(repo_key, salt=b"sshenv:v1", info=b"payload")`
produces the 512-bit AES-256-SIV key.

See [`security.md`](security.md) for threat model and crypto choices.

### Bindings (`~/.sshenv/bindings.toml`)

Local per-host plaintext state. A list of profile/command pairs. Not
secret. Not synced by vault copy. Used to regenerate shim scripts.

### Shims (`~/.sshenv/bin/<command>`)

Tiny `sh` scripts, one per bound command. Each shim execs
`sshenv run <profile> -- <command>`. Put `~/.sshenv/bin` at the front of
`$PATH` and shim-bound commands transparently get their secrets.

### Sessions (`~/.sshenv/sessions.toml`)

Local per-host plaintext orchestration state for tracked `sshenv run`
executions. Records contain profile name, vault path, PID,
platform-specific process-start token, start timestamp, and command name.
They do not contain secret values. `sshenv run --incognito ...` skips this
registry.

## Flows

### `sshenv init --recipient-key KEY`

1. Read SSH public key line.
2. Generate a 32-byte data key via `OsRng`.
3. Wrap the data key for the supplied recipient using `age::Encryptor`
   with an `age::ssh::Recipient`.
4. Encrypt an empty `ProfileMap` with AES-256-SIV using the derived key.
5. Write the vault file at `0600`.

### `sshenv add-recipient --key KEY`

1. Unwrap the existing data key using the current SSH identity (via
   `ssh-agent` or an on-disk key).
2. Re-wrap the **same** data key for the new recipient.
3. Append a new recipient entry to the vault. Payload ciphertext
   unchanged.

This means anyone who ever held a wrapped copy of the data key retains
the ability to decrypt — classic asymmetric recipient model. Rotation
(changing the data key) is a planned follow-up.

### `sshenv set PROFILE VAR`

1. Unwrap data key.
2. Decrypt payload → `ProfileMap`.
3. Insert `profiles[PROFILE][VAR] = value`.
4. Encrypt payload under the same data key.
5. Atomic rename the vault file (write temp, `rename(2)`).

### `sshenv run PROFILE -- CMD ARGS...`

1. Unwrap data key.
2. Decrypt payload.
3. Collect env vars for `PROFILE`.
4. Unless `--incognito` was passed, record the current PID plus a
   platform-specific process-start token in `sessions.toml`.
5. `execve(cmd, argv, env)` — the child replaces the sshenv process while
   keeping the same PID. Parent shell never saw the secret.

### `sshenv sessions list [--profile PROFILE]`

1. Lock and load `sessions.toml`.
2. Drop stale records whose PID no longer matches the recorded
   process-start token.
3. Print live records for the current vault, optionally filtered by
   profile.

### `sshenv sessions kill PROFILE`

1. Lock and load `sessions.toml`.
2. Drop stale records whose PID no longer matches the recorded
   process-start token.
3. For records matching the current vault and profile, re-verify the PID
   still has the recorded process-start token.
4. Send the requested signal (`TERM` by default).

This targets the tracked top-level exec PID only. If a command daemonizes,
forks workers, or otherwise leaves descendants after that PID exits, those
processes are not tracked by the v1 session registry.

### `sshenv shims bind PROFILE --command CMD`

1. Load `bindings.toml` (or start empty).
2. Reject if `CMD` is already bound to a different profile.
3. Append binding.
4. Save `bindings.toml`.
5. Run `shims sync`: regenerate every shim file from the full bindings.

## Crate responsibilities

- `vault_models`: byte-level structs (`VaultHeader`, `RecipientEntry`),
  `ProfileMap` JSON shape, serde derives. No I/O.
- `vault`: disk I/O (read/write with perms), crypto (wrap/unwrap via
  `age`, AEAD via `aes-siv`), recipient operations. No CLI concerns.
- `shims_models`: `Binding` + `BindingsFile` types. Serde for TOML.
- `shims`: bindings file I/O, shim script generation, collision checks.
- `cli_models`: command/arg enums for clap, shared error type.
- `cli`: wires everything into a binary, handles user I/O (prompts,
  stdout/stderr), resolves paths from env vars, runs child processes.

## Non-goals for v1

- No cache daemon. Every `sshenv run` re-unwraps the data key.
- No GitHub recipient fetching (easy to add later; the `age` + ssh-key
  plumbing already supports it).
- No value reference templates (`op://…`).
- No bulk `sshenv edit` with `$EDITOR` + tempfile.
- No data key rotation (recipient removal alone does not revoke past
  access).
