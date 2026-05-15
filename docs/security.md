# Security details

See [`../SECURITY.md`](../SECURITY.md) for the short version and the
reporting contact.

## Full threat model

### What `sshenv` protects against

1. **Disk snapshot / stolen backup.** The vault file is encrypted. Without
   access to an SSH private key listed as a recipient, the body and values
   cannot be recovered.
2. **Leakage via shell history.** `sshenv set <profile> <VAR>` prompts for
   the value on a hidden stdin; it does not accept the value as an
   argument unless you explicitly pass `--value`, and even then
   non-interactive wrappers can skip that path entirely.
3. **Leakage via parent shell environment.** `sshenv run` uses `execve`
   semantics: the env is built for the child only. The parent shell's env
   is unmodified. By default, `run` writes non-secret session metadata
   before `execve`; use `--incognito` to skip that registry entry.
4. **Plaintext leftovers.** No temp files are written containing any
   plaintext secret. `sshenv edit` is intentionally not provided in v1 to
   avoid introducing such a temp file.
5. **Runtime dumps.** Default CLI builds disable core dumps before `run`
   decrypts and injects secrets; Linux builds also request non-dumpable
   process state where supported.
6. **Tamper detection.** AES-256-SIV with AAD-bound headers ensures that
   a modified vault body fails to decrypt.

### What `sshenv` does not protect against

1. **Root on the machine.** Root can read the SSH key, hijack the agent,
   `ptrace` sshenv, read `/dev/mem`. Nothing stops this.
2. **A compromised ssh-agent.** Possession of the agent is, by design, the
   unlock factor.
3. **A compromised SSH private key.** Same.
4. **Memory-forensic attacks against a running process.** `zeroize`
   scrubs known buffers on clean drops, and runtime hardening reduces common
   dump paths, but a sufficiently privileged hostile memory dump captures
   anything live.
5. **A user who runs `sshenv show <profile>` in a terminal that logs
   output.** Output hits stdout; what happens next is the user's
   responsibility. A stderr warning is printed before values.
6. **Shoulder-surfing over the user's terminal.** Same.

## Format migration summary

v1 remains the stable compatibility format. v2 is only written through an
explicit migration command and adds policy metadata plus recipient public
metadata. That metadata is non-secret and exists so future policy factors and
rekey operations can preserve the intended recipient set safely.

## Crypto summary

- **Recipient wrapping**: `age 0.11.1` with the `ssh` feature. The
  wrapped blob is a full `age`-encrypted message; any holder of the
  corresponding SSH private key can decrypt via `age::Decryptor`.
- **Body encryption**: `aes-siv 0.7` (AES-256-SIV) with versioned AAD
  (`"sshenv:v1:payload"` or `"sshenv:v2:payload"`). Deterministic; rejects
  tampering; immune to nonce-reuse because it derives a synthetic IV internally.
- **Key derivation**: `hkdf 0.12` over `sha2 0.10`, salt
  `"sshenv:v1"`, info `"payload"`. Expands 32 input bytes to the 64
  bytes AES-256-SIV wants. For opt-in passphrase-protected v2 vaults, an
  additional HKDF step binds the SSH-unwrapped data key to an Argon2id-derived
  passphrase factor before payload encryption/decryption.
- **Passphrase factor**: `argon2 0.5` using Argon2id. This is an opt-in v2
  factor; it requires both an authorized SSH recipient and the passphrase.
- **Device-seal factor**: optional v2 factor plumbing. The macOS Keychain
  backend stores a random factor in Keychain. The local-file backend is for
  development/testing only and is not theft-resistant.
- **RNG for data key**: `OsRng` at `init` time.

## Recipient semantics

A recipient is an SSH public key line (`ssh-ed25519 AAA...` or
`ssh-rsa AAA...`). Supported key types match `age`'s ssh feature:
`ssh-ed25519` and `ssh-rsa`.

The fingerprint we display and key by is `SHA256:<base64>` of the
public key blob, matching `ssh-keygen -lf`.

Each recipient gets an independent wrapped copy of the same 32-byte
data key. Removing a recipient deletes their wrapped copy. **Past
decrypts they performed are not revoked** — the data key has not
changed. To revoke past access, rotate the data key (planned).

## Per-profile encryption and policy metadata

v2 vaults can store profiles as independently encrypted profile entries. The
outer vault payload is still encrypted by the vault payload key, and each
profile entry also has its own random profile key and ciphertext. Use
`sshenv security profile-policy rotate-key <profile>` to rotate one profile's
data key without rotating other unchanged profile entries.

Profile policies can also record explicit factor requirements. Use
`profile-policy status <profile>` to inspect the effective profile posture,
including whether requirements are profile-specific cryptographic bindings,
vault-level factors, or missing.

```sh
sshenv security profile-policy status <profile>
sshenv security profile-policy require-passphrase <profile> [--passphrase <v>]
sshenv security profile-policy change-passphrase <profile> [--old-passphrase <v>] [--new-passphrase <v>]
sshenv security profile-policy disable-passphrase <profile> [--passphrase <v>]
sshenv security profile-policy require-device-seal <profile>
sshenv security profile-policy disable-device-seal <profile>
sshenv security profile-policy clear-requirements <profile>
```

These requirements are opt-in. `require-passphrase` creates per-profile
passphrase metadata and binds the selected profile's inner ciphertext to that
profile factor when the policy is saved. `change-passphrase` rotates that
profile-specific factor, and `disable-passphrase` re-encrypts the profile
without it. `require-device-seal` similarly binds only the selected profile to
the configured device-seal backend; `disable-device-seal` removes that binding.
Commands that only need one profile (`show`, `export`, and `run`) lazily decrypt
the selected profile, so normal profiles do not need the profile passphrase. For
non-interactive use, provide `SSHENV_PROFILE_PASSPHRASE`.

v2 vaults can also store encrypted advisory policy metadata for individual
profiles. Preset metadata is not yet a cryptographic boundary by itself.
Commands that set this metadata print that limitation explicitly.

## Rollback protection considerations

When compiled with rollback protection, sshenv records the highest v2 vault
generation seen for each local vault path in `~/.sshenv/rollback.toml` (or
`$SSHENV_ROLLBACK`). This detects an older valid vault copy being restored on
the same machine. The state is plaintext and contains only vault path identity
and generation numbers. It is local best-effort protection, not a TPM-backed or
remote monotonic counter.

## Session registry security considerations

The session registry (`~/.sshenv/sessions.toml`, or `$SSHENV_SESSIONS`) is
plaintext local state used only for listing and signaling tracked `run`
executions. It contains profile names, vault path, PID, a process-start
identity token, timestamp, and command name. It never contains env var
names or values.

`sshenv sessions kill` verifies the PID still has the recorded
process-start token before signaling it, so a stale record should not kill
an unrelated process after PID reuse. Records that cannot be verified are
garbage-collected or skipped rather than signaled.

## Shim security considerations

Shims are `sh` scripts in `~/.sshenv/bin/`. They:

- are marked `0755` (not secret; they only contain profile/command
  names),
- embed `profile: X` and `command: Y` header comments so `shims sync`
  can detect out-of-sync shims,
- use `exec sshenv run "<profile>" -- "<command>" "$@"` (no `eval`,
  no untrusted expansion),
- shadow the real command on PATH by virtue of `~/.sshenv/bin` being
  first; if a user needs the real command, they can `command -p
<name>` or `/absolute/path/to/<name>`.

## Permissions enforcement

On every vault write, after `rename(2)` we `chmod 0600`. On every
bindings-file write, we `chmod 0644`. On every sessions-file write, we
`chmod 0600`.

If the vault file exists but has unexpected permissions, `sshenv
doctor` warns; we do not refuse to operate because the user may have
intentionally relaxed perms on a local-only setup. (This may become
stricter in a future version.)
