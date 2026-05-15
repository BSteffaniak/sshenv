# Security model

## Threat model

**In scope:**

1. An attacker reads arbitrary files in your home directory (e.g. stolen
   backup, stolen laptop disk image). They must not be able to recover any
   secret values from the vault file alone.
2. A sibling process running as your user reads your shell environment or
   `/proc/<pid>/environ`. Secrets must not appear in the parent shell.
3. A committer of this code is incentivized to avoid footguns that cause
   plaintext secrets to leak to disk (e.g. swap, tempfiles, coredumps).

**Out of scope:**

1. Root on the machine. Nothing protects you from root, and this tool does
   not try to.
2. A compromised SSH private key or compromised `ssh-agent`. Possession of
   the private key (or the running agent) is the unlock factor, by design.
3. Coldboot / memory-forensic attacks against a running process. `zeroize`
   helps on clean exits; hostile dumps bypass it.
4. Physical-access shoulder-surfing of `sshenv show`. Use `sshenv run`
   instead.

## How secrets live

- **At rest**: inside `~/.sshenv/vault`, never plaintext. File permissions
  are enforced to `0600` on every write.
- **In transit to processes**: only as environment variables of the exact
  child process spawned by `sshenv run`. The parent shell does not inherit
  them; no temp file is ever written.
- **In memory**: wrapped in `Zeroizing` where practical. Drops scrub the
  memory. Heap reallocation during processing is the usual Rust caveat.

## Vault file format

Binary, versioned. v1 is stable and immutable:

```
MAGIC       "SSHE"          (4 bytes)
VERSION     0x01            (1 byte)
FLAGS       0x00            (1 byte, reserved)
RECIP_LEN   u32 BE          (4 bytes)
RECIPIENTS  (variable)      array of { fp_len u16 BE, fp utf8, wrap_len u32 BE, wrap bytes }
PAYLOAD_LEN u32 BE          (4 bytes)
PAYLOAD     (variable)      AES-256-SIV ciphertext, AAD = "sshenv:v1:payload"
```

v2 is an explicit migration target for policy metadata and stores recipient
public descriptors so future data-key rotation can preserve recipient sets
without asking for every public key again. v2 payload AAD is
`"sshenv:v2:payload"`.

Plaintext payload is JSON: `{ "profiles": { "<name>": { "<VAR>": "<value>" } } }`.

The 32-byte data key is generated at `init` time with a CSPRNG and wrapped
per recipient via `age`'s SSH support. Each recipient's wrapped blob is a
complete `age`-encrypted message; any holder of the corresponding SSH
private key (via `ssh-agent` or an on-disk identity) can unwrap.

## Crypto choices

- **AES-256-SIV** for the payload. Deterministic (no per-write nonce
  state), authenticated, with AAD binding to the vault version tag. Keyed
  via `HKDF-SHA-256` over the 32-byte data key with a static salt and
  info string.
- **`age`** with `ssh-ed25519` and `ssh-rsa` recipients for key wrapping.
- **Argon2id passphrase factor** for opt-in v2 vaults. When enabled, the
  payload encryption key is derived from both the SSH-unwrapped data key and
  the passphrase-derived factor key, so either factor alone is insufficient.
- **CSPRNG** (`OsRng` via `rand_core`) for the data key at `init` time.

## Recipient management

Adding a recipient re-wraps the existing data key for the new SSH public
key without changing the body ciphertext. Removing a recipient deletes
their wrapped blob; prior copies of the ciphertext they've seen remain
readable if they retained their wrapped key. **Rotate the data key** after
removing recipients if past access is a concern (planned; not in v1).

## Bindings and shims

`~/.sshenv/bindings.toml` is **plaintext**. It contains profile/command
name pairs, which are non-secret. The shim scripts it generates are also
plaintext. Neither file contains any secret values.

## Reporting

Open a private security advisory at
<https://github.com/BSteffaniak/sshenv/security/advisories/new>.
