# Security model

sshenv is early-alpha, security-sensitive software. This document describes intended boundaries, not an independent security certification.

## Protection and assumptions

The encrypted vault protects secret values in a copied vault file when the attacker lacks the authorized private key and any configured additional factors. A backup containing both the vault and an unencrypted authorized private key does not satisfy that assumption.

The default identity loader reads private-key files. An SSH key available only in `ssh-agent` is not the default unlock mechanism. Optional plugin/hardware recipients have separate setup requirements.

`sshenv run` supplies a profile to the executed command without modifying its parent shell. It does not protect against a compromised endpoint, privileged attacker, malicious child program, inherited child environments, debugger, terminal recording, or intentional disclosure through `show`/`export`.

## Secret handling

- Vault writes are encrypted and use Unix owner-only permissions or Windows current-user ACL handling.
- Shims, bindings, session records, and rollback baselines contain non-secret metadata, not secret values.
- Long-lived data keys and decrypted payloads use dedicated page-aligned locked buffers where supported; short-lived secret values use zeroizing wrappers. These reduce exposure but cannot promise that every intermediate copy is locked or that crash-time memory is erased.
- Default CLI builds apply OS-specific runtime hardening before secret injection. Executing another program can change process protections; do not assume Linux non-dumpable state or locked memory persists across `exec`.
- sshenv does not intentionally create plaintext secret temp files. `show`, `export`, shell redirection, child programs, and OS memory behavior are outside any “no plaintext on disk” guarantee.

## Formats and optional features

New vaults use v1. Explicit migration enables v2 metadata, generation tracking, and additional factor support; do not reinterpret v1 files as v2.

Payloads use authenticated AES-256-SIV with versioned associated data and derived keys. SSH-recipient wrapping uses Switchy Age. Configured v2 passphrase factors use Argon2id. Optional device, remote, and recovery features must be built and configured explicitly. The local-file device-seal backend is for development/testing, not theft resistance.

Advisory policy metadata alone does not enforce a cryptographic boundary. Use the actual factor-enforcement commands and inspect effective status.

## Rollback detection

The default CLI's rollback feature records the highest observed **v2** generation for each local vault path. It can reject an older vault against that baseline. v1 has no generation, new machines/paths have no prior baseline, and an attacker able to replace both the vault and trusted state can evade local detection. Optional synchronized/command-backed state needs its own trust model.

The reusable vault store does not automatically perform the CLI's local-baseline tracking. Embedded callers must explicitly provide their own rollback policy and runtime-hardening lifecycle.

## Recipients and recovery

Removing a recipient removes its current wrapped-key entry. `rotate-key` is implemented and enabled in default CLI builds; use it when changing access policy. Rotation protects newly encrypted state, not plaintext or historical ciphertext/key material already retained by a former recipient.

Shamir sharing is an optional feature. Treat recovery shares as sensitive key material, store them separately, and test recovery without exposing live secrets. Threshold metadata and cryptographic share recovery are distinct concepts.

See [security details](docs/security.md) for implementation details and [architecture](docs/architecture.md) for ownership boundaries.

## Reporting

Report privately at <https://github.com/BSteffaniak/sshenv/security/advisories/new> or email [bradensteffaniak@gmail.com](mailto:bradensteffaniak@gmail.com) if private reporting is unavailable. Include versions and a synthetic reproduction, not production keys, vaults, or secret values. No response-time or supported-version guarantee is implied.
