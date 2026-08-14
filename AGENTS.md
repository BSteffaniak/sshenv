# Agent / contributor notes

This repository is a Cargo workspace. Crates live under `packages/`.

## Layout

```
packages/
  cli/              sshenv binary
  cli/models/       CLI argument & error types
  vault/            vault file format I/O + crypto
  vault/models/     vault data structures (serde types)
  shims/            shim script generation, bindings file I/O
  shims/models/     binding data structures
```

## Build / test

- `cargo build`
- `cargo test --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo fmt --all`
- `cargo deny check` (if `cargo-deny` is installed)

## Conventions

- Edition 2024.
- Lints: `clippy::all`, `pedantic`, `nursery`, `cargo` as warn; `clippy::multiple_crate_versions` allowed at workspace level.
- Error handling: `anyhow` in the CLI crate for chained context; `thiserror` in library crates for typed errors.
- Secret types: wrap raw bytes or `String` in `Zeroizing` from the `zeroize` crate when they hold plaintext secret material. Long-lived vault data keys and decrypted payloads use the vault crate's dedicated page-aligned locked secret buffers; short-lived derived scratch keys remain `Zeroizing`.
- **Never** write secret values to disk outside the encrypted vault.

## Vault format versioning

Magic + version bytes at the head. Breaking changes require a new version
byte plus explicit migration code. Do not mutate the `v1` format.
