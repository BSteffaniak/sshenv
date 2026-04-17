//! Discover SSH private keys on the local machine and load them as
//! `age::Identity` objects suitable for unwrapping vault recipients.

use std::fs;
use std::io::{Cursor, IsTerminal};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, anyhow};

/// Discover SSH private-key file paths in the conventional locations.
///
/// Returns the union of:
///
/// - `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` (when present)
/// - `~/.ssh/*` files that have a matching `.pub` sibling
/// - `IdentityFile` entries from `~/.ssh/config`
#[must_use]
pub fn discover_private_key_paths() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    let Some(home) = dirs::home_dir() else {
        return out;
    };
    let ssh_dir = home.join(".ssh");

    for name in &["id_ed25519", "id_rsa"] {
        let p = ssh_dir.join(name);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }

    if let Ok(entries) = fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let pub_path = entry.path();
            let Some(ext) = pub_path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("pub") {
                continue;
            }
            let priv_path = pub_path.with_extension("");
            if priv_path.is_file() && !out.contains(&priv_path) {
                out.push(priv_path);
            }
        }
    }

    for cfg_identity in parse_identity_files_from_ssh_config() {
        if cfg_identity.is_file() && !out.contains(&cfg_identity) {
            out.push(cfg_identity);
        }
    }

    out
}

/// Discover SSH public-key file paths in the conventional locations.
///
/// The returned list is ordered: well-known keys (`id_ed25519.pub`,
/// `id_rsa.pub`) first in that order, then every other `*.pub` in
/// `~/.ssh/` that has a matching private-key sibling, sorted
/// alphabetically, then `<IdentityFile>.pub` entries from `~/.ssh/config`
/// that exist on disk.
///
/// Duplicates are removed while preserving first occurrence.
#[must_use]
pub fn discover_public_key_paths() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    let Some(home) = dirs::home_dir() else {
        return out;
    };
    let ssh_dir = home.join(".ssh");

    // Well-known first, in deterministic order.
    for name in &["id_ed25519.pub", "id_rsa.pub"] {
        let p = ssh_dir.join(name);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }

    // Everything else alphabetically.
    let mut extras: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let pub_path = entry.path();
            let Some(ext) = pub_path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("pub") {
                continue;
            }
            // Require a matching private key sibling so we don't surface
            // random .pub files that have no corresponding identity.
            let priv_path = pub_path.with_extension("");
            if !priv_path.is_file() {
                continue;
            }
            if out.contains(&pub_path) {
                continue;
            }
            extras.push(pub_path);
        }
    }
    extras.sort();
    for p in extras {
        if !out.contains(&p) {
            out.push(p);
        }
    }

    // IdentityFile entries: derive .pub path and keep if present.
    for cfg_identity in parse_identity_files_from_ssh_config() {
        let pub_path = cfg_identity.with_extension("pub");
        if pub_path.is_file() && !out.contains(&pub_path) {
            out.push(pub_path);
        }
    }

    out
}

/// Load all discoverable private keys as `age` identities.
///
/// For unencrypted keys, loading is silent. For encrypted keys, we prompt
/// interactively for a passphrase (up to 3 attempts) **only** if stdin is
/// a TTY. Otherwise encrypted keys are skipped.
///
/// # Errors
///
/// Returns an error if a key file exists but cannot be read.
pub fn load_identities() -> Result<Vec<Box<dyn age::Identity>>> {
    let paths = discover_private_key_paths();
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();

    for path in &paths {
        match try_load_identity(path) {
            Ok(Some(id)) => identities.push(id),
            Ok(None) => {
                eprintln!("note: skipping encrypted SSH key {}", path.display());
            }
            Err(err) => {
                eprintln!("note: could not parse SSH key {}: {err}", path.display());
            }
        }
    }

    Ok(identities)
}

fn try_load_identity(path: &Path) -> Result<Option<Box<dyn age::Identity>>> {
    let content = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let filename = Some(path.display().to_string());
    let identity = age::ssh::Identity::from_buffer(Cursor::new(&content), filename)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    match identity {
        age::ssh::Identity::Unencrypted(_) | age::ssh::Identity::Unsupported(_) => {
            Ok(Some(Box::new(identity)))
        }
        age::ssh::Identity::Encrypted(ref enc) => {
            let Some(decrypted) = maybe_decrypt_interactively(enc, path) else {
                return Ok(None);
            };
            Ok(Some(Box::new(decrypted)))
        }
    }
}

fn maybe_decrypt_interactively(
    enc: &age::ssh::EncryptedKey,
    path: &Path,
) -> Option<age::ssh::Identity> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let max_attempts = 3;
    for attempt in 1..=max_attempts {
        let prompt = format!(
            "Enter passphrase for {} (attempt {attempt}/{max_attempts}): ",
            path.display()
        );
        let raw = rpassword::prompt_password(prompt).ok()?;
        let passphrase = SecretString::from(raw);
        if let Ok(unenc) = enc.decrypt(passphrase) {
            return Some(age::ssh::Identity::from(unenc));
        }
        eprintln!("incorrect passphrase");
    }
    None
}

fn parse_identity_files_from_ssh_config() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    let cfg_path = home.join(".ssh").join("config");
    let Ok(text) = fs::read_to_string(&cfg_path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.len() <= 12 {
            continue;
        }
        if !trimmed[..12].eq_ignore_ascii_case("identityfile") {
            continue;
        }
        let value = trimmed[12..].trim_start_matches(|c: char| c == '=' || c.is_whitespace());
        if value.is_empty() {
            continue;
        }
        let expanded = if let Some(rest) = value.strip_prefix("~/") {
            home.join(rest)
        } else if value == "~" {
            home.clone()
        } else {
            PathBuf::from(value)
        };
        out.push(expanded);
    }
    out
}

/// Describe the configured identity for `doctor`. Does not load or
/// decrypt any keys.
#[must_use]
pub fn describe_available_identities() -> Vec<String> {
    discover_private_key_paths()
        .into_iter()
        .map(|p| p.display().to_string())
        .collect()
}

/// Return an error suitable for printing when no identity could unlock
/// the vault.
pub fn error_no_identity_unlocked() -> anyhow::Error {
    let paths = describe_available_identities();
    if paths.is_empty() {
        anyhow!(
            "no SSH private keys found in ~/.ssh/ and none configured in ~/.ssh/config.\n\
             Add one and re-run, or authorize a new recipient on a machine that can decrypt."
        )
    } else {
        anyhow!(
            "none of the following SSH keys could unwrap any vault recipient:\n  {}\n\
             Is this host a known recipient? If not, run `sshenv add-recipient --key <pubkey>` \
             on a machine that can decrypt, then copy the updated vault here.",
            paths.join("\n  "),
        )
    }
}
