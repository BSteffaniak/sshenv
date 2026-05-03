//! SSH identity discovery and loading for vault unlock operations.
//!
//! These helpers are library-safe: callers can either use conventional
//! `~/.ssh` discovery or pass explicit private-key paths for embedded app
//! integrations that manage their own paths.

use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, IsTerminal};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, anyhow};

use crate::recipient::fingerprint_from_line;

/// Discover SSH private-key file paths in the conventional locations.
///
/// Returns the list in a deterministic order:
///
/// 1. `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` (when present)
/// 2. Every other `~/.ssh/*` with a `.pub` sibling, sorted alphabetically
/// 3. `IdentityFile` entries from `~/.ssh/config` (file order)
///
/// Duplicates are preserved at their first occurrence.
#[must_use]
pub fn discover_private_key_paths() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    let ssh_dir = home.join(".ssh");
    let mut out = discover_private_key_paths_in(&ssh_dir);

    for cfg_identity in parse_identity_files_from_ssh_config_in(&home) {
        if cfg_identity.is_file() && !out.contains(&cfg_identity) {
            out.push(cfg_identity);
        }
    }

    out
}

/// Test-friendly/private variant of [`discover_private_key_paths`] that
/// takes an explicit SSH directory. Skips the `~/.ssh/config` lookup.
#[must_use]
pub fn discover_private_key_paths_in(ssh_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    for name in &["id_ed25519", "id_rsa"] {
        let path = ssh_dir.join(name);
        if path.is_file() && !out.contains(&path) {
            out.push(path);
        }
    }

    let mut extras: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(ssh_dir) {
        for entry in entries.flatten() {
            let pub_path = entry.path();
            let Some(ext) = pub_path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("pub") {
                continue;
            }
            let priv_path = pub_path.with_extension("");
            if priv_path.is_file() && !out.contains(&priv_path) {
                extras.push(priv_path);
            }
        }
    }
    extras.sort();
    for path in extras {
        if !out.contains(&path) {
            out.push(path);
        }
    }

    out
}

/// Discover SSH public-key file paths in the conventional locations.
#[must_use]
pub fn discover_public_key_paths() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    let Some(home) = dirs::home_dir() else {
        return out;
    };
    let ssh_dir = home.join(".ssh");

    for name in &["id_ed25519.pub", "id_rsa.pub"] {
        let path = ssh_dir.join(name);
        if path.is_file() && !out.contains(&path) {
            out.push(path);
        }
    }

    let mut extras: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let pub_path = entry.path();
            let Some(ext) = pub_path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("pub") {
                continue;
            }
            let priv_path = pub_path.with_extension("");
            if !priv_path.is_file() || out.contains(&pub_path) {
                continue;
            }
            extras.push(pub_path);
        }
    }
    extras.sort();
    for path in extras {
        if !out.contains(&path) {
            out.push(path);
        }
    }

    for cfg_identity in parse_identity_files_from_ssh_config_in(&home) {
        let pub_path = append_pub_extension(&cfg_identity);
        if pub_path.is_file() && !out.contains(&pub_path) {
            out.push(pub_path);
        }
    }

    out
}

/// Given the path to a private SSH key, return the fingerprint of its
/// `<path>.pub` sibling if present and parseable.
#[must_use]
pub fn public_fingerprint_for_private_key(priv_path: &Path) -> Option<String> {
    let pub_path = append_pub_extension(priv_path);
    let content = fs::read_to_string(&pub_path).ok()?;
    let line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))?;
    fingerprint_from_line(line).ok()
}

fn append_pub_extension(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".pub");
    PathBuf::from(value)
}

/// Load all discoverable private keys as `age` identities, without any
/// vault-recipient filter.
///
/// # Errors
///
/// Never returns `Err` under normal conditions; per-key failures are logged
/// to stderr and skipped.
pub fn load_identities() -> Result<Vec<Box<dyn age::Identity>>> {
    load_identities_from_paths(&discover_private_key_paths())
}

/// Load private keys from explicit paths as `age` identities.
///
/// # Errors
///
/// Never returns `Err` under normal conditions; per-key failures are logged
/// to stderr and skipped.
pub fn load_identities_from_paths(paths: &[PathBuf]) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();

    for path in paths {
        match try_load_identity(path) {
            Ok(Some(identity)) => identities.push(identity),
            Ok(None) => {
                eprintln!("note: skipping encrypted SSH key {}", path.display());
            }
            Err(error) => {
                eprintln!("note: could not parse SSH key {}: {error}", path.display());
            }
        }
    }

    Ok(identities)
}

/// Load only conventional SSH private keys whose `.pub` fingerprint appears
/// in `recipient_fingerprints`.
///
/// # Errors
///
/// Never returns `Err` under normal conditions.
pub fn load_identities_for_vault(
    recipient_fingerprints: &HashSet<String>,
) -> Result<Vec<Box<dyn age::Identity>>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(Vec::new());
    };
    let ssh_dir = home.join(".ssh");
    let mut out = load_identities_for_vault_in(&ssh_dir, recipient_fingerprints)?;

    for priv_path in parse_identity_files_from_ssh_config_in(&home) {
        if !priv_path.is_file() {
            continue;
        }
        try_load_matching(&priv_path, recipient_fingerprints, &mut out);
    }

    Ok(out)
}

/// Load only explicit SSH private keys whose `.pub` fingerprint appears in
/// `recipient_fingerprints`.
///
/// # Errors
///
/// Never returns `Err` under normal conditions.
pub fn load_identities_for_vault_from_paths(
    private_key_paths: &[PathBuf],
    recipient_fingerprints: &HashSet<String>,
) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut out: Vec<Box<dyn age::Identity>> = Vec::new();
    for path in private_key_paths {
        try_load_matching(path, recipient_fingerprints, &mut out);
    }
    Ok(out)
}

/// Test-friendly variant of [`load_identities_for_vault`] that takes an
/// explicit SSH directory and ignores `~/.ssh/config`.
///
/// # Errors
///
/// Never returns `Err` under normal conditions.
pub fn load_identities_for_vault_in(
    ssh_dir: &Path,
    recipient_fingerprints: &HashSet<String>,
) -> Result<Vec<Box<dyn age::Identity>>> {
    let paths = discover_private_key_paths_in(ssh_dir);
    load_identities_for_vault_from_paths(&paths, recipient_fingerprints)
}

fn try_load_matching(
    priv_path: &Path,
    recipient_fingerprints: &HashSet<String>,
    sink: &mut Vec<Box<dyn age::Identity>>,
) {
    match public_fingerprint_for_private_key(priv_path) {
        Some(fingerprint) => {
            if !recipient_fingerprints.contains(&fingerprint) {
                return;
            }
            match try_load_identity(priv_path) {
                Ok(Some(identity)) => sink.push(identity),
                Ok(None) => {
                    eprintln!("note: skipping encrypted SSH key {}", priv_path.display());
                }
                Err(error) => {
                    eprintln!(
                        "note: could not parse SSH key {}: {error}",
                        priv_path.display()
                    );
                }
            }
        }
        None => match try_load_identity(priv_path) {
            Ok(Some(identity)) => sink.push(identity),
            Ok(None) | Err(_) => {}
        },
    }
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
        age::ssh::Identity::Encrypted(ref encrypted) => {
            let Some(decrypted) = maybe_decrypt_interactively(encrypted, path) else {
                return Ok(None);
            };
            Ok(Some(Box::new(decrypted)))
        }
    }
}

fn maybe_decrypt_interactively(
    encrypted: &age::ssh::EncryptedKey,
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
        if let Ok(unencrypted) = encrypted.decrypt(passphrase) {
            return Some(age::ssh::Identity::from(unencrypted));
        }
        eprintln!("incorrect passphrase");
    }
    None
}

fn parse_identity_files_from_ssh_config_in(home: &Path) -> Vec<PathBuf> {
    let cfg_path = home.join(".ssh").join("config");
    let Ok(text) = fs::read_to_string(&cfg_path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.len() <= 12 {
            continue;
        }
        if !trimmed[..12].eq_ignore_ascii_case("identityfile") {
            continue;
        }
        let value = trimmed[12..]
            .trim_start_matches(|character: char| character == '=' || character.is_whitespace());
        if value.is_empty() {
            continue;
        }
        let expanded = if let Some(rest) = value.strip_prefix("~/") {
            home.join(rest)
        } else if value == "~" {
            home.to_path_buf()
        } else {
            PathBuf::from(value)
        };
        out.push(expanded);
    }
    out
}

/// Describe the configured identity paths for diagnostics. Does not load or
/// decrypt any keys.
#[must_use]
pub fn describe_available_identities() -> Vec<String> {
    discover_private_key_paths()
        .into_iter()
        .map(|path| path.display().to_string())
        .collect()
}

/// Return a generic error suitable for printing when no identity could
/// unlock the vault.
#[must_use]
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

/// Return an error that explains why unlock failed, listing vault recipient
/// fingerprints, local keys, and a fingerprint-by-fingerprint comparison.
#[must_use]
pub fn error_no_identity_unlocked_detailed(
    attempted: &[PathBuf],
    vault_recipients: &HashSet<String>,
) -> anyhow::Error {
    let mut lines = String::new();
    lines.push_str("this host has no SSH private key authorized to unlock the vault.\n\n");

    lines.push_str("Vault recipients:\n");
    let mut sorted: Vec<&String> = vault_recipients.iter().collect();
    sorted.sort();
    for fingerprint in &sorted {
        lines.push_str("  ");
        lines.push_str(fingerprint);
        lines.push('\n');
    }

    if attempted.is_empty() {
        lines.push_str("\nNo SSH private keys were found in ~/.ssh/ or ~/.ssh/config.\n");
    } else {
        lines.push_str("\nLocal keys checked:\n");
        for path in attempted {
            let label = match public_fingerprint_for_private_key(path) {
                Some(fingerprint) => {
                    let status = if vault_recipients.contains(&fingerprint) {
                        "(authorized)"
                    } else {
                        "(not a recipient)"
                    };
                    format!("  {}  {fingerprint}  {status}\n", path.display())
                }
                None => format!("  {}  (no .pub sibling)\n", path.display()),
            };
            lines.push_str(&label);
        }
    }

    lines.push_str(
        "\nHint: run `sshenv add-recipient --key <this-host-pubkey>` on a machine\n\
         that can already unlock the vault, then copy the vault back here.",
    );

    anyhow!("{lines}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};

    fn write_keypair(dir: &Path, name: &str) -> (PathBuf, String, String) {
        let priv_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen key");
        let pub_line = priv_key.public_key().to_openssh().expect("pub");
        let priv_pem = priv_key
            .to_openssh(LineEnding::LF)
            .expect("priv pem")
            .to_string();

        let priv_path = dir.join(name);
        fs::write(&priv_path, &priv_pem).unwrap();
        fs::write(append_pub_extension(&priv_path), format!("{pub_line}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let fingerprint = fingerprint_from_line(&pub_line).unwrap();
        (priv_path, pub_line, fingerprint)
    }

    #[test]
    fn discover_private_key_paths_in_is_deterministic_and_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let _ = write_keypair(dir.path(), "zeta");
        let _ = write_keypair(dir.path(), "alpha");
        let _ = write_keypair(dir.path(), "middle");
        let _ = write_keypair(dir.path(), "id_ed25519");
        let _ = write_keypair(dir.path(), "id_rsa");

        let first = discover_private_key_paths_in(dir.path());
        let second = discover_private_key_paths_in(dir.path());
        assert_eq!(first, second, "order should be stable");

        let names: Vec<String> = first
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["id_ed25519", "id_rsa", "alpha", "middle", "zeta"]
        );
    }

    #[test]
    fn public_fingerprint_for_private_key_matches_pub_body() {
        let dir = tempfile::tempdir().unwrap();
        let (priv_path, _, written_fingerprint) = write_keypair(dir.path(), "id_ed25519");
        let fingerprint = public_fingerprint_for_private_key(&priv_path).unwrap();
        assert_eq!(fingerprint, written_fingerprint);
    }

    #[test]
    fn load_identities_for_vault_in_skips_non_matching_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let (_matching_path, _matching_line, matching_fingerprint) =
            write_keypair(dir.path(), "matching");
        let _ = write_keypair(dir.path(), "nonmatching");

        let mut fingerprints = HashSet::new();
        fingerprints.insert(matching_fingerprint);
        let identities = load_identities_for_vault_in(dir.path(), &fingerprints).unwrap();

        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn error_detailed_lists_recipients_and_status_labels() {
        let dir = tempfile::tempdir().unwrap();
        let (priv_path, _, local_fingerprint) = write_keypair(dir.path(), "matching");

        let mut recipients = HashSet::new();
        recipients.insert(local_fingerprint.clone());
        recipients.insert("SHA256:another-host".to_string());

        let err =
            error_no_identity_unlocked_detailed(std::slice::from_ref(&priv_path), &recipients);
        let msg = err.to_string();
        assert!(msg.contains("Vault recipients:"), "{msg}");
        assert!(msg.contains(&local_fingerprint), "{msg}");
        assert!(msg.contains("SHA256:another-host"), "{msg}");
        assert!(msg.contains("authorized"), "{msg}");
    }
}
