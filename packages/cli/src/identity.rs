//! Discover SSH private keys on the local machine and load them as
//! `age::Identity` objects suitable for unwrapping vault recipients.
//!
//! The primary entry point for unlock paths is
//! [`load_identities_for_vault`]: given the vault's recipient
//! fingerprints, it only loads private keys whose `.pub` sibling matches,
//! silently skipping everything else. This avoids prompting for
//! passphrases on keys that could never unlock the vault.

use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, IsTerminal};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, anyhow};
use sshenv_vault::recipient::fingerprint_from_line;

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

    // IdentityFile entries from ~/.ssh/config; values live outside the
    // ssh_dir in principle, so we append them after the _in() result.
    for cfg_identity in parse_identity_files_from_ssh_config_in(&home) {
        if cfg_identity.is_file() && !out.contains(&cfg_identity) {
            out.push(cfg_identity);
        }
    }

    out
}

/// Test-friendly variant of [`discover_private_key_paths`] that takes an
/// explicit SSH directory. Skips the `~/.ssh/config` lookup.
#[must_use]
pub fn discover_private_key_paths_in(ssh_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    // Well-known keys first in a fixed order.
    for name in &["id_ed25519", "id_rsa"] {
        let p = ssh_dir.join(name);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }

    // Everything else with a .pub sibling, sorted alphabetically.
    let mut extras: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(ssh_dir) {
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
                extras.push(priv_path);
            }
        }
    }
    extras.sort();
    for p in extras {
        if !out.contains(&p) {
            out.push(p);
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
#[must_use]
pub fn discover_public_key_paths() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    let Some(home) = dirs::home_dir() else {
        return out;
    };
    let ssh_dir = home.join(".ssh");

    for name in &["id_ed25519.pub", "id_rsa.pub"] {
        let p = ssh_dir.join(name);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }

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

    for cfg_identity in parse_identity_files_from_ssh_config_in(&home) {
        let pub_path = cfg_identity.with_extension("pub");
        if pub_path.is_file() && !out.contains(&pub_path) {
            out.push(pub_path);
        }
    }

    out
}

/// Given the path to a private SSH key, return the fingerprint of its
/// `<path>.pub` sibling (if present and parseable). Returns `None` when
/// the `.pub` file is missing, unreadable, or malformed — callers should
/// fall back to "try loading this key anyway" in that case.
#[must_use]
pub fn public_fingerprint_for_private_key(priv_path: &Path) -> Option<String> {
    let pub_path = append_pub_extension(priv_path);
    let content = fs::read_to_string(&pub_path).ok()?;
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    fingerprint_from_line(line).ok()
}

fn append_pub_extension(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".pub");
    PathBuf::from(s)
}

/// Load all discoverable private keys as `age` identities, **without**
/// any vault-recipient filter. Encrypted keys prompt for a passphrase
/// (up to 3 attempts) when stdin is a TTY; otherwise they are skipped.
///
/// Prefer [`load_identities_for_vault`] for anything that actually
/// unlocks a vault — this function is for `doctor` and similar paths
/// that want to inspect every available key regardless of authorization.
///
/// # Errors
///
/// Never returns `Err` under normal conditions; per-key failures are
/// logged to stderr and the key is skipped.
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

/// Load only those SSH private keys whose `.pub` fingerprint appears in
/// `recipient_fingerprints`. Keys with a matching fingerprint are loaded
/// normally (prompting for a passphrase if encrypted and stdin is a
/// TTY). Keys with a non-matching fingerprint are **silently skipped**.
/// Keys whose `.pub` sibling is missing or unparseable fall back to the
/// "try loading anyway" behavior of [`load_identities`].
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

    // Also try IdentityFile entries from ssh_config that live outside
    // the ssh_dir.
    for priv_path in parse_identity_files_from_ssh_config_in(&home) {
        if !priv_path.is_file() {
            continue;
        }
        try_load_matching(&priv_path, recipient_fingerprints, &mut out);
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
    let mut out: Vec<Box<dyn age::Identity>> = Vec::new();
    for p in &paths {
        try_load_matching(p, recipient_fingerprints, &mut out);
    }
    Ok(out)
}

fn try_load_matching(
    priv_path: &Path,
    recipient_fingerprints: &HashSet<String>,
    sink: &mut Vec<Box<dyn age::Identity>>,
) {
    match public_fingerprint_for_private_key(priv_path) {
        Some(fp) => {
            if !recipient_fingerprints.contains(&fp) {
                // Silent skip: this key cannot possibly unlock the vault.
                return;
            }
            match try_load_identity(priv_path) {
                Ok(Some(id)) => sink.push(id),
                Ok(None) => {
                    eprintln!("note: skipping encrypted SSH key {}", priv_path.display());
                }
                Err(err) => {
                    eprintln!(
                        "note: could not parse SSH key {}: {err}",
                        priv_path.display()
                    );
                }
            }
        }
        None => {
            // Fallback: no parseable .pub sibling. Try to load anyway so
            // we don't fail closed on unusual setups.
            match try_load_identity(priv_path) {
                Ok(Some(id)) => sink.push(id),
                Ok(None) | Err(_) => {
                    // Silent: we don't know whether this key would have
                    // matched, so don't alarm the user.
                }
            }
        }
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

fn parse_identity_files_from_ssh_config_in(home: &Path) -> Vec<PathBuf> {
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
            home.to_path_buf()
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
///
/// Preserved for backwards compatibility; prefer
/// [`error_no_identity_unlocked_detailed`] which takes vault-recipient
/// context and can produce a much more actionable message.
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

/// Return an error that explains why unlock failed, listing the vault's
/// recipient fingerprints, the keys on this host, and a fingerprint-by-
/// fingerprint comparison.
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
    for fp in &sorted {
        lines.push_str("  ");
        lines.push_str(fp);
        lines.push('\n');
    }

    if attempted.is_empty() {
        lines.push_str("\nNo SSH private keys were found in ~/.ssh/ or ~/.ssh/config.\n");
    } else {
        lines.push_str("\nLocal keys checked:\n");
        for path in attempted {
            let label = match public_fingerprint_for_private_key(path) {
                Some(fp) => {
                    let status = if vault_recipients.contains(&fp) {
                        "(authorized)"
                    } else {
                        "(not a recipient)"
                    };
                    format!("  {}  {fp}  {status}\n", path.display())
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

    /// Write a generated ed25519 keypair to `dir` with basename `name`.
    /// Returns `(priv_path, pub_line, fingerprint)`.
    fn write_keypair(dir: &Path, name: &str) -> (PathBuf, String, String) {
        let priv_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen key");
        let pub_line = priv_key.public_key().to_openssh().expect("pub");
        let priv_pem = priv_key
            .to_openssh(LineEnding::LF)
            .expect("priv pem")
            .to_string();

        let priv_path = dir.join(name);
        fs::write(&priv_path, &priv_pem).unwrap();
        fs::write(priv_path.with_extension("pub"), format!("{pub_line}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let fp = fingerprint_from_line(&pub_line).unwrap();
        (priv_path, pub_line, fp)
    }

    #[test]
    fn discover_private_key_paths_in_is_deterministic_and_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let _ = write_keypair(dir.path(), "zeta");
        let _ = write_keypair(dir.path(), "alpha");
        let _ = write_keypair(dir.path(), "middle");
        let _ = write_keypair(dir.path(), "id_ed25519");
        let _ = write_keypair(dir.path(), "id_rsa");

        let a = discover_private_key_paths_in(dir.path());
        let b = discover_private_key_paths_in(dir.path());
        assert_eq!(a, b, "order should be stable");

        // Well-known first in fixed order, then alphabetical extras.
        let names: Vec<String> = a
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["id_ed25519", "id_rsa", "alpha", "middle", "zeta"]
        );
    }

    #[test]
    fn public_fingerprint_for_private_key_matches_pub_body() {
        let dir = tempfile::tempdir().unwrap();
        let (priv_path, _, fp_written) = write_keypair(dir.path(), "id_ed25519");
        let fp = public_fingerprint_for_private_key(&priv_path).unwrap();
        assert_eq!(fp, fp_written);
    }

    #[test]
    fn public_fingerprint_for_private_key_returns_none_when_pub_missing() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id_solo");
        fs::write(&priv_path, b"not really a key").unwrap();
        assert!(public_fingerprint_for_private_key(&priv_path).is_none());
    }

    #[test]
    fn load_identities_for_vault_in_skips_non_matching_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let (_a, _aline, a_fp) = write_keypair(dir.path(), "matching");
        let (_b, _bline, _b_fp) = write_keypair(dir.path(), "nonmatching");

        let mut fps = HashSet::new();
        fps.insert(a_fp);
        let ids = load_identities_for_vault_in(dir.path(), &fps).unwrap();

        // Only 'matching' should have been loaded.
        assert_eq!(
            ids.len(),
            1,
            "expected exactly one matching key to be loaded"
        );
    }

    #[test]
    fn load_identities_for_vault_in_returns_empty_when_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let _ = write_keypair(dir.path(), "nonmatching_only");

        let mut fps = HashSet::new();
        fps.insert("SHA256:does-not-exist".to_string());
        let ids = load_identities_for_vault_in(dir.path(), &fps).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn load_identities_for_vault_in_falls_back_when_pub_missing() {
        // A private key with no .pub sibling should get a load attempt
        // via the fallback. We construct an intentionally invalid key so
        // the load silently fails instead of panicking; the point is
        // that the fallback path runs without prompting.
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("orphan");
        fs::write(&priv_path, b"not a real key\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mut fps = HashSet::new();
        fps.insert("SHA256:whatever".to_string());
        let ids = load_identities_for_vault_in(dir.path(), &fps).unwrap();
        assert!(ids.is_empty(), "invalid orphan key should produce no ids");
    }

    #[test]
    fn error_detailed_lists_recipients_and_status_labels() {
        let dir = tempfile::tempdir().unwrap();
        let (priv_path, _, local_fp) = write_keypair(dir.path(), "matching");

        let mut recipients = HashSet::new();
        recipients.insert(local_fp.clone());
        recipients.insert("SHA256:another-host".to_string());

        let err =
            error_no_identity_unlocked_detailed(std::slice::from_ref(&priv_path), &recipients);
        let msg = err.to_string();
        assert!(msg.contains("Vault recipients:"), "{msg}");
        assert!(msg.contains(&local_fp), "{msg}");
        assert!(msg.contains("SHA256:another-host"), "{msg}");
        assert!(msg.contains("authorized"), "{msg}");
    }

    #[test]
    fn error_detailed_labels_non_recipients_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let (priv_path, _, _local_fp) = write_keypair(dir.path(), "nonmatching");

        let mut recipients = HashSet::new();
        recipients.insert("SHA256:some-other-key".to_string());

        let err =
            error_no_identity_unlocked_detailed(std::slice::from_ref(&priv_path), &recipients);
        let msg = err.to_string();
        assert!(msg.contains("not a recipient"), "{msg}");
    }

    #[test]
    fn error_detailed_handles_empty_attempts() {
        let recipients = HashSet::new();
        let err = error_no_identity_unlocked_detailed(&[], &recipients);
        let msg = err.to_string();
        assert!(msg.contains("No SSH private keys were found"));
    }
}
