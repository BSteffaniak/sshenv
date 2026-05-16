//! Local non-secret security reminder state.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::session_registry::vault_id;

#[derive(Debug, Default, Deserialize, Serialize)]
struct SecurityStateFile {
    #[serde(default)]
    vaults: Vec<SecurityStateRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SecurityStateRecord {
    vault: String,
    #[serde(default)]
    rotation_recommended: bool,
    reason: Option<String>,
}

/// Resolve the local security state path: `$SSHENV_SECURITY_STATE`, else
/// `~/.sshenv/security-state.toml`.
#[must_use]
pub fn default_security_state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SSHENV_SECURITY_STATE") {
        return PathBuf::from(path);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/security-state.toml"),
        |home| home.join(".sshenv").join("security-state.toml"),
    )
}

/// Mark that this vault should rotate its data key.
///
/// # Errors
///
/// Returns an error if local state cannot be read or written.
pub fn mark_rotation_recommended(vault_path: &Path, reason: impl Into<String>) -> Result<()> {
    update_rotation_recommendation(vault_path, true, Some(reason.into()))
}

/// Clear any data-key rotation reminder for this vault.
///
/// # Errors
///
/// Returns an error if local state cannot be read or written.
pub fn clear_rotation_recommended(vault_path: &Path) -> Result<()> {
    update_rotation_recommendation(vault_path, false, None)
}

/// Return the current data-key rotation reminder reason, if any.
///
/// # Errors
///
/// Returns an error if local state cannot be read.
pub fn rotation_recommendation(vault_path: &Path) -> Result<Option<String>> {
    let state = load_state()?;
    let id = vault_id(vault_path);
    Ok(state
        .vaults
        .iter()
        .find(|record| record.vault == id && record.rotation_recommended)
        .and_then(|record| record.reason.clone()))
}

fn update_rotation_recommendation(
    vault_path: &Path,
    recommended: bool,
    reason: Option<String>,
) -> Result<()> {
    let path = default_security_state_path();
    let id = vault_id(vault_path);
    let mut state = load_state()?;

    match state.vaults.iter_mut().find(|record| record.vault == id) {
        Some(record) => {
            record.rotation_recommended = recommended;
            record.reason = reason;
        }
        None => state.vaults.push(SecurityStateRecord {
            vault: id,
            rotation_recommended: recommended,
            reason,
        }),
    }

    save_state(&path, &state)
}

fn load_state() -> Result<SecurityStateFile> {
    let path = default_security_state_path();
    if !path.exists() {
        return Ok(SecurityStateFile::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read security state {}", path.display()))?;
    toml::from_str(&text)
        .with_context(|| format!("failed to parse security state {}", path.display()))
}

fn save_state(path: &Path, state: &SecurityStateFile) -> Result<()> {
    let preamble = "\
# sshenv local security reminder state (plaintext, non-secret).
# Stores vault path identities and operational reminders.
";
    let body = toml::to_string_pretty(state).context("failed to serialize security state")?;
    sshenv_vault::atomic_write(path, format!("{preamble}\n{body}").as_bytes(), 0o600)
}
