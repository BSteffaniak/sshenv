//! Local rollback-protection state.
//!
//! This stores only non-secret local metadata: the highest v2 vault generation
//! seen for each vault path. It detects older valid vault copies being restored
//! on the same machine. It is not a substitute for TPM/remote monotonic state.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::session_registry::vault_id;

#[derive(Debug, Default, Deserialize, Serialize)]
struct RollbackFile {
    #[serde(default)]
    vaults: Vec<RollbackRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RollbackRecord {
    vault: String,
    generation: u64,
}

/// Resolve the rollback state path: `$SSHENV_ROLLBACK`, else
/// `~/.sshenv/rollback.toml`.
#[must_use]
pub fn default_rollback_path() -> PathBuf {
    if let Ok(p) = std::env::var("SSHENV_ROLLBACK") {
        return PathBuf::from(p);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/rollback.toml"),
        |home| home.join(".sshenv").join("rollback.toml"),
    )
}

/// Ensure the loaded generation is not older than local state.
///
/// # Errors
///
/// Returns an error if local state records a newer generation for this vault.
pub fn check_generation(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    let Some(generation) = generation else {
        return Ok(());
    };
    let state = load_state()?;
    let id = vault_id(vault_path);
    if let Some(record) = state.vaults.iter().find(|record| record.vault == id) {
        if generation < record.generation {
            bail!(
                "possible vault rollback detected: current generation {generation} is older than local last-seen generation {}",
                record.generation
            );
        }
    }
    Ok(())
}

/// Record the highest generation seen for this vault.
///
/// # Errors
///
/// Returns an error if local rollback state cannot be written.
pub fn record_generation(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    let Some(generation) = generation else {
        return Ok(());
    };
    let path = default_rollback_path();
    let id = vault_id(vault_path);
    let mut state = load_state()?;

    match state.vaults.iter_mut().find(|record| record.vault == id) {
        Some(record) => {
            if generation > record.generation {
                record.generation = generation;
            }
        }
        None => state.vaults.push(RollbackRecord {
            vault: id,
            generation,
        }),
    }

    save_state(&path, &state)
}

fn load_state() -> Result<RollbackFile> {
    let path = default_rollback_path();
    if !path.exists() {
        return Ok(RollbackFile::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read rollback state {}", path.display()))?;
    toml::from_str(&text)
        .with_context(|| format!("failed to parse rollback state {}", path.display()))
}

fn save_state(path: &Path, state: &RollbackFile) -> Result<()> {
    let preamble = "\
# sshenv rollback protection (plaintext, local per-host state).
# Stores only vault path identities and highest seen v2 generations.
";
    let body = toml::to_string_pretty(state).context("failed to serialize rollback state")?;
    sshenv_vault::atomic_write(path, format!("{preamble}\n{body}").as_bytes(), 0o600)
}
