//! Local rollback-protection state.
//!
//! This stores only non-secret local metadata: the highest v2 vault generation
//! seen for each vault path. It detects older valid vault copies being restored
//! on the same machine. It is not a substitute for TPM/remote monotonic state.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// Opt-in shared rollback sync state path. Point this at a file in a trusted
/// multi-device sync location to reject vault generations older than the
/// highest generation observed by any participating device.
pub const ROLLBACK_SYNC_ENV: &str = "SSHENV_ROLLBACK_SYNC";

/// Opt-in command-backed monotonic state adapter. This is intended for TPM
/// counter/NV-index wrappers without baking a platform-specific TPM policy into
/// sshenv. The command receives non-secret JSON on stdin and returns JSON on
/// stdout.
pub const ROLLBACK_MONOTONIC_COMMAND_ENV: &str = "SSHENV_ROLLBACK_MONOTONIC_COMMAND";

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct RollbackMonotonicCommandRequest<'a> {
    operation: &'a str,
    vault_id: &'a str,
    generation: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RollbackMonotonicCommandResponse {
    generation: Option<u64>,
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
    check_synced_generation_for_id(&id, generation)?;
    check_monotonic_command_generation_for_id(&id, generation)?;
    Ok(())
}

/// Return the locally recorded rollback baseline for this vault, if any.
///
/// # Errors
///
/// Returns an error if local rollback state cannot be read.
pub fn generation_for(vault_path: &Path) -> Result<Option<u64>> {
    let state = load_state()?;
    let id = vault_id(vault_path);
    Ok(generation_for_id(&state, &id))
}

/// Return the opt-in synced rollback baseline for this vault, if configured.
///
/// # Errors
///
/// Returns an error if `SSHENV_ROLLBACK_SYNC` is set but the sync state cannot
/// be read.
pub fn synced_generation_for(vault_path: &Path) -> Result<Option<u64>> {
    let Some(path) = rollback_sync_path() else {
        return Ok(None);
    };
    let state = load_state_at(&path)?;
    Ok(generation_for_id(&state, &vault_id(vault_path)))
}

/// Return the configured sync state path, if any.
#[must_use]
pub fn rollback_sync_path() -> Option<PathBuf> {
    std::env::var(ROLLBACK_SYNC_ENV).ok().map(PathBuf::from)
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
    let id = vault_id(vault_path);
    let current = load_state()?
        .vaults
        .iter()
        .find(|record| record.vault == id)
        .map_or(generation, |record| record.generation.max(generation));
    set_generation(vault_path, Some(current))?;
    record_synced_generation(vault_path, Some(generation))?;
    record_monotonic_command_generation_for_id(&id, generation)
}

/// Set the local generation for this vault exactly.
///
/// This is used after an explicit user-requested restore, where an older
/// generation is intentional and should become the new local baseline.
///
/// # Errors
///
/// Returns an error if local rollback state cannot be written.
pub fn set_generation(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    let Some(generation) = generation else {
        return Ok(());
    };
    let path = default_rollback_path();
    let id = vault_id(vault_path);
    let mut state = load_state()?;

    match state.vaults.iter_mut().find(|record| record.vault == id) {
        Some(record) => record.generation = generation,
        None => state.vaults.push(RollbackRecord {
            vault: id,
            generation,
        }),
    }

    save_state(&path, &state)
}

fn check_synced_generation_for_id(vault_id: &str, generation: u64) -> Result<()> {
    let Some(path) = rollback_sync_path() else {
        return Ok(());
    };
    let state = load_state_at(&path)?;
    if let Some(baseline) = generation_for_id(&state, vault_id) {
        if generation < baseline {
            bail!(
                "possible vault rollback detected: current generation {generation} is older than synced last-seen generation {baseline}"
            );
        }
    }
    Ok(())
}

fn check_monotonic_command_generation_for_id(vault_id: &str, generation: u64) -> Result<()> {
    let Some(baseline) = invoke_monotonic_command("check", vault_id, generation)? else {
        return Ok(());
    };
    if generation < baseline {
        bail!(
            "possible vault rollback detected: current generation {generation} is older than monotonic backend generation {baseline}"
        );
    }
    Ok(())
}

fn record_monotonic_command_generation_for_id(vault_id: &str, generation: u64) -> Result<()> {
    let Some(accepted) = invoke_monotonic_command("record", vault_id, generation)? else {
        return Ok(());
    };
    if accepted < generation {
        bail!(
            "monotonic rollback backend accepted generation {accepted}, which is older than current generation {generation}"
        );
    }
    Ok(())
}

fn invoke_monotonic_command(
    operation: &str,
    vault_id: &str,
    generation: u64,
) -> Result<Option<u64>> {
    let Ok(command_path) = std::env::var(ROLLBACK_MONOTONIC_COMMAND_ENV) else {
        return Ok(None);
    };
    if command_path.trim().is_empty() {
        return Ok(None);
    }
    invoke_monotonic_command_path(&command_path, operation, vault_id, generation)
}

fn invoke_monotonic_command_path(
    command_path: &str,
    operation: &str,
    vault_id: &str,
    generation: u64,
) -> Result<Option<u64>> {
    let input = serde_json::to_vec(&RollbackMonotonicCommandRequest {
        operation,
        vault_id,
        generation,
    })
    .context("failed to serialize monotonic rollback request")?;
    let mut child = Command::new(command_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to invoke monotonic rollback command '{command_path}'"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open monotonic rollback command stdin")?;
        stdin
            .write_all(&input)
            .context("failed to write monotonic rollback request")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for monotonic rollback command")?;
    if !output.status.success() {
        bail!(
            "monotonic rollback command exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let response: RollbackMonotonicCommandResponse = serde_json::from_slice(&output.stdout)
        .context("monotonic rollback command returned invalid JSON")?;
    Ok(response.generation)
}

fn record_synced_generation(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    let (Some(path), Some(generation)) = (rollback_sync_path(), generation) else {
        return Ok(());
    };
    let id = vault_id(vault_path);
    let mut state = load_state_at(&path)?;
    match state.vaults.iter_mut().find(|record| record.vault == id) {
        Some(record) => record.generation = record.generation.max(generation),
        None => state.vaults.push(RollbackRecord {
            vault: id,
            generation,
        }),
    }
    save_state(&path, &state)
}

fn generation_for_id(state: &RollbackFile, vault_id: &str) -> Option<u64> {
    state
        .vaults
        .iter()
        .find(|record| record.vault == vault_id)
        .map(|record| record.generation)
}

fn load_state() -> Result<RollbackFile> {
    load_state_at(&default_rollback_path())
}

fn load_state_at(path: &Path) -> Result<RollbackFile> {
    if !path.exists() {
        return Ok(RollbackFile::default());
    }
    let text = std::fs::read_to_string(path)
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    #[test]
    fn monotonic_command_returns_generation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let command_path = dir.path().join("monotonic.sh");
        std::fs::write(
            &command_path,
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"generation\":7}\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&command_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let generation =
            invoke_monotonic_command_path(command_path.to_str().unwrap(), "check", "vault-1", 6)
                .unwrap();
        assert_eq!(generation, Some(7));
    }
}
