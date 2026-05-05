//! Command handlers, one module per logical area.

pub mod doctor;
pub mod export;
pub mod init;
pub mod profile;
pub mod recipient;
pub mod run;
pub mod sessions;
pub mod shims;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sshenv_cli_models::Cli;
use sshenv_vault::{CiphertextVault, DataKey, Vault};

use crate::identity::{
    discover_private_key_paths, error_no_identity_unlocked_detailed, load_identities_for_vault,
};

/// Per-invocation context: resolved paths, etc.
pub struct Context {
    pub vault_path: PathBuf,
}

impl Context {
    #[must_use]
    pub fn from_cli(cli: &Cli) -> Self {
        let vault_path = cli
            .vault
            .clone()
            .unwrap_or_else(sshenv_vault::default_vault_path);
        Self { vault_path }
    }
}

/// Load the ciphertext vault at `path`, load the matching SSH identities
/// (pre-filtered by recipient fingerprint), and unlock.
///
/// Fails with a detailed error if no local key matches a vault recipient,
/// or if all matching keys refuse to decrypt.
///
/// # Errors
///
/// Propagates filesystem and decryption errors.
pub fn load_and_unlock(vault_path: &Path) -> Result<(Vault, DataKey)> {
    let ciphertext = Vault::load_ciphertext(vault_path)?;
    let fps: HashSet<String> = ciphertext
        .recipients
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();
    let identities = load_identities_for_vault(&fps)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            &fps,
        ));
    }
    Vault::unlock(ciphertext, &identities)
        .map_err(|_| error_no_identity_unlocked_detailed(&discover_private_key_paths(), &fps))
}

/// Load the ciphertext vault and return both the ciphertext and the
/// pre-computed recipient fingerprint set. Used by commands that need to
/// inspect recipients before unlocking (e.g. `add-recipient`).
///
/// # Errors
///
/// Propagates filesystem errors.
pub fn load_ciphertext_and_fps(vault_path: &Path) -> Result<(CiphertextVault, HashSet<String>)> {
    let ciphertext = Vault::load_ciphertext(vault_path)?;
    let fps: HashSet<String> = ciphertext
        .recipients
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();
    Ok((ciphertext, fps))
}

/// Unlock a previously-loaded ciphertext vault using the recipient-
/// filtered identity loader. The `recipient_fingerprints` must match the
/// ciphertext's recipients (callers typically get these from
/// [`load_ciphertext_and_fps`]).
///
/// # Errors
///
/// Fails with a detailed error if no key matches or decryption fails.
pub fn unlock_ciphertext(
    ciphertext: CiphertextVault,
    recipient_fingerprints: &HashSet<String>,
) -> Result<(Vault, DataKey)> {
    let identities = load_identities_for_vault(recipient_fingerprints)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            recipient_fingerprints,
        ));
    }
    Vault::unlock(ciphertext, &identities).map_err(|_| {
        error_no_identity_unlocked_detailed(&discover_private_key_paths(), recipient_fingerprints)
    })
}
