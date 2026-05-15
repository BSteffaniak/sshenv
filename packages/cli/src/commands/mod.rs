//! Command handlers, one module per logical area.

pub mod doctor;
pub mod export;
pub mod init;
pub mod migrate;
pub mod profile;
pub mod recipient;
pub mod rekey;
pub mod run;
pub mod security;
pub mod sessions;
pub mod shims;

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sshenv_cli_models::Cli;
use sshenv_vault::models::UnlockFactorKindV2;
use sshenv_vault::{CiphertextVault, DataKey, Vault};
use zeroize::Zeroizing;

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
    check_rollback(vault_path, &ciphertext)?;
    let generation = ciphertext.generation();
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
    let requires_extra_factor = ciphertext_requires_extra_factor(&ciphertext);
    let passphrase = passphrase_for_ciphertext(&ciphertext, None)?;
    Vault::unlock_with_passphrase(
        ciphertext,
        &identities,
        passphrase.as_ref().map(|p| p.as_str()),
    )
    .map_err(|err| {
        if requires_extra_factor {
            err
        } else {
            error_no_identity_unlocked_detailed(&discover_private_key_paths(), &fps)
        }
    })
    .and_then(|unlocked| {
        record_rollback(vault_path, generation)?;
        Ok(unlocked)
    })
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
    check_rollback(vault_path, &ciphertext)?;
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
    unlock_ciphertext_with_passphrase(ciphertext, recipient_fingerprints, None)
}

/// Unlock a previously-loaded ciphertext vault, optionally providing an
/// explicit sshenv passphrase-factor value.
///
/// # Errors
///
/// Fails with a detailed error if no key matches, decryption fails, or a
/// required passphrase factor is unavailable.
pub fn unlock_ciphertext_with_passphrase(
    ciphertext: CiphertextVault,
    recipient_fingerprints: &HashSet<String>,
    explicit_passphrase: Option<&str>,
) -> Result<(Vault, DataKey)> {
    let identities = load_identities_for_vault(recipient_fingerprints)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            recipient_fingerprints,
        ));
    }
    let requires_extra_factor = ciphertext_requires_extra_factor(&ciphertext);
    let passphrase = passphrase_for_ciphertext(&ciphertext, explicit_passphrase)?;
    Vault::unlock_with_passphrase(
        ciphertext,
        &identities,
        passphrase.as_ref().map(|p| p.as_str()),
    )
    .map_err(|err| {
        if requires_extra_factor {
            err
        } else {
            error_no_identity_unlocked_detailed(
                &discover_private_key_paths(),
                recipient_fingerprints,
            )
        }
    })
}

/// Save a vault and update local rollback-protection state when applicable.
///
/// # Errors
///
/// Returns an error if the vault cannot be saved or rollback state cannot be
/// updated.
pub fn save_vault(ctx: &Context, vault: &mut Vault, data_key: &DataKey) -> Result<()> {
    let generation = vault.bump_generation();
    vault.save(&ctx.vault_path, data_key)?;
    record_rollback(&ctx.vault_path, generation)?;
    Ok(())
}

#[cfg(feature = "rollback-protection")]
fn check_rollback(vault_path: &Path, ciphertext: &CiphertextVault) -> Result<()> {
    crate::rollback::check_generation(vault_path, ciphertext.generation())
}

#[cfg(not(feature = "rollback-protection"))]
fn check_rollback(_vault_path: &Path, _ciphertext: &CiphertextVault) -> Result<()> {
    Ok(())
}

#[cfg(feature = "rollback-protection")]
fn record_rollback(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    crate::rollback::record_generation(vault_path, generation)
}

#[cfg(not(feature = "rollback-protection"))]
fn record_rollback(_vault_path: &Path, _generation: Option<u64>) -> Result<()> {
    Ok(())
}

fn passphrase_for_ciphertext(
    ciphertext: &CiphertextVault,
    explicit_passphrase: Option<&str>,
) -> Result<Option<Zeroizing<String>>> {
    if !ciphertext_requires_passphrase(ciphertext) {
        return Ok(None);
    }

    if let Some(value) = explicit_passphrase {
        return Ok(Some(Zeroizing::new(value.to_string())));
    }

    if let Ok(value) = std::env::var("SSHENV_PASSPHRASE") {
        if !value.is_empty() {
            return Ok(Some(Zeroizing::new(value)));
        }
    }

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "vault requires a passphrase factor, but stdin is not a terminal; set SSHENV_PASSPHRASE for non-interactive use"
        ));
    }

    let value = rpassword::prompt_password("Enter sshenv vault passphrase: ")?;
    Ok(Some(Zeroizing::new(value)))
}

fn ciphertext_requires_passphrase(ciphertext: &CiphertextVault) -> bool {
    ciphertext
        .policy_metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(|factor| factor.kind == UnlockFactorKindV2::Passphrase)
}

fn ciphertext_requires_extra_factor(ciphertext: &CiphertextVault) -> bool {
    ciphertext
        .policy_metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(|factor| {
            matches!(
                factor.kind,
                UnlockFactorKindV2::Passphrase | UnlockFactorKindV2::DeviceSeal
            )
        })
}
