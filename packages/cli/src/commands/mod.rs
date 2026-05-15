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
    let requires_passphrase = ciphertext_requires_passphrase(&ciphertext);
    let passphrase = passphrase_for_ciphertext(&ciphertext)?;
    Vault::unlock_with_passphrase(
        ciphertext,
        &identities,
        passphrase.as_ref().map(|p| p.as_str()),
    )
    .map_err(|err| {
        if requires_passphrase {
            err
        } else {
            error_no_identity_unlocked_detailed(&discover_private_key_paths(), &fps)
        }
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
    let requires_passphrase = ciphertext_requires_passphrase(&ciphertext);
    let passphrase = passphrase_for_ciphertext(&ciphertext)?;
    Vault::unlock_with_passphrase(
        ciphertext,
        &identities,
        passphrase.as_ref().map(|p| p.as_str()),
    )
    .map_err(|err| {
        if requires_passphrase {
            err
        } else {
            error_no_identity_unlocked_detailed(
                &discover_private_key_paths(),
                recipient_fingerprints,
            )
        }
    })
}

fn passphrase_for_ciphertext(ciphertext: &CiphertextVault) -> Result<Option<Zeroizing<String>>> {
    if !ciphertext_requires_passphrase(ciphertext) {
        return Ok(None);
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
