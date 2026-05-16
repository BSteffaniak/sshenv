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
    check_ssh_key_hardening(&fps)?;
    let identities = load_identities_for_vault(&fps)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            &fps,
        ));
    }
    let requires_extra_factor = ciphertext_requires_extra_factor(&ciphertext);
    let passphrase = passphrase_for_ciphertext(vault_path, &ciphertext, None)?;
    let unlocked = Vault::unlock_with_passphrase(
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
    })?;
    cache_vault_passphrase_if_present(vault_path, passphrase.as_ref());
    record_rollback(vault_path, generation)?;
    Ok(unlocked)
}

/// Load the vault and decrypt only the outer profile-entry container. Profile
/// entries remain encrypted.
///
/// # Errors
///
/// Propagates filesystem, identity, and outer-vault decrypt errors.
pub fn load_and_unlock_metadata(vault_path: &Path) -> Result<(Vault, DataKey)> {
    let ciphertext = Vault::load_ciphertext(vault_path)?;
    check_rollback(vault_path, &ciphertext)?;
    let generation = ciphertext.generation();
    let fps: HashSet<String> = ciphertext
        .recipients
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();
    check_ssh_key_hardening(&fps)?;
    let identities = load_identities_for_vault(&fps)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            &fps,
        ));
    }
    let requires_extra_factor = ciphertext_requires_extra_factor(&ciphertext);
    let passphrase = passphrase_for_ciphertext(vault_path, &ciphertext, None)?;
    let unlocked = Vault::unlock_metadata_with_passphrase(
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
    })?;
    cache_vault_passphrase_if_present(vault_path, passphrase.as_ref());
    record_rollback(vault_path, generation)?;
    Ok(unlocked)
}

/// Load the vault and decrypt only one profile when profile-key mode allows it.
///
/// # Errors
///
/// Propagates filesystem, identity, outer-vault, and selected-profile decrypt
/// errors.
pub fn load_and_unlock_profile(vault_path: &Path, profile: &str) -> Result<(Vault, DataKey)> {
    load_and_unlock_profile_with_passphrase(vault_path, profile, None)
}

/// Load the vault and decrypt only one profile using an explicit profile
/// passphrase when one is required.
///
/// # Errors
///
/// Propagates filesystem, identity, outer-vault, and selected-profile decrypt
/// errors.
pub fn load_and_unlock_profile_with_passphrase(
    vault_path: &Path,
    profile: &str,
    explicit_profile_passphrase: Option<&str>,
) -> Result<(Vault, DataKey)> {
    let ciphertext = Vault::load_ciphertext(vault_path)?;
    check_rollback(vault_path, &ciphertext)?;
    let generation = ciphertext.generation();
    let fps: HashSet<String> = ciphertext
        .recipients
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();
    check_ssh_key_hardening(&fps)?;
    let identities = load_identities_for_vault(&fps)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            &fps,
        ));
    }
    let requires_extra_factor = ciphertext_requires_extra_factor(&ciphertext);
    let passphrase = passphrase_for_ciphertext(vault_path, &ciphertext, None)?;
    let (mut vault, data_key) = Vault::unlock_metadata_with_passphrase(
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
    })?;
    cache_vault_passphrase_if_present(vault_path, passphrase.as_ref());
    if vault.profiles.get(profile).is_none() && vault.profiles.profile_entries.contains_key(profile)
    {
        let profile_passphrase =
            passphrase_for_profile(&vault, profile, explicit_profile_passphrase)?;
        vault.unlock_profile_with_passphrase(
            profile,
            &data_key,
            profile_passphrase.as_ref().map(|p| p.as_str()),
        )?;
    }
    record_rollback(vault_path, generation)?;
    Ok((vault, data_key))
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
    check_ssh_key_hardening(recipient_fingerprints)?;
    let identities = load_identities_for_vault(recipient_fingerprints)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            &discover_private_key_paths(),
            recipient_fingerprints,
        ));
    }
    let requires_extra_factor = ciphertext_requires_extra_factor(&ciphertext);
    let passphrase = passphrase_for_ciphertext(Path::new(""), &ciphertext, explicit_passphrase)?;
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

#[cfg(feature = "ssh-hardening")]
fn check_ssh_key_hardening(vault_recipients: &HashSet<String>) -> Result<()> {
    use crate::config::UnencryptedSshKeysPolicy;

    let policy = crate::config::load()?.security.unencrypted_ssh_keys;
    if policy == UnencryptedSshKeysPolicy::Allow {
        return Ok(());
    }

    let mut findings = Vec::new();
    for path in discover_private_key_paths() {
        let Some(fingerprint) = crate::identity::public_fingerprint_for_private_key(&path) else {
            continue;
        };
        if !vault_recipients.contains(&fingerprint) {
            continue;
        }
        if matches!(
            crate::identity::inspect_private_key_security(&path),
            Ok(crate::identity::PrivateKeySecurity::Unencrypted)
        ) {
            findings.push(format!("{} ({fingerprint})", path.display()));
        }
    }

    if findings.is_empty() {
        return Ok(());
    }

    match policy {
        UnencryptedSshKeysPolicy::Allow => Ok(()),
        UnencryptedSshKeysPolicy::Warn => {
            for finding in findings {
                eprintln!(
                    "warning: authorized SSH private key is unencrypted: {finding}; set [security] unencrypted_ssh_keys = \"allow\" to silence or \"deny\" to fail"
                );
            }
            Ok(())
        }
        UnencryptedSshKeysPolicy::Deny => anyhow::bail!(
            "authorized unencrypted SSH private key(s) denied by config: {}",
            findings.join(", ")
        ),
    }
}

#[cfg(not(feature = "ssh-hardening"))]
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "feature-gated no-op preserves fallible call sites when ssh hardening is disabled"
)]
fn check_ssh_key_hardening(_vault_recipients: &HashSet<String>) -> Result<()> {
    Ok(())
}

#[cfg(feature = "rollback-protection")]
fn check_rollback(vault_path: &Path, ciphertext: &CiphertextVault) -> Result<()> {
    crate::rollback_checkpoint::enforce_env_checkpoint(vault_path, ciphertext.generation())?;
    crate::rollback::check_generation(vault_path, ciphertext.generation())
}

#[cfg(not(feature = "rollback-protection"))]
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "feature-gated no-op preserves fallible call sites when rollback protection is disabled"
)]
fn check_rollback(_vault_path: &Path, _ciphertext: &CiphertextVault) -> Result<()> {
    Ok(())
}

#[cfg(feature = "rollback-protection")]
pub(crate) fn record_rollback(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    crate::rollback::record_generation(vault_path, generation)
}

#[cfg(not(feature = "rollback-protection"))]
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "feature-gated no-op preserves fallible call sites when rollback protection is disabled"
)]
pub(crate) fn record_rollback(_vault_path: &Path, _generation: Option<u64>) -> Result<()> {
    Ok(())
}

#[cfg(feature = "rollback-protection")]
pub(crate) fn set_rollback(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    crate::rollback::set_generation(vault_path, generation)
}

#[cfg(not(feature = "rollback-protection"))]
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    reason = "feature-gated no-op preserves fallible call sites when rollback protection is disabled"
)]
pub(crate) fn set_rollback(_vault_path: &Path, _generation: Option<u64>) -> Result<()> {
    Ok(())
}

fn cache_vault_passphrase_if_present(vault_path: &Path, passphrase: Option<&Zeroizing<String>>) {
    if let Some(passphrase) = passphrase {
        if let Err(error) =
            crate::passphrase_cache::put_vault_passphrase(vault_path, passphrase.as_str())
        {
            eprintln!("warning: failed to update passphrase cache: {error}");
        }
    }
}

fn passphrase_for_ciphertext(
    vault_path: &Path,
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

    if !vault_path.as_os_str().is_empty() {
        if let Some(value) = crate::passphrase_cache::get_vault_passphrase(vault_path)? {
            return Ok(Some(value));
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

fn passphrase_for_profile(
    vault: &Vault,
    profile: &str,
    explicit_passphrase: Option<&str>,
) -> Result<Option<Zeroizing<String>>> {
    let Some(policy) = vault.profiles.profile_policy(profile) else {
        return Ok(None);
    };
    if !policy
        .factor_metadata
        .iter()
        .any(|factor| factor.kind == UnlockFactorKindV2::Passphrase)
    {
        return Ok(None);
    }

    if let Some(value) = explicit_passphrase {
        return Ok(Some(Zeroizing::new(value.to_string())));
    }

    if let Ok(value) = std::env::var("SSHENV_PROFILE_PASSPHRASE") {
        if !value.is_empty() {
            return Ok(Some(Zeroizing::new(value)));
        }
    }
    if let Ok(value) = std::env::var("SSHENV_PASSPHRASE") {
        if !value.is_empty() {
            return Ok(Some(Zeroizing::new(value)));
        }
    }

    if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "profile '{profile}' requires a passphrase factor, but stdin is not a terminal; set SSHENV_PROFILE_PASSPHRASE for non-interactive use"
        ));
    }

    let value =
        rpassword::prompt_password(format!("Enter sshenv profile passphrase for '{profile}': "))?;
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
