#[cfg(feature = "rekey")]
use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Result, bail};
use sshenv_cli_models::RotateKeyArgs;
#[cfg(feature = "rekey")]
use sshenv_vault::recipient::fingerprint_from_line;
use sshenv_vault::{DataKey, Vault};

use crate::commands::Context as CmdContext;
#[cfg(feature = "rekey")]
use crate::commands::{load_ciphertext_and_fps, unlock_ciphertext};
#[cfg(feature = "rekey")]
use crate::identity::discover_public_key_paths;
#[cfg(feature = "rekey")]
use crate::pubkey::load_public_key;

#[cfg(feature = "rekey")]
pub fn rotate_key(ctx: &CmdContext, args: RotateKeyArgs) -> Result<()> {
    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, _old_key) = unlock_ciphertext(ciphertext, &recipients)?;
    let new_key = rotate_unlocked_vault(&mut vault, &args.recipient_keys)?;
    vault.save(&ctx.vault_path, &new_key)?;
    eprintln!(
        "Rotated vault data key for {} recipient(s).",
        vault.recipients.len()
    );
    Ok(())
}

#[cfg(not(feature = "rekey"))]
pub fn rotate_key(_ctx: &CmdContext, _args: RotateKeyArgs) -> Result<()> {
    bail!("this sshenv build was compiled without rekey support")
}

#[cfg(feature = "rekey")]
pub fn rotate_unlocked_vault(vault: &mut Vault, explicit_keys: &[String]) -> Result<DataKey> {
    let expected: HashSet<String> = vault
        .recipients
        .iter()
        .map(|recipient| recipient.fingerprint.clone())
        .collect();
    let public_key_lines = resolve_recipient_public_key_lines(explicit_keys, &expected)?;
    vault.rotate_data_key(&public_key_lines)
}

#[cfg(not(feature = "rekey"))]
pub fn rotate_unlocked_vault(_vault: &mut Vault, _explicit_keys: &[String]) -> Result<DataKey> {
    bail!("this sshenv build was compiled without rekey support")
}

#[cfg(feature = "rekey")]
fn resolve_recipient_public_key_lines(
    explicit_keys: &[String],
    expected_fingerprints: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut public_keys_by_fingerprint = BTreeMap::new();

    for key in explicit_keys {
        let line = load_public_key(key)?;
        let fingerprint = fingerprint_from_line(&line)?;
        if !expected_fingerprints.contains(&fingerprint) {
            bail!(
                "provided recipient key {fingerprint} is not a current vault recipient; \
                 use add-recipient/remove-recipient to change recipients before rotating"
            );
        }
        public_keys_by_fingerprint
            .entry(fingerprint)
            .or_insert(line);
    }

    for path in discover_public_key_paths() {
        let Ok(line) = load_public_key(&path.display().to_string()) else {
            continue;
        };
        let Ok(fingerprint) = fingerprint_from_line(&line) else {
            continue;
        };
        if expected_fingerprints.contains(&fingerprint) {
            public_keys_by_fingerprint
                .entry(fingerprint)
                .or_insert(line);
        }
    }

    let expected_sorted: BTreeSet<String> = expected_fingerprints.iter().cloned().collect();
    let provided_sorted: BTreeSet<String> = public_keys_by_fingerprint.keys().cloned().collect();
    if provided_sorted != expected_sorted {
        let missing: Vec<&String> = expected_sorted.difference(&provided_sorted).collect();
        bail!(
            "cannot rotate data key because public keys are missing for recipient(s): {}. \
             Re-run with `--recipient-key <path-or-public-key-line>` for each missing recipient.",
            format_fingerprint_list(&missing)
        );
    }

    Ok(expected_sorted
        .iter()
        .filter_map(|fingerprint| public_keys_by_fingerprint.get(fingerprint).cloned())
        .collect())
}

#[cfg(feature = "rekey")]
fn format_fingerprint_list(values: &[&String]) -> String {
    if values.is_empty() {
        "(none)".to_string()
    } else {
        values
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
