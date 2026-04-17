use std::collections::HashSet;
use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use sshenv_cli_models::{AddRecipientArgs, ListRecipientsArgs, RemoveRecipientArgs};
use sshenv_vault::{Vault, recipient::fingerprint_from_line};

use crate::commands::Context as CmdContext;
use crate::identity::{discover_public_key_paths, error_no_identity_unlocked, load_identities};
use crate::picker::{PubkeyCandidate, select_pubkey_interactive};
use crate::pubkey::load_public_key;

pub fn add(ctx: &CmdContext, args: AddRecipientArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let existing: HashSet<String> = ciphertext
        .recipients
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();

    let (pubkey_line, incoming_fp) = resolve_new_recipient(args.key.as_deref(), &existing)?;

    // Early exit on duplicate: the vault's add_recipient also rejects, but
    // we give a friendlier message here before loading identities.
    if existing.contains(&incoming_fp) {
        bail!("recipient {incoming_fp} is already registered; nothing to do");
    }

    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (mut vault, key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    let entry = vault.add_recipient(&pubkey_line, &key)?;
    let fingerprint = entry.fingerprint.clone();
    vault.save(&ctx.vault_path, &key)?;

    eprintln!("Added recipient {fingerprint}.");
    Ok(())
}

/// Resolve the SSH public key line for a new recipient, either from the
/// explicit `--key` argument or interactively from autodiscovery.
/// Already-registered fingerprints are filtered out of the picker.
fn resolve_new_recipient(
    explicit: Option<&str>,
    existing_fingerprints: &HashSet<String>,
) -> Result<(String, String)> {
    if let Some(s) = explicit {
        let line = load_public_key(s)?;
        let fingerprint = fingerprint_from_line(&line)
            .with_context(|| format!("failed to parse SSH public key from {s:?}"))?;
        return Ok((line, fingerprint));
    }

    let paths = discover_public_key_paths();
    let mut candidates: Vec<PubkeyCandidate> = Vec::new();
    for p in &paths {
        match PubkeyCandidate::from_path(p) {
            Ok(c) => {
                if existing_fingerprints.contains(&c.fingerprint) {
                    eprintln!(
                        "note: skipping {} (already a recipient: {})",
                        p.display(),
                        c.fingerprint
                    );
                    continue;
                }
                candidates.push(c);
            }
            Err(err) => {
                eprintln!("note: skipping {} ({err})", p.display());
            }
        }
    }

    let tty = std::io::stdin().is_terminal();
    let picked = {
        let mut stdin = std::io::stdin().lock();
        let mut stderr = std::io::stderr().lock();
        select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, tty)?
    };
    Ok((picked.line, picked.fingerprint))
}

pub fn list(ctx: &CmdContext, args: ListRecipientsArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)
        .with_context(|| format!("failed to load vault {}", ctx.vault_path.display()))?;

    if ciphertext.recipients.is_empty() {
        eprintln!("(no recipients)");
        return Ok(());
    }

    for r in &ciphertext.recipients {
        if args.verbose && !r.public_key_line.is_empty() {
            println!("{}  {}", r.fingerprint, r.public_key_line);
        } else {
            println!("{}", r.fingerprint);
        }
    }
    Ok(())
}

pub fn remove(ctx: &CmdContext, args: RemoveRecipientArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;

    // Reject removing the last recipient — that would brick the vault.
    if ciphertext.recipients.len() <= 1 {
        bail!(
            "refusing to remove the only remaining recipient; add another \
             recipient first or delete the vault file explicitly"
        );
    }

    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (mut vault, key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    if !vault.remove_recipient(&args.fingerprint) {
        bail!("no recipient with fingerprint {}", args.fingerprint);
    }
    vault.save(&ctx.vault_path, &key)?;
    eprintln!("Removed recipient {}.", args.fingerprint);
    Ok(())
}
