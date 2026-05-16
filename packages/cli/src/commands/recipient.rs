use std::collections::HashSet;
use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use sshenv_cli_models::{AddRecipientArgs, ListRecipientsArgs, RemoveRecipientArgs};
use sshenv_vault::models::UnlockFactorKindV2;
use sshenv_vault::{
    Vault,
    recipient::{fingerprint_from_recipient_descriptor, recipient_descriptor_kind},
};

use crate::commands::{
    Context as CmdContext, load_ciphertext_and_fps, save_vault, unlock_ciphertext,
};
use crate::identity::discover_public_key_paths;
use crate::picker::{PubkeyCandidate, select_pubkey_interactive};
use crate::pubkey::load_public_key;

pub fn add(ctx: &CmdContext, args: AddRecipientArgs) -> Result<()> {
    if args.hardware && args.key.is_none() {
        add_hardware_recipient()?;
    }
    let (ciphertext, existing) = load_ciphertext_and_fps(&ctx.vault_path)?;

    let (pubkey_line, incoming_fp) = resolve_new_recipient(args.key.as_deref(), &existing)?;
    if args.hardware
        && recipient_descriptor_kind(&pubkey_line) != UnlockFactorKindV2::HardwareRecipient
    {
        bail!("--hardware requires an age-plugin/hardware recipient descriptor such as age1...");
    }

    // Early exit on duplicate: the vault's add_recipient also rejects, but
    // we give a friendlier message here before loading identities.
    if existing.contains(&incoming_fp) {
        bail!("recipient {incoming_fp} is already registered; nothing to do");
    }

    let (mut vault, key) = unlock_ciphertext(ciphertext, &existing)?;

    let entry = vault.add_recipient(&pubkey_line, &key)?;
    let fingerprint = entry.fingerprint.clone();
    save_vault(ctx, &mut vault, &key)?;

    eprintln!("Added recipient {fingerprint}.");
    Ok(())
}

#[cfg(feature = "hardware-recipient")]
fn add_hardware_recipient() -> Result<()> {
    bail!(
        "hardware recipient discovery is not implemented yet; pass --key <age-plugin-recipient> with --hardware"
    )
}

#[cfg(not(feature = "hardware-recipient"))]
fn add_hardware_recipient() -> Result<()> {
    bail!("this sshenv build was compiled without hardware-recipient support")
}

/// Resolve the public descriptor for a new recipient, either from the
/// explicit `--key` argument or interactively from SSH pubkey autodiscovery.
/// Already-registered fingerprints are filtered out of the picker.
fn resolve_new_recipient(
    explicit: Option<&str>,
    existing_fingerprints: &HashSet<String>,
) -> Result<(String, String)> {
    if let Some(s) = explicit {
        let line = load_public_key(s)?;
        let fingerprint = fingerprint_from_recipient_descriptor(&line)
            .with_context(|| format!("failed to parse recipient descriptor from {s:?}"))?;
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
    let (ciphertext, existing) = load_ciphertext_and_fps(&ctx.vault_path)?;

    // Reject removing the last recipient — that would brick the vault.
    if ciphertext.recipients.len() <= 1 {
        bail!(
            "refusing to remove the only remaining recipient; add another \
             recipient first or delete the vault file explicitly"
        );
    }

    let (mut vault, key) = unlock_ciphertext(ciphertext, &existing)?;

    if !vault.remove_recipient(&args.fingerprint) {
        bail!("no recipient with fingerprint {}", args.fingerprint);
    }

    if args.rotate {
        let new_key =
            crate::commands::rekey::rotate_unlocked_vault(&mut vault, &args.recipient_keys)?;
        save_vault(ctx, &mut vault, &new_key)?;
        crate::security_state::clear_rotation_recommended(&ctx.vault_path)?;
        eprintln!(
            "Removed recipient {} and rotated vault data key.",
            args.fingerprint
        );
    } else {
        save_vault(ctx, &mut vault, &key)?;
        crate::security_state::mark_rotation_recommended(
            &ctx.vault_path,
            format!(
                "recipient {} was removed without rotating the vault data key",
                args.fingerprint
            ),
        )?;
        eprintln!("Removed recipient {}.", args.fingerprint);
        eprintln!(
            "warning: rotate the vault data key with `sshenv rotate-key` to reduce exposure from the removed recipient"
        );
    }
    Ok(())
}
