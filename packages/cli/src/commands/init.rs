use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use sshenv_cli_models::InitArgs;
use sshenv_vault::{Vault, recipient::fingerprint_from_line};

use crate::commands::Context as CmdContext;
use crate::identity::discover_public_key_paths;
use crate::picker::{PubkeyCandidate, select_pubkey_interactive};
use crate::pubkey::load_public_key;

/// Create a brand-new vault at the configured path.
pub fn run(ctx: &CmdContext, args: InitArgs) -> Result<()> {
    if ctx.vault_path.exists() {
        bail!(
            "vault already exists at {}; refusing to overwrite",
            ctx.vault_path.display()
        );
    }

    let (line, fingerprint) = resolve_recipient(args.recipient_key.as_deref())?;

    let (vault, key) = Vault::create(&line)?;
    vault.save(&ctx.vault_path, &key)?;

    eprintln!(
        "Created vault at {} with recipient {fingerprint}.",
        ctx.vault_path.display()
    );
    Ok(())
}

/// Resolve which SSH public key line to use as the initial recipient.
///
/// If `explicit` is `Some`, load it as-is (path-or-line). Otherwise,
/// autodiscover `~/.ssh/*.pub` candidates and present them interactively.
fn resolve_recipient(explicit: Option<&str>) -> Result<(String, String)> {
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
            Ok(c) => candidates.push(c),
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
