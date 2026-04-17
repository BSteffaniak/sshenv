use anyhow::{Context, Result, bail};
use sshenv_cli_models::InitArgs;
use sshenv_vault::Vault;

use crate::commands::Context as CmdContext;
use crate::pubkey::load_public_key;

/// Create a brand-new vault at the configured path.
pub fn run(ctx: &CmdContext, args: InitArgs) -> Result<()> {
    if ctx.vault_path.exists() {
        bail!(
            "vault already exists at {}; refusing to overwrite",
            ctx.vault_path.display()
        );
    }

    let pubkey_input = args
        .recipient_key
        .context("--recipient-key is required for init in v1")?;
    let pubkey_line = load_public_key(&pubkey_input)?;

    let (vault, key) = Vault::create(&pubkey_line)?;
    vault.save(&ctx.vault_path, &key)?;

    eprintln!(
        "Created vault at {} with recipient {}.",
        ctx.vault_path.display(),
        vault
            .recipients
            .first()
            .map(|r| r.fingerprint.as_str())
            .unwrap_or("<none>")
    );
    Ok(())
}
