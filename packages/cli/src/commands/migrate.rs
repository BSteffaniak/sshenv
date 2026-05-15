use anyhow::{Result, bail};
use sshenv_cli_models::{MigrateVaultArgs, VaultFormatVersionArg};
use sshenv_vault::models::VERSION_V2;

use crate::commands::{
    Context as CmdContext, load_ciphertext_and_fps, save_vault, unlock_ciphertext,
};

pub fn run(ctx: &CmdContext, args: MigrateVaultArgs) -> Result<()> {
    match args.to {
        VaultFormatVersionArg::V2 => migrate_to_v2(ctx, &args.recipient_keys),
    }
}

fn migrate_to_v2(ctx: &CmdContext, recipient_keys: &[String]) -> Result<()> {
    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    if ciphertext.header.version == VERSION_V2 {
        eprintln!("Vault is already in v2 format.");
        return Ok(());
    }

    let (mut vault, data_key) = unlock_ciphertext(ciphertext, &recipients)?;
    let public_key_lines =
        crate::commands::rekey::resolve_current_recipient_public_key_lines(&vault, recipient_keys)?;
    vault.migrate_to_v2(&public_key_lines)?;
    if vault.header.version != VERSION_V2 {
        bail!("internal error: migration did not set v2 header");
    }
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Migrated vault to v2 policy format.");
    Ok(())
}
