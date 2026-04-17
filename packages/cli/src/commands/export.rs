use anyhow::{Result, bail};
use sshenv_cli_models::ExportArgs;
use sshenv_vault::Vault;

use crate::commands::Context as CmdContext;
use crate::identity::{error_no_identity_unlocked, load_identities};

pub fn run(ctx: &CmdContext, args: ExportArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (vault, _key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    let Some(vars) = vault.profiles.get(&args.profile) else {
        bail!("no such profile: {}", args.profile);
    };

    for (k, v) in vars {
        // Single-quote the value and escape embedded quotes for sh compat.
        let escaped = v.replace('\'', r"'\''");
        println!("export {k}='{escaped}'");
    }
    Ok(())
}
