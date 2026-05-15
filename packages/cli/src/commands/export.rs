use anyhow::{Result, bail};
use sshenv_cli_models::ExportArgs;

use crate::commands::{Context as CmdContext, load_and_unlock};

pub fn run(ctx: &CmdContext, args: ExportArgs) -> Result<()> {
    let (vault, _key) = load_and_unlock(&ctx.vault_path)?;

    let Some(vars) = vault.profiles.get(&args.profile) else {
        bail!("no such profile: {}", args.profile);
    };
    crate::commands::security::ensure_profile_factor_requirements_met(&vault, &args.profile)?;
    crate::commands::security::warn_if_profile_policy_unmet(&vault, &args.profile);

    for (k, v) in vars {
        // Single-quote the value and escape embedded quotes for sh compat.
        let escaped = v.replace('\'', r"'\''");
        println!("export {k}='{escaped}'");
    }
    Ok(())
}
