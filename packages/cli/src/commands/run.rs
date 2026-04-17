use std::process::Command;

use anyhow::{Context, Result, bail};
use sshenv_cli_models::RunArgs;
use sshenv_vault::Vault;

use crate::commands::Context as CmdContext;
use crate::identity::{error_no_identity_unlocked, load_identities};

pub fn run(ctx: &CmdContext, args: RunArgs) -> Result<()> {
    if args.command.is_empty() {
        bail!("no command provided; usage: sshenv run <profile> -- <cmd> [args...]");
    }

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

    // Build the child's command.
    let (cmd_name, cmd_args) = args
        .command
        .split_first()
        .expect("not empty, checked above");
    let mut child = Command::new(cmd_name);
    child.args(cmd_args);
    for (k, v) in vars {
        child.env(k, v);
    }

    // On Unix we prefer `exec`: replace this process entirely so nothing
    // about sshenv remains in the chain. On non-Unix we spawn + wait.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = child.exec();
        // exec only returns on failure.
        Err(err).with_context(|| format!("failed to exec {cmd_name}"))?;
        unreachable!()
    }

    #[cfg(not(unix))]
    {
        let status = child
            .status()
            .with_context(|| format!("failed to spawn {cmd_name}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
