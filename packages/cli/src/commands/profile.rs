use anyhow::{Context, Result, bail};
use sshenv_cli_models::{ListArgs, RmProfileArgs, SetArgs, ShowArgs, UnsetArgs};
use sshenv_vault::Vault;
use zeroize::Zeroizing;

use crate::commands::Context as CmdContext;
use crate::identity::{error_no_identity_unlocked, load_identities};

pub fn set(ctx: &CmdContext, args: SetArgs) -> Result<()> {
    let value = resolve_value(&args)?;

    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (mut vault, key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    vault
        .profiles
        .set(&args.profile, &args.var, value.as_str().to_string());
    vault.save(&ctx.vault_path, &key)?;
    eprintln!("Set {}/{}.", args.profile, args.var);
    Ok(())
}

fn resolve_value(args: &SetArgs) -> Result<Zeroizing<String>> {
    if let Some(v) = &args.value {
        return Ok(Zeroizing::new(v.clone()));
    }
    let prompt = format!("Value for {}/{}: ", args.profile, args.var);
    let raw = rpassword::prompt_password(prompt).context("failed to read value from terminal")?;
    if raw.is_empty() {
        bail!("value is empty; aborting");
    }
    Ok(Zeroizing::new(raw))
}

pub fn unset(ctx: &CmdContext, args: UnsetArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (mut vault, key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    if !vault.profiles.unset(&args.profile, &args.var) {
        bail!("no such variable: {}/{}", args.profile, args.var);
    }
    vault.save(&ctx.vault_path, &key)?;
    eprintln!("Unset {}/{}.", args.profile, args.var);
    Ok(())
}

pub fn list(ctx: &CmdContext, args: ListArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (vault, _key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    match args.profile {
        Some(profile) => {
            let Some(vars) = vault.profiles.get(&profile) else {
                bail!("no such profile: {profile}");
            };
            for name in vars.keys() {
                println!("{name}");
            }
        }
        None => {
            let names = vault.profiles.profile_names();
            let filtered: Vec<&String> = match &args.prefix {
                Some(p) => names.iter().filter(|n| n.starts_with(p.as_str())).collect(),
                None => names.iter().collect(),
            };
            for name in filtered {
                println!("{name}");
            }
        }
    }
    Ok(())
}

pub fn show(ctx: &CmdContext, args: ShowArgs) -> Result<()> {
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

    eprintln!(
        "warning: printing secret values for profile '{}' to stdout.",
        args.profile
    );
    for (k, v) in vars {
        println!("{k}={v}");
    }
    Ok(())
}

pub fn rm(ctx: &CmdContext, args: RmProfileArgs) -> Result<()> {
    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let identities = load_identities()?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked());
    }
    let (mut vault, key) =
        Vault::unlock(ciphertext, &identities).map_err(|_| error_no_identity_unlocked())?;

    if !vault.profiles.remove_profile(&args.profile) {
        bail!("no such profile: {}", args.profile);
    }
    vault.save(&ctx.vault_path, &key)?;
    eprintln!("Removed profile {}.", args.profile);
    Ok(())
}
