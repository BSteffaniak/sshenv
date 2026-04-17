use anyhow::{Context, Result, bail};
use sshenv_cli_models::{ListArgs, RmProfileArgs, SetArgs, ShowArgs, UnsetArgs};
use zeroize::Zeroizing;

use crate::commands::{Context as CmdContext, load_and_unlock};

pub fn set(ctx: &CmdContext, args: SetArgs) -> Result<()> {
    let value = resolve_value(&args)?;

    let (mut vault, key) = load_and_unlock(&ctx.vault_path)?;

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
    let (mut vault, key) = load_and_unlock(&ctx.vault_path)?;

    if !vault.profiles.unset(&args.profile, &args.var) {
        bail!("no such variable: {}/{}", args.profile, args.var);
    }
    vault.save(&ctx.vault_path, &key)?;
    eprintln!("Unset {}/{}.", args.profile, args.var);
    Ok(())
}

pub fn list(ctx: &CmdContext, args: ListArgs) -> Result<()> {
    let (vault, _key) = load_and_unlock(&ctx.vault_path)?;

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
    let (vault, _key) = load_and_unlock(&ctx.vault_path)?;

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
    let (mut vault, key) = load_and_unlock(&ctx.vault_path)?;

    if !vault.profiles.remove_profile(&args.profile) {
        bail!("no such profile: {}", args.profile);
    }
    vault.save(&ctx.vault_path, &key)?;
    eprintln!("Removed profile {}.", args.profile);
    Ok(())
}
