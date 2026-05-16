use anyhow::{Context, Result, bail};
use sshenv_cli_models::{ListArgs, RenameProfileArgs, RmProfileArgs, SetArgs, ShowArgs, UnsetArgs};
use sshenv_shims::{
    default_bindings_path, load_bindings, resolve_shim_dir, save_bindings, sync_shims,
};
use zeroize::Zeroizing;

use crate::commands::{
    Context as CmdContext, load_and_unlock, load_and_unlock_profile, save_vault,
};

pub fn set(ctx: &CmdContext, args: SetArgs) -> Result<()> {
    let value = resolve_value(&args)?;

    let (mut vault, key) = load_and_unlock(&ctx.vault_path)?;

    vault
        .profiles
        .set(&args.profile, &args.var, value.as_str().to_string());
    save_vault(ctx, &mut vault, &key)?;
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
    save_vault(ctx, &mut vault, &key)?;
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
    let (vault, _key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;

    let Some(vars) = vault.profiles.get(&args.profile) else {
        bail!("no such profile: {}", args.profile);
    };
    crate::commands::security::ensure_profile_factor_requirements_met(&vault, &args.profile)?;
    crate::commands::security::warn_if_profile_policy_unmet(&vault, &args.profile);
    crate::commands::security::warn_if_high_security_profile_stdout(&vault, &args.profile, "show");

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
    save_vault(ctx, &mut vault, &key)?;
    eprintln!("Removed profile {}.", args.profile);
    Ok(())
}

pub fn rename(ctx: &CmdContext, args: RenameProfileArgs) -> Result<()> {
    let (mut vault, key) = load_and_unlock(&ctx.vault_path)?;

    let vault_changed = vault.profiles.rename_profile(&args.from, &args.to)?;
    if vault_changed {
        save_vault(ctx, &mut vault, &key)?;
        eprintln!("Renamed profile {} -> {}.", args.from, args.to);
    } else {
        eprintln!(
            "Profile {} is already named {}; no changes.",
            args.from, args.to
        );
    }

    let bindings_path = default_bindings_path();
    let mut bindings = load_bindings(&bindings_path)?;
    let changed_bindings = bindings.rename_profile(&args.from, &args.to);
    if changed_bindings == 0 {
        return Ok(());
    }

    save_bindings(&bindings_path, &bindings)?;
    let shim_dir = resolve_shim_dir(&bindings);
    let (wrote, removed) = sync_shims(&shim_dir, &bindings)?;
    eprintln!(
        "Updated {changed_bindings} shim binding(s). Regenerated shims in {} ({wrote} wrote, {removed} removed).",
        shim_dir.display()
    );
    Ok(())
}
