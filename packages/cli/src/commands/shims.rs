use anyhow::{Context, Result};
use sshenv_cli_models::{ShimsBindArgs, ShimsRenameArgs, ShimsUnbindArgs};
use sshenv_shims::{
    default_bindings_path, load_bindings, load_bindings_merged, resolve_shim_dir, save_bindings,
    sync_shims,
};

use crate::commands::Context as CmdContext;

pub fn bind(_ctx: &CmdContext, args: ShimsBindArgs) -> Result<()> {
    let bindings_path = default_bindings_path();
    let mut bindings = load_bindings(&bindings_path)?;
    let changed = bindings
        .add(&args.profile, &args.command)
        .with_context(|| {
            format!(
                "failed to bind command '{}' to profile '{}'",
                args.command, args.profile
            )
        })?;
    save_bindings(&bindings_path, &bindings)?;

    if changed {
        let shim_dir = resolve_shim_dir(&bindings);
        let (wrote, removed) = sync_shims(&shim_dir, &bindings)?;
        eprintln!(
            "Bound '{}' -> profile '{}'. Regenerated shims in {} ({wrote} wrote, {removed} removed).",
            args.command,
            args.profile,
            shim_dir.display()
        );
    } else {
        eprintln!(
            "'{}' is already bound to '{}'; no changes.",
            args.command, args.profile
        );
    }
    Ok(())
}

pub fn unbind(_ctx: &CmdContext, args: ShimsUnbindArgs) -> Result<()> {
    let bindings_path = default_bindings_path();
    let mut bindings = load_bindings(&bindings_path)?;

    if !bindings.remove_by_command(&args.command) {
        eprintln!("'{}' is not bound; nothing to do.", args.command);
        return Ok(());
    }
    save_bindings(&bindings_path, &bindings)?;
    let shim_dir = resolve_shim_dir(&bindings);
    let (wrote, removed) = sync_shims(&shim_dir, &bindings)?;
    eprintln!(
        "Unbound '{}'. Regenerated shims in {} ({wrote} wrote, {removed} removed).",
        args.command,
        shim_dir.display()
    );
    Ok(())
}

pub fn rename(_ctx: &CmdContext, args: ShimsRenameArgs) -> Result<()> {
    let bindings_path = default_bindings_path();
    let mut bindings = load_bindings(&bindings_path)?;
    let changed = bindings
        .rename_command(&args.command, &args.to)
        .with_context(|| {
            format!(
                "failed to rename shim command '{}' to '{}'",
                args.command, args.to
            )
        })?;

    if !changed {
        eprintln!(
            "'{}' is already named '{}'; no changes.",
            args.command, args.to
        );
        return Ok(());
    }

    save_bindings(&bindings_path, &bindings)?;
    let shim_dir = resolve_shim_dir(&bindings);
    let (wrote, removed) = sync_shims(&shim_dir, &bindings)?;
    eprintln!(
        "Renamed shim command '{}' -> '{}'. Regenerated shims in {} ({wrote} wrote, {removed} removed).",
        args.command,
        args.to,
        shim_dir.display()
    );
    Ok(())
}

pub fn list(_ctx: &CmdContext) -> Result<()> {
    let bindings = load_bindings_merged()?;
    if bindings.bindings.is_empty() {
        eprintln!("(no bindings)");
        return Ok(());
    }

    // Sort for stable, readable output
    let mut items: Vec<_> = bindings.bindings.iter().collect();
    items.sort_by(|a, b| a.command.cmp(&b.command));

    let max_len = items.iter().map(|b| b.command.len()).max().unwrap_or(0);
    let width = max_len.max(20);

    // Header
    println!("{:<width$}  PROFILE", "COMMAND", width = width);
    println!("{:-<width$}  -------", "", width = width);

    for b in items {
        println!("{:<width$}  {}", b.command, b.profile, width = width);
    }
    Ok(())
}

pub fn sync(_ctx: &CmdContext) -> Result<()> {
    let bindings = load_bindings_merged()?;
    let shim_dir = resolve_shim_dir(&bindings);
    let (wrote, removed) = sync_shims(&shim_dir, &bindings)?;
    eprintln!(
        "Synced shims in {} ({wrote} wrote, {removed} removed).",
        shim_dir.display()
    );
    Ok(())
}

pub fn dir(_ctx: &CmdContext) -> Result<()> {
    let bindings = load_bindings_merged().unwrap_or_default();
    println!("{}", resolve_shim_dir(&bindings).display());
    Ok(())
}

pub fn path(_ctx: &CmdContext) -> Result<()> {
    let bindings = load_bindings_merged().unwrap_or_default();
    let dir = resolve_shim_dir(&bindings);
    println!(
        "# Add this to your shell rc to make sshenv shims active.\n\
         export PATH=\"{}:$PATH\"",
        dir.display()
    );
    Ok(())
}
