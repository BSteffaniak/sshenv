use std::collections::HashSet;

use anyhow::Result;
use sshenv_shims::{default_bindings_path, load_bindings_merged, resolve_shim_dir};
use sshenv_vault::Vault;

use crate::commands::Context as CmdContext;
use crate::identity::{
    discover_private_key_paths, load_identities, load_identities_for_vault,
    public_fingerprint_for_private_key,
};

pub fn run(ctx: &CmdContext) -> Result<()> {
    let mut ok = true;

    println!("sshenv doctor");
    println!("=============");
    println!();

    // Vault.
    println!("Vault path: {}", ctx.vault_path.display());
    let mut vault_recipient_fps: Option<HashSet<String>> = None;
    if ctx.vault_path.exists() {
        match Vault::load_ciphertext(&ctx.vault_path) {
            Ok(ct) => {
                println!("  - parses OK");
                println!("  - recipients: {}", ct.recipients.len());
                let mut fps = HashSet::new();
                for r in &ct.recipients {
                    println!("      {}", r.fingerprint);
                    fps.insert(r.fingerprint.clone());
                }
                vault_recipient_fps = Some(fps);
                match crate::security_state::rotation_recommendation(&ctx.vault_path) {
                    Ok(Some(reason)) => {
                        println!("  - data-key rotation: recommended ({reason})");
                        ok = false;
                    }
                    Ok(None) => println!("  - data-key rotation: no local reminder"),
                    Err(error) => {
                        println!("  - data-key rotation: unknown ({error})");
                        ok = false;
                    }
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&ctx.vault_path) {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode == 0o600 {
                            println!("  - permissions: 0600 (ok)");
                        } else {
                            println!("  - permissions: {mode:04o} (expected 0600)");
                        }
                    }
                }
            }
            Err(err) => {
                println!("  - failed to parse: {err}");
                ok = false;
            }
        }
    } else {
        println!("  - vault file does not exist; run `sshenv init` first.");
        ok = false;
    }

    // Identities — annotate each with authorization status when we have a
    // vault to compare against.
    println!();
    println!("Available SSH private keys:");
    let key_paths = discover_private_key_paths();
    if key_paths.is_empty() {
        println!("  (none found in ~/.ssh/ or ~/.ssh/config)");
    } else {
        for path in &key_paths {
            let annotation = match (
                &vault_recipient_fps,
                public_fingerprint_for_private_key(path),
            ) {
                (Some(recipients), Some(fp)) => {
                    if recipients.contains(&fp) {
                        format!("  {fp}  (authorized)")
                    } else {
                        format!("  {fp}  (not a recipient)")
                    }
                }
                (_, Some(fp)) => format!("  {fp}"),
                (_, None) => "  (no .pub sibling)".to_string(),
            };
            println!("  {}{annotation}", path.display());
        }
    }

    // Try unlocking.
    if let Some(fps) = &vault_recipient_fps {
        println!();
        print!("Unlock check: ");
        let id_result = load_identities_for_vault(fps);
        match id_result {
            Ok(ids) if ids.is_empty() => {
                println!("no SSH key on this host matches a vault recipient");
                ok = false;
            }
            Ok(ids) => match Vault::load_ciphertext(&ctx.vault_path) {
                Ok(ct) => match Vault::unlock(ct, &ids) {
                    Ok(_) => println!("ok"),
                    Err(_) => {
                        println!("a matching key was found but decryption failed");
                        ok = false;
                    }
                },
                Err(err) => {
                    println!("vault not loadable: {err}");
                    ok = false;
                }
            },
            Err(err) => {
                println!("error: {err}");
                ok = false;
            }
        }
    } else if ctx.vault_path.exists() {
        // Vault exists but couldn't be parsed above; fall back to the
        // unfiltered identity loader purely so we can report something.
        println!();
        print!("Unlock check: ");
        match load_identities() {
            Ok(ids) if ids.is_empty() => {
                println!("no SSH identities available");
                ok = false;
            }
            Ok(_) => println!("(skipped; vault not parseable)"),
            Err(err) => {
                println!("error: {err}");
                ok = false;
            }
        }
    }

    // Shims.
    println!();
    let bindings_path = default_bindings_path();
    println!("Bindings file: {}", bindings_path.display());
    let bindings_d = sshenv_shims::bindings_d_dir();
    if bindings_d.exists() {
        println!(
            "Bindings.d:    {} ({} fragments)",
            bindings_d.display(),
            sshenv_shims::discover_bindings_fragments()
                .map(|v| v.len())
                .unwrap_or(0)
        );
    }
    let bindings = load_bindings_merged().unwrap_or_default();
    let shim_dir = resolve_shim_dir(&bindings);
    println!("Shim dir:      {}", shim_dir.display());
    println!("Effective bindings: {}", bindings.bindings.len());

    // PATH sanity.
    let path_env = std::env::var("PATH").unwrap_or_default();
    let shim_dir_str = shim_dir.display().to_string();
    let on_path = path_env.split(':').any(|p| {
        p == shim_dir_str || p.trim_end_matches('/') == shim_dir_str.trim_end_matches('/')
    });
    println!(
        "PATH:          {}",
        if on_path {
            "shim dir is on PATH"
        } else {
            "shim dir NOT on PATH (shims will not activate)"
        }
    );
    if !bindings.bindings.is_empty() && !on_path {
        ok = false;
    }

    println!();
    println!("Result: {}", if ok { "ok" } else { "problems detected" });
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
