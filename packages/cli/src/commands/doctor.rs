use anyhow::Result;
use sshenv_shims::{default_bindings_path, load_bindings, resolve_shim_dir};
use sshenv_vault::Vault;

use crate::commands::Context as CmdContext;
use crate::identity::{describe_available_identities, load_identities};

pub fn run(ctx: &CmdContext) -> Result<()> {
    let mut ok = true;

    println!("sshenv doctor");
    println!("=============");
    println!();

    // Vault.
    println!("Vault path: {}", ctx.vault_path.display());
    if !ctx.vault_path.exists() {
        println!("  - vault file does not exist; run `sshenv init` first.");
        ok = false;
    } else {
        match Vault::load_ciphertext(&ctx.vault_path) {
            Ok(ct) => {
                println!("  - parses OK");
                println!("  - recipients: {}", ct.recipients.len());
                for r in &ct.recipients {
                    println!("      {}", r.fingerprint);
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
    }

    // Identities.
    println!();
    println!("Available SSH private keys:");
    let paths = describe_available_identities();
    if paths.is_empty() {
        println!("  (none found in ~/.ssh/ or ~/.ssh/config)");
    } else {
        for p in &paths {
            println!("  {p}");
        }
    }

    // Try unlocking.
    if ctx.vault_path.exists() {
        println!();
        print!("Unlock check: ");
        let id_result = load_identities();
        match id_result {
            Ok(ids) if ids.is_empty() => {
                println!("no usable identities");
                ok = false;
            }
            Ok(ids) => match Vault::load_ciphertext(&ctx.vault_path) {
                Ok(ct) => match Vault::unlock(ct, &ids) {
                    Ok(_) => println!("ok"),
                    Err(_) => {
                        println!("no identity could unwrap the vault");
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
    }

    // Shims.
    println!();
    let bindings_path = default_bindings_path();
    println!("Bindings file: {}", bindings_path.display());
    let bindings = load_bindings(&bindings_path).unwrap_or_default();
    let shim_dir = resolve_shim_dir(&bindings);
    println!("Shim dir:      {}", shim_dir.display());
    println!("Bindings:      {}", bindings.bindings.len());

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
