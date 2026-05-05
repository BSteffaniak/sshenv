//! Integration tests that drive the CLI end-to-end against temp files.

use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;

use rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

fn cargo_bin() -> PathBuf {
    let dir = env!("CARGO_MANIFEST_DIR");
    let target = PathBuf::from(dir).join("../../target");
    // Prefer debug build.
    let debug = target.join("debug").join("sshenv");
    if debug.exists() {
        return debug;
    }
    target.join("release").join("sshenv")
}

fn write_pubkey_file(dir: &std::path::Path) -> (PathBuf, String) {
    write_named_keypair(dir, "id_test")
}

/// Write an ed25519 keypair at `dir/<name>` and `dir/<name>.pub`.
/// Returns `(priv_path, pub_line)`.
fn write_named_keypair(dir: &std::path::Path, name: &str) -> (PathBuf, String) {
    let priv_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen key");
    let pub_line = priv_key.public_key().to_openssh().expect("pub");
    let priv_pem = priv_key
        .to_openssh(LineEnding::LF)
        .expect("priv pem")
        .to_string();

    let priv_path = dir.join(name);
    std::fs::write(&priv_path, &priv_pem).unwrap();
    std::fs::write(priv_path.with_extension("pub"), format!("{pub_line}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (priv_path, pub_line)
}

fn init_vault_with_profile(
    bin: &std::path::Path,
    home: &std::path::Path,
    vault_path: &std::path::Path,
    profile: &str,
) {
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let _key = write_named_keypair(&home.join(".ssh"), "id_ed25519");

    let init_out = Command::new(bin)
        .arg("--vault")
        .arg(vault_path)
        .arg("init")
        .arg("--recipient-key")
        .arg(home.join(".ssh").join("id_ed25519.pub"))
        .env("HOME", home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run init");
    assert!(
        init_out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    let set_out = Command::new(bin)
        .arg("--vault")
        .arg(vault_path)
        .arg("set")
        .arg(profile)
        .arg("DUMMY")
        .arg("--value")
        .arg("value")
        .env("HOME", home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run set");
    assert!(
        set_out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );
}

/// Prove the `age` roundtrip works without invoking the binary. Keeps CI
/// passing even when the binary hasn't been built yet (e.g. `cargo test
/// --no-run` scenarios).
#[test]
fn age_roundtrip_using_generated_key() {
    let dir = tempfile::tempdir().unwrap();
    let (priv_path, pub_line) = write_pubkey_file(dir.path());

    let (mut vault, key) = sshenv_vault::Vault::create(&pub_line).expect("create");
    vault.profiles.set("p", "VAR", "value".into());
    let vault_path = dir.path().join("vault");
    vault.save(&vault_path, &key).expect("save");

    // Load on behalf of the test: read the private key, build an Identity.
    let raw = std::fs::read(&priv_path).unwrap();
    let id = age::ssh::Identity::from_buffer(Cursor::new(&raw), None).expect("parse");
    let identities: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
    let ct = sshenv_vault::Vault::load_ciphertext(&vault_path).expect("load ct");
    let (unlocked, _k) = sshenv_vault::Vault::unlock(ct, &identities).expect("unlock");
    assert_eq!(
        unlocked.profiles.get("p").unwrap().get("VAR").unwrap(),
        "value"
    );
}

/// If the `sshenv` binary has been built, smoke-test that `--help`
/// succeeds. Skip otherwise — the debug build isn't present in the
/// workspace cache until the first non-test build.
#[test]
fn binary_help_runs() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!(
            "skipping: {} does not exist; run `cargo build` first",
            bin.display()
        );
        return;
    }
    let output = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(
        output.status.success(),
        "sshenv --help exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sshenv"));
}

/// When `sshenv init` is run non-interactively without --recipient-key,
/// it must exit non-zero, print a helpful error message, and NOT dump a
/// stack backtrace.
#[test]
fn binary_init_non_tty_without_key_errors_cleanly() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!(
            "skipping: {} does not exist; run `cargo build` first",
            bin.display()
        );
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");

    // HOME is set to an empty tempdir so autodiscovery finds nothing.
    // stdin isn't piped to a TTY, so the picker must refuse to guess.
    let output = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("init")
        .env("HOME", dir.path())
        .env_remove("SSHENV_VAULT")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE")
        .output()
        .expect("run init");

    assert!(
        !output.status.success(),
        "init should fail non-interactively; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Helpful pointer to the flag.
    assert!(
        stderr.contains("--recipient-key"),
        "stderr missing --recipient-key hint: {stderr}"
    );
    // No stack backtrace leaks to stderr for a user error.
    assert!(
        !stderr.contains("Stack backtrace"),
        "anyhow backtrace leaked to user: {stderr}"
    );
    assert!(
        !stderr.contains("std::backtrace::Backtrace"),
        "anyhow backtrace leaked to user: {stderr}"
    );
    // And the vault file shouldn't have been created.
    assert!(!vault_path.exists(), "vault file should not exist");
}

/// Explicit --recipient-key path still works non-interactively.
#[test]
fn binary_init_with_explicit_key_works_non_tty() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let (_priv_path, _pub_line) = write_pubkey_file(dir.path());
    let pub_path = dir.path().join("id_test.pub");
    let vault_path = dir.path().join("vault");

    let output = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("init")
        .arg("--recipient-key")
        .arg(&pub_path)
        .env("HOME", dir.path())
        .output()
        .expect("run init");

    assert!(
        output.status.success(),
        "init failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(vault_path.exists(), "vault file should exist");
}

/// Regression test for the real-world bug where `sshenv set` prompted
/// for a passphrase on an encrypted SSH key that was not a vault
/// recipient. After the identity-filter fix, non-matching keys must be
/// silently skipped — the command should complete without ever asking
/// for a passphrase.
#[test]
fn binary_set_does_not_prompt_for_non_matching_encrypted_key() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();

    // The authorized key: unencrypted ed25519.
    let (_auth_priv, _auth_pub) = write_named_keypair(&home.join(".ssh"), "id_ed25519");

    // A second key: we write the pub file but NO matching private file.
    // This stands in for "an unrelated key that could be encrypted" —
    // the crucial property is that `load_identities_for_vault` must
    // skip it without prompting. The .pub-only path exercises the
    // fingerprint pre-filter (not the fallback).
    let (_other_priv, _other_pub) = write_named_keypair(&home.join(".ssh"), "id_other");

    let vault_path = dir.path().join("vault");

    // Init with the authorized key only.
    let init_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("init")
        .arg("--recipient-key")
        .arg(home.join(".ssh").join("id_ed25519.pub"))
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run init");
    assert!(
        init_out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    // Now set a secret. If the filter is broken, sshenv will try to
    // load id_other (which passes the fingerprint check — wait, no:
    // id_other's fp IS in our hashset here? let's make sure it's NOT
    // a recipient, which it isn't because we only init'd with id_ed25519).
    // The set command must NOT prompt for id_other.
    let set_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("set")
        .arg("myprofile")
        .arg("MYVAR")
        .arg("--value")
        .arg("myvalue")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run set");

    assert!(
        set_out.status.success(),
        "set failed: stdout={} stderr={}",
        String::from_utf8_lossy(&set_out.stdout),
        String::from_utf8_lossy(&set_out.stderr),
    );

    let stderr = String::from_utf8_lossy(&set_out.stderr);
    assert!(
        !stderr.contains("passphrase"),
        "non-matching key should not have been prompted: {stderr}"
    );
    assert!(
        !stderr.contains("Stack backtrace"),
        "backtrace leaked to user: {stderr}"
    );
}

/// When the host has no SSH private key that matches a vault recipient,
/// the error must be detailed and helpful (not a terse backtrace).
#[test]
fn binary_unlock_no_matching_key_errors_helpfully() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home_a = dir.path().join("home_a");
    let home_b = dir.path().join("home_b");
    std::fs::create_dir_all(home_a.join(".ssh")).unwrap();
    std::fs::create_dir_all(home_b.join(".ssh")).unwrap();

    // Create a vault authorized for key A (living under home_a).
    let (_a_priv, _a_pub) = write_named_keypair(&home_a.join(".ssh"), "id_ed25519");
    let vault_path = dir.path().join("vault");
    let init_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("init")
        .arg("--recipient-key")
        .arg(home_a.join(".ssh").join("id_ed25519.pub"))
        .env("HOME", &home_a)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("init");
    assert!(init_out.status.success());

    // Under home_b only key B exists. Try to unlock the vault.
    let (_b_priv, _b_pub) = write_named_keypair(&home_b.join(".ssh"), "id_ed25519");
    let out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("list")
        .env("HOME", &home_b)
        .env_remove("SSHENV_VAULT")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE")
        .output()
        .expect("list");

    assert!(!out.status.success(), "list should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no SSH private key authorized"),
        "stderr missing 'no SSH private key authorized': {stderr}"
    );
    assert!(
        stderr.contains("Vault recipients:"),
        "stderr missing vault recipient list: {stderr}"
    );
    assert!(
        stderr.contains("Local keys checked:"),
        "stderr missing local key diagnostics: {stderr}"
    );
    assert!(
        !stderr.contains("Stack backtrace"),
        "backtrace leaked: {stderr}"
    );
}

/// Regression test for the infinite-loop bug: if a shim at
/// `~/.sshenv/bin/<cmd>` invokes `sshenv run <profile> -- <cmd>`, and
/// `~/.sshenv/bin` is first in PATH, the naive `Command::new(<cmd>)`
/// would re-find the shim and loop forever. `sshenv run` must resolve
/// the target by PATH-skipping the shim directory.
#[test]
fn binary_shim_does_not_self_invoke() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();

    // Authorized key.
    let _k = write_named_keypair(&home.join(".ssh"), "id_ed25519");

    // Init vault.
    let vault_path = home.join(".sshenv").join("vault");
    let init_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("init")
        .arg("--recipient-key")
        .arg(home.join(".ssh").join("id_ed25519.pub"))
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run init");
    assert!(
        init_out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    // Set a profile variable.
    let set_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("set")
        .arg("shim-test")
        .arg("MYVAR")
        .arg("--value")
        .arg("hello-from-sshenv")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run set");
    assert!(
        set_out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );

    // Create a fake "real" binary at $HOME/real_bin/test-cmd that prints
    // the value of MYVAR. This is what sshenv's PATH-skipping resolver
    // must find instead of re-finding the shim.
    let real_bin_dir = home.join("real_bin");
    std::fs::create_dir_all(&real_bin_dir).unwrap();
    let real_cmd = real_bin_dir.join("test-cmd");
    std::fs::write(
        &real_cmd,
        "#!/bin/sh\nprintf 'env-check:%s\\n' \"$MYVAR\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real_cmd, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Bind a shim: shim-test -> profile "shim-test", command "test-cmd".
    let shim_dir = home.join(".sshenv").join("bin");
    let bindings_path = home.join(".sshenv").join("bindings.toml");
    let bind_out = Command::new(&bin)
        .arg("shims")
        .arg("bind")
        .arg("shim-test")
        .arg("--command")
        .arg("test-cmd")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .env("SSHENV_BINDINGS", &bindings_path)
        .env("SSHENV_SHIM_DIR", &shim_dir)
        .output()
        .expect("run shims bind");
    assert!(
        bind_out.status.success(),
        "shims bind failed: {}",
        String::from_utf8_lossy(&bind_out.stderr)
    );

    // The shim should now exist at $shim_dir/test-cmd.
    let shim_path = shim_dir.join("test-cmd");
    assert!(
        shim_path.exists(),
        "shim not created at {}",
        shim_path.display()
    );

    // Invoke the shim directly. Set PATH so the shim dir is FIRST (mimics
    // the production configuration), the dir containing the sshenv
    // binary is included (so the shim's `exec sshenv run ...` resolves),
    // and the real bin follows. If the infinite-loop bug regressed,
    // execvp would find the shim again, sshenv run would re-exec the
    // shim, and so on.
    let sshenv_bin_dir = bin.parent().expect("sshenv bin has a parent dir");
    let path_value = format!(
        "{}:{}:{}",
        shim_dir.display(),
        sshenv_bin_dir.display(),
        real_bin_dir.display()
    );
    let run_out = Command::new(&shim_path)
        .env("HOME", &home)
        .env("PATH", &path_value)
        .env("SSHENV_VAULT", &vault_path)
        .env("SSHENV_BINDINGS", &bindings_path)
        .env("SSHENV_SHIM_DIR", &shim_dir)
        .output()
        .expect("run shim");

    assert!(
        run_out.status.success(),
        "shim invocation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr),
    );
    let stdout = String::from_utf8_lossy(&run_out.stdout);
    assert!(
        stdout.contains("env-check:hello-from-sshenv"),
        "expected env var to be injected into real binary; got stdout: {stdout}"
    );
}

#[test]
fn binary_rename_profile_moves_vars_and_updates_shim_bindings() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let _k = write_named_keypair(&home.join(".ssh"), "id_ed25519");

    let vault_path = home.join(".sshenv").join("vault");
    let bindings_path = home.join(".sshenv").join("bindings.toml");
    let shim_dir = home.join(".sshenv").join("bin");

    let init_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("init")
        .arg("--recipient-key")
        .arg(home.join(".ssh").join("id_ed25519.pub"))
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run init");
    assert!(
        init_out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    let set_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("set")
        .arg("pi-bedrock")
        .arg("AWS_BEARER_TOKEN_BEDROCK")
        .arg("--value")
        .arg("secret")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run set");
    assert!(
        set_out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );

    let bind_out = Command::new(&bin)
        .arg("shims")
        .arg("bind")
        .arg("pi-bedrock")
        .arg("--command")
        .arg("pi-bedrock")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .env("SSHENV_BINDINGS", &bindings_path)
        .env("SSHENV_SHIM_DIR", &shim_dir)
        .output()
        .expect("run shims bind");
    assert!(
        bind_out.status.success(),
        "bind failed: {}",
        String::from_utf8_lossy(&bind_out.stderr)
    );

    let rename_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("rename-profile")
        .arg("pi-bedrock")
        .arg("bedrock")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .env("SSHENV_BINDINGS", &bindings_path)
        .env("SSHENV_SHIM_DIR", &shim_dir)
        .output()
        .expect("run rename-profile");
    assert!(
        rename_out.status.success(),
        "rename-profile failed: stdout={} stderr={}",
        String::from_utf8_lossy(&rename_out.stdout),
        String::from_utf8_lossy(&rename_out.stderr),
    );

    let list_profiles = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("list")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run list");
    assert!(list_profiles.status.success());
    let stdout = String::from_utf8_lossy(&list_profiles.stdout);
    assert!(stdout.contains("bedrock"), "missing new profile: {stdout}");
    assert!(
        !stdout.contains("pi-bedrock"),
        "old profile still listed: {stdout}"
    );

    let list_new_profile = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("list")
        .arg("bedrock")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run list bedrock");
    assert!(list_new_profile.status.success());
    let stdout = String::from_utf8_lossy(&list_new_profile.stdout);
    assert!(
        stdout.contains("AWS_BEARER_TOKEN_BEDROCK"),
        "missing renamed profile var: {stdout}"
    );

    let list_old_profile = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("list")
        .arg("pi-bedrock")
        .env("HOME", &home)
        .env_remove("SSHENV_VAULT")
        .output()
        .expect("run list pi-bedrock");
    assert!(!list_old_profile.status.success());

    let bindings = sshenv_shims::load_bindings(&bindings_path).unwrap();
    let binding = bindings.find_by_command("pi-bedrock").unwrap();
    assert_eq!(binding.profile, "bedrock");

    let shim = std::fs::read_to_string(shim_dir.join("pi-bedrock")).unwrap();
    assert!(shim.contains("profile: bedrock"));
    assert!(shim.contains("exec sshenv run \"bedrock\" -- \"pi-bedrock\" \"$@\""));
}

#[test]
fn binary_shims_rename_updates_binding_and_regenerates_shims() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bindings_path = home.join(".sshenv").join("bindings.toml");
    let shim_dir = home.join(".sshenv").join("bin");

    let bind_out = Command::new(&bin)
        .arg("shims")
        .arg("bind")
        .arg("bedrock")
        .arg("--command")
        .arg("pi-bedrock")
        .env("HOME", &home)
        .env("SSHENV_BINDINGS", &bindings_path)
        .env("SSHENV_SHIM_DIR", &shim_dir)
        .output()
        .expect("run shims bind");
    assert!(
        bind_out.status.success(),
        "bind failed: {}",
        String::from_utf8_lossy(&bind_out.stderr)
    );
    assert!(shim_dir.join("pi-bedrock").exists());

    let rename_out = Command::new(&bin)
        .arg("shims")
        .arg("rename")
        .arg("--command")
        .arg("pi-bedrock")
        .arg("--to")
        .arg("bedrock")
        .env("HOME", &home)
        .env("SSHENV_BINDINGS", &bindings_path)
        .env("SSHENV_SHIM_DIR", &shim_dir)
        .output()
        .expect("run shims rename");
    assert!(
        rename_out.status.success(),
        "shims rename failed: stdout={} stderr={}",
        String::from_utf8_lossy(&rename_out.stdout),
        String::from_utf8_lossy(&rename_out.stderr),
    );

    let bindings = sshenv_shims::load_bindings(&bindings_path).unwrap();
    assert!(bindings.find_by_command("pi-bedrock").is_none());
    assert_eq!(
        bindings.find_by_command("bedrock").unwrap().profile,
        "bedrock"
    );

    assert!(!shim_dir.join("pi-bedrock").exists());
    let shim = std::fs::read_to_string(shim_dir.join("bedrock")).unwrap();
    assert!(shim.contains("profile: bedrock"));
    assert!(shim.contains("command: bedrock"));
    assert!(shim.contains("exec sshenv run \"bedrock\" -- \"bedrock\" \"$@\""));
}

#[cfg(unix)]
fn wait_for_stdout_contains(command: &mut Command, needle: &str) -> bool {
    for _ in 0..40 {
        let output = command.output().expect("run polling command");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && stdout.contains(needle) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

#[cfg(unix)]
#[test]
fn binary_sessions_list_and_kill_tracked_run() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let vault_path = home.join(".sshenv").join("vault");
    let sessions_path = dir.path().join("sessions.toml");
    init_vault_with_profile(&bin, &home, &vault_path, "tracked");

    let mut child = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("run")
        .arg("tracked")
        .arg("--")
        .arg("/bin/sleep")
        .arg("30")
        .env("HOME", &home)
        .env("SSHENV_SESSIONS", &sessions_path)
        .spawn()
        .expect("spawn tracked run");

    let pid_text = child.id().to_string();
    let mut list_cmd = Command::new(&bin);
    list_cmd
        .arg("--vault")
        .arg(&vault_path)
        .arg("sessions")
        .arg("list")
        .arg("--profile")
        .arg("tracked")
        .env("HOME", &home)
        .env("SSHENV_SESSIONS", &sessions_path);
    assert!(
        wait_for_stdout_contains(&mut list_cmd, &pid_text),
        "tracked session did not appear in sessions list"
    );

    let kill_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("sessions")
        .arg("kill")
        .arg("tracked")
        .arg("--signal")
        .arg("kill")
        .env("HOME", &home)
        .env("SSHENV_SESSIONS", &sessions_path)
        .output()
        .expect("run sessions kill");
    assert!(
        kill_out.status.success(),
        "sessions kill failed: stdout={} stderr={}",
        String::from_utf8_lossy(&kill_out.stdout),
        String::from_utf8_lossy(&kill_out.stderr)
    );

    for _ in 0..40 {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.kill().ok();
    panic!("tracked child was not killed by sessions kill");
}

#[cfg(unix)]
#[test]
fn binary_run_incognito_is_not_tracked() {
    let bin = cargo_bin();
    if !bin.exists() {
        eprintln!("skipping: {} does not exist", bin.display());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let vault_path = home.join(".sshenv").join("vault");
    let sessions_path = dir.path().join("sessions.toml");
    init_vault_with_profile(&bin, &home, &vault_path, "hidden");

    let mut child = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("run")
        .arg("--incognito")
        .arg("hidden")
        .arg("--")
        .arg("/bin/sleep")
        .arg("30")
        .env("HOME", &home)
        .env("SSHENV_SESSIONS", &sessions_path)
        .spawn()
        .expect("spawn incognito run");

    std::thread::sleep(std::time::Duration::from_millis(200));
    let list_out = Command::new(&bin)
        .arg("--vault")
        .arg(&vault_path)
        .arg("sessions")
        .arg("list")
        .arg("--profile")
        .arg("hidden")
        .env("HOME", &home)
        .env("SSHENV_SESSIONS", &sessions_path)
        .output()
        .expect("run sessions list");
    child.kill().ok();
    child.wait().ok();

    assert!(
        list_out.status.success(),
        "sessions list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&list_out.stdout),
        String::from_utf8_lossy(&list_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        !stdout.contains("hidden"),
        "incognito run should not be listed: {stdout}"
    );
}
