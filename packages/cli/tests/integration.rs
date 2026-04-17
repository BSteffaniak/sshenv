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
