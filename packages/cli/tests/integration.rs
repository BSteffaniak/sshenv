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
    let priv_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen key");
    let pub_line = priv_key.public_key().to_openssh().expect("pub");
    let priv_pem = priv_key
        .to_openssh(LineEnding::LF)
        .expect("priv pem")
        .to_string();

    let pub_path = dir.join("id_test.pub");
    std::fs::write(&pub_path, format!("{pub_line}\n")).unwrap();
    let priv_path = dir.join("id_test");
    std::fs::write(&priv_path, &priv_pem).unwrap();
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
