//! Device-seal factor support for v2 vault policies.
//!
//! This module defines the device-seal abstraction plus optional backends.
//! The macOS backend stores a random factor in Keychain. The local-file backend
//! is useful for development/testing only and is not theft-resistant.
//! Future DPAPI, Secret Service, TPM, or Secure Enclave backends should plug
//! into the same metadata shape without changing the vault format.

use std::collections::BTreeMap;
#[cfg(any(
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux")
))]
use std::io::Write;
#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
use std::path::Path;
#[cfg(any(
    feature = "device-seal-file",
    all(feature = "tpm-device-seal", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use std::path::PathBuf;
#[cfg(any(
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux")
))]
use std::process::Command;
#[cfg(any(
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux")
))]
use std::process::Stdio;

use anyhow::{Context, Result, bail};
#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use rand_core::RngCore;
#[cfg(feature = "secure-enclave")]
use serde::{Deserialize, Serialize};
use sshenv_vault_models::{UnlockFactorKindV2, UnlockFactorV2};
use zeroize::Zeroizing;

const DEVICE_SEAL_FACTOR_ID: &str = "device-seal:default";
const BACKEND: &str = "backend";
const BACKEND_LOCAL_FILE: &str = "local-file";
const BACKEND_LINUX_SECRET_SERVICE: &str = "linux-secret-service";
const BACKEND_MACOS_KEYCHAIN: &str = "macos-keychain";
const BACKEND_SECURE_ENCLAVE: &str = "secure-enclave";
const BACKEND_TPM: &str = "tpm";
const BACKEND_WINDOWS_DPAPI: &str = "windows-dpapi";
const KEY_LEN: usize = 32;
#[cfg(feature = "secure-enclave")]
pub const SECURE_ENCLAVE_COMMAND_ENV: &str = "SSHENV_SECURE_ENCLAVE_DEVICE_SEAL_COMMAND";
#[cfg(feature = "device-seal-file")]
const DEVICE_SEAL_BACKEND_ENV: &str = "SSHENV_DEVICE_SEAL_BACKEND";
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
const MACOS_KEYCHAIN_SERVICE: &str = "sshenv device seal";
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
const MACOS_KEYCHAIN_ACCOUNT: &str = "default";
#[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
const LINUX_SECRET_SERVICE_LABEL: &str = "sshenv device seal";

/// Create metadata for a device-seal factor and return the device factor key.
///
/// # Errors
///
/// Returns an error if this build has no available device-seal backend or if
/// the backend cannot create/load its secret.
pub fn create_factor() -> Result<(UnlockFactorV2, Zeroizing<[u8; KEY_LEN]>)> {
    let (backend, factor_key) = load_or_create_device_secret()?;
    let mut params = BTreeMap::new();
    params.insert(BACKEND.to_string(), backend.to_string());
    Ok((
        UnlockFactorV2 {
            id: DEVICE_SEAL_FACTOR_ID.to_string(),
            kind: UnlockFactorKindV2::DeviceSeal,
            recipient_fingerprint: None,
            params,
        },
        factor_key,
    ))
}

/// Derive/load the device-seal factor key for existing metadata.
///
/// # Errors
///
/// Returns an error if metadata is invalid or the configured backend is not
/// available in this build.
pub fn derive_factor_from_metadata(factor: &UnlockFactorV2) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if factor.kind != UnlockFactorKindV2::DeviceSeal {
        bail!("factor {} is not a device-seal factor", factor.id);
    }
    let backend = factor
        .params
        .get(BACKEND)
        .context("device-seal factor is missing backend")?;
    match backend.as_str() {
        BACKEND_MACOS_KEYCHAIN => load_macos_keychain_secret(),
        BACKEND_SECURE_ENCLAVE => load_secure_enclave_secret(),
        BACKEND_LINUX_SECRET_SERVICE => load_linux_secret_service_secret(),
        BACKEND_TPM => load_tpm_secret(),
        BACKEND_WINDOWS_DPAPI => load_windows_dpapi_secret(),
        BACKEND_LOCAL_FILE => load_local_file_secret(),
        _ => bail!("device-seal backend '{backend}' is not supported by this build"),
    }
}

/// True when the factor is a device-seal factor.
#[must_use]
pub fn is_device_seal_factor(factor: &UnlockFactorV2) -> bool {
    factor.kind == UnlockFactorKindV2::DeviceSeal
}

/// Human-readable backend status.
#[must_use]
pub const fn backend_status() -> &'static str {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        "macOS Keychain"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        feature = "linux-secret-service",
        target_os = "linux"
    ))]
    {
        "Linux Secret Service"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        feature = "windows-dpapi",
        target_os = "windows"
    ))]
    {
        "Windows DPAPI"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        feature = "tpm-device-seal",
        target_os = "linux"
    ))]
    {
        "TPM"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        feature = "secure-enclave"
    ))]
    {
        "Secure Enclave command adapter"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        not(feature = "secure-enclave"),
        feature = "device-seal-file"
    ))]
    {
        "local-file (development/testing; not theft-resistant)"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        not(feature = "secure-enclave"),
        not(feature = "device-seal-file")
    ))]
    {
        "none"
    }
}

fn load_or_create_device_secret() -> Result<(&'static str, Zeroizing<[u8; KEY_LEN]>)> {
    #[cfg(feature = "device-seal-file")]
    if local_file_backend_requested()? {
        return load_or_create_local_file_secret();
    }

    #[cfg(feature = "secure-enclave")]
    if secure_enclave_command_path().is_some() {
        if let Ok(secret) = load_secure_enclave_secret() {
            return Ok((BACKEND_SECURE_ENCLAVE, secret));
        }
        let secret = create_random_secret();
        store_secure_enclave_secret(secret.as_slice())?;
        return Ok((BACKEND_SECURE_ENCLAVE, secret));
    };

    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        if let Ok(secret) = load_macos_keychain_secret() {
            return Ok((BACKEND_MACOS_KEYCHAIN, secret));
        }
        let secret = create_random_secret();
        store_macos_keychain_secret(secret.as_slice())?;
        Ok((BACKEND_MACOS_KEYCHAIN, secret))
    }

    #[cfg(all(
        feature = "linux-secret-service",
        target_os = "linux",
        not(all(feature = "macos-keychain", target_os = "macos"))
    ))]
    {
        if let Ok(secret) = load_linux_secret_service_secret() {
            return Ok((BACKEND_LINUX_SECRET_SERVICE, secret));
        }
        let secret = create_random_secret();
        store_linux_secret_service_secret(secret.as_slice())?;
        Ok((BACKEND_LINUX_SECRET_SERVICE, secret))
    }

    #[cfg(all(
        feature = "windows-dpapi",
        target_os = "windows",
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux"))
    ))]
    {
        if let Ok(secret) = load_windows_dpapi_secret() {
            return Ok((BACKEND_WINDOWS_DPAPI, secret));
        }
        let secret = create_random_secret();
        store_windows_dpapi_secret(secret.as_slice())?;
        Ok((BACKEND_WINDOWS_DPAPI, secret))
    }

    #[cfg(all(
        feature = "tpm-device-seal",
        target_os = "linux",
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows"))
    ))]
    {
        if let Ok(secret) = load_tpm_secret() {
            return Ok((BACKEND_TPM, secret));
        }
        let secret = create_random_secret();
        store_tpm_secret(secret.as_slice())?;
        Ok((BACKEND_TPM, secret))
    }

    #[cfg(all(
        feature = "device-seal-file",
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux"))
    ))]
    {
        load_or_create_local_file_secret()
    }

    #[cfg(all(
        feature = "secure-enclave",
        not(feature = "device-seal-file"),
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows"))
    ))]
    bail!("Secure Enclave device-seal backend requires SSHENV_SECURE_ENCLAVE_DEVICE_SEAL_COMMAND");

    #[cfg(not(any(
        feature = "device-seal-file",
        all(feature = "macos-keychain", target_os = "macos"),
        all(feature = "linux-secret-service", target_os = "linux"),
        feature = "secure-enclave",
        all(feature = "tpm-device-seal", target_os = "linux"),
        all(feature = "windows-dpapi", target_os = "windows")
    )))]
    bail!("no device-seal backend is available in this build")
}

#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
fn create_random_secret() -> Zeroizing<[u8; KEY_LEN]> {
    let mut secret = [0_u8; KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut secret);
    Zeroizing::new(secret)
}

#[cfg(feature = "device-seal-file")]
fn local_file_backend_requested() -> Result<bool> {
    let Ok(value) = std::env::var(DEVICE_SEAL_BACKEND_ENV) else {
        return Ok(false);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(false);
    }
    if value == BACKEND_LOCAL_FILE {
        Ok(true)
    } else {
        bail!("unsupported device-seal backend override '{value}'")
    }
}

#[cfg(feature = "device-seal-file")]
fn load_or_create_local_file_secret() -> Result<(&'static str, Zeroizing<[u8; KEY_LEN]>)> {
    if let Ok(secret) = load_local_file_secret() {
        return Ok((BACKEND_LOCAL_FILE, secret));
    }
    let secret = create_random_secret();
    let encoded = format!("{}\n", hex::encode(secret.as_slice()));
    crate::atomic_write(&local_file_secret_path(), encoded.as_bytes(), 0o600)?;
    Ok((BACKEND_LOCAL_FILE, secret))
}

fn load_local_file_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(feature = "device-seal-file")]
    {
        let path = local_file_secret_path();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read device seal secret {}", path.display()))?;
        parse_hex_secret(raw.trim(), "device seal secret")
    }

    #[cfg(not(feature = "device-seal-file"))]
    bail!("local-file device-seal backend is not available in this build")
}

fn load_macos_keychain_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        let output = Command::new("/usr/bin/security")
            .arg("find-generic-password")
            .arg("-w")
            .arg("-s")
            .arg(MACOS_KEYCHAIN_SERVICE)
            .arg("-a")
            .arg(MACOS_KEYCHAIN_ACCOUNT)
            .output()
            .context("failed to invoke macOS security command")?;
        if !output.status.success() {
            bail!("macOS Keychain device seal secret not found or unavailable");
        }
        let raw = String::from_utf8(output.stdout)
            .context("macOS Keychain returned non-UTF8 device seal secret")?;
        parse_hex_secret(raw.trim(), "macOS Keychain device seal secret")
    }

    #[cfg(not(all(feature = "macos-keychain", target_os = "macos")))]
    bail!("macOS Keychain device-seal backend is not available in this build")
}

#[cfg(feature = "secure-enclave")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct SecureEnclaveCommandInput<'a> {
    operation: &'a str,
    secret_hex: Option<String>,
}

#[cfg(feature = "secure-enclave")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SecureEnclaveCommandOutput {
    #[serde(alias = "secret_hex")]
    secret_hex: String,
}

#[cfg(feature = "secure-enclave")]
fn secure_enclave_command_path() -> Option<String> {
    std::env::var(SECURE_ENCLAVE_COMMAND_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn load_secure_enclave_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(feature = "secure-enclave")]
    {
        let command_path = secure_enclave_command_path().with_context(|| {
            format!("Secure Enclave device-seal backend requires {SECURE_ENCLAVE_COMMAND_ENV}")
        })?;
        let output = invoke_secure_enclave_command(&command_path, "load", None)?;
        parse_hex_secret(&output.secret_hex, "Secure Enclave device seal secret")
    }

    #[cfg(not(feature = "secure-enclave"))]
    bail!("Secure Enclave device-seal backend is not available in this build")
}

#[cfg(feature = "secure-enclave")]
fn store_secure_enclave_secret(secret: &[u8]) -> Result<()> {
    let command_path = secure_enclave_command_path().with_context(|| {
        format!("Secure Enclave device-seal backend requires {SECURE_ENCLAVE_COMMAND_ENV}")
    })?;
    invoke_secure_enclave_command(&command_path, "store", Some(secret))?;
    Ok(())
}

#[cfg(feature = "secure-enclave")]
fn invoke_secure_enclave_command(
    command_path: &str,
    operation: &str,
    secret: Option<&[u8]>,
) -> Result<SecureEnclaveCommandOutput> {
    let input = serde_json::to_vec(&SecureEnclaveCommandInput {
        operation,
        secret_hex: secret.map(hex::encode),
    })
    .context("failed to serialize Secure Enclave device-seal request")?;
    let mut child = Command::new(command_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to invoke Secure Enclave adapter '{command_path}'"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open Secure Enclave adapter stdin")?;
        stdin
            .write_all(&input)
            .context("failed to write Secure Enclave adapter request")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for Secure Enclave adapter")?;
    if !output.status.success() {
        bail!(
            "Secure Enclave adapter exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("Secure Enclave adapter returned invalid JSON")
}

fn load_linux_secret_service_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
    {
        let output = secret_tool_command("lookup")
            .output()
            .context("failed to invoke secret-tool for Linux Secret Service")?;
        if !output.status.success() {
            bail!("Linux Secret Service device seal secret not found or unavailable");
        }
        let raw = String::from_utf8(output.stdout)
            .context("Linux Secret Service returned non-UTF8 device seal secret")?;
        parse_hex_secret(raw.trim(), "Linux Secret Service device seal secret")
    }

    #[cfg(not(all(feature = "linux-secret-service", target_os = "linux")))]
    bail!("Linux Secret Service device-seal backend is not available in this build")
}

#[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
fn store_linux_secret_service_secret(secret: &[u8]) -> Result<()> {
    let secret_hex = hex::encode(secret);
    let mut child = secret_tool_store_command()
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to invoke secret-tool for Linux Secret Service")?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open secret-tool stdin")?;
        stdin
            .write_all(secret_hex.as_bytes())
            .context("failed to write device seal to secret-tool stdin")?;
    }
    let status = child
        .wait()
        .context("failed to wait for secret-tool to store device seal")?;
    if status.success() {
        Ok(())
    } else {
        bail!(
            "failed to store device seal in Linux Secret Service; ensure secret-tool and an unlocked collection are available"
        )
    }
}

#[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
fn secret_tool_command(action: &str) -> Command {
    let mut command = Command::new("secret-tool");
    command.arg(action);
    add_secret_tool_attributes(&mut command);
    command
}

#[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
fn secret_tool_store_command() -> Command {
    let mut command = Command::new("secret-tool");
    command
        .arg("store")
        .arg("--label")
        .arg(LINUX_SECRET_SERVICE_LABEL);
    add_secret_tool_attributes(&mut command);
    command
}

#[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
fn add_secret_tool_attributes(command: &mut Command) {
    command
        .arg("application")
        .arg("sshenv")
        .arg("purpose")
        .arg("device-seal")
        .arg("account")
        .arg("default");
}

fn load_tpm_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
    {
        let state = tpm_state_dir();
        let primary = state.join("primary.ctx");
        let public = state.join("seal.pub");
        let private = state.join("seal.priv");
        let seal = state.join("seal.ctx");
        if !seal.exists() {
            create_tpm_primary(&primary)?;
            load_tpm_sealed_object(&primary, &public, &private, &seal)?;
        }
        let output = Command::new("tpm2_unseal")
            .arg("-c")
            .arg(&seal)
            .output()
            .context("failed to invoke tpm2_unseal")?;
        if !output.status.success() {
            bail!(
                "failed to unseal TPM device seal: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        parse_binary_secret(&output.stdout, "TPM device seal secret")
    }

    #[cfg(not(all(feature = "tpm-device-seal", target_os = "linux")))]
    bail!("TPM device-seal backend is not available in this build")
}

#[cfg(all(
    feature = "tpm-device-seal",
    target_os = "linux",
    not(all(feature = "linux-secret-service", target_os = "linux")),
    not(all(feature = "windows-dpapi", target_os = "windows"))
))]
fn store_tpm_secret(secret: &[u8]) -> Result<()> {
    let state = tpm_state_dir();
    std::fs::create_dir_all(&state).with_context(|| {
        format!(
            "failed to create TPM device seal state dir {}",
            state.display()
        )
    })?;
    let primary = state.join("primary.ctx");
    let public = state.join("seal.pub");
    let private = state.join("seal.priv");
    let seal = state.join("seal.ctx");
    create_tpm_primary(&primary)?;
    create_tpm_sealed_object(&primary, &public, &private, secret)?;
    load_tpm_sealed_object(&primary, &public, &private, &seal)
}

#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
fn create_tpm_primary(primary: &Path) -> Result<()> {
    run_tpm2(
        Command::new("tpm2_createprimary")
            .arg("-C")
            .arg("o")
            .arg("-G")
            .arg("rsa")
            .arg("-c")
            .arg(primary),
        "create TPM primary context",
    )
}

#[cfg(all(
    feature = "tpm-device-seal",
    target_os = "linux",
    not(all(feature = "linux-secret-service", target_os = "linux")),
    not(all(feature = "windows-dpapi", target_os = "windows"))
))]
fn create_tpm_sealed_object(
    primary: &Path,
    public: &Path,
    private: &Path,
    secret: &[u8],
) -> Result<()> {
    let mut child = Command::new("tpm2_create")
        .arg("-C")
        .arg(primary)
        .arg("-u")
        .arg(public)
        .arg("-r")
        .arg(private)
        .arg("-i")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to invoke tpm2_create")?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open tpm2_create stdin")?;
        stdin
            .write_all(secret)
            .context("failed to write device seal to tpm2_create stdin")?;
    }
    let status = child
        .wait()
        .context("failed to wait for tpm2_create to seal device secret")?;
    if status.success() {
        Ok(())
    } else {
        bail!("failed to create TPM sealed device seal object")
    }
}

#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
fn load_tpm_sealed_object(
    primary: &Path,
    public: &Path,
    private: &Path,
    seal: &Path,
) -> Result<()> {
    run_tpm2(
        Command::new("tpm2_load")
            .arg("-C")
            .arg(primary)
            .arg("-u")
            .arg(public)
            .arg("-r")
            .arg(private)
            .arg("-c")
            .arg(seal),
        "load TPM sealed device seal object",
    )
}

#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
fn run_tpm2(command: &mut Command, action: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to invoke tpm2-tools command to {action}"))?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "failed to {action}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
fn tpm_state_dir() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/device-seal-tpm"),
        |home| home.join(".sshenv").join("device-seal-tpm"),
    )
}

fn load_windows_dpapi_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
    {
        let path = windows_dpapi_secret_path();
        let protected_hex = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read Windows DPAPI device seal {}",
                path.display()
            )
        })?;
        let protected = hex::decode(protected_hex.trim())
            .context("Windows DPAPI device seal entry is not valid hex")?;
        let secret = dpapi_unprotect(&protected)?;
        parse_binary_secret(&secret, "Windows DPAPI device seal secret")
    }

    #[cfg(not(all(feature = "windows-dpapi", target_os = "windows")))]
    bail!("Windows DPAPI device-seal backend is not available in this build")
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn store_windows_dpapi_secret(secret: &[u8]) -> Result<()> {
    let protected = dpapi_protect(secret, "sshenv device seal")?;
    crate::atomic_write(
        &windows_dpapi_secret_path(),
        format!("{}\n", hex::encode(protected)).as_bytes(),
        0o600,
    )
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn windows_dpapi_secret_path() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(r".sshenv\device-seal-dpapi"),
        |home| home.join(".sshenv").join("device-seal-dpapi"),
    )
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn dpapi_protect(plaintext: &[u8], description: &str) -> Result<Vec<u8>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plaintext.len()).context("DPAPI plaintext too large")?,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let description: Vec<u16> = OsStr::new(description)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: All pointers are valid for the duration of the call; output is freed with LocalFree.
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            description.as_ptr(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to protect device seal with Windows DPAPI");
    }
    let output_guard = LocalAllocGuard(output.pbData.cast());
    // SAFETY: DPAPI returned `cbData` bytes at `pbData` on success.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            output.pbData,
            usize::try_from(output.cbData).context("DPAPI output length too large")?,
        )
    }
    .to_vec();
    drop(output_guard);
    Ok(bytes)
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).context("DPAPI ciphertext too large")?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: All pointers are valid for the duration of the call; output is freed with LocalFree.
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to unprotect device seal with Windows DPAPI");
    }
    let output_guard = LocalAllocGuard(output.pbData.cast());
    // SAFETY: DPAPI returned `cbData` bytes at `pbData` on success.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            output.pbData,
            usize::try_from(output.cbData).context("DPAPI output length too large")?,
        )
    }
    .to_vec();
    drop(output_guard);
    Ok(bytes)
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
struct LocalAllocGuard(windows_sys::Win32::Foundation::HLOCAL);

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_keychain_secret(secret: &[u8]) -> Result<()> {
    let secret_hex = hex::encode(secret);
    let output = Command::new("/usr/bin/security")
        .arg("add-generic-password")
        .arg("-U")
        .arg("-s")
        .arg(MACOS_KEYCHAIN_SERVICE)
        .arg("-a")
        .arg(MACOS_KEYCHAIN_ACCOUNT)
        .arg("-w")
        .arg(secret_hex)
        .output()
        .context("failed to invoke macOS security command")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "failed to store device seal in macOS Keychain: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "windows-dpapi", target_os = "windows")
))]
fn parse_hex_secret(value: &str, label: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not valid hex"))?;
    parse_binary_secret(&bytes, label)
}

#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
fn parse_binary_secret(bytes: &[u8], label: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let secret: [u8; KEY_LEN] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} is {} bytes, expected {KEY_LEN}", bytes.len()))?;
    Ok(Zeroizing::new(secret))
}

#[cfg(feature = "device-seal-file")]
fn local_file_secret_path() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/device-seal"),
        |home| home.join(".sshenv").join("device-seal"),
    )
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "secure-enclave", unix))]
    #[test]
    fn secure_enclave_command_roundtrips_secret_hex() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let command_path = dir.path().join("secure-enclave-adapter.sh");
        std::fs::write(
            &command_path,
            r#"#!/bin/sh
input=$(cat)
case "$input" in
  *'"operation":"store"'*|*'"operation": "store"'*)
    key=$(printf '%s' "$input" | sed -n 's/.*"secret-hex":"\([0-9a-f]*\)".*/\1/p')
    printf '{"secret-hex":"%s"}\n' "$key"
    ;;
  *'"operation":"load"'*|*'"operation": "load"'*)
    printf '{"secret-hex":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}\n'
    ;;
  *) echo 'unknown operation' >&2; exit 1 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&command_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let output =
            super::invoke_secure_enclave_command(command_path.to_str().unwrap(), "load", None)
                .unwrap();
        let parsed = super::parse_hex_secret(&output.secret_hex, "test secret").unwrap();
        assert_eq!(parsed.len(), super::KEY_LEN);

        let output = super::invoke_secure_enclave_command(
            command_path.to_str().unwrap(),
            "store",
            Some(parsed.as_slice()),
        )
        .unwrap();
        assert_eq!(output.secret_hex, hex::encode(parsed.as_slice()));
    }
}
