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
    all(feature = "windows-dpapi", target_os = "windows")
))]
use std::io::Write;
#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use std::path::PathBuf;
#[cfg(any(
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use std::process::Command;
#[cfg(any(
    all(feature = "linux-secret-service", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use std::process::Stdio;

use anyhow::{Context, Result, bail};
#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use rand_core::RngCore;
use sshenv_vault_models::{UnlockFactorKindV2, UnlockFactorV2};
use zeroize::Zeroizing;

const DEVICE_SEAL_FACTOR_ID: &str = "device-seal:default";
const BACKEND: &str = "backend";
const BACKEND_LOCAL_FILE: &str = "local-file";
const BACKEND_LINUX_SECRET_SERVICE: &str = "linux-secret-service";
const BACKEND_MACOS_KEYCHAIN: &str = "macos-keychain";
const BACKEND_WINDOWS_DPAPI: &str = "windows-dpapi";
const KEY_LEN: usize = 32;
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
        BACKEND_LINUX_SECRET_SERVICE => load_linux_secret_service_secret(),
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
        feature = "device-seal-file"
    ))]
    {
        "local-file (development/testing; not theft-resistant)"
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(feature = "device-seal-file")
    ))]
    {
        "none"
    }
}

fn load_or_create_device_secret() -> Result<(&'static str, Zeroizing<[u8; KEY_LEN]>)> {
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
        feature = "device-seal-file",
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows"))
    ))]
    {
        if let Ok(secret) = load_local_file_secret() {
            return Ok((BACKEND_LOCAL_FILE, secret));
        }
        let secret = create_random_secret();
        let encoded = format!("{}\n", hex::encode(secret.as_slice()));
        crate::atomic_write(&local_file_secret_path(), encoded.as_bytes(), 0o600)?;
        Ok((BACKEND_LOCAL_FILE, secret))
    }

    #[cfg(not(any(
        feature = "device-seal-file",
        all(feature = "macos-keychain", target_os = "macos"),
        all(feature = "linux-secret-service", target_os = "linux"),
        all(feature = "windows-dpapi", target_os = "windows")
    )))]
    bail!("no device-seal backend is available in this build")
}

#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
fn create_random_secret() -> Zeroizing<[u8; KEY_LEN]> {
    let mut secret = [0_u8; KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut secret);
    Zeroizing::new(secret)
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

fn load_windows_dpapi_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
    {
        let path = windows_dpapi_secret_path();
        let protected = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read Windows DPAPI device seal {}",
                path.display()
            )
        })?;
        let output = run_dpapi_powershell(DPAPI_UNPROTECT_SCRIPT, protected.trim())?;
        parse_hex_secret(output.trim(), "Windows DPAPI device seal secret")
    }

    #[cfg(not(all(feature = "windows-dpapi", target_os = "windows")))]
    bail!("Windows DPAPI device-seal backend is not available in this build")
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn store_windows_dpapi_secret(secret: &[u8]) -> Result<()> {
    let protected = run_dpapi_powershell(DPAPI_PROTECT_SCRIPT, &hex::encode(secret))?;
    crate::atomic_write(
        &windows_dpapi_secret_path(),
        format!("{}\n", protected.trim()).as_bytes(),
        0o600,
    )
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn run_dpapi_powershell(script: &str, stdin_text: &str) -> Result<String> {
    let mut child = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to invoke powershell.exe for Windows DPAPI")?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open powershell.exe stdin")?;
        stdin
            .write_all(stdin_text.as_bytes())
            .context("failed to write Windows DPAPI input")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for Windows DPAPI powershell command")?;
    if output.status.success() {
        String::from_utf8(output.stdout).context("Windows DPAPI command returned non-UTF8 output")
    } else {
        bail!(
            "Windows DPAPI command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
fn windows_dpapi_secret_path() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(r".sshenv\device-seal-dpapi"),
        |home| home.join(".sshenv").join("device-seal-dpapi"),
    )
}

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
const DPAPI_PROTECT_SCRIPT: &str = r#"
$hex = [Console]::In.ReadToEnd().Trim()
if (($hex.Length % 2) -ne 0) { throw 'hex input has odd length' }
$bytes = New-Object byte[] ($hex.Length / 2)
for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
$protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Convert]::ToBase64String($protected)
"#;

#[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
const DPAPI_UNPROTECT_SCRIPT: &str = r#"
$encoded = [Console]::In.ReadToEnd().Trim()
$protected = [Convert]::FromBase64String($encoded)
$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
([BitConverter]::ToString($bytes)).Replace('-', '')
"#;

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
    all(feature = "windows-dpapi", target_os = "windows")
))]
fn parse_hex_secret(value: &str, label: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not valid hex"))?;
    let secret: [u8; KEY_LEN] = bytes.try_into().map_err(|value: Vec<u8>| {
        anyhow::anyhow!("{label} is {} bytes, expected {KEY_LEN}", value.len())
    })?;
    Ok(Zeroizing::new(secret))
}

#[cfg(feature = "device-seal-file")]
fn local_file_secret_path() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/device-seal"),
        |home| home.join(".sshenv").join("device-seal"),
    )
}
