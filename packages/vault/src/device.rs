//! Device-seal factor support for v2 vault policies.
//!
//! This module defines the device-seal abstraction and a deliberately optional
//! local-file backend used for development/testing. Production OS keychain,
//! DPAPI, Secret Service, TPM, or Secure Enclave backends should plug into the
//! same metadata shape without changing the vault format.

use std::collections::BTreeMap;
#[cfg(feature = "device-seal-file")]
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
#[cfg(feature = "device-seal-file")]
use rand_core::RngCore;
use sshenv_vault_models::{UnlockFactorKindV2, UnlockFactorV2};
use zeroize::Zeroizing;

const DEVICE_SEAL_FACTOR_ID: &str = "device-seal:default";
const BACKEND: &str = "backend";
const BACKEND_LOCAL_FILE: &str = "local-file";
const KEY_LEN: usize = 32;

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
    if backend != BACKEND_LOCAL_FILE {
        bail!("device-seal backend '{backend}' is not supported by this build");
    }
    load_device_secret()
}

/// True when the factor is a device-seal factor.
#[must_use]
pub fn is_device_seal_factor(factor: &UnlockFactorV2) -> bool {
    factor.kind == UnlockFactorKindV2::DeviceSeal
}

/// Human-readable backend status.
#[must_use]
pub const fn backend_status() -> &'static str {
    #[cfg(feature = "device-seal-file")]
    {
        "local-file (development/testing; not theft-resistant)"
    }
    #[cfg(not(feature = "device-seal-file"))]
    {
        "none"
    }
}

fn load_or_create_device_secret() -> Result<(&'static str, Zeroizing<[u8; KEY_LEN]>)> {
    #[cfg(feature = "device-seal-file")]
    {
        if let Ok(secret) = load_device_secret() {
            return Ok((BACKEND_LOCAL_FILE, secret));
        }

        let mut secret = [0_u8; KEY_LEN];
        rand_core::OsRng.fill_bytes(&mut secret);
        let encoded = format!("{}\n", hex::encode(secret));
        crate::atomic_write(&local_file_secret_path(), encoded.as_bytes(), 0o600)?;
        Ok((BACKEND_LOCAL_FILE, Zeroizing::new(secret)))
    }

    #[cfg(not(feature = "device-seal-file"))]
    bail!("no device-seal backend is available in this build")
}

fn load_device_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(feature = "device-seal-file")]
    {
        let path = local_file_secret_path();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read device seal secret {}", path.display()))?;
        let bytes = hex::decode(raw.trim()).context("device seal secret is not valid hex")?;
        let secret: [u8; KEY_LEN] = bytes.try_into().map_err(|value: Vec<u8>| {
            anyhow::anyhow!(
                "device seal secret is {} bytes, expected {KEY_LEN}",
                value.len()
            )
        })?;
        Ok(Zeroizing::new(secret))
    }

    #[cfg(not(feature = "device-seal-file"))]
    bail!("no device-seal backend is available in this build")
}

#[cfg(feature = "device-seal-file")]
fn local_file_secret_path() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/device-seal"),
        |home| home.join(".sshenv").join("device-seal"),
    )
}
