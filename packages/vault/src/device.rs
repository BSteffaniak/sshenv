//! Device-seal factor support for v2 vault policies.
//!
//! This module defines the device-seal abstraction plus optional backends.
//! The macOS backend stores a random factor in Keychain. The local-file backend
//! is useful for development/testing only and is not theft-resistant.
//! Future DPAPI, Secret Service, TPM, or Secure Enclave backends should plug
//! into the same metadata shape without changing the vault format.

use std::collections::BTreeMap;
#[cfg(any(
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux")
))]
use std::io::Write;
#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
use std::path::Path;
#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
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
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux")
))]
use std::process::Stdio;
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
use std::ptr;

use anyhow::{Context, Result, bail};
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType as _},
    string::CFString,
};
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
use core_foundation_sys::{
    array::{CFArrayGetValueAtIndex, CFArrayRef},
    base::{CFRelease, CFTypeRef, OSStatus},
    string::CFStringRef,
};
#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave",
    all(feature = "tpm-device-seal", target_os = "linux"),
    all(feature = "windows-dpapi", target_os = "windows")
))]
use rand_core::RngCore;
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
#[cfg(feature = "secure-enclave")]
use serde::{Deserialize, Serialize};
use sshenv_vault_models::{
    DEVICE_SEAL_COMMAND_ENV, DeviceSealBrokerOperation, DeviceSealBrokerRequest,
    DeviceSealBrokerResponse, UnlockFactorKindV2, UnlockFactorV2,
};
use zeroize::Zeroizing;

const DEVICE_SEAL_FACTOR_ID: &str = "device-seal:default";
const BACKEND: &str = "backend";
const KEYCHAIN_SERVICE: &str = "keychain-service";
const POLICY: &str = "policy";
const STRICT: &str = "strict";
const BACKEND_LOCAL_FILE: &str = "local-file";
const BACKEND_LINUX_SECRET_SERVICE: &str = "linux-secret-service";
const BACKEND_MACOS_KEYCHAIN: &str = "macos-keychain";
const BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY: &str = "macos-keychain-device-only";
const BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION: &str =
    "macos-keychain-device-only-any-application";
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
const MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE: &str = "sshenv device seal device-only noninteractive v1";
const MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE: &str =
    "sshenv device seal transparent device-only any-application v1";
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
const MACOS_KEYCHAIN_ACCOUNT: &str = "default";
#[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
const LINUX_SECRET_SERVICE_LABEL: &str = "sshenv device seal";

/// Requested high-level device-seal policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSealPolicy {
    /// Pick a non-interactive backend that stores a random seal outside the vault
    /// and binds it to this device where the platform supports that guarantee.
    TransparentDeviceOnly,
    /// Preserve the legacy platform default behavior.
    Default,
}

impl DeviceSealPolicy {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::TransparentDeviceOnly => "transparent-device-only",
            Self::Default => "default",
        }
    }
}

/// Concrete device-seal backend requested by an advanced caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSealBackendSelection {
    /// Use the legacy macOS Keychain item.
    MacosKeychain,
    /// Use a non-synchronizing, device-only macOS Keychain item.
    MacosKeychainDeviceOnly,
    /// Use a non-synchronizing, device-only macOS Keychain item with an
    /// any-application ACL to avoid runtime access prompts.
    MacosKeychainDeviceOnlyAnyApplication,
    /// Use Windows DPAPI scoped to the current user.
    WindowsDpapiCurrentUser,
    /// Use the Linux TPM backend.
    LinuxTpm,
    /// Use the Linux Secret Service backend.
    LinuxSecretService,
    /// Use an external Secure Enclave backend command.
    SecureEnclave,
    /// Use the development local-file backend.
    LocalFile,
}

impl DeviceSealBackendSelection {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::MacosKeychain => BACKEND_MACOS_KEYCHAIN,
            Self::MacosKeychainDeviceOnly => BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY,
            Self::MacosKeychainDeviceOnlyAnyApplication => {
                BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION
            }
            Self::WindowsDpapiCurrentUser => BACKEND_WINDOWS_DPAPI,
            Self::LinuxTpm => BACKEND_TPM,
            Self::LinuxSecretService => BACKEND_LINUX_SECRET_SERVICE,
            Self::SecureEnclave => BACKEND_SECURE_ENCLAVE,
            Self::LocalFile => BACKEND_LOCAL_FILE,
        }
    }

    fn from_backend_name(name: &str) -> Option<Self> {
        match name {
            BACKEND_MACOS_KEYCHAIN => Some(Self::MacosKeychain),
            BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY => Some(Self::MacosKeychainDeviceOnly),
            BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION => {
                Some(Self::MacosKeychainDeviceOnlyAnyApplication)
            }
            BACKEND_WINDOWS_DPAPI => Some(Self::WindowsDpapiCurrentUser),
            BACKEND_TPM => Some(Self::LinuxTpm),
            BACKEND_LINUX_SECRET_SERVICE => Some(Self::LinuxSecretService),
            BACKEND_SECURE_ENCLAVE => Some(Self::SecureEnclave),
            BACKEND_LOCAL_FILE => Some(Self::LocalFile),
            _ => None,
        }
    }
}

/// Device-seal selection requested by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSealSelection {
    /// Select a backend by high-level policy.
    Policy(DeviceSealPolicy),
    /// Select a concrete backend explicitly.
    Backend(DeviceSealBackendSelection),
}

impl Default for DeviceSealSelection {
    fn default() -> Self {
        Self::Policy(DeviceSealPolicy::Default)
    }
}

/// Options controlling device-seal creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceSealOptions {
    /// Requested policy or concrete backend.
    pub selection: DeviceSealSelection,
    /// Whether weaker fallback behavior must be rejected.
    pub strict: bool,
}

/// Result of executing a brokered device-seal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSealBrokerExecution {
    /// Whether the operation completed successfully.
    pub ok: bool,
    /// JSON-encoded [`DeviceSealBrokerResponse`] payload to return to the broker caller.
    pub response_payload: Vec<u8>,
    /// Human-readable error text when `ok` is false.
    pub error: Option<String>,
}

/// Execute a device-seal broker request locally and return an encoded broker response.
///
/// This is intended for transport brokers such as terminal multiplexers. It deliberately
/// bypasses [`DEVICE_SEAL_COMMAND_ENV`] so a broker implementation can call it without
/// recursively invoking itself.
#[must_use]
pub fn execute_device_seal_broker_payload(payload: &[u8]) -> DeviceSealBrokerExecution {
    match run_device_seal_broker_payload(payload) {
        Ok(response_payload) => DeviceSealBrokerExecution {
            ok: true,
            response_payload,
            error: None,
        },
        Err(error) => {
            let error = error.to_string();
            let response = DeviceSealBrokerResponse {
                secret_hex: None,
                error: Some(error.clone()),
            };
            let response_payload = serde_json::to_vec(&response).unwrap_or_default();
            DeviceSealBrokerExecution {
                ok: false,
                response_payload,
                error: Some(error),
            }
        }
    }
}

/// Return whether existing device-seal factor metadata satisfies selected options.
///
/// This helper lets callers decide whether a stored factor should be rebound
/// without duplicating sshenv backend names or backend-specific storage
/// metadata rules.
#[must_use]
pub fn factor_matches_options(factor: &UnlockFactorV2, options: DeviceSealOptions) -> bool {
    if factor.kind != UnlockFactorKindV2::DeviceSeal {
        return false;
    }
    factor_backend_selection(factor)
        .is_some_and(|backend| backend_satisfies_options(backend, options))
        && factor_storage_matches(&factor.params)
        && factor
            .params
            .get(POLICY)
            .is_none_or(|policy| policy_matches_options(policy, options))
        && factor
            .params
            .get(STRICT)
            .is_none_or(|strict| parse_bool_setting(strict, options.strict) == options.strict)
}

fn factor_backend_selection(factor: &UnlockFactorV2) -> Option<DeviceSealBackendSelection> {
    factor
        .params
        .get(BACKEND)
        .and_then(|backend| DeviceSealBackendSelection::from_backend_name(backend))
}

fn backend_satisfies_options(
    backend: DeviceSealBackendSelection,
    options: DeviceSealOptions,
) -> bool {
    match options.selection {
        DeviceSealSelection::Backend(expected) => backend == expected,
        DeviceSealSelection::Policy(DeviceSealPolicy::Default) => {
            resolve_default_backend().is_ok_and(|expected| backend == expected)
        }
        DeviceSealSelection::Policy(DeviceSealPolicy::TransparentDeviceOnly) => {
            transparent_device_only_candidates()
                .iter()
                .any(|candidate| {
                    candidate.backend == backend
                        && (!options.strict || candidate.strict_transparent_device_only)
                })
        }
    }
}

fn factor_storage_matches(params: &BTreeMap<String, String>) -> bool {
    params
        .get(BACKEND)
        .is_none_or(|backend| match backend.as_str() {
            BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY => {
                keychain_service_matches(params, MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE)
            }
            BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION => {
                keychain_service_matches(params, MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE)
            }
            _ => true,
        })
}

fn keychain_service_matches(params: &BTreeMap<String, String>, expected: &str) -> bool {
    params
        .get(KEYCHAIN_SERVICE)
        .is_some_and(|service| service == expected)
}

fn parse_bool_setting(value: &str, default: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

fn policy_matches_options(policy: &str, options: DeviceSealOptions) -> bool {
    match options.selection {
        DeviceSealSelection::Policy(expected) => policy == expected.as_str(),
        DeviceSealSelection::Backend(_) => true,
    }
}

/// Create metadata for a device-seal factor and return the device factor key.
///
/// # Errors
///
/// Returns an error if this build has no available device-seal backend or if
/// the backend cannot create/load its secret.
pub fn create_factor() -> Result<(UnlockFactorV2, Zeroizing<[u8; KEY_LEN]>)> {
    create_factor_with_options(DeviceSealOptions::default())
}

/// Create metadata for a selected device-seal factor and return the factor key.
///
/// # Errors
///
/// Returns an error if this build has no available device-seal backend or if
/// the selected backend cannot create/load its secret.
pub fn create_factor_with_options(
    options: DeviceSealOptions,
) -> Result<(UnlockFactorV2, Zeroizing<[u8; KEY_LEN]>)> {
    let (backend, factor_key) = load_or_create_device_secret(options)?;
    let mut params = BTreeMap::new();
    params.insert(BACKEND.to_string(), backend.as_str().to_string());
    insert_backend_metadata(&mut params, backend);
    if let DeviceSealSelection::Policy(policy) = options.selection {
        if policy != DeviceSealPolicy::Default {
            params.insert(POLICY.to_string(), policy.as_str().to_string());
        }
    }
    if options.strict {
        params.insert(STRICT.to_string(), "true".to_string());
    }
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

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn insert_backend_metadata(
    params: &mut BTreeMap<String, String>,
    backend: DeviceSealBackendSelection,
) {
    if matches!(
        backend,
        DeviceSealBackendSelection::MacosKeychainDeviceOnly
            | DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication
    ) {
        let service = match backend {
            DeviceSealBackendSelection::MacosKeychainDeviceOnly => {
                MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE
            }
            DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication => {
                MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE
            }
            _ => unreachable!("matched only macOS device-only Keychain backends"),
        };
        params.insert(KEYCHAIN_SERVICE.to_string(), service.to_string());
    }
}

#[cfg(not(all(feature = "macos-keychain", target_os = "macos")))]
fn insert_backend_metadata(
    _params: &mut BTreeMap<String, String>,
    _backend: DeviceSealBackendSelection,
) {
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
    let backend = DeviceSealBackendSelection::from_backend_name(backend).with_context(|| {
        format!("device-seal backend '{backend}' is not supported by this build")
    })?;
    load_device_secret_from_metadata(backend, &factor.params)
}

fn load_device_secret_from_metadata(
    backend: DeviceSealBackendSelection,
    params: &BTreeMap<String, String>,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        if matches!(
            backend,
            DeviceSealBackendSelection::MacosKeychainDeviceOnly
                | DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication
        ) {
            let service = params.get(KEYCHAIN_SERVICE).context(
                "macOS device-only Keychain factor is missing keychain-service storage metadata",
            )?;
            return load_macos_device_only_keychain_secret_for_service(service);
        }
    }

    let _ = params;
    load_device_secret(backend)
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

fn load_or_create_device_secret(
    options: DeviceSealOptions,
) -> Result<(DeviceSealBackendSelection, Zeroizing<[u8; KEY_LEN]>)> {
    let backend = resolve_device_seal_backend(options)?;
    let secret = load_or_create_backend_secret(backend)?;
    Ok((backend, secret))
}

fn resolve_device_seal_backend(options: DeviceSealOptions) -> Result<DeviceSealBackendSelection> {
    match options.selection {
        DeviceSealSelection::Policy(DeviceSealPolicy::TransparentDeviceOnly) => {
            resolve_transparent_device_only_backend(options.strict)
        }
        DeviceSealSelection::Policy(DeviceSealPolicy::Default) => resolve_default_backend(),
        DeviceSealSelection::Backend(backend) => Ok(backend),
    }
}

fn resolve_default_backend() -> Result<DeviceSealBackendSelection> {
    #[cfg(feature = "device-seal-file")]
    if local_file_backend_requested()? {
        return Ok(DeviceSealBackendSelection::LocalFile);
    }

    #[cfg(feature = "secure-enclave")]
    if secure_enclave_command_path().is_some() {
        return Ok(DeviceSealBackendSelection::SecureEnclave);
    }

    default_backend_candidates()
        .first()
        .map(|candidate| candidate.backend)
        .context("this sshenv build has no device-seal backend enabled")
}

fn resolve_transparent_device_only_backend(strict: bool) -> Result<DeviceSealBackendSelection> {
    transparent_device_only_candidates()
        .iter()
        .copied()
        .find(|candidate| !strict || candidate.strict_transparent_device_only)
        .map(|candidate| candidate.backend)
        .with_context(|| {
            if strict {
                "transparent-device-only strict mode requires a hardware/device-bound backend".to_string()
            } else {
                "transparent-device-only device seal is not available in this build/on this platform".to_string()
            }
        })
}

#[must_use]
const fn default_backend_candidates() -> &'static [DeviceSealBackendCandidate] {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::MacosKeychain,
            strict_transparent_device_only: false,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        feature = "linux-secret-service",
        target_os = "linux"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::LinuxSecretService,
            strict_transparent_device_only: false,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        feature = "windows-dpapi",
        target_os = "windows"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::WindowsDpapiCurrentUser,
            strict_transparent_device_only: true,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        feature = "tpm-device-seal",
        target_os = "linux"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::LinuxTpm,
            strict_transparent_device_only: true,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        feature = "device-seal-file"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::LocalFile,
            strict_transparent_device_only: false,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "linux-secret-service", target_os = "linux")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        not(feature = "device-seal-file")
    ))]
    {
        &[]
    }
}

#[must_use]
const fn transparent_device_only_candidates() -> &'static [DeviceSealBackendCandidate] {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication,
            strict_transparent_device_only: true,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        feature = "windows-dpapi",
        target_os = "windows"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::WindowsDpapiCurrentUser,
            strict_transparent_device_only: true,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        feature = "tpm-device-seal",
        target_os = "linux"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::LinuxTpm,
            strict_transparent_device_only: true,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        feature = "linux-secret-service",
        target_os = "linux"
    ))]
    {
        &[DeviceSealBackendCandidate {
            backend: DeviceSealBackendSelection::LinuxSecretService,
            strict_transparent_device_only: false,
        }]
    }
    #[cfg(all(
        not(all(feature = "macos-keychain", target_os = "macos")),
        not(all(feature = "windows-dpapi", target_os = "windows")),
        not(all(feature = "tpm-device-seal", target_os = "linux")),
        not(all(feature = "linux-secret-service", target_os = "linux"))
    ))]
    {
        &[]
    }
}

fn load_or_create_backend_secret(
    backend: DeviceSealBackendSelection,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    match load_device_secret(backend) {
        Ok(secret) => Ok(secret),
        Err(_) => {
            let secret = create_random_secret();
            store_device_secret(backend, secret.as_slice())?;
            Ok(secret)
        }
    }
}

fn load_device_secret(backend: DeviceSealBackendSelection) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    match backend {
        DeviceSealBackendSelection::MacosKeychain => load_macos_keychain_secret(),
        DeviceSealBackendSelection::MacosKeychainDeviceOnly => {
            load_macos_device_only_keychain_secret()
        }
        DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication => {
            load_macos_device_only_any_application_keychain_secret()
        }
        DeviceSealBackendSelection::WindowsDpapiCurrentUser => load_windows_dpapi_secret(),
        DeviceSealBackendSelection::LinuxTpm => load_tpm_secret(),
        DeviceSealBackendSelection::LinuxSecretService => load_linux_secret_service_secret(),
        DeviceSealBackendSelection::SecureEnclave => load_secure_enclave_secret(),
        DeviceSealBackendSelection::LocalFile => load_local_file_secret(),
    }
}

fn store_device_secret(backend: DeviceSealBackendSelection, secret: &[u8]) -> Result<()> {
    match backend {
        DeviceSealBackendSelection::MacosKeychain => store_macos_keychain_secret(secret),
        DeviceSealBackendSelection::MacosKeychainDeviceOnly => {
            store_macos_device_only_keychain_secret(secret)
        }
        DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication => {
            store_macos_device_only_any_application_keychain_secret(secret)
        }
        DeviceSealBackendSelection::WindowsDpapiCurrentUser => store_windows_dpapi_secret(secret),
        DeviceSealBackendSelection::LinuxTpm => store_tpm_secret(secret),
        DeviceSealBackendSelection::LinuxSecretService => store_linux_secret_service_secret(secret),
        DeviceSealBackendSelection::SecureEnclave => store_secure_enclave_secret(secret),
        DeviceSealBackendSelection::LocalFile => store_local_file_secret(secret),
    }
}

fn create_random_secret() -> Zeroizing<[u8; KEY_LEN]> {
    let mut secret = [0_u8; KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut secret);
    Zeroizing::new(secret)
}

#[derive(Clone, Copy)]
struct DeviceSealBackendCandidate {
    backend: DeviceSealBackendSelection,
    strict_transparent_device_only: bool,
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

fn store_local_file_secret(secret: &[u8]) -> Result<()> {
    #[cfg(feature = "device-seal-file")]
    {
        let encoded = format!("{}\n", hex::encode(secret));
        crate::atomic_write(&local_file_secret_path(), encoded.as_bytes(), 0o600)
    }

    #[cfg(not(feature = "device-seal-file"))]
    {
        let _ = secret;
        bail!("local-file device-seal backend is not available in this build")
    }
}

fn load_macos_keychain_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        if let Some(secret) = invoke_device_seal_broker(
            DeviceSealBrokerOperation::Load,
            BACKEND_MACOS_KEYCHAIN,
            MACOS_KEYCHAIN_SERVICE,
            MACOS_KEYCHAIN_ACCOUNT,
            None,
        )? {
            return parse_hex_secret(&secret, "macOS Keychain device seal secret");
        }
        load_macos_keychain_secret_direct()
    }

    #[cfg(not(all(feature = "macos-keychain", target_os = "macos")))]
    bail!("macOS Keychain device-seal backend is not available in this build")
}

fn load_macos_device_only_keychain_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        load_macos_device_only_keychain_secret_for_service(MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE)
    }

    #[cfg(not(all(feature = "macos-keychain", target_os = "macos")))]
    bail!("macOS device-only Keychain device-seal backend is not available in this build")
}

fn load_macos_device_only_any_application_keychain_secret() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    #[cfg(all(feature = "macos-keychain", target_os = "macos"))]
    {
        load_macos_device_only_keychain_secret_for_service(
            MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE,
        )
    }

    #[cfg(not(all(feature = "macos-keychain", target_os = "macos")))]
    bail!(
        "macOS device-only any-application Keychain device-seal backend is not available in this build"
    )
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn load_macos_device_only_keychain_secret_for_service(
    service: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if let Some(secret) = invoke_device_seal_broker(
        DeviceSealBrokerOperation::Load,
        BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY,
        service,
        MACOS_KEYCHAIN_ACCOUNT,
        None,
    )? {
        return parse_hex_secret(&secret, "macOS device-only Keychain device seal secret");
    }
    load_macos_device_only_keychain_secret_direct(service)
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

fn store_secure_enclave_secret(secret: &[u8]) -> Result<()> {
    #[cfg(feature = "secure-enclave")]
    {
        let command_path = secure_enclave_command_path().with_context(|| {
            format!("Secure Enclave device-seal backend requires {SECURE_ENCLAVE_COMMAND_ENV}")
        })?;
        invoke_secure_enclave_command(&command_path, "store", Some(secret))?;
        Ok(())
    }

    #[cfg(not(feature = "secure-enclave"))]
    {
        let _ = secret;
        bail!("Secure Enclave device-seal backend is not available in this build")
    }
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

fn store_linux_secret_service_secret(_secret: &[u8]) -> Result<()> {
    #[cfg(all(feature = "linux-secret-service", target_os = "linux"))]
    {
        let secret_hex = hex::encode(_secret);
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

    #[cfg(not(all(feature = "linux-secret-service", target_os = "linux")))]
    bail!("Linux Secret Service device-seal backend is not available in this build")
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

fn store_tpm_secret(_secret: &[u8]) -> Result<()> {
    #[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
    {
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
        create_tpm_sealed_object(&primary, &public, &private, _secret)?;
        load_tpm_sealed_object(&primary, &public, &private, &seal)
    }

    #[cfg(not(all(feature = "tpm-device-seal", target_os = "linux")))]
    bail!("TPM device-seal backend is not available in this build")
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

#[cfg(all(feature = "tpm-device-seal", target_os = "linux"))]
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

fn store_windows_dpapi_secret(_secret: &[u8]) -> Result<()> {
    #[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
    {
        let protected = dpapi_protect(_secret, "sshenv device seal")?;
        return crate::atomic_write(
            &windows_dpapi_secret_path(),
            format!("{}\n", hex::encode(protected)).as_bytes(),
            0o600,
        );
    }

    #[cfg(not(all(feature = "windows-dpapi", target_os = "windows")))]
    bail!("Windows DPAPI device-seal backend is not available in this build")
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

    let input = CRYPT_INTEGER_BLOB {
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
            &raw const input,
            description.as_ptr(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
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

    let input = CRYPT_INTEGER_BLOB {
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
            &raw const input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
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

#[cfg(all(test, feature = "windows-dpapi", target_os = "windows"))]
fn test_windows_dpapi_roundtrip() {
    let secret = [42_u8; KEY_LEN];
    let protected = dpapi_protect(&secret, "sshenv device seal test").unwrap();
    assert_ne!(protected, secret);
    let unprotected = dpapi_unprotect(&protected).unwrap();
    assert_eq!(unprotected, secret);
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_keychain_secret(secret: &[u8]) -> Result<()> {
    let secret_hex = hex::encode(secret);
    if invoke_device_seal_broker(
        DeviceSealBrokerOperation::Store,
        BACKEND_MACOS_KEYCHAIN,
        MACOS_KEYCHAIN_SERVICE,
        MACOS_KEYCHAIN_ACCOUNT,
        Some(secret_hex.clone()),
    )?
    .is_some()
    {
        return Ok(());
    }
    store_macos_keychain_secret_direct(&secret_hex)
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_device_only_keychain_secret(secret: &[u8]) -> Result<()> {
    let secret_hex = hex::encode(secret);
    if invoke_device_seal_broker(
        DeviceSealBrokerOperation::Store,
        BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY,
        MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE,
        MACOS_KEYCHAIN_ACCOUNT,
        Some(secret_hex.clone()),
    )?
    .is_some()
    {
        return Ok(());
    }
    store_macos_device_only_keychain_secret_direct(MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE, &secret_hex)
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_device_only_any_application_keychain_secret(secret: &[u8]) -> Result<()> {
    let secret_hex = hex::encode(secret);
    if invoke_device_seal_broker(
        DeviceSealBrokerOperation::Store,
        BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION,
        MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE,
        MACOS_KEYCHAIN_ACCOUNT,
        Some(secret_hex.clone()),
    )?
    .is_some()
    {
        return Ok(());
    }
    store_macos_device_only_any_application_keychain_secret_direct(
        MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE,
        &secret_hex,
    )
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn run_device_seal_broker_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let request: DeviceSealBrokerRequest = serde_json::from_slice(payload)
        .context("device-seal broker request was not valid sshenv JSON")?;
    let target = macos_broker_target(&request)?;

    let response = match request.operation {
        DeviceSealBrokerOperation::Load => {
            let secret = target.load()?;
            DeviceSealBrokerResponse {
                secret_hex: Some(hex::encode(secret.as_slice())),
                error: None,
            }
        }
        DeviceSealBrokerOperation::Store => {
            let secret_hex = request
                .secret_hex
                .as_deref()
                .filter(|value| !value.is_empty())
                .context("store request is missing secret_hex")?;
            parse_hex_secret(secret_hex, target.description)?;
            target.store(secret_hex)?;
            DeviceSealBrokerResponse {
                secret_hex: None,
                error: None,
            }
        }
    };
    serde_json::to_vec(&response).context("failed to encode device-seal broker response")
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
struct MacosBrokerTarget {
    description: &'static str,
    load: fn() -> Result<Zeroizing<[u8; KEY_LEN]>>,
    store: fn(&str) -> Result<()>,
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
impl MacosBrokerTarget {
    fn load(&self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        (self.load)()
    }

    fn store(&self, secret_hex: &str) -> Result<()> {
        (self.store)(secret_hex)
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn macos_broker_target(request: &DeviceSealBrokerRequest) -> Result<MacosBrokerTarget> {
    if request.account != MACOS_KEYCHAIN_ACCOUNT {
        bail!("unsupported device-seal broker account");
    }
    match (request.backend.as_str(), request.service.as_str()) {
        (BACKEND_MACOS_KEYCHAIN, MACOS_KEYCHAIN_SERVICE) => Ok(MacosBrokerTarget {
            description: "macOS Keychain device seal secret",
            load: load_macos_keychain_secret_direct,
            store: store_macos_keychain_secret_direct,
        }),
        (BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY, MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE) => {
            Ok(MacosBrokerTarget {
                description: "macOS device-only Keychain device seal secret",
                load: load_macos_device_only_keychain_secret_direct_default,
                store: store_macos_device_only_keychain_secret_direct_default,
            })
        }
        (
            BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION,
            MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE,
        ) => Ok(MacosBrokerTarget {
            description: "macOS device-only any-application Keychain device seal secret",
            load: load_macos_device_only_any_application_keychain_secret_direct_default,
            store: store_macos_device_only_any_application_keychain_secret_direct_default,
        }),
        _ => bail!("unsupported device-seal broker target"),
    }
}

#[cfg(not(all(feature = "macos-keychain", target_os = "macos")))]
fn run_device_seal_broker_payload(_payload: &[u8]) -> Result<Vec<u8>> {
    bail!("macOS Keychain device seal broker is only supported on macOS")
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
unsafe extern "C" {
    static kSecAttrAccessible: core_foundation::string::CFStringRef;
    static kSecAttrAccess: core_foundation::string::CFStringRef;

    fn SecAccessCreate(
        descriptor: CFStringRef,
        trusted_list: CFArrayRef,
        access_ref: *mut security_framework_sys::base::SecAccessRef,
    ) -> OSStatus;
    fn SecAccessCopySelectedACLList(
        access_ref: security_framework_sys::base::SecAccessRef,
        action: u32,
        acl_list: *mut CFArrayRef,
    ) -> OSStatus;
    fn SecACLCopySimpleContents(
        acl: SecAclRef,
        app_list: *mut CFArrayRef,
        prompt_description: *mut CFStringRef,
        prompt_selector: *mut CssmAclKeychainPromptSelector,
    ) -> OSStatus;
    fn SecACLSetSimpleContents(
        acl: SecAclRef,
        app_list: CFArrayRef,
        prompt_description: CFStringRef,
        prompt_selector: *const CssmAclKeychainPromptSelector,
    ) -> OSStatus;
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
type SecAclRef = *mut std::ffi::c_void;

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct CssmAclKeychainPromptSelector {
    version: u16,
    flags: u16,
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
const CSSM_ACL_AUTHORIZATION_DECRYPT: u32 = 24;
#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
const CSSM_ACL_KEYCHAIN_PROMPT_REQUIRE_PASSPHRASE: u16 = 0x0001;

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn device_seal_password_options(
    service: &str,
    account: &str,
) -> security_framework::passwords::PasswordOptions {
    security_framework::passwords::PasswordOptions::new_generic_password(service, account)
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn device_only_password_options(
    service: &str,
    account: &str,
) -> security_framework::passwords::PasswordOptions {
    let mut options =
        security_framework::passwords::PasswordOptions::new_generic_password(service, account);
    options.set_access_synchronized(Some(false));
    set_macos_device_only_accessibility(&mut options);
    options
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn device_only_any_application_password_options(
    service: &str,
    account: &str,
) -> Result<security_framework::passwords::PasswordOptions> {
    let mut options = device_only_password_options(service, account);
    set_macos_any_application_access(&mut options, service)?;
    Ok(options)
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn set_macos_any_application_access(
    options: &mut security_framework::passwords::PasswordOptions,
    access_name: &str,
) -> Result<()> {
    let access = create_macos_any_application_access(access_name)?;
    #[allow(deprecated)]
    options.query.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecAttrAccess),
            access.into_CFType(),
        )
    });
    Ok(())
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn create_macos_any_application_access(access_name: &str) -> Result<CFType> {
    let description = CFString::from(access_name);
    let trusted_apps: CFArray<CFType> = CFArray::from_CFTypes(&[]);
    let mut access = ptr::null_mut();
    check_macos_security_status(
        unsafe {
            SecAccessCreate(
                description.as_concrete_TypeRef(),
                trusted_apps.as_concrete_TypeRef(),
                ptr::addr_of_mut!(access),
            )
        },
        "SecAccessCreate",
    )?;

    let result = configure_macos_any_application_access(access).map(|()| unsafe {
        CFType::wrap_under_create_rule(access.cast::<std::ffi::c_void>().cast_const() as CFTypeRef)
    });
    if result.is_err() && !access.is_null() {
        unsafe { CFRelease(access.cast::<std::ffi::c_void>().cast_const() as CFTypeRef) };
    }
    result
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn configure_macos_any_application_access(
    access: security_framework_sys::base::SecAccessRef,
) -> Result<()> {
    let mut acl_list = ptr::null();
    check_macos_security_status(
        unsafe {
            SecAccessCopySelectedACLList(
                access,
                CSSM_ACL_AUTHORIZATION_DECRYPT,
                ptr::addr_of_mut!(acl_list),
            )
        },
        "SecAccessCopySelectedACLList",
    )?;
    let _acl_list = CfReleaseGuard::new(acl_list.cast::<std::ffi::c_void>() as CFTypeRef);

    let acl = unsafe { CFArrayGetValueAtIndex(acl_list, 0) }
        .cast_mut()
        .cast::<std::ffi::c_void>();
    let mut app_list = ptr::null();
    let mut prompt_description = ptr::null();
    let mut prompt_selector = CssmAclKeychainPromptSelector {
        version: 0,
        flags: 0,
    };
    check_macos_security_status(
        unsafe {
            SecACLCopySimpleContents(
                acl,
                ptr::addr_of_mut!(app_list),
                ptr::addr_of_mut!(prompt_description),
                ptr::addr_of_mut!(prompt_selector),
            )
        },
        "SecACLCopySimpleContents",
    )?;
    let _app_list = CfReleaseGuard::new(app_list.cast::<std::ffi::c_void>() as CFTypeRef);
    let _prompt_description =
        CfReleaseGuard::new(prompt_description.cast::<std::ffi::c_void>() as CFTypeRef);

    prompt_selector.flags &= !CSSM_ACL_KEYCHAIN_PROMPT_REQUIRE_PASSPHRASE;
    check_macos_security_status(
        unsafe {
            SecACLSetSimpleContents(
                acl,
                ptr::null(),
                prompt_description,
                ptr::addr_of!(prompt_selector),
            )
        },
        "SecACLSetSimpleContents",
    )
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
struct CfReleaseGuard(CFTypeRef);

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
impl CfReleaseGuard {
    const fn new(value: CFTypeRef) -> Option<Self> {
        if value.is_null() {
            None
        } else {
            Some(Self(value))
        }
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
impl Drop for CfReleaseGuard {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn check_macos_security_status(status: OSStatus, operation: &str) -> Result<()> {
    if status == security_framework_sys::base::errSecSuccess {
        Ok(())
    } else {
        bail!("{operation} failed with OSStatus {status}")
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn set_macos_device_only_accessibility(
    options: &mut security_framework::passwords::PasswordOptions,
) {
    #[allow(deprecated)]
    options.query.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecAttrAccessible),
            CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
                .into_CFType(),
        )
    });
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn load_macos_keychain_secret_direct() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    match security_framework::passwords::generic_password(device_seal_password_options(
        MACOS_KEYCHAIN_SERVICE,
        MACOS_KEYCHAIN_ACCOUNT,
    )) {
        Ok(secret) => String::from_utf8(secret)
            .context("macOS Keychain returned non-UTF8 device seal secret")
            .and_then(|secret| {
                parse_hex_secret(secret.trim(), "macOS Keychain device seal secret")
            }),
        Err(keychain_error) => match load_macos_keychain_fallback_secret() {
            Ok(secret_hex) => parse_hex_secret(&secret_hex, "macOS Keychain device seal secret"),
            Err(fallback_error) => Err(anyhow::anyhow!(
                "macOS Keychain device seal secret not found or unavailable: OSStatus {} ({}); fallback file unavailable: {fallback_error}",
                keychain_error.code(),
                keychain_error
            )),
        },
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_keychain_secret_direct(secret_hex: &str) -> Result<()> {
    match security_framework::passwords::set_generic_password_options(
        secret_hex.as_bytes(),
        device_seal_password_options(MACOS_KEYCHAIN_SERVICE, MACOS_KEYCHAIN_ACCOUNT),
    ) {
        Ok(()) => Ok(()),
        Err(keychain_error) => store_macos_keychain_fallback_secret(secret_hex).map_err(|fallback_error| {
            anyhow::anyhow!(
                "failed to store device seal in macOS Keychain: OSStatus {} ({}); fallback file store failed: {fallback_error}",
                keychain_error.code(),
                keychain_error
            )
        }),
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn load_macos_device_only_keychain_secret_direct_default() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    load_macos_device_only_keychain_secret_direct(MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE)
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn load_macos_device_only_any_application_keychain_secret_direct_default()
-> Result<Zeroizing<[u8; KEY_LEN]>> {
    load_macos_device_only_keychain_secret_direct(
        MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE,
    )
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_device_only_keychain_secret_direct_default(secret_hex: &str) -> Result<()> {
    store_macos_device_only_keychain_secret_direct(MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE, secret_hex)
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_device_only_any_application_keychain_secret_direct_default(
    secret_hex: &str,
) -> Result<()> {
    store_macos_device_only_any_application_keychain_secret_direct(
        MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE,
        secret_hex,
    )
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn load_macos_device_only_keychain_secret_direct(
    service: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    match security_framework::passwords::generic_password(device_only_password_options(
        service,
        MACOS_KEYCHAIN_ACCOUNT,
    )) {
        Ok(secret) => String::from_utf8(secret)
            .context("macOS device-only Keychain returned non-UTF8 device seal secret")
            .and_then(|secret| {
                parse_hex_secret(
                    secret.trim(),
                    "macOS device-only Keychain device seal secret",
                )
            }),
        Err(keychain_error) => Err(anyhow::anyhow!(
            "macOS device-only Keychain device seal secret not found or unavailable: OSStatus {} ({})",
            keychain_error.code(),
            keychain_error
        )),
    }
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_device_only_keychain_secret_direct(service: &str, secret_hex: &str) -> Result<()> {
    security_framework::passwords::set_generic_password_options(
        secret_hex.as_bytes(),
        device_only_password_options(service, MACOS_KEYCHAIN_ACCOUNT),
    )
    .map_err(|keychain_error| {
        anyhow::anyhow!(
            "failed to store device seal in macOS device-only Keychain: OSStatus {} ({})",
            keychain_error.code(),
            keychain_error
        )
    })
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_device_only_any_application_keychain_secret_direct(
    service: &str,
    secret_hex: &str,
) -> Result<()> {
    security_framework::passwords::set_generic_password_options(
        secret_hex.as_bytes(),
        device_only_any_application_password_options(service, MACOS_KEYCHAIN_ACCOUNT)?,
    )
    .map_err(|keychain_error| {
        anyhow::anyhow!(
            "failed to store device seal in macOS device-only any-application Keychain: OSStatus {} ({})",
            keychain_error.code(),
            keychain_error
        )
    })
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn macos_keychain_fallback_path() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join("Library").join("Application Support")))
        .context("could not resolve user data directory for device-seal fallback")?;
    Ok(base
        .join("sshenv")
        .join("device-seal-broker")
        .join("sshenv_device_seal-default.hex"))
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn load_macos_keychain_fallback_secret() -> Result<String> {
    let path = macos_keychain_fallback_path()?;
    std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))
        .map(|secret| secret.trim().to_string())
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn store_macos_keychain_fallback_secret(secret_hex: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let path = macos_keychain_fallback_path()?;
    let parent = path
        .parent()
        .context("device-seal fallback path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to secure {}", parent.display()))?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{secret_hex}")
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

#[cfg(all(feature = "macos-keychain", target_os = "macos"))]
fn invoke_device_seal_broker(
    operation: DeviceSealBrokerOperation,
    backend: &str,
    service: &str,
    account: &str,
    secret_hex: Option<String>,
) -> Result<Option<String>> {
    let Some(raw_command) = std::env::var_os(DEVICE_SEAL_COMMAND_ENV) else {
        return Ok(None);
    };
    if raw_command.is_empty() {
        return Ok(None);
    }
    let raw_command = raw_command.to_string_lossy();
    let mut parts = raw_command.split_whitespace();
    let Some(program) = parts.next() else {
        return Ok(None);
    };
    let request = DeviceSealBrokerRequest {
        operation,
        backend: backend.to_string(),
        service: service.to_string(),
        account: account.to_string(),
        secret_hex,
    };
    let input =
        serde_json::to_vec(&request).context("failed to encode device-seal broker request")?;
    let mut child = Command::new(program)
        .args(parts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to invoke device-seal broker '{program}'"))?;
    child
        .stdin
        .as_mut()
        .context("device-seal broker stdin was unavailable")?
        .write_all(&input)
        .context("failed to write device-seal broker request")?;
    let output = child
        .wait_with_output()
        .context("failed to wait for device-seal broker")?;
    if !output.status.success() {
        bail!(
            "device-seal broker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let response: DeviceSealBrokerResponse = serde_json::from_slice(&output.stdout)
        .context("device-seal broker response was not valid JSON")?;
    if let Some(error) = response.error {
        bail!("device-seal broker failed: {error}");
    }
    Ok(match operation {
        DeviceSealBrokerOperation::Load => response.secret_hex,
        DeviceSealBrokerOperation::Store => Some(String::new()),
    })
}

#[cfg(any(
    feature = "device-seal-file",
    all(feature = "macos-keychain", target_os = "macos"),
    all(feature = "linux-secret-service", target_os = "linux"),
    feature = "secure-enclave"
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
    use std::collections::BTreeMap;

    use sshenv_vault_models::{UnlockFactorKindV2, UnlockFactorV2};

    fn device_seal_factor(params: BTreeMap<String, String>) -> UnlockFactorV2 {
        UnlockFactorV2 {
            id: "device-seal".to_string(),
            kind: UnlockFactorKindV2::DeviceSeal,
            recipient_fingerprint: None,
            params,
        }
    }

    #[test]
    fn factor_matches_device_only_any_application_metadata() {
        let mut params = BTreeMap::new();
        params.insert(
            super::BACKEND.to_string(),
            super::BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION.to_string(),
        );
        params.insert(
            super::KEYCHAIN_SERVICE.to_string(),
            super::MACOS_DEVICE_ONLY_ANY_APPLICATION_KEYCHAIN_SERVICE.to_string(),
        );
        params.insert(
            super::POLICY.to_string(),
            super::DeviceSealPolicy::TransparentDeviceOnly
                .as_str()
                .to_string(),
        );
        params.insert(super::STRICT.to_string(), "true".to_string());

        assert!(super::factor_matches_options(
            &device_seal_factor(params),
            super::DeviceSealOptions {
                selection: super::DeviceSealSelection::Backend(
                    super::DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication,
                ),
                strict: true,
            },
        ));
    }

    #[test]
    fn factor_rejects_stale_macos_device_only_any_application_service_metadata() {
        let mut params = BTreeMap::new();
        params.insert(
            super::BACKEND.to_string(),
            super::BACKEND_MACOS_KEYCHAIN_DEVICE_ONLY_ANY_APPLICATION.to_string(),
        );
        params.insert(
            super::KEYCHAIN_SERVICE.to_string(),
            super::MACOS_DEVICE_ONLY_KEYCHAIN_SERVICE.to_string(),
        );
        params.insert(
            super::POLICY.to_string(),
            super::DeviceSealPolicy::TransparentDeviceOnly
                .as_str()
                .to_string(),
        );
        params.insert(super::STRICT.to_string(), "true".to_string());

        assert!(!super::factor_matches_options(
            &device_seal_factor(params),
            super::DeviceSealOptions {
                selection: super::DeviceSealSelection::Backend(
                    super::DeviceSealBackendSelection::MacosKeychainDeviceOnlyAnyApplication,
                ),
                strict: true,
            },
        ));
    }

    #[cfg(all(feature = "windows-dpapi", target_os = "windows"))]
    #[test]
    fn windows_dpapi_roundtrips_device_secret() {
        super::test_windows_dpapi_roundtrip();
    }

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
