//! Application-owned vaults.
//!
//! An application that keeps its own secrets (API keys, webhook URLs, tokens) owns one vault
//! file plus a dedicated, generated Ed25519 identity stored next to it. The user's own SSH keys
//! and their passphrases are never involved, so unlocking is prompt-free and works from
//! background jobs. Profiles are encrypted individually and can be bound to this device with a
//! device seal according to an [`AppDeviceSealOptions`] policy.
//!
//! ```no_run
//! use sshenv_vault::app::{AppVault, AppVaultConfig};
//! use zeroize::Zeroizing;
//!
//! let vault = AppVault::new(AppVaultConfig::new("myapp", "/home/me/.local/state/myapp/vault"));
//! vault.set("openai", "API_KEY", Zeroizing::new("sk-...".to_owned()))?;
//! let key = vault.get("openai", "API_KEY")?;
//! # Ok::<(), sshenv_vault::app::AppVaultError>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};
use sshenv_vault_models::{
    ProfileFactorRequirement, UnlockFactorKindV2, UnlockFactorV2, VERSION_V2,
};
use zeroize::{Zeroize as _, Zeroizing};

use crate::device::{
    DeviceSealBackendSelection, DeviceSealOptions, DeviceSealPolicy, DeviceSealSelection,
    factor_matches_options,
};
use crate::recipient::fingerprint_from_line;
use crate::{DataKey, SshenvStore, SshenvStoreConfig, Vault};

const KEY_DIR_SUFFIX: &str = "keys";

/// Errors from application-owned vault operations.
#[derive(Debug, thiserror::Error)]
pub enum AppVaultError {
    /// Only one half of the managed keypair exists; it must be repaired manually.
    #[error(
        "vault identity is incomplete; expected both {} and {}",
        private_key.display(),
        public_key.display()
    )]
    IncompleteIdentity {
        /// Expected private key path.
        private_key: PathBuf,
        /// Expected public key path.
        public_key: PathBuf,
    },
    /// The managed identity could not be created or read.
    #[error("vault identity: {0}")]
    Identity(String),
    /// The vault exists but could not be read or unlocked.
    #[error("vault unavailable: {0}")]
    Unavailable(String),
    /// The vault could not be written.
    #[error("vault write failed: {0}")]
    Write(String),
    /// The value already exists and the operation does not overwrite.
    #[error("{profile}/{var} already exists")]
    AlreadyExists {
        /// Profile name.
        profile: String,
        /// Variable name.
        var: String,
    },
    /// The configured device-seal policy is `Required` and could not be satisfied.
    #[error("device seal required for profile {profile}: {reason}")]
    DeviceSealRequired {
        /// Profile name.
        profile: String,
        /// Why the seal could not be applied.
        reason: String,
    },
}

/// Whether an application wants its vault profiles bound to this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppDeviceSealPolicy {
    /// Do not add a device seal automatically.
    Off,
    /// Add a device seal when the local host supports it; continue without one on failure.
    Preferred,
    /// Add a device seal and treat failure as an error.
    Required,
}

impl AppDeviceSealPolicy {
    /// Parse a user-facing setting (`off`, `preferred`, `required`, and common synonyms).
    ///
    /// Returns `None` for unrecognized values.
    #[must_use]
    pub fn from_setting(value: &str) -> Option<Self> {
        match normalize_setting(value).as_str() {
            "off" | "false" | "disabled" | "never" => Some(Self::Off),
            "preferred" | "prefer" | "auto" => Some(Self::Preferred),
            "required" | "require" | "true" | "on" => Some(Self::Required),
            _ => None,
        }
    }

    /// Stable lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Preferred => "preferred",
            Self::Required => "required",
        }
    }
}

/// Complete device-seal configuration for an application vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppDeviceSealOptions {
    /// Whether to reconcile a profile device seal.
    pub policy: AppDeviceSealPolicy,
    /// Concrete sshenv device-seal selection and strictness.
    pub seal: DeviceSealOptions,
}

impl AppDeviceSealOptions {
    /// Prompt-free default: prefer a local-file device seal, never fail without one.
    #[must_use]
    pub const fn preferred_prompt_free() -> Self {
        Self {
            policy: AppDeviceSealPolicy::Preferred,
            seal: DeviceSealOptions {
                selection: DeviceSealSelection::Backend(DeviceSealBackendSelection::LocalFile),
                strict: false,
            },
        }
    }

    /// Strict: require a transparent, device-only seal.
    #[must_use]
    pub const fn required_transparent_device_only() -> Self {
        Self {
            policy: AppDeviceSealPolicy::Required,
            seal: DeviceSealOptions {
                selection: DeviceSealSelection::Policy(DeviceSealPolicy::TransparentDeviceOnly),
                strict: true,
            },
        }
    }

    /// No device seal.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            policy: AppDeviceSealPolicy::Off,
            ..Self::preferred_prompt_free()
        }
    }

    /// Default options for a policy.
    #[must_use]
    pub const fn from_policy(policy: AppDeviceSealPolicy) -> Self {
        match policy {
            AppDeviceSealPolicy::Required => Self::required_transparent_device_only(),
            AppDeviceSealPolicy::Off | AppDeviceSealPolicy::Preferred => Self {
                policy,
                ..Self::preferred_prompt_free()
            },
        }
    }

    /// Build options from user-facing settings, falling back to `default_policy`.
    ///
    /// * `policy`: `off` / `preferred` / `required`
    /// * `backend`: a concrete backend name, see [`parse_device_seal_backend`]
    /// * `mode`: a high-level selection, see [`parse_device_seal_mode`]
    /// * `strict`: boolean-ish
    ///
    /// Unrecognized values fall back to the policy's defaults.
    #[must_use]
    pub fn from_settings(
        default_policy: AppDeviceSealPolicy,
        policy: Option<&str>,
        backend: Option<&str>,
        mode: Option<&str>,
        strict: Option<&str>,
    ) -> Self {
        let policy = policy
            .and_then(AppDeviceSealPolicy::from_setting)
            .unwrap_or(default_policy);
        let defaults = Self::from_policy(policy);
        let selection = backend.and_then(parse_device_seal_backend).map_or_else(
            || {
                mode.and_then(parse_device_seal_mode)
                    .map_or(defaults.seal.selection, DeviceSealSelection::Policy)
            },
            DeviceSealSelection::Backend,
        );
        let strict = strict.map_or(defaults.seal.strict, |value| {
            parse_bool_setting(value, defaults.seal.strict)
        });
        Self {
            policy,
            seal: DeviceSealOptions { selection, strict },
        }
    }
}

impl Default for AppDeviceSealOptions {
    fn default() -> Self {
        Self::preferred_prompt_free()
    }
}

/// Parse a high-level device-seal mode setting (`default`, `transparent-device-only`).
#[must_use]
pub fn parse_device_seal_mode(value: &str) -> Option<DeviceSealPolicy> {
    match normalize_setting(value).as_str() {
        "default" | "legacy" => Some(DeviceSealPolicy::Default),
        "transparentdeviceonly" | "transparentlocaldevice" | "devicelocaltransparent" => {
            Some(DeviceSealPolicy::TransparentDeviceOnly)
        }
        _ => None,
    }
}

/// Parse a concrete device-seal backend setting (`macos-keychain-device-only`, `local-file`, ...).
#[must_use]
pub fn parse_device_seal_backend(value: &str) -> Option<DeviceSealBackendSelection> {
    match normalize_setting(value).as_str() {
        "macoskeychain" => Some(DeviceSealBackendSelection::MacosKeychain),
        "macoskeychaindeviceonly" => Some(DeviceSealBackendSelection::MacosKeychainDeviceOnly),
        "windowsdpapi" | "windowsdpapicurrentuser" => {
            Some(DeviceSealBackendSelection::WindowsDpapiCurrentUser)
        }
        "linuxtpm" | "tpm" => Some(DeviceSealBackendSelection::LinuxTpm),
        "linuxsecretservice" | "secretservice" => {
            Some(DeviceSealBackendSelection::LinuxSecretService)
        }
        "secureenclave" => Some(DeviceSealBackendSelection::SecureEnclave),
        "localfile" => Some(DeviceSealBackendSelection::LocalFile),
        _ => None,
    }
}

/// Parse a boolean-ish setting, returning `default` for unrecognized values.
#[must_use]
pub fn parse_bool_setting(value: &str, default: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "strict" => true,
        "0" | "false" | "no" | "off" | "relaxed" => false,
        _ => default,
    }
}

fn normalize_setting(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Configuration of an application-owned vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppVaultConfig {
    /// Vault file path.
    pub vault_path: PathBuf,
    /// File stem of the managed keypair (`<key_name>_sshenv_ed25519`).
    pub key_name: String,
    /// Comment written into the managed key.
    pub key_comment: String,
    /// Device-seal policy for profiles written through this vault.
    pub device_seal: AppDeviceSealOptions,
}

impl AppVaultConfig {
    /// Configuration for application `app` with the prompt-free preferred device seal.
    #[must_use]
    pub fn new(app: &str, vault_path: impl Into<PathBuf>) -> Self {
        Self {
            vault_path: vault_path.into(),
            key_name: app.to_owned(),
            key_comment: format!("{app} sshenv vault key"),
            device_seal: AppDeviceSealOptions::default(),
        }
    }

    /// Override the device-seal options.
    #[must_use]
    pub const fn with_device_seal(mut self, device_seal: AppDeviceSealOptions) -> Self {
        self.device_seal = device_seal;
        self
    }
}

/// Something that changed while reconciling a profile's security.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityAction {
    /// The vault was migrated to format v2.
    MigratedToV2,
    /// Per-profile encryption was enabled.
    EnabledProfileKeys,
    /// The profile was bound to this device.
    BoundDeviceSeal,
    /// An existing device seal was replaced with the configured one.
    ReboundDeviceSeal,
    /// The profile is sealed although policy is `Off`; the stronger state was kept.
    KeptStrongerSeal,
}

impl fmt::Display for SecurityAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MigratedToV2 => "migrated vault to sshenv v2",
            Self::EnabledProfileKeys => "enabled per-profile vault encryption",
            Self::BoundDeviceSeal => "bound profile to this device",
            Self::ReboundDeviceSeal => "rebound profile to the configured device seal",
            Self::KeptStrongerSeal => {
                "profile is device-sealed although device sealing is off; left unchanged"
            }
        })
    }
}

/// Outcome of a write: what security reconciliation did, or why it was skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Changes applied.
    pub actions: Vec<SecurityAction>,
    /// Set when a `Preferred` device seal could not be applied (the write still succeeded).
    pub skipped: Option<String>,
}

/// Non-mutating security problems found by [`AppVault::inspect`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityIssue {
    /// The vault file does not exist.
    VaultMissing,
    /// The vault metadata could not be unlocked.
    UnlockFailed(String),
    /// The profile exists but could not be unlocked.
    ProfileUnlockFailed(String),
    /// The profile does not exist.
    ProfileMissing,
    /// Device sealing is preferred or required but the profile is not sealed.
    DeviceSealMissing,
    /// Device sealing is off but the profile is sealed (informational).
    StrongerThanPolicy,
}

impl SecurityIssue {
    /// Stable snake-case code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::VaultMissing => "vault_missing",
            Self::UnlockFailed(_) => "vault_unlock_failed",
            Self::ProfileUnlockFailed(_) => "vault_profile_unlock_failed",
            Self::ProfileMissing => "vault_profile_missing",
            Self::DeviceSealMissing => "vault_device_seal_missing",
            Self::StrongerThanPolicy => "vault_stronger_than_policy",
        }
    }
}

impl fmt::Display for SecurityIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultMissing => f.write_str("vault does not exist"),
            Self::UnlockFailed(e) => write!(f, "vault metadata could not be unlocked: {e}"),
            Self::ProfileUnlockFailed(e) => write!(f, "profile could not be unlocked: {e}"),
            Self::ProfileMissing => f.write_str("profile does not exist"),
            Self::DeviceSealMissing => f.write_str("profile is not device-sealed"),
            Self::StrongerThanPolicy => {
                f.write_str("profile is device-sealed although device sealing is off")
            }
        }
    }
}

/// Read-only security status of one profile.
#[allow(clippy::struct_excessive_bools)] // flat status record serialized as-is
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSecurityStatus {
    /// Vault path inspected.
    pub vault_path: PathBuf,
    /// Profile inspected.
    pub profile: String,
    /// Configured device-seal policy.
    pub policy: AppDeviceSealPolicy,
    /// Whether the vault file exists.
    pub vault_exists: bool,
    /// Vault format version when readable.
    pub vault_version: Option<u8>,
    /// Whether per-profile encryption is enabled.
    pub profile_keys_enabled: bool,
    /// Whether the profile exists.
    pub profile_exists: bool,
    /// Whether the profile requires a device seal.
    pub profile_device_sealed: bool,
    /// Device-seal backend recorded in profile metadata.
    pub device_seal_backend: Option<String>,
    /// Device-seal mode recorded in profile metadata.
    pub device_seal_mode: Option<String>,
    /// Strictness recorded in profile metadata.
    pub device_seal_strict: Option<bool>,
    /// macOS Keychain service recorded in profile metadata when applicable.
    pub device_seal_keychain_service: Option<String>,
    /// Whether the configured policy is satisfied.
    pub policy_satisfied: bool,
    /// Problems found.
    pub issues: Vec<SecurityIssue>,
}

/// An application-owned sshenv vault.
#[derive(Debug, Clone)]
pub struct AppVault {
    config: AppVaultConfig,
}

impl AppVault {
    /// Wrap a configuration. Nothing is touched on disk until a write.
    #[must_use]
    pub const fn new(config: AppVaultConfig) -> Self {
        Self { config }
    }

    /// This vault's configuration.
    #[must_use]
    pub const fn config(&self) -> &AppVaultConfig {
        &self.config
    }

    /// Vault file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.config.vault_path
    }

    /// Whether the vault file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.config.vault_path.exists()
    }

    /// Directory holding the managed keypair (`<vault>.keys`).
    #[must_use]
    pub fn identity_dir(&self) -> PathBuf {
        let mut dir = self.config.vault_path.as_os_str().to_os_string();
        dir.push(".");
        dir.push(KEY_DIR_SUFFIX);
        PathBuf::from(dir)
    }

    /// Managed private key path.
    #[must_use]
    pub fn private_key_path(&self) -> PathBuf {
        self.identity_dir()
            .join(format!("{}_sshenv_ed25519", self.config.key_name))
    }

    /// Managed public key path.
    #[must_use]
    pub fn public_key_path(&self) -> PathBuf {
        self.identity_dir()
            .join(format!("{}_sshenv_ed25519.pub", self.config.key_name))
    }

    /// Private keys used to unlock this vault (only the managed one).
    #[must_use]
    pub fn private_key_paths(&self) -> Vec<PathBuf> {
        vec![self.private_key_path()]
    }

    /// The underlying store, unlocking with the managed identity only.
    #[must_use]
    pub fn store(&self) -> SshenvStore {
        SshenvStore::new(
            SshenvStoreConfig::new(self.config.vault_path.clone())
                .with_private_key_paths(self.private_key_paths()),
        )
    }

    /// Read the managed recipient public key if the complete keypair exists.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::IncompleteIdentity`] if only one half of the keypair exists
    /// * [`AppVaultError::Identity`] if the public key cannot be read
    pub fn read_recipient_key(&self) -> Result<Option<String>, AppVaultError> {
        let private_key = self.private_key_path();
        let public_key = self.public_key_path();
        match (private_key.exists(), public_key.exists()) {
            (true, true) => read_public_key_file(&public_key).map(Some),
            (false, false) => Ok(None),
            _ => Err(AppVaultError::IncompleteIdentity {
                private_key,
                public_key,
            }),
        }
    }

    /// Create the managed keypair if needed and return its public key line.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::IncompleteIdentity`] if only one half of the keypair exists
    /// * [`AppVaultError::Identity`] if generation or file writes fail
    pub fn ensure_recipient_key(&self) -> Result<String, AppVaultError> {
        if let Some(key) = self.read_recipient_key()? {
            return Ok(key);
        }
        let dir = self.identity_dir();
        fs::create_dir_all(&dir).map_err(|e| identity_error("create", &dir, &e))?;
        restrict_permissions(&dir, 0o700)?;

        let mut private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| AppVaultError::Identity(format!("generate key: {e}")))?;
        private_key.set_comment(&self.config.key_comment);
        let private_text = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| AppVaultError::Identity(format!("encode private key: {e}")))?;
        let public_text = private_key
            .public_key()
            .to_openssh()
            .map_err(|e| AppVaultError::Identity(format!("encode public key: {e}")))?;

        let private_path = self.private_key_path();
        let public_path = self.public_key_path();
        fs::write(&private_path, private_text.as_bytes())
            .map_err(|e| identity_error("write", &private_path, &e))?;
        restrict_permissions(&private_path, 0o600)?;
        fs::write(&public_path, format!("{public_text}\n"))
            .map_err(|e| identity_error("write", &public_path, &e))?;
        restrict_permissions(&public_path, 0o644)?;
        read_public_key_file(&public_path)
    }

    /// Validate an existing vault, or create it (identity, v2 format, per-profile keys).
    ///
    /// Never resets or archives a damaged vault. Returns the recipient public key.
    ///
    /// # Errors
    ///
    /// * identity errors from [`Self::ensure_recipient_key`]
    /// * [`AppVaultError::Unavailable`] if an existing vault cannot be unlocked
    /// * [`AppVaultError::Write`] if a new vault cannot be written
    pub fn open_or_create(&self) -> Result<String, AppVaultError> {
        let recipient = self.ensure_recipient_key()?;
        if self.exists() {
            self.load_metadata()?;
        } else {
            // Only tighten a directory created here; never change one the user already owns.
            if let Some(parent) = self.config.vault_path.parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                fs::create_dir_all(parent).map_err(|e| AppVaultError::Write(e.to_string()))?;
                restrict_permissions(parent, 0o700)?;
            }
            let store = self.store();
            store
                .init(&recipient)
                .map_err(|e| AppVaultError::Write(e.to_string()))?;
            let (mut vault, data_key) = store
                .load_and_unlock()
                .map_err(|e| AppVaultError::Unavailable(e.to_string()))?;
            vault
                .migrate_to_v2(std::slice::from_ref(&recipient))
                .map_err(|e| AppVaultError::Write(e.to_string()))?;
            vault
                .enable_profile_keys()
                .map_err(|e| AppVaultError::Write(e.to_string()))?;
            vault
                .save(&self.config.vault_path, &data_key)
                .map_err(|e| AppVaultError::Write(e.to_string()))?;
        }
        Ok(recipient)
    }

    /// Unlock vault metadata (profile entries stay encrypted).
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::Unavailable`] if the vault cannot be read or unlocked
    pub fn load_metadata(&self) -> Result<(Vault, DataKey), AppVaultError> {
        crate::load_and_unlock_metadata_with_private_key_paths(
            &self.config.vault_path,
            &self.private_key_paths(),
        )
        .map_err(|e| AppVaultError::Unavailable(e.to_string()))
    }

    /// One secret value. A missing vault reads as `None`.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::Unavailable`] if the vault or profile cannot be unlocked
    pub fn get(
        &self,
        profile: &str,
        var: &str,
    ) -> Result<Option<Zeroizing<String>>, AppVaultError> {
        if !self.exists() {
            return Ok(None);
        }
        self.store()
            .get_secret(profile, var)
            .map_err(|e| AppVaultError::Unavailable(e.to_string()))
    }

    /// Every value of one profile. A missing vault or profile reads as `None`.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::Unavailable`] if the vault or profile cannot be unlocked
    pub fn get_profile(
        &self,
        profile: &str,
    ) -> Result<Option<BTreeMap<String, Zeroizing<String>>>, AppVaultError> {
        if !self.exists() {
            return Ok(None);
        }
        self.store()
            .get_profile(profile)
            .map_err(|e| AppVaultError::Unavailable(e.to_string()))
    }

    /// Profile names, without unlocking any profile.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::Unavailable`] if the vault metadata cannot be unlocked
    pub fn profile_names(&self) -> Result<BTreeSet<String>, AppVaultError> {
        if !self.exists() {
            return Ok(BTreeSet::new());
        }
        let (mut vault, _key) = self.load_metadata()?;
        let names = vault
            .profiles
            .profiles
            .keys()
            .chain(vault.profiles.profile_entries.keys())
            .cloned()
            .collect();
        zeroize_vault_values(&mut vault);
        Ok(names)
    }

    /// Variable names of one profile (values are unlocked and wiped immediately).
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::Unavailable`] if the vault or profile cannot be unlocked
    pub fn var_names(&self, profile: &str) -> Result<BTreeSet<String>, AppVaultError> {
        Ok(self
            .get_profile(profile)?
            .map(|values| values.into_keys().collect())
            .unwrap_or_default())
    }

    /// Store a value (creating the vault if needed), then reconcile the device seal.
    ///
    /// # Errors
    ///
    /// * errors from [`Self::open_or_create`]
    /// * [`AppVaultError::Write`] if the value cannot be saved
    /// * [`AppVaultError::DeviceSealRequired`] if the policy is `Required` and unsatisfiable
    pub fn set(
        &self,
        profile: &str,
        var: &str,
        value: Zeroizing<String>,
    ) -> Result<SecurityReport, AppVaultError> {
        let recipient = self.open_or_create()?;
        self.store()
            .set_secret(profile, var, value)
            .map_err(|e| AppVaultError::Write(e.to_string()))?;
        self.reconcile(profile, Some(&recipient))
    }

    /// Store a value only when absent, then reconcile the device seal.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::AlreadyExists`] if the value exists
    /// * otherwise as [`Self::set`]
    pub fn insert_if_absent(
        &self,
        profile: &str,
        var: &str,
        value: Zeroizing<String>,
    ) -> Result<SecurityReport, AppVaultError> {
        let recipient = self.open_or_create()?;
        if self.get(profile, var)?.is_some() {
            return Err(AppVaultError::AlreadyExists {
                profile: profile.to_owned(),
                var: var.to_owned(),
            });
        }
        self.store()
            .insert_secret_if_absent(profile, var, value)
            .map_err(|e| AppVaultError::Write(e.to_string()))?;
        self.reconcile(profile, Some(&recipient))
    }

    /// Remove one value. Returns whether it existed.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::Unavailable`] if the vault cannot be unlocked or saved
    pub fn unset(&self, profile: &str, var: &str) -> Result<bool, AppVaultError> {
        if !self.exists() {
            return Ok(false);
        }
        self.store()
            .unset_secret(profile, var)
            .map_err(|e| AppVaultError::Unavailable(e.to_string()))
    }

    /// Non-destructively bring `profile` in line with the configured device-seal policy.
    ///
    /// A `Preferred` policy that cannot be applied is reported in
    /// [`SecurityReport::skipped`] rather than failing.
    ///
    /// # Errors
    ///
    /// * [`AppVaultError::DeviceSealRequired`] if the policy is `Required` and unsatisfiable
    pub fn reconcile(
        &self,
        profile: &str,
        explicit_recipient_key: Option<&str>,
    ) -> Result<SecurityReport, AppVaultError> {
        let result = (|| {
            if !self.exists() {
                return Ok(Vec::new());
            }
            let (mut vault, data_key) = self.load_metadata().map_err(|e| e.to_string())?;
            let result =
                self.prepare_security(&mut vault, &data_key, profile, explicit_recipient_key);
            let outcome = match result {
                Ok((actions, true)) => vault
                    .save(&self.config.vault_path, &data_key)
                    .map(|()| actions)
                    .map_err(|e| format!("save reconciled vault: {e}")),
                Ok((actions, false)) => Ok(actions),
                Err(e) => Err(e),
            };
            zeroize_vault_values(&mut vault);
            outcome
        })();
        match result {
            Ok(actions) => Ok(SecurityReport {
                actions,
                skipped: None,
            }),
            Err(reason) if self.config.device_seal.policy == AppDeviceSealPolicy::Required => {
                Err(AppVaultError::DeviceSealRequired {
                    profile: profile.to_owned(),
                    reason,
                })
            }
            Err(reason) => Ok(SecurityReport {
                actions: Vec::new(),
                skipped: Some(reason),
            }),
        }
    }

    /// Apply the configured policy to `profile` on a caller-loaded vault without saving.
    ///
    /// Returns the actions taken and whether the vault changed. On error the caller must
    /// discard `vault`.
    ///
    /// # Errors
    ///
    /// Returns a description when the profile cannot be unlocked, the vault cannot be
    /// migrated (recipient keys missing), or the device seal cannot be bound.
    pub fn prepare_security(
        &self,
        vault: &mut Vault,
        data_key: &[u8; 32],
        profile: &str,
        explicit_recipient_key: Option<&str>,
    ) -> Result<(Vec<SecurityAction>, bool), String> {
        let options = self.config.device_seal;
        if options.policy == AppDeviceSealPolicy::Off {
            let actions = if profile_has_device_seal(vault, profile) {
                vec![SecurityAction::KeptStrongerSeal]
            } else {
                Vec::new()
            };
            return Ok((actions, false));
        }
        if !profile_exists(vault, profile)
            || (profile_has_device_seal(vault, profile)
                && profile_device_seal_matches(vault, profile, options.seal))
        {
            return Ok((Vec::new(), false));
        }
        if vault.profiles.get(profile).is_none() {
            vault
                .unlock_profile_with_passphrase(profile, data_key, None)
                .map_err(|e| format!("unlock profile {profile}: {e}"))?;
        }

        let mut actions = Vec::new();
        if vault.header.version != VERSION_V2 {
            let keys = self.recipient_keys_for(vault, explicit_recipient_key)?;
            vault
                .migrate_to_v2(&keys)
                .map_err(|e| format!("migrate vault to v2: {e}"))?;
            actions.push(SecurityAction::MigratedToV2);
        }
        if !vault.profile_keys_enabled() {
            vault
                .enable_profile_keys()
                .map_err(|e| format!("enable profile keys: {e}"))?;
            actions.push(SecurityAction::EnabledProfileKeys);
        }
        let rebinding = profile_has_device_seal(vault, profile);
        vault
            .require_profile_device_seal_with_options(profile, options.seal)
            .map_err(|e| format!("bind profile {profile} to this device: {e}"))?;
        actions.push(if rebinding {
            SecurityAction::ReboundDeviceSeal
        } else {
            SecurityAction::BoundDeviceSeal
        });
        Ok((actions, true))
    }

    /// Inspect one profile's security without mutating anything.
    #[must_use]
    pub fn inspect(&self, profile: &str) -> ProfileSecurityStatus {
        let policy = self.config.device_seal.policy;
        let mut status = ProfileSecurityStatus {
            vault_path: self.config.vault_path.clone(),
            profile: profile.to_owned(),
            policy,
            vault_exists: self.exists(),
            vault_version: None,
            profile_keys_enabled: false,
            profile_exists: false,
            profile_device_sealed: false,
            device_seal_backend: None,
            device_seal_mode: None,
            device_seal_strict: None,
            device_seal_keychain_service: None,
            policy_satisfied: policy != AppDeviceSealPolicy::Required,
            issues: Vec::new(),
        };
        if !status.vault_exists {
            status.issues.push(SecurityIssue::VaultMissing);
            return status;
        }
        if let Ok(ciphertext) = Vault::load_ciphertext(&self.config.vault_path) {
            status.vault_version = Some(ciphertext.header.version);
        }
        let (mut vault, data_key) = match self.load_metadata() {
            Ok(loaded) => loaded,
            Err(e) => {
                status
                    .issues
                    .push(SecurityIssue::UnlockFailed(e.to_string()));
                return status;
            }
        };
        status.vault_version = Some(vault.header.version);
        status.profile_keys_enabled = vault.profile_keys_enabled();
        status.profile_exists = profile_exists(&vault, profile);
        status.profile_device_sealed = profile_has_device_seal(&vault, profile);
        if let Some(metadata) = profile_device_seal_metadata(&vault, profile) {
            status.device_seal_backend = metadata.params.get("backend").cloned();
            status.device_seal_mode = metadata.params.get("policy").cloned();
            status.device_seal_strict = metadata
                .params
                .get("strict")
                .map(|value| parse_bool_setting(value, true));
            status.device_seal_keychain_service = metadata.params.get("keychain-service").cloned();
        }
        let unlockable = if status.profile_exists && vault.profiles.get(profile).is_none() {
            match vault.unlock_profile_with_passphrase(profile, &data_key, None) {
                Ok(()) => true,
                Err(e) => {
                    status
                        .issues
                        .push(SecurityIssue::ProfileUnlockFailed(e.to_string()));
                    false
                }
            }
        } else {
            true
        };
        zeroize_vault_values(&mut vault);
        status.policy_satisfied = match policy {
            AppDeviceSealPolicy::Off | AppDeviceSealPolicy::Preferred => true,
            AppDeviceSealPolicy::Required => status.profile_device_sealed && unlockable,
        };
        if !status.profile_exists {
            status.issues.push(SecurityIssue::ProfileMissing);
        } else if policy != AppDeviceSealPolicy::Off && !status.profile_device_sealed {
            status.issues.push(SecurityIssue::DeviceSealMissing);
        } else if policy == AppDeviceSealPolicy::Off && status.profile_device_sealed {
            status.issues.push(SecurityIssue::StrongerThanPolicy);
        }
        status
    }

    fn recipient_keys_for(
        &self,
        vault: &Vault,
        explicit_recipient_key: Option<&str>,
    ) -> Result<Vec<String>, String> {
        let candidate = match explicit_recipient_key.and_then(read_public_key_arg) {
            Some(key) => Some(key),
            None => self.read_recipient_key().ok().flatten(),
        };
        let by_fingerprint: BTreeMap<String, String> = candidate
            .into_iter()
            .filter_map(|line| fingerprint_from_line(&line).ok().map(|fp| (fp, line)))
            .collect();
        let mut keys = Vec::new();
        let mut missing = Vec::new();
        let expected: BTreeSet<&String> = vault.recipients.iter().map(|r| &r.fingerprint).collect();
        for fingerprint in expected {
            match by_fingerprint.get(fingerprint) {
                Some(line) => keys.push(line.clone()),
                None => missing.push(fingerprint.clone()),
            }
        }
        if missing.is_empty() {
            Ok(keys)
        } else {
            Err(format!(
                "cannot migrate vault to v2: recipient public keys not found for {}",
                missing.join(", ")
            ))
        }
    }
}

/// Whether `profile` exists, unlocked or still encrypted.
#[must_use]
pub fn profile_exists(vault: &Vault, profile: &str) -> bool {
    vault.profiles.profiles.contains_key(profile)
        || vault.profiles.profile_entries.contains_key(profile)
}

/// Whether `profile` requires a device seal and records its metadata.
#[must_use]
pub fn profile_has_device_seal(vault: &Vault, profile: &str) -> bool {
    profile_device_seal_metadata(vault, profile).is_some()
        && vault
            .profiles
            .profile_policy(profile)
            .is_some_and(|policy| {
                policy
                    .required_factors
                    .contains(&ProfileFactorRequirement::DeviceSeal)
            })
}

/// Whether `profile`'s device seal matches `options`.
#[must_use]
pub fn profile_device_seal_matches(
    vault: &Vault,
    profile: &str,
    options: DeviceSealOptions,
) -> bool {
    profile_device_seal_metadata(vault, profile)
        .is_some_and(|metadata| factor_matches_options(metadata, options))
}

/// Device-seal factor metadata recorded for `profile`.
#[must_use]
pub fn profile_device_seal_metadata<'a>(
    vault: &'a Vault,
    profile: &str,
) -> Option<&'a UnlockFactorV2> {
    vault.profiles.profile_policy(profile).and_then(|policy| {
        policy
            .factor_metadata
            .iter()
            .find(|factor| factor.kind == UnlockFactorKindV2::DeviceSeal)
    })
}

/// Wipe every unlocked plaintext value held by `vault`.
pub fn zeroize_vault_values(vault: &mut Vault) {
    for values in vault.profiles.profiles.values_mut() {
        for value in values.values_mut() {
            value.zeroize();
        }
    }
}

fn read_public_key_arg(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with("ssh-") {
        return Some(trimmed.to_owned());
    }
    fs::read_to_string(trimmed).ok()
}

fn read_public_key_file(path: &Path) -> Result<String, AppVaultError> {
    let contents = fs::read_to_string(path).map_err(|e| identity_error("read", path, &e))?;
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            AppVaultError::Identity(format!("{} has no public key line", path.display()))
        })
}

fn identity_error(action: &str, path: &Path, error: &std::io::Error) -> AppVaultError {
    AppVaultError::Identity(format!("{action} {}: {error}", path.display()))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path, mode: u32) -> Result<(), AppVaultError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| identity_error("restrict permissions of", path, &e))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // same fallible interface as the Unix version
const fn restrict_permissions(_path: &Path, _mode: u32) -> Result<(), AppVaultError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(dir: &Path) -> AppVault {
        AppVault::new(
            AppVaultConfig::new("testapp", dir.join("state").join("vault"))
                .with_device_seal(AppDeviceSealOptions::off()),
        )
    }

    #[test]
    fn missing_vault_reads_empty_without_creating_anything() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        assert!(v.get("p", "K").unwrap().is_none());
        assert!(!v.unset("p", "K").unwrap());
        assert!(v.profile_names().unwrap().is_empty());
        assert!(!v.exists());
        assert!(!v.identity_dir().exists());
        assert_eq!(v.inspect("p").issues, vec![SecurityIssue::VaultMissing]);
    }

    #[test]
    fn set_get_unset_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        v.set("openai", "API_KEY", Zeroizing::new("sk-1".into()))
            .unwrap();
        assert!(v.exists());
        assert!(v.private_key_path().exists() && v.public_key_path().exists());
        assert_eq!(
            v.get("openai", "API_KEY")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("sk-1")
        );
        v.set("openai", "API_KEY", Zeroizing::new("sk-2".into()))
            .unwrap();
        v.set("notify", "WEBHOOK", Zeroizing::new("https://x".into()))
            .unwrap();
        assert_eq!(
            v.get("openai", "API_KEY")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("sk-2")
        );
        assert_eq!(
            v.profile_names().unwrap().into_iter().collect::<Vec<_>>(),
            ["notify", "openai"]
        );
        assert_eq!(
            v.var_names("openai")
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            ["API_KEY"]
        );
        assert!(v.unset("openai", "API_KEY").unwrap());
        assert!(v.get("openai", "API_KEY").unwrap().is_none());
        assert!(v.get("notify", "WEBHOOK").unwrap().is_some());
    }

    #[test]
    fn insert_if_absent_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        v.insert_if_absent("p", "K", Zeroizing::new("a".into()))
            .unwrap();
        let err = v
            .insert_if_absent("p", "K", Zeroizing::new("b".into()))
            .unwrap_err();
        assert!(matches!(err, AppVaultError::AlreadyExists { .. }), "{err}");
        assert_eq!(
            v.get("p", "K").unwrap().as_deref().map(String::as_str),
            Some("a")
        );
    }

    #[test]
    fn existing_identity_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let first = v.ensure_recipient_key().unwrap();
        assert_eq!(v.ensure_recipient_key().unwrap(), first);
        assert!(first.starts_with("ssh-ed25519 "));
        assert!(first.ends_with("testapp sshenv vault key"));
    }

    #[test]
    fn half_identity_is_reported_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        v.ensure_recipient_key().unwrap();
        fs::remove_file(v.private_key_path()).unwrap();
        assert!(matches!(
            v.ensure_recipient_key(),
            Err(AppVaultError::IncompleteIdentity { .. })
        ));
        assert!(v.public_key_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn identity_files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        v.ensure_recipient_key().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&v.identity_dir()), 0o700);
        assert_eq!(mode(&v.private_key_path()), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn existing_parent_directory_permissions_are_left_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("shared");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let v = AppVault::new(
            AppVaultConfig::new("testapp", parent.join("vault"))
                .with_device_seal(AppDeviceSealOptions::off()),
        );
        v.set("p", "K", Zeroizing::new("a".into())).unwrap();
        let mode = fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn values_never_appear_in_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        v.set("p", "K", Zeroizing::new("super-secret-value".into()))
            .unwrap();
        let bytes = fs::read(v.path()).unwrap();
        assert!(
            !bytes
                .windows(b"super-secret-value".len())
                .any(|w| w == b"super-secret-value")
        );
    }

    #[test]
    fn inspect_reports_unsealed_profile_per_policy() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        v.set("p", "K", Zeroizing::new("a".into())).unwrap();
        let status = v.inspect("p");
        assert!(status.profile_exists && status.policy_satisfied && status.profile_keys_enabled);
        assert!(status.issues.is_empty(), "{:?}", status.issues);
        assert_eq!(
            v.inspect("other").issues,
            vec![SecurityIssue::ProfileMissing]
        );

        let required = AppVault::new(
            v.config()
                .clone()
                .with_device_seal(AppDeviceSealOptions::required_transparent_device_only()),
        );
        let status = required.inspect("p");
        assert!(!status.policy_satisfied);
        assert_eq!(status.issues, vec![SecurityIssue::DeviceSealMissing]);
    }

    #[test]
    fn settings_parse_with_fallbacks() {
        assert_eq!(
            AppDeviceSealPolicy::from_setting("Required"),
            Some(AppDeviceSealPolicy::Required)
        );
        assert_eq!(AppDeviceSealPolicy::from_setting("bogus"), None);
        assert_eq!(
            parse_device_seal_backend("macos-keychain-device-only"),
            Some(DeviceSealBackendSelection::MacosKeychainDeviceOnly)
        );
        let options = AppDeviceSealOptions::from_settings(
            AppDeviceSealPolicy::Preferred,
            Some("off"),
            None,
            Some("transparent-device-only"),
            Some("yes"),
        );
        assert_eq!(options.policy, AppDeviceSealPolicy::Off);
        assert_eq!(
            options.seal,
            DeviceSealOptions {
                selection: DeviceSealSelection::Policy(DeviceSealPolicy::TransparentDeviceOnly),
                strict: true,
            }
        );
    }
}
