//! Data structures and constants for the sshenv vault file format.
//!
//! The on-disk vault format is:
//!
//! ```text
//! MAGIC       b"SSHE"          (4 bytes)
//! VERSION     0x01             (1 byte)
//! FLAGS       0x00             (1 byte, reserved)
//! RECIP_LEN   u32 BE           (4 bytes)
//! RECIPIENTS  (variable)       array of RecipientEntry on-wire form
//! PAYLOAD_LEN u32 BE           (4 bytes)
//! PAYLOAD     (variable)       AES-256-SIV ciphertext, AAD = "sshenv:v1:payload"
//! ```
//!
//! Each `RecipientEntry` on wire is:
//!
//! ```text
//! FP_LEN    u16 BE
//! FP        utf8 bytes
//! WRAP_LEN  u32 BE
//! WRAP      age-wrapped data-key bytes
//! ```
//!
//! Decrypted payload is JSON: `{ "profiles": { "<name>": { "<VAR>": "<value>" } } }`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Magic bytes at the head of every vault file.
pub const MAGIC: [u8; 4] = *b"SSHE";

/// Current stable on-disk format version.
pub const VERSION: u8 = 1;

/// Planned v2 on-disk format version for policy-based vaults.
pub const VERSION_V2: u8 = 2;

/// AAD tag used for AES-SIV payload encryption. Binds ciphertext to format
/// version so a downgrade attack that swaps in an older vault's body is
/// rejected.
pub const PAYLOAD_AAD: &[u8] = b"sshenv:v1:payload";

/// HKDF salt for deriving the AES-SIV key from the 32-byte data key.
pub const HKDF_SALT: &[u8] = b"sshenv:v1";

/// HKDF info for deriving the AES-SIV key.
pub const HKDF_INFO: &[u8] = b"payload";

/// Size of the vault data key, in bytes.
pub const DATA_KEY_LEN: usize = 32;

/// Size of the AES-256-SIV key material, in bytes. AES-SIV uses two keys
/// (MAC + encryption) which together make 64 bytes for AES-256.
pub const SIV_KEY_LEN: usize = 64;

/// AAD tag reserved for a future v2 policy metadata block.
pub const V2_POLICY_AAD: &[u8] = b"sshenv:v2:policy";

/// AAD tag reserved for a future v2 payload block.
pub const V2_PAYLOAD_AAD: &[u8] = b"sshenv:v2:payload";

/// AAD tag for wrapping per-profile data keys inside the encrypted v2 payload.
pub const V2_PROFILE_KEY_AAD: &[u8] = b"sshenv:v2:profile-key";

/// AAD tag for per-profile ciphertexts inside the encrypted v2 payload.
pub const V2_PROFILE_PAYLOAD_AAD: &[u8] = b"sshenv:v2:profile-payload";

/// Errors produced while parsing or building vault structures.
#[derive(Debug, thiserror::Error)]
pub enum VaultModelsError {
    #[error("not a sshenv vault file (bad magic)")]
    BadMagic,
    #[error("unsupported sshenv vault version {0} (expected {VERSION})")]
    UnsupportedVersion(u8),
    #[error("reserved flags byte must be zero, got {0:#x}")]
    BadFlags(u8),
    #[error("recipient block truncated")]
    TruncatedRecipients,
    #[error("payload block truncated")]
    TruncatedPayload,
    #[error("invalid fingerprint UTF-8")]
    InvalidFingerprintUtf8,
    #[error("vault file is truncated (expected at least {expected} more bytes, had {had})")]
    Truncated { expected: usize, had: usize },
    #[error("duplicate recipient fingerprint: {0}")]
    DuplicateRecipient(String),
    #[error("no such profile: {0}")]
    MissingProfile(String),
    #[error("profile already exists: {0}")]
    ProfileAlreadyExists(String),
}

/// Parsed on-disk header bytes (magic + version + flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultHeader {
    pub version: u8,
    pub flags: u8,
}

impl Default for VaultHeader {
    fn default() -> Self {
        Self {
            version: VERSION,
            flags: 0,
        }
    }
}

/// A wrapped-key entry: one per recipient authorized to unwrap the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientEntry {
    /// SHA256 fingerprint of the SSH public key (e.g.
    /// `SHA256:AAAA...`). Matches `ssh-keygen -lf`.
    pub fingerprint: String,
    /// Full SSH public key line (`ssh-ed25519 AAAA... optional-comment`).
    /// Retained so `list-recipients` can display something meaningful
    /// and `add-recipient` can avoid needing the file on disk.
    pub public_key_line: String,
    /// `age`-wrapped copy of the 32-byte data key, bytes as produced by
    /// `age::Encryptor`.
    pub wrapped_key: Vec<u8>,
}

impl RecipientEntry {
    /// On-wire length of this recipient entry (without payload).
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        2 + self.fingerprint.len() + 4 + self.wrapped_key.len()
    }
}

/// Skeleton metadata for future v2 policy-based vaults.
///
/// This is intentionally not wired into the v1 parser/writer yet. It gives
/// future hardening work a shared vocabulary while preserving the immutable
/// v1 format.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPolicyMetadataV2 {
    /// Monotonic local vault generation. This is used by optional rollback
    /// protection to detect older valid vault copies being restored.
    #[serde(default)]
    pub generation: u64,
    /// True when the encrypted payload stores profiles as independently
    /// encrypted entries with per-profile data keys.
    #[serde(default)]
    pub profile_keys_enabled: bool,
    /// Alternative unlock policies. Any one successful policy may unlock the
    /// vault data key.
    #[serde(default)]
    pub policies: Vec<UnlockPolicyV2>,
    /// Recipient metadata retained so future rekey operations can re-wrap new
    /// data keys without asking users to re-provide public keys.
    #[serde(default)]
    pub recipients: Vec<RecipientMetadataV2>,
    /// Non-secret metadata for planned break-glass recovery-share sets.
    /// This never stores raw share material.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_share_sets: Vec<RecoveryShareSetMetadataV2>,
    /// Non-secret metadata for planned remote/KMS-assisted unlock factors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_factors: Vec<RemoteFactorMetadataV2>,
}

/// One alternative way to unlock a v2 vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockPolicyV2 {
    /// Stable policy identifier for CLI display and future edits.
    pub id: String,
    /// Number of listed factors that must succeed. `None` means all factors
    /// are required.
    pub threshold: Option<u8>,
    /// Factor identifiers or inline factors required by this policy.
    pub factors: Vec<UnlockFactorV2>,
}

/// One factor that can participate in an unlock policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockFactorV2 {
    /// Stable factor identifier for CLI display and future edits.
    pub id: String,
    /// Factor kind.
    pub kind: UnlockFactorKindV2,
    /// Optional recipient fingerprint associated with this factor.
    pub recipient_fingerprint: Option<String>,
    /// Additional non-secret, factor-specific parameters.
    pub params: BTreeMap<String, String>,
}

/// Supported/planned v2 unlock factor kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockFactorKindV2 {
    /// Current SSH-recipient wrapping model.
    SshRecipient,
    /// User-supplied passphrase-derived wrapping material.
    Passphrase,
    /// Device-local secret from OS keychain, DPAPI, Secret Service, or TPM.
    DeviceSeal,
    /// Non-exportable hardware-backed recipient.
    HardwareRecipient,
    /// Threshold/recovery share.
    RecoveryShare,
    /// Remote/KMS-assisted factor.
    RemoteKms,
}

/// Recipient metadata retained by future v2 vaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientMetadataV2 {
    /// Recipient fingerprint shown in CLI output.
    pub fingerprint: String,
    /// Public key or public recipient descriptor, when safe to persist.
    pub public_descriptor: String,
    /// Factor kind this recipient belongs to.
    pub kind: UnlockFactorKindV2,
}

/// Non-secret metadata describing one planned recovery-share set.
///
/// The actual share strings are secret material and must not be stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryShareSetMetadataV2 {
    /// Stable recovery set identifier.
    pub id: String,
    /// Human-friendly label shown in CLI output.
    pub label: Option<String>,
    /// Number of shares required to recover.
    pub threshold: u8,
    /// Share holder descriptors. These are public labels/commitments only.
    pub shares: Vec<RecoveryShareMetadataV2>,
    /// Shamir split parameters, when this set uses Shamir-style recovery.
    pub shamir: Option<ShamirSplitMetadataV2>,
}

/// Public descriptor for one recovery share holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryShareMetadataV2 {
    /// Stable share identifier.
    pub id: String,
    /// Optional human-friendly share label.
    pub label: Option<String>,
    /// Optional holder name, email, or team role.
    pub holder: Option<String>,
    /// Optional public commitment/fingerprint for verifying the share later.
    pub public_identifier: Option<String>,
}

/// Non-secret parameters for a Shamir/key-splitting recovery set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShamirSplitMetadataV2 {
    /// Required shares.
    pub threshold: u8,
    /// Total generated shares.
    pub share_count: u8,
}

/// Planned remote/KMS factor backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteFactorBackendKindV2 {
    /// A self-hosted sshenv unlock service.
    SelfHosted,
    /// Cloud KMS such as AWS KMS, Google Cloud KMS, or Azure Key Vault.
    CloudKms,
    /// Approval-gated OIDC/device-flow service.
    OidcApproval,
}

/// Non-secret metadata for a planned remote/KMS-assisted factor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFactorMetadataV2 {
    /// Stable factor identifier matching an [`UnlockFactorV2`] id when active.
    pub id: String,
    /// Backend family.
    pub backend: RemoteFactorBackendKindV2,
    /// Human-friendly label shown in CLI output.
    pub label: Option<String>,
    /// Non-secret backend parameters such as region, key id alias, or URL.
    pub params: BTreeMap<String, String>,
}

/// Environment variable used to route device-seal operations through an
/// interactive broker process.
pub const DEVICE_SEAL_COMMAND_ENV: &str = "SSHENV_DEVICE_SEAL_COMMAND";

/// Device-seal broker operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceSealBrokerOperation {
    Load,
    Store,
}

/// JSON request sent to a device-seal broker command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSealBrokerRequest {
    pub operation: DeviceSealBrokerOperation,
    pub backend: String,
    pub service: String,
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hex: Option<String>,
}

/// JSON response returned by a device-seal broker command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSealBrokerResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The plaintext payload of a vault: the full profile → var map.
///
/// Serialized as JSON into the encrypted body. Individual secret values
/// are zeroized at the call-site via [`zeroize::Zeroizing<Vec<u8>>`] when
/// they live in isolation; this map itself is not zeroized because
/// `BTreeMap` cannot be cleanly zeroized in place.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMap {
    pub profiles: BTreeMap<String, BTreeMap<String, String>>,
    /// Encrypted per-profile entries used by v2 profile-key mode.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_entries: BTreeMap<String, ProfileEntry>,
    /// Encrypted per-profile policy metadata. These are currently advisory
    /// scaffolding for future per-profile/per-scope encryption.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_policies: BTreeMap<String, ProfilePolicy>,
}

/// One independently encrypted profile entry inside the encrypted v2 payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileEntry {
    /// Profile data key encrypted under the vault payload key.
    pub wrapped_key: Vec<u8>,
    /// Serialized profile variable map encrypted under the profile data key.
    pub ciphertext: Vec<u8>,
}

/// Advisory per-profile security policy metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePolicy {
    /// Intended profile security preset.
    pub preset: ProfilePolicyPreset,
    /// Extra factors this profile requires before it may be used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_factors: Vec<ProfileFactorRequirement>,
    /// Per-profile factor metadata used to derive profile payload keys without
    /// making the factor apply to the whole vault payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factor_metadata: Vec<UnlockFactorV2>,
}

/// Warning emitted when a metadata-only unlock has not decrypted/generated the
/// selected profile entry yet.
pub const PROFILE_ENTRY_MISSING_WARNING: &str =
    "profile-key mode is enabled but this profile has no encrypted profile entry";

/// Severity for a profile policy validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfilePolicyFindingSeverity {
    Warning,
    Error,
}

/// Stable code for a profile policy validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfilePolicyFindingCode {
    PolicyForMissingProfile,
    ProfileFactorsWithoutProfileKeyMode,
    MissingProfileEntry,
    UnsatisfiedRequirement,
    MissingPresetBinding,
    UnsupportedFactorMetadata,
    TeamRequiresRecoveryMetadata,
}

/// One structured profile policy validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePolicyFinding {
    /// Warning/error classification.
    pub severity: ProfilePolicyFindingSeverity,
    /// Stable machine-readable finding code.
    pub code: ProfilePolicyFindingCode,
    /// Human-readable explanation.
    pub message: String,
    /// Related factor kind, when applicable.
    pub factor: Option<UnlockFactorKindV2>,
    /// Related profile requirement, when applicable.
    pub requirement: Option<ProfileFactorRequirement>,
}

impl ProfilePolicyFinding {
    /// Create a warning finding.
    #[must_use]
    pub fn warning(
        code: ProfilePolicyFindingCode,
        message: impl Into<String>,
        factor: Option<UnlockFactorKindV2>,
        requirement: Option<ProfileFactorRequirement>,
    ) -> Self {
        Self {
            severity: ProfilePolicyFindingSeverity::Warning,
            code,
            message: message.into(),
            factor,
            requirement,
        }
    }

    /// Create an error finding.
    #[must_use]
    pub fn error(
        code: ProfilePolicyFindingCode,
        message: impl Into<String>,
        factor: Option<UnlockFactorKindV2>,
        requirement: Option<ProfileFactorRequirement>,
    ) -> Self {
        Self {
            severity: ProfilePolicyFindingSeverity::Error,
            code,
            message: message.into(),
            factor,
            requirement,
        }
    }
}

/// Consistency validation for one profile policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePolicyValidation {
    /// True when the profile exists in plaintext or profile-entry storage.
    pub profile_exists: bool,
    /// True when policy metadata exists for this profile.
    pub policy_present: bool,
    /// Structured validation findings.
    pub findings: Vec<ProfilePolicyFinding>,
}

impl ProfilePolicyValidation {
    /// True when neither a profile nor policy metadata exists for a name.
    #[must_use]
    pub const fn profile_policy_missing(&self) -> bool {
        !self.profile_exists && !self.policy_present
    }

    /// Warning findings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ProfilePolicyFinding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity == ProfilePolicyFindingSeverity::Warning)
            .collect()
    }

    /// Error findings.
    #[must_use]
    pub fn errors(&self) -> Vec<&ProfilePolicyFinding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity == ProfilePolicyFindingSeverity::Error)
            .collect()
    }

    /// Number of warning findings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == ProfilePolicyFindingSeverity::Warning)
            .count()
    }

    /// Number of error findings.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == ProfilePolicyFindingSeverity::Error)
            .count()
    }

    /// Warning messages for human-oriented CLI output.
    #[must_use]
    pub fn warning_messages(&self) -> Vec<String> {
        self.warnings()
            .into_iter()
            .map(|finding| finding.message.clone())
            .collect()
    }

    /// Error messages for human-oriented CLI output.
    #[must_use]
    pub fn error_messages(&self) -> Vec<String> {
        self.errors()
            .into_iter()
            .map(|finding| finding.message.clone())
            .collect()
    }
}

/// Aggregate consistency validation across every profile/policy entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePolicyCheck {
    /// Number of profile/policy names checked.
    pub profiles_checked: usize,
    /// Sum of all warnings across profiles.
    pub warnings: usize,
    /// Sum of all errors across profiles.
    pub errors: usize,
    /// Per-profile validation results, keyed by profile name.
    pub profiles: BTreeMap<String, ProfilePolicyValidation>,
}

/// Repair action planned for a profile policy finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfilePolicyRepairAction {
    MigrateToV2,
    EnableProfileKeyMode,
    RegenerateProfileEntry,
    BindPassphrase,
    BindDeviceSeal,
    RotateProfileKey,
}

impl ProfilePolicyRepairAction {
    /// Human-readable action label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MigrateToV2 => "migrated vault to v2",
            Self::EnableProfileKeyMode => "enabled profile-key mode",
            Self::RegenerateProfileEntry => "regenerated encrypted profile entry",
            Self::BindPassphrase => "bound profile payload to passphrase",
            Self::BindDeviceSeal => "bound profile payload to device seal",
            Self::RotateProfileKey => "rotated profile data key",
        }
    }
}

/// Repair plan for a profile policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "repair-plan JSON intentionally exposes independent boolean facts"
)]
pub struct ProfilePolicyRepairPlan {
    pub profile: String,
    pub repairable: bool,
    pub already_consistent: bool,
    pub requires_passphrase: bool,
    pub requires_device_seal: bool,
    pub requires_recipient_key: bool,
    pub actions: Vec<ProfilePolicyRepairAction>,
    pub action_labels: Vec<String>,
    pub unrepairable: Vec<String>,
    pub findings: Vec<ProfilePolicyFinding>,
}

/// Result from applying non-secret profile policy repair actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePolicyRepairApplyResult {
    pub changed: bool,
    pub applied_actions: Vec<ProfilePolicyRepairAction>,
    pub remaining_actions: Vec<ProfilePolicyRepairAction>,
}

/// One profile-level factor requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileFactorRequirement {
    Passphrase,
    DeviceSeal,
}

/// Intended profile security posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfilePolicyPreset {
    Standard,
    Recommended,
    Portable,
    Team,
    Paranoid,
}

impl ProfileMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of profiles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Get (immutable) all vars for a profile.
    #[must_use]
    pub fn get(&self, profile: &str) -> Option<&BTreeMap<String, String>> {
        self.profiles.get(profile)
    }

    /// Insert or replace a single `VAR = value` pair. Creates the profile
    /// if it does not exist.
    pub fn set(&mut self, profile: &str, var: &str, value: String) {
        self.profiles
            .entry(profile.to_string())
            .or_default()
            .insert(var.to_string(), value);
    }

    /// Remove a single `VAR` from a profile. If the profile becomes empty
    /// it is also removed.
    ///
    /// Returns `true` if the var was present.
    pub fn unset(&mut self, profile: &str, var: &str) -> bool {
        let Some(vars) = self.profiles.get_mut(profile) else {
            return false;
        };
        let removed = vars.remove(var).is_some();
        if vars.is_empty() {
            self.profiles.remove(profile);
        }
        removed
    }

    /// Remove an entire profile. Returns `true` if present.
    pub fn remove_profile(&mut self, profile: &str) -> bool {
        let removed = self.profiles.remove(profile).is_some();
        if removed {
            self.profile_entries.remove(profile);
            self.profile_policies.remove(profile);
        }
        removed
    }

    /// Rename an entire profile, preserving all variables.
    ///
    /// Returns `Ok(true)` when the map changed. Renaming a profile to itself
    /// is treated as a successful no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the source profile is missing or the destination
    /// profile already exists.
    pub fn rename_profile(&mut self, from: &str, to: &str) -> Result<bool, VaultModelsError> {
        if from == to {
            return Ok(false);
        }
        if self.profiles.contains_key(to) {
            return Err(VaultModelsError::ProfileAlreadyExists(to.to_string()));
        }
        let Some(vars) = self.profiles.remove(from) else {
            return Err(VaultModelsError::MissingProfile(from.to_string()));
        };
        self.profiles.insert(to.to_string(), vars);
        if let Some(entry) = self.profile_entries.remove(from) {
            self.profile_entries.insert(to.to_string(), entry);
        }
        if let Some(policy) = self.profile_policies.remove(from) {
            self.profile_policies.insert(to.to_string(), policy);
        }
        Ok(true)
    }

    /// Set advisory security policy metadata for a profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile does not exist.
    pub fn set_profile_policy(
        &mut self,
        profile: &str,
        policy: ProfilePolicy,
    ) -> Result<(), VaultModelsError> {
        if !self.profiles.contains_key(profile) {
            return Err(VaultModelsError::MissingProfile(profile.to_string()));
        }
        self.profile_policies.insert(profile.to_string(), policy);
        Ok(())
    }

    /// Return advisory policy metadata for a profile.
    #[must_use]
    pub fn profile_policy(&self, profile: &str) -> Option<&ProfilePolicy> {
        self.profile_policies.get(profile)
    }

    /// Names of all profiles, sorted.
    #[must_use]
    pub fn profile_names(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_default_uses_current_version() {
        let h = VaultHeader::default();
        assert_eq!(h.version, VERSION);
        assert_eq!(h.flags, 0);
    }

    #[test]
    fn profile_map_set_and_get() {
        let mut m = ProfileMap::new();
        m.set("pi-bedrock", "AWS_BEARER_TOKEN_BEDROCK", "abc".into());
        assert_eq!(m.len(), 1);
        let vars = m.get("pi-bedrock").unwrap();
        assert_eq!(vars.get("AWS_BEARER_TOKEN_BEDROCK").unwrap(), "abc");
    }

    #[test]
    fn profile_map_unset_empties_profile() {
        let mut m = ProfileMap::new();
        m.set("p", "K", "v".into());
        assert!(m.unset("p", "K"));
        assert!(m.get("p").is_none());
        assert!(m.is_empty());
    }

    #[test]
    fn profile_map_unset_missing_is_false() {
        let mut m = ProfileMap::new();
        assert!(!m.unset("nope", "K"));
    }

    #[test]
    fn profile_map_rename_moves_vars() {
        let mut m = ProfileMap::new();
        m.set("old", "K", "v".into());

        assert!(m.rename_profile("old", "new").unwrap());

        assert!(m.get("old").is_none());
        assert_eq!(m.get("new").unwrap().get("K").unwrap(), "v");
    }

    #[test]
    fn profile_map_rename_missing_errors() {
        let mut m = ProfileMap::new();
        let err = m.rename_profile("old", "new").unwrap_err();
        assert!(matches!(err, VaultModelsError::MissingProfile(p) if p == "old"));
    }

    #[test]
    fn profile_map_rename_existing_destination_errors() {
        let mut m = ProfileMap::new();
        m.set("old", "K", "v".into());
        m.set("new", "OTHER", "value".into());

        let err = m.rename_profile("old", "new").unwrap_err();

        assert!(matches!(err, VaultModelsError::ProfileAlreadyExists(p) if p == "new"));
        assert!(m.get("old").is_some());
        assert_eq!(m.get("new").unwrap().get("OTHER").unwrap(), "value");
    }

    #[test]
    fn profile_map_rename_same_name_is_noop() {
        let mut m = ProfileMap::new();
        m.set("same", "K", "v".into());

        assert!(!m.rename_profile("same", "same").unwrap());
        assert_eq!(m.get("same").unwrap().get("K").unwrap(), "v");
    }

    #[test]
    fn profile_policy_moves_and_removes_with_profile() {
        let mut m = ProfileMap::new();
        m.set("old", "K", "v".into());
        m.profile_entries.insert(
            "old".to_string(),
            ProfileEntry {
                wrapped_key: vec![1],
                ciphertext: vec![2],
            },
        );
        m.set_profile_policy(
            "old",
            ProfilePolicy {
                preset: ProfilePolicyPreset::Paranoid,
                required_factors: Vec::new(),
                factor_metadata: Vec::new(),
            },
        )
        .unwrap();

        m.rename_profile("old", "new").unwrap();
        assert!(!m.profile_entries.contains_key("old"));
        assert!(m.profile_entries.contains_key("new"));
        assert!(m.profile_policy("old").is_none());
        assert_eq!(
            m.profile_policy("new").unwrap().preset,
            ProfilePolicyPreset::Paranoid
        );

        assert!(m.remove_profile("new"));
        assert!(!m.profile_entries.contains_key("new"));
        assert!(m.profile_policy("new").is_none());
    }

    #[test]
    fn recipient_entry_wire_len_accounts_for_all_fields() {
        let r = RecipientEntry {
            fingerprint: "SHA256:abc".to_string(),
            public_key_line: "ssh-ed25519 AAA".to_string(),
            wrapped_key: vec![1, 2, 3, 4, 5],
        };
        // 2 + 10 + 4 + 5
        assert_eq!(r.wire_len(), 21);
    }
}
