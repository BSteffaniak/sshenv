//! Vault file I/O, crypto, and recipient operations.
//!
//! A vault is a single file whose body is encrypted with AES-256-SIV under
//! a 32-byte data key. The data key is independently wrapped to one or
//! more SSH public-key recipients via `age`, so any holder of a matching
//! SSH private key can recover the data key and decrypt the body.
//!
//! See [`sshenv_vault_models`] for the on-disk byte layout.

#![allow(clippy::multiple_crate_versions)]

pub mod crypto;
#[cfg(feature = "device-seal")]
pub mod device;
pub mod format;
pub mod identity;
#[cfg(feature = "passphrase-factor")]
pub mod passphrase;
pub mod recipient;

#[cfg(feature = "rekey")]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use sshenv_vault_models::{
    DATA_KEY_LEN, PAYLOAD_AAD, ProfileEntry, ProfileMap, RecipientEntry, RecipientMetadataV2,
    UnlockFactorKindV2, V2_PAYLOAD_AAD, V2_PROFILE_KEY_AAD, V2_PROFILE_PAYLOAD_AAD, VERSION,
    VERSION_V2, VaultHeader, VaultModelsError, VaultPolicyMetadataV2,
};
use zeroize::Zeroizing;

pub use sshenv_vault_models as models;

#[cfg(any(feature = "passphrase-factor", feature = "device-seal"))]
use crate::crypto::bind_data_key_to_factor;
use crate::crypto::{decrypt_payload_with_aad, encrypt_payload_with_aad, generate_data_key};
use crate::format::{encode, encode_v2, parse};
use crate::identity::{
    discover_private_key_paths, error_no_identity_unlocked_detailed,
    load_identities_for_vault_from_paths,
};

/// Shorthand alias for the fixed-size, auto-zeroizing data key.
pub type DataKey = Zeroizing<[u8; DATA_KEY_LEN]>;

/// Configurable embeddable sshenv vault store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshenvStoreConfig {
    pub vault_path: PathBuf,
    pub private_key_paths: Vec<PathBuf>,
}

impl SshenvStoreConfig {
    /// Create a store config for a specific vault path, using default SSH
    /// identity discovery for unlock operations.
    #[must_use]
    pub fn new(vault_path: impl Into<PathBuf>) -> Self {
        Self {
            vault_path: vault_path.into(),
            private_key_paths: discover_private_key_paths(),
        }
    }

    /// Override private-key paths used to unlock the vault.
    #[must_use]
    pub fn with_private_key_paths(mut self, private_key_paths: Vec<PathBuf>) -> Self {
        self.private_key_paths = private_key_paths;
        self
    }
}

impl Default for SshenvStoreConfig {
    fn default() -> Self {
        Self::new(default_vault_path())
    }
}

/// Embeddable encrypted secret store backed by an sshenv vault file.
#[derive(Debug, Clone)]
pub struct SshenvStore {
    config: SshenvStoreConfig,
}

impl SshenvStore {
    /// Create an embeddable store from explicit configuration.
    #[must_use]
    pub const fn new(config: SshenvStoreConfig) -> Self {
        Self { config }
    }

    /// Return this store's configuration.
    #[must_use]
    pub const fn config(&self) -> &SshenvStoreConfig {
        &self.config
    }

    /// Initialize a vault at this store's configured path.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient public key cannot be parsed or the
    /// vault cannot be written.
    pub fn init(&self, recipient_public_key_line: &str) -> Result<()> {
        let (vault, data_key) = Vault::create(recipient_public_key_line)?;
        vault.save(&self.config.vault_path, &data_key)
    }

    /// Initialize the vault only when it does not already exist. Returns
    /// `true` when a new vault was created.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn init_if_missing(&self, recipient_public_key_line: &str) -> Result<bool> {
        if self.config.vault_path.exists() {
            return Ok(false);
        }
        self.init(recipient_public_key_line)?;
        Ok(true)
    }

    /// Set or replace one secret value.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be unlocked or saved.
    pub fn set_secret(&self, profile: &str, var: &str, value: Zeroizing<String>) -> Result<()> {
        let (mut vault, data_key) = self.load_and_unlock()?;
        vault.profiles.set(profile, var, value.as_str().to_string());
        vault.save(&self.config.vault_path, &data_key)
    }

    /// Remove one secret value. Returns `true` when it existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be unlocked or saved.
    pub fn unset_secret(&self, profile: &str, var: &str) -> Result<bool> {
        let (mut vault, data_key) = self.load_and_unlock()?;
        let removed = vault.profiles.unset(profile, var);
        if removed {
            vault.save(&self.config.vault_path, &data_key)?;
        }
        Ok(removed)
    }

    /// Return one secret value, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be unlocked.
    pub fn get_secret(&self, profile: &str, var: &str) -> Result<Option<Zeroizing<String>>> {
        let (vault, _data_key) = self.load_and_unlock()?;
        Ok(vault
            .profiles
            .get(profile)
            .and_then(|vars| vars.get(var))
            .map(|value| Zeroizing::new(value.clone())))
    }

    /// Return all secrets for one profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be unlocked.
    pub fn get_profile(
        &self,
        profile: &str,
    ) -> Result<Option<BTreeMap<String, Zeroizing<String>>>> {
        let (vault, _data_key) = self.load_and_unlock()?;
        Ok(vault.profiles.get(profile).map(|vars| {
            vars.iter()
                .map(|(key, value)| (key.clone(), Zeroizing::new(value.clone())))
                .collect()
        }))
    }

    /// Unlock and return the full vault plus data key.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be read or no configured identity
    /// can decrypt it.
    pub fn load_and_unlock(&self) -> Result<(Vault, DataKey)> {
        load_and_unlock_with_private_key_paths(
            &self.config.vault_path,
            &self.config.private_key_paths,
        )
    }
}

/// Load and unlock a vault using explicit private-key paths.
///
/// # Errors
///
/// Returns an error if the vault cannot be read or no configured identity can
/// decrypt it.
pub fn load_and_unlock_with_private_key_paths(
    vault_path: &Path,
    private_key_paths: &[PathBuf],
) -> Result<(Vault, DataKey)> {
    let ciphertext = Vault::load_ciphertext(vault_path)?;
    let fingerprints: HashSet<String> = ciphertext
        .recipients
        .iter()
        .map(|recipient| recipient.fingerprint.clone())
        .collect();
    let identities = load_identities_for_vault_from_paths(private_key_paths, &fingerprints)?;
    if identities.is_empty() {
        return Err(error_no_identity_unlocked_detailed(
            private_key_paths,
            &fingerprints,
        ));
    }
    Vault::unlock(ciphertext, &identities)
        .map_err(|_| error_no_identity_unlocked_detailed(private_key_paths, &fingerprints))
}

/// An in-memory, decrypted vault: header + recipients + profile map.
#[derive(Debug, Clone)]
pub struct Vault {
    pub header: VaultHeader,
    pub policy_metadata: Option<VaultPolicyMetadataV2>,
    pub recipients: Vec<RecipientEntry>,
    pub profiles: ProfileMap,
    payload_key_factors: Vec<PayloadKeyFactor>,
}

#[derive(Debug, Clone)]
struct PayloadKeyFactor {
    kind: UnlockFactorKindV2,
    key: Zeroizing<[u8; DATA_KEY_LEN]>,
}

impl Vault {
    /// Create a fresh empty vault with a freshly-generated data key, wrapped
    /// for the given SSH recipient public key line.
    ///
    /// Returns the vault and the generated data key.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient public key cannot be parsed or if
    /// the data key cannot be wrapped.
    pub fn create(recipient_public_key_line: &str) -> Result<(Self, DataKey)> {
        let data_key = generate_data_key();
        let recipient = recipient::build_entry_for_public_key_line(
            recipient_public_key_line,
            data_key.as_slice(),
        )?;

        let vault = Self {
            header: VaultHeader::default(),
            policy_metadata: None,
            recipients: vec![recipient],
            profiles: ProfileMap::default(),
            payload_key_factors: Vec::new(),
        };

        Ok((vault, data_key))
    }

    /// Load and decode (but not decrypt) a vault from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or has an invalid format.
    pub fn load_ciphertext(path: &Path) -> Result<CiphertextVault> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read vault file {}", path.display()))?;
        let parsed = parse(&bytes)?;
        Ok(CiphertextVault {
            header: parsed.header,
            policy_metadata: parsed.policy_metadata,
            recipients: parsed.recipients,
            payload_ciphertext: parsed.payload,
        })
    }

    /// Unwrap a loaded ciphertext vault and decrypt the body using a list
    /// of `age` identities.
    ///
    /// # Errors
    ///
    /// Returns an error if none of the identities can unwrap any recipient,
    /// or if the payload fails to decrypt.
    pub fn unlock(
        ciphertext: CiphertextVault,
        identities: &[Box<dyn age::Identity>],
    ) -> Result<(Self, DataKey)> {
        Self::unlock_with_passphrase(ciphertext, identities, None)
    }

    /// Unwrap and decrypt a vault, optionally satisfying a passphrase factor.
    ///
    /// # Errors
    ///
    /// Returns an error if SSH unwrapping fails, a required passphrase is
    /// missing, or the payload fails to decrypt.
    pub fn unlock_with_passphrase(
        ciphertext: CiphertextVault,
        identities: &[Box<dyn age::Identity>],
        passphrase: Option<&str>,
    ) -> Result<(Self, DataKey)> {
        let data_key = recipient::unwrap_data_key(&ciphertext.recipients, identities)
            .context("no configured SSH identity could unwrap the vault data key")?;
        let payload_key_factors =
            payload_key_factors_for_metadata(ciphertext.policy_metadata.as_ref(), passphrase)?;
        let payload_key = payload_key_for_data_key(data_key.as_slice(), &payload_key_factors);

        let aad = payload_aad_for_version(ciphertext.header.version)?;
        let plaintext =
            decrypt_payload_with_aad(payload_key.as_slice(), &ciphertext.payload_ciphertext, aad)
                .context("failed to decrypt vault payload")?;

        let profiles = if plaintext.is_empty() {
            ProfileMap::default()
        } else {
            decode_profiles_from_payload(&plaintext, payload_key.as_slice())?
        };

        Ok((
            Self {
                header: ciphertext.header,
                policy_metadata: ciphertext.policy_metadata,
                recipients: ciphertext.recipients,
                profiles,
                payload_key_factors,
            },
            data_key,
        ))
    }

    /// Add a new SSH recipient to this vault, wrapping the existing data
    /// key for them. Caller must have already unlocked the vault so the
    /// data key is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient key is invalid, if a recipient
    /// with the same fingerprint is already registered, or if wrapping
    /// fails.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the entry was just inserted into
    /// `self.recipients` so the final `find` is guaranteed to succeed.
    pub fn add_recipient(
        &mut self,
        public_key_line: &str,
        data_key: &[u8; DATA_KEY_LEN],
    ) -> Result<&RecipientEntry> {
        let entry = recipient::build_entry_for_public_key_line(public_key_line, data_key)?;
        if self
            .recipients
            .iter()
            .any(|r| r.fingerprint == entry.fingerprint)
        {
            return Err(VaultModelsError::DuplicateRecipient(entry.fingerprint).into());
        }
        let fp = entry.fingerprint.clone();
        self.recipients.push(entry);
        self.recipients
            .sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        Ok(self
            .recipients
            .iter()
            .find(|r| r.fingerprint == fp)
            .expect("just inserted"))
    }

    /// Remove a recipient by fingerprint. Returns `true` if a recipient
    /// was removed.
    pub fn remove_recipient(&mut self, fingerprint: &str) -> bool {
        let before = self.recipients.len();
        self.recipients.retain(|r| r.fingerprint != fingerprint);
        self.recipients.len() < before
    }

    /// Generate a new data key and re-wrap it to the same recipient set.
    ///
    /// The current v1 format does not persist public key lines, so callers
    /// must provide the public keys for every current recipient. This keeps
    /// rotation explicit and avoids accidentally changing the vault's
    /// authorized recipient set.
    ///
    /// # Errors
    ///
    /// Returns an error if any provided key is invalid, if the provided keys
    /// contain duplicates, or if their fingerprints do not exactly match the
    /// vault's current recipients.
    #[cfg(feature = "rekey")]
    pub fn rotate_data_key(&mut self, recipient_public_key_lines: &[String]) -> Result<DataKey> {
        let expected: BTreeSet<String> = self
            .recipients
            .iter()
            .map(|recipient| recipient.fingerprint.clone())
            .collect();
        let new_data_key = generate_data_key();
        let mut new_recipients = Vec::with_capacity(recipient_public_key_lines.len());
        let mut provided = BTreeSet::new();

        for public_key_line in recipient_public_key_lines {
            let entry = recipient::build_entry_for_public_key_line(
                public_key_line,
                new_data_key.as_slice(),
            )?;
            if !provided.insert(entry.fingerprint.clone()) {
                return Err(VaultModelsError::DuplicateRecipient(entry.fingerprint).into());
            }
            new_recipients.push(entry);
        }

        if provided != expected {
            let missing: Vec<&String> = expected.difference(&provided).collect();
            let unexpected: Vec<&String> = provided.difference(&expected).collect();
            return Err(anyhow!(
                "recipient keys do not match current vault recipients; missing: {}; unexpected: {}",
                format_fingerprint_list(&missing),
                format_fingerprint_list(&unexpected),
            ));
        }

        new_recipients.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        self.recipients = new_recipients;
        Ok(new_data_key)
    }

    /// Attach public key lines for all current recipients and mark the vault
    /// for v2 policy-format saving.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided keys do not exactly match current
    /// recipients.
    pub fn migrate_to_v2(&mut self, recipient_public_key_lines: &[String]) -> Result<()> {
        self.attach_recipient_public_key_lines(recipient_public_key_lines)?;
        self.header.version = VERSION_V2;
        self.policy_metadata = Some(policy_metadata_from_recipients(&self.recipients));
        Ok(())
    }

    /// Require a passphrase factor in addition to an SSH recipient for future
    /// payload decrypts.
    ///
    /// The vault must already be migrated to v2. The caller must save the
    /// vault with the original data key after enabling the factor.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault is not v2 or if a passphrase factor is
    /// already configured.
    #[cfg(feature = "passphrase-factor")]
    pub fn enable_passphrase_factor(&mut self, passphrase: &str) -> Result<()> {
        ensure_v2_for_passphrase(self.header.version)?;
        if self.passphrase_factor_enabled() {
            return Err(anyhow!("passphrase factor is already enabled"));
        }
        self.add_or_replace_passphrase_factor(passphrase)
    }

    /// Change the existing passphrase factor to a new passphrase.
    ///
    /// The vault must already be unlocked with the old passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault is not v2 or no passphrase factor is
    /// enabled.
    #[cfg(feature = "passphrase-factor")]
    pub fn change_passphrase_factor(&mut self, new_passphrase: &str) -> Result<()> {
        ensure_v2_for_passphrase(self.header.version)?;
        if !self.remove_passphrase_factor_metadata() {
            return Err(anyhow!("passphrase factor is not enabled"));
        }
        self.add_or_replace_passphrase_factor(new_passphrase)
    }

    /// Disable the existing passphrase factor.
    ///
    /// The vault must already be unlocked with the current passphrase. The
    /// next save will re-encrypt the payload using only the SSH-unwrapped data
    /// key.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault is not v2 or no passphrase factor is
    /// enabled.
    #[cfg(feature = "passphrase-factor")]
    pub fn disable_passphrase_factor(&mut self) -> Result<()> {
        ensure_v2_for_passphrase(self.header.version)?;
        if !self.remove_passphrase_factor_metadata() {
            return Err(anyhow!("passphrase factor is not enabled"));
        }
        self.payload_key_factors
            .retain(|factor| factor.kind != UnlockFactorKindV2::Passphrase);
        Ok(())
    }

    /// True when this vault metadata requires a passphrase factor.
    #[cfg(feature = "passphrase-factor")]
    #[must_use]
    pub fn passphrase_factor_enabled(&self) -> bool {
        metadata_has_passphrase_factor(self.policy_metadata.as_ref())
    }

    #[cfg(feature = "passphrase-factor")]
    fn add_or_replace_passphrase_factor(&mut self, passphrase: &str) -> Result<()> {
        let metadata = self
            .policy_metadata
            .get_or_insert_with(|| policy_metadata_from_recipients(&self.recipients));
        let (factor, factor_key) = passphrase::create_factor(passphrase)?;
        metadata.policies.push(sshenv_vault_models::UnlockPolicyV2 {
            id: "ssh+passphrase".to_string(),
            threshold: None,
            factors: vec![factor],
        });
        self.payload_key_factors
            .retain(|factor| factor.kind != UnlockFactorKindV2::Passphrase);
        self.payload_key_factors.push(PayloadKeyFactor {
            kind: UnlockFactorKindV2::Passphrase,
            key: factor_key,
        });
        Ok(())
    }

    #[cfg(feature = "passphrase-factor")]
    fn remove_passphrase_factor_metadata(&mut self) -> bool {
        let Some(metadata) = &mut self.policy_metadata else {
            return false;
        };
        let mut removed = false;
        for policy in &mut metadata.policies {
            let before = policy.factors.len();
            policy.factors.retain(|factor| {
                let keep = !passphrase::is_passphrase_factor(factor);
                if !keep {
                    removed = true;
                }
                keep
            });
            removed |= policy.factors.len() < before;
        }
        metadata
            .policies
            .retain(|policy| !policy.factors.is_empty());
        removed
    }

    /// Require a device-local seal factor in addition to SSH recipient unlock.
    ///
    /// The vault must already be migrated to v2. The caller must save the
    /// vault with the original data key after enabling the factor.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault is not v2, no device-seal backend is
    /// available, or a device-seal factor is already configured.
    #[cfg(feature = "device-seal")]
    pub fn enable_device_seal_factor(&mut self) -> Result<()> {
        ensure_v2_for_device_seal(self.header.version)?;
        if self.device_seal_factor_enabled() {
            return Err(anyhow!("device-seal factor is already enabled"));
        }
        let metadata = self
            .policy_metadata
            .get_or_insert_with(|| policy_metadata_from_recipients(&self.recipients));
        let (factor, factor_key) = device::create_factor()?;
        metadata.policies.push(sshenv_vault_models::UnlockPolicyV2 {
            id: "ssh+device-seal".to_string(),
            threshold: None,
            factors: vec![factor],
        });
        self.payload_key_factors.push(PayloadKeyFactor {
            kind: UnlockFactorKindV2::DeviceSeal,
            key: factor_key,
        });
        Ok(())
    }

    /// True when this vault metadata requires a device-seal factor.
    #[cfg(feature = "device-seal")]
    #[must_use]
    pub fn device_seal_factor_enabled(&self) -> bool {
        metadata_has_device_seal_factor(self.policy_metadata.as_ref())
    }

    /// Attach public key lines to existing recipients without changing their
    /// wrapped keys.
    ///
    /// # Errors
    ///
    /// Returns an error if any provided key is invalid, if the provided keys
    /// contain duplicates, or if their fingerprints do not exactly match the
    /// vault's current recipients.
    pub fn attach_recipient_public_key_lines(
        &mut self,
        recipient_public_key_lines: &[String],
    ) -> Result<()> {
        let expected: BTreeSet<String> = self
            .recipients
            .iter()
            .map(|recipient| recipient.fingerprint.clone())
            .collect();
        let mut public_keys_by_fingerprint = BTreeMap::new();

        for public_key_line in recipient_public_key_lines {
            let fingerprint = recipient::fingerprint_from_line(public_key_line)?;
            if public_keys_by_fingerprint
                .insert(fingerprint.clone(), public_key_line.clone())
                .is_some()
            {
                return Err(VaultModelsError::DuplicateRecipient(fingerprint).into());
            }
        }

        let provided: BTreeSet<String> = public_keys_by_fingerprint.keys().cloned().collect();
        if provided != expected {
            let missing: Vec<&String> = expected.difference(&provided).collect();
            let unexpected: Vec<&String> = provided.difference(&expected).collect();
            return Err(anyhow!(
                "recipient keys do not match current vault recipients; missing: {}; unexpected: {}",
                format_fingerprint_list(&missing),
                format_fingerprint_list(&unexpected),
            ));
        }

        for recipient in &mut self.recipients {
            if let Some(public_key_line) = public_keys_by_fingerprint.get(&recipient.fingerprint) {
                recipient.public_key_line = public_key_line.clone();
            }
        }
        Ok(())
    }

    /// Enable independently encrypted per-profile payload entries for future
    /// saves.
    ///
    /// # Errors
    ///
    /// Returns an error if this vault is not v2.
    pub fn enable_profile_keys(&mut self) -> Result<bool> {
        if self.header.version != VERSION_V2 {
            return Err(anyhow!(
                "profile keys require v2; run `sshenv migrate-vault --to v2` first"
            ));
        }
        let metadata = self
            .policy_metadata
            .get_or_insert_with(|| policy_metadata_from_recipients(&self.recipients));
        if metadata.profile_keys_enabled {
            return Ok(false);
        }
        metadata.profile_keys_enabled = true;
        Ok(true)
    }

    /// True when future saves will use per-profile encrypted entries.
    #[must_use]
    pub fn profile_keys_enabled(&self) -> bool {
        self.policy_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.profile_keys_enabled)
    }

    /// Return the v2 metadata generation, if present.
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        self.policy_metadata
            .as_ref()
            .map(|metadata| metadata.generation)
    }

    /// Increment and return the v2 metadata generation, if this is a v2 vault.
    pub fn bump_generation(&mut self) -> Option<u64> {
        if self.header.version != VERSION_V2 {
            return None;
        }
        let metadata = self
            .policy_metadata
            .get_or_insert_with(|| policy_metadata_from_recipients(&self.recipients));
        metadata.generation = metadata.generation.saturating_add(1);
        Some(metadata.generation)
    }

    /// Serialize, encrypt, and atomically write this vault to disk with
    /// mode `0600`.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails, the file cannot be written,
    /// or the rename fails.
    pub fn save(&self, path: &Path, data_key: &[u8; DATA_KEY_LEN]) -> Result<()> {
        let payload_key = payload_key_for_data_key(data_key.as_slice(), &self.payload_key_factors);
        let plaintext = encode_profiles_for_payload(
            &self.profiles,
            payload_key.as_slice(),
            self.profile_keys_enabled(),
        )?;
        let plaintext = Zeroizing::new(plaintext);
        let aad = payload_aad_for_version(self.header.version)?;
        let ciphertext =
            encrypt_payload_with_aad(payload_key.as_slice(), plaintext.as_slice(), aad)
                .context("failed to encrypt vault payload")?;

        let encoded = match self.header.version {
            VERSION => encode(self.header, &self.recipients, &ciphertext)?,
            VERSION_V2 => {
                let metadata = self
                    .policy_metadata
                    .clone()
                    .unwrap_or_else(|| policy_metadata_from_recipients(&self.recipients));
                encode_v2(self.header, &metadata, &self.recipients, &ciphertext)?
            }
            version => return Err(VaultModelsError::UnsupportedVersion(version).into()),
        };
        atomic_write(path, &encoded, 0o600)?;
        Ok(())
    }
}

/// A parsed but still-encrypted vault file.
pub struct CiphertextVault {
    pub header: VaultHeader,
    pub policy_metadata: Option<VaultPolicyMetadataV2>,
    pub recipients: Vec<RecipientEntry>,
    pub payload_ciphertext: Vec<u8>,
}

impl CiphertextVault {
    /// Return the v2 metadata generation, if present.
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        self.policy_metadata
            .as_ref()
            .map(|metadata| metadata.generation)
    }
}

/// Atomically write `bytes` to `path` with the given unix mode (ignored on
/// non-unix).
///
/// Creates the parent directory if necessary.
///
/// # Errors
///
/// Returns an error if any filesystem operation fails.
#[cfg(any(feature = "passphrase-factor", feature = "device-seal"))]
fn payload_key_for_data_key(
    data_key: &[u8],
    payload_key_factors: &[PayloadKeyFactor],
) -> Zeroizing<[u8; DATA_KEY_LEN]> {
    let mut current = copy_data_key(data_key);
    for factor in payload_key_factors {
        current = bind_data_key_to_factor(current.as_slice(), factor.key.as_slice());
    }
    current
}

#[cfg(not(any(feature = "passphrase-factor", feature = "device-seal")))]
fn payload_key_for_data_key(
    data_key: &[u8],
    _payload_key_factors: &[PayloadKeyFactor],
) -> Zeroizing<[u8; DATA_KEY_LEN]> {
    copy_data_key(data_key)
}

fn copy_data_key(data_key: &[u8]) -> Zeroizing<[u8; DATA_KEY_LEN]> {
    let mut out = [0_u8; DATA_KEY_LEN];
    out.copy_from_slice(data_key);
    Zeroizing::new(out)
}

fn decode_profiles_from_payload(payload: &[u8], payload_key: &[u8]) -> Result<ProfileMap> {
    let mut profiles: ProfileMap =
        serde_json::from_slice(payload).context("decrypted vault payload was not valid JSON")?;
    if profiles.profile_entries.is_empty() {
        return Ok(profiles);
    }

    let entries = std::mem::take(&mut profiles.profile_entries);
    for (profile, entry) in entries {
        let profile_key =
            decrypt_payload_with_aad(payload_key, &entry.wrapped_key, V2_PROFILE_KEY_AAD)
                .with_context(|| format!("failed to decrypt profile key for {profile}"))?;
        if profile_key.len() != DATA_KEY_LEN {
            return Err(anyhow!(
                "profile key for {profile} is {} bytes, expected {DATA_KEY_LEN}",
                profile_key.len()
            ));
        }
        let profile_plaintext = decrypt_payload_with_aad(
            profile_key.as_slice(),
            &entry.ciphertext,
            V2_PROFILE_PAYLOAD_AAD,
        )
        .with_context(|| format!("failed to decrypt profile payload for {profile}"))?;
        let vars: BTreeMap<String, String> = serde_json::from_slice(&profile_plaintext)
            .with_context(|| format!("profile payload for {profile} was not valid JSON"))?;
        profiles.profiles.insert(profile, vars);
    }
    Ok(profiles)
}

fn encode_profiles_for_payload(
    profiles: &ProfileMap,
    payload_key: &[u8],
    profile_keys_enabled: bool,
) -> Result<Vec<u8>> {
    if !profile_keys_enabled {
        return serde_json::to_vec(profiles).context("failed to serialize profile map to JSON");
    }

    let mut encoded = profiles.clone();
    encoded.profile_entries.clear();
    for (profile, vars) in &profiles.profiles {
        let profile_key = generate_data_key();
        let profile_plaintext = serde_json::to_vec(vars)
            .with_context(|| format!("failed to serialize profile {profile}"))?;
        let ciphertext = encrypt_payload_with_aad(
            profile_key.as_slice(),
            &profile_plaintext,
            V2_PROFILE_PAYLOAD_AAD,
        )
        .with_context(|| format!("failed to encrypt profile {profile}"))?;
        let wrapped_key =
            encrypt_payload_with_aad(payload_key, profile_key.as_slice(), V2_PROFILE_KEY_AAD)
                .with_context(|| format!("failed to wrap profile key for {profile}"))?;
        encoded.profile_entries.insert(
            profile.clone(),
            ProfileEntry {
                wrapped_key,
                ciphertext,
            },
        );
    }
    encoded.profiles.clear();
    serde_json::to_vec(&encoded).context("failed to serialize profile-entry map to JSON")
}

fn payload_key_factors_for_metadata(
    metadata: Option<&VaultPolicyMetadataV2>,
    passphrase: Option<&str>,
) -> Result<Vec<PayloadKeyFactor>> {
    let mut factors = Vec::new();
    let Some(metadata) = metadata else {
        return Ok(factors);
    };

    for factor in metadata.policies.iter().flat_map(|policy| &policy.factors) {
        match factor.kind {
            UnlockFactorKindV2::Passphrase => {
                factors.push(PayloadKeyFactor {
                    kind: UnlockFactorKindV2::Passphrase,
                    key: passphrase_factor_key(factor, passphrase)?,
                });
            }
            UnlockFactorKindV2::DeviceSeal => factors.push(PayloadKeyFactor {
                kind: UnlockFactorKindV2::DeviceSeal,
                key: device_seal_factor_key(factor)?,
            }),
            _ => {}
        }
    }
    Ok(factors)
}

#[cfg(feature = "passphrase-factor")]
fn passphrase_factor_key(
    factor: &sshenv_vault_models::UnlockFactorV2,
    passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; DATA_KEY_LEN]>> {
    let Some(passphrase) = passphrase else {
        return Err(anyhow!("vault requires a passphrase factor"));
    };
    passphrase::derive_factor_from_metadata(factor, passphrase)
}

#[cfg(not(feature = "passphrase-factor"))]
fn passphrase_factor_key(
    _factor: &sshenv_vault_models::UnlockFactorV2,
    _passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; DATA_KEY_LEN]>> {
    Err(anyhow!(
        "vault requires a passphrase factor, but this sshenv build was compiled without passphrase support"
    ))
}

#[cfg(feature = "device-seal")]
fn device_seal_factor_key(
    factor: &sshenv_vault_models::UnlockFactorV2,
) -> Result<Zeroizing<[u8; DATA_KEY_LEN]>> {
    device::derive_factor_from_metadata(factor)
}

#[cfg(not(feature = "device-seal"))]
fn device_seal_factor_key(
    _factor: &sshenv_vault_models::UnlockFactorV2,
) -> Result<Zeroizing<[u8; DATA_KEY_LEN]>> {
    Err(anyhow!(
        "vault requires a device-seal factor, but this sshenv build was compiled without device-seal support"
    ))
}

#[cfg(feature = "passphrase-factor")]
fn metadata_has_passphrase_factor(metadata: Option<&VaultPolicyMetadataV2>) -> bool {
    metadata
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(passphrase::is_passphrase_factor)
}

#[cfg(feature = "device-seal")]
fn metadata_has_device_seal_factor(metadata: Option<&VaultPolicyMetadataV2>) -> bool {
    metadata
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(device::is_device_seal_factor)
}

#[cfg(feature = "passphrase-factor")]
fn ensure_v2_for_passphrase(version: u8) -> Result<()> {
    if version == VERSION_V2 {
        Ok(())
    } else {
        Err(anyhow!(
            "passphrase factors require v2; run `sshenv migrate-vault --to v2` first"
        ))
    }
}

#[cfg(feature = "device-seal")]
fn ensure_v2_for_device_seal(version: u8) -> Result<()> {
    if version == VERSION_V2 {
        Ok(())
    } else {
        Err(anyhow!(
            "device-seal factors require v2; run `sshenv migrate-vault --to v2` first"
        ))
    }
}

fn payload_aad_for_version(version: u8) -> Result<&'static [u8]> {
    match version {
        VERSION => Ok(PAYLOAD_AAD),
        VERSION_V2 => Ok(V2_PAYLOAD_AAD),
        _ => Err(VaultModelsError::UnsupportedVersion(version).into()),
    }
}

fn policy_metadata_from_recipients(recipients: &[RecipientEntry]) -> VaultPolicyMetadataV2 {
    VaultPolicyMetadataV2 {
        generation: 0,
        profile_keys_enabled: false,
        policies: Vec::new(),
        recipients: recipients
            .iter()
            .map(|recipient| RecipientMetadataV2 {
                fingerprint: recipient.fingerprint.clone(),
                public_descriptor: recipient.public_key_line.clone(),
                kind: UnlockFactorKindV2::SshRecipient,
            })
            .collect(),
    }
}

fn format_fingerprint_list(values: &[&String]) -> String {
    if values.is_empty() {
        "(none)".to_string()
    } else {
        values
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("vault path has no parent directory: {}", path.display()))?;

    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }

    let parent_for_tempfile = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let mut tmp = tempfile::NamedTempFile::new_in(parent_for_tempfile).with_context(|| {
        format!(
            "failed to create temp file in {}",
            parent_for_tempfile.display()
        )
    })?;
    tmp.write_all(bytes)
        .with_context(|| format!("failed to write temp vault file {}", tmp.path().display()))?;
    tmp.as_file_mut().sync_all().ok();

    set_permissions_mode_on_file(tmp.as_file(), mode)
        .with_context(|| format!("failed to set mode {mode:o} on {}", tmp.path().display()))?;

    tmp.persist(path)
        .with_context(|| format!("failed to persist vault at {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_permissions_mode_on_file(file: &fs::File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    file.set_permissions(perms).context("failed to chmod")?;
    Ok(())
}

#[cfg(not(unix))]
fn set_permissions_mode_on_file(_file: &fs::File, _mode: u32) -> Result<()> {
    Ok(())
}

/// Resolve the default vault file path, respecting `$SSHENV_VAULT` and the
/// user's home directory.
#[must_use]
pub fn default_vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SSHENV_VAULT") {
        return PathBuf::from(p);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/vault"),
        |h| h.join(".sshenv").join("vault"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sshenv_vault_models::MAGIC;

    /// Generate a fresh `ssh-ed25519` keypair on demand, returning
    /// `(openssh_pubkey_line, age_identity)`.
    fn generate_keypair() -> (String, Box<dyn age::Identity>) {
        use rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey};
        let priv_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen key");
        let pub_key_line = priv_key
            .public_key()
            .to_openssh()
            .expect("serialize pubkey");
        let privkey_pem = priv_key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("serialize privkey")
            .to_string();
        let id = age::ssh::Identity::from_buffer(std::io::Cursor::new(privkey_pem), None)
            .expect("parse age identity");
        (pub_key_line, Box::new(id))
    }

    #[test]
    fn create_save_load_unlock_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault");

        let (pubkey, identity) = generate_keypair();

        let (mut v, key) = Vault::create(&pubkey).expect("create vault");
        v.profiles.set("p", "K", "value".into());
        v.save(&vault_path, &key).expect("save vault");

        let ct = Vault::load_ciphertext(&vault_path).expect("load ciphertext");
        let identities: Vec<Box<dyn age::Identity>> = vec![identity];
        let (unlocked, _key) = Vault::unlock(ct, &identities).expect("unlock");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "value"
        );
    }

    #[test]
    fn duplicate_recipient_rejected() {
        let (pubkey, _id) = generate_keypair();
        let (mut v, key) = Vault::create(&pubkey).expect("create vault");
        let err = v
            .add_recipient(&pubkey, &key)
            .expect_err("should be duplicate");
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    #[test]
    fn vault_file_has_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");
        let (pubkey, _id) = generate_keypair();
        let (v, key) = Vault::create(&pubkey).expect("create");
        v.save(&path, &key).expect("save");
        let bytes = fs::read(&path).expect("read");
        assert_eq!(&bytes[..4], &MAGIC);
    }

    #[test]
    #[cfg(unix)]
    fn vault_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");
        let (pubkey, _id) = generate_keypair();
        let (v, key) = Vault::create(&pubkey).expect("create");
        v.save(&path, &key).expect("save");
        let meta = fs::metadata(&path).expect("meta");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn migrate_to_v2_preserves_secret_access_and_public_key_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let (pubkey, identity) = generate_keypair();
        let (mut v, key) = Vault::create(&pubkey).expect("create");
        v.profiles.set("p", "K", "migrated".into());
        v.migrate_to_v2(std::slice::from_ref(&pubkey))
            .expect("migrate");
        v.save(&path, &key).expect("save v2");

        let ct = Vault::load_ciphertext(&path).expect("load v2");
        assert_eq!(ct.header.version, VERSION_V2);
        assert_eq!(ct.recipients[0].public_key_line, pubkey);
        assert!(ct.policy_metadata.is_some());

        let identities: Vec<Box<dyn age::Identity>> = vec![identity];
        let (unlocked, _) = Vault::unlock(ct, &identities).expect("unlock v2");
        assert_eq!(unlocked.header.version, VERSION_V2);
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "migrated"
        );
    }

    #[test]
    fn profile_key_mode_roundtrips_and_uses_profile_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let (pubkey, identity) = generate_keypair();
        let (mut v, key) = Vault::create(&pubkey).expect("create");
        v.profiles.set("p", "K", "profile-keyed".into());
        v.migrate_to_v2(std::slice::from_ref(&pubkey))
            .expect("migrate");
        assert!(v.enable_profile_keys().expect("enable profile keys"));
        v.save(&path, &key).expect("save profile-keyed v2");

        let parsed = Vault::load_ciphertext(&path).expect("load ciphertext");
        assert!(
            parsed
                .policy_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.profile_keys_enabled)
        );
        let payload_key = payload_key_for_data_key(key.as_slice(), &[]);
        let plaintext = decrypt_payload_with_aad(
            payload_key.as_slice(),
            &parsed.payload_ciphertext,
            V2_PAYLOAD_AAD,
        )
        .expect("decrypt outer payload");
        let encoded: ProfileMap = serde_json::from_slice(&plaintext).expect("profile map json");
        assert!(encoded.profiles.is_empty());
        assert!(encoded.profile_entries.contains_key("p"));

        let identities: Vec<Box<dyn age::Identity>> = vec![identity];
        let (unlocked, _) = Vault::unlock(parsed, &identities).expect("unlock profile-keyed");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "profile-keyed"
        );
    }

    #[test]
    #[cfg(feature = "passphrase-factor")]
    fn passphrase_factor_requires_ssh_and_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let (pubkey, identity) = generate_keypair();
        let (mut v, key) = Vault::create(&pubkey).expect("create");
        v.profiles.set("p", "K", "passphrased".into());
        v.migrate_to_v2(std::slice::from_ref(&pubkey))
            .expect("migrate");
        v.enable_passphrase_factor("correct horse battery staple")
            .expect("enable passphrase");
        v.save(&path, &key).expect("save passphrase vault");

        let ct = Vault::load_ciphertext(&path).expect("load");
        let identities: Vec<Box<dyn age::Identity>> = vec![identity];
        assert!(Vault::unlock(ct, &identities).is_err());

        let ct = Vault::load_ciphertext(&path).expect("load again");
        let (mut unlocked, data_key) =
            Vault::unlock_with_passphrase(ct, &identities, Some("correct horse battery staple"))
                .expect("unlock with passphrase");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "passphrased"
        );

        unlocked
            .change_passphrase_factor("new passphrase")
            .expect("change passphrase");
        unlocked.save(&path, &data_key).expect("save changed");
        let ct = Vault::load_ciphertext(&path).expect("load changed");
        assert!(
            Vault::unlock_with_passphrase(ct, &identities, Some("correct horse battery staple"))
                .is_err()
        );
        let ct = Vault::load_ciphertext(&path).expect("load changed again");
        let (mut unlocked, data_key) =
            Vault::unlock_with_passphrase(ct, &identities, Some("new passphrase"))
                .expect("unlock changed passphrase");

        unlocked
            .disable_passphrase_factor()
            .expect("disable passphrase");
        unlocked.save(&path, &data_key).expect("save disabled");
        let ct = Vault::load_ciphertext(&path).expect("load disabled");
        let (unlocked, _) = Vault::unlock(ct, &identities).expect("unlock without passphrase");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "passphrased"
        );
    }

    #[test]
    #[cfg(feature = "rekey")]
    fn rotate_data_key_preserves_recipient_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let (pubkey_a, id_a) = generate_keypair();
        let (pubkey_b, id_b) = generate_keypair();

        let (mut v, old_key) = Vault::create(&pubkey_a).expect("create");
        v.add_recipient(&pubkey_b, &old_key).expect("add B");
        v.profiles.set("p", "K", "rotated".into());

        let new_key = v.rotate_data_key(&[pubkey_a, pubkey_b]).expect("rotate");
        assert_ne!(old_key.as_slice(), new_key.as_slice());
        v.save(&path, &new_key).expect("save");

        let ct = Vault::load_ciphertext(&path).unwrap();
        let identities: Vec<Box<dyn age::Identity>> = vec![id_a, id_b];
        let (unlocked, _) = Vault::unlock(ct, &identities).expect("unlock after rotate");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "rotated"
        );
    }

    #[test]
    fn add_recipient_then_unlock_with_either_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let (pubkey_a, id_a) = generate_keypair();
        let (pubkey_b, id_b) = generate_keypair();

        let (mut v, key) = Vault::create(&pubkey_a).expect("create");
        v.add_recipient(&pubkey_b, &key).expect("add B");
        v.profiles.set("p", "K", "hello".into());
        v.save(&path, &key).expect("save");

        // Unlock with B alone.
        let ct = Vault::load_ciphertext(&path).unwrap();
        let (unlocked, _) = Vault::unlock(ct, &[id_b]).expect("unlock with B");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "hello"
        );

        // Unlock with A alone.
        let ct = Vault::load_ciphertext(&path).unwrap();
        let (unlocked, _) = Vault::unlock(ct, &[id_a]).expect("unlock with A");
        assert_eq!(
            unlocked.profiles.get("p").unwrap().get("K").unwrap(),
            "hello"
        );
    }
}
