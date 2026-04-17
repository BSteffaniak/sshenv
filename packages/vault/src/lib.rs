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
pub mod format;
pub mod recipient;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use sshenv_vault_models::{
    DATA_KEY_LEN, ProfileMap, RecipientEntry, VaultHeader, VaultModelsError,
};
use zeroize::Zeroizing;

pub use sshenv_vault_models as models;

use crate::crypto::{decrypt_payload, encrypt_payload, generate_data_key};
use crate::format::{encode, parse};

/// Shorthand alias for the fixed-size, auto-zeroizing data key.
pub type DataKey = Zeroizing<[u8; DATA_KEY_LEN]>;

/// An in-memory, decrypted vault: header + recipients + profile map.
#[derive(Debug, Clone)]
pub struct Vault {
    pub header: VaultHeader,
    pub recipients: Vec<RecipientEntry>,
    pub profiles: ProfileMap,
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
            recipients: vec![recipient],
            profiles: ProfileMap::default(),
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
        let data_key = recipient::unwrap_data_key(&ciphertext.recipients, identities)
            .context("no configured SSH identity could unwrap the vault data key")?;

        let plaintext = decrypt_payload(data_key.as_slice(), &ciphertext.payload_ciphertext)
            .context("failed to decrypt vault payload")?;

        let profiles: ProfileMap = if plaintext.is_empty() {
            ProfileMap::default()
        } else {
            serde_json::from_slice(&plaintext)
                .context("decrypted vault payload was not valid JSON")?
        };

        Ok((
            Self {
                header: ciphertext.header,
                recipients: ciphertext.recipients,
                profiles,
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

    /// Serialize, encrypt, and atomically write this vault to disk with
    /// mode `0600`.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails, the file cannot be written,
    /// or the rename fails.
    pub fn save(&self, path: &Path, data_key: &[u8; DATA_KEY_LEN]) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.profiles)
            .context("failed to serialize profile map to JSON")?;
        let plaintext = Zeroizing::new(plaintext);
        let ciphertext = encrypt_payload(data_key.as_slice(), plaintext.as_slice())
            .context("failed to encrypt vault payload")?;

        let encoded = encode(self.header, &self.recipients, &ciphertext)?;
        atomic_write(path, &encoded, 0o600)?;
        Ok(())
    }
}

/// A parsed but still-encrypted vault file.
pub struct CiphertextVault {
    pub header: VaultHeader,
    pub recipients: Vec<RecipientEntry>,
    pub payload_ciphertext: Vec<u8>,
}

/// Atomically write `bytes` to `path` with the given unix mode (ignored on
/// non-unix).
///
/// Creates the parent directory if necessary.
///
/// # Errors
///
/// Returns an error if any filesystem operation fails.
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
