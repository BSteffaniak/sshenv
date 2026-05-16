//! SSH-recipient key wrapping and unwrapping via `age`.
//!
//! The vault's 32-byte data key is wrapped independently for each
//! authorized SSH public key. Wrapping uses `age::Encryptor` with an
//! `age::ssh::Recipient`; unwrapping uses `age::Decryptor` with any of a
//! list of `age::Identity` objects (which in practice are
//! `age::ssh::Identity` values constructed from on-disk SSH private keys).

use std::io::{Read, Write};
use std::iter;
use std::str::FromStr;

use age::ssh::Recipient as SshRecipient;
use age::{Decryptor, Encryptor};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use sshenv_vault_models::{DATA_KEY_LEN, RecipientEntry, UnlockFactorKindV2};
use zeroize::Zeroizing;

/// Supported SSH key types for recipients. Must match a subset of what
/// `age`'s `ssh` feature supports.
const SUPPORTED_KEY_TYPES: &[&str] = &["ssh-ed25519", "ssh-rsa"];

/// Compute a stable fingerprint for an age-plugin recipient descriptor.
#[must_use]
pub fn fingerprint_for_age_plugin_recipient(descriptor: &str) -> String {
    use base64::Engine;
    let hash = Sha256::digest(descriptor.trim().as_bytes());
    let no_pad = base64::engine::general_purpose::STANDARD_NO_PAD;
    let encoded = no_pad.encode(hash);
    format!("AGE-PLUGIN-SHA256:{encoded}")
}

/// Compute the `SHA256:<base64>` fingerprint of an SSH public key given
/// its type and base64-encoded body, matching `ssh-keygen -lf`.
#[must_use]
pub fn fingerprint_for_public_key(key_body_b64: &str) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let Ok(body) = engine.decode(key_body_b64) else {
        return format!("SHA256:INVALID_{}", key_body_b64.len());
    };
    let hash = Sha256::digest(body);
    let no_pad = base64::engine::general_purpose::STANDARD_NO_PAD;
    let encoded = no_pad.encode(hash);
    format!("SHA256:{encoded}")
}

/// Parse an SSH public key line and return `(key_type, body_base64)`.
fn split_public_key_line(line: &str) -> Result<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        bail!("empty SSH public key line");
    }
    let mut parts = trimmed.split_whitespace();
    let kt = parts.next().context("SSH public key is missing key type")?;
    let body = parts
        .next()
        .context("SSH public key is missing key material")?;
    Ok((kt, body))
}

/// Compute the `SHA256:<base64>` fingerprint from a full SSH public key
/// line (e.g. `ssh-ed25519 AAAA... optional-comment`).
///
/// # Errors
///
/// Returns an error if the line is empty or missing key material.
pub fn fingerprint_from_line(public_key_line: &str) -> Result<String> {
    let (_, body) = split_public_key_line(public_key_line)?;
    Ok(fingerprint_for_public_key(body))
}

/// Determine the v2 factor kind for a persisted public recipient descriptor.
#[must_use]
pub fn recipient_descriptor_kind(descriptor: &str) -> UnlockFactorKindV2 {
    if descriptor.trim().starts_with("age1") {
        UnlockFactorKindV2::HardwareRecipient
    } else {
        UnlockFactorKindV2::SshRecipient
    }
}

/// Compute the stable fingerprint for any supported public recipient descriptor.
///
/// # Errors
///
/// Returns an error if the descriptor is neither a supported SSH public key nor,
/// with `age-plugin-recipient`, a valid age-plugin recipient.
pub fn fingerprint_from_recipient_descriptor(descriptor: &str) -> Result<String> {
    let trimmed = descriptor.trim();
    if trimmed.starts_with("age1") {
        return fingerprint_from_age_plugin_recipient_descriptor(trimmed);
    }
    fingerprint_from_line(trimmed)
}

#[cfg(feature = "age-plugin-recipient")]
fn fingerprint_from_age_plugin_recipient_descriptor(descriptor: &str) -> Result<String> {
    let _recipient: age::plugin::Recipient = descriptor
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid age-plugin recipient: {err}"))?;
    Ok(fingerprint_for_age_plugin_recipient(descriptor))
}

#[cfg(not(feature = "age-plugin-recipient"))]
fn fingerprint_from_age_plugin_recipient_descriptor(_descriptor: &str) -> Result<String> {
    bail!("this sshenv build was compiled without age-plugin-recipient support")
}

/// Build a new [`RecipientEntry`] by wrapping `data_key` to any supported
/// public recipient descriptor.
///
/// # Errors
///
/// Returns an error if the descriptor is invalid, unsupported by this build,
/// or wrapping fails.
pub fn build_entry_for_recipient_descriptor(
    descriptor: &str,
    data_key: &[u8],
) -> Result<RecipientEntry> {
    let trimmed = descriptor.trim();
    if trimmed.starts_with("age1") {
        return build_entry_for_age_plugin_recipient(trimmed, data_key);
    }
    build_entry_for_public_key_line(trimmed, data_key)
}

/// Build a new [`RecipientEntry`] by wrapping `data_key` to the given SSH
/// public key line.
///
/// # Errors
///
/// Returns an error if the key type is unsupported, the public key cannot
/// be parsed by `age`, or wrapping fails.
pub fn build_entry_for_public_key_line(
    public_key_line: &str,
    data_key: &[u8],
) -> Result<RecipientEntry> {
    let (key_type, key_body) = split_public_key_line(public_key_line)?;
    if !SUPPORTED_KEY_TYPES.contains(&key_type) {
        bail!(
            "unsupported SSH key type '{key_type}'; supported: {}",
            SUPPORTED_KEY_TYPES.join(", ")
        );
    }
    if data_key.len() != DATA_KEY_LEN {
        bail!(
            "internal error: data key is {} bytes, expected {DATA_KEY_LEN}",
            data_key.len()
        );
    }

    let fingerprint = fingerprint_for_public_key(key_body);

    let ssh_recipient = SshRecipient::from_str(public_key_line.trim())
        .map_err(|err| anyhow::anyhow!("invalid SSH public key: {err:?}"))?;

    let encryptor = Encryptor::with_recipients(iter::once(&ssh_recipient as &dyn age::Recipient))
        .context("failed to initialize age encryptor")?;

    let mut wrapped = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut wrapped)
            .context("failed to start age wrapping")?;
        writer
            .write_all(data_key)
            .context("failed to write data key to wrapper")?;
        writer.finish().context("failed to finish age wrapping")?;
    }

    Ok(RecipientEntry {
        fingerprint,
        public_key_line: public_key_line.trim().to_string(),
        wrapped_key: wrapped,
    })
}

#[cfg(feature = "age-plugin-recipient")]
fn build_entry_for_age_plugin_recipient(
    descriptor: &str,
    data_key: &[u8],
) -> Result<RecipientEntry> {
    if data_key.len() != DATA_KEY_LEN {
        bail!(
            "internal error: data key is {} bytes, expected {DATA_KEY_LEN}",
            data_key.len()
        );
    }

    let recipient: age::plugin::Recipient = descriptor
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid age-plugin recipient: {err}"))?;
    let fingerprint = fingerprint_for_age_plugin_recipient(descriptor);
    let plugin_name = recipient.plugin().to_string();
    let plugin_recipient =
        age::plugin::RecipientPluginV1::new(&plugin_name, &[recipient], &[], age::NoCallbacks)
            .with_context(|| format!("failed to initialize age plugin recipient {plugin_name}"))?;

    let encryptor =
        Encryptor::with_recipients(iter::once(&plugin_recipient as &dyn age::Recipient))
            .context("failed to initialize age encryptor")?;

    let mut wrapped = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut wrapped)
            .context("failed to start age plugin wrapping")?;
        writer
            .write_all(data_key)
            .context("failed to write data key to age plugin wrapper")?;
        writer
            .finish()
            .context("failed to finish age plugin wrapping")?;
    }

    Ok(RecipientEntry {
        fingerprint,
        public_key_line: descriptor.to_string(),
        wrapped_key: wrapped,
    })
}

#[cfg(not(feature = "age-plugin-recipient"))]
fn build_entry_for_age_plugin_recipient(
    _descriptor: &str,
    _data_key: &[u8],
) -> Result<RecipientEntry> {
    bail!("this sshenv build was compiled without age-plugin-recipient support")
}

/// Try to unwrap any of the recipient entries using any of the provided
/// identities. Returns the first successful data key found.
///
/// # Errors
///
/// Returns an error only if no identity can unwrap any recipient.
pub fn unwrap_data_key(
    recipients: &[RecipientEntry],
    identities: &[Box<dyn age::Identity>],
) -> Result<Zeroizing<[u8; DATA_KEY_LEN]>> {
    for recipient in recipients {
        for identity in identities {
            let Ok(decryptor) =
                Decryptor::new_buffered(std::io::Cursor::new(&recipient.wrapped_key))
            else {
                continue;
            };
            let Ok(mut reader) = decryptor.decrypt(iter::once(identity.as_ref())) else {
                continue;
            };
            let mut out = [0_u8; DATA_KEY_LEN];
            // Read exactly DATA_KEY_LEN bytes.
            if reader.read_exact(&mut out).is_err() {
                continue;
            }
            // Confirm EOF.
            let mut one = [0_u8; 1];
            if reader.read(&mut one).ok() != Some(0) {
                continue;
            }
            return Ok(Zeroizing::new(out));
        }
    }
    bail!("no identity could unwrap any recipient blob")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_key_line() {
        let err = build_entry_for_public_key_line("", &[0_u8; DATA_KEY_LEN]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_unsupported_key_type() {
        let err = build_entry_for_public_key_line("ssh-dss AAAA fake", &[0_u8; DATA_KEY_LEN])
            .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_wrong_key_length() {
        // Uses a real ed25519 pubkey so we reach the length check.
        let k = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF1r4mXp9V1d6JEcv5m5d8ONnuQVpMb1i+B7ifqWeu6w";
        let err = build_entry_for_public_key_line(k, &[0_u8; 10]).unwrap_err();
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn fingerprint_is_stable() {
        let b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIF1r4mXp9V1d6JEcv5m5d8ONnuQVpMb1i+B7ifqWeu6w";
        let fp1 = fingerprint_for_public_key(b64);
        let fp2 = fingerprint_for_public_key(b64);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
    }

    #[test]
    fn age_plugin_recipient_fingerprint_is_stable() {
        let descriptor = "age1yubikey1q2w3e4r5t6y7u8i9o0p";
        let fp1 = fingerprint_for_age_plugin_recipient(descriptor);
        let fp2 = fingerprint_for_age_plugin_recipient(descriptor);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("AGE-PLUGIN-SHA256:"));
        assert_eq!(
            recipient_descriptor_kind(descriptor),
            UnlockFactorKindV2::HardwareRecipient
        );
    }

    #[test]
    fn fingerprint_from_line_matches_fingerprint_for_public_key() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF1r4mXp9V1d6JEcv5m5d8ONnuQVpMb1i+B7ifqWeu6w braden@test";
        let from_line = fingerprint_from_line(line).unwrap();
        let from_body = fingerprint_for_public_key(
            "AAAAC3NzaC1lZDI1NTE5AAAAIF1r4mXp9V1d6JEcv5m5d8ONnuQVpMb1i+B7ifqWeu6w",
        );
        assert_eq!(from_line, from_body);
    }

    #[test]
    fn fingerprint_from_line_rejects_empty() {
        assert!(fingerprint_from_line("").is_err());
        assert!(fingerprint_from_line("   ").is_err());
    }

    #[test]
    fn fingerprint_from_line_rejects_missing_body() {
        assert!(fingerprint_from_line("ssh-ed25519").is_err());
    }
}
