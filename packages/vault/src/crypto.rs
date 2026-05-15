//! Symmetric crypto: derive an AES-256-SIV key from a 32-byte data key,
//! then encrypt/decrypt vault payloads.

use aes_siv::Aes256SivAead;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::{Aead, KeyInit, Payload};
use anyhow::Result;
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use sshenv_vault_models::{DATA_KEY_LEN, HKDF_INFO, HKDF_SALT, PAYLOAD_AAD, SIV_KEY_LEN};
use zeroize::Zeroizing;

/// Generate a cryptographically random 32-byte data key.
#[must_use]
pub fn generate_data_key() -> Zeroizing<[u8; DATA_KEY_LEN]> {
    let mut key = [0_u8; DATA_KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut key);
    Zeroizing::new(key)
}

/// Derive a 64-byte AES-SIV key from the 32-byte data key.
/// Bind a data key to an additional factor key. The returned key should be
/// used as the payload encryption key when the factor is required.
#[cfg(any(feature = "passphrase-factor", feature = "device-seal"))]
#[must_use]
pub fn bind_data_key_to_factor(
    data_key: &[u8],
    factor_key: &[u8],
) -> Zeroizing<[u8; DATA_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(factor_key), data_key);
    let mut out = [0_u8; DATA_KEY_LEN];
    hk.expand(b"sshenv:v2:factor-bound-payload-key", &mut out)
        .expect("DATA_KEY_LEN is within HKDF output bounds");
    Zeroizing::new(out)
}

/// Derive a 64-byte AES-SIV key from the 32-byte data key.
fn derive_siv_key(data_key: &[u8]) -> Zeroizing<[u8; SIV_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), data_key);
    let mut out = [0_u8; SIV_KEY_LEN];
    hk.expand(HKDF_INFO, &mut out)
        .expect("SIV_KEY_LEN is within HKDF output bounds");
    Zeroizing::new(out)
}

/// Encrypt `plaintext` under `data_key` with payload AAD binding.
///
/// # Errors
///
/// Returns an error if the AES-SIV implementation rejects the operation.
pub fn encrypt_payload(data_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_payload_with_aad(data_key, plaintext, PAYLOAD_AAD)
}

/// Encrypt `plaintext` under `data_key` with an explicit AAD binding.
///
/// # Errors
///
/// Returns an error if the AES-SIV implementation rejects the operation.
pub fn encrypt_payload_with_aad(data_key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let siv = derive_siv_key(data_key);
    let cipher = Aes256SivAead::new(GenericArray::from_slice(siv.as_slice()));
    let nonce = GenericArray::from_slice(&[0_u8; 16]);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("failed to encrypt vault payload: {e}"))
}

/// Decrypt `ciphertext` under `data_key` with payload AAD binding.
///
/// The result is wrapped in [`Zeroizing`] so that on drop the plaintext
/// bytes are zeroed.
///
/// # Errors
///
/// Returns an error if `data_key` does not match, if AAD differs, or if
/// the ciphertext has been tampered with.
pub fn decrypt_payload(data_key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_payload_with_aad(data_key, ciphertext, PAYLOAD_AAD)
}

/// Decrypt `ciphertext` under `data_key` with an explicit AAD binding.
///
/// # Errors
///
/// Returns an error if `data_key` does not match, if AAD differs, or if
/// the ciphertext has been tampered with.
pub fn decrypt_payload_with_aad(
    data_key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let siv = derive_siv_key(data_key);
    let cipher = Aes256SivAead::new(GenericArray::from_slice(siv.as_slice()));
    let nonce = GenericArray::from_slice(&[0_u8; 16]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("failed to decrypt vault payload: {e}"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_payload_empty() {
        let key = [7_u8; DATA_KEY_LEN];
        let ct = encrypt_payload(&key, b"").expect("encrypt");
        let pt = decrypt_payload(&key, &ct).expect("decrypt");
        assert_eq!(pt.as_slice(), b"");
    }

    #[test]
    fn roundtrip_payload_nonempty() {
        let key = [7_u8; DATA_KEY_LEN];
        let msg = b"{\"profiles\":{}}";
        let ct = encrypt_payload(&key, msg).expect("encrypt");
        let pt = decrypt_payload(&key, &ct).expect("decrypt");
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = [7_u8; DATA_KEY_LEN];
        let msg = b"secret data";
        let mut ct = encrypt_payload(&key, msg).expect("encrypt");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt_payload(&key, &ct).is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let k1 = [1_u8; DATA_KEY_LEN];
        let k2 = [2_u8; DATA_KEY_LEN];
        let ct = encrypt_payload(&k1, b"stuff").unwrap();
        assert!(decrypt_payload(&k2, &ct).is_err());
    }

    #[test]
    fn generated_keys_differ() {
        let a = generate_data_key();
        let b = generate_data_key();
        assert_ne!(a.as_slice(), b.as_slice());
    }
}
