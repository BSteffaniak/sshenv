use std::collections::BTreeSet;

use serde::Serialize;
use sshenv_vault_models::RecoveryShareSetMetadataV2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryUnlockPlan {
    pub set_id: String,
    pub threshold: u8,
    pub provided_share_ids: Vec<String>,
    pub ignored_share_ids: Vec<String>,
    pub missing_share_count: usize,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BreakGlassRecoveryPlan {
    pub set_id: String,
    pub ready: bool,
    pub steps: Vec<String>,
    pub warnings: Vec<String>,
}

use thiserror::Error;
#[cfg(feature = "shamir-sharing")]
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "shamir-sharing")]
const RECOVERY_SHARE_ENVELOPE_PREFIX: &str = "sshenv-shamir-v1";

#[cfg(feature = "shamir-sharing")]
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ShamirShare {
    pub index: u8,
    pub value: Vec<u8>,
}

#[cfg(feature = "shamir-sharing")]
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct RecoveryShareEnvelope {
    pub set_id: String,
    pub threshold: u8,
    pub share: ShamirShare,
}

#[cfg(feature = "shamir-sharing")]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryShareEnvelopeError {
    #[error("recovery share envelope has invalid format")]
    InvalidFormat,
    #[error("recovery share envelope version is unsupported")]
    UnsupportedVersion,
    #[error("recovery share envelope threshold is invalid")]
    InvalidThreshold,
    #[error("recovery share envelope share index is invalid")]
    InvalidShareIndex,
    #[error("recovery share envelope payload is invalid hex")]
    InvalidHex,
}

#[cfg(feature = "shamir-sharing")]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShamirError {
    #[error("Shamir threshold must be at least 1")]
    InvalidThreshold,
    #[error("Shamir share count must be at least 1 and at most 255")]
    InvalidShareCount,
    #[error("Shamir threshold {threshold} exceeds share count {share_count}")]
    ThresholdExceedsShareCount { threshold: u8, share_count: u8 },
    #[error("not enough shares: need {threshold}, got {provided}")]
    NotEnoughShares { threshold: u8, provided: usize },
    #[error("duplicate Shamir share index: {0}")]
    DuplicateShareIndex(u8),
    #[error("Shamir share index must be non-zero")]
    ZeroShareIndex,
    #[error("Shamir shares have inconsistent lengths")]
    InconsistentShareLength,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryShareMetadataError {
    #[error("recovery share set id is empty")]
    EmptySetId,
    #[error("recovery share threshold must be at least 1")]
    ZeroThreshold,
    #[error("recovery share threshold {threshold} exceeds share count {share_count}")]
    ThresholdExceedsShareCount { threshold: u8, share_count: usize },
    #[error("recovery share id is empty")]
    EmptyShareId,
    #[error("duplicate recovery share id: {0}")]
    DuplicateShareId(String),
    #[error("shamir metadata does not match recovery share set threshold/share count")]
    ShamirMismatch,
}

pub fn validate_recovery_share_set_metadata(
    set: &RecoveryShareSetMetadataV2,
) -> Result<(), RecoveryShareMetadataError> {
    if set.id.trim().is_empty() {
        return Err(RecoveryShareMetadataError::EmptySetId);
    }
    if set.threshold == 0 {
        return Err(RecoveryShareMetadataError::ZeroThreshold);
    }
    if usize::from(set.threshold) > set.shares.len() {
        return Err(RecoveryShareMetadataError::ThresholdExceedsShareCount {
            threshold: set.threshold,
            share_count: set.shares.len(),
        });
    }

    let mut ids = BTreeSet::new();
    for share in &set.shares {
        if share.id.trim().is_empty() {
            return Err(RecoveryShareMetadataError::EmptyShareId);
        }
        if !ids.insert(share.id.clone()) {
            return Err(RecoveryShareMetadataError::DuplicateShareId(
                share.id.clone(),
            ));
        }
    }

    if let Some(shamir) = set.shamir {
        if shamir.threshold != set.threshold || usize::from(shamir.share_count) != set.shares.len()
        {
            return Err(RecoveryShareMetadataError::ShamirMismatch);
        }
    }

    Ok(())
}

pub fn plan_m_of_n_unlock(
    set: &RecoveryShareSetMetadataV2,
    provided_share_ids: &[String],
) -> Result<RecoveryUnlockPlan, RecoveryShareMetadataError> {
    validate_recovery_share_set_metadata(set)?;
    let valid_share_ids = set
        .shares
        .iter()
        .map(|share| share.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut unique_provided = BTreeSet::new();
    let mut ignored_share_ids = BTreeSet::new();
    for id in provided_share_ids {
        if valid_share_ids.contains(id.as_str()) {
            unique_provided.insert(id.clone());
        } else {
            ignored_share_ids.insert(id.clone());
        }
    }
    let unique_provided = unique_provided.into_iter().collect::<Vec<_>>();
    let ignored_share_ids = ignored_share_ids.into_iter().collect::<Vec<_>>();

    let provided_count = unique_provided.len();
    let threshold = usize::from(set.threshold);
    let missing_share_count = threshold.saturating_sub(provided_count);

    Ok(RecoveryUnlockPlan {
        set_id: set.id.clone(),
        threshold: set.threshold,
        provided_share_ids: unique_provided,
        ignored_share_ids,
        missing_share_count,
        ready: missing_share_count == 0,
    })
}

#[cfg(feature = "shamir-sharing")]
pub fn split_secret_shamir(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<Vec<ShamirShare>, ShamirError> {
    validate_shamir_parameters(threshold, share_count)?;

    let mut shares = (1..=share_count)
        .map(|index| ShamirShare {
            index,
            value: Vec::with_capacity(secret.len()),
        })
        .collect::<Vec<_>>();

    for &secret_byte in secret {
        let mut coefficients = vec![0_u8; usize::from(threshold.saturating_sub(1))];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut coefficients);
        for share in &mut shares {
            share
                .value
                .push(evaluate_polynomial(secret_byte, &coefficients, share.index));
        }
    }

    Ok(shares)
}

#[cfg(feature = "shamir-sharing")]
pub fn combine_recovery_share_envelopes(
    envelopes: &[RecoveryShareEnvelope],
) -> Result<Vec<u8>, ShamirError> {
    let Some(first) = envelopes.first() else {
        return Err(ShamirError::NotEnoughShares {
            threshold: 1,
            provided: 0,
        });
    };
    let threshold = first.threshold;
    let shares = envelopes
        .iter()
        .filter(|envelope| envelope.set_id == first.set_id && envelope.threshold == threshold)
        .map(|envelope| envelope.share.clone())
        .collect::<Vec<_>>();
    combine_shamir_shares(&shares, threshold)
}

#[cfg(feature = "shamir-sharing")]
pub fn encode_recovery_share_envelope(envelope: &RecoveryShareEnvelope) -> String {
    format!(
        "{RECOVERY_SHARE_ENVELOPE_PREFIX}:{}:{}:{}:{}",
        envelope.set_id,
        envelope.threshold,
        envelope.share.index,
        hex::encode(&envelope.share.value)
    )
}

#[cfg(feature = "shamir-sharing")]
pub fn decode_recovery_share_envelope(
    encoded: &str,
) -> Result<RecoveryShareEnvelope, RecoveryShareEnvelopeError> {
    let mut parts = encoded.trim().split(':');
    if parts.next() != Some(RECOVERY_SHARE_ENVELOPE_PREFIX) {
        return Err(RecoveryShareEnvelopeError::UnsupportedVersion);
    }
    let set_id = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(RecoveryShareEnvelopeError::InvalidFormat)?
        .to_string();
    let threshold = parts
        .next()
        .ok_or(RecoveryShareEnvelopeError::InvalidFormat)?
        .parse::<u8>()
        .map_err(|_| RecoveryShareEnvelopeError::InvalidThreshold)?;
    if threshold == 0 {
        return Err(RecoveryShareEnvelopeError::InvalidThreshold);
    }
    let index = parts
        .next()
        .ok_or(RecoveryShareEnvelopeError::InvalidFormat)?
        .parse::<u8>()
        .map_err(|_| RecoveryShareEnvelopeError::InvalidShareIndex)?;
    if index == 0 {
        return Err(RecoveryShareEnvelopeError::InvalidShareIndex);
    }
    let value = parts
        .next()
        .ok_or(RecoveryShareEnvelopeError::InvalidFormat)
        .and_then(|hex_value| {
            hex::decode(hex_value).map_err(|_| RecoveryShareEnvelopeError::InvalidHex)
        })?;
    if parts.next().is_some() {
        return Err(RecoveryShareEnvelopeError::InvalidFormat);
    }
    Ok(RecoveryShareEnvelope {
        set_id,
        threshold,
        share: ShamirShare { index, value },
    })
}

#[cfg(feature = "shamir-sharing")]
pub fn combine_shamir_shares(
    shares: &[ShamirShare],
    threshold: u8,
) -> Result<Vec<u8>, ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::InvalidThreshold);
    }
    if shares.len() < usize::from(threshold) {
        return Err(ShamirError::NotEnoughShares {
            threshold,
            provided: shares.len(),
        });
    }

    let share_len = shares.first().map_or(0, |share| share.value.len());
    let mut seen = BTreeSet::new();
    for share in shares.iter().take(usize::from(threshold)) {
        if share.index == 0 {
            return Err(ShamirError::ZeroShareIndex);
        }
        if !seen.insert(share.index) {
            return Err(ShamirError::DuplicateShareIndex(share.index));
        }
        if share.value.len() != share_len {
            return Err(ShamirError::InconsistentShareLength);
        }
    }

    let selected = &shares[..usize::from(threshold)];
    let mut secret = vec![0_u8; share_len];
    for (byte_index, secret_byte) in secret.iter_mut().enumerate() {
        let mut recovered = 0_u8;
        for (i, share_i) in selected.iter().enumerate() {
            let mut coefficient = 1_u8;
            for (j, share_j) in selected.iter().enumerate() {
                if i == j {
                    continue;
                }
                coefficient = gf_mul(coefficient, share_j.index);
                coefficient = gf_mul(coefficient, gf_inv(share_i.index ^ share_j.index));
            }
            recovered ^= gf_mul(share_i.value[byte_index], coefficient);
        }
        *secret_byte = recovered;
    }
    Ok(secret)
}

#[cfg(feature = "shamir-sharing")]
const fn validate_shamir_parameters(threshold: u8, share_count: u8) -> Result<(), ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::InvalidThreshold);
    }
    if share_count == 0 {
        return Err(ShamirError::InvalidShareCount);
    }
    if threshold > share_count {
        return Err(ShamirError::ThresholdExceedsShareCount {
            threshold,
            share_count,
        });
    }
    Ok(())
}

#[cfg(feature = "shamir-sharing")]
fn evaluate_polynomial(secret_byte: u8, coefficients: &[u8], x: u8) -> u8 {
    coefficients
        .iter()
        .rev()
        .fold(0_u8, |acc, coefficient| gf_mul(acc, x) ^ coefficient)
        .pipe(|tail| gf_mul(tail, x) ^ secret_byte)
}

#[cfg(feature = "shamir-sharing")]
const fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0_u8;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let carry = left & 0x80;
        left <<= 1;
        if carry != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

#[cfg(feature = "shamir-sharing")]
fn gf_inv(value: u8) -> u8 {
    debug_assert_ne!(value, 0);
    gf_pow(value, 254)
}

#[cfg(feature = "shamir-sharing")]
const fn gf_pow(mut value: u8, mut exponent: u16) -> u8 {
    let mut result = 1_u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

#[cfg(feature = "shamir-sharing")]
trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

#[cfg(feature = "shamir-sharing")]
impl<T> Pipe for T {}

pub fn plan_break_glass_recovery(
    set: &RecoveryShareSetMetadataV2,
    provided_share_ids: &[String],
) -> Result<BreakGlassRecoveryPlan, RecoveryShareMetadataError> {
    let unlock = plan_m_of_n_unlock(set, provided_share_ids)?;
    let mut steps = Vec::new();
    if unlock.ready {
        steps.push(
            "combine the provided recovery shares in an offline/trusted environment".to_string(),
        );
        steps.push(
            "unlock the vault payload key using the reconstructed recovery factor".to_string(),
        );
        steps.push("immediately rotate the vault data key after recovery".to_string());
        steps.push("replace the used recovery-share set with fresh shares".to_string());
    } else {
        steps.push(format!(
            "collect {} additional recovery share(s) for set '{}'",
            unlock.missing_share_count, unlock.set_id
        ));
    }

    let mut warnings = vec![
        "break-glass recovery should be treated as emergency access".to_string(),
        "all recovered material must be rotated after use".to_string(),
    ];
    if !unlock.ignored_share_ids.is_empty() {
        warnings.push(format!(
            "ignored unknown recovery share id(s): {}",
            unlock.ignored_share_ids.join(", ")
        ));
    }

    Ok(BreakGlassRecoveryPlan {
        set_id: unlock.set_id,
        ready: unlock.ready,
        steps,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use sshenv_vault_models::{
        RecoveryShareMetadataV2, RecoveryShareSetMetadataV2, ShamirSplitMetadataV2,
    };

    use super::{RecoveryShareMetadataError, validate_recovery_share_set_metadata};

    fn sample_set() -> RecoveryShareSetMetadataV2 {
        RecoveryShareSetMetadataV2 {
            id: "team-recovery".to_string(),
            label: Some("Team recovery".to_string()),
            threshold: 2,
            shares: vec![
                RecoveryShareMetadataV2 {
                    id: "alice".to_string(),
                    label: None,
                    holder: Some("Alice".to_string()),
                    public_identifier: Some("SHA256:alice".to_string()),
                },
                RecoveryShareMetadataV2 {
                    id: "bob".to_string(),
                    label: None,
                    holder: Some("Bob".to_string()),
                    public_identifier: Some("SHA256:bob".to_string()),
                },
                RecoveryShareMetadataV2 {
                    id: "carol".to_string(),
                    label: None,
                    holder: Some("Carol".to_string()),
                    public_identifier: Some("SHA256:carol".to_string()),
                },
            ],
            shamir: Some(ShamirSplitMetadataV2 {
                threshold: 2,
                share_count: 3,
            }),
        }
    }

    #[test]
    fn valid_recovery_share_metadata_passes() {
        validate_recovery_share_set_metadata(&sample_set()).unwrap();
    }

    #[test]
    fn m_of_n_plan_ready_when_threshold_met() {
        let provided = vec!["alice".to_string(), "bob".to_string(), "alice".to_string()];
        let plan = super::plan_m_of_n_unlock(&sample_set(), &provided).unwrap();
        assert!(plan.ready);
        assert_eq!(plan.missing_share_count, 0);
        assert_eq!(plan.provided_share_ids, vec!["alice", "bob"]);
    }

    #[test]
    fn m_of_n_plan_counts_missing_valid_shares() {
        let provided = vec!["alice".to_string(), "unknown".to_string()];
        let plan = super::plan_m_of_n_unlock(&sample_set(), &provided).unwrap();
        assert!(!plan.ready);
        assert_eq!(plan.missing_share_count, 1);
        assert_eq!(plan.provided_share_ids, vec!["alice"]);
        assert_eq!(plan.ignored_share_ids, vec!["unknown"]);
    }

    #[test]
    fn break_glass_plan_requires_rotation_after_recovery() {
        let provided = vec!["alice".to_string(), "bob".to_string()];
        let plan = super::plan_break_glass_recovery(&sample_set(), &provided).unwrap();
        assert!(plan.ready);
        assert!(plan.steps.iter().any(|step| step.contains("rotate")));
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("emergency"))
        );
    }

    #[cfg(feature = "shamir-sharing")]
    #[test]
    fn shamir_roundtrip_recovers_secret_from_threshold_shares() {
        let secret = b"vault-data-key-material";
        let shares = super::split_secret_shamir(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = super::combine_shamir_shares(&shares[1..4], 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "shamir-sharing")]
    #[test]
    fn recovery_share_envelopes_roundtrip_and_combine() {
        let secret = b"vault-data-key-material";
        let shares = super::split_secret_shamir(secret, 2, 3).unwrap();
        let envelopes = shares
            .into_iter()
            .map(|share| super::RecoveryShareEnvelope {
                set_id: "team-recovery".to_string(),
                threshold: 2,
                share,
            })
            .collect::<Vec<_>>();
        let encoded = envelopes
            .iter()
            .map(super::encode_recovery_share_envelope)
            .collect::<Vec<_>>();
        let decoded = encoded
            .iter()
            .map(|value| super::decode_recovery_share_envelope(value).unwrap())
            .collect::<Vec<_>>();

        let recovered = super::combine_recovery_share_envelopes(&decoded[..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "shamir-sharing")]
    #[test]
    fn recovery_share_envelope_rejects_bad_prefix() {
        assert_eq!(
            super::decode_recovery_share_envelope("wrong:set:2:1:abcd"),
            Err(super::RecoveryShareEnvelopeError::UnsupportedVersion)
        );
    }

    #[cfg(feature = "shamir-sharing")]
    #[test]
    fn shamir_rejects_duplicate_share_indices() {
        let secret = b"secret";
        let shares = super::split_secret_shamir(secret, 2, 3).unwrap();
        let duplicate = vec![shares[0].clone(), shares[0].clone()];
        assert_eq!(
            super::combine_shamir_shares(&duplicate, 2),
            Err(super::ShamirError::DuplicateShareIndex(shares[0].index))
        );
    }

    #[cfg(feature = "shamir-sharing")]
    #[test]
    fn shamir_requires_threshold_shares() {
        let secret = b"secret";
        let shares = super::split_secret_shamir(secret, 3, 5).unwrap();
        assert_eq!(
            super::combine_shamir_shares(&shares[..2], 3),
            Err(super::ShamirError::NotEnoughShares {
                threshold: 3,
                provided: 2,
            })
        );
    }

    #[test]
    fn rejects_threshold_above_share_count() {
        let mut set = sample_set();
        set.threshold = 4;
        set.shamir = None;
        assert_eq!(
            validate_recovery_share_set_metadata(&set),
            Err(RecoveryShareMetadataError::ThresholdExceedsShareCount {
                threshold: 4,
                share_count: 3,
            })
        );
    }

    #[test]
    fn rejects_duplicate_share_ids() {
        let mut set = sample_set();
        set.shares[1].id = "alice".to_string();
        assert_eq!(
            validate_recovery_share_set_metadata(&set),
            Err(RecoveryShareMetadataError::DuplicateShareId(
                "alice".to_string()
            ))
        );
    }
}
