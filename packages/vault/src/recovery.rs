use std::collections::BTreeSet;

use sshenv_vault_models::RecoveryShareSetMetadataV2;
use thiserror::Error;

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
