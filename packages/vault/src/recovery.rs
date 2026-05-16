use std::collections::BTreeSet;

use serde::Serialize;
use sshenv_vault_models::RecoveryShareSetMetadataV2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryUnlockPlan {
    pub set_id: String,
    pub threshold: u8,
    pub provided_share_ids: Vec<String>,
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
    let mut unique_provided = provided_share_ids
        .iter()
        .filter(|id| valid_share_ids.contains(id.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    unique_provided.sort();

    let provided_count = unique_provided.len();
    let threshold = usize::from(set.threshold);
    let missing_share_count = threshold.saturating_sub(provided_count);

    Ok(RecoveryUnlockPlan {
        set_id: set.id.clone(),
        threshold: set.threshold,
        provided_share_ids: unique_provided,
        missing_share_count,
        ready: missing_share_count == 0,
    })
}

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

    Ok(BreakGlassRecoveryPlan {
        set_id: unlock.set_id,
        ready: unlock.ready,
        steps,
        warnings: vec![
            "break-glass recovery should be treated as emergency access".to_string(),
            "all recovered material must be rotated after use".to_string(),
        ],
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
