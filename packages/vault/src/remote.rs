use std::collections::BTreeMap;

use sshenv_vault_models::{RemoteFactorBackendKindV2, RemoteFactorMetadataV2};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFactorRequest {
    pub factor_id: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFactorResponse {
    pub wrapped_key: Vec<u8>,
    pub audit_id: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteFactorError {
    #[error("remote factor backend is unavailable: {0}")]
    Unavailable(String),
    #[error("remote factor request was denied: {0}")]
    Denied(String),
    #[error("remote factor response was invalid: {0}")]
    InvalidResponse(String),
}

pub trait RemoteFactorBackend {
    fn kind(&self) -> RemoteFactorBackendKindV2;

    fn metadata(&self) -> RemoteFactorMetadataV2;

    fn wrap_payload_key(
        &self,
        request: &RemoteFactorRequest,
        payload_key: &[u8],
    ) -> Result<RemoteFactorResponse, RemoteFactorError>;

    fn unwrap_payload_key(
        &self,
        request: &RemoteFactorRequest,
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, RemoteFactorError>;
}

pub fn validate_remote_factor_metadata(metadata: &RemoteFactorMetadataV2) -> Result<(), String> {
    if metadata.id.trim().is_empty() {
        return Err("remote factor id is empty".to_string());
    }

    match metadata.backend {
        RemoteFactorBackendKindV2::SelfHosted | RemoteFactorBackendKindV2::OidcApproval => {
            if !metadata.params.contains_key("url") {
                return Err("remote factor requires non-secret `url` param".to_string());
            }
        }
        RemoteFactorBackendKindV2::CloudKms => {
            if !metadata.params.contains_key("key") {
                return Err("cloud KMS factor requires non-secret `key` param".to_string());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sshenv_vault_models::{RemoteFactorBackendKindV2, RemoteFactorMetadataV2};

    use super::validate_remote_factor_metadata;

    #[test]
    fn validates_self_hosted_url_param() {
        let mut params = BTreeMap::new();
        params.insert("url".to_string(), "https://unlock.example".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "prod-unlock".to_string(),
            backend: RemoteFactorBackendKindV2::SelfHosted,
            label: Some("prod unlock".to_string()),
            params,
        };
        validate_remote_factor_metadata(&metadata).unwrap();
    }

    #[test]
    fn rejects_cloud_kms_without_key_param() {
        let metadata = RemoteFactorMetadataV2 {
            id: "kms".to_string(),
            backend: RemoteFactorBackendKindV2::CloudKms,
            label: None,
            params: BTreeMap::new(),
        };
        assert_eq!(
            validate_remote_factor_metadata(&metadata),
            Err("cloud KMS factor requires non-secret `key` param".to_string())
        );
    }
}
