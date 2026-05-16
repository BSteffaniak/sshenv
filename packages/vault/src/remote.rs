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
    #[error("remote factor request is invalid: {0}")]
    InvalidRequest(String),
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

pub fn validate_remote_factor_request(
    metadata: &RemoteFactorMetadataV2,
    request: &RemoteFactorRequest,
) -> Result<(), RemoteFactorError> {
    if request.factor_id != metadata.id {
        return Err(RemoteFactorError::InvalidRequest(format!(
            "request factor id '{}' does not match metadata id '{}'",
            request.factor_id, metadata.id
        )));
    }
    require_context(&request.context, "vault-id")?;
    require_context(&request.context, "request-id")?;
    require_context(&request.context, "generation")?;
    require_context(&request.context, "expires-unix")?;

    match metadata.backend {
        RemoteFactorBackendKindV2::SelfHosted => {
            require_context(&request.context, "client-id")?;
        }
        RemoteFactorBackendKindV2::CloudKms => {
            require_context(&request.context, "encryption-context")?;
        }
        RemoteFactorBackendKindV2::OidcApproval => {
            require_context(&request.context, "subject")?;
            require_context(&request.context, "audience")?;
        }
    }

    Ok(())
}

fn require_context(context: &BTreeMap<String, String>, key: &str) -> Result<(), RemoteFactorError> {
    if context
        .get(key)
        .is_some_and(|value| !value.trim().is_empty())
    {
        Ok(())
    } else {
        Err(RemoteFactorError::InvalidRequest(format!(
            "missing request context `{key}`"
        )))
    }
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

    use super::{
        RemoteFactorError, RemoteFactorRequest, validate_remote_factor_metadata,
        validate_remote_factor_request,
    };

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
    fn validates_oidc_request_context() {
        let mut params = BTreeMap::new();
        params.insert("url".to_string(), "https://approval.example".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "oidc".to_string(),
            backend: RemoteFactorBackendKindV2::OidcApproval,
            label: None,
            params,
        };
        let request = RemoteFactorRequest {
            factor_id: "oidc".to_string(),
            context: BTreeMap::from([
                ("vault-id".to_string(), "vault".to_string()),
                ("request-id".to_string(), "req".to_string()),
                ("generation".to_string(), "7".to_string()),
                ("expires-unix".to_string(), "123".to_string()),
                ("subject".to_string(), "user@example".to_string()),
                ("audience".to_string(), "sshenv".to_string()),
            ]),
        };
        validate_remote_factor_request(&metadata, &request).unwrap();
    }

    #[test]
    fn rejects_request_for_wrong_factor() {
        let mut params = BTreeMap::new();
        params.insert("key".to_string(), "alias/sshenv".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "kms".to_string(),
            backend: RemoteFactorBackendKindV2::CloudKms,
            label: None,
            params,
        };
        let request = RemoteFactorRequest {
            factor_id: "other".to_string(),
            context: BTreeMap::new(),
        };
        assert!(matches!(
            validate_remote_factor_request(&metadata, &request),
            Err(RemoteFactorError::InvalidRequest(message)) if message.contains("does not match")
        ));
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
