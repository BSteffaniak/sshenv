use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sshenv_vault_models::{RemoteFactorBackendKindV2, RemoteFactorMetadataV2};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFactorRequest {
    pub factor_id: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub struct CommandRemoteFactorBackend {
    metadata: RemoteFactorMetadataV2,
    command: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct CommandRemoteFactorInput<'a> {
    operation: &'a str,
    request: &'a RemoteFactorRequest,
    payload_key_hex: Option<String>,
    wrapped_key_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CommandRemoteFactorUnwrapOutput {
    payload_key_hex: String,
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

impl CommandRemoteFactorBackend {
    pub fn from_metadata(metadata: RemoteFactorMetadataV2) -> Result<Self, RemoteFactorError> {
        validate_remote_factor_metadata(&metadata).map_err(RemoteFactorError::InvalidRequest)?;
        let command = metadata
            .params
            .get("command")
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .ok_or_else(|| {
                RemoteFactorError::Unavailable(
                    "command-backed remote factor requires non-secret `command` param".to_string(),
                )
            })?;
        Ok(Self { metadata, command })
    }

    fn invoke<I: Serialize, O: for<'de> Deserialize<'de>>(
        &self,
        input: &I,
    ) -> Result<O, RemoteFactorError> {
        let encoded = serde_json::to_vec(input).map_err(|error| {
            RemoteFactorError::InvalidRequest(format!(
                "failed to serialize command remote request: {error}"
            ))
        })?;
        let mut child = Command::new(&self.command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| {
                RemoteFactorError::Unavailable(format!(
                    "failed to invoke command-backed remote factor '{}': {error}",
                    self.command
                ))
            })?;
        {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                RemoteFactorError::Unavailable(
                    "failed to open command-backed remote factor stdin".to_string(),
                )
            })?;
            stdin.write_all(&encoded).map_err(|error| {
                RemoteFactorError::Unavailable(format!(
                    "failed to write command-backed remote factor request: {error}"
                ))
            })?;
        }
        let output = child.wait_with_output().map_err(|error| {
            RemoteFactorError::Unavailable(format!(
                "failed to wait for command-backed remote factor: {error}"
            ))
        })?;
        if !output.status.success() {
            return Err(RemoteFactorError::Denied(format!(
                "command-backed remote factor exited unsuccessfully: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        serde_json::from_slice(&output.stdout).map_err(|error| {
            RemoteFactorError::InvalidResponse(format!(
                "command-backed remote factor returned invalid JSON: {error}"
            ))
        })
    }
}

impl RemoteFactorBackend for CommandRemoteFactorBackend {
    fn kind(&self) -> RemoteFactorBackendKindV2 {
        self.metadata.backend
    }

    fn metadata(&self) -> RemoteFactorMetadataV2 {
        self.metadata.clone()
    }

    fn wrap_payload_key(
        &self,
        request: &RemoteFactorRequest,
        payload_key: &[u8],
    ) -> Result<RemoteFactorResponse, RemoteFactorError> {
        validate_remote_factor_request(&self.metadata, request)?;
        self.invoke(&CommandRemoteFactorInput {
            operation: "wrap",
            request,
            payload_key_hex: Some(hex::encode(payload_key)),
            wrapped_key_hex: None,
        })
    }

    fn unwrap_payload_key(
        &self,
        request: &RemoteFactorRequest,
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, RemoteFactorError> {
        validate_remote_factor_request(&self.metadata, request)?;
        let output: CommandRemoteFactorUnwrapOutput = self.invoke(&CommandRemoteFactorInput {
            operation: "unwrap",
            request,
            payload_key_hex: None,
            wrapped_key_hex: Some(hex::encode(wrapped_key)),
        })?;
        hex::decode(output.payload_key_hex).map_err(|error| {
            RemoteFactorError::InvalidResponse(format!(
                "command-backed remote factor returned invalid payload key hex: {error}"
            ))
        })
    }
}

pub fn validate_remote_factor_request(
    metadata: &RemoteFactorMetadataV2,
    request: &RemoteFactorRequest,
) -> Result<(), RemoteFactorError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    validate_remote_factor_request_at(metadata, request, now_unix)
}

pub fn validate_remote_factor_request_at(
    metadata: &RemoteFactorMetadataV2,
    request: &RemoteFactorRequest,
    now_unix: u64,
) -> Result<(), RemoteFactorError> {
    if request.factor_id != metadata.id {
        return Err(RemoteFactorError::InvalidRequest(format!(
            "request factor id '{}' does not match metadata id '{}'",
            request.factor_id, metadata.id
        )));
    }
    require_context(&request.context, "vault-id")?;
    require_context(&request.context, "request-id")?;
    require_u64_context(&request.context, "generation")?;
    let expires_unix = require_u64_context(&request.context, "expires-unix")?;
    if expires_unix <= now_unix {
        return Err(RemoteFactorError::InvalidRequest(format!(
            "request expired at {expires_unix}; current time is {now_unix}"
        )));
    }

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

fn require_u64_context(
    context: &BTreeMap<String, String>,
    key: &str,
) -> Result<u64, RemoteFactorError> {
    require_context(context, key)?;
    let value = context.get(key).expect("context key checked above");
    value.trim().parse::<u64>().map_err(|_| {
        RemoteFactorError::InvalidRequest(format!(
            "request context `{key}` must be an unsigned integer"
        ))
    })
}

pub fn validate_remote_factor_metadata(metadata: &RemoteFactorMetadataV2) -> Result<(), String> {
    if metadata.id.trim().is_empty() {
        return Err("remote factor id is empty".to_string());
    }

    match metadata.backend {
        RemoteFactorBackendKindV2::SelfHosted | RemoteFactorBackendKindV2::OidcApproval => {
            if metadata.params.contains_key("command") {
                require_non_empty_metadata_param(metadata, "command")?;
            } else {
                let url = require_non_empty_metadata_param(metadata, "url")?;
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(
                        "remote factor `url` param must start with http:// or https://".to_string(),
                    );
                }
            }
        }
        RemoteFactorBackendKindV2::CloudKms => {
            require_non_empty_metadata_param(metadata, "key")?;
        }
    }

    Ok(())
}

fn require_non_empty_metadata_param<'a>(
    metadata: &'a RemoteFactorMetadataV2,
    key: &str,
) -> Result<&'a str, String> {
    let Some(value) = metadata.params.get(key) else {
        return match metadata.backend {
            RemoteFactorBackendKindV2::CloudKms if key == "key" => {
                Err("cloud KMS factor requires non-secret `key` param".to_string())
            }
            _ => Err(format!("remote factor requires non-secret `{key}` param")),
        };
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("remote factor `{key}` param must not be empty"));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sshenv_vault_models::{RemoteFactorBackendKindV2, RemoteFactorMetadataV2};

    use super::{
        RemoteFactorError, RemoteFactorRequest, validate_remote_factor_metadata,
        validate_remote_factor_request, validate_remote_factor_request_at,
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
        validate_remote_factor_request_at(&metadata, &request, 100).unwrap();
    }

    #[test]
    fn rejects_expired_request_context() {
        let mut params = BTreeMap::new();
        params.insert("key".to_string(), "alias/sshenv".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "kms".to_string(),
            backend: RemoteFactorBackendKindV2::CloudKms,
            label: None,
            params,
        };
        let request = RemoteFactorRequest {
            factor_id: "kms".to_string(),
            context: BTreeMap::from([
                ("vault-id".to_string(), "vault".to_string()),
                ("request-id".to_string(), "req".to_string()),
                ("generation".to_string(), "7".to_string()),
                ("expires-unix".to_string(), "123".to_string()),
                ("encryption-context".to_string(), "sshenv:vault".to_string()),
            ]),
        };
        assert!(matches!(
            validate_remote_factor_request_at(&metadata, &request, 123),
            Err(RemoteFactorError::InvalidRequest(message)) if message.contains("expired")
        ));
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
    fn rejects_non_numeric_generation_context() {
        let mut params = BTreeMap::new();
        params.insert("url".to_string(), "https://unlock.example".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "remote".to_string(),
            backend: RemoteFactorBackendKindV2::SelfHosted,
            label: None,
            params,
        };
        let request = RemoteFactorRequest {
            factor_id: "remote".to_string(),
            context: BTreeMap::from([
                ("vault-id".to_string(), "vault".to_string()),
                ("request-id".to_string(), "req".to_string()),
                ("generation".to_string(), "not-a-number".to_string()),
                ("expires-unix".to_string(), "123".to_string()),
                ("client-id".to_string(), "client".to_string()),
            ]),
        };
        assert!(matches!(
            validate_remote_factor_request(&metadata, &request),
            Err(RemoteFactorError::InvalidRequest(message))
                if message.contains("generation") && message.contains("unsigned integer")
        ));
    }

    #[test]
    fn rejects_empty_url_param() {
        let mut params = BTreeMap::new();
        params.insert("url".to_string(), "  ".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "remote".to_string(),
            backend: RemoteFactorBackendKindV2::SelfHosted,
            label: None,
            params,
        };
        assert_eq!(
            validate_remote_factor_metadata(&metadata),
            Err("remote factor `url` param must not be empty".to_string())
        );
    }

    #[test]
    fn rejects_non_http_url_param() {
        let mut params = BTreeMap::new();
        params.insert("url".to_string(), "unlock.example".to_string());
        let metadata = RemoteFactorMetadataV2 {
            id: "remote".to_string(),
            backend: RemoteFactorBackendKindV2::OidcApproval,
            label: None,
            params,
        };
        assert_eq!(
            validate_remote_factor_metadata(&metadata),
            Err("remote factor `url` param must start with http:// or https://".to_string())
        );
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
