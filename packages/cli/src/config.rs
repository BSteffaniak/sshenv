//! Runtime configuration for sshenv CLI security behavior.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnencryptedSshKeysPolicy {
    Allow,
    #[default]
    Warn,
    Deny,
}

impl UnencryptedSshKeysPolicy {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassphraseCacheBackend {
    #[default]
    Auto,
    MacosKeychain,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PassphraseCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: PassphraseCacheBackend,
    pub ttl_seconds: Option<u64>,
}

impl Default for PassphraseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: PassphraseCacheBackend::Auto,
            ttl_seconds: Some(300),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub unencrypted_ssh_keys: UnencryptedSshKeysPolicy,
    #[serde(default)]
    pub passphrase_cache: PassphraseCacheConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            unencrypted_ssh_keys: UnencryptedSshKeysPolicy::Warn,
            passphrase_cache: PassphraseCacheConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SshenvConfig {
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Resolve runtime config path: `$SSHENV_CONFIG`, else `~/.sshenv/config.toml`.
#[must_use]
pub fn default_config_path() -> PathBuf {
    if let Ok(path) = std::env::var("SSHENV_CONFIG") {
        return PathBuf::from(path);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/config.toml"),
        |home| home.join(".sshenv").join("config.toml"),
    )
}

/// Load runtime configuration, returning defaults when no config file exists.
///
/// # Errors
///
/// Returns an error when the config file exists but cannot be read or parsed.
pub fn load() -> Result<SshenvConfig> {
    let path = default_config_path();
    if !path.exists() {
        return Ok(SshenvConfig::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
}
