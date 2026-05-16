use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{PassphraseCacheBackend, load as load_config};
use crate::session_registry::vault_id;

const MACOS_KEYCHAIN_SERVICE: &str = "sshenv passphrase cache";
const DEFAULT_TTL_SECONDS: u64 = 300;

#[derive(Debug, Serialize)]
struct CacheEntry<'a> {
    passphrase: &'a str,
    expires_unix: u64,
}

#[derive(Debug, Deserialize)]
struct OwnedCacheEntry {
    passphrase: String,
    expires_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PassphraseCacheStatus {
    pub enabled: bool,
    pub backend: &'static str,
    pub backend_available: bool,
    pub ttl_seconds: u64,
}

pub fn status() -> Result<PassphraseCacheStatus> {
    let config = load_config()?.security.passphrase_cache;
    Ok(PassphraseCacheStatus {
        enabled: config.enabled,
        backend: backend_label(config.backend),
        backend_available: backend_available(config.backend),
        ttl_seconds: config.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS),
    })
}

pub fn get_vault_passphrase(vault_path: &Path) -> Result<Option<Zeroizing<String>>> {
    let config = load_config()?.security.passphrase_cache;
    if !config.enabled {
        return Ok(None);
    }
    match config.backend {
        PassphraseCacheBackend::Auto | PassphraseCacheBackend::MacosKeychain => {
            get_macos_keychain(vault_path)
        }
    }
}

pub fn put_vault_passphrase(vault_path: &Path, passphrase: &str) -> Result<()> {
    if passphrase.is_empty() {
        return Ok(());
    }
    let config = load_config()?.security.passphrase_cache;
    if !config.enabled {
        return Ok(());
    }
    let ttl = config.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let expires_unix = now_unix().saturating_add(ttl);
    match config.backend {
        PassphraseCacheBackend::Auto | PassphraseCacheBackend::MacosKeychain => {
            put_macos_keychain(vault_path, passphrase, expires_unix)
        }
    }
}

pub fn clear_vault_passphrase(vault_path: &Path) -> Result<bool> {
    let config = load_config()?.security.passphrase_cache;
    match config.backend {
        PassphraseCacheBackend::Auto | PassphraseCacheBackend::MacosKeychain => {
            clear_macos_keychain(vault_path)
        }
    }
}

const fn backend_label(backend: PassphraseCacheBackend) -> &'static str {
    match backend {
        PassphraseCacheBackend::Auto | PassphraseCacheBackend::MacosKeychain => "macos-keychain",
    }
}

const fn backend_available(backend: PassphraseCacheBackend) -> bool {
    match backend {
        PassphraseCacheBackend::Auto | PassphraseCacheBackend::MacosKeychain => {
            cfg!(target_os = "macos")
        }
    }
}

fn account(vault_path: &Path) -> String {
    format!("vault:{}", vault_id(vault_path))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn get_macos_keychain(vault_path: &Path) -> Result<Option<Zeroizing<String>>> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/bin/security")
            .arg("find-generic-password")
            .arg("-w")
            .arg("-s")
            .arg(MACOS_KEYCHAIN_SERVICE)
            .arg("-a")
            .arg(account(vault_path))
            .output()
            .context("failed to invoke macOS security command")?;
        if !output.status.success() {
            return Ok(None);
        }
        let raw = String::from_utf8(output.stdout)
            .context("macOS Keychain returned non-UTF8 passphrase cache entry")?;
        let entry: OwnedCacheEntry =
            serde_json::from_str(raw.trim()).context("failed to parse passphrase cache entry")?;
        if entry.expires_unix <= now_unix() {
            let _ = clear_macos_keychain(vault_path);
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(entry.passphrase)))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = vault_path;
        bail!("passphrase cache backend macos-keychain is not available on this platform")
    }
}

fn put_macos_keychain(vault_path: &Path, passphrase: &str, expires_unix: u64) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let entry = CacheEntry {
            passphrase,
            expires_unix,
        };
        let encoded = serde_json::to_string(&entry).context("failed to serialize cache entry")?;
        let output = Command::new("/usr/bin/security")
            .arg("add-generic-password")
            .arg("-U")
            .arg("-s")
            .arg(MACOS_KEYCHAIN_SERVICE)
            .arg("-a")
            .arg(account(vault_path))
            .arg("-w")
            .arg(encoded)
            .output()
            .context("failed to invoke macOS security command")?;
        if output.status.success() {
            Ok(())
        } else {
            bail!(
                "failed to store passphrase cache entry in macOS Keychain: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (vault_path, passphrase, expires_unix);
        bail!("passphrase cache backend macos-keychain is not available on this platform")
    }
}

fn clear_macos_keychain(vault_path: &Path) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/bin/security")
            .arg("delete-generic-password")
            .arg("-s")
            .arg(MACOS_KEYCHAIN_SERVICE)
            .arg("-a")
            .arg(account(vault_path))
            .output()
            .context("failed to invoke macOS security command")?;
        Ok(output.status.success())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = vault_path;
        bail!("passphrase cache backend macos-keychain is not available on this platform")
    }
}
