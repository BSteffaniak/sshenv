use std::path::Path;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::config::{PassphraseCacheBackend, load as load_config};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::session_registry::vault_id;

#[cfg(target_os = "macos")]
const MACOS_KEYCHAIN_SERVICE: &str = "sshenv passphrase cache";
const DEFAULT_TTL_SECONDS: u64 = 300;

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug, Serialize)]
struct CacheEntry<'a> {
    passphrase: &'a str,
    expires_unix: u64,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
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
        PassphraseCacheBackend::Auto => get_auto_backend(vault_path),
        PassphraseCacheBackend::MacosKeychain => get_macos_keychain(vault_path),
        PassphraseCacheBackend::WindowsDpapi => get_windows_dpapi(vault_path),
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
        PassphraseCacheBackend::Auto => put_auto_backend(vault_path, passphrase, expires_unix),
        PassphraseCacheBackend::MacosKeychain => {
            put_macos_keychain(vault_path, passphrase, expires_unix)
        }
        PassphraseCacheBackend::WindowsDpapi => {
            put_windows_dpapi(vault_path, passphrase, expires_unix)
        }
    }
}

pub fn clear_vault_passphrase(vault_path: &Path) -> Result<bool> {
    let config = load_config()?.security.passphrase_cache;
    match config.backend {
        PassphraseCacheBackend::Auto => clear_auto_backend(vault_path),
        PassphraseCacheBackend::MacosKeychain => clear_macos_keychain(vault_path),
        PassphraseCacheBackend::WindowsDpapi => clear_windows_dpapi(vault_path),
    }
}

const fn backend_label(backend: PassphraseCacheBackend) -> &'static str {
    match backend {
        PassphraseCacheBackend::Auto => auto_backend_label(),
        PassphraseCacheBackend::MacosKeychain => "macos-keychain",
        PassphraseCacheBackend::WindowsDpapi => "windows-dpapi",
    }
}

const fn auto_backend_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos-keychain"
    } else if cfg!(target_os = "windows") {
        "windows-dpapi"
    } else {
        "unavailable"
    }
}

const fn backend_available(backend: PassphraseCacheBackend) -> bool {
    match backend {
        PassphraseCacheBackend::Auto => cfg!(any(target_os = "macos", target_os = "windows")),
        PassphraseCacheBackend::MacosKeychain => cfg!(target_os = "macos"),
        PassphraseCacheBackend::WindowsDpapi => cfg!(target_os = "windows"),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn account(vault_path: &Path) -> String {
    format!("vault:{}", vault_id(vault_path))
}

fn get_auto_backend(vault_path: &Path) -> Result<Option<Zeroizing<String>>> {
    #[cfg(target_os = "macos")]
    return get_macos_keychain(vault_path);
    #[cfg(target_os = "windows")]
    return get_windows_dpapi(vault_path);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = vault_path;
        bail!("passphrase cache auto backend is not available on this platform")
    }
}

fn put_auto_backend(vault_path: &Path, passphrase: &str, expires_unix: u64) -> Result<()> {
    #[cfg(target_os = "macos")]
    return put_macos_keychain(vault_path, passphrase, expires_unix);
    #[cfg(target_os = "windows")]
    return put_windows_dpapi(vault_path, passphrase, expires_unix);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (vault_path, passphrase, expires_unix);
        bail!("passphrase cache auto backend is not available on this platform")
    }
}

fn clear_auto_backend(vault_path: &Path) -> Result<bool> {
    #[cfg(target_os = "macos")]
    return clear_macos_keychain(vault_path);
    #[cfg(target_os = "windows")]
    return clear_windows_dpapi(vault_path);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = vault_path;
        bail!("passphrase cache auto backend is not available on this platform")
    }
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

fn get_windows_dpapi(vault_path: &Path) -> Result<Option<Zeroizing<String>>> {
    #[cfg(target_os = "windows")]
    {
        let path = windows_dpapi_cache_path(vault_path);
        if !path.exists() {
            return Ok(None);
        }
        let protected_hex = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read passphrase cache {}", path.display()))?;
        let protected = hex::decode(protected_hex.trim())
            .context("Windows DPAPI passphrase cache entry is not valid hex")?;
        let plaintext = dpapi_unprotect(&protected)?;
        let raw = String::from_utf8(plaintext)
            .context("Windows DPAPI passphrase cache entry is not UTF-8")?;
        let entry: OwnedCacheEntry = serde_json::from_str(raw.trim())
            .context("failed to parse Windows DPAPI passphrase cache entry")?;
        if entry.expires_unix <= now_unix() {
            let _ = clear_windows_dpapi(vault_path);
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(entry.passphrase)))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = vault_path;
        bail!("passphrase cache backend windows-dpapi is not available on this platform")
    }
}

fn put_windows_dpapi(vault_path: &Path, passphrase: &str, expires_unix: u64) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let entry = CacheEntry {
            passphrase,
            expires_unix,
        };
        let encoded = serde_json::to_vec(&entry).context("failed to serialize cache entry")?;
        let protected = dpapi_protect(&encoded, "sshenv passphrase cache")?;
        sshenv_vault::atomic_write(
            &windows_dpapi_cache_path(vault_path),
            format!("{}\n", hex::encode(protected)).as_bytes(),
            0o600,
        )
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (vault_path, passphrase, expires_unix);
        bail!("passphrase cache backend windows-dpapi is not available on this platform")
    }
}

fn clear_windows_dpapi(vault_path: &Path) -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        let path = windows_dpapi_cache_path(vault_path);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove passphrase cache {}", path.display()))?;
        Ok(true)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = vault_path;
        bail!("passphrase cache backend windows-dpapi is not available on this platform")
    }
}

#[cfg(target_os = "windows")]
fn windows_dpapi_cache_path(vault_path: &Path) -> PathBuf {
    let file_name = hex::encode(vault_id(vault_path).as_bytes());
    sshenv_cache_dir().join("passphrase-cache").join(file_name)
}

#[cfg(target_os = "windows")]
fn sshenv_cache_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .map_or_else(|| PathBuf::from(".sshenv"), |base| base.join("sshenv"))
}

#[cfg(target_os = "windows")]
fn dpapi_protect(plaintext: &[u8], description: &str) -> Result<Vec<u8>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plaintext.len()).context("DPAPI plaintext too large")?,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let description: Vec<u16> = OsStr::new(description)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: All pointers are valid for the duration of the call; output is freed with LocalFree.
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            description.as_ptr(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to protect passphrase cache with DPAPI");
    }
    let output_guard = LocalAllocGuard(output.pbData.cast());
    // SAFETY: DPAPI returned `cbData` bytes at `pbData` on success.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            output.pbData,
            usize::try_from(output.cbData).context("DPAPI output length too large")?,
        )
    }
    .to_vec();
    drop(output_guard);
    Ok(bytes)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).context("DPAPI ciphertext too large")?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: All pointers are valid for the duration of the call; output is freed with LocalFree.
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to unprotect passphrase cache with DPAPI");
    }
    let output_guard = LocalAllocGuard(output.pbData.cast());
    // SAFETY: DPAPI returned `cbData` bytes at `pbData` on success.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            output.pbData,
            usize::try_from(output.cbData).context("DPAPI output length too large")?,
        )
    }
    .to_vec();
    drop(output_guard);
    Ok(bytes)
}

#[cfg(target_os = "windows")]
struct LocalAllocGuard(windows_sys::Win32::Foundation::HLOCAL);

#[cfg(target_os = "windows")]
impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}
