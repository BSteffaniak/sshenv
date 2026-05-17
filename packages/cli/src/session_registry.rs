//! Local plaintext registry for tracked `sshenv run` executions.
//!
//! The registry intentionally stores only orchestration metadata: profile,
//! vault identity, PID, process-start token, timestamp, and command name.
//! It never stores environment variable names or values.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::process::{self, Pid};

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SessionsFile {
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionRecord {
    pub profile: String,
    pub vault: String,
    pub pid: i32,
    pub process_token: String,
    pub started_at_unix_ms: u64,
    pub command: String,
}

impl SessionRecord {
    #[must_use]
    pub fn pid(&self) -> Option<Pid> {
        Pid::try_from(self.pid).ok()
    }

    #[must_use]
    pub fn is_live_verified(&self) -> bool {
        let Some(pid) = self.pid() else {
            return false;
        };
        !self.process_token.is_empty() && process::is_same_process(pid, &self.process_token)
    }
}

pub struct LockedRegistry {
    path: PathBuf,
    _lock: RegistryLock,
    pub data: SessionsFile,
}

impl LockedRegistry {
    /// Remove records whose PID is no longer the exact process recorded.
    #[must_use]
    pub fn gc_stale(&mut self) -> usize {
        let before = self.data.sessions.len();
        self.data.sessions.retain(SessionRecord::is_live_verified);
        before - self.data.sessions.len()
    }

    /// Save the current registry contents atomically.
    pub fn save(&self) -> Result<()> {
        save_registry(&self.path, &self.data)
    }
}

/// Resolve the registry path: `$SSHENV_SESSIONS`, else
/// `~/.sshenv/sessions.toml`.
#[must_use]
pub fn default_sessions_path() -> PathBuf {
    if let Ok(p) = std::env::var("SSHENV_SESSIONS") {
        return PathBuf::from(p);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/sessions.toml"),
        |h| h.join(".sshenv").join("sessions.toml"),
    )
}

/// Convert a vault path into the stable string used for session scoping.
#[must_use]
pub fn vault_id(path: &Path) -> String {
    absolute_or_canonical(path).display().to_string()
}

/// Open, lock, and load the session registry.
///
/// The lock is held until the returned [`LockedRegistry`] is dropped.
pub fn open_locked() -> Result<LockedRegistry> {
    let path = default_sessions_path();
    let lock = RegistryLock::acquire(&lock_path_for(&path))?;
    let data = load_registry(&path)?;
    Ok(LockedRegistry {
        path,
        _lock: lock,
        data,
    })
}

/// Register the current process before it is replaced by `execve`.
///
/// Returns `Ok(false)` when this platform cannot produce a process-start
/// token. In that case callers should skip tracking rather than record an
/// unverifiable PID that could later be unsafe to signal.
pub fn register_current_process(profile: &str, vault_path: &Path, command: &str) -> Result<bool> {
    let Some(process_token) = process::current_process_token() else {
        return Ok(false);
    };

    let mut registry = open_locked()?;
    let _removed = registry.gc_stale();

    let pid_i32: i32 = process::current_pid();
    registry.data.sessions.push(SessionRecord {
        profile: profile.to_string(),
        vault: vault_id(vault_path),
        pid: pid_i32,
        process_token,
        started_at_unix_ms: unix_time_ms(),
        command: command.to_string(),
    });
    registry.save()?;
    Ok(true)
}

fn load_registry(path: &Path) -> Result<SessionsFile> {
    if !path.exists() {
        return Ok(SessionsFile::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read sessions file {}", path.display()))?;
    let parsed: SessionsFile = toml::from_str(&text)
        .with_context(|| format!("failed to parse sessions file {}", path.display()))?;
    Ok(parsed)
}

fn save_registry(path: &Path, registry: &SessionsFile) -> Result<()> {
    let preamble = "\
# sshenv sessions (plaintext, local per-host state). Do not put secrets in
# here. Stale records are garbage-collected by `sshenv sessions list` and
# `sshenv sessions kill`.
";
    let body = toml::to_string_pretty(registry).context("failed to serialize sessions to TOML")?;
    atomic_write_text(path, &format!("{preamble}\n{body}"), 0o600)
}

fn atomic_write_text(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dir {}", parent.display()))?;
    }
    let parent_for_tempfile = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let mut tmp = tempfile::NamedTempFile::new_in(parent_for_tempfile).with_context(|| {
        format!(
            "failed to create temp file in {}",
            parent_for_tempfile.display()
        )
    })?;
    tmp.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write temp file {}", tmp.path().display()))?;
    tmp.as_file_mut().sync_all().ok();

    set_mode_on_file(tmp.as_file(), mode)?;

    tmp.persist(path)
        .with_context(|| format!("failed to persist file at {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_on_file(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .context("failed to chmod sessions file")?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn set_mode_on_file(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

fn lock_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sessions.toml");
    path.with_file_name(format!("{file_name}.lock"))
}

struct RegistryLock {
    #[cfg_attr(not(unix), allow(dead_code))]
    file: File,
}

impl RegistryLock {
    fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create lock dir {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open sessions lock {}", path.display()))?;
        lock_file(&file).with_context(|| format!("failed to lock {}", path.display()))?;
        Ok(Self { file })
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `flock` operates on a valid fd owned by `file`.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("flock failed")
    }
}

#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn lock_file(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
impl Drop for RegistryLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: best-effort unlock of a valid fd during drop.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(not(unix))]
impl Drop for RegistryLock {
    fn drop(&mut self) {}
}

fn absolute_or_canonical(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_id_canonicalizes_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        fs::write(&vault, "x").unwrap();
        assert_eq!(
            vault_id(&vault),
            vault.canonicalize().unwrap().display().to_string()
        );
    }
}
