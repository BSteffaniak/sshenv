//! Shim script generation + bindings file I/O.
//!
//! The bindings file (default: `~/.sshenv/bindings.toml`) is local
//! per-host plaintext state: a list of profile/command pairs plus an
//! optional shim-directory override.
//!
//! Shim scripts (default: `~/.sshenv/bin/<command>`) are tiny `sh`
//! scripts that exec `sshenv run <profile> -- <command> "$@"`.

#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use sshenv_shims_models::{Binding, BindingsFile};

pub use sshenv_shims_models as models;

/// Resolve the default bindings-file path: `$SSHENV_BINDINGS`, else
/// `~/.sshenv/bindings.toml`.
#[must_use]
pub fn default_bindings_path() -> PathBuf {
    if let Ok(p) = std::env::var("SSHENV_BINDINGS") {
        return PathBuf::from(p);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/bindings.toml"),
        |h| h.join(".sshenv").join("bindings.toml"),
    )
}

/// Resolve the shim output directory.
///
/// Priority: explicit value on the bindings file, then `$SSHENV_SHIM_DIR`,
/// then `~/.sshenv/bin`.
#[must_use]
pub fn resolve_shim_dir(bindings: &BindingsFile) -> PathBuf {
    if let Some(dir) = &bindings.shim_dir {
        return shellexpand_tilde(dir);
    }
    if let Ok(dir) = std::env::var("SSHENV_SHIM_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir().map_or_else(
        || PathBuf::from(".sshenv/bin"),
        |h| h.join(".sshenv").join("bin"),
    )
}

/// Load a bindings file from disk. If the file does not exist, returns a
/// default (empty) `BindingsFile`.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed.
pub fn load_bindings(path: &Path) -> Result<BindingsFile> {
    if !path.exists() {
        return Ok(BindingsFile::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read bindings file {}", path.display()))?;
    let parsed: BindingsFile = toml::from_str(&text)
        .with_context(|| format!("failed to parse bindings file {}", path.display()))?;
    Ok(parsed)
}

/// Save a bindings file to disk atomically with mode `0644`.
///
/// # Errors
///
/// Returns an error if serialization or filesystem operations fail.
pub fn save_bindings(path: &Path, bindings: &BindingsFile) -> Result<()> {
    let preamble = "\
# sshenv bindings (plaintext, local per-host state). Do not put secrets in
# here. Shim files at the configured shim_dir are regenerated from this
# file by `sshenv shims sync`.
";
    let body = toml::to_string_pretty(bindings).context("failed to serialize bindings to TOML")?;
    let combined = format!("{preamble}\n{body}");
    atomic_write_text(path, &combined, 0o644)
}

/// Generate the script body for one shim.
#[must_use]
pub fn render_shim_script(binding: &Binding) -> String {
    format!(
        "#!/bin/sh\n\
# Managed by sshenv; do not edit. Regenerate via `sshenv shims sync`.\n\
# profile: {profile}\n\
# command: {command}\n\
exec sshenv run \"{profile}\" -- \"{command}\" \"$@\"\n",
        profile = binding.profile,
        command = binding.command,
    )
}

/// Write all shims in `bindings.bindings` to `shim_dir`, removing any
/// stale managed shims that no longer have a matching binding.
///
/// A "managed" shim is one whose content starts with the
/// `# Managed by sshenv;` marker comment. Unrelated files in the shim
/// directory are left alone.
///
/// Returns `(written_count, removed_count)`.
///
/// # Errors
///
/// Returns an error if the shim directory cannot be created or any
/// shim file cannot be written, chmodded, or removed.
pub fn sync_shims(shim_dir: &Path, bindings: &BindingsFile) -> Result<(usize, usize)> {
    fs::create_dir_all(shim_dir)
        .with_context(|| format!("failed to create shim dir {}", shim_dir.display()))?;

    let mut wanted_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let mut written = 0_usize;
    for binding in &bindings.bindings {
        validate_command_name(&binding.command)?;
        wanted_names.insert(binding.command.clone());
        let target = shim_dir.join(&binding.command);
        let script = render_shim_script(binding);
        atomic_write_text(&target, &script, 0o755)?;
        written += 1;
    }

    let mut removed = 0_usize;
    for entry in fs::read_dir(shim_dir)
        .with_context(|| format!("failed to read shim dir {}", shim_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to iterate shim dir {}", shim_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat shim dir entry {}", entry.path().display()))?;
        if !file_type.is_file() {
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if wanted_names.contains(&name) {
            continue;
        }
        // Only delete files that we recognize as sshenv-managed shims.
        let path = entry.path();
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        if is_managed_shim(&contents) {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove stale shim {}", path.display()))?;
            removed += 1;
        }
    }

    Ok((written, removed))
}

fn is_managed_shim(contents: &str) -> bool {
    contents.lines().any(|l| l.contains("Managed by sshenv;"))
}

/// Reject command names that would be ambiguous or unsafe on a filesystem.
fn validate_command_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("command name is empty"));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(anyhow!(
            "command name '{name}' contains path separators or NUL"
        ));
    }
    if name == "." || name == ".." {
        return Err(anyhow!("command name '{name}' is not allowed"));
    }
    Ok(())
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
fn set_mode_on_file(file: &fs::File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .context("failed to chmod")?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_on_file(_file: &fs::File, _mode: u32) -> Result<()> {
    Ok(())
}

fn shellexpand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");
        let f = load_bindings(&path).unwrap();
        assert!(f.bindings.is_empty());
        assert!(f.shim_dir.is_none());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bindings.toml");

        let mut f = BindingsFile::default();
        f.add("p1", "cmd-a").unwrap();
        f.add("p1", "cmd-b").unwrap();
        f.add("p2", "cmd-c").unwrap();

        save_bindings(&path, &f).unwrap();
        let loaded = load_bindings(&path).unwrap();
        assert_eq!(loaded.bindings.len(), 3);
        assert_eq!(loaded.find_by_command("cmd-a").unwrap().profile, "p1");
        assert_eq!(loaded.find_by_command("cmd-c").unwrap().profile, "p2");
    }

    #[test]
    fn render_shim_script_shape() {
        let b = Binding {
            profile: "pi-bedrock".into(),
            command: "pi-bedrock".into(),
        };
        let s = render_shim_script(&b);
        assert!(s.starts_with("#!/bin/sh\n"));
        assert!(s.contains("profile: pi-bedrock"));
        assert!(s.contains("command: pi-bedrock"));
        assert!(s.contains("exec sshenv run \"pi-bedrock\" -- \"pi-bedrock\" \"$@\""));
    }

    #[test]
    fn sync_writes_new_shims_and_removes_stale_managed() {
        let dir = tempfile::tempdir().unwrap();
        let shim_dir = dir.path().join("bin");

        let mut f = BindingsFile::default();
        f.add("p1", "a").unwrap();
        f.add("p1", "b").unwrap();
        let (w, r) = sync_shims(&shim_dir, &f).unwrap();
        assert_eq!(w, 2);
        assert_eq!(r, 0);
        assert!(shim_dir.join("a").exists());
        assert!(shim_dir.join("b").exists());

        // Unbind b, sync again: b should be removed.
        f.remove_by_command("b");
        let (w, r) = sync_shims(&shim_dir, &f).unwrap();
        assert_eq!(w, 1);
        assert_eq!(r, 1);
        assert!(shim_dir.join("a").exists());
        assert!(!shim_dir.join("b").exists());
    }

    #[test]
    fn sync_leaves_foreign_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        let shim_dir = dir.path().join("bin");
        fs::create_dir_all(&shim_dir).unwrap();
        let foreign = shim_dir.join("not-ours");
        fs::write(&foreign, "#!/bin/sh\necho hi\n").unwrap();

        let f = BindingsFile::default();
        let (_, r) = sync_shims(&shim_dir, &f).unwrap();
        assert_eq!(r, 0);
        assert!(foreign.exists());
    }

    #[test]
    fn validate_command_name_rejects_path_separators() {
        assert!(validate_command_name("ok").is_ok());
        assert!(validate_command_name("").is_err());
        assert!(validate_command_name("a/b").is_err());
        assert!(validate_command_name("a\\b").is_err());
        assert!(validate_command_name(".").is_err());
        assert!(validate_command_name("..").is_err());
    }
}
