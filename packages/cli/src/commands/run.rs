use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sshenv_cli_models::RunArgs;
use sshenv_shims::{load_bindings_merged, resolve_shim_dir};

use crate::commands::{Context as CmdContext, load_and_unlock_profile};
use crate::session_registry;

pub fn run(ctx: &CmdContext, args: RunArgs) -> Result<()> {
    #[cfg(feature = "runtime-hardening")]
    apply_runtime_hardening()?;

    if args.command.is_empty() {
        bail!("no command provided; usage: sshenv run <profile> -- <cmd> [args...]");
    }

    let (vault, _key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;

    let Some(vars) = vault.profiles.get(&args.profile) else {
        bail!("no such profile: {}", args.profile);
    };
    crate::commands::security::ensure_profile_factor_requirements_met(&vault, &args.profile)?;
    crate::commands::security::warn_if_profile_policy_unmet(&vault, &args.profile);

    // Build the child's command.
    let (cmd_name, cmd_args) = args
        .command
        .split_first()
        .expect("not empty, checked above");

    // Resolve the target by walking PATH, skipping the sshenv shim directory.
    // This prevents infinite loops where a shim at `~/.sshenv/bin/pi-bedrock`
    // would re-invoke itself: the shell finds the shim first (because the
    // shim dir is at the front of PATH), the shim calls `sshenv run ... --
    // pi-bedrock`, and without this filter `Command::new("pi-bedrock")`
    // would again hit the shim.
    let shim_dir = current_shim_dir();
    let target = resolve_command_skipping_shim_dir(cmd_name, &shim_dir)?;

    if !args.incognito {
        let tracked = session_registry::register_current_process(
            &args.profile,
            &ctx.vault_path,
            Path::new(cmd_name)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(cmd_name),
        )
        .context("failed to record tracked session; use --incognito to run without tracking")?;
        if !tracked {
            eprintln!(
                "warning: this platform cannot safely verify process identity; running untracked"
            );
        }
    }

    let mut child = Command::new(&target);
    child.args(cmd_args);
    if args.clean_env {
        child.env_clear();
    }
    for (k, v) in vars {
        child.env(k, v);
    }

    // On Unix we prefer `exec`: replace this process entirely so nothing
    // about sshenv remains in the chain. On non-Unix we spawn + wait.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = child.exec();
        // exec only returns on failure.
        Err(err).with_context(|| format!("failed to exec {}", target.display()))?;
        unreachable!()
    }

    #[cfg(not(unix))]
    {
        let status = child
            .status()
            .with_context(|| format!("failed to spawn {}", target.display()))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Determine the currently-configured sshenv shim directory by reading the
/// bindings file (or falling back to `$SSHENV_SHIM_DIR` / `~/.sshenv/bin`).
fn current_shim_dir() -> PathBuf {
    let bindings = load_bindings_merged().unwrap_or_default();
    resolve_shim_dir(&bindings)
}

/// Resolve `cmd` to an executable path, excluding the sshenv shim directory
/// from the PATH search. This is the production entry point; see
/// [`resolve_command_skipping_shim_dir_in`] for a testable variant.
fn resolve_command_skipping_shim_dir(cmd: &str, shim_dir: &Path) -> Result<PathBuf> {
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    #[cfg(windows)]
    let path_ext = std::env::var_os("PATHEXT").unwrap_or_default();
    #[cfg(windows)]
    let path_ext = path_ext.as_os_str();
    #[cfg(not(windows))]
    let path_ext = OsStr::new("");
    resolve_command_skipping_shim_dir_in(cmd, shim_dir, path_env.as_os_str(), path_ext)
}

/// Test-friendly variant: takes PATH and PATHEXT explicitly so tests don't
/// need to mutate the process environment.
fn resolve_command_skipping_shim_dir_in(
    cmd: &str,
    shim_dir: &Path,
    path_env: &OsStr,
    path_ext: &OsStr,
) -> Result<PathBuf> {
    // Pass-through: if the command name is an absolute or relative path,
    // don't do a PATH lookup. Matches execvp/CreateProcess-style explicit
    // path semantics.
    if command_has_path_component(cmd) {
        return Ok(PathBuf::from(cmd));
    }

    let canon_shim = shim_dir.canonicalize().ok();

    let mut found_outside_shim_dir = false;

    for dir in std::env::split_paths(path_env) {
        let is_shim_dir = matches!(
            (&canon_shim, dir.canonicalize().ok()),
            (Some(a), Some(b)) if a == &b
        );
        if is_shim_dir {
            continue;
        }
        found_outside_shim_dir = true;
        for candidate in command_candidates(&dir, cmd, path_ext) {
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
    }

    if found_outside_shim_dir {
        bail!("command '{cmd}' not found on PATH");
    }
    bail!(
        "command '{cmd}' not found on PATH outside the shim directory ({}). \
         Aborting to prevent infinite shim recursion.",
        shim_dir.display()
    );
}

#[cfg(windows)]
fn command_has_path_component(cmd: &str) -> bool {
    cmd.contains('/') || cmd.contains('\\') || Path::new(cmd).is_absolute()
}

#[cfg(not(windows))]
fn command_has_path_component(cmd: &str) -> bool {
    cmd.contains('/')
}

#[cfg(windows)]
fn command_candidates(dir: &Path, cmd: &str, path_ext: &OsStr) -> Vec<PathBuf> {
    let base = dir.join(cmd);
    let mut candidates = vec![base];
    if Path::new(cmd).extension().is_some() {
        return candidates;
    }

    let path_ext = path_ext.to_string_lossy();
    let extensions = if path_ext.trim().is_empty() {
        ".COM;.EXE;.BAT;.CMD".to_string()
    } else {
        path_ext.to_string()
    };

    for ext in extensions.split(';') {
        let ext = ext.trim();
        if ext.is_empty() {
            continue;
        }
        let normalized = if ext.starts_with('.') {
            ext.to_string()
        } else {
            format!(".{ext}")
        };
        candidates.push(dir.join(format!("{cmd}{normalized}")));
    }
    candidates
}

#[cfg(not(windows))]
fn command_candidates(dir: &Path, cmd: &str, _path_ext: &OsStr) -> Vec<PathBuf> {
    vec![dir.join(cmd)]
}

#[cfg(feature = "runtime-hardening")]
fn apply_runtime_hardening() -> Result<()> {
    crate::runtime_hardening::apply_for_secret_runtime()
        .context("failed to apply runtime hardening")
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;

    #[cfg(unix)]
    fn mk_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(not(unix))]
    fn mk_executable(path: &Path) {
        fs::write(path, "").unwrap();
    }

    fn path_os(parts: &[&Path]) -> OsString {
        std::env::join_paths(parts.iter().map(|p| p.as_os_str())).unwrap()
    }

    fn path_ext() -> &'static OsStr {
        OsStr::new(".COM;.EXE;.BAT;.CMD")
    }

    #[test]
    fn resolve_absolute_path_passes_through() {
        let path = path_os(&[]);
        let r = resolve_command_skipping_shim_dir_in(
            "/usr/bin/env",
            Path::new("/nonexistent"),
            &path,
            path_ext(),
        )
        .unwrap();
        assert_eq!(r, PathBuf::from("/usr/bin/env"));
    }

    #[test]
    fn resolve_relative_with_slash_passes_through() {
        let path = path_os(&[]);
        let r = resolve_command_skipping_shim_dir_in(
            "./foo/bar",
            Path::new("/nonexistent"),
            &path,
            path_ext(),
        )
        .unwrap();
        assert_eq!(r, PathBuf::from("./foo/bar"));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_relative_with_backslash_passes_through() {
        let path = path_os(&[]);
        let r = resolve_command_skipping_shim_dir_in(
            r".\foo\bar.exe",
            Path::new(r"C:\nonexistent"),
            &path,
            path_ext(),
        )
        .unwrap();
        assert_eq!(r, PathBuf::from(r".\foo\bar.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_honors_pathext() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shim");
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        mk_executable(&shim_dir.join("mycmd.cmd"));
        mk_executable(&real_dir.join("mycmd.cmd"));

        let path = path_os(&[shim_dir.as_path(), real_dir.as_path()]);
        let r =
            resolve_command_skipping_shim_dir_in("mycmd", &shim_dir, &path, path_ext()).unwrap();
        assert_eq!(r.parent(), Some(real_dir.as_path()));
        assert!(
            r.file_name()
                .unwrap()
                .to_string_lossy()
                .eq_ignore_ascii_case("mycmd.cmd")
        );
    }

    #[test]
    fn resolve_finds_command_outside_shim_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shim");
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        mk_executable(&shim_dir.join("mycmd"));
        mk_executable(&real_dir.join("mycmd"));

        let path = path_os(&[shim_dir.as_path(), real_dir.as_path()]);
        let r =
            resolve_command_skipping_shim_dir_in("mycmd", &shim_dir, &path, path_ext()).unwrap();
        assert_eq!(r, real_dir.join("mycmd"));
    }

    #[test]
    fn resolve_errors_when_only_in_shim_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shim");
        fs::create_dir_all(&shim_dir).unwrap();
        mk_executable(&shim_dir.join("mycmd"));

        // PATH contains only the shim dir.
        let path = path_os(&[shim_dir.as_path()]);
        let err = resolve_command_skipping_shim_dir_in("mycmd", &shim_dir, &path, path_ext())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("infinite shim recursion"),
            "expected loop-prevention message, got: {msg}"
        );
        assert!(
            msg.contains("not found on PATH outside the shim directory"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn resolve_errors_when_command_missing_entirely() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shim");
        let other_dir = tmp.path().join("other");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&other_dir).unwrap();
        // other_dir exists but does not contain the command.

        let path = path_os(&[shim_dir.as_path(), other_dir.as_path()]);
        let err = resolve_command_skipping_shim_dir_in("no-such-cmd", &shim_dir, &path, path_ext())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found on PATH"),
            "expected 'not found on PATH' message, got: {msg}"
        );
        // Not the recursion message, since there WAS a non-shim dir.
        assert!(
            !msg.contains("infinite shim recursion"),
            "should not claim recursion when the command is simply missing: {msg}"
        );
    }

    #[test]
    fn resolve_canonicalizes_shim_dir_for_comparison() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shim");
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        mk_executable(&shim_dir.join("mycmd"));
        mk_executable(&real_dir.join("mycmd"));

        // PATH uses a trailing-slash form of the shim dir; must still be
        // recognized and skipped.
        let shim_with_slash: PathBuf = format!("{}/", shim_dir.display()).into();
        let path = path_os(&[shim_with_slash.as_path(), real_dir.as_path()]);
        let r =
            resolve_command_skipping_shim_dir_in("mycmd", &shim_dir, &path, path_ext()).unwrap();
        assert_eq!(r, real_dir.join("mycmd"));
    }

    #[test]
    fn resolve_ignores_nonexistent_path_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shim");
        let real_dir = tmp.path().join("real");
        let nope = tmp.path().join("nonexistent");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        mk_executable(&real_dir.join("mycmd"));

        // PATH includes a nonexistent entry; canonicalize returns Err for
        // it, so comparison skips; then we check if mycmd exists there
        // (it doesn't), then move on.
        let path = path_os(&[nope.as_path(), shim_dir.as_path(), real_dir.as_path()]);
        let r =
            resolve_command_skipping_shim_dir_in("mycmd", &shim_dir, &path, path_ext()).unwrap();
        assert_eq!(r, real_dir.join("mycmd"));
    }
}
