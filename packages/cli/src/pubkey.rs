//! Helpers for reading SSH public key input (either a file path or the
//! literal public key line).

use std::fs;

use anyhow::{Context, Result, bail};

/// Load an SSH public key line from either a path or a literal string.
///
/// Heuristic: if the input starts with a known SSH key-type prefix
/// (`ssh-ed25519 `, `ssh-rsa `, etc.), treat it as a literal key line.
/// Otherwise, try to read it as a file.
///
/// # Errors
///
/// Returns an error if the input cannot be interpreted.
pub fn load_public_key(path_or_line: &str) -> Result<String> {
    let trimmed = path_or_line.trim();
    if trimmed.is_empty() {
        bail!("empty SSH public key input");
    }
    if looks_like_key_line(trimmed) {
        return Ok(trimmed.to_string());
    }
    let content = fs::read_to_string(trimmed)
        .with_context(|| format!("failed to read SSH public key file '{trimmed}'"))?;
    let line = content
        .lines()
        .find(|l| looks_like_key_line(l.trim()))
        .ok_or_else(|| anyhow::anyhow!("no recognizable SSH key line in file '{trimmed}'"))?
        .trim()
        .to_string();
    Ok(line)
}

fn looks_like_key_line(s: &str) -> bool {
    const PREFIXES: &[&str] = &["ssh-ed25519 ", "ssh-rsa ", "ssh-dss ", "ecdsa-"];
    PREFIXES.iter().any(|p| s.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_line_is_passed_through() {
        let line = "ssh-ed25519 AAAAB3 comment";
        let out = load_public_key(line).unwrap();
        assert_eq!(out, line);
    }

    #[test]
    fn leading_trailing_whitespace_is_trimmed() {
        let line = "  ssh-ed25519 AAAAB3  \n";
        let out = load_public_key(line).unwrap();
        assert_eq!(out, "ssh-ed25519 AAAAB3");
    }

    #[test]
    fn reads_from_file_if_not_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pub");
        std::fs::write(&path, "ssh-ed25519 ABCDEF comment\n").unwrap();
        let out = load_public_key(path.to_str().unwrap()).unwrap();
        assert_eq!(out, "ssh-ed25519 ABCDEF comment");
    }

    #[test]
    fn errors_on_empty() {
        assert!(load_public_key("").is_err());
    }
}
