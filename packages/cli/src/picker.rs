//! Interactive SSH public-key picker.
//!
//! Used by `sshenv init` and `sshenv add-recipient` when the caller does
//! not pass `--recipient-key` / `--key` explicitly. Given a list of
//! candidate public-key file paths, we show a selection UI on the TTY
//! and return the chosen one.
//!
//! Non-TTY behavior is intentionally strict: if stdin is not a terminal,
//! the picker refuses to guess and returns an error telling the user to
//! pass `--recipient-key` explicitly. This matches the user's expectation
//! that sshenv never silently picks an authorization key.

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A candidate SSH public key that the user can pick from.
#[derive(Debug, Clone)]
pub struct PubkeyCandidate {
    pub path: PathBuf,
    pub line: String,
    pub fingerprint: String,
}

impl PubkeyCandidate {
    /// Load a public key file from disk, parse, and compute its fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the content does
    /// not look like an SSH public key line.
    pub fn from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let line = content
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or_else(|| anyhow::anyhow!("no SSH public key line in {}", path.display()))?
            .to_string();
        let fingerprint = sshenv_vault::recipient::fingerprint_from_line(&line)
            .with_context(|| format!("failed to parse SSH public key in {}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            line,
            fingerprint,
        })
    }
}

/// Select a single candidate interactively. Errors (and therefore exits
/// the CLI with code 1 via the `main` handler) if:
///
/// - stdin is not a TTY (caller must pass `--recipient-key` explicitly),
/// - the candidate list is empty,
/// - the user types `n` / `q` / anything out of range.
///
/// # Errors
///
/// See behavior above.
pub fn select_pubkey_interactive<R: BufRead, W: Write>(
    candidates: &[PubkeyCandidate],
    stdin: &mut R,
    stderr: &mut W,
    tty: bool,
) -> Result<PubkeyCandidate> {
    if !tty {
        bail!(
            "not running interactively; pass --recipient-key explicitly.\n\
             Example: sshenv ... --recipient-key ~/.ssh/id_ed25519.pub"
        );
    }
    if candidates.is_empty() {
        bail!(
            "no SSH public keys found in ~/.ssh/ or ~/.ssh/config.\n\
             Generate one with `ssh-keygen -t ed25519`, or pass \
             --recipient-key <path-or-line> explicitly."
        );
    }

    if candidates.len() == 1 {
        let only = &candidates[0];
        writeln!(
            stderr,
            "Found SSH public key: {} ({})",
            only.path.display(),
            only.fingerprint
        )?;
        write!(stderr, "Use this key? [Y/n] ")?;
        stderr.flush()?;

        let mut buf = String::new();
        stdin
            .read_line(&mut buf)
            .context("failed to read selection from stdin")?;
        let answer = buf.trim();
        if answer.eq_ignore_ascii_case("n") || answer.eq_ignore_ascii_case("no") {
            bail!("cancelled; no recipient selected");
        }
        // Empty input, "y", "Y", "yes" all accept.
        return Ok(only.clone());
    }

    // Multiple candidates: numbered menu.
    writeln!(stderr, "Multiple SSH public keys found. Pick one:")?;
    for (i, c) in candidates.iter().enumerate() {
        writeln!(
            stderr,
            "  {}) {}  ({})",
            i + 1,
            c.path.display(),
            c.fingerprint
        )?;
    }
    write!(stderr, "Enter a number (or 'q' to cancel): ")?;
    stderr.flush()?;

    let mut buf = String::new();
    stdin
        .read_line(&mut buf)
        .context("failed to read selection from stdin")?;
    let answer = buf.trim();
    if answer.eq_ignore_ascii_case("q") {
        bail!("cancelled; no recipient selected");
    }
    let Ok(n) = answer.parse::<usize>() else {
        bail!("invalid selection: {answer:?}");
    };
    if n == 0 || n > candidates.len() {
        bail!(
            "selection out of range: {n} (expected 1..={})",
            candidates.len()
        );
    }
    Ok(candidates[n - 1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cand(path: &str, fp: &str) -> PubkeyCandidate {
        PubkeyCandidate {
            path: PathBuf::from(path),
            line: format!("ssh-ed25519 AAAA... {path}"),
            fingerprint: fp.to_string(),
        }
    }

    #[test]
    fn non_tty_always_errors_with_pointer_to_flag() {
        let mut stdin = Cursor::new(b"1\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![cand("/tmp/k.pub", "SHA256:abc")];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--recipient-key"), "got: {msg}");
        assert!(
            stderr.is_empty(),
            "nothing should have been written to stderr"
        );
    }

    #[test]
    fn empty_candidates_errors_even_in_tty() {
        let mut stdin = Cursor::new(b"");
        let mut stderr: Vec<u8> = Vec::new();
        let err = select_pubkey_interactive(&[], &mut stdin, &mut stderr, true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no SSH public keys found"), "got: {msg}");
        assert!(msg.contains("ssh-keygen"), "got: {msg}");
    }

    #[test]
    fn single_candidate_accepted_on_empty_input() {
        let mut stdin = Cursor::new(b"\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![cand("/tmp/k.pub", "SHA256:abc")];
        let picked = select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true)
            .expect("should accept");
        assert_eq!(picked.fingerprint, "SHA256:abc");
    }

    #[test]
    fn single_candidate_accepted_on_y() {
        let mut stdin = Cursor::new(b"y\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![cand("/tmp/k.pub", "SHA256:abc")];
        let picked = select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap();
        assert_eq!(picked.fingerprint, "SHA256:abc");
    }

    #[test]
    fn single_candidate_rejected_on_n() {
        let mut stdin = Cursor::new(b"n\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![cand("/tmp/k.pub", "SHA256:abc")];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap_err();
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn single_candidate_rejected_on_no_word() {
        let mut stdin = Cursor::new(b"no\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![cand("/tmp/k.pub", "SHA256:abc")];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap_err();
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn multiple_candidates_pick_by_number() {
        let mut stdin = Cursor::new(b"2\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![
            cand("/tmp/a.pub", "SHA256:aaa"),
            cand("/tmp/b.pub", "SHA256:bbb"),
            cand("/tmp/c.pub", "SHA256:ccc"),
        ];
        let picked = select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap();
        assert_eq!(picked.fingerprint, "SHA256:bbb");
        let rendered = String::from_utf8_lossy(&stderr);
        assert!(rendered.contains("1)"));
        assert!(rendered.contains("2)"));
        assert!(rendered.contains("3)"));
    }

    #[test]
    fn multiple_candidates_cancelled_on_q() {
        let mut stdin = Cursor::new(b"q\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![
            cand("/tmp/a.pub", "SHA256:aaa"),
            cand("/tmp/b.pub", "SHA256:bbb"),
        ];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap_err();
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn multiple_candidates_out_of_range_errors() {
        let mut stdin = Cursor::new(b"5\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![
            cand("/tmp/a.pub", "SHA256:aaa"),
            cand("/tmp/b.pub", "SHA256:bbb"),
        ];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn multiple_candidates_zero_errors() {
        let mut stdin = Cursor::new(b"0\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![
            cand("/tmp/a.pub", "SHA256:aaa"),
            cand("/tmp/b.pub", "SHA256:bbb"),
        ];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn multiple_candidates_garbage_errors() {
        let mut stdin = Cursor::new(b"apple\n");
        let mut stderr: Vec<u8> = Vec::new();
        let candidates = vec![
            cand("/tmp/a.pub", "SHA256:aaa"),
            cand("/tmp/b.pub", "SHA256:bbb"),
        ];
        let err =
            select_pubkey_interactive(&candidates, &mut stdin, &mut stderr, true).unwrap_err();
        assert!(err.to_string().contains("invalid selection"));
    }

    #[test]
    fn from_path_reads_and_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.pub");
        fs::write(
            &p,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF1r4mXp9V1d6JEcv5m5d8ONnuQVpMb1i+B7ifqWeu6w braden@test\n",
        )
        .unwrap();
        let c = PubkeyCandidate::from_path(&p).unwrap();
        assert!(c.fingerprint.starts_with("SHA256:"));
        assert!(c.line.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn from_path_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.pub");
        fs::write(
            &p,
            "\n# a comment\n\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF1r4mXp9V1d6JEcv5m5d8ONnuQVpMb1i+B7ifqWeu6w\n",
        )
        .unwrap();
        let c = PubkeyCandidate::from_path(&p).unwrap();
        assert!(c.line.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn from_path_errors_if_no_key_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.pub");
        fs::write(&p, "\n# just a comment\n\n").unwrap();
        assert!(PubkeyCandidate::from_path(&p).is_err());
    }
}
