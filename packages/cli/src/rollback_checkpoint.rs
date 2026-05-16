//! Signed rollback checkpoint helpers.
//!
//! Checkpoints are non-secret JSON documents that can be distributed by a
//! remote service or another trusted channel. When `SSHENV_ROLLBACK_CHECKPOINT`
//! points at a signed checkpoint, vault unlock refuses older generations.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use ssh_key::{PublicKey, SshSig};

use crate::session_registry::vault_id;

pub const CHECKPOINT_ENV: &str = "SSHENV_ROLLBACK_CHECKPOINT";
pub const CHECKPOINT_COMMAND_ENV: &str = "SSHENV_ROLLBACK_CHECKPOINT_COMMAND";
pub const SSHSIG_NAMESPACE: &str = "sshenv-rollback-checkpoint-v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RollbackCheckpointRequest {
    pub vault_id: String,
    pub generation: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RollbackCheckpointDocument {
    pub backend: String,
    pub vault_id: String,
    pub generation: u64,
    pub created_unix: u64,
    pub signer: Option<String>,
    pub signature: Option<String>,
}

pub fn load_checkpoint(path: &Path) -> Result<RollbackCheckpointDocument> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read rollback checkpoint {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse rollback checkpoint {}", path.display()))
}

pub fn fetch_checkpoint_from_command(
    command_path: &str,
    request: &RollbackCheckpointRequest,
) -> Result<RollbackCheckpointDocument> {
    let input =
        serde_json::to_vec(request).context("failed to serialize rollback checkpoint request")?;
    let mut child = Command::new(command_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!("failed to invoke rollback checkpoint command '{command_path}'")
        })?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open rollback checkpoint command stdin")?;
        stdin
            .write_all(&input)
            .context("failed to write rollback checkpoint command request")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for rollback checkpoint command")?;
    if !output.status.success() {
        anyhow::bail!(
            "rollback checkpoint command exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout)
        .context("rollback checkpoint command returned invalid checkpoint JSON")
}

pub fn validate_checkpoint_shape(checkpoint: &RollbackCheckpointDocument) -> Result<()> {
    if checkpoint.backend != "remote-checkpoint" {
        anyhow::bail!(
            "rollback checkpoint backend '{}' is not supported",
            checkpoint.backend
        );
    }
    if checkpoint.vault_id.trim().is_empty() {
        anyhow::bail!("rollback checkpoint vault-id is empty");
    }
    Ok(())
}

pub fn verify_checkpoint_signature(checkpoint: &RollbackCheckpointDocument) -> Result<bool> {
    match (&checkpoint.signer, &checkpoint.signature) {
        (None, None) => Ok(false),
        (Some(_), None) => {
            anyhow::bail!("rollback checkpoint signer is set but signature is missing")
        }
        (None, Some(_)) => {
            anyhow::bail!("rollback checkpoint signature is set but signer is missing")
        }
        (Some(signer), Some(signature)) => {
            let public_key = signer
                .parse::<PublicKey>()
                .context("failed to parse rollback checkpoint signer public key")?;
            let signature = signature
                .parse::<SshSig>()
                .context("failed to parse rollback checkpoint SSH signature")?;
            public_key
                .verify(
                    SSHSIG_NAMESPACE,
                    signed_payload(checkpoint).as_bytes(),
                    &signature,
                )
                .context("rollback checkpoint SSH signature verification failed")?;
            Ok(true)
        }
    }
}

pub fn signed_payload(checkpoint: &RollbackCheckpointDocument) -> String {
    format!(
        "sshenv rollback checkpoint v1\nbackend:{}\nvault-id:{}\ngeneration:{}\ncreated-unix:{}\n",
        checkpoint.backend, checkpoint.vault_id, checkpoint.generation, checkpoint.created_unix
    )
}

pub fn enforce_env_checkpoint(vault_path: &Path, generation: Option<u64>) -> Result<()> {
    let expected_vault_id = vault_id(vault_path);
    let checkpoint = if let Ok(path) = std::env::var(CHECKPOINT_ENV) {
        load_checkpoint(Path::new(&path))?
    } else if let Ok(command) = std::env::var(CHECKPOINT_COMMAND_ENV) {
        fetch_checkpoint_from_command(
            &command,
            &RollbackCheckpointRequest {
                vault_id: expected_vault_id.clone(),
                generation,
            },
        )?
    } else {
        return Ok(());
    };
    validate_checkpoint_shape(&checkpoint)?;
    if !verify_checkpoint_signature(&checkpoint)? {
        anyhow::bail!(
            "rollback checkpoint from {CHECKPOINT_ENV} / {CHECKPOINT_COMMAND_ENV} is unsigned; signed checkpoints are required for runtime enforcement"
        );
    }
    if checkpoint.vault_id != expected_vault_id {
        anyhow::bail!(
            "rollback checkpoint vault-id '{}' does not match current vault id '{}'",
            checkpoint.vault_id,
            expected_vault_id
        );
    }
    let Some(generation) = generation else {
        anyhow::bail!("signed rollback checkpoint requires a v2 vault generation");
    };
    if generation < checkpoint.generation {
        anyhow::bail!(
            "possible vault rollback detected: current generation {generation} is older than signed checkpoint generation {}",
            checkpoint.generation
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ssh_key::{HashAlg, LineEnding, PrivateKey};

    use super::*;

    const TEST_PRIVATE_KEY: &str = r"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

    fn signed_checkpoint() -> RollbackCheckpointDocument {
        let private_key = TEST_PRIVATE_KEY.parse::<PrivateKey>().unwrap();
        let mut checkpoint = RollbackCheckpointDocument {
            backend: "remote-checkpoint".to_string(),
            vault_id: "vault-1".to_string(),
            generation: 7,
            created_unix: 4_102_444_800,
            signer: Some(private_key.public_key().to_openssh().unwrap()),
            signature: None,
        };
        let signature = private_key
            .sign(
                SSHSIG_NAMESPACE,
                HashAlg::default(),
                signed_payload(&checkpoint).as_bytes(),
            )
            .unwrap();
        checkpoint.signature = Some(signature.to_pem(LineEnding::LF).unwrap());
        checkpoint
    }

    #[test]
    fn checkpoint_signature_verifies_and_detects_tampering() {
        let mut checkpoint = signed_checkpoint();
        assert!(verify_checkpoint_signature(&checkpoint).unwrap());

        checkpoint.generation += 1;
        assert!(verify_checkpoint_signature(&checkpoint).is_err());
    }

    #[test]
    fn unsigned_checkpoint_is_not_verified() {
        let checkpoint = RollbackCheckpointDocument {
            backend: "remote-checkpoint".to_string(),
            vault_id: "vault-1".to_string(),
            generation: 7,
            created_unix: 4_102_444_800,
            signer: None,
            signature: None,
        };
        assert!(!verify_checkpoint_signature(&checkpoint).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_command_returns_signed_document() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let checkpoint_path = dir.path().join("checkpoint.json");
        std::fs::write(
            &checkpoint_path,
            serde_json::to_string(&signed_checkpoint()).unwrap(),
        )
        .unwrap();
        let command_path = dir.path().join("checkpoint-command.sh");
        std::fs::write(
            &command_path,
            format!(
                "#!/bin/sh\ncat >/dev/null\ncat '{}'\n",
                checkpoint_path.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&command_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let checkpoint = fetch_checkpoint_from_command(
            command_path.to_str().unwrap(),
            &RollbackCheckpointRequest {
                vault_id: "vault-1".to_string(),
                generation: Some(7),
            },
        )
        .unwrap();
        assert_eq!(checkpoint.vault_id, "vault-1");
        assert!(verify_checkpoint_signature(&checkpoint).unwrap());
    }
}
