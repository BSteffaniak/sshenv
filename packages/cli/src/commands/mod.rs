//! Command handlers, one module per logical area.

pub mod doctor;
pub mod export;
pub mod init;
pub mod profile;
pub mod recipient;
pub mod run;
pub mod shims;

use std::path::PathBuf;

use sshenv_cli_models::Cli;

/// Per-invocation context: resolved paths, etc.
pub struct Context {
    pub vault_path: PathBuf,
}

impl Context {
    #[must_use]
    pub fn from_cli(cli: &Cli) -> Self {
        let vault_path = cli
            .vault
            .clone()
            .unwrap_or_else(sshenv_vault::default_vault_path);
        Self { vault_path }
    }
}
