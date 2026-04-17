use anyhow::Result;
use clap::Parser;
use sshenv_cli_models::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    sshenv::run(cli)
}
